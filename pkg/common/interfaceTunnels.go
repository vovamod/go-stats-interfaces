/*
 * Copyright © 2026 Volodymyr Khalin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/vovamod/utils/log"
)

// TUNNEL DETECTION AND small funcs. *i am tired.*

// getIfaceArpType reads ARPHRD type from sysfs.
// arpType reads /sys/class/net/<iface>/type
func arpType(ifaceName string) int {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/type")
	if err != nil {
		return -1
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return v
}

// isTunnelType returns true for ip6tnl/sit/gre ARPHRD values.
func isTunnelType(t int) bool {
	return t == 769 || t == 776 || t == 778
}

// sysfsIPv6 decodes a 16-byte colon-hex IPv6 from a sysfs file (address/broadcast).
func sysfsIPv6(path string) net.IP {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ":")
	if len(parts) != 16 {
		return nil
	}
	b := make([]byte, 16)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil
		}
		b[i] = byte(v)
	}
	ip := net.IP(b)
	if ip.IsUnspecified() {
		return nil
	}
	return ip
}

// tunnelPeer returns the remote endpoint of a tunnel from sysfs broadcast.
func tunnelPeer(tunName string) string {
	ip := sysfsIPv6("/sys/class/net/" + tunName + "/broadcast")
	if ip == nil {
		return ""
	}
	return ip.String()
}

// physicalParent finds the ethernet interface whose address prefix contains
// the tunnel's local end (from sysfs address field).
func physicalParent(tunName string) string {
	tunLocal := sysfsIPv6("/sys/class/net/" + tunName + "/address")

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if tunLocal != nil && ipnet.Contains(tunLocal) {
				return iface.Name
			}
		}
	}

	// Fallback: first ethernet with any global unicast address
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
				return iface.Name
			}
		}
	}
	return ""
}

// sniffParams returns what to sniff and how for any interface type.
func sniffParams(ifaceName string) (sniffIface string, outerStart int, peer string, tunnel bool) {
	switch arpType(ifaceName) {
	case 1: // ethernet
		return ifaceName, 14, "", false
	case 769, 776, 778: // ip6tnl, sit, gre
		return physicalParent(ifaceName), 14, tunnelPeer(ifaceName), true
	default:
		return ifaceName, 0, "", false
	}
}

// innerIPOffset walks IPv6 extension headers starting at outerIPv6Start
// and returns the byte offset of the inner IP header, or -1 on failure.
// tested with ECMP IPIP6 tunnels
func innerIPOffset(buf []byte, outerIPv6Start int) int {
	nhPos := outerIPv6Start + 6
	if nhPos >= len(buf) {
		return -1
	}
	nextHdr := buf[nhPos]
	pos := outerIPv6Start + 40

	for range 8 {
		if pos >= len(buf) {
			return -1
		}
		switch nextHdr {
		case 4:
			if buf[pos]>>4 == 4 {
				return pos
			}
			return -1
		case 41:
			if buf[pos]>>4 == 6 {
				return pos
			}
			return -1
		case 59:
			return -1
		case 0, 60, 43, 135, 139, 140:
			if pos+2 > len(buf) {
				return -1
			}
			nextHdr = buf[pos]
			pos += (int(buf[pos+1]) + 1) * 8
		case 51:
			if pos+2 > len(buf) {
				return -1
			}
			nextHdr = buf[pos]
			pos += (int(buf[pos+1]) + 2) * 4
		default:
			return -1 // drop unknown — eliminates garbage IPv6 parses
		}
	}
	return -1
}

// collectLocalIPs returns a set of all IP addresses assigned to local interfaces. (to ignore)
func collectLocalIPs() map[string]bool {
	result := make(map[string]bool)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				result[ipnet.IP.String()] = true
			}
		}
	}
	return result
}

// getTopIPFromConntrack falls back to nf_conntrack when sniffing yields nothing.
// Returns the external src IP with the most ESTABLISHED connections to local IPs.
func getTopIPFromConntrack(localIPs map[string]bool) string {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`ESTABLISHED src=(\S+)\s+dst=(\S+)`)
	counts := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if localIPs[m[2]] {
			counts[m[1]]++
		}
	}
	var topIP string
	var maxA int
	for ip, c := range counts {
		if c > maxA {
			maxA = c
			topIP = ip
		}
	}
	return topIP
}

func sampleInterfaceProtocol(ifaceName string) string {
	sniffIface, outerIPv6Start, _, isTunnel := sniffParams(ifaceName)
	if sniffIface == "" {
		return ""
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return ""
	}
	defer func(fd int) {
		if err = syscall.Close(fd); err != nil {
			log.Warnf("Failed to close socket: %v", fd)
		}
	}(sock)

	ifi, err := net.InterfaceByName(sniffIface)
	if err != nil {
		return ""
	}
	sall := syscall.SockaddrLinklayer{
		Ifindex:  ifi.Index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err = syscall.Bind(sock, &sall); err != nil {
		return ""
	}
	tv := syscall.Timeval{Sec: 0, Usec: 50000}
	_ = syscall.SetsockoptTimeval(sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, 2048)
	tcp, udp := 0, 0

	for i := 0; i < 100; i++ {
		n, from, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			continue
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}

		offset := outerIPv6Start
		if isTunnel {
			inner := innerIPOffset(buf[:n], outerIPv6Start)
			if inner < 0 {
				continue
			}
			offset = inner
		}

		if n < offset+20 {
			continue
		}

		switch buf[offset] >> 4 {
		case 4:
			switch buf[offset+9] {
			case 6:
				tcp++
			case 17:
				udp++
			}
		case 6:
			if n >= offset+40 {
				switch buf[offset+6] {
				case 6:
					tcp++
				case 17:
					udp++
				}
			}
		}
	}

	if tcp == 0 && udp == 0 {
		return ""
	}
	if udp > tcp {
		return "UDP"
	}
	return "TCP"
}

func htons(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}

// EXPORTED

// ResolveConsumerIface maps a physical ethernet to its busiest tunnel child,
// so GetTopConsumerIP can decapsulate correctly.
func ResolveConsumerIface(ifaceName string) string {
	if arpType(ifaceName) != 1 {
		return ifaceName // already a tunnel or tun/tap
	}
	var best string
	var bestRX int64
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if !isTunnelType(arpType(iface.Name)) {
			continue
		}
		if physicalParent(iface.Name) != ifaceName {
			continue
		}
		snap, err := ReadStats(iface.Name)
		if err != nil {
			continue
		}
		if snap.RxBytes > bestRX {
			bestRX = snap.RxBytes
			best = iface.Name
		}
	}
	if best != "" {
		return best
	}
	return ifaceName
}

// GetTopConsumerIP returns the src IP sending the most inbound traffic
// on ifaceName, correctly handling ethernet, ip6tnl, sit, and gre.
func GetTopConsumerIP(ifaceName string) string {
	localIPs := collectLocalIPs()
	sniffIface, outerIPv6Start, tunnelPeerVar, isTunnel := sniffParams(ifaceName)

	log.Debugf("Sniffing %s (for %s) | outerStart=%d | peer=%q | tunnel=%v",
		sniffIface, ifaceName, outerIPv6Start, tunnelPeerVar, isTunnel)

	if sniffIface == "" {
		log.Warnf("Could not determine sniff interface for %s, falling back to conntrack", ifaceName)
		return getTopIPFromConntrack(localIPs)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return ""
	}
	defer func(fd int) {
		err = syscall.Close(fd)
		if err != nil {
			log.Warnf("Failed to close socket %d: %v", fd, err)
		}
	}(sock)

	ifi, err := net.InterfaceByName(sniffIface)
	if err != nil {
		return ""
	}
	sall := syscall.SockaddrLinklayer{
		Ifindex:  ifi.Index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err = syscall.Bind(sock, &sall); err != nil {
		return ""
	}
	tv := syscall.Timeval{Sec: 0, Usec: 200000}
	_ = syscall.SetsockoptTimeval(sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, 2048)
	counts := make(map[string]int)

	for i := 0; i < 200; i++ {
		n, from, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			continue
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}

		// Determine offset to inner IP header
		offset := outerIPv6Start
		if isTunnel {
			// Skip the outer IPv6 + any extension headers to reach inner IP
			inner := innerIPOffset(buf[:n], outerIPv6Start)
			if inner < 0 {
				continue
			}
			offset = inner
		}

		if n < offset+20 {
			continue
		}

		var srcIP string
		switch buf[offset] >> 4 {
		case 4:
			srcIP = net.IPv4(buf[offset+12], buf[offset+13], buf[offset+14], buf[offset+15]).String()
		case 6:
			if n >= offset+40 {
				srcIP = net.IP(buf[offset+8 : offset+24]).String()
			}
		}
		if srcIP == "" {
			continue
		}

		parsed := net.ParseIP(srcIP)
		if parsed == nil || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
			continue
		}
		if localIPs[srcIP] || (tunnelPeerVar != "" && srcIP == tunnelPeerVar) {
			continue
		}

		counts[srcIP]++
	}

	var topIP string
	var maxCount int
	for ip, c := range counts {
		// TODO: add --debug flag.
		log.Debugf("Seen: %s -> %d packets", ip, c)
		if c > maxCount {
			maxCount = c
			topIP = ip
		}
	}

	if topIP == "" {
		log.Infof("No consumer IP from sniffing, falling back to conntrack")
		return getTopIPFromConntrack(localIPs)
	}
	return topIP
}
