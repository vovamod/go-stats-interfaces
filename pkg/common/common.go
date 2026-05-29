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
	"fmt"
	"go-tun/pkg/config"
	"go-tun/pkg/entities"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vovamod/utils/log"
)

func ReadStats(iface string) (entities.StatSnapshot, error) {
	var snap entities.StatSnapshot
	var err error

	snap.RxBytes, err = readSysfsInt(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface))
	if err != nil {
		return snap, err
	}
	snap.TxBytes, err = readSysfsInt(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface))
	if err != nil {
		return snap, err
	}
	snap.RxPackets, err = readSysfsInt(fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface))
	if err != nil {
		return snap, err
	}
	snap.TxPackets, err = readSysfsInt(fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface))
	return snap, err
}

func readSysfsInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func ParseThreshold(t string) int64 {
	t = strings.ToUpper(strings.TrimSpace(t))
	if !strings.HasSuffix(t, "MBIT") {
		return 0
	}
	numStr := strings.TrimSuffix(t, "MBIT")
	val, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0
	}
	return val
}

func ParseCooldown(cooldownStr string) time.Duration {
	d, err := time.ParseDuration(cooldownStr)
	if err != nil {
		return 1 * time.Minute
	}
	return d
}

func GetTopConsumerIP() string {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		// Fallback to simpler active network connections state if conntrack metrics are absent
		data, err = os.ReadFile("/proc/net/tcp")
		if err != nil {
			return "unknown"
		}
	}

	lines := strings.Split(string(data), "\n")
	ipCounts := make(map[string]int)

	for _, line := range lines {
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") {
				ip := strings.Split(f, "=")[1]
				if ip != "127.0.0.1" {
					ipCounts[ip]++
				}
			}
		}
	}

	var topIP string
	var maxCount int
	for ip, count := range ipCounts {
		if count > maxCount {
			maxCount = count
			topIP = ip
		}
	}

	if topIP == "" {
		return "N/A"
	}
	return topIP
}

func DetectTrafficType(ifaceName string, pps int64) string {
	if pps <= 0 {
		return ""
	}

	dominantProto := sampleInterfaceProtocol(ifaceName)
	if dominantProto == "" {
		return ""
	}

	if pps > int64(config.GlobalConfig.PPSThreshold) {
		return dominantProto + " Flood"
	}

	return dominantProto
}

func sampleInterfaceProtocol(ifaceName string) string {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return ""
	}
	defer func(fd int) {
		err = syscall.Close(fd)
		if err != nil {
			log.Errorf("Failed to close socket %d", fd)
		}
	}(sock)

	ifi, err := net.InterfaceByName(ifaceName)
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

	buffer := make([]byte, 1518)
	tcpPackets := 0
	udpPackets := 0
	maxSamples := 100

	for i := 0; i < maxSamples; i++ {
		n, _, err := syscall.Recvfrom(sock, buffer, 0)
		if err != nil {
			break
		}
		if n < 34 {
			continue
		}

		ethProto := (uint16(buffer[12]) << 8) | uint16(buffer[13])
		if ethProto == 0x0800 {
			ipProto := buffer[23]
			if ipProto == 6 {
				tcpPackets++
			} else if ipProto == 17 {
				udpPackets++
			}
		} else if ethProto == 0x86DD {
			if n < 54 {
				continue
			}
			ipProto := buffer[20]
			if ipProto == 6 {
				tcpPackets++
			} else if ipProto == 17 {
				udpPackets++
			}
		}
	}

	if tcpPackets == 0 && udpPackets == 0 {
		return ""
	}

	if udpPackets > tcpPackets {
		return "UDP"
	}
	return "TCP"
}

func htons(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}
