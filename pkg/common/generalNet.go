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
	"os"
	"strconv"
	"strings"
	"time"
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

// funcs
func readSysfsInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}
