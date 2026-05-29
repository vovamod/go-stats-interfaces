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

package main

import (
	"go-tun/pkg/common"
	"go-tun/pkg/config"
	"go-tun/pkg/entities"
	"go-tun/pkg/notifier"
	"runtime/debug"
	"time"

	"github.com/vovamod/utils/log"
)

var (
	prevStats     = make(map[string]entities.StatSnapshot)
	thresholdMbit = common.ParseThreshold(config.GlobalConfig.Threshold)
	alertCooldown = common.ParseCooldown(config.GlobalConfig.AlertCooldown)
	lastAlertTime time.Time
)

// Metadata
var (
	version   = "dev"
	buildDate = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			version = info.Main.Version
		}
	}
}

func main() {
	log.Infof("Starting gsi daemon ver:%s-%v for node [%s]. Threshold: %d Mbit\n", version, buildDate, config.GlobalConfig.Node, thresholdMbit)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			execute()
		}
	}
}

func execute() {
	var totalCurrentMbit float64
	var discInterfaces []entities.MessageInterface

	for _, ifaceMap := range config.GlobalConfig.Interfaces {
		for ifaceName, flags := range ifaceMap {
			current, err := common.ReadStats(ifaceName)
			if err != nil {
				continue
			}

			prev, exists := prevStats[ifaceName]
			if !exists {
				prevStats[ifaceName] = current
				continue
			}

			rxMbit := float64(current.RxBytes-prev.RxBytes) * 8 / 1_000_000
			txMbit := float64(current.TxBytes-prev.TxBytes) * 8 / 1_000_000
			pps := current.RxPackets - prev.RxPackets

			totalCurrentMbit += rxMbit + txMbit
			var trafficType string
			if flags.Type {
				trafficType = common.DetectTrafficType(ifaceName, pps)
			}

			var topIP string
			if flags.OftenIP {
				topIP = common.GetTopConsumerIP()
			}

			item := entities.MessageInterface{
				Name: ifaceName,
				Type: trafficType,
				IP:   topIP,
			}
			if flags.RX {
				item.RX = rxMbit
			}
			if flags.TX {
				item.TX = txMbit
			}
			if flags.PPS {
				item.PPS = uint64(pps)
			}
			discInterfaces = append(discInterfaces, item)
			prevStats[ifaceName] = current
		}
	}

	if thresholdMbit > 0 && totalCurrentMbit >= float64(thresholdMbit) {
		if time.Since(lastAlertTime) > alertCooldown {
			log.Infof("Threshold exceeded: %.2f Mbit/s. Sending alert.", totalCurrentMbit)

			ctx := entities.MessageContext{
				Node:       config.GlobalConfig.Node,
				Current:    totalCurrentMbit,
				Allowed:    thresholdMbit,
				Interfaces: discInterfaces,
			}

			notifier.DispatchAlerts(ctx)
			lastAlertTime = time.Now()
		}
	}
}
