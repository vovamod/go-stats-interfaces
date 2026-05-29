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

package config

import (
	"go-tun/pkg/entities"
	"os"
	"strings"

	"github.com/vovamod/utils/log"
	"gopkg.in/yaml.v3"
)

var GlobalConfig *entities.Config

const (
	configDir  = "/etc/gsi"
	configPath = "/etc/gsi/config.yml"
)

// Configs here
func init() {
	log.Info("Starting up gsi")
	if err := EnsureConfig(); err != nil {
		log.Fatalf("Config initialization failed: %v", err)
	}

	err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
}

func EnsureConfig() error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err = os.MkdirAll(configDir, 0755); err != nil {
			return err
		}

		descTemplate := "Traffic Spike: **{{printf \"%.2f\" .Current}}Mbit** / Max allowed: **{{.Allowed}}Mbit**\n\n" +
			"{{range .Interfaces}}**Interface: {{.Name}}**\n" +
			"{{if .Type}}- Traffic Pattern: `{{.Type}}`\n" +
			"{{end}}- RX Bandwidth: {{printf \"%.2f\" .RX}} Mbit/s\n" +
			"- TX Bandwidth: {{printf \"%.2f\" .TX}} Mbit/s\n" +
			"{{if .IP}}- Top Inbound Target: {{.IP}}\n" +
			"{{end}}{{if .PPS}}- Total PPS Rate: {{.PPS}}\n" +
			"{{end}}\n" +
			"{{end}}"

		defaultCfg := entities.Config{
			Node:          "neon",
			Threshold:     "200Mbit",
			AlertCooldown: "1m",
			PPSThreshold:  90000,
			Providers: entities.MessageProviders{
				Telegram: struct {
					Token  string `yaml:"token"`
					ChatID int64  `yaml:"chatId"`
				}{
					Token:  "",
					ChatID: 0,
				},
				Discord: struct {
					Hook string `yaml:"hook"`
				}{
					Hook: "",
				},
			},
			Message: entities.MessageFields{
				Title: "Status for machine: {{.Node}}",
				Color: 5814783,
				Desc:  strings.TrimSpace(descTemplate),
			},
			Interfaces: []map[string]entities.InterfaceConfig{
				{"enp2s0": {Type: true, PPS: true, RX: true, TX: true, OftenIP: true}},
				{"docker0": {Type: true, PPS: false, RX: true, TX: true, OftenIP: false}},
			},
		}

		var data []byte
		data, err = yaml.Marshal(&defaultCfg)
		if err != nil {
			return err
		}
		return os.WriteFile(configPath, data, 0644)
	}
	return nil
}

func LoadConfig() error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg entities.Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	GlobalConfig = &cfg
	return nil
}
