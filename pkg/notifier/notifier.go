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

package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-tun/pkg/config"
	"go-tun/pkg/entities"
	"io"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/vovamod/utils/log"
)

var (
	boldRegex = regexp.MustCompile(`\*\*(.*?)\*\*`)
	codeRegex = regexp.MustCompile("`(.*?)`")
)

const (
	defaultTitle = "⚠️ ALERT: VBX-{{.Node}}"
	defaultDesc  = `Interfaces stats were triggered due to threshold exceed {{printf "%.2f" .Current}}Mbit/{{.Allowed}}Mbit

{{range .Interfaces}}**{{.Name}}**:
{{if .Type}}- **Type**: {{.Type}}
{{end}}{{if ne .RX 0.0}}- **RX**: {{printf "%.2f" .RX}}Mbit
{{end}}{{if ne .TX 0.0}}- **TX**: {{printf "%.2f" .TX}}Mbit
{{end}}{{if .IP}}- **IP**: {{.IP}}
{{end}}{{if .PPS}}- **PPS**: {{.PPS}}
{{end}}
{{end}}`
)

func DispatchAlerts(ctx entities.MessageContext) {
	prov := config.GlobalConfig.Providers
	hasDiscord := prov.Discord.Hook != "" && prov.Discord.Hook != "HERE_IS_URL"
	hasTelegram := prov.Telegram.Token != "" && prov.Telegram.ChatID != 0

	if !hasDiscord && !hasTelegram {
		log.Warnf("Threshold triggered, but no notification providers are configured.")
		return
	}

	titleTpl := defaultTitle
	if config.GlobalConfig.Message.Title != "" {
		titleTpl = config.GlobalConfig.Message.Title
	}
	descTpl := defaultDesc
	if config.GlobalConfig.Message.Desc != "" {
		descTpl = config.GlobalConfig.Message.Desc
	}

	renderedTitle := render(titleTpl, ctx)
	renderedDesc := render(descTpl, ctx)

	client := &http.Client{Timeout: 10 * time.Second}
	if hasDiscord {
		go sendDiscord(client, renderedTitle, renderedDesc, ctx)
	}

	if hasTelegram {
		go sendTelegram(client, renderedTitle, renderedDesc)
	}
}

func sendDiscord(client *http.Client, title, desc string, ctx entities.MessageContext) {
	col := 5814783
	if config.GlobalConfig.Message.Color != 0 {
		col = config.GlobalConfig.Message.Color
	}
	// high alert
	if ctx.Current > float64(ctx.Allowed*2) {
		col = 14947862 // Red
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       title,
				"description": desc,
				"color":       col,
			},
		},
	}

	jsonBytes, _ := json.Marshal(payload)
	executeRequest(client, "POST", config.GlobalConfig.Providers.Discord.Hook, jsonBytes, "Discord")
}

func sendTelegram(client *http.Client, title, desc string) {
	htmlDesc := boldRegex.ReplaceAllString(desc, "<b>$1</b>")
	formattedText := fmt.Sprintf("<b>%s</b>\n\n%s", title, htmlDesc)
	formattedText = codeRegex.ReplaceAllString(formattedText, "<code>$1</code>")

	payload := map[string]interface{}{
		"chat_id":    config.GlobalConfig.Providers.Telegram.ChatID,
		"text":       formattedText,
		"parse_mode": "HTML",
	}

	jsonBytes, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.GlobalConfig.Providers.Telegram.Token)
	executeRequest(client, "POST", url, jsonBytes, "Telegram")
}

func executeRequest(client *http.Client, method, url string, body []byte, provider string) {
	maxRetries := 3
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
		if err != nil {
			// TODO: If shows token - remove IMMEDIATELY
			log.Errorf("[%s] Failed to allocate memory wrapper for request: %v", provider, err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Warnf("[%s] Delivery attempt %d/%d failed: %v", provider, attempt, maxRetries, err.Error())
			if attempt < maxRetries {
				time.Sleep(backoff * time.Duration(attempt))
				continue
			}
			log.Errorf("[%s] Final drop: Failed to deliver payload package: %v", provider, err.Error())
			return
		}

		respBytes, _ := io.ReadAll(resp.Body)
		err = resp.Body.Close()
		if err != nil {
			log.Warnf("[%s] Final drop: Failed to close response body: %v", provider, err.Error())
			return
		}

		if resp.StatusCode >= 300 {
			log.Warnf("[%s] Target responded with error status [%d] on attempt %d/%d. Body: %s",
				provider, resp.StatusCode, attempt, maxRetries, string(respBytes))

			if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
				time.Sleep(1 * time.Second)
				continue
			}
			return
		}

		return
	}
}

func render(tplStr string, ctx entities.MessageContext) string {
	tmpl, err := template.New("msg").Parse(tplStr)
	if err != nil {
		return "Template Error"
	}
	var buf bytes.Buffer
	if err = tmpl.Execute(&buf, ctx); err != nil {
		return "Render Error"
	}
	return strings.TrimSpace(buf.String())
}
