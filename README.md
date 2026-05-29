# gsi

Go Network Interface Monitoring and Alerting Daemon.

Monitors specified network interfaces for throughput (Mbit/s) and packet-per-second (PPS) thresholds. When thresholds are exceeded, the daemon samples traffic via raw sockets to determine pattern structures and dispatches alerts to configured communication channels.

## Requirements

The daemon isolates network sockets and processes metrics without requiring full root execution privileges by leveraging specific Linux kernel capabilities:

    CAP_NET_ADMIN: Required to read network interface parameters and properties.

    CAP_NET_RAW: Required to bind raw sockets (AF_PACKET) for traffic sampling.

## Configuration

Place config.yaml in the active runtime directory of the daemon. If the configuration file is missing, the application generates a default template on its initial execution.
```yaml

providers:
    telegram:
        token: ""
        chatId: 0
    discord:
        hook: ""
message:
title: "Status for machine: {{.Node}}"
color: 5814783 # Blue-ish color
desc: |
    Traffic Spike: **{{printf "%.2f" .Current}}Mbit** / Max allowed: **{{.Allowed}}Mbit**
    
        {{range .Interfaces}}**Interface: {{.Name}}**
        {{if .Type}}- Traffic Pattern: `{{.Type}}`
        {{end}}- RX Bandwidth: {{printf "%.2f" .RX}} Mbit/s
        - TX Bandwidth: {{printf "%.2f" .TX}} Mbit/s
        {{if .IP}}- Top Inbound Target: {{.IP}}
        {{end}}{{if .PPS}}- Total PPS Rate: {{.PPS}}
        {{end}}
        {{end}}
node: neon
threshold: 200Mbit
alert_cooldown: 1m # Supported formats: 20s,1m,5m,1h - recommended is 1m
pps_threshold: 90000
interfaces:
- enp2s0:
  Type: true
  PPS: true
  RX: true
  TX: true
  OftenIP: true
- docker0:
  Type: true
  PPS: false
  RX: true
  TX: true
  OftenIP: false
```

config.yaml - in src

## Deployment
1. Installation

Move the compiled binary to the local binary execution path:
```bash
sudo cp gsi /usr/local/bin/gsi
sudo chmod +x /usr/local/bin/gsi
```

2. Systemd Integration

Create the service definition file at **/etc/systemd/system/gsi.service** using the following structure:
```unit file (systemd)

[Unit]
Description=Go Network Interface Monitoring and Alerting Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gsi
WorkingDirectory=/tmp
Restart=always
RestartSec=5s
# LIMITS
Environment=GOMEMLIMIT=50MiB
MemoryHigh=56M
MemoryMax=64M
# Limits and safety constraints (required)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

gsi.service - in src

3. Service Activation

Reload systemd configurations, enable the service to initialize on system startup, and start the daemon:
```Bash

sudo systemctl daemon-reload
sudo systemctl enable --now gsi.service
```

4. Log Inspection

Monitor runtime logs and tracking mechanisms via journalctl:
```Bash
sudo journalctl -u gsi.service -f
```

## Contributing

This project is open for any initiative and improvements via pull requests.