# PAN Firewall - Home Assistant Custom Integration

Control Palo Alto Networks (PAN-OS) firewalls from Home Assistant.

## Features

- **Security rule switches** (enable/disable + auto-commit)
  - All switches are created **disabled by default** (enable manually in entity registry)
- **Rule count sensors**
  - Security Rules Total
  - NAT Rules Total
  - Decryption Rules Total
- **Performance sensors**
  - Dataplane CPU (%)
  - Management CPU (%)
  - Concurrent Connections
  - Connections per Second
  - Total Throughput (Mbps)
  - Number of Routes
- **System information sensors** (mostly diagnostic)
  - Hostname, IP, Time, Uptime, Model, Serial, Software Version, etc.
  - Version sensors (App, AV, Threat, Wildfire, etc.) include release dates as attributes
  - VM-specific sensors (when platform-family = vm): Cores, Memory, License, UUID, etc.
- Configurable polling interval (default: 30 seconds, min: 10 seconds)
- All entities grouped under one device

## Requirements

- Home Assistant 2024.6+
- PAN-OS firewall (tested on 12.1.x)
- API user with read/write permissions

## Installation

### Via HACS (recommended)

1. HACS → Integrations → Custom repositories
2. URL: `https://github.com/YOURUSERNAME/pan-firewall`  
   Category: Integration
3. Install → restart HA
4. Add integration via **Settings → Devices & services → Add Integration → PAN Firewall**

### Manual

Copy `custom_components/pan_firewall` folder to `config/custom_components/`.

## Configuration

Fields:

- Host / IP
- Port (default 443)
- Username
- Password
- VSYS (default: vsys1)
- Verify SSL (default: true)
- Polling interval (seconds, default: 30, min: 10)

After setup: one device "PAN Firewall [serial]" with all entities.

## Usage Notes

- Rule switches are **disabled by default** → go to device → Entities tab → enable the ones you want to use
- Toggling a switch disables/enables the rule and commits the config automatically
- Version sensors are **diagnostic** → appear in the device's Diagnostics tab

## Troubleshooting

- Switches / counts missing → check logs for "Rulebase fetch failed"
- Sensors 0 → verify API permissions (operational + configuration read)
- Commit slow → normal on busy firewalls (sync=True waits for commit)

## License

MIT
