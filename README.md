# PAN-Firewall – Home Assistant Custom Integration

Control **Palo Alto Networks** (PAN-OS) firewall security, NAT and decryption rules directly from Home Assistant.

Toggle rules on/off (with automatic commit), monitor firewall health metrics (CPU, sessions, throughput, routes, …), and get detailed system information.

![PAN Firewall in Home Assistant](https://via.placeholder.com/800x400.png?text=PAN+Firewall+in+HA+Dashboard)  
*(replace with your own screenshot when you have one)*

## Features

- **Rule control as switches**  
  - Security rules  
  - NAT rules  
  - Decryption rules  
  → All switches are **disabled by default** in the entity registry (enable manually if you want them visible/usable)

- **Automatic commit** after every enable/disable action

- **Health & performance sensors**  
  - Dataplane CPU %  
  - Management CPU %  
  - Concurrent connections  
  - Connections per second  
  - Total throughput (Mbps)  
  - Number of routes

- **Detailed system information sensors** (most are diagnostic)  
  - Hostname, IP, uptime, software version, app/av/threat/wildfire versions + release dates (as attributes)  
  - VM-specific info (cores, memory, license, UUID, etc.) when platform-family = vm

- **Rule count sensors**  
  - Security Rules Total  
  - NAT Rules Total  
  - Decryption Rules Total

- Configurable polling interval (default 30 s, minimum 10 s)

- Single device entity in Home Assistant with all switches & sensors grouped under it

- Local polling only – no cloud dependency

## Requirements

- Home Assistant 2024.6 or newer (tested up to 2026.x)
- PAN-OS firewall (tested on 12.1.4, should work on 10.x–12.x)
- `pan-os-python` library (automatically installed via manifest)

## Installation

### Via HACS (recommended)

1. **HACS → Integrations → Explore & Download Repositories** (or the three dots menu → Custom repositories)
2. Add this repository URL:  
   `https://github.com/YOURUSERNAME/pan-firewall`  
   Category: **Integration**
3. Search for **PAN Firewall** and install it
4. Restart Home Assistant
5. Go to **Settings → Devices & Services → Add Integration → PAN Firewall**

### Manual installation

1. Download the latest release ZIP
2. Copy the `custom_components/pan_firewall` folder to your HA `config/custom_components/` directory
3. Restart Home Assistant
4. Add the integration via the UI

## Configuration

Go to **Settings → Devices & Services → Add Integration → PAN Firewall**

Fields:

| Field              | Description                              | Default / Example          |
|---------------------|------------------------------------------|----------------------------|
| Host               | Firewall IP or hostname                  | 192.168.1.1               |
| Port               | HTTPS port                               | 443                       |
| Username           | API user with read/write privileges      | admin                     |
| Password           | API password                             | —                         |
| VSYS               | Virtual system (multi-vsys firewalls)    | vsys1                     |
| Verify SSL         | Validate firewall certificate            | true                      |
| Polling interval   | How often to refresh data (seconds)      | 30 (min 10)               |

After setup you will see one device named **PAN Firewall [serial-number]** containing:

- switches (all disabled by default)
- performance sensors
- rule count sensors
- diagnostic system/version sensors

## Usage Tips

- **Enabling switches**  
  All rule switches are **disabled by default** in the entity registry.  
  Go to **Settings → Devices & Services → PAN Firewall → Entities** and enable the ones you want to use/control.

- **Dashboard example**

```yaml
type: entities
entities:
  - entity: switch.security_rule_block_tor
  - entity: sensor.dataplane_cpu
  - entity: sensor.concurrent_connections
  - entity: sensor.total_throughput
title: Firewall Controls
