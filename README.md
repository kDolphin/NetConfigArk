# NetConfigArk

Network device configuration backup tool. Connects to switches, routers, and firewalls via SSH/Telnet to fetch running configurations in **read-only** mode (no changes made to devices).

## Supported Devices

| Type | Device | Config Command |
|---|---|---|
| `cisco` | Cisco IOS/IOS-XE Switch/Router | `show running-config` |
| `cisco_asa` | Cisco ASA/FTD Firewall | `show running-config` |
| `cisco_nxos` | Cisco Nexus Data Center Switch | `show running-config` |
| `cisco_xr` | Cisco IOS-XR Router | `show running-config` |
| `huawei` | Huawei VRP Switch/Router | `display current-configuration` |
| `huawei_usg` | Huawei USG Firewall | `display current-configuration` |
| `h3c` | H3C Comware Switch/Router | `display current-configuration` |
| `fortinet` | Fortinet FortiGate Firewall | `show full-configuration` |
| `juniper` | Juniper JunOS Router/Switch/SRX | `show configuration` |
| `paloalto` | Palo Alto PAN-OS Firewall | `show config running` |
| `routeros` | MikroTik RouterOS Router/Switch | `export` |

## Features

- **Batch or single device** — CSV file for bulk operations, or CLI arguments for one device
- **Device type fingerprint validation** — auto-detects and corrects wrong `device_type` during pre-check (e.g., H3C mislabeled as Huawei)
- **SSH auto-detection** — leave `device_type` empty in CSV for SSH connections, auto-detected via SSHDetect
- **Pre-check before backup** — verifies all devices are reachable before starting; `--skip-unreachable` to continue with reachable ones
- **Config completeness validation** — checks for end markers, paging residue, and minimum line count
- **Connection retry** — automatic retry on timeout for intermittent network issues
- **Empty output retry** — fallback to time-based command for devices with prompt detection quirks
- **Concurrent execution** — configurable thread count for parallel backups; `--burst` mode for maximum parallelism
- **Config diff report** — compare latest N backups per device, generate an HTML report with color-coded diffs; auto-generated timestamps filtered by default
- **Config viewer** — generate an interactive HTML page to browse the latest backup config for each device with syntax highlighting and search
- **Organized output** — backups grouped by location, named by IP/type/hostname/timestamp
- **Read-only guarantee** — only sends show/display/export commands, never enters config mode

## Requirements

- Python 3.8+
- Network reachability to target devices (SSH/Telnet)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate a CSV template
python3 backup_config.py --init

# View supported device types
python3 backup_config.py --list-types

# Edit devices.csv with your device info, then run:
python3 backup_config.py -c devices.csv
```

## Usage

### CSV Batch Mode

```bash
# Basic batch backup
python3 backup_config.py -c devices.csv

# With options
python3 backup_config.py -c devices.csv -w 4 -t 30 --read-timeout 120 --skip-unreachable

# Burst mode: one thread per device, all devices in parallel
python3 backup_config.py -c devices.csv --burst
```

### Config Diff Mode

```bash
# Compare latest 5 backups per device (default), generate HTML report
python3 backup_config.py -c devices.csv --diff

# Compare latest 3 backups per device
python3 backup_config.py -c devices.csv --diff 3

# Diff without timestamp filtering (show all differences including timestamps)
python3 backup_config.py -c devices.csv --diff --no-filter
```

The diff report is saved as `backups/diff_report_<timestamp>.html`. Open it in a browser to see color-coded comparisons of configuration changes across backup versions. By default, auto-generated timestamps (RouterOS export headers, Huawei/Cisco timestamp lines, `ntp clock-period`) are filtered out to reduce noise.

### Config View Mode

```bash
# Generate an HTML viewer for the latest config of each device
python3 backup_config.py -c devices.csv --view
```

The viewer is saved as `backups/config_view_<timestamp>.html`. It provides a dual-column layout with a device sidebar (grouped by location, searchable) and a syntax-highlighted config panel. Keyboard shortcuts: `j/k` or arrow keys to navigate devices, `/` to focus search, `Esc` to clear.

### Single Device Mode

```bash
# Minimal (password prompted, device type auto-detected)
python3 backup_config.py -H 192.168.1.1 -u admin

# Full options
python3 backup_config.py -H 10.0.0.1 -u admin -p pass123 -d cisco --enable-password en123

# Telnet with non-standard port
python3 backup_config.py -H 172.16.0.1 -u admin -p pass123 -P telnet --port 2323 -d h3c
```

### CLI Options

| Option | Default | Description |
|---|---|---|
| `-c, --csv` | `devices.csv` | Device inventory CSV file |
| `-H, --host` | | Device IP (enables single device mode) |
| `-u, --username` | | Login username |
| `-p, --password` | | Login password (prompted if omitted) |
| `-P, --protocol` | `ssh` | `ssh` or `telnet` |
| `-d, --device-type` | | Device type (optional for SSH, required for Telnet) |
| `--enable-password` | | Privileged mode password |
| `--location` | `default` | Site/location for grouping backups |
| `-o, --output` | `./backups` | Output directory |
| `-w, --workers` | `2` | Concurrent threads |
| `--burst` | off | Set concurrency = device count (all in parallel) |
| `-t, --timeout` | `20` | Connection timeout (seconds) |
| `--read-timeout` | `60` | Config fetch timeout per device (seconds) |
| `-v, --verbose` | off | Debug logging |
| `--skip-unreachable` | off | Skip failed devices, backup the rest |
| `--list-types` | | Show supported device types and exit |
| `--init` | | Generate CSV template and exit |
| `--diff [N]` | `5` | Compare latest N backups per device, generate HTML diff report |
| `--no-filter` | off | Disable timestamp filtering in diff mode |
| `--view` | off | Generate HTML config viewer with syntax highlighting |

## CSV Format

```csv
ip,protocol,port,username,password,device_type,enable_password,hostname,location
192.168.1.1,ssh,,admin,password,huawei,,Core-Switch,DC-East
10.0.0.1,ssh,22,admin,password,cisco,enable123,Router-01,DC-East
172.16.0.1,telnet,23,admin,password,h3c,,Access-SW,Office
```

- `port` — empty for default (SSH=22, Telnet=23)
- `device_type` — optional for SSH (auto-detected), required for Telnet
- `enable_password` — optional, for Cisco enable / Huawei super
- `hostname` — optional, used in directory and file naming
- `location` — optional, groups backups by site (defaults to `default`)
- Lines starting with `#` are comments

## Output Structure

```
backups/
  DC-East/
    192.168.1.1_huawei_Core-Switch/
      192.168.1.1_huawei_Core-Switch_2026-03-10_143000.txt
  default/
    172.16.0.1_h3c/
      172.16.0.1_h3c_2026-03-10_143000.txt
```

## License

MIT
