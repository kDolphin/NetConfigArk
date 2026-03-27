#!/usr/bin/env python3
"""
Network Device Configuration Backup Tool

Supports Cisco/Huawei/H3C/Fortinet/Juniper/Palo Alto/MikroTik devices.
Connects via SSH/Telnet to fetch running config (read-only, no changes made to devices).

Usage:
    python3 backup_config.py --init              # Generate CSV template
    python3 backup_config.py --list-types        # Show supported device types
    python3 backup_config.py -c devices.csv      # Batch backup from CSV
    python3 backup_config.py -H 10.0.0.1 -u admin  # Single device backup
    python3 backup_config.py -c devices.csv --diff  # Compare latest 5 backups per device
    python3 backup_config.py -c devices.csv --view  # View latest configs with highlighting
"""

import os
import sys
import csv
import logging
import argparse
import ipaddress
import getpass
import time
import re
import io
import difflib
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from netmiko import ConnectHandler, SSHDetect
    from netmiko.exceptions import (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
        ReadTimeout,
    )
except ImportError:
    print("Error: netmiko is not installed. Run: pip install netmiko>=4.0.0")
    sys.exit(1)


# ============================================================================
# Constants — all commands sent to devices are defined here (whitelist)
# ============================================================================

# CSV device_type -> (ssh netmiko type, telnet netmiko type)
DEVICE_TYPE_MAP: Dict[str, Tuple[str, str]] = {
    "cisco":      ("cisco_ios",         "cisco_ios_telnet"),
    "cisco_asa":  ("cisco_asa",         "cisco_asa_telnet"),
    "cisco_nxos": ("cisco_nxos",        "cisco_nxos_telnet"),
    "cisco_xr":   ("cisco_xr",          "cisco_xr_telnet"),
    "huawei":     ("huawei",            "huawei_telnet"),
    "huawei_usg": ("huawei",            "huawei_telnet"),
    "h3c":        ("hp_comware",        "hp_comware_telnet"),
    "fortinet":   ("fortinet",          "fortinet"),
    "juniper":    ("juniper_junos",     "juniper_junos_telnet"),
    "paloalto":   ("paloalto_panos",    "paloalto_panos"),
    "routeros":   ("mikrotik_routeros", "mikrotik_routeros"),
}

# Reverse map: netmiko type -> short CSV device_type name
NETMIKO_TO_CSV_TYPE: Dict[str, str] = {}
for csv_type, (ssh_type, telnet_type) in DEVICE_TYPE_MAP.items():
    if ssh_type not in NETMIKO_TO_CSV_TYPE:
        NETMIKO_TO_CSV_TYPE[ssh_type] = csv_type
    if telnet_type not in NETMIKO_TO_CSV_TYPE:
        NETMIKO_TO_CSV_TYPE[telnet_type] = csv_type

# netmiko device_type -> config fetch command (READ-ONLY commands only)
NETMIKO_TYPE_TO_COMMAND: Dict[str, str] = {
    "cisco_ios":          "show running-config",
    "cisco_ios_telnet":   "show running-config",
    "cisco_xe":           "show running-config",
    "cisco_asa":          "show running-config",
    "cisco_asa_telnet":   "show running-config",
    "cisco_nxos":         "show running-config",
    "cisco_nxos_telnet":  "show running-config",
    "cisco_xr":           "show running-config",
    "cisco_xr_telnet":    "show running-config",
    "huawei":             "display current-configuration",
    "huawei_vrpv8":       "display current-configuration",
    "huawei_telnet":      "display current-configuration",
    "hp_comware":         "display current-configuration",
    "hp_comware_telnet":  "display current-configuration",
    "fortinet":           "show full-configuration",
    "juniper_junos":      "show configuration",
    "juniper_junos_telnet": "show configuration",
    "paloalto_panos":     "show config running",
    "mikrotik_routeros":  "export",
}

# netmiko device_type -> disable paging command (session-scoped, auto-reverts on disconnect)
DISABLE_PAGING_COMMANDS: Dict[str, Optional[str]] = {
    "cisco_ios":          "terminal length 0",
    "cisco_ios_telnet":   "terminal length 0",
    "cisco_xe":           "terminal length 0",
    "cisco_asa":          "terminal pager 0",
    "cisco_asa_telnet":   "terminal pager 0",
    "cisco_nxos":         "terminal length 0",
    "cisco_nxos_telnet":  "terminal length 0",
    "cisco_xr":           "terminal length 0",
    "cisco_xr_telnet":    "terminal length 0",
    "huawei":             "screen-length 0 temporary",
    "huawei_vrpv8":       "screen-length 0 temporary",
    "huawei_telnet":      "screen-length 0 temporary",
    "hp_comware":         "screen-length disable",
    "hp_comware_telnet":  "screen-length disable",
    "fortinet":           None,  # handled specially below
    "juniper_junos":      "set cli screen-length 0",
    "juniper_junos_telnet": "set cli screen-length 0",
    "paloalto_panos":     "set cli pager off",
    "mikrotik_routeros":  None,  # RouterOS export outputs without paging
}

# Fortinet requires multi-step command to disable paging
FORTINET_DISABLE_PAGING = [
    "config system console",
    "set output standard",
    "end",
]

# netmiko device_type -> expected end marker for config completeness validation
CONFIG_END_MARKERS: Dict[str, Optional[str]] = {
    "cisco_ios":          "end",
    "cisco_ios_telnet":   "end",
    "cisco_xe":           "end",
    "cisco_asa":          "end",
    "cisco_asa_telnet":   "end",
    "cisco_nxos":         None,  # NX-OS show running-config has no 'end' marker
    "cisco_nxos_telnet":  None,  # NX-OS show running-config has no 'end' marker
    "cisco_xr":           "end",
    "cisco_xr_telnet":    "end",
    "huawei":             "return",
    "huawei_vrpv8":       "return",
    "huawei_telnet":      "return",
    "hp_comware":         "return",
    "hp_comware_telnet":  "return",
    "fortinet":           "end",
    "juniper_junos":      "}",
    "juniper_junos_telnet": "}",
    "paloalto_panos":     None,  # no fixed end marker
    "mikrotik_routeros":  None,  # no fixed end marker
}

# Device type info for --list-types display
DEVICE_TYPE_INFO = [
    ("cisco",      "Cisco IOS/IOS-XE Switch/Router",     "show running-config"),
    ("cisco_asa",  "Cisco ASA/FTD Firewall",             "show running-config"),
    ("cisco_nxos", "Cisco Nexus Data Center Switch",     "show running-config"),
    ("cisco_xr",   "Cisco IOS-XR Router",                "show running-config"),
    ("huawei",     "Huawei VRP Switch/Router",           "display current-configuration"),
    ("huawei_usg", "Huawei USG Firewall",                "display current-configuration"),
    ("h3c",        "H3C Comware Switch/Router",          "display current-configuration"),
    ("fortinet",   "Fortinet FortiGate Firewall",        "show full-configuration"),
    ("juniper",    "Juniper JunOS Router/Switch/SRX",    "show configuration"),
    ("paloalto",   "Palo Alto PAN-OS Firewall",          "show config running"),
    ("routeros",   "MikroTik RouterOS Router/Switch",    "export"),
]

SUPPORTED_TYPES = [t[0] for t in DEVICE_TYPE_INFO]

# Paging residue patterns
PAGING_RESIDUE_RE = re.compile(r"--\s*[Mm]ore\s*--|-{4}\s*More\s*-{4}", re.IGNORECASE)

# Lines matching these patterns are ignored during --diff comparison.
# These are auto-generated timestamps that change on every config export
# but do not represent actual configuration changes.
DIFF_IGNORE_PATTERNS: List["re.Pattern[str]"] = [
    # RouterOS: # 2026-03-26 08:50:49 by RouterOS 7.21.3
    re.compile(r"^#\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+by\s+RouterOS"),
    # Huawei/H3C: standalone timestamp line  2026-03-26 08:46:20.880 +08:00  or  2026-03-27 10:01:07.430
    re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+(\s+[+-]\d{2}:\d{2})?\s*$"),
    # Cisco IOS: ! Last configuration change at ...
    re.compile(r"^!\s*Last\s+(configuration\s+change|config\s+update)\s+at\s+", re.IGNORECASE),
    # Cisco IOS: ! NVRAM config last updated at ...
    re.compile(r"^!\s*NVRAM\s+config\s+last\s+updated\s+at\s+", re.IGNORECASE),
    # Cisco NX-OS: !Time: ...
    re.compile(r"^!Time:\s+", re.IGNORECASE),
    # Cisco IOS: ntp clock-period (auto-adjusted value)
    re.compile(r"^ntp\s+clock-period\s+\d+"),
]

# CSV device_type -> version command for fingerprinting (read-only)
VERSION_COMMANDS: Dict[str, str] = {
    "huawei":     "display version",
    "huawei_usg": "display version",
    "h3c":        "display version",
    "cisco":      "show version",
    "cisco_asa":  "show version",
    "cisco_nxos": "show version",
    "cisco_xr":   "show version",
    "fortinet":   "get system status",
    "juniper":    "show version",
    "paloalto":   "show system info",
    "routeros":   "/system resource print",
}

# Fingerprint patterns: (csv_type, compiled_regex)
# Ordered by priority — first match wins. H3C before Huawei because
# H3C output may contain "Huawei" but always has "Comware" or "H3C".
DEVICE_FINGERPRINTS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("h3c",        re.compile(r"\bComware\b", re.IGNORECASE)),
    ("h3c",        re.compile(r"\bH3C\b", re.IGNORECASE)),
    ("huawei",     re.compile(r"Huawei.*VRP|VRP.*Software", re.IGNORECASE)),
    ("huawei",     re.compile(r"\bHUAWEI\b", re.IGNORECASE)),
    ("cisco_xr",   re.compile(r"Cisco\s+IOS\s+XR", re.IGNORECASE)),
    ("cisco_nxos", re.compile(r"\bNX-OS\b", re.IGNORECASE)),
    ("cisco_asa",  re.compile(r"Adaptive\s+Security\s+Appliance", re.IGNORECASE)),
    ("cisco",      re.compile(r"Cisco\s+IOS", re.IGNORECASE)),
    ("cisco",      re.compile(r"\bCisco\b", re.IGNORECASE)),
    ("fortinet",   re.compile(r"FortiGate|FortiOS", re.IGNORECASE)),
    ("juniper",    re.compile(r"\bJUNOS\b", re.IGNORECASE)),
    ("paloalto",   re.compile(r"Palo\s+Alto|PAN-?OS", re.IGNORECASE)),
    ("routeros",   re.compile(r"MikroTik|RouterOS", re.IGNORECASE)),
]

# Equivalent device type groups — types within the same group use the same
# netmiko driver and commands, so a mismatch within a group is harmless.
TYPE_EQUIVALENCE_GROUPS: Dict[str, set] = {
    "huawei":     {"huawei", "huawei_usg"},
    "huawei_usg": {"huawei", "huawei_usg"},
    "cisco":      {"cisco"},
    "cisco_asa":  {"cisco_asa"},
    "cisco_nxos": {"cisco_nxos"},
    "cisco_xr":   {"cisco_xr"},
    "h3c":        {"h3c"},
    "fortinet":   {"fortinet"},
    "juniper":    {"juniper"},
    "paloalto":   {"paloalto"},
    "routeros":   {"routeros"},
}


# ============================================================================
# Data classes
# ============================================================================

@dataclass
class PrecheckResult:
    ip: str
    hostname: str
    success: bool
    netmiko_type: str = ""
    csv_device_type: str = ""
    error: str = ""
    type_corrected: bool = False
    type_warning: str = ""


@dataclass
class BackupResult:
    ip: str
    hostname: str
    success: bool
    file_path: str = ""
    error: str = ""
    warning: str = ""
    duration: float = 0.0
    detected_type: str = ""


# ============================================================================
# CSV parsing
# ============================================================================

REQUIRED_CSV_FIELDS = {"ip", "protocol", "username", "password"}
ALL_CSV_FIELDS = {"ip", "protocol", "port", "username", "password",
                  "device_type", "enable_password", "hostname", "location"}


def parse_csv(file_path: str, logger: logging.Logger) -> List[Dict[str, str]]:
    """Parse device inventory CSV file. Returns list of validated device dicts."""
    if not os.path.isfile(file_path):
        logger.error("CSV file not found: %s", file_path)
        sys.exit(1)

    devices = []
    with open(file_path, "r", encoding="utf-8-sig") as f:
        # Filter out comment lines before passing to DictReader
        lines = [line for line in f if not line.strip().startswith("#")]

    if not lines:
        logger.error("CSV file is empty or contains only comments: %s", file_path)
        sys.exit(1)

    reader = csv.DictReader(lines)

    # Validate header
    if reader.fieldnames is None:
        logger.error("CSV file has no header row: %s", file_path)
        sys.exit(1)

    missing_headers = REQUIRED_CSV_FIELDS - set(reader.fieldnames)
    if missing_headers:
        logger.error("CSV missing required columns: %s", ", ".join(missing_headers))
        sys.exit(1)

    for row_num, row in enumerate(reader, start=2):
        # Strip whitespace from all values
        row = {k: (v.strip() if v else "") for k, v in row.items()}

        # Validate required fields
        missing = [f for f in REQUIRED_CSV_FIELDS if not row.get(f)]
        if missing:
            logger.warning("Row %d: skipping - missing required fields: %s",
                           row_num, ", ".join(missing))
            continue

        # Validate IP
        try:
            ipaddress.ip_address(row["ip"])
        except ValueError:
            logger.warning("Row %d: skipping - invalid IP address: %s",
                           row_num, row["ip"])
            continue

        # Validate protocol
        row["protocol"] = row["protocol"].lower()
        if row["protocol"] not in ("ssh", "telnet"):
            logger.warning("Row %d: skipping - invalid protocol '%s' (must be ssh or telnet)",
                           row_num, row["protocol"])
            continue

        # Validate device_type if provided
        dt = row.get("device_type", "")
        if dt and dt not in DEVICE_TYPE_MAP:
            logger.warning("Row %d: skipping - unknown device_type '%s'. "
                           "Use --list-types to see supported types.",
                           row_num, dt)
            continue

        # Telnet requires device_type
        if row["protocol"] == "telnet" and not dt:
            logger.warning("Row %d: skipping - Telnet requires device_type to be specified",
                           row_num)
            continue

        # Fill default port
        port_str = row.get("port", "")
        if port_str:
            try:
                port = int(port_str)
                if not 1 <= port <= 65535:
                    raise ValueError
                row["port"] = str(port)
            except ValueError:
                logger.warning("Row %d: skipping - invalid port '%s'", row_num, port_str)
                continue
        else:
            row["port"] = "22" if row["protocol"] == "ssh" else "23"

        # Fill defaults
        row.setdefault("enable_password", "")
        row.setdefault("hostname", "")
        row.setdefault("device_type", "")
        row.setdefault("location", "")
        # Preserve raw hostname to decide dir/file naming
        row["raw_hostname"] = row["hostname"]
        if not row["hostname"]:
            row["hostname"] = row["ip"]

        devices.append(row)

    if not devices:
        logger.error("No valid devices found in CSV file: %s", file_path)
        sys.exit(1)

    # Warn about duplicate IPs
    seen_ips: Dict[str, int] = {}
    for dev in devices:
        ip = dev["ip"]
        if ip in seen_ips:
            logger.warning("Duplicate IP '%s' found in CSV (rows %d and later). "
                           "Only the last entry will be used during pre-check mapping.",
                           ip, seen_ips[ip])
        seen_ips[ip] = seen_ips.get(ip, 0) + 1

    logger.info("Loaded %d device(s) from %s", len(devices), file_path)
    return devices


# ============================================================================
# Device type detection
# ============================================================================

def _run_ssh_detect(detect_params: dict) -> Optional[str]:
    """Run SSHDetect in a way that can be killed by ThreadPoolExecutor timeout."""
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        guesser = SSHDetect(**detect_params)
        best_match = guesser.autodetect()
        guesser.connection.disconnect()
        return best_match
    finally:
        sys.stderr = old_stderr


def detect_device_type(device_info: Dict[str, str], timeout: int,
                       logger: logging.Logger) -> Optional[str]:
    """Auto-detect device type via SSH. Returns netmiko device_type or None."""
    if device_info["protocol"] != "ssh":
        return None

    ip = device_info["ip"]

    try:
        detect_params = {
            "device_type": "autodetect",
            "host": ip,
            "username": device_info["username"],
            "password": device_info["password"],
            "port": int(device_info["port"]),
            "timeout": timeout,
            "conn_timeout": timeout,
        }
        if device_info.get("enable_password"):
            detect_params["secret"] = device_info["enable_password"]

        # Use a hard timeout via thread to prevent SSHDetect from hanging
        # (some devices like RouterOS cause SSHDetect to hang indefinitely)
        hard_timeout = timeout + 15
        with ThreadPoolExecutor(max_workers=1) as detect_executor:
            future = detect_executor.submit(_run_ssh_detect, detect_params)
            try:
                best_match = future.result(timeout=hard_timeout)
            except Exception as e:
                logger.debug("[%s] SSHDetect timed out after %ds: %s",
                             ip, hard_timeout, str(e))
                future.cancel()
                return None

        if best_match:
            logger.info("[%s] Auto-detected device type: %s", ip, best_match)
            return best_match
        else:
            logger.debug("[%s] SSHDetect returned no match", ip)
            return None
    except Exception as e:
        logger.debug("[%s] SSHDetect failed: %s", ip, str(e))
        return None


def resolve_device_type(device_info: Dict[str, str], timeout: int,
                        logger: logging.Logger) -> str:
    """
    Resolve netmiko device_type:
    - If CSV device_type is specified: use it directly (skip auto-detect)
    - If CSV device_type is empty: try SSHDetect auto-detection (SSH only)
    - If both fail: raise ValueError

    Auto-detection is skipped when device_type is specified because some
    devices (e.g., MikroTik RouterOS) cause SSHDetect to hang indefinitely.
    """
    ip = device_info["ip"]
    csv_type = device_info.get("device_type", "")

    # If user specified device_type in CSV, use it directly
    if csv_type and csv_type in DEVICE_TYPE_MAP:
        ssh_type, telnet_type = DEVICE_TYPE_MAP[csv_type]
        netmiko_type = ssh_type if device_info["protocol"] == "ssh" else telnet_type
        logger.info("[%s] Using CSV device_type '%s' -> '%s'", ip, csv_type, netmiko_type)
        return netmiko_type

    # device_type not specified: try auto-detection (SSH only)
    detected = detect_device_type(device_info, timeout, logger)
    if detected:
        return detected

    # Both failed
    raise ValueError(
        "Cannot determine device type: device_type not specified in CSV "
        "and SSH auto-detection failed. Please specify device_type in CSV "
        "or use --list-types to see supported types."
    )


def get_device_type_label(device_info: Dict[str, str], netmiko_type: str) -> str:
    """Get a short device type label for directory/file naming."""
    csv_type = device_info.get("device_type", "")
    if csv_type:
        return csv_type
    return NETMIKO_TO_CSV_TYPE.get(netmiko_type, netmiko_type)


def fingerprint_device_type(conn, csv_type: str, ip: str,
                            logger: logging.Logger) -> Optional[str]:
    """
    Send a version command and match output against known fingerprints.
    Returns detected csv_type or None if unable to determine.
    """
    version_cmd = VERSION_COMMANDS.get(csv_type)
    if not version_cmd:
        return None

    try:
        output = conn.send_command_timing(version_cmd, delay_factor=2)
        if not output or not output.strip():
            logger.debug("[%s] Fingerprint: version command returned empty output", ip)
            return None

        for fp_type, fp_regex in DEVICE_FINGERPRINTS:
            if fp_regex.search(output):
                logger.debug("[%s] Fingerprint matched: '%s' (pattern: %s)",
                             ip, fp_type, fp_regex.pattern)
                return fp_type

        logger.debug("[%s] Fingerprint: no pattern matched version output", ip)
        return None
    except Exception as e:
        logger.debug("[%s] Fingerprint command failed: %s", ip, str(e))
        return None


# ============================================================================
# Config command and paging helpers
# ============================================================================

def get_config_command(netmiko_type: str, logger: logging.Logger) -> str:
    """Get the config fetch command for a given netmiko device type."""
    cmd = NETMIKO_TYPE_TO_COMMAND.get(netmiko_type)
    if cmd:
        return cmd
    logger.warning("Unknown netmiko type '%s', using default 'show running-config'",
                   netmiko_type)
    return "show running-config"


def disable_paging(conn, netmiko_type: str, logger: logging.Logger) -> None:
    """Send disable paging command(s) to device."""
    if netmiko_type == "fortinet":
        for cmd in FORTINET_DISABLE_PAGING:
            conn.send_command_timing(cmd)
        logger.debug("[%s] Disabled paging (Fortinet multi-step)", conn.host)
        return

    cmd = DISABLE_PAGING_COMMANDS.get(netmiko_type)
    if cmd:
        conn.send_command_timing(cmd)
        logger.debug("[%s] Disabled paging: %s", conn.host, cmd)


# ============================================================================
# Config validation
# ============================================================================

def validate_config(config: str, netmiko_type: str,
                    logger: logging.Logger, ip: str) -> Tuple[bool, str]:
    """
    Validate fetched config completeness.
    Returns (is_valid, warning_message).
    is_valid=False means config is empty/unusable.
    warning_message non-empty means saved as .incomplete.
    """
    # Check 1: Non-empty
    stripped = config.strip()
    if not stripped:
        return False, "Config output is empty"

    lines = stripped.splitlines()
    if len(lines) < 5:
        return False, f"Config has only {len(lines)} lines (expected >= 5)"

    warnings = []

    # Check 2: Paging residue
    if PAGING_RESIDUE_RE.search(config):
        logger.warning("[%s] Paging prompt residue found in config output", ip)
        warnings.append("Paging prompt residue detected")

    # Check 3: End marker
    end_marker = CONFIG_END_MARKERS.get(netmiko_type)
    if end_marker is not None:
        tail_lines = [line.strip() for line in lines[-10:]]
        found = any(line == end_marker for line in tail_lines)
        if not found:
            logger.warning("[%s] Config end marker '%s' not found in last 10 lines",
                           ip, end_marker)
            warnings.append(f"End marker '{end_marker}' not found")

    if warnings:
        return True, "; ".join(warnings)

    return True, ""


# ============================================================================
# Connection helper with retry
# ============================================================================

def connect_with_retry(conn_params: dict, ip: str, logger: logging.Logger,
                       max_retries: int = 1) -> "ConnectHandler":
    """
    Establish a netmiko connection with automatic retry on timeout.
    Retries once by default to handle intermittent network slowness.
    """
    for attempt in range(1 + max_retries):
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            conn = ConnectHandler(**conn_params)
            return conn
        except NetmikoTimeoutException:
            if attempt < max_retries:
                logger.warning("[%s] Connection timed out, retrying (%d/%d)...",
                               ip, attempt + 1, max_retries)
                time.sleep(2)
            else:
                raise
        finally:
            sys.stderr = old_stderr


# ============================================================================
# Pre-check
# ============================================================================

def precheck_single_device(device_info: Dict[str, str], timeout: int,
                           logger: logging.Logger) -> PrecheckResult:
    """
    Pre-check: verify connectivity and detect device type.
    Does NOT fetch config. Disconnects immediately after verification.
    """
    ip = device_info["ip"]
    hostname = device_info.get("hostname", ip)
    conn = None

    try:
        # Resolve device type (auto-detect or CSV fallback)
        netmiko_type = resolve_device_type(device_info, timeout, logger)

        # Test connection (suppress paramiko stderr noise)
        conn_params = {
            "device_type": netmiko_type,
            "host": ip,
            "username": device_info["username"],
            "password": device_info["password"],
            "port": int(device_info["port"]),
            "timeout": timeout,
            "conn_timeout": timeout,
        }
        if device_info.get("enable_password"):
            conn_params["secret"] = device_info["enable_password"]

        conn = connect_with_retry(conn_params, ip, logger)

        # Test enable if needed
        if device_info.get("enable_password"):
            conn.enable()

        # Fingerprint: verify device type matches CSV claim
        csv_type = device_info.get("device_type", "")
        type_corrected = False
        type_warning = ""
        if csv_type:
            detected = fingerprint_device_type(conn, csv_type, ip, logger)
            if detected:
                equiv = TYPE_EQUIVALENCE_GROUPS.get(csv_type, {csv_type})
                if detected not in equiv:
                    # Mismatch — auto-correct
                    ssh_t, telnet_t = DEVICE_TYPE_MAP[detected]
                    new_netmiko_type = ssh_t if device_info["protocol"] == "ssh" else telnet_t
                    type_warning = f"{csv_type} -> {detected}"
                    logger.warning(
                        "[%s] (%s) Type mismatch: CSV='%s' but detected '%s'. "
                        "Auto-correcting netmiko type: %s -> %s",
                        ip, hostname, csv_type, detected, netmiko_type, new_netmiko_type)
                    netmiko_type = new_netmiko_type
                    type_corrected = True
                else:
                    logger.debug("[%s] Fingerprint confirmed: %s", ip, detected)

        conn.disconnect()
        conn = None

        log_suffix = f" (auto-corrected: {type_warning})" if type_corrected else ""
        logger.info("[%s] (%s) Pre-check passed - type: %s%s", ip, hostname, netmiko_type, log_suffix)
        return PrecheckResult(
            ip=ip, hostname=hostname, success=True,
            netmiko_type=netmiko_type,
            csv_device_type=device_info.get("device_type", ""),
            type_corrected=type_corrected,
            type_warning=type_warning,
        )

    except NetmikoTimeoutException:
        msg = "Connection timed out"
        logger.error("[%s] (%s) Pre-check failed: %s", ip, hostname, msg)
        return PrecheckResult(ip=ip, hostname=hostname, success=False, error=msg)
    except NetmikoAuthenticationException:
        msg = "Authentication failed"
        logger.error("[%s] (%s) Pre-check failed: %s", ip, hostname, msg)
        return PrecheckResult(ip=ip, hostname=hostname, success=False, error=msg)
    except ValueError as e:
        msg = str(e)
        logger.error("[%s] (%s) Pre-check failed: %s", ip, hostname, msg)
        return PrecheckResult(ip=ip, hostname=hostname, success=False, error=msg)
    except Exception as e:
        msg = f"Unexpected error: {str(e)}"
        logger.error("[%s] (%s) Pre-check failed: %s", ip, hostname, msg)
        return PrecheckResult(ip=ip, hostname=hostname, success=False, error=msg)
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def run_precheck(devices: List[Dict[str, str]], workers: int, timeout: int,
                 logger: logging.Logger) -> List[PrecheckResult]:
    """Run pre-check on all devices concurrently. Returns list of results."""
    results = []
    total = len(devices)

    logger.info("Starting pre-check for %d device(s) with %d thread(s)...", total, workers)
    print()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(precheck_single_device, dev, timeout, logger): dev
            for dev in devices
        }
        for i, future in enumerate(as_completed(future_map), start=1):
            result = future.result()
            results.append(result)
            if not result.success:
                status = "FAILED"
            elif result.type_corrected:
                status = f"OK (type corrected: {result.type_warning})"
            else:
                status = "OK"
            print(f"  Pre-check [{i}/{total}] {result.ip} ({result.hostname}): {status}",
                  flush=True)

    return results


def print_precheck_report(results: List[PrecheckResult],
                          skip_unreachable: bool,
                          logger: logging.Logger) -> Tuple[bool, List[PrecheckResult]]:
    """
    Print pre-check report.
    Returns (should_continue, passed_results).
    - Default mode: should_continue=True only if ALL passed.
    - --skip-unreachable: should_continue=True if ANY passed, failed devices skipped.
    """
    failed = [r for r in results if not r.success]
    passed = [r for r in results if r.success]
    corrected = [r for r in passed if r.type_corrected]

    # Print type correction summary if any
    if corrected:
        corr_lines = [
            "",
            "=" * 60,
            f"  Pre-check: {len(corrected)} device(s) had device_type auto-corrected:",
            "-" * 60,
        ]
        for i, r in enumerate(corrected, start=1):
            corr_lines.append(f"  {i}. {r.ip:<16} ({r.hostname}) {r.type_warning}")
        corr_lines.append("-" * 60)
        corr_lines.append("  Backup will use the corrected type.")
        corr_lines.append("  Consider updating your CSV to avoid future warnings.")
        corr_lines.append("=" * 60)
        print("\n".join(corr_lines))

    if not failed:
        logger.info("Pre-check passed: all %d device(s) reachable", len(results))
        print(f"\n  Pre-check PASSED: all {len(results)} device(s) are reachable.\n")
        return True, passed

    logger.error("Pre-check failed: %d/%d device(s) unreachable", len(failed), len(results))
    for r in failed:
        logger.error("  FAILED: %s (%s) - %s", r.ip, r.hostname, r.error)

    msg_lines = [
        "",
        "=" * 60,
        f"  Pre-check: {len(failed)}/{len(results)} device(s) cannot be reached:",
        "-" * 60,
    ]
    for i, r in enumerate(failed, start=1):
        msg_lines.append(f"  {i}. {r.ip:<16} ({r.hostname}) - {r.error}")
    msg_lines.append("=" * 60)

    if skip_unreachable:
        if not passed:
            msg_lines.append("  No reachable devices. Aborting.")
            msg_lines.append("=" * 60)
            msg_lines.append("")
            print("\n".join(msg_lines))
            return False, []
        msg_lines.append(f"  --skip-unreachable: continuing with {len(passed)} reachable device(s).")
        msg_lines.append(f"  Skipping {len(failed)} unreachable device(s).")
        msg_lines.append("=" * 60)
        msg_lines.append("")
        print("\n".join(msg_lines))
        return True, passed
    else:
        msg_lines.append("  Please fix the corresponding entries and re-run.")
        msg_lines.append("  Or use --skip-unreachable to skip failed devices.")
        msg_lines.append("=" * 60)
        msg_lines.append("")
        print("\n".join(msg_lines))
        return False, []


# ============================================================================
# Backup
# ============================================================================

def backup_single_device(device_info: Dict[str, str], output_dir: str,
                         timeout: int, read_timeout: int, run_timestamp: str,
                         logger: logging.Logger) -> BackupResult:
    """Backup config from a single device. Uses pre-checked netmiko type."""
    ip = device_info["ip"]
    hostname = device_info.get("hostname", ip)
    netmiko_type = device_info["resolved_netmiko_type"]
    type_label = device_info["resolved_type_label"]
    start_time = time.time()
    conn = None

    try:
        # Connect (suppress paramiko stderr noise)
        conn_params = {
            "device_type": netmiko_type,
            "host": ip,
            "username": device_info["username"],
            "password": device_info["password"],
            "port": int(device_info["port"]),
            "timeout": timeout,
            "conn_timeout": timeout,
        }
        if device_info.get("enable_password"):
            conn_params["secret"] = device_info["enable_password"]

        conn = connect_with_retry(conn_params, ip, logger)

        # Enable privileged mode first (before disable paging)
        # Some devices (e.g., Huawei super) reset paging settings on privilege change
        if device_info.get("enable_password"):
            conn.enable()

        # Disable paging (extra safeguard on top of netmiko's built-in handling)
        disable_paging(conn, netmiko_type, logger)

        # Fetch config (read-only command only)
        config_cmd = get_config_command(netmiko_type, logger)
        logger.info("[%s] Fetching config: %s (read_timeout=%ds)", ip, config_cmd, read_timeout)

        # H3C Comware: always use send_command_timing() because send_command()
        # frequently truncates large configs — the prompt pattern <hostname>
        # can match mid-output, causing premature return and inconsistent results.
        if netmiko_type in ("hp_comware", "hp_comware_telnet"):
            config_output = conn.send_command_timing(
                config_cmd, delay_factor=4, max_loops=500)
        else:
            config_output = conn.send_command(config_cmd, read_timeout=read_timeout)

        # Retry with send_command_timing if output is empty
        # Some devices have intermittent prompt detection issues
        # that cause send_command() to return empty. send_command_timing() uses
        # time-based detection which is more robust as a fallback.
        if not config_output.strip():
            logger.warning("[%s] Config output empty, retrying with send_command_timing...", ip)
            time.sleep(1)
            conn.read_channel()  # clear residual buffer
            config_output = conn.send_command_timing(
                config_cmd, delay_factor=4, max_loops=500)

        # Disconnect
        conn.disconnect()
        conn = None

        duration = time.time() - start_time

        # Validate config
        is_valid, warning = validate_config(config_output, netmiko_type, logger, ip)

        if not is_valid:
            logger.error("[%s] Config validation failed: %s", ip, warning)
            return BackupResult(
                ip=ip, hostname=hostname, success=False,
                error=warning, duration=duration, detected_type=netmiko_type,
            )

        # Build output path
        # Location determines the top-level subdirectory under output_dir
        location = device_info.get("location", "").strip()
        if not location:
            location = "default"
        location_dir = os.path.join(output_dir, location)

        # Include hostname in dir/file name if user provided one (not just IP)
        raw_hostname = device_info.get("raw_hostname", "")
        if raw_hostname:
            name_prefix = f"{ip}_{type_label}_{raw_hostname}"
        else:
            name_prefix = f"{ip}_{type_label}"

        device_dir = os.path.join(location_dir, name_prefix)
        os.makedirs(device_dir, exist_ok=True)

        if warning:
            file_name = f"{name_prefix}_{run_timestamp}.incomplete.txt"
        else:
            file_name = f"{name_prefix}_{run_timestamp}.txt"

        file_path = os.path.join(device_dir, file_name)

        # Save config
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(config_output)

        logger.info("[%s] Config saved: %s (%.1fs)", ip, file_path, duration)

        return BackupResult(
            ip=ip, hostname=hostname, success=True,
            file_path=file_path, warning=warning,
            duration=duration, detected_type=netmiko_type,
        )

    except NetmikoTimeoutException:
        msg = "Connection timed out"
        logger.error("[%s] Backup failed: %s", ip, msg)
        return BackupResult(ip=ip, hostname=hostname, success=False,
                            error=msg, duration=time.time() - start_time,
                            detected_type=netmiko_type)
    except NetmikoAuthenticationException:
        msg = "Authentication failed"
        logger.error("[%s] Backup failed: %s", ip, msg)
        return BackupResult(ip=ip, hostname=hostname, success=False,
                            error=msg, duration=time.time() - start_time,
                            detected_type=netmiko_type)
    except ReadTimeout:
        msg = "Command execution timed out (read_timeout)"
        logger.error("[%s] Backup failed: %s", ip, msg)
        return BackupResult(ip=ip, hostname=hostname, success=False,
                            error=msg, duration=time.time() - start_time,
                            detected_type=netmiko_type)
    except OSError as e:
        msg = f"Failed to save file: {str(e)}"
        logger.error("[%s] Backup failed: %s", ip, msg)
        return BackupResult(ip=ip, hostname=hostname, success=False,
                            error=msg, duration=time.time() - start_time,
                            detected_type=netmiko_type)
    except Exception as e:
        msg = f"Unexpected error: {str(e)}"
        logger.error("[%s] Backup failed: %s", ip, msg)
        return BackupResult(ip=ip, hostname=hostname, success=False,
                            error=msg, duration=time.time() - start_time,
                            detected_type=netmiko_type)
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def run_backup(devices: List[Dict[str, str]], output_dir: str,
               workers: int, timeout: int, read_timeout: int, run_timestamp: str,
               logger: logging.Logger) -> List[BackupResult]:
    """Run backup on all devices concurrently."""
    results = []
    total = len(devices)

    logger.info("Starting backup for %d device(s) with %d thread(s)...", total, workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(backup_single_device, dev, output_dir,
                            timeout, read_timeout, run_timestamp, logger): dev
            for dev in devices
        }
        for i, future in enumerate(as_completed(future_map), start=1):
            result = future.result()
            results.append(result)
            if result.success:
                status = "OK" if not result.warning else "WARNING"
            else:
                status = "FAILED"
            print(f"  Backup [{i}/{total}] {result.ip} ({result.hostname}): {status}")

    return results


# ============================================================================
# Summary report
# ============================================================================

def print_summary(results: List[BackupResult], skipped_count: int,
                  precheck_results: List["PrecheckResult"],
                  start_time: float, logger: logging.Logger) -> None:
    """Print final backup summary report."""
    backup_total = len(results)
    succeeded = [r for r in results if r.success and not r.warning]
    warnings = [r for r in results if r.success and r.warning]
    failed = [r for r in results if not r.success]
    overall_total = backup_total + skipped_count
    elapsed = time.time() - start_time

    corrected = [r for r in precheck_results if r.type_corrected]
    unreachable = [r for r in precheck_results if not r.success]

    lines = [
        "",
        "=" * 60,
        "  Network Device Configuration Backup Report",
        f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Elapsed   : {elapsed:.1f}s",
        "=" * 60,
        f"  Total devices : {overall_total}",
        f"  Succeeded     : {len(succeeded)}",
        f"  Warnings      : {len(warnings)}",
        f"  Failed        : {len(failed)}",
        f"  Skipped       : {skipped_count}",
    ]

    if skipped_count > 0:
        lines.append("-" * 60)
        lines.append(f"  {skipped_count} device(s) skipped (unreachable during pre-check):")
        for i, r in enumerate(unreachable, start=1):
            lines.append(f"    {i}. {r.ip:<16} ({r.hostname}) - {r.error}")

    if corrected:
        lines.append("-" * 60)
        lines.append(f"  {len(corrected)} device(s) had device_type auto-corrected:")
        for i, r in enumerate(corrected, start=1):
            lines.append(f"    {i}. {r.ip:<16} ({r.hostname}) {r.type_warning}")
        lines.append("  Consider updating your CSV to avoid future warnings.")

    if warnings:
        lines.append("-" * 60)
        lines.append("  Devices with warnings (saved as .incomplete.txt):")
        for i, r in enumerate(warnings, start=1):
            lines.append(f"    {i}. {r.ip:<16} ({r.hostname}) - {r.warning}")
            if r.file_path:
                lines.append(f"       File: {r.file_path}")

    if failed:
        lines.append("-" * 60)
        lines.append("  Failed devices:")
        for i, r in enumerate(failed, start=1):
            lines.append(f"    {i}. {r.ip:<16} ({r.hostname}) - {r.error}")

    lines.append("=" * 60)
    lines.append("")

    report = "\n".join(lines)
    print(report)

    logger.info("Backup complete: %d succeeded, %d warnings, %d failed, %d skipped, %.1fs elapsed",
                len(succeeded), len(warnings), len(failed), skipped_count, elapsed)


# ============================================================================
# Config diff
# ============================================================================

@dataclass
class DeviceDiffResult:
    """Diff result for a single device."""
    ip: str
    hostname: str
    device_type: str
    location: str
    backup_dir: str
    files_found: int
    pairs_compared: int
    pairs_changed: int
    error: str = ""


def filter_timestamp_lines(lines: List[str]) -> List[str]:
    """Remove lines matching DIFF_IGNORE_PATTERNS (auto-generated timestamps)."""
    result = []
    for line in lines:
        stripped = line.strip()
        if any(p.search(stripped) for p in DIFF_IGNORE_PATTERNS):
            continue
        result.append(line)
    return result


def find_backup_dir_for_device(device_info: Dict[str, str],
                               output_dir: str) -> Optional[str]:
    """
    Find the backup directory for a device under output_dir.
    Searches backups/<location>/ for a directory starting with <IP>_.
    Returns the first match or None.
    """
    ip = device_info["ip"]
    location = device_info.get("location", "").strip() or "default"
    location_dir = os.path.join(output_dir, location)

    if not os.path.isdir(location_dir):
        return None

    for entry in os.listdir(location_dir):
        if entry.startswith(f"{ip}_") and os.path.isdir(
                os.path.join(location_dir, entry)):
            return os.path.join(location_dir, entry)
    return None


def find_latest_backups(backup_dir: str, count: int = 5) -> List[str]:
    """
    Find the latest N backup files in a device backup directory.
    Only considers .txt files (excludes .incomplete.txt).
    Returns file paths sorted newest-first.
    """
    if not os.path.isdir(backup_dir):
        return []

    txt_files = []
    for f in os.listdir(backup_dir):
        if f.endswith(".txt") and not f.endswith(".incomplete.txt"):
            txt_files.append(os.path.join(backup_dir, f))

    # Sort by modification time, newest first
    txt_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return txt_files[:count]


def generate_diff_html(devices: List[Dict[str, str]], output_dir: str,
                       diff_count: int, no_filter: bool,
                       logger: logging.Logger) -> Optional[str]:
    """
    Generate an HTML diff report comparing the latest N backups for each device.
    Returns the output file path, or None if no diffs to report.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = os.path.join(output_dir, f"diff_report_{timestamp}.html")
    filter_active = not no_filter

    device_results: List[DeviceDiffResult] = []
    diff_sections: List[str] = []

    for dev in devices:
        ip = dev["ip"]
        hostname = dev.get("hostname", ip)
        device_type = dev.get("device_type", "unknown")
        location = dev.get("location", "").strip() or "default"

        backup_dir = find_backup_dir_for_device(dev, output_dir)
        if not backup_dir:
            device_results.append(DeviceDiffResult(
                ip=ip, hostname=hostname, device_type=device_type,
                location=location, backup_dir="",
                files_found=0, pairs_compared=0, pairs_changed=0,
                error="No backup directory found",
            ))
            continue

        files = find_latest_backups(backup_dir, diff_count)
        if len(files) < 2:
            device_results.append(DeviceDiffResult(
                ip=ip, hostname=hostname, device_type=device_type,
                location=location, backup_dir=backup_dir,
                files_found=len(files), pairs_compared=0, pairs_changed=0,
                error=f"Only {len(files)} backup(s), need at least 2 to compare",
            ))
            continue

        pairs_compared = 0
        pairs_changed = 0
        pair_htmls: List[str] = []

        # Compare adjacent pairs: newest vs 2nd, 2nd vs 3rd, ...
        for i in range(len(files) - 1):
            newer_path = files[i]
            older_path = files[i + 1]
            newer_name = os.path.basename(newer_path)
            older_name = os.path.basename(older_path)

            with open(older_path, "r", encoding="utf-8", errors="replace") as f:
                older_lines = f.readlines()
            with open(newer_path, "r", encoding="utf-8", errors="replace") as f:
                newer_lines = f.readlines()

            # Apply timestamp filter before comparison
            if filter_active:
                older_filtered = filter_timestamp_lines(older_lines)
                newer_filtered = filter_timestamp_lines(newer_lines)
            else:
                older_filtered = older_lines
                newer_filtered = newer_lines

            pairs_compared += 1

            # Check if identical (after filtering)
            if older_filtered == newer_filtered:
                pair_htmls.append(
                    f'<div class="pair no-change">'
                    f'<h4>{older_name} &rarr; {newer_name}</h4>'
                    f'<p class="identical">No changes detected</p>'
                    f'</div>'
                )
                continue

            pairs_changed += 1

            # Generate unified diff (using filtered lines)
            diff_lines = list(difflib.unified_diff(
                older_filtered, newer_filtered,
                fromfile=older_name, tofile=newer_name,
                lineterm="",
            ))

            diff_html_lines = []
            for line in diff_lines:
                line_stripped = line.rstrip("\n")
                escaped = (line_stripped
                           .replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;"))
                if line_stripped.startswith("+++") or line_stripped.startswith("---"):
                    diff_html_lines.append(
                        f'<span class="diff-file">{escaped}</span>')
                elif line_stripped.startswith("@@"):
                    diff_html_lines.append(
                        f'<span class="diff-hunk">{escaped}</span>')
                elif line_stripped.startswith("+"):
                    diff_html_lines.append(
                        f'<span class="diff-add">{escaped}</span>')
                elif line_stripped.startswith("-"):
                    diff_html_lines.append(
                        f'<span class="diff-del">{escaped}</span>')
                else:
                    diff_html_lines.append(escaped)

            pair_htmls.append(
                f'<div class="pair changed">'
                f'<h4>{older_name} &rarr; {newer_name}</h4>'
                f'<pre class="diff-block">{"<br>".join(diff_html_lines)}</pre>'
                f'</div>'
            )

        device_results.append(DeviceDiffResult(
            ip=ip, hostname=hostname, device_type=device_type,
            location=location, backup_dir=backup_dir,
            files_found=len(files), pairs_compared=pairs_compared,
            pairs_changed=pairs_changed,
        ))

        # Build device section
        status_badge = (
            '<span class="badge changed">Changes Found</span>'
            if pairs_changed > 0
            else '<span class="badge unchanged">No Changes</span>'
        )
        diff_sections.append(
            f'<div class="device-section">'
            f'<h3>{ip} ({hostname}) '
            f'<span class="type-tag">{device_type}</span> '
            f'<span class="loc-tag">{location}</span> '
            f'{status_badge}'
            f'</h3>'
            f'<p class="meta">Backups found: {len(files)} | '
            f'Pairs compared: {pairs_compared} | '
            f'Changed: {pairs_changed}</p>'
            f'{"".join(pair_htmls)}'
            f'</div>'
        )

    # Build full HTML
    total_devices = len(device_results)
    devices_with_changes = sum(1 for r in device_results if r.pairs_changed > 0)
    devices_no_changes = sum(1 for r in device_results
                             if r.pairs_compared > 0 and r.pairs_changed == 0)
    devices_skipped = sum(1 for r in device_results if r.error)

    # Skipped devices section
    skipped_html = ""
    skipped_results = [r for r in device_results if r.error]
    if skipped_results:
        rows = []
        for r in skipped_results:
            rows.append(
                f'<tr><td>{r.ip}</td><td>{r.hostname}</td>'
                f'<td>{r.device_type}</td><td>{r.error}</td></tr>'
            )
        skipped_html = (
            '<div class="device-section skipped">'
            '<h3>Skipped Devices</h3>'
            '<table><tr><th>IP</th><th>Hostname</th>'
            '<th>Type</th><th>Reason</th></tr>'
            f'{"".join(rows)}'
            '</table></div>'
        )

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Config Diff Report - {timestamp}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px;
         background: #f5f5f5; color: #333; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
  h2 {{ color: #2c3e50; margin-top: 30px; }}
  h3 {{ color: #34495e; border-bottom: 1px solid #ddd; padding-bottom: 8px; }}
  h4 {{ color: #555; margin: 10px 0 5px; }}
  .summary {{ background: #fff; padding: 20px; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 15px; }}
  .summary-card {{ text-align: center; padding: 15px; border-radius: 6px; }}
  .summary-card .number {{ font-size: 2em; font-weight: bold; }}
  .summary-card .label {{ font-size: 0.9em; color: #777; }}
  .card-total {{ background: #eef2f7; }}
  .card-total .number {{ color: #2c3e50; }}
  .card-changed {{ background: #fef5e7; }}
  .card-changed .number {{ color: #e67e22; }}
  .card-unchanged {{ background: #eafaf1; }}
  .card-unchanged .number {{ color: #27ae60; }}
  .card-skipped {{ background: #fdecea; }}
  .card-skipped .number {{ color: #e74c3c; }}
  .device-section {{ background: #fff; padding: 20px; border-radius: 8px;
                     box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
  .meta {{ color: #888; font-size: 0.9em; }}
  .type-tag {{ background: #3498db; color: #fff; padding: 2px 8px;
               border-radius: 4px; font-size: 0.8em; }}
  .loc-tag {{ background: #9b59b6; color: #fff; padding: 2px 8px;
              border-radius: 4px; font-size: 0.8em; }}
  .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.8em; }}
  .badge.changed {{ background: #e67e22; color: #fff; }}
  .badge.unchanged {{ background: #27ae60; color: #fff; }}
  .pair {{ margin: 15px 0; padding: 10px; border: 1px solid #eee;
           border-radius: 4px; }}
  .pair.changed {{ border-left: 4px solid #e67e22; }}
  .pair.no-change {{ border-left: 4px solid #27ae60; }}
  .identical {{ color: #27ae60; font-style: italic; }}
  .diff-block {{ background: #1e1e1e; color: #d4d4d4; padding: 15px;
                 border-radius: 4px; overflow-x: auto; font-size: 13px;
                 line-height: 1.5; white-space: pre; }}
  .diff-add {{ color: #4ec9b0; background: rgba(78, 201, 176, 0.1); }}
  .diff-del {{ color: #f44747; background: rgba(244, 71, 71, 0.1); }}
  .diff-hunk {{ color: #569cd6; }}
  .diff-file {{ color: #dcdcaa; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #f8f9fa; color: #555; }}
  .footer {{ text-align: center; color: #aaa; font-size: 0.8em;
             margin-top: 30px; padding: 10px; }}
</style>
</head>
<body>
<div class="container">
<h1>Configuration Diff Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
   Comparing latest {diff_count} backups per device |
   Timestamp filter: {"ON" if filter_active else "OFF"}</p>

<div class="summary">
<div class="summary-grid">
  <div class="summary-card card-total">
    <div class="number">{total_devices}</div>
    <div class="label">Total Devices</div>
  </div>
  <div class="summary-card card-changed">
    <div class="number">{devices_with_changes}</div>
    <div class="label">With Changes</div>
  </div>
  <div class="summary-card card-unchanged">
    <div class="number">{devices_no_changes}</div>
    <div class="label">No Changes</div>
  </div>
  <div class="summary-card card-skipped">
    <div class="number">{devices_skipped}</div>
    <div class="label">Skipped</div>
  </div>
</div>
</div>

<h2>Device Details</h2>
{"".join(diff_sections)}
{skipped_html}

<div class="footer">
  Generated by NetConfigArk &mdash; Network Device Configuration Backup Tool
</div>
</div>
</body>
</html>"""

    os.makedirs(output_dir, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)

    return report_file


def do_diff(csv_path: str, output_dir: str, diff_count: int,
            no_filter: bool, logger: logging.Logger) -> None:
    """Run config diff mode: compare latest N backups for each device in CSV."""
    devices = parse_csv(csv_path, logger)

    filter_label = "OFF (--no-filter)" if no_filter else "ON"
    print(f"\n--- Config Diff: comparing latest {diff_count} backups per device "
          f"(timestamp filter: {filter_label}) ---\n")

    report_path = generate_diff_html(devices, output_dir, diff_count, no_filter, logger)

    if report_path:
        print(f"\n  Diff report generated: {report_path}")
        print(f"  Open in browser to view.\n")
    else:
        print("\n  No diff report generated (no devices to compare).\n")


# ============================================================================
# Config viewer
# ============================================================================

def _syntax_highlight_config(text: str) -> str:
    """
    Apply syntax highlighting to network device config text.
    Returns HTML with <span> tags for coloring.
    Uses regex-based highlighting tuned for network device configs.
    """
    import html as html_mod

    lines = text.splitlines()
    result_lines: List[str] = []

    # Pre-compile patterns
    comment_re = re.compile(r"^(\s*)(#.*|!.*)$")
    section_header_re = re.compile(
        r"^(\s*)(interface\s+|router\s+|ip\s+route|vlan\s+|acl\s+|"
        r"rule\s+|policy\s+|security-zone\s+|firewall\s+|"
        r"bgp\s+|ospf\s+|mpls\s+|aaa|ntp|dns|snmp|logging|sysname|"
        r"system-view|user-interface|"
        r"set\s+|config\s+|edit\s+)", re.IGNORECASE)
    keyword_re = re.compile(
        r"\b(permit|deny|enable|disable|shutdown|no\s+shutdown|"
        r"description|switchport|vlanif|loopback|GigabitEthernet|"
        r"FastEthernet|Ethernet|Vlanif|undo|display|show|"
        r"ip\s+address|mask|gateway|default-route|"
        r"trunk|access|hybrid|port|quit|return|end|"
        r"password|secret|authentication|authorization|accounting)\b", re.IGNORECASE)
    ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")
    number_re = re.compile(r"\b(\d+)\b")
    string_re = re.compile(r'("(?:[^"\\]|\\.)*")')

    for line in lines:
        escaped = html_mod.escape(line)

        # Comment lines (# or !)
        m = comment_re.match(line)
        if m:
            result_lines.append(f'<span class="hl-comment">{escaped}</span>')
            continue

        # Section headers get special treatment
        m = section_header_re.match(line)
        is_section = bool(m)

        # Apply highlighting in order: strings -> IPs -> keywords -> numbers
        # We use a placeholder approach to avoid double-replacing
        placeholders: List[str] = []
        placeholder_idx = 0

        def _replace_and_store(pattern, css_class, text_val):
            nonlocal placeholder_idx
            result = text_val

            def replacer(match):
                nonlocal placeholder_idx
                ph = f"\x00PH{placeholder_idx}\x00"
                placeholders.append(f'<span class="{css_class}">{html_mod.escape(match.group(0))}</span>')
                placeholder_idx += 1
                return ph
            result = pattern.sub(replacer, result)
            return result

        processed = line
        processed = _replace_and_store(string_re, "hl-string", processed)
        processed = _replace_and_store(ip_re, "hl-ip", processed)
        processed = _replace_and_store(keyword_re, "hl-keyword", processed)
        processed = _replace_and_store(number_re, "hl-number", processed)

        # Escape remaining text (but not placeholders)
        parts = re.split(r"(\x00PH\d+\x00)", processed)
        final_parts = []
        for part in parts:
            ph_match = re.match(r"\x00PH(\d+)\x00", part)
            if ph_match:
                final_parts.append(placeholders[int(ph_match.group(1))])
            else:
                final_parts.append(html_mod.escape(part))

        final_line = "".join(final_parts)
        if is_section:
            final_line = f'<span class="hl-section">{final_line}</span>'

        result_lines.append(final_line)

    return "\n".join(result_lines)


def generate_view_html(devices: List[Dict[str, str]], output_dir: str,
                       logger: logging.Logger) -> Optional[str]:
    """
    Generate a self-contained HTML config viewer page.
    Shows the latest backup for each device with syntax highlighting.
    Returns the output file path, or None if no configs found.
    """
    import html as html_mod

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = os.path.join(output_dir, f"config_view_{timestamp}.html")

    # Collect device configs
    device_entries: List[Dict] = []
    locations: Dict[str, List[int]] = {}  # location -> list of indices

    for dev in devices:
        ip = dev["ip"]
        hostname = dev.get("hostname", ip)
        device_type = dev.get("device_type", "unknown")
        location = dev.get("location", "").strip() or "default"

        backup_dir = find_backup_dir_for_device(dev, output_dir)
        if not backup_dir:
            logger.debug("[%s] No backup directory found, skipping for view", ip)
            continue

        files = find_latest_backups(backup_dir, 1)
        if not files:
            logger.debug("[%s] No backup files found, skipping for view", ip)
            continue

        latest_file = files[0]
        file_stat = os.stat(latest_file)
        file_size = file_stat.st_size
        file_mtime = datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        with open(latest_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)

        # Syntax highlight
        highlighted = _syntax_highlight_config(content)

        idx = len(device_entries)
        entry = {
            "idx": idx,
            "ip": ip,
            "hostname": hostname,
            "device_type": device_type,
            "location": location,
            "file_name": os.path.basename(latest_file),
            "file_size": file_size,
            "file_mtime": file_mtime,
            "line_count": line_count,
            "highlighted": highlighted,
        }
        device_entries.append(entry)

        if location not in locations:
            locations[location] = []
        locations[location].append(idx)

    if not device_entries:
        return None

    # Build sidebar HTML
    sidebar_items: List[str] = []
    sorted_locations = sorted(locations.keys())
    for loc in sorted_locations:
        indices = locations[loc]
        loc_escaped = html_mod.escape(loc)
        items_html = []
        for idx in indices:
            e = device_entries[idx]
            items_html.append(
                f'<div class="sidebar-item" data-idx="{idx}" '
                f'data-search="{html_mod.escape(e["ip"] + " " + e["hostname"] + " " + e["device_type"])}" '
                f'onclick="selectDevice({idx})">'
                f'<div class="item-ip">{html_mod.escape(e["ip"])}</div>'
                f'<div class="item-host">{html_mod.escape(e["hostname"])}</div>'
                f'<div class="item-type">{html_mod.escape(e["device_type"])}</div>'
                f'</div>'
            )
        sidebar_items.append(
            f'<div class="sidebar-group" data-location="{loc_escaped}">'
            f'<div class="group-header">{loc_escaped} '
            f'<span class="group-count">{len(indices)}</span></div>'
            f'{"".join(items_html)}'
            f'</div>'
        )

    # Build config content sections
    config_sections: List[str] = []
    for e in device_entries:
        size_str = f"{e['file_size']:,} bytes" if e['file_size'] < 1024 * 1024 else f"{e['file_size'] / 1024 / 1024:.1f} MB"
        config_sections.append(
            f'<div class="config-panel" id="config-{e["idx"]}" style="display:none;">'
            f'<div class="config-header">'
            f'<div class="config-title">'
            f'<span class="config-ip">{html_mod.escape(e["ip"])}</span>'
            f'<span class="config-hostname">{html_mod.escape(e["hostname"])}</span>'
            f'<span class="config-type-tag">{html_mod.escape(e["device_type"])}</span>'
            f'<span class="config-loc-tag">{html_mod.escape(e["location"])}</span>'
            f'</div>'
            f'<div class="config-meta">'
            f'<span>File: {html_mod.escape(e["file_name"])}</span>'
            f'<span>Backup: {html_mod.escape(e["file_mtime"])}</span>'
            f'<span>Size: {size_str}</span>'
            f'<span>Lines: {e["line_count"]}</span>'
            f'</div>'
            f'</div>'
            f'<div class="config-body"><pre class="config-code"><code>{e["highlighted"]}</code></pre></div>'
            f'</div>'
        )

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Config Viewer - {timestamp}</title>
<style>
  /* ---- Theme variables ---- */
  :root {{
    --bg-body: #1a1a2e;
    --bg-sidebar: #16213e;
    --bg-sidebar-header: #0f3460;
    --border-color: #0f3460;
    --bg-input: #1a1a2e;
    --text-primary: #e0e0e0;
    --text-secondary: #888;
    --text-muted: #555;
    --text-meta: #666;
    --text-footer: #444;
    --accent: #e94560;
    --item-hover: rgba(15, 52, 96, 0.6);
    --item-active-bg: rgba(233, 69, 96, 0.15);
    --group-count-bg: #0f3460;
    --group-count-color: #aaa;
    --scrollbar-thumb: #0f3460;
    --scrollbar-thumb-main: #333;
    --code-bg: #1a1a2e;
    --code-color: #d4d4d4;
    --hl-comment: #6a9955;
    --hl-section: #569cd6;
    --hl-keyword: #c586c0;
    --hl-ip: #4ec9b0;
    --hl-number: #b5cea8;
    --hl-string: #ce9178;
    --type-badge-text: #0f3460;
    --welcome-color: #444;
    --toggle-bg: #0f3460;
    --toggle-hover: rgba(233, 69, 96, 0.2);
  }}
  body.light {{
    --bg-body: #f0f2f5;
    --bg-sidebar: #ffffff;
    --bg-sidebar-header: #e8ecf1;
    --border-color: #d0d7de;
    --bg-input: #f6f8fa;
    --text-primary: #1f2328;
    --text-secondary: #656d76;
    --text-muted: #8b949e;
    --text-meta: #656d76;
    --text-footer: #8b949e;
    --accent: #cf222e;
    --item-hover: rgba(208, 215, 222, 0.5);
    --item-active-bg: rgba(207, 34, 46, 0.08);
    --group-count-bg: #d0d7de;
    --group-count-color: #656d76;
    --scrollbar-thumb: #c0c8d0;
    --scrollbar-thumb-main: #c0c8d0;
    --code-bg: #ffffff;
    --code-color: #1f2328;
    --hl-comment: #6a737d;
    --hl-section: #0550ae;
    --hl-keyword: #8250df;
    --hl-ip: #0a3069;
    --hl-number: #0550ae;
    --hl-string: #0a3069;
    --type-badge-text: #fff;
    --welcome-color: #8b949e;
    --toggle-bg: #d0d7de;
    --toggle-hover: rgba(207, 34, 46, 0.1);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         "Helvetica Neue", Arial, sans-serif;
         background: var(--bg-body); color: var(--text-primary);
         height: 100vh; overflow: hidden; transition: background 0.2s, color 0.2s; }}

  .app {{ display: flex; height: 100vh; }}

  /* Sidebar */
  .sidebar {{ width: 280px; min-width: 280px; background: var(--bg-sidebar);
              border-right: 1px solid var(--border-color); display: flex;
              flex-direction: column; overflow: hidden;
              transition: background 0.2s, border-color 0.2s; }}
  .sidebar-header {{ padding: 12px 16px; background: var(--bg-sidebar-header);
                     display: flex; align-items: center; justify-content: space-between;
                     transition: background 0.2s; }}
  .sidebar-header .header-left {{ }}
  .sidebar-header h1 {{ font-size: 15px; color: var(--accent); letter-spacing: 0.5px; }}
  .sidebar-header .subtitle {{ font-size: 11px; color: var(--text-secondary); margin-top: 4px; }}
  .theme-toggle {{ background: var(--toggle-bg); border: none; color: var(--text-secondary);
                   width: 32px; height: 32px; border-radius: 6px; cursor: pointer;
                   font-size: 16px; display: flex; align-items: center;
                   justify-content: center; transition: background 0.2s; flex-shrink: 0; }}
  .theme-toggle:hover {{ background: var(--toggle-hover); }}
  .search-box {{ padding: 10px 16px; background: var(--bg-sidebar);
                 border-bottom: 1px solid var(--border-color);
                 transition: background 0.2s, border-color 0.2s; }}
  .search-box input {{ width: 100%; padding: 8px 12px; border: 1px solid var(--border-color);
                        border-radius: 6px; background: var(--bg-input);
                        color: var(--text-primary); font-size: 13px; outline: none;
                        transition: background 0.2s, border-color 0.2s, color 0.2s; }}
  .search-box input:focus {{ border-color: var(--accent); }}
  .search-box input::placeholder {{ color: var(--text-muted); }}
  .sidebar-list {{ flex: 1; overflow-y: auto; padding: 8px 0; }}
  .sidebar-list::-webkit-scrollbar {{ width: 6px; }}
  .sidebar-list::-webkit-scrollbar-track {{ background: var(--bg-sidebar); }}
  .sidebar-list::-webkit-scrollbar-thumb {{ background: var(--scrollbar-thumb); border-radius: 3px; }}

  .sidebar-group {{ margin-bottom: 4px; }}
  .group-header {{ padding: 8px 16px; font-size: 11px; text-transform: uppercase;
                   color: var(--accent); font-weight: 600; letter-spacing: 1px;
                   cursor: pointer; user-select: none; display: flex;
                   align-items: center; justify-content: space-between; }}
  .group-header:hover {{ background: var(--toggle-hover); }}
  .group-count {{ background: var(--group-count-bg); color: var(--group-count-color);
                  padding: 1px 7px; border-radius: 10px; font-size: 10px;
                  transition: background 0.2s, color 0.2s; }}
  .sidebar-item {{ padding: 8px 16px 8px 24px; cursor: pointer;
                   border-left: 3px solid transparent; transition: all 0.15s; }}
  .sidebar-item:hover {{ background: var(--item-hover); }}
  .sidebar-item.active {{ background: var(--item-active-bg);
                          border-left-color: var(--accent); }}
  .item-ip {{ font-size: 13px; font-weight: 600; color: var(--text-primary);
              font-family: "SF Mono", "Fira Code", monospace; }}
  .item-host {{ font-size: 11px; color: var(--text-secondary); margin-top: 2px; }}
  .item-type {{ font-size: 10px; color: var(--type-badge-text); background: var(--accent);
                display: inline-block; padding: 1px 6px; border-radius: 3px;
                margin-top: 3px; font-weight: 500; }}

  /* Main content */
  .main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}

  .welcome {{ flex: 1; display: flex; align-items: center; justify-content: center;
              flex-direction: column; color: var(--welcome-color); }}
  .welcome .icon {{ font-size: 64px; margin-bottom: 16px; opacity: 0.3; }}
  .welcome p {{ font-size: 15px; }}

  .config-panel {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
  .config-header {{ padding: 12px 20px; background: var(--bg-sidebar);
                    border-bottom: 1px solid var(--border-color);
                    transition: background 0.2s, border-color 0.2s; }}
  .config-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .config-ip {{ font-size: 18px; font-weight: 700; color: var(--accent);
                font-family: "SF Mono", "Fira Code", monospace; }}
  .config-hostname {{ font-size: 14px; color: var(--text-secondary); }}
  .config-type-tag {{ background: #3498db; color: #fff; padding: 2px 8px;
                      border-radius: 4px; font-size: 11px; }}
  .config-loc-tag {{ background: #9b59b6; color: #fff; padding: 2px 8px;
                     border-radius: 4px; font-size: 11px; }}
  .config-meta {{ display: flex; gap: 20px; margin-top: 6px; flex-wrap: wrap; }}
  .config-meta span {{ font-size: 12px; color: var(--text-meta); }}

  .config-body {{ flex: 1; overflow: auto; padding: 0; }}
  .config-body::-webkit-scrollbar {{ width: 8px; height: 8px; }}
  .config-body::-webkit-scrollbar-track {{ background: var(--bg-body); }}
  .config-body::-webkit-scrollbar-thumb {{ background: var(--scrollbar-thumb-main);
                                           border-radius: 4px; }}

  .config-code {{ margin: 0; padding: 16px 20px; font-family: "SF Mono", "Fira Code",
                  "Cascadia Code", "JetBrains Mono", Consolas, monospace;
                  font-size: 13px; line-height: 1.6; color: var(--code-color);
                  background: var(--code-bg); white-space: pre; tab-size: 4;
                  transition: background 0.2s, color 0.2s; }}

  /* Syntax highlighting */
  .hl-comment {{ color: var(--hl-comment); font-style: italic; }}
  .hl-section {{ color: var(--hl-section); font-weight: 600; }}
  .hl-keyword {{ color: var(--hl-keyword); }}
  .hl-ip {{ color: var(--hl-ip); }}
  .hl-number {{ color: var(--hl-number); }}
  .hl-string {{ color: var(--hl-string); }}

  /* Footer */
  .footer {{ text-align: center; padding: 6px; background: var(--bg-sidebar);
             border-top: 1px solid var(--border-color); font-size: 11px;
             color: var(--text-footer); transition: background 0.2s, border-color 0.2s; }}

  /* Responsive */
  @media (max-width: 768px) {{
    .sidebar {{ width: 220px; min-width: 220px; }}
    .config-code {{ font-size: 12px; }}
  }}
</style>
</head>
<body>
<div class="app">
  <div class="sidebar">
    <div class="sidebar-header">
      <div class="header-left">
        <h1>NetConfigArk</h1>
        <div class="subtitle">{len(device_entries)} devices &middot; {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
      </div>
      <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="Toggle light/dark theme">
        <span id="themeIcon">&#9788;</span>
      </button>
    </div>
    <div class="search-box">
      <input type="text" id="searchInput" placeholder="Search IP / hostname / type..."
             oninput="filterDevices(this.value)">
    </div>
    <div class="sidebar-list" id="sidebarList">
      {"".join(sidebar_items)}
    </div>
  </div>

  <div class="main" id="mainContent">
    <div class="welcome" id="welcomePanel">
      <div class="icon">&#9776;</div>
      <p>Select a device from the sidebar to view its configuration</p>
    </div>
    {"".join(config_sections)}
    <div class="footer">
      Generated by NetConfigArk &mdash; Network Device Configuration Backup Tool
    </div>
  </div>
</div>

<script>
(function() {{
  var currentIdx = -1;

  // Theme toggle
  function applyTheme(theme) {{
    if (theme === 'light') {{
      document.body.classList.add('light');
      document.getElementById('themeIcon').innerHTML = '&#9790;';
    }} else {{
      document.body.classList.remove('light');
      document.getElementById('themeIcon').innerHTML = '&#9788;';
    }}
  }}

  // Initialize theme from localStorage
  var savedTheme = localStorage.getItem('netconfigark-theme') || 'dark';
  applyTheme(savedTheme);

  window.toggleTheme = function() {{
    var isLight = document.body.classList.contains('light');
    var newTheme = isLight ? 'dark' : 'light';
    localStorage.setItem('netconfigark-theme', newTheme);
    applyTheme(newTheme);
  }};

  window.selectDevice = function(idx) {{
    // Hide previous
    if (currentIdx >= 0) {{
      var prev = document.getElementById('config-' + currentIdx);
      if (prev) prev.style.display = 'none';
      var prevItem = document.querySelector('.sidebar-item[data-idx="' + currentIdx + '"]');
      if (prevItem) prevItem.classList.remove('active');
    }}

    // Hide welcome
    var welcome = document.getElementById('welcomePanel');
    if (welcome) welcome.style.display = 'none';

    // Show selected
    var panel = document.getElementById('config-' + idx);
    if (panel) panel.style.display = 'flex';
    var item = document.querySelector('.sidebar-item[data-idx="' + idx + '"]');
    if (item) item.classList.add('active');

    currentIdx = idx;
  }};

  window.filterDevices = function(query) {{
    query = query.toLowerCase().trim();
    var items = document.querySelectorAll('.sidebar-item');
    var groups = document.querySelectorAll('.sidebar-group');

    // Track which groups have visible items
    var groupVisibility = {{}};

    items.forEach(function(item) {{
      var searchText = (item.getAttribute('data-search') || '').toLowerCase();
      var visible = !query || searchText.indexOf(query) !== -1;
      item.style.display = visible ? '' : 'none';

      var group = item.closest('.sidebar-group');
      if (group) {{
        var loc = group.getAttribute('data-location');
        if (!groupVisibility[loc]) groupVisibility[loc] = false;
        if (visible) groupVisibility[loc] = true;
      }}
    }});

    groups.forEach(function(group) {{
      var loc = group.getAttribute('data-location');
      group.style.display = groupVisibility[loc] ? '' : 'none';
    }});
  }};

  // Keyboard navigation
  document.addEventListener('keydown', function(e) {{
    if (e.target.tagName === 'INPUT') return;

    var visibleItems = Array.from(document.querySelectorAll(
      '.sidebar-item:not([style*="display: none"])'));
    if (!visibleItems.length) return;

    var currentItem = document.querySelector('.sidebar-item.active');
    var currentPos = currentItem ? visibleItems.indexOf(currentItem) : -1;

    if (e.key === 'ArrowDown' || e.key === 'j') {{
      e.preventDefault();
      var next = currentPos + 1;
      if (next < visibleItems.length) {{
        var idx = parseInt(visibleItems[next].getAttribute('data-idx'));
        selectDevice(idx);
        visibleItems[next].scrollIntoView({{ block: 'nearest' }});
      }}
    }} else if (e.key === 'ArrowUp' || e.key === 'k') {{
      e.preventDefault();
      var prev = currentPos - 1;
      if (prev >= 0) {{
        var idx = parseInt(visibleItems[prev].getAttribute('data-idx'));
        selectDevice(idx);
        visibleItems[prev].scrollIntoView({{ block: 'nearest' }});
      }}
    }} else if (e.key === '/') {{
      e.preventDefault();
      document.getElementById('searchInput').focus();
    }}
  }});

  // Focus search on Escape (clear and blur)
  document.getElementById('searchInput').addEventListener('keydown', function(e) {{
    if (e.key === 'Escape') {{
      this.value = '';
      filterDevices('');
      this.blur();
    }}
  }});

  // Auto-select first device
  var firstItem = document.querySelector('.sidebar-item');
  if (firstItem) {{
    var idx = parseInt(firstItem.getAttribute('data-idx'));
    selectDevice(idx);
  }}
}})();
</script>
</body>
</html>"""

    os.makedirs(output_dir, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)

    return report_file


def do_view(csv_path: str, output_dir: str, logger: logging.Logger) -> None:
    """Run config view mode: generate HTML viewer for latest backup of each device."""
    devices = parse_csv(csv_path, logger)

    print(f"\n--- Config Viewer: loading latest backup for each device ---\n")

    report_path = generate_view_html(devices, output_dir, logger)

    if report_path:
        print(f"\n  Config viewer generated: {report_path}")
        print(f"  Open in browser to view.\n")
    else:
        print("\n  No config viewer generated (no backup files found).\n")


# ============================================================================
# --init and --list-types
# ============================================================================

CSV_TEMPLATE = """\
# Network Device Configuration Backup - Device Inventory Template
# Use --list-types to see supported device_type values
# Lines starting with # are comments and will be ignored
#
# ip              - Device management IP (required)
# protocol        - Connection protocol: ssh or telnet (required)
# port            - Port number, leave empty for default (SSH=22, Telnet=23)
# username        - Login username (required)
# password        - Login password (required)
# device_type     - Device type, leave empty for SSH auto-detect, required for Telnet
# enable_password - Privileged mode password (Cisco enable / Huawei super), optional
# hostname        - Display name for logs, optional
# location        - Site/location name for grouping backups (e.g. DC-East), optional
#                   Devices with same location are saved under the same directory.
#                   Leave empty to use "default" directory.
#
ip,protocol,port,username,password,device_type,enable_password,hostname,location
# 192.168.1.1,ssh,,admin,password,huawei,,HW-Core-SW,Site-A
# 10.0.0.1,ssh,22,admin,password,cisco,enable123,Cisco-RTR,Site-B
# 172.16.0.1,telnet,23,admin,password,h3c,,H3C-Switch,
"""


def do_init():
    """Generate CSV template file."""
    target = os.path.join(os.getcwd(), "devices.csv")
    if os.path.exists(target):
        print(f"Error: '{target}' already exists. Refusing to overwrite.")
        sys.exit(1)
    with open(target, "w", encoding="utf-8") as f:
        f.write(CSV_TEMPLATE)
    print(f"CSV template generated: {target}")
    print("Edit this file with your device information, then run:")
    print("  python3 backup_config.py -c devices.csv")


def do_list_types():
    """Print supported device types."""
    print("\nSupported device types (device_type):\n")
    print(f"  {'Type':<14}  {'Device':<38}  {'Config Command'}")
    print(f"  {'─'*14}  {'─'*38}  {'─'*30}")
    for type_name, description, command in DEVICE_TYPE_INFO:
        print(f"  {type_name:<14}  {description:<38}  {command}")
    print()
    print("Notes:")
    print("  - SSH connections will auto-detect device type, device_type can be left empty")
    print("  - Telnet connections require device_type to be specified")
    print("  - Falls back to CSV device_type if auto-detection fails")
    print()


# ============================================================================
# Logging setup
# ============================================================================

def setup_logging(verbose: bool, log_dir: str = "logs") -> logging.Logger:
    """Configure logging with file + console output."""
    logger = logging.getLogger("backup_config")
    logger.setLevel(logging.DEBUG)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"backup_{timestamp}.log")

    # File handler - DEBUG level
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)-7s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # Console handler - outputs to stdout to avoid interleaving with print()
    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter(
        "[%(levelname)-7s] %(message)s",
    ))
    logger.addHandler(ch)

    logger.debug("Log file: %s", log_file)

    # Suppress noisy third-party library logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
    logging.getLogger("netmiko").setLevel(logging.WARNING)

    return logger


# ============================================================================
# Argument parsing
# ============================================================================

EPILOG = f"""\
Supported device_type values:
  {', '.join(SUPPORTED_TYPES)}
  (Use --list-types for details and corresponding config commands)

CSV format:
  ip,protocol,port,username,password,device_type,enable_password,hostname,location

Examples:
  # Generate a CSV template for first-time use
  python3 backup_config.py --init

  # List all supported device types
  python3 backup_config.py --list-types

  # Batch mode: backup all devices from CSV file
  python3 backup_config.py -c devices.csv

  # Batch mode: 10 threads, 60s timeout
  python3 backup_config.py -c my_devices.csv -w 10 -t 60

  # Single device mode: backup one Huawei switch (password prompted)
  python3 backup_config.py -H 192.168.1.1 -u admin

  # Single device mode: specify all options
  python3 backup_config.py -H 10.0.0.1 -u admin -p pass123 -d cisco --enable-password en123

  # Single device mode: Telnet with non-standard port
  python3 backup_config.py -H 172.16.0.1 -u admin -p pass123 -P telnet --port 2323 -d h3c

  # Verbose mode with custom output directory
  python3 backup_config.py -c devices.csv -v -o /data/network-backups

  # Skip unreachable devices and backup the rest
  python3 backup_config.py -c devices.csv --skip-unreachable

  # Burst mode: one thread per device, all devices in parallel
  python3 backup_config.py -c devices.csv --burst

  # Compare latest 5 backups per device (default), generate HTML diff report
  python3 backup_config.py -c devices.csv --diff

  # Compare latest 3 backups per device
  python3 backup_config.py -c devices.csv --diff 3

  # Diff without timestamp filtering (show all differences)
  python3 backup_config.py -c devices.csv --diff --no-filter

  # View latest config for each device with syntax highlighting
  python3 backup_config.py -c devices.csv --view

Output structure:
  backups/<location>/<IP>_<device_type>[_<hostname>]/<IP>_<device_type>[_<hostname>]_<YYYY-MM-DD>_<HHMMSS>.txt
  (location defaults to "default" if not specified in CSV)

Workflow:
  1. Parse and validate input (CSV file or command-line arguments)
  2. Pre-check: connect to all devices (abort if any fail)
  3. Backup: fetch running config from all devices concurrently
  4. Validate: check config completeness (end markers, paging residue)
  5. Report: print backup summary
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backup_config.py",
        description=(
            "Network Device Configuration Backup Tool\n"
            "Supports Cisco/Huawei/H3C/Fortinet/Juniper/Palo Alto/MikroTik devices.\n"
            "Connects via SSH/Telnet to fetch running config "
            "(read-only, no changes made to devices)."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # CSV batch mode
    csv_group = parser.add_argument_group("CSV batch mode (default)")
    csv_group.add_argument("-c", "--csv", default="devices.csv",
                           help="Path to device inventory CSV file (default: devices.csv)")
    csv_group.add_argument("-w", "--workers", type=int, default=2,
                           help="Number of concurrent connection threads (default: 2)")
    csv_group.add_argument("--burst", action="store_true",
                           help="Set concurrency equal to the number of devices in CSV "
                                "(one thread per device, all devices in parallel)")

    # Single device mode
    single_group = parser.add_argument_group("Single device mode")
    single_group.add_argument("-H", "--host",
                              help="Device IP address (enables single device mode)")
    single_group.add_argument("-u", "--username",
                              help="Login username (required in single mode)")
    single_group.add_argument("-p", "--password",
                              help="Login password (prompted securely if omitted)")
    single_group.add_argument("-P", "--protocol", choices=["ssh", "telnet"], default="ssh",
                              help="Connection protocol (default: ssh)")
    single_group.add_argument("--port", type=int,
                              help="Port number (default: SSH=22, Telnet=23)")
    single_group.add_argument("-d", "--device-type", dest="device_type",
                              help="Device type (optional for SSH, required for Telnet)")
    single_group.add_argument("--enable-password", dest="enable_password",
                              help="Privileged mode password (Cisco enable / Huawei super)")
    single_group.add_argument("--location",
                              help="Site/location name for grouping backups (default: 'default')")

    # Common options
    common_group = parser.add_argument_group("Common options")
    common_group.add_argument("-o", "--output", default="./backups",
                              help="Backup output directory (default: ./backups)")
    common_group.add_argument("-t", "--timeout", type=int, default=20,
                              help="Device connection timeout in seconds (default: 20)")
    common_group.add_argument("--read-timeout", type=int, default=60,
                              dest="read_timeout",
                              help="Config fetch timeout in seconds per device (default: 60)")
    common_group.add_argument("-v", "--verbose", action="store_true",
                              help="Enable verbose logging (DEBUG level)")
    common_group.add_argument("--skip-unreachable", action="store_true",
                              help="Skip unreachable devices and continue backup for the rest "
                                   "(default: abort if any device fails pre-check)")
    common_group.add_argument("--list-types", action="store_true",
                              help="Show supported device types and exit")
    common_group.add_argument("--init", action="store_true",
                              help="Generate a CSV template file (devices.csv) and exit")
    common_group.add_argument("--diff", type=int, nargs="?", const=5, default=None,
                              metavar="N",
                              help="Compare the latest N backups per device and generate "
                                   "an HTML diff report (default N=5). "
                                   "Requires -c to specify CSV file.")
    common_group.add_argument("--no-filter", action="store_true",
                              dest="no_filter",
                              help="Disable timestamp filtering in --diff mode. "
                                   "By default, auto-generated timestamps (RouterOS export "
                                   "header, Huawei/Cisco timestamp lines, ntp clock-period) "
                                   "are excluded from comparison.")
    common_group.add_argument("--view", action="store_true",
                              help="Generate an HTML page showing the latest backup "
                                   "config for each device with syntax highlighting. "
                                   "Requires -c to specify CSV file.")

    return parser


# ============================================================================
# Main
# ============================================================================

def build_single_device_info(args) -> Dict[str, str]:
    """Build device info dict from command-line arguments for single device mode."""
    # Validate host IP
    try:
        ipaddress.ip_address(args.host)
    except ValueError:
        print(f"Error: invalid IP address: {args.host}")
        sys.exit(1)

    if not args.username:
        print("Error: --username (-u) is required in single device mode")
        sys.exit(1)

    # Prompt for password if not provided
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
        if not password:
            print("Error: password cannot be empty")
            sys.exit(1)

    # Validate device type
    dt = args.device_type or ""
    if dt and dt not in DEVICE_TYPE_MAP:
        print(f"Error: unknown device_type '{dt}'. Use --list-types to see supported types.")
        sys.exit(1)

    if args.protocol == "telnet" and not dt:
        print("Error: Telnet connections require --device-type to be specified")
        sys.exit(1)

    # Default port
    port = args.port
    if port is None:
        port = 22 if args.protocol == "ssh" else 23

    return {
        "ip": args.host,
        "protocol": args.protocol,
        "port": str(port),
        "username": args.username,
        "password": password,
        "device_type": dt,
        "enable_password": args.enable_password or "",
        "hostname": args.host,
        "raw_hostname": "",  # single device mode has no separate hostname
        "location": args.location or "",
    }


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Handle --init
    if args.init:
        do_init()
        sys.exit(0)

    # Handle --list-types
    if args.list_types:
        do_list_types()
        sys.exit(0)

    # Setup logging
    logger = setup_logging(args.verbose)

    # Handle --diff mode
    if args.diff is not None:
        diff_count = args.diff
        if diff_count < 2:
            print("Error: --diff requires N >= 2 (need at least 2 backups to compare)")
            sys.exit(1)
        do_diff(args.csv, args.output, diff_count, args.no_filter, logger)
        sys.exit(0)

    # Handle --view mode
    if args.view:
        do_view(args.csv, args.output, logger)
        sys.exit(0)

    # Determine mode and build device list
    if args.host:
        # Single device mode
        if args.csv != "devices.csv":
            logger.info("Single device mode: --csv option is ignored when --host is provided")
        device_info = build_single_device_info(args)
        devices = [device_info]
        workers = 1
        logger.info("Single device mode: %s", args.host)
    else:
        # CSV batch mode
        devices = parse_csv(args.csv, logger)
        if args.burst:
            workers = len(devices)
            logger.info("Burst mode: concurrency set to %d (one thread per device)", workers)
        else:
            workers = args.workers

    # Run timestamp (shared across all devices in this run)
    now = datetime.now()
    run_timestamp = now.strftime("%Y-%m-%d_%H%M%S")

    overall_start = time.time()

    # Phase 1: Pre-check all devices
    print("\n--- Phase 1: Pre-check (verifying connectivity) ---", flush=True)
    precheck_results = run_precheck(devices, workers, args.timeout, logger)

    should_continue, passed_results = print_precheck_report(
        precheck_results, args.skip_unreachable, logger)
    if not should_continue:
        sys.exit(1)

    # Inject resolved netmiko types into device info
    # Filter to only passed devices, match by IP
    passed_ips = {r.ip for r in passed_results}
    precheck_map = {r.ip: r for r in passed_results}
    devices = [dev for dev in devices if dev["ip"] in passed_ips]
    for dev in devices:
        pr = precheck_map[dev["ip"]]
        dev["resolved_netmiko_type"] = pr.netmiko_type
        # If type was auto-corrected, update device_type so directory naming reflects it
        if pr.type_corrected:
            corrected_csv_type = NETMIKO_TO_CSV_TYPE.get(pr.netmiko_type, "")
            if corrected_csv_type:
                dev["device_type"] = corrected_csv_type
        dev["resolved_type_label"] = get_device_type_label(dev, pr.netmiko_type)

    # Count skipped devices from pre-check
    skipped_count = sum(1 for r in precheck_results if not r.success)

    # Phase 2: Backup
    print("--- Phase 2: Backup (fetching configurations) ---\n")
    backup_results = run_backup(devices, args.output, workers,
                                args.timeout, args.read_timeout, run_timestamp, logger)

    # Phase 3: Summary
    print_summary(backup_results, skipped_count, precheck_results, overall_start, logger)

    # Exit code: non-zero if any backup failed or devices were skipped
    failed_count = sum(1 for r in backup_results if not r.success)
    sys.exit(1 if (failed_count > 0 or skipped_count > 0) else 0)


if __name__ == "__main__":
    main()
