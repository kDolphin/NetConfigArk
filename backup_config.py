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
        config_output = conn.send_command(config_cmd, read_timeout=read_timeout)

        # Retry with send_command_timing if output is empty
        # Some devices (e.g., H3C Comware) have intermittent prompt detection issues
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
