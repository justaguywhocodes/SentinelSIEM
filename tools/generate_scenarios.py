#!/usr/bin/env python3
"""
P1-T5: Scenario Generator CLI for SentinelSIEM.

Reads YAML scenario definitions, entity directories, and noise profiles
to produce a mixed NDJSON event stream that matches the SIEM parser schemas.

Usage:
    python generate_scenarios.py --scenario credential_theft --output out.ndjson
    python generate_scenarios.py --scenario lateral_movement -o out.ndjson --noise-ratio 0.95 --seed 42
    python generate_scenarios.py --scenario malware_delivery -o - --start-time 2026-03-14T08:00:00Z
"""

import argparse
import hashlib
import json
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML>=6.0", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOOLS_DIR = Path(__file__).resolve().parent
SCENARIOS_DIR = TOOLS_DIR / "scenarios"
PROFILES_DIR = TOOLS_DIR / "profiles"
ENTITIES_DIR = TOOLS_DIR / "entities"

# ---------------------------------------------------------------------------
# Entity resolution
# ---------------------------------------------------------------------------

class EntityDirectory:
    """Loads and resolves hosts, users, and network topology from YAML."""

    def __init__(self, entities_dir: Path):
        self.hosts = {}       # name -> host dict
        self.users = {}       # name -> user dict
        self.network = {}     # full network config
        self._load(entities_dir)

    def _load(self, d: Path):
        with open(d / "hosts.yaml") as f:
            data = yaml.safe_load(f)
        for h in data.get("hosts", []):
            self.hosts[h["name"]] = h

        with open(d / "users.yaml") as f:
            data = yaml.safe_load(f)
        for u in data.get("users", []):
            self.users[u["name"]] = u

        with open(d / "network.yaml") as f:
            self.network = yaml.safe_load(f)

    def host_ip(self, hostname: str) -> str:
        h = self.hosts.get(hostname)
        if h:
            return h["ip"]
        return "0.0.0.0"

    def user_sid(self, username: str) -> str:
        u = self.users.get(username)
        if u:
            return u["sid"]
        return "S-1-5-21-0-0-0-0"

    def user_domain(self, username: str) -> str:
        u = self.users.get(username)
        if u:
            return u.get("domain", "CORP")
        return "CORP"

    def user_full_name(self, username: str) -> str:
        u = self.users.get(username)
        if u:
            return u.get("full_name", username)
        return username

    def host_profile(self, hostname: str) -> str:
        h = self.hosts.get(hostname)
        if h:
            return h.get("profile", "workstation")
        return "workstation"

    def host_users(self, hostname: str) -> list:
        h = self.hosts.get(hostname)
        if h:
            return h.get("users", [])
        return []

    def external_ip(self, name: str) -> str:
        return self.network.get("external_ips", {}).get(name, "0.0.0.0")


# ---------------------------------------------------------------------------
# Template expression evaluator
# ---------------------------------------------------------------------------

class TemplateEvaluator:
    """Resolves {{ expr }} placeholders in scenario/profile field values."""

    def __init__(self, entities: EntityDirectory, actors: dict, rng: random.Random):
        self.entities = entities
        self.actors = actors
        self.rng = rng

    def evaluate(self, value, host: str = None, user: str = None):
        """Evaluate a value that may contain {{ ... }} expressions."""
        if not isinstance(value, str):
            return value

        def replacer(match):
            expr = match.group(1).strip()
            return self._eval_expr(expr, host, user)

        return re.sub(r"\{\{(.+?)\}\}", replacer, value)

    def _eval_expr(self, expr: str, host: str = None, user: str = None) -> str:
        # Actor references: actors.attacker.initial_host
        if expr.startswith("actors."):
            return self._resolve_actor_path(expr)

        # host_ip(...)
        m = re.match(r"host_ip\((.+)\)", expr)
        if m:
            arg = m.group(1).strip()
            hostname = self._eval_expr(arg, host, user)
            return self.entities.host_ip(hostname)

        # random_choice([...])
        m = re.match(r"random_choice\(\[(.+)\]\)", expr)
        if m:
            items_str = m.group(1)
            items = self._parse_list(items_str)
            # Resolve nested {{ user }} in items
            resolved = []
            for item in items:
                if "{{ user }}" in item and user:
                    item = item.replace("{{ user }}", user)
                resolved.append(item)
            return self.rng.choice(resolved)

        # random_port()
        if expr == "random_port()":
            return str(self.rng.randint(49152, 65535))

        # random_int(min, max)
        m = re.match(r"random_int\((\d+),\s*(\d+)\)", expr)
        if m:
            return str(self.rng.randint(int(m.group(1)), int(m.group(2))))

        # random_hex(length)
        m = re.match(r"random_hex\((\d+)\)", expr)
        if m:
            length = int(m.group(1))
            return "".join(self.rng.choice("0123456789abcdef") for _ in range(length))

        # Simple variable: user
        if expr == "user" and user:
            return user

        # host
        if expr == "host" and host:
            return host

        return expr

    def _resolve_actor_path(self, expr: str) -> str:
        """Resolve dotted actor path like actors.attacker.initial_host."""
        parts = expr.split(".")
        obj = self.actors
        for part in parts[1:]:  # skip 'actors'
            if isinstance(obj, dict):
                obj = obj.get(part, "")
            else:
                return str(obj)
        return str(obj)

    def _parse_list(self, items_str: str) -> list:
        """Parse a comma-separated list of quoted strings or bare values."""
        items = []
        current = ""
        in_quote = False
        quote_char = None
        for ch in items_str:
            if not in_quote and ch in ("'", '"'):
                in_quote = True
                quote_char = ch
            elif in_quote and ch == quote_char:
                in_quote = False
                items.append(current)
                current = ""
            elif in_quote:
                current += ch
            elif ch == ',':
                # End of an unquoted item
                stripped = current.strip()
                if stripped:
                    items.append(stripped)
                current = ""
            else:
                current += ch
        stripped = current.strip()
        if stripped:
            items.append(stripped)
        return items if items else [items_str.strip().strip("'\"")]


# ---------------------------------------------------------------------------
# Event builders -- one per source_type + template
# ---------------------------------------------------------------------------

def _uuid() -> str:
    return str(uuid.uuid4())


def _sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _md5(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()


def _sha1(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()


def build_sentinel_edr(template: str, ts: str, host: str, fields: dict,
                       entities: EntityDirectory) -> dict:
    """Build a sentinel_edr event matching the siemEnvelope + edrEvent schema."""
    user = fields.get("user", "SYSTEM")
    user_sid = entities.user_sid(user) if user != "SYSTEM" else "S-1-5-18"
    severity = fields.get("severity", "Low")
    host_ip = entities.host_ip(host)
    agent_id = _uuid()
    event_id = _uuid()
    pid = random.randint(1000, 65000)
    ppid = random.randint(500, 5000)

    # Base process context
    process_ctx = {
        "pid": pid,
        "parentPid": ppid,
        "threadId": random.randint(1, 50000),
        "sessionId": 1,
        "imagePath": "",
        "commandLine": "",
        "userSid": user_sid,
        "integrityLevel": 8192,
        "isElevated": False,
        "parentImagePath": ""
    }

    source = "DriverProcess"
    payload = {}

    if template == "process_creation":
        source = "DriverProcess"
        proc_name = fields.get("process_name", "cmd.exe")
        cmd_line = fields.get("command_line", proc_name)
        parent = fields.get("parent_process", "explorer.exe")
        image_path = f"C:\\Windows\\System32\\{proc_name}"
        parent_path = f"C:\\Windows\\System32\\{parent}"
        if "\\" in proc_name or "/" in proc_name:
            image_path = proc_name
        if "\\" in parent or "/" in parent:
            parent_path = parent

        process_ctx["imagePath"] = parent_path
        process_ctx["commandLine"] = parent
        process_ctx["parentImagePath"] = parent_path

        payload = {
            "isCreate": True,
            "newProcessId": random.randint(2000, 65000),
            "parentProcessId": ppid,
            "imagePath": image_path,
            "commandLine": cmd_line,
            "integrityLevel": 8192,
            "isElevated": False,
            "exitStatus": ""
        }

    elif template == "network_connection":
        source = "DriverNetwork"
        remote_ip = fields.get("remote_ip", "0.0.0.0")
        remote_port = int(fields.get("remote_port", 443))
        local_port = int(fields.get("local_port", random.randint(49152, 65535)))
        direction = fields.get("direction", "Outbound")
        protocol = int(fields.get("protocol", 6))

        process_ctx["imagePath"] = "C:\\Windows\\System32\\svchost.exe"
        process_ctx["commandLine"] = "svchost.exe"

        payload = {
            "direction": direction,
            "processId": pid,
            "protocol": protocol,
            "localAddr": host_ip,
            "localPort": local_port,
            "remoteAddr": remote_ip,
            "remotePort": remote_port
        }

    elif template == "file_operation":
        source = "DriverMinifilter"
        operation = fields.get("operation", "Read")
        file_path = fields.get("file_path", "C:\\Windows\\Temp\\data.tmp")

        process_ctx["imagePath"] = "C:\\Windows\\System32\\svchost.exe"
        process_ctx["commandLine"] = "svchost.exe"

        payload = {
            "operation": operation,
            "processId": pid,
            "filePath": file_path,
            "newFilePath": "",
            "fileSize": random.randint(1024, 1048576),
            "sha256": _sha256(file_path + ts),
            "hashSkipped": False
        }

    elif template == "registry_operation":
        source = "DriverRegistry"
        operation = fields.get("operation", "SetValue")
        key_path = fields.get("key_path", "HKLM\\SOFTWARE\\Test")

        process_ctx["imagePath"] = "C:\\Windows\\System32\\svchost.exe"
        process_ctx["commandLine"] = "svchost.exe"

        payload = {
            "operation": operation,
            "keyPath": key_path,
            "valueName": fields.get("value_name", ""),
            "dataType": 1,
            "dataSize": random.randint(4, 256)
        }

    elif template == "dns_query":
        source = "Etw"
        query_name = fields.get("query_name", "example.com")

        process_ctx["imagePath"] = "C:\\Windows\\System32\\svchost.exe"
        process_ctx["commandLine"] = "svchost.exe -k NetworkService"

        payload = {
            "provider": "DnsClient",
            "eventId": 3006,
            "level": 4,
            "keyword": "0x8000000000000000",
            "processId": pid,
            "threadId": random.randint(1, 50000),
            "queryName": query_name,
            "queryType": 1,
            "queryStatus": 0
        }

    elif template == "lsass_access":
        source = "DriverObject"
        src_proc = fields.get("source_process", "mimikatz.exe")
        process_ctx["imagePath"] = f"C:\\Users\\{user}\\Downloads\\{src_proc}"
        process_ctx["commandLine"] = src_proc

        payload = {
            "operation": "Open",
            "objectType": "Process",
            "sourceProcessId": pid,
            "targetProcessId": random.randint(600, 900),
            "targetImagePath": "C:\\Windows\\System32\\lsass.exe",
            "desiredAccess": fields.get("desired_access", "0x1010"),
            "grantedAccess": fields.get("desired_access", "0x1010")
        }

    elif template == "image_load":
        source = "DriverImageLoad"
        image_path = fields.get("image_path", "C:\\Windows\\System32\\ntdll.dll")

        process_ctx["imagePath"] = "C:\\Windows\\System32\\svchost.exe"
        process_ctx["commandLine"] = "svchost.exe"

        payload = {
            "processId": pid,
            "imagePath": image_path,
            "imageBase": "0x00007FF" + format(random.randint(0, 0xFFFF), '04X') + "0000",
            "imageSize": "0x" + format(random.randint(0x10000, 0x200000), 'X'),
            "isKernelImage": False,
            "isSigned": True,
            "isSignatureValid": True
        }

    else:
        # Generic process creation fallback
        source = "DriverProcess"
        process_ctx["imagePath"] = "C:\\Windows\\System32\\cmd.exe"
        process_ctx["commandLine"] = "cmd.exe"
        payload = {
            "isCreate": True,
            "newProcessId": random.randint(2000, 65000),
            "parentProcessId": ppid,
            "imagePath": "C:\\Windows\\System32\\cmd.exe",
            "commandLine": "cmd.exe",
            "integrityLevel": 8192,
            "isElevated": False,
            "exitStatus": ""
        }

    inner_event = {
        "eventId": event_id,
        "timestamp": ts,
        "source": source,
        "severity": severity,
        "process": process_ctx,
        "payload": payload
    }

    return {
        "source_type": "sentinel_edr",
        "schema": "sentinel/v1",
        "host": host,
        "agent_id": agent_id,
        "timestamp": ts,
        "event": inner_event
    }


def build_sentinel_av(template: str, ts: str, host: str, fields: dict,
                      entities: EntityDirectory) -> dict:
    """Build a sentinel_av event."""
    user = fields.get("user", "SYSTEM")
    user_sid = entities.user_sid(user) if user != "SYSTEM" else "S-1-5-18"

    base = {
        "source_type": "sentinel_av",
        "timestamp": ts,
        "hostname": host,
        "event_type": "",
        "user": {
            "sid": user_sid,
            "name": user
        },
        "payload": {}
    }

    if template == "scan_result_clean":
        base["event_type"] = "av:scan_result"
        file_path = fields.get("file_path",
                               f"C:\\Users\\{user}\\Documents\\report_{random.randint(1,999)}.docx")
        base["payload"] = {
            "file_path": file_path,
            "file_size": random.randint(1024, 524288),
            "hash_md5": _md5(file_path + ts),
            "hash_sha1": _sha1(file_path + ts),
            "hash_sha256": _sha256(file_path + ts),
            "verdict": "clean",
            "engine": "SentinelAV/2.1"
        }

    elif template == "scan_result_malicious":
        base["event_type"] = "av:scan_result"
        file_path = fields.get("file_path", "C:\\Users\\Downloads\\malware.exe")
        base["payload"] = {
            "file_path": file_path,
            "file_size": random.randint(50000, 2000000),
            "hash_md5": _md5(file_path),
            "hash_sha1": _sha1(file_path),
            "hash_sha256": _sha256(file_path),
            "verdict": fields.get("verdict", "malicious"),
            "signature_name": fields.get("signature_name", "Trojan:Win32/Generic"),
            "engine": "SentinelAV/2.1"
        }

    elif template == "scan_result_suspicious":
        base["event_type"] = "av:scan_result"
        file_path = fields.get("file_path", "C:\\Users\\Downloads\\suspicious.exe")
        base["payload"] = {
            "file_path": file_path,
            "file_size": random.randint(50000, 2000000),
            "hash_md5": _md5(file_path),
            "hash_sha1": _sha1(file_path),
            "hash_sha256": _sha256(file_path),
            "verdict": fields.get("verdict", "suspicious"),
            "signature_name": fields.get("signature_name", "PUA:Win32/Suspicious"),
            "engine": "SentinelAV/2.1"
        }

    elif template == "quarantine":
        base["event_type"] = "av:quarantine"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "original_path": fields.get("original_path", ""),
            "hash_md5": _md5(fields.get("original_path", "") + ts),
            "hash_sha1": _sha1(fields.get("original_path", "") + ts),
            "hash_sha256": _sha256(fields.get("original_path", "") + ts),
            "file_size": random.randint(50000, 2000000),
            "rule": fields.get("rule", "")
        }

    elif template == "realtime_block":
        base["event_type"] = "av:realtime_block"
        file_path = fields.get("file_path", "")
        base["payload"] = {
            "file_path": file_path,
            "hash_md5": _md5(file_path),
            "hash_sha1": _sha1(file_path),
            "hash_sha256": _sha256(file_path),
            "file_size": random.randint(50000, 2000000),
            "process_pid": random.randint(1000, 65000),
            "process_executable": fields.get("process_executable", file_path),
            "process_command_line": fields.get("process_executable", file_path),
            "reason": fields.get("reason", "Malicious file detected")
        }

    elif template == "signature_update":
        base["event_type"] = "av:signature_update"
        base["payload"] = {
            "version": fields.get("version", "2.1.0.350"),
            "signature_count": random.randint(50000, 100000),
            "engine": "SentinelAV/2.1"
        }

    else:
        base["event_type"] = "av:scan_result"
        base["payload"] = {
            "file_path": f"C:\\Windows\\Temp\\scan_{random.randint(1,999)}.tmp",
            "verdict": "clean",
            "engine": "SentinelAV/2.1"
        }

    return base


def build_sentinel_dlp(template: str, ts: str, host: str, fields: dict,
                       entities: EntityDirectory) -> dict:
    """Build a sentinel_dlp event."""
    user = fields.get("user", "SYSTEM")
    user_sid = entities.user_sid(user) if user != "SYSTEM" else "S-1-5-18"

    base = {
        "source_type": "sentinel_dlp",
        "timestamp": ts,
        "hostname": host,
        "event_type": "",
        "user": {
            "sid": user_sid,
            "name": user
        },
        "payload": {}
    }

    if template == "policy_violation":
        base["event_type"] = "dlp:policy_violation"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "file_size": random.randint(1024, 10485760),
            "policy_name": fields.get("policy_name", "Default Policy"),
            "policy_action": fields.get("policy_action", "alert"),
            "classification": fields.get("classification", "internal"),
            "channel": fields.get("channel", "share")
        }

    elif template == "classification":
        base["event_type"] = "dlp:classification"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "file_size": random.randint(1024, 10485760),
            "classification": fields.get("classification", "internal"),
            "previous_label": fields.get("previous_label", "")
        }

    elif template == "block":
        base["event_type"] = "dlp:block"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "file_size": random.randint(1024, 10485760),
            "policy_name": fields.get("policy_name", "Default Policy"),
            "policy_action": fields.get("policy_action", "block"),
            "classification": fields.get("classification", "restricted"),
            "channel": fields.get("channel", "upload"),
            "reason": fields.get("reason", "Policy violation")
        }

    elif template == "audit":
        base["event_type"] = "dlp:audit"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "file_size": random.randint(1024, 10485760),
            "policy_name": fields.get("policy_name", "Default Policy"),
            "policy_action": fields.get("policy_action", "audit"),
            "classification": fields.get("classification", "internal"),
            "channel": fields.get("channel", "share")
        }

    elif template == "removable_media":
        base["event_type"] = "dlp:removable_media"
        base["payload"] = {
            "file_path": fields.get("file_path", ""),
            "file_size": random.randint(1024, 10485760),
            "device_id": fields.get("device_id", "USB\\VID_0781&PID_5583"),
            "device_label": fields.get("device_label", "SanDisk Cruzer"),
            "policy_name": fields.get("policy_name", "USB Policy"),
            "policy_action": fields.get("policy_action", "alert"),
            "classification": fields.get("classification", "internal"),
            "channel": "usb"
        }

    return base


def build_sentinel_ndr(template: str, ts: str, fields: dict,
                       entities: EntityDirectory) -> dict:
    """Build a sentinel_ndr event (pre-normalized ECS)."""
    src_ip = fields.get("src_ip", "0.0.0.0")
    dst_ip = fields.get("dst_ip", "0.0.0.0")
    src_port = int(fields.get("src_port", random.randint(49152, 65535)))
    dst_port = int(fields.get("dst_port", 443))
    protocol = fields.get("protocol", "tcp")
    community_id = f"1:{_sha1(f'{src_ip}:{src_port}-{dst_ip}:{dst_port}')[:20]}"

    base = {
        "source_type": "sentinel_ndr",
        "timestamp": ts,
        "event_type": "",
        "source": {"ip": src_ip, "port": src_port},
        "destination": {"ip": dst_ip, "port": dst_port},
    }

    if template == "ndr_session":
        base["event_type"] = "ndr:session"
        base["event"] = {
            "kind": "event",
            "category": ["network_connection"],
            "type": ["connection"],
            "action": "session"
        }
        base["network"] = {
            "protocol": protocol,
            "direction": "unknown",
            "community_id": community_id
        }
        base["ndr"] = {
            "session": {
                "community_id": community_id,
                "bytes_in": int(fields.get("bytes_in", random.randint(100, 50000))),
                "bytes_out": int(fields.get("bytes_out", random.randint(100, 50000))),
                "duration_ms": random.randint(10, 30000)
            }
        }
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_dns":
        base["event_type"] = "ndr:dns"
        base["event"] = {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol"],
            "action": "dns_query"
        }
        base["network"] = {"protocol": "dns"}
        base["dns"] = {
            "question": {
                "name": fields.get("query_name", "example.com"),
                "type": fields.get("query_type", "A")
            },
            "response_code": fields.get("response_code", "NOERROR")
        }
        base["destination"]["port"] = 53
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_http":
        base["event_type"] = "ndr:http"
        base["event"] = {
            "kind": "event",
            "category": ["network", "web"],
            "type": ["protocol"],
            "action": "http_request"
        }
        base["network"] = {"protocol": "http"}
        base["http"] = {
            "request": {
                "method": fields.get("method", "GET")
            },
            "response": {
                "status_code": int(fields.get("status_code", 200))
            }
        }
        base["url"] = {
            "path": fields.get("uri", "/"),
            "domain": fields.get("host", "example.com")
        }
        base["destination"]["port"] = int(fields.get("dst_port", 80))
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_tls":
        base["event_type"] = "ndr:tls"
        base["event"] = {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol"],
            "action": "tls_handshake"
        }
        base["network"] = {"protocol": "tls"}
        base["tls"] = {
            "client": {
                "ja3": fields.get("ja3_hash", _md5(ts))
            },
            "server": {
                "name": fields.get("server_name", "example.com")
            },
            "version": fields.get("version", "TLSv1.3")
        }
        base["destination"]["port"] = 443
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_smb":
        base["event_type"] = "ndr:smb"
        base["event"] = {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol"],
            "action": "smb_" + fields.get("action", "tree_connect")
        }
        base["network"] = {"protocol": "smb"}
        base["smb"] = {
            "action": fields.get("action", "tree_connect"),
            "share_name": fields.get("share_name", "")
        }
        base["destination"]["port"] = 445
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_rdp":
        base["event_type"] = "ndr:rdp"
        base["event"] = {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol"],
            "action": "rdp"
        }
        base["network"] = {"protocol": "rdp"}
        base["destination"]["port"] = 3389
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_detection":
        base["event_type"] = "ndr:detection"
        base["event"] = {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "action": "detection",
            "severity": 100 if fields.get("severity") == "Critical" else 75
        }
        base["ndr"] = {
            "detection": {
                "name": fields.get("detection_name", "Unknown Detection"),
                "category": fields.get("category", "unknown"),
                "severity": fields.get("severity", "High")
            }
        }
        base["threat"] = {
            "technique": {
                "name": fields.get("detection_name", "Unknown")
            }
        }
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    elif template == "ndr_host_score":
        base["event_type"] = "ndr:host_score"
        base["event"] = {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": "host_score_update"
        }
        base["ndr"] = {
            "host_score": {
                "certainty": int(fields.get("certainty", 50)),
                "threat": int(fields.get("threat", 50)),
                "quadrant": fields.get("quadrant", "medium")
            }
        }
        base["host"] = {
            "ip": [src_ip],
            "name": fields.get("host_name", "")
        }
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    else:
        base["event_type"] = "ndr:session"
        base["event"] = {
            "kind": "event",
            "category": ["network_connection"],
            "type": ["connection"],
            "action": "session"
        }
        base["network"] = {"protocol": protocol, "community_id": community_id}
        base["ndr"] = {
            "session": {
                "community_id": community_id,
                "bytes_in": random.randint(100, 50000),
                "bytes_out": random.randint(100, 50000),
                "duration_ms": random.randint(10, 30000)
            }
        }
        base["observer"] = {
            "type": "ndr",
            "vendor": "SentinelNDR",
            "product": "SentinelNDR"
        }

    return base


def build_winevt_xml(template: str, ts: str, host: str, fields: dict,
                     entities: EntityDirectory) -> dict:
    """Build a winevt_xml event with raw XML matching the winevt_xml parser."""
    user = fields.get("user", "SYSTEM")
    user_sid = entities.user_sid(user) if user != "SYSTEM" else "S-1-5-18"
    user_domain = entities.user_domain(user) if user != "SYSTEM" else "NT AUTHORITY"

    if template == "logon_success":
        event_id = int(fields.get("event_id", 4624))
        logon_type = int(fields.get("logon_type", 3))
        source_ip = fields.get("source_ip", "127.0.0.1")
        xml = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing" '
            f'Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>'
            f'<EventID>{event_id}</EventID>'
            f'<Version>2</Version>'
            f'<Level>0</Level>'
            f'<Task>12544</Task>'
            f'<Opcode>0</Opcode>'
            f'<Keywords>0x8020000000000000</Keywords>'
            f'<TimeCreated SystemTime="{ts}"/>'
            f'<EventRecordID>{random.randint(100000, 999999)}</EventRecordID>'
            f'<Channel>Security</Channel>'
            f'<Computer>{host}</Computer>'
            f'<Security UserID="{user_sid}"/>'
            f'</System>'
            f'<EventData>'
            f'<Data Name="SubjectUserSid">S-1-5-18</Data>'
            f'<Data Name="SubjectUserName">-</Data>'
            f'<Data Name="SubjectDomainName">-</Data>'
            f'<Data Name="SubjectLogonId">0x3e7</Data>'
            f'<Data Name="TargetUserSid">{user_sid}</Data>'
            f'<Data Name="TargetUserName">{user}</Data>'
            f'<Data Name="TargetDomainName">{user_domain}</Data>'
            f'<Data Name="TargetLogonId">0x{random.randint(0x10000, 0xFFFFF):x}</Data>'
            f'<Data Name="LogonType">{logon_type}</Data>'
            f'<Data Name="LogonProcessName">NtLmSsp</Data>'
            f'<Data Name="AuthenticationPackageName">NTLM</Data>'
            f'<Data Name="WorkstationName">{host}</Data>'
            f'<Data Name="LogonGuid">{{00000000-0000-0000-0000-000000000000}}</Data>'
            f'<Data Name="TransmittedServices">-</Data>'
            f'<Data Name="LmPackageName">-</Data>'
            f'<Data Name="KeyLength">0</Data>'
            f'<Data Name="ProcessId">0x{random.randint(100, 9999):x}</Data>'
            f'<Data Name="ProcessName">C:\\Windows\\System32\\lsass.exe</Data>'
            f'<Data Name="IpAddress">{source_ip}</Data>'
            f'<Data Name="IpPort">{random.randint(49152, 65535)}</Data>'
            f'<Data Name="ImpersonationLevel">%%1833</Data>'
            f'</EventData>'
            f'</Event>'
        )

    elif template == "kerberos_tgt":
        xml = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing" '
            f'Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>'
            f'<EventID>4768</EventID>'
            f'<Version>0</Version>'
            f'<Level>0</Level>'
            f'<Task>14339</Task>'
            f'<Opcode>0</Opcode>'
            f'<Keywords>0x8020000000000000</Keywords>'
            f'<TimeCreated SystemTime="{ts}"/>'
            f'<EventRecordID>{random.randint(100000, 999999)}</EventRecordID>'
            f'<Channel>Security</Channel>'
            f'<Computer>{host}</Computer>'
            f'<Security UserID="{user_sid}"/>'
            f'</System>'
            f'<EventData>'
            f'<Data Name="TargetUserName">{user}@CORP.LOCAL</Data>'
            f'<Data Name="TargetDomainName">CORP.LOCAL</Data>'
            f'<Data Name="TargetSid">{user_sid}</Data>'
            f'<Data Name="ServiceName">krbtgt</Data>'
            f'<Data Name="ServiceSid">S-1-5-21-3623811015-3361044348-30300820-502</Data>'
            f'<Data Name="TicketOptions">0x40810010</Data>'
            f'<Data Name="Status">0x0</Data>'
            f'<Data Name="TicketEncryptionType">0x12</Data>'
            f'<Data Name="PreAuthType">15</Data>'
            f'<Data Name="IpAddress">::ffff:192.168.1.{random.randint(10, 12)}</Data>'
            f'<Data Name="IpPort">{random.randint(49152, 65535)}</Data>'
            f'</EventData>'
            f'</Event>'
        )

    elif template == "service_install":
        service_name = fields.get("service_name", "TestService")
        service_path = fields.get("service_path", "C:\\Windows\\TestService.exe")
        event_id = int(fields.get("event_id", 7045))
        xml = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System>'
            f'<Provider Name="Service Control Manager" '
            f'Guid="{{555908d1-a6d7-4695-8e1e-26931d2012f4}}"/>'
            f'<EventID>{event_id}</EventID>'
            f'<Version>0</Version>'
            f'<Level>4</Level>'
            f'<Task>0</Task>'
            f'<Opcode>0</Opcode>'
            f'<Keywords>0x8080000000000000</Keywords>'
            f'<TimeCreated SystemTime="{ts}"/>'
            f'<EventRecordID>{random.randint(100000, 999999)}</EventRecordID>'
            f'<Channel>System</Channel>'
            f'<Computer>{host}</Computer>'
            f'<Security UserID="{user_sid}"/>'
            f'</System>'
            f'<EventData>'
            f'<Data Name="ServiceName">{service_name}</Data>'
            f'<Data Name="ImagePath">{service_path}</Data>'
            f'<Data Name="ServiceType">user mode service</Data>'
            f'<Data Name="StartType">demand start</Data>'
            f'<Data Name="AccountName">LocalSystem</Data>'
            f'</EventData>'
            f'</Event>'
        )

    else:
        # Generic security event
        xml = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID>4634</EventID>'
            f'<TimeCreated SystemTime="{ts}"/>'
            f'<Computer>{host}</Computer>'
            f'<Channel>Security</Channel>'
            f'</System>'
            f'<EventData>'
            f'<Data Name="TargetUserSid">{user_sid}</Data>'
            f'<Data Name="TargetUserName">{user}</Data>'
            f'<Data Name="TargetDomainName">{user_domain}</Data>'
            f'<Data Name="TargetLogonId">0x{random.randint(0x10000, 0xFFFFF):x}</Data>'
            f'<Data Name="LogonType">3</Data>'
            f'</EventData>'
            f'</Event>'
        )

    return {
        "source_type": "winevt_xml",
        "raw": xml
    }


def build_syslog(template: str, ts: str, host: str, fields: dict,
                 entities: EntityDirectory) -> dict:
    """Build a syslog event."""
    host_ip = entities.host_ip(host)

    if template == "firewall_pass":
        iface_in = fields.get("interface_in", "em0")
        iface_out = fields.get("interface_out", "em1")
        src_ip = fields.get("src_ip", "192.168.1.10")
        dst_ip = fields.get("dst_ip", "151.101.1.140")
        src_port = fields.get("src_port", str(random.randint(49152, 65535)))
        dst_port = fields.get("dst_port", "443")
        proto = fields.get("protocol", "tcp")
        raw = (
            f"<134>{ts} {host} filterlog[12345]: "
            f"6,,,1000000103,{iface_in},match,pass,out,"
            f"4,0x0,,64,0,0,DF,6,{proto},60,"
            f"{src_ip},{dst_ip},{src_port},{dst_port},0,S,0,,mss;nop;wscale"
        )

    elif template == "firewall_block":
        iface_in = fields.get("interface_in", "em0")
        src_ip = fields.get("src_ip", "203.0.113.50")
        dst_ip = fields.get("dst_ip", "10.0.0.1")
        src_port = fields.get("src_port", str(random.randint(49152, 65535)))
        dst_port = fields.get("dst_port", "22")
        proto = fields.get("protocol", "tcp")
        raw = (
            f"<134>{ts} {host} filterlog[12345]: "
            f"4,,,1000000100,{iface_in},match,block,in,"
            f"4,0x0,,128,0,0,DF,6,{proto},60,"
            f"{src_ip},{dst_ip},{src_port},{dst_port},0,S,0,,mss;nop;wscale"
        )

    elif template == "firewall_nat":
        src_ip = fields.get("src_ip", "192.168.1.10")
        translated_ip = fields.get("translated_ip", "203.0.113.1")
        dst_ip = fields.get("dst_ip", "151.101.1.140")
        raw = (
            f"<134>{ts} {host} pf[0]: "
            f"NAT {src_ip} -> {translated_ip} -> {dst_ip}:443"
        )

    elif template == "firewall_state":
        message = fields.get("message", "State table entries: 1000")
        raw = f"<134>{ts} {host} kernel[0]: {message}"

    else:
        raw = f"<134>{ts} {host} generic[1]: {template}"

    return {
        "source_type": "syslog",
        "raw_message": raw,
        "transport": "tcp",
        "remote_addr": host_ip
    }


# ---------------------------------------------------------------------------
# Event dispatcher
# ---------------------------------------------------------------------------

def build_event(source_type: str, template: str, ts: str, host: str,
                fields: dict, entities: EntityDirectory) -> dict:
    """Route to the correct builder."""
    if source_type == "sentinel_edr":
        return build_sentinel_edr(template, ts, host, fields, entities)
    elif source_type == "sentinel_av":
        return build_sentinel_av(template, ts, host, fields, entities)
    elif source_type == "sentinel_dlp":
        return build_sentinel_dlp(template, ts, host, fields, entities)
    elif source_type == "sentinel_ndr":
        return build_sentinel_ndr(template, ts, fields, entities)
    elif source_type == "winevt_xml":
        return build_winevt_xml(template, ts, host, fields, entities)
    elif source_type == "syslog":
        return build_syslog(template, ts, host, fields, entities)
    else:
        raise ValueError(f"Unknown source_type: {source_type}")


# ---------------------------------------------------------------------------
# Scenario + noise generation
# ---------------------------------------------------------------------------

def generate_attack_events(scenario: dict, start_time: datetime,
                           entities: EntityDirectory, rng: random.Random) -> list:
    """Parse scenario timeline and produce concrete attack events."""
    actors = scenario.get("actors", {})
    evaluator = TemplateEvaluator(entities, actors, rng)
    events = []

    for entry in scenario.get("timeline", []):
        offset_sec = entry.get("time_offset_sec", 0)
        ts = start_time + timedelta(seconds=offset_sec)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}"[:-3] + "Z"

        source_type = entry["source_type"]
        template = entry["template"]

        # Resolve host
        host_raw = entry.get("host", "")
        host = evaluator.evaluate(host_raw) if host_raw else ""

        # Resolve fields
        raw_fields = entry.get("fields", {})
        resolved_fields = {}
        user_field = raw_fields.get("user", "")
        user = evaluator.evaluate(user_field) if user_field else None

        for k, v in raw_fields.items():
            resolved_fields[k] = evaluator.evaluate(str(v), host=host, user=user)

        event = build_event(source_type, template, ts_str, host,
                            resolved_fields, entities)
        events.append((ts, event, True))  # True = attack event

    return events


def load_profiles(profiles_dir: Path) -> dict:
    """Load all noise profiles from YAML files."""
    profiles = {}
    if not profiles_dir.exists():
        return profiles

    for f in profiles_dir.glob("*.yaml"):
        with open(f) as fh:
            data = yaml.safe_load(fh)
        if data and "name" in data:
            profiles[data["name"]] = data

    return profiles


def generate_noise_events(entities: EntityDirectory, profiles: dict,
                          start_time: datetime, duration_minutes: int,
                          noise_count: int, rng: random.Random) -> list:
    """Generate background noise events for all hosts."""
    events = []
    duration_sec = duration_minutes * 60

    # Build list of (host, profile_data) pairs
    host_profiles = []
    for hname, hdata in entities.hosts.items():
        profile_name = hdata.get("profile", "workstation")
        profile = profiles.get(profile_name)
        if profile:
            host_profiles.append((hname, hdata, profile))

    if not host_profiles:
        return events

    # Calculate total weight across all hosts
    total_rate = sum(p["events_per_minute"] for _, _, p in host_profiles)
    if total_rate == 0:
        return events

    # Distribute noise events across hosts proportionally
    for hname, hdata, profile in host_profiles:
        host_ratio = profile["events_per_minute"] / total_rate
        host_event_count = max(1, int(noise_count * host_ratio))
        host_users = hdata.get("users", ["SYSTEM"])

        templates = profile.get("event_templates", [])
        if not templates:
            continue

        # Build weighted selection
        weights = [t.get("weight", 1) for t in templates]

        evaluator = TemplateEvaluator(entities, {}, rng)

        for _ in range(host_event_count):
            # Random time within duration
            offset = rng.uniform(0, duration_sec)
            ts = start_time + timedelta(seconds=offset)
            ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}"[:-3] + "Z"

            # Pick template by weight
            tmpl = rng.choices(templates, weights=weights, k=1)[0]
            source_type = tmpl["source_type"]
            template_name = tmpl["template"]

            # Resolve fields
            user = rng.choice(host_users) if host_users else "SYSTEM"
            raw_fields = tmpl.get("fields", {})
            resolved_fields = {}
            for k, v in raw_fields.items():
                resolved_fields[k] = evaluator.evaluate(str(v), host=hname, user=user)

            # Ensure user is set
            if "user" not in resolved_fields:
                resolved_fields["user"] = user

            event = build_event(source_type, template_name, ts_str, hname,
                                resolved_fields, entities)
            events.append((ts, event, False))  # False = noise event

    return events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SentinelSIEM Scenario Generator - generates NDJSON event streams"
    )
    parser.add_argument(
        "--scenario", "-s", required=True,
        help="Scenario name (without .yaml extension) from the scenarios/ directory"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output file path for NDJSON (use '-' for stdout)"
    )
    parser.add_argument(
        "--noise-ratio", type=float, default=0.95,
        help="Ratio of noise events to total events (default: 0.95)"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducible output"
    )
    parser.add_argument(
        "--start-time", default=None,
        help="Start time in ISO8601 format (default: now minus duration)"
    )
    parser.add_argument(
        "--scenarios-dir", default=str(SCENARIOS_DIR),
        help="Path to scenarios directory"
    )
    parser.add_argument(
        "--profiles-dir", default=str(PROFILES_DIR),
        help="Path to noise profiles directory"
    )
    parser.add_argument(
        "--entities-dir", default=str(ENTITIES_DIR),
        help="Path to entities directory"
    )

    args = parser.parse_args()

    # Initialize RNG
    rng = random.Random(args.seed)
    if args.seed is not None:
        random.seed(args.seed)  # Also seed module-level random for builders

    # Load entities
    entities_dir = Path(args.entities_dir)
    entities = EntityDirectory(entities_dir)
    print(f"Loaded {len(entities.hosts)} hosts, {len(entities.users)} users", file=sys.stderr)

    # Load scenario
    scenario_path = Path(args.scenarios_dir) / f"{args.scenario}.yaml"
    if not scenario_path.exists():
        print(f"ERROR: Scenario file not found: {scenario_path}", file=sys.stderr)
        sys.exit(1)
    with open(scenario_path) as f:
        scenario = yaml.safe_load(f)
    print(f"Loaded scenario: {scenario['name']} ({scenario.get('description', '')})",
          file=sys.stderr)

    # Parse start time
    if args.start_time:
        start_time = datetime.fromisoformat(args.start_time.replace("Z", "+00:00"))
    else:
        duration = scenario.get("duration_minutes", 60)
        start_time = datetime.now(timezone.utc) - timedelta(minutes=duration)

    duration_minutes = scenario.get("duration_minutes", 60)

    # Generate attack events
    attack_events = generate_attack_events(scenario, start_time, entities, rng)
    attack_count = len(attack_events)
    print(f"Generated {attack_count} attack events", file=sys.stderr)

    # Calculate noise count to achieve desired ratio
    if args.noise_ratio > 0 and args.noise_ratio < 1:
        noise_count = int(attack_count * args.noise_ratio / (1 - args.noise_ratio))
    elif args.noise_ratio == 0:
        noise_count = 0
    else:
        noise_count = attack_count * 19  # 95% default

    # Load profiles and generate noise
    profiles = load_profiles(Path(args.profiles_dir))
    print(f"Loaded {len(profiles)} noise profiles", file=sys.stderr)

    noise_events = generate_noise_events(
        entities, profiles, start_time, duration_minutes, noise_count, rng
    )
    print(f"Generated {len(noise_events)} noise events", file=sys.stderr)

    # Merge and sort by timestamp
    all_events = attack_events + noise_events
    all_events.sort(key=lambda x: x[0])

    total = len(all_events)
    actual_attack = sum(1 for _, _, is_attack in all_events if is_attack)
    actual_noise = total - actual_attack
    print(f"Total events: {total} (attack: {actual_attack}, noise: {actual_noise}, "
          f"ratio: {actual_noise/total*100:.1f}% noise)" if total > 0 else "No events",
          file=sys.stderr)

    # Write NDJSON output
    if args.output == "-":
        out = sys.stdout
        close_out = False
    else:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out = open(out_path, "w", encoding="utf-8")
        close_out = True

    try:
        for _, event, _ in all_events:
            json.dump(event, out, separators=(",", ":"), ensure_ascii=False)
            out.write("\n")
    finally:
        if close_out:
            out.close()

    if args.output != "-":
        print(f"Wrote {total} events to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
