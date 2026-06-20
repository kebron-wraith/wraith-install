"""WRAITH Cell v5.0 — IoT/OT Defense Agent.
Monitors for IoT device vulnerabilities, OT/ICS network threats,
firmware tampering, and industrial control system attacks.
Covers: MQTT/CoAP vulnerabilities, Modbus/S7comm exploits,
firmware analysis, rogue device detection, SCADA threats.
"""
from __future__ import annotations
import logging, time, json, hashlib, os, re, platform, socket, subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger("wraith.iot_defense")

# Common IoT/OT ports to monitor
_IOT_PORTS = {
    1883:  "MQTT",
    8883:  "MQTT-TLS",
    5683:  "CoAP",
    5684:  "CoAP-DTLS",
    47808: "BACnet",
    102:   "S7comm",
    502:   "Modbus",
    44818: "EtherNet/IP",
    2222:  "EtherNet/IP-CIP",
    789:   "Red Lion",
    1911:  "Niagara Fox",
    1962:  "PCWorx",
    20000: "DNP3",
    34964: "Profinet",
    4840:  "OPC-UA",
    4843:  "OPC-UA-SSL",
}

# Known IoT/OT vulnerability signatures
_IOT_VULN_PATTERNS = {
    "mqtt_auth_bypass":     r"(?:mqtt|broker).*(?:no.?auth|anonymous|default.?pass)",
    "modbus_no_auth":      r"modbus.*(?:no.?auth|open|unprotected)",
    "telnet_enabled":      r"telnet.*(?:open|enabled|running)",
    "default_creds":       r"(?:admin|root|user|default|password|1234|0000)",
    "firmware_outdated":    r"(?:firmware|version).*(?:outdated|old|vulnerable)",
    "unencrypted_ot":      r"(?:modbus|s7|dnp3|bacnet).*(?:no.?encrypt|plaintext)",
}

# Known IoT malware families
_IOT_MALWARE = {
    "Mirai":        {"type": "botnet", "targets": ["cameras", "routers", "DVRs"]},
    "Mozi":         {"type": "botnet", "targets": ["routers", "IoT"]},
    "Hajime":       {"type": "botnet", "targets": ["IoT"]},
    "Bashlite":     {"type": "botnet", "targets": ["Linux IoT"]},
    "Reaper":       {"type": "botnet", "targets": ["routers", "cameras"]},
    "VPNFilter":    {"type": "APT",    "targets": ["routers"]},
    "BlackEnergy":  {"type": "APT",    "targets": ["SCADA", "ICS"]},
    "Industroyer":  {"type": "APT",    "targets": ["SCADA", "power grid"]},
    "Pipedream":    {"type": "APT",    "targets": ["ICS", "OT"]},
    "Incontroller": {"type": "APT",    "targets": ["ICS", "OT"]},
}

# OT/ICS MITRE ATT&CK techniques
_OT_TTPS = [
    {"id": "T0802", "name": "Automated Collection", "description": "Collect OT data via automated means"},
    {"id": "T0803", "name": "Block Command Message", "description": "Block OT command messages"},
    {"id": "T0804", "name": "Block Reporting Message", "description": "Block OT reporting messages"},
    {"id": "T0805", "name": "Block Serial COM", "description": "Block serial communications"},
    {"id": "T0809", "name": "Data Destruction", "description": "Destroy OT data"},
    {"id": "T0813", "name": "Denial of Service", "description": "DoS on OT systems"},
    {"id": "T0815", "name": "Denial of View", "description": "Blind operators by denying data"},
    {"id": "T0816", "name": "Device Restart/Shutdown", "description": "Restart/shutdown OT devices"},
    {"id": "T0830", "name": "Adversary-in-the-Middle", "description": "MitM on OT protocols"},
    {"id": "T0831", "name": "Manipulation of Control", "description": "Manipulate OT control processes"},
    {"id": "T0836", "name": "Modify Parameter", "description": "Modify OT device parameters"},
    {"id": "T0855", "name": "Unauthorized Command Message", "description": "Send unauthorized OT commands"},
]


class IoTDefenseAgent:
    """Monitors and defends against IoT/OT/ICS threats."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.active = False
        self._findings: list[dict] = []
        self._threat_count = 0
        self._last_scan = 0.0
        self._rogue_devices: list[dict] = []
        self._ot_connections: list[dict] = []
        _LOG.info("IoTDefenseAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("IoTDefenseAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("IoTDefenseAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for IoT/OT vulnerabilities and threats."""
        try:
            findings = []
            now = time.time()

            # 1. Scan for open IoT/OT ports
            port_findings = self._scan_iot_ports()
            findings.extend(port_findings)

            # 2. Check for rogue devices on network
            rogue_findings = self._detect_rogue_devices()
            findings.extend(rogue_findings)

            # 3. Check for IoT malware indicators
            malware_findings = self._check_iot_malware()
            findings.extend(malware_findings)

            # 4. Analyze OT protocol security
            ot_findings = self._analyze_ot_protocols()
            findings.extend(ot_findings)

            # 5. Check for firmware tampering indicators
            firmware_findings = self._check_firmware_integrity()
            findings.extend(firmware_findings)

            self._findings.extend(findings)
            self._threat_count += len(findings)
            self._last_scan = now

            return {
                "status": "ok",
                "iot_threats": len(findings),
                "total_threats": self._threat_count,
                "rogue_devices": len(self._rogue_devices),
                "ot_connections": len(self._ot_connections),
                "findings": findings,
            }
        except Exception as exc:
            _LOG.error("IoT defense scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze IoT/OT threat findings."""
        try:
            findings = data.get("findings", [])
            if not findings:
                return {"iot_risk": "low", "score": 0, "ot_safe": True}

            severity_scores = {"critical": 35, "high": 25, "medium": 12, "low": 5}
            score = sum(severity_scores.get(f.get("severity", "low"), 5) for f in findings)
            score = min(score, 100)

            level = "low"
            if score >= 75:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"

            categories = {}
            for f in findings:
                cat = f.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

            return {
                "iot_risk": level,
                "score": score,
                "categories": categories,
                "ot_safe": score < 25,
                "recommendation": self._recommend(level, categories),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {
            "agent": "IoTDefense",
            "active": self.active,
            "total_threats": self._threat_count,
            "rogue_devices": len(self._rogue_devices),
            "ot_connections": len(self._ot_connections),
            "last_findings": self._findings[-5:],
        }

    # --- internal checks ---

    def _scan_iot_ports(self) -> list[dict]:
        """Scan for open IoT/OT ports on the local network."""
        findings = []
        for port, protocol in _IOT_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                if result == 0:
                    severity = "high" if protocol in ("Modbus", "S7comm", "BACnet", "OPC-UA") else "medium"
                    findings.append({
                        "type": "open_ot_port",
                        "category": "port_scan",
                        "severity": severity,
                        "port": port,
                        "protocol": protocol,
                        "detail": f"{protocol} port {port} is open — potential OT/IoT exposure",
                        "ts": time.time(),
                    })
            except Exception:
                pass
        return findings

    def _detect_rogue_devices(self) -> list[dict]:
        """Detect rogue/unauthorized devices on the network."""
        findings = []
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["arp", "-an"], timeout=10).decode(errors="ignore")

            # Parse ARP table for unknown devices
            local_ip = "127.0.0.1"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass

            subnet = ".".join(local_ip.split(".")[:3])
            known_prefixes = [f"{subnet}."]

            for line in out.splitlines():
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                mac_match = re.search(r"([\w-]{17}|[\w:]{17})", line)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).replace("-", ":").lower()
                    # Check if device is new (not in known list)
                    if mac not in [d.get("mac") for d in self._rogue_devices]:
                        if any(ip.startswith(p) for p in known_prefixes):
                            self._rogue_devices.append({
                                "ip": ip, "mac": mac, "first_seen": time.time(),
                            })
                            # Flag if MAC OUI matches known IoT vendors
                            if self._is_iot_oui(mac):
                                findings.append({
                                    "type": "iot_device_detected",
                                    "category": "rogue_device",
                                    "severity": "medium",
                                    "ip": ip,
                                    "mac": mac,
                                    "detail": f"New IoT device detected: {ip} ({mac})",
                                    "ts": time.time(),
                                })
        except Exception:
            pass
        return findings

    def _is_iot_oui(self, mac: str) -> bool:
        """Check if MAC OUI belongs to known IoT vendors."""
        iot_ouis = [
            "b8:27:eb", "dc:a6:32", "e4:5f:01",  # Raspberry Pi
            "00:17:88", "ec:b5:fa", "d8:f1:5b",  # Philips Hue
            "68:37:e9", "7c:49:eb",              # Amazon Echo
            "f0:f6:1c", "74:c2:46",              # Google Home
            "b0:09:93", "c8:ba:94",              # Nest
            "44:61:32", "60:38:e0",              # ESP8266/ESP32
            "24:0a:c4", "30:ae:a4",              # ESP32
        ]
        return mac[:8].lower() in iot_ouis

    def _check_iot_malware(self) -> list[dict]:
        """Check for IoT malware indicators."""
        findings = []
        # Check for known malware processes
        malware_procs = {
            "mirai": ["mirai", "mirai.*bot"],
            "mozi": ["mozi", "mozi.*bot"],
            "hajime": ["hajime"],
            "reaper": ["reaper"],
            "vpnfilter": ["vpnfilter"],
        }
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["tasklist"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ps", "aux"], timeout=10).decode(errors="ignore")

            for malware, patterns in malware_procs.items():
                for pat in patterns:
                    if re.search(pat, out, re.IGNORECASE):
                        findings.append({
                            "type": "iot_malware",
                            "category": "malware",
                            "severity": "critical",
                            "malware": malware,
                            "detail": f"IoT malware '{malware}' process detected!",
                            "ts": time.time(),
                        })
        except Exception:
            pass

        # Check for brute-force SSH/Telnet (common IoT attack vector)
        if platform.system() != "Windows":
            try:
                auth_log = Path("/var/log/auth.log")
                if auth_log.exists():
                    content = auth_log.read_text(errors="ignore")
                    recent = content.splitlines()[-500:]
                    failed_ips = {}
                    for line in recent:
                        if "Failed password" in line:
                            ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                            if ip_match:
                                ip = ip_match.group(1)
                                failed_ips[ip] = failed_ips.get(ip, 0) + 1
                    for ip, count in failed_ips.items():
                        if count > 20:
                            findings.append({
                                "type": "iot_bruteforce",
                                "category": "bruteforce",
                                "severity": "high",
                                "source_ip": ip,
                                "attempts": count,
                                "detail": f"SSH brute-force from {ip} ({count} attempts) — common IoT attack",
                                "ts": time.time(),
                            })
            except Exception:
                pass

        return findings

    def _analyze_ot_protocols(self) -> list[dict]:
        """Analyze OT protocol security posture."""
        findings = []
        # Check for unencrypted OT protocol usage
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["netstat", "-an"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ss", "-tunapl"], timeout=10).decode(errors="ignore")

            for port, protocol in _IOT_PORTS.items():
                if str(port) in out and protocol in ("Modbus", "S7comm", "BACnet", "DNP3"):
                    findings.append({
                        "type": "unencrypted_ot",
                        "category": "ot_protocol",
                        "severity": "high",
                        "protocol": protocol,
                        "port": port,
                        "detail": f"{protocol} on port {port} — unencrypted OT protocol exposed",
                        "ts": time.time(),
                    })
                    self._ot_connections.append({
                        "protocol": protocol,
                        "port": port,
                        "encrypted": False,
                        "ts": time.time(),
                    })
        except Exception:
            pass
        return findings

    def _check_firmware_integrity(self) -> list[dict]:
        """Check for firmware tampering indicators."""
        findings = []
        # Check for common firmware modification tools
        fw_tools = ["binwalk", "firmwalker", "firmware-mod-kit", "flashrom"]
        for tool in fw_tools:
            try:
                if platform.system() == "Windows":
                    subprocess.check_output(["where", tool], timeout=5)
                else:
                    subprocess.check_output(["which", tool], timeout=5)
                self._findings.append({
                    "type": "fw_tool_present",
                    "category": "firmware",
                    "severity": "low",
                    "tool": tool,
                    "detail": f"Firmware analysis tool '{tool}' is installed",
                    "ts": time.time(),
                })
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        return findings

    def _recommend(self, level: str, categories: dict) -> str:
        if level == "critical":
            return "IMMEDIATE: Isolate affected IoT/OT devices. Block malware C2. Patch firmware."
        if level == "high":
            return "URGENT: Segment IoT network. Enable OT protocol encryption. Update firmware."
        if "rogue_device" in categories:
            return "Investigate new devices on network. Verify authorization. Apply network access control."
        if "ot_protocol" in categories:
            return "Enable encryption on all OT protocols. Implement network segmentation (Purdue model)."
        return "Monitor IoT/OT network. Maintain device inventory. Plan firmware update schedule."
