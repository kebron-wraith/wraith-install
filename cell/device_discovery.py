#!/usr/bin/env python3
"""
WRAITH v5.0 — Auto Device Discovery
=====================================
Automatically discovers devices on the local network:
- ARP table reading for known devices
- Ping sweep of /24 subnet (255 hosts, 50 parallel threads)
- mDNS/SSDP discovery for IoT devices
- Device classification: TV, phone, laptop, router, printer, camera, IoT, NAS
- Vulnerability detection: RTSP cameras, JetDirect printers, MQTT brokers
- Stores device map in ~/.wraith/discovered_devices.json
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

CELL_HOME = Path(os.path.expanduser("~")) / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
DEVICE_DB = CELL_HOME / "discovered_devices.json"

log = logging.getLogger("wraith-device-discovery")

# ═══════════════════════════════════════════════════════════════
# DEVICE CLASSIFIER — Heuristic classification by MAC/vendor/port
# ═══════════════════════════════════════════════════════════════

VENDOR_SIGNATURES: Dict[str, str] = {
    "apple": "phone",       # Phones/tablets
    "samsung": "phone",
    "huawei": "phone",
    "xiaomi": "phone",
    "oneplus": "phone",
    "google": "phone",
    "microsoft": "laptop",
    "dell": "laptop",
    "hp": "laptop",
    "hewlett": "laptop",
    "lenovo": "laptop",
    "asus": "laptop",
    "acer": "laptop",
    "intel": "laptop",
    "tp-link": "router",
    "netgear": "router",
    "linksys": "router",
    "ubiquiti": "router",
    "mikrotik": "router",
    "cisco": "router",
    "asus": "router",
    "canon": "printer",
    "epson": "printer",
    "brother": "printer",
    "xerox": "printer",
    "lexmark": "printer",
    "kyocera": "printer",
    "ricoh": "printer",
    "konica": "printer",
    "samsung": "printer",
    "lg": "tv",
    "sony": "tv",
    "samsung": "tv",
    "tcl": "tv",
    "hisense": "tv",
    "vizio": "tv",
    "panasonic": "tv",
    "philips": "tv",
    "western digital": "nas",
    "wd": "nas",
    "qnap": "nas",
    "synology": "nas",
    "netgear": "nas",
    "buffalo": "nas",
    "drobo": "nas",
    "hikvision": "camera",
    "dahua": "camera",
    "axis": "camera",
    "foscam": "camera",
    "amcrest": "camera",
    "reolink": "camera",
    "wyze": "camera",
    "nest": "camera",
    "ring": "camera",
    "arlo": "camera",
    "tp-link": "iot",
    "tuya": "iot",
    "smartlife": "iot",
    "espressif": "iot",
    "esp": "iot",
    "raspberry": "iot",
    "arduino": "iot",
}

# Common ports for vulnerability detection
VULN_CHECKS: Dict[str, List[int]] = {
    "rtsp_camera": [554, 8554],
    "jetdirect_printer": [9100],
    "mqtt_broker": [1883, 8883],
    "upnp": [1900],
    "telnet": [23],
    "ftp": [21],
    "smb": [445, 139],
    "rdp": [3389],
    "vnc": [5900, 5901],
}


class DeviceInfo:
    """Represents a discovered network device."""

    def __init__(self, ip: str, mac: str = "00:00:00:00:00:00",
                 hostname: str = "", vendor: str = "",
                 device_type: str = "unknown",
                 open_ports: Optional[List[int]] = None,
                 vulnerabilities: Optional[List[Dict]] = None):
        self.ip = ip
        self.mac = mac.upper()
        self.hostname = hostname
        self.vendor = vendor
        self.device_type = device_type
        self.open_ports = open_ports or []
        self.vulnerabilities = vulnerabilities or []
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_seen = self.first_seen
        self.device_id = self._compute_id()

    def _compute_id(self) -> str:
        mac_clean = re.sub(r'[^a-f0-9]', '', self.mac.replace(':', '')).lower()
        if mac_clean:
            self.device_id = f"dev_{mac_clean[:12]}"
        else:
            self.device_id = f"dev_{secrets.token_hex(6)}"
        return self.device_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "open_ports": self.open_ports,
            "vulnerabilities": self.vulnerabilities,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "DeviceInfo":
        dev = cls(
            ip=data.get("ip", ""),
            mac=data.get("mac", "00:00:00:00:00:00"),
            hostname=data.get("hostname", ""),
            vendor=data.get("vendor", ""),
            device_type=data.get("device_type", "unknown"),
            open_ports=data.get("open_ports", []),
            vulnerabilities=data.get("vulnerabilities", []),
        )
        dev.device_id = data.get("device_id", dev.device_id)
        dev.first_seen = data.get("first_seen", dev.first_seen)
        dev.last_seen = data.get("last_seen", dev.last_seen)
        return dev


# ═══════════════════════════════════════════════════════════════
# DEVICE DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════

class DeviceDiscovery:
    """
    Auto-discovery of local network devices:
    - ARP table reading
    - Ping sweep (255 hosts, 50 threads)
    - mDNS/SSDP for IoT
    - Classification + vulnerability detection
    """

    def __init__(self, db_path: Optional[Path] = None,
                 max_threads: int = 50,
                 ping_timeout: float = 0.5):
        self.db_path = db_path or DEVICE_DB
        self.max_threads = max_threads
        self.ping_timeout = ping_timeout
        self._devices: Dict[str, DeviceInfo] = {}  # ip -> DeviceInfo
        self._lock = threading.Lock()
        self._rate_limiter = threading.Semaphore(max_threads)
        self._stop_event = threading.Event()
        self._local_ip = self._get_local_ip()
        self._subnet = self._compute_subnet()
        self._load()

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _compute_subnet(self) -> str:
        """Compute /24 subnet from local IP."""
        parts = self._local_ip.split(".")
        parts[-1] = "0"
        return ".".join(parts) + "/24"

    def _load(self):
        """Load previously discovered devices."""
        if self.db_path.exists():
            try:
                data = json.loads(self.db_path.read_text())
                for entry in data.get("devices", []):
                    dev = DeviceInfo.from_dict(entry)
                    self._devices[dev.ip] = dev
            except (json.JSONDecodeError, IOError):
                pass

    def _save(self):
        """Persist device map."""
        data = {
            "last_scan": datetime.now(timezone.utc).isoformat(),
            "subnet": self._subnet,
            "devices": [d.to_dict() for d in self._devices.values()],
        }
        try:
            self.db_path.write_text(json.dumps(data, indent=2, default=str))
        except IOError:
            pass

    # ── ARP Table ──────────────────────────────────────────────────

    def read_arp_table(self) -> List[Tuple[str, str]]:
        """Read system ARP table to find known devices."""
        arp_entries = []
        system = platform.system().lower()

        try:
            if system == "windows":
                output = subprocess.check_output(
                    ["arp", "-a"], text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                # Parse: IP  MAC  Type
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)"
                for match in re.finditer(pattern, output):
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    if mac != "ff:ff:ff:ff:ff:ff":
                        arp_entries.append((ip, mac))
            else:
                output = subprocess.check_output(
                    ["arp", "-an"], text=True, timeout=10
                )
                # Parse: ? (IP) at MAC on ...
                pattern = r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]+)"
                for match in re.finditer(pattern, output):
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    if mac != "(incomplete)":
                        arp_entries.append((ip, mac))
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
            log.debug(f"ARP table read failed: {exc}")

        return arp_entries

    # ── Ping Sweep ──────────────────────────────────────────────────

    def ping_host(self, ip: str) -> bool:
        """Ping a single host. Returns True if alive."""
        system = platform.system().lower()
        try:
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.ping_timeout * 1000)), ip]
                creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                result = subprocess.run(
                    cmd, capture_output=True, timeout=self.ping_timeout + 1,
                    creationflags=creationflags,
                )
                return result.returncode == 0
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(self.ping_timeout)), ip]
                result = subprocess.run(
                    cmd, capture_output=True, timeout=self.ping_timeout + 1,
                )
                return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    def ping_sweep(self, subnet: Optional[str] = None) -> List[str]:
        """
        Sweep /24 subnet with ping. Uses 50 parallel threads.
        Returns list of alive IPs.
        """
        target_subnet = subnet or self._subnet
        network = ipaddress.ip_network(target_subnet, strict=False)
        hosts = [str(h) for h in network.hosts()]  # 254 hosts

        alive: List[str] = []
        alive_lock = threading.Lock()

        def _ping_one(ip: str):
            with self._rate_limiter:
                if self.ping_host(ip):
                    with alive_lock:
                        alive.append(ip)

        log.info(f"Ping sweep: {len(hosts)} hosts with {self.max_threads} threads")
        with ThreadPoolExecutor(max_workers=self.max_threads) as pool:
            futures = {pool.submit(_ping_one, ip): ip for ip in hosts}
            for _ in as_completed(futures):
                pass  # results collected in alive list

        log.info(f"Ping sweep complete: {len(alive)} alive hosts")
        return alive

    # ── mDNS Discovery ──────────────────────────────────────────────

    def mdns_discover(self, timeout: float = 3.0) -> List[Dict[str, str]]:
        """
        Discover devices via mDNS (Bonjour/Avahi).
        Looks for common service types.
        """
        services = [
            "_http._tcp.local.",
            "_smb._tcp.local.",
            "_ipp._tcp.local.",       # Printers
            "_rtsp._tcp.local.",      # Cameras
            "_googlecast._tcp.local.",  # Chromecast
            "_airplay._tcp.local.",   # Apple TV
            "_raop._tcp.local.",      # AirPlay audio
            "_mqtt._tcp.local.",      # MQTT brokers
        ]

        discovered = []
        multicast_group = "224.0.0.251"
        multicast_port = 5353

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            # Build mDNS query packet
            query = self._build_mdns_query(services)
            sock.sendto(query, (multicast_group, multicast_port))

            # Collect responses
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    parsed = self._parse_mdns_response(data, addr[0])
                    if parsed:
                        discovered.append(parsed)
                except socket.timeout:
                    break
                except Exception:
                    continue

            sock.close()
        except Exception as exc:
            log.debug(f"mDNS discovery failed: {exc}")

        return discovered

    def _build_mdns_query(self, services: List[str]) -> bytes:
        """Build a simple mDNS query packet."""
        # Header: ID=0, Flags=0, Questions=1, etc.
        header = struct.pack(">HHHHHH", 0, 0, len(services), 0, 0, 0)
        body = b""
        for svc in services:
            encoded = svc.encode("utf-8")
            body += bytes([len(encoded)]) + encoded + b"\x00"
            body += struct.pack(">HH", 12, 1)  # PTR record, IN class
        return header + body

    def _parse_mdns_response(self, data: bytes, src_ip: str) -> Optional[Dict[str, str]]:
        """Parse mDNS response to extract service info."""
        if len(data) < 12:
            return None
        try:
            # Skip header, look for service names in payload
            text = data.decode("utf-8", errors="ignore")
            for line in text.split("\x00"):
                if line and len(line) > 5:
                    return {"ip": src_ip, "service_name": line, "type": "mdns"}
        except Exception:
            pass
        return None

    # ── SSDP Discovery ──────────────────────────────────────────────

    def ssdp_discover(self, timeout: float = 3.0) -> List[Dict[str, str]]:
        """
        Discover devices via SSDP (UPnP).
        Finds smart TVs, routers, media servers, cameras.
        """
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()

        discovered = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.sendto(ssdp_request, ("239.255.255.250", 1900))

            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode("utf-8", errors="ignore")
                    headers = {}
                    for line in response.split("\r\n"):
                        if ":" in line:
                            k, _, v = line.partition(":")
                            headers[k.strip().lower()] = v.strip()
                    discovered.append({
                        "ip": addr[0],
                        "type": "ssdp",
                        "server": headers.get("server", ""),
                        "st": headers.get("st", ""),
                        "location": headers.get("location", ""),
                    })
                except socket.timeout:
                    break
                except Exception:
                    continue

            sock.close()
        except Exception as exc:
            log.debug(f"SSDP discovery failed: {exc}")

        return discovered

    # ── Port Scan (Lightweight) ────────────────────────────────────

    def scan_common_ports(self, ip: str, ports: Optional[List[int]] = None) -> List[int]:
        """Scan common ports on a host. Returns list of open ports."""
        if ports is None:
            ports = [22, 23, 80, 443, 445, 9100, 1883, 554, 8554, 3389, 5900, 8080, 8443]
        open_ports = []

        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                continue

        return open_ports

    # ── Classification ──────────────────────────────────────────────

    def classify_device(self, ip: str, mac: str, vendor: str,
                        open_ports: List[int], hostname: str = "") -> str:
        """Classify device type based on available information."""
        # Check vendor signatures
        vendor_lower = vendor.lower()
        for sig, dtype in VENDOR_SIGNATURES.items():
            if sig in vendor_lower:
                return dtype

        # Check hostname hints
        hostname_lower = hostname.lower()
        if any(x in hostname_lower for x in ["tv", "smarttv", "bravia", "roku", "appletv", "chromecast"]):
            return "tv"
        if any(x in hostname_lower for x in ["phone", "iphone", "android", "mobile"]):
            return "phone"
        if any(x in hostname_lower for x in ["printer", "print", "hp-", "canon"]):
            return "printer"
        if any(x in hostname_lower for x in ["camera", "cam", "dvr", "nvr"]):
            return "camera"
        if any(x in hostname_lower for x in ["router", "gateway", "ap-", "wifi"]):
            return "router"
        if any(x in hostname_lower for x in ["nas", "synology", "qnap", "storage"]):
            return "nas"

        # Check port-based classification
        port_set = set(open_ports)
        if {554, 8554} & port_set:
            return "camera"
        if {9100} & port_set:
            return "printer"
        if {1883, 8883} & port_set:
            return "iot"
        if {80, 443, 8080, 8443} & port_set and len(port_set) <= 3:
            return "iot"
        if {445, 139} & port_set:
            return "nas"
        if {22, 80, 443} & port_set:
            return "laptop"  # Likely a computer/server

        return "unknown"

    # ── Vulnerability Detection ────────────────────────────────────

    def check_vulnerabilities(self, ip: str, open_ports: List[int]) -> List[Dict]:
        """Check for known vulnerabilities based on open ports."""
        vulns = []
        port_set = set(open_ports)

        if port_set & {554, 8554}:
            vulns.append({
                "type": "rtsp_camera",
                "severity": "medium",
                "description": "RTSP camera stream detected. Check for default credentials.",
                "ports": list(port_set & {554, 8554}),
                "recommendation": "Change default credentials, enable RTSP auth",
            })

        if 9100 in port_set:
            vulns.append({
                "type": "jetdirect_printer",
                "severity": "low",
                "description": "JetDirect printer port open. May allow unauthenticated access.",
                "ports": [9100],
                "recommendation": "Enable printer authentication, restrict network access",
            })

        if 1883 in port_set:
            vulns.append({
                "type": "mqtt_broker",
                "severity": "high",
                "description": "MQTT broker without TLS detected. May allow message interception.",
                "ports": [1883],
                "recommendation": "Enable MQTT over TLS (port 8883), add authentication",
            })

        if 23 in port_set:
            vulns.append({
                "type": "telnet",
                "severity": "high",
                "description": "Telnet service detected. Sends data in cleartext.",
                "ports": [23],
                "recommendation": "Disable telnet, use SSH instead",
            })

        if 21 in port_set:
            vulns.append({
                "type": "ftp",
                "severity": "medium",
                "description": "FTP service detected. May allow anonymous access.",
                "ports": [21],
                "recommendation": "Use SFTP instead, disable anonymous access",
            })

        if {445, 139} & port_set:
            vulns.append({
                "type": "smb",
                "severity": "medium",
                "description": "SMB file sharing detected. Check for EternalBlue / outdated SMB.",
                "ports": list(port_set & {445, 139}),
                "recommendation": "Update to SMBv3, disable SMBv1",
            })

        if 3389 in port_set:
            vulns.append({
                "type": "rdp",
                "severity": "medium",
                "description": "RDP exposed. Check for BlueKeep / weak credentials.",
                "ports": [3389],
                "recommendation": "Enable NLA, use VPN for RDP access",
            })

        return vulns

    # ── Full Discovery ──────────────────────────────────────────────

    def discover(self, full_scan: bool = False) -> Dict[str, DeviceInfo]:
        """
        Run full device discovery:
        1. Read ARP table
        2. Ping sweep
        3. mDNS/SSDP
        4. Port scan + classify + vuln check
        """
        log.info(f"Starting device discovery on {self._subnet}")
        start_time = time.time()

        # Phase 1: ARP table
        arp_entries = self.read_arp_table()
        for ip, mac in arp_entries:
            if ip not in self._devices:
                vendor = self._lookup_vendor(mac)
                self._devices[ip] = DeviceInfo(
                    ip=ip, mac=mac, vendor=vendor,
                    device_type=self.classify_device(ip, mac, vendor, []),
                )
        log.info(f"ARP table: {len(arp_entries)} entries")

        # Phase 2: Ping sweep
        alive_hosts = self.ping_sweep()
        for ip in alive_hosts:
            if ip == self._local_ip:
                continue
            if ip not in self._devices:
                self._devices[ip] = DeviceInfo(
                    ip=ip, device_type="unknown",
                )
        log.info(f"Ping sweep: {len(alive_hosts)} alive")

        # Phase 3: mDNS + SSDP
        mdns_results = self.mdns_discover()
        ssdp_results = self.ssdp_discover()
        for result in mdns_results + ssdp_results:
            ip = result.get("ip", "")
            if ip and ip not in self._devices:
                self._devices[ip] = DeviceInfo(
                    ip=ip, device_type="iot",
                )
            if ip and ip in self._devices:
                # Update with service info
                if result.get("service_name"):
                    self._devices[ip].hostname = result["service_name"]

        # Phase 4: Port scan + classify (only if full_scan)
        if full_scan:
            scan_targets = [
                ip for ip, dev in self._devices.items()
                if dev.device_type == "unknown"
            ]
            log.info(f"Port scanning {len(scan_targets)} unknown devices")
            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {
                    pool.submit(self.scan_common_ports, ip): ip
                    for ip in scan_targets[:50]  # Limit to 50 for speed
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        open_ports = future.result()
                        dev = self._devices.get(ip)
                        if dev:
                            dev.open_ports = open_ports
                            dev.vulnerabilities = self.check_vulnerabilities(ip, open_ports)
                            dev.device_type = self.classify_device(
                                ip, dev.mac, dev.vendor, open_ports, dev.hostname
                            )
                    except Exception:
                        pass

        # Update last_seen
        now = datetime.now(timezone.utc).isoformat()
        for dev in self._devices.values():
            dev.last_seen = now

        # Save
        self._save()
        elapsed = time.time() - start_time
        log.info(
            f"Discovery complete: {len(self._devices)} devices in {elapsed:.1f}s"
        )
        return self._devices

    def _lookup_vendor(self, mac: str) -> str:
        """Look up vendor from MAC OUI."""
        # Simple OUI lookup — in production, use a full OUI database
        prefix = mac.upper()[:8]
        # This is a simplified placeholder
        return ""

    def get_devices(self) -> Dict[str, DeviceInfo]:
        """Get all discovered devices."""
        with self._lock:
            return dict(self._devices)

    def get_devices_by_type(self, device_type: str) -> List[DeviceInfo]:
        """Get devices filtered by type."""
        with self._lock:
            return [d for d in self._devices.values() if d.device_type == device_type]

    def get_vulnerable_devices(self) -> List[DeviceInfo]:
        """Get devices with detected vulnerabilities."""
        with self._lock:
            return [d for d in self._devices.values() if d.vulnerabilities]

    def get_device_count(self) -> int:
        with self._lock:
            return len(self._devices)

    @property
    def is_healthy(self) -> bool:
        return self.get_device_count() > 0

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_devices": len(self._devices),
                "subnet": self._subnet,
                "devices": {ip: d.to_dict() for ip, d in self._devices.items()},
            }
