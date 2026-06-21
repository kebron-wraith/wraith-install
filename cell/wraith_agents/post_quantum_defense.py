"""WRAITH Cell v5.0 — Post-Quantum Cryptography Defense Agent.
Detects quantum-computing threats to classical encryption, monitors crypto
agility readiness, and enforces quantum-safe migration paths.
Covers: RSA/ECC vulnerability to Shor's, Grover's hash weakening,
quantum-safe algorithm adoption, hybrid crypto transitions.
"""
from __future__ import annotations
import logging, time, json, hashlib, os, re, platform, subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger("wraith.post_quantum")

# NIST PQC standard algorithms (finalized 2024-2025)
_PQC_ALGORITHMS = {
    "ML-KEM-512":   {"type": "KEM",  "nist_level": 1, "status": "final"},
    "ML-KEM-768":   {"type": "KEM",  "nist_level": 3, "status": "final"},
    "ML-KEM-1024":  {"type": "KEM",  "nist_level": 5, "status": "final"},
    "ML-DSA-44":    {"type": "sig",  "nist_level": 2, "status": "final"},
    "ML-DSA-65":    {"type": "sig",  "nist_level": 3, "status": "final"},
    "ML-DSA-87":    {"type": "sig",  "nist_level": 5, "status": "final"},
    "SLH-DSA-SHA2":  {"type": "sig",  "nist_level": 1, "status": "final"},
}

# Classical algorithms vulnerable to quantum attacks
_QUANTUM_VULNERABLE = {
    "RSA-1024":     {"vulnerability": "Shor's algorithm", "severity": "critical"},
    "RSA-2048":     {"vulnerability": "Shor's algorithm", "severity": "high"},
    "RSA-4096":     {"vulnerability": "Shor's algorithm", "severity": "medium"},
    "ECDSA-P256":   {"vulnerability": "Shor's algorithm", "severity": "high"},
    "ECDSA-P384":   {"vulnerability": "Shor's algorithm", "severity": "medium"},
    "ECDH-P256":    {"vulnerability": "Shor's algorithm", "severity": "high"},
    "DH-1024":      {"vulnerability": "Shor's algorithm", "severity": "critical"},
    "DH-2048":      {"vulnerability": "Shor's algorithm", "severity": "high"},
    "AES-128":      {"vulnerability": "Grover's algorithm (halved)", "severity": "medium"},
    "SHA-256":      {"vulnerability": "Grover's (collision)", "severity": "low"},
    "SHA-1":        {"vulnerability": "Grover's + classical breaks", "severity": "high"},
}

# Known quantum attack indicators in network traffic
_QUANTUM_ATTACK_INDICATORS = [
    r"harvest.?now.?decrypt.?later",
    r"quantum.?ready|quantum.?safe|post.?quantum",
    r"ML.?KEM|ML.?DSA|SLH.?DSA",
    r"kyber|dilithium|sphincs",
    r"crypto.?agility|algorithm.?agility",
    r"hybrid.?key.?exchange|hybrid.?signature",
]


class PostQuantumDefenseAgent:
    """Monitors and enforces post-quantum cryptography readiness."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.active = False
        self._findings: list[dict] = []
        self._vuln_count = 0
        self._last_scan = 0.0
        self._crypto_inventory: list[dict] = []
        _LOG.info("PostQuantumDefenseAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("PostQuantumDefenseAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("PostQuantumDefenseAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for quantum-vulnerable crypto and attack indicators."""
        try:
            findings = []
            now = time.time()

            # 1. Audit local TLS/SSL certificates
            cert_findings = self._audit_certificates()
            findings.extend(cert_findings)

            # 2. Check SSH key types
            ssh_findings = self._audit_ssh_keys()
            findings.extend(ssh_findings)

            # 3. Scan for quantum attack indicators in traffic
            attack_findings = self._detect_quantum_attacks()
            findings.extend(attack_findings)

            # 4. Check crypto library versions for PQC support
            lib_findings = self._check_pqc_library_support()
            findings.extend(lib_findings)

            # 5. Assess hash algorithm strength
            hash_findings = self._assess_hash_strength()
            findings.extend(hash_findings)

            self._findings.extend(findings)
            self._vuln_count += len(findings)
            self._last_scan = now

            return {
                "status": "ok",
                "quantum_vulns": len(findings),
                "total_vulns": self._vuln_count,
                "findings": findings,
                "crypto_inventory_size": len(self._crypto_inventory),
            }
        except Exception as exc:
            _LOG.error("Post-quantum scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze quantum vulnerability findings."""
        try:
            findings = data.get("findings", [])
            if not findings:
                return {"quantum_risk": "low", "score": 0, "ready": True}

            severity_scores = {"critical": 30, "high": 20, "medium": 10, "low": 5}
            score = sum(severity_scores.get(f.get("severity", "low"), 5) for f in findings)
            score = min(score, 100)

            level = "low"
            if score >= 75:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"

            # Categorize
            categories = {}
            for f in findings:
                cat = f.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

            return {
                "quantum_risk": level,
                "score": score,
                "categories": categories,
                "ready": score < 25,
                "recommendation": self._recommend(level, categories),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {
            "agent": "PostQuantumDefense",
            "active": self.active,
            "total_vulns": self._vuln_count,
            "crypto_inventory": len(self._crypto_inventory),
            "last_findings": self._findings[-5:],
        }

    # --- internal checks ---

    def _audit_certificates(self) -> list[dict]:
        """Audit local certificates for quantum-vulnerable algorithms."""
        findings = []
        cert_paths = self._find_certificates()
        for cert_path in cert_paths:
            try:
                content = Path(cert_path).read_text(errors="ignore")
                # Check for RSA < 4096 or ECDSA
                if re.search(r"RSA\s+(?:1024|2048)\b", content):
                    findings.append({
                        "type": "weak_rsa",
                        "category": "certificate",
                        "severity": "high",
                        "file": cert_path,
                        "detail": "RSA < 4096 is vulnerable to Shor's algorithm",
                        "ts": time.time(),
                    })
                if re.search(r"ECDSA|ecdsa", content, re.IGNORECASE):
                    findings.append({
                        "type": "ecdsa_cert",
                        "category": "certificate",
                        "severity": "medium",
                        "file": cert_path,
                        "detail": "ECDSA is vulnerable to quantum attacks",
                        "ts": time.time(),
                    })
                # Check for PQC algorithms (good)
                if any(alg in content.lower() for alg in ["kyber", "dilithium", "sphincs", "ml-kem", "ml-dsa"]):
                    self._crypto_inventory.append({
                        "file": cert_path,
                        "pqc": True,
                        "ts": time.time(),
                    })
            except (PermissionError, OSError):
                pass
        return findings

    def _find_certificates(self) -> list[str]:
        """Find certificate files on the system."""
        cert_paths = []
        home = str(Path.home())
        cert_dirs = [
            os.path.join(home, ".wraith"),
            os.path.join(home, ".ssh"),
        ]
        if platform.system() != "Windows":
            cert_dirs.extend(["/etc/ssl/certs", "/etc/ssh"])
        else:
            cert_dirs.append(os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "ssl"))

        for d in cert_dirs:
            if os.path.isdir(d):
                try:
                    for root, _, files in os.walk(d):
                        for f in files:
                            if f.endswith((".pem", ".crt", ".cer", ".key", ".pub")):
                                cert_paths.append(os.path.join(root, f))
                except PermissionError:
                    pass
        return cert_paths[:50]  # Cap at 50 to avoid slowdown

    def _audit_ssh_keys(self) -> list[dict]:
        """Check SSH key types for quantum resistance."""
        findings = []
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return findings

        for key_file in ssh_dir.iterdir():
            if key_file.suffix == ".pub" or key_file.name in ("id_rsa", "id_ecdsa", "id_ed25519"):
                try:
                    content = key_file.read_text(errors="ignore")
                    if "ssh-rsa" in content and "1024" in content:
                        findings.append({
                            "type": "weak_ssh_rsa",
                            "category": "ssh",
                            "severity": "high",
                            "file": str(key_file),
                            "detail": "RSA-1024 SSH key — quantum-vulnerable",
                            "ts": time.time(),
                        })
                    if "ecdsa-sha2" in content:
                        findings.append({
                            "type": "ecdsa_ssh",
                            "category": "ssh",
                            "severity": "medium",
                            "file": str(key_file),
                            "detail": "ECDSA SSH key — migrate to Ed25519 or PQC",
                            "ts": time.time(),
                        })
                    if "ssh-ed25519" in content:
                        self._crypto_inventory.append({
                            "file": str(key_file),
                            "pqc": False,
                            "quantum_safe": "partial",
                            "ts": time.time(),
                        })
                except (PermissionError, OSError):
                    pass
        return findings

    def _detect_quantum_attacks(self) -> list[dict]:
        """Detect quantum-related attack indicators in network/config."""
        findings = []
        # Check for harvest-now-decrypt-later patterns
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["netstat", "-an"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ss", "-tunapl"], timeout=10).decode(errors="ignore")

            # Look for unusual TLS negotiation patterns
            for line in out.splitlines():
                for pat in _QUANTUM_ATTACK_INDICATORS:
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append({
                            "type": "quantum_attack_indicator",
                            "category": "network",
                            "severity": "high",
                            "pattern": pat[:50],
                            "detail": "Possible quantum-related network activity",
                            "ts": time.time(),
                        })
        except Exception:
            pass
        return findings

    def _check_pqc_library_support(self) -> list[dict]:
        """Check if system crypto libraries support PQC algorithms."""
        findings = []
        # Check OpenSSL version for PQC support
        try:
            out = subprocess.check_output(["openssl", "version"], timeout=5).decode(errors="ignore")
            version_match = re.search(r"OpenSSL\s+(\d+\.\d+)", out)
            if version_match:
                ver = float(version_match.group(1))
                if ver < 3.0:
                    findings.append({
                        "type": "old_openssl",
                        "category": "library",
                        "severity": "medium",
                        "detail": f"OpenSSL {ver} — upgrade to 3.0+ for PQC support",
                        "ts": time.time(),
                    })
                else:
                    self._crypto_inventory.append({
                        "library": "openssl",
                        "version": ver,
                        "pqc": True,
                        "ts": time.time(),
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check for liboqs (Open Quantum Safe)
        try:
            if platform.system() != "Windows":
                out = subprocess.check_output(["pkg-config", "--modversion", "liboqs"], timeout=5).decode(errors="ignore")
                self._crypto_inventory.append({
                    "library": "liboqs",
                    "version": out.strip(),
                    "pqc": True,
                    "ts": time.time(),
                })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            findings.append({
                "type": "no_liboqs",
                "category": "library",
                "severity": "low",
                "detail": "liboqs not found — consider installing for PQC support",
                "ts": time.time(),
            })

        return findings

    def _assess_hash_strength(self) -> list[dict]:
        """Assess hash algorithm usage for quantum resistance."""
        findings = []
        # Check for SHA-1 usage in configs
        config_paths = [
            Path.home() / ".wraith" / ".env",
            Path.home() / ".ssh" / "config",
        ]
        for cp in config_paths:
            if cp.exists():
                try:
                    content = cp.read_text(errors="ignore")
                    if "sha1" in content.lower() or "sha-1" in content.lower():
                        findings.append({
                            "type": "sha1_usage",
                            "category": "hash",
                            "severity": "high",
                            "file": str(cp),
                            "detail": "SHA-1 detected — vulnerable to Grover's + classical attacks",
                            "ts": time.time(),
                        })
                except (PermissionError, OSError):
                    pass
        return findings

    def _recommend(self, level: str, categories: dict) -> str:
        if level == "critical":
            return "IMMEDIATE: Migrate all RSA < 4096 and ECDSA to PQC (ML-KEM/ML-DSA). Enable crypto agility."
        if level == "high":
            return "URGENT: Upgrade certificates to RSA-4096+ or PQC. Replace SSH RSA keys with Ed25519."
        if "library" in categories:
            return "Upgrade OpenSSL to 3.0+ and install liboqs for post-quantum support."
        if "hash" in categories:
            return "Replace SHA-1 with SHA-256/SHA-3 in all configurations."
        return "Monitor quantum computing advances. Plan crypto agility roadmap."
