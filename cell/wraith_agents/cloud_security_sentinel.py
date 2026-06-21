"""WRAITH Cell v5.0 — Cloud Security Sentinel Agent.
Monitors cloud infrastructure for misconfigurations, unauthorized access,
data exposure, and compliance violations.
Covers: AWS/Azure/GCP IAM, S3 bucket exposure, serverless security,
container escape, cloud trail analysis, compliance frameworks.
"""
from __future__ import annotations
import logging, time, json, hashlib, os, re, platform, subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger("wraith.cloud_sentinel")

# Cloud provider endpoints and indicators
_CLOUD_PROVIDERS = {
    "aws": {
        "metadata_url": "http://169.254.169.254/latest/meta-data/",
        "imds_v2": "http://169.254.169.254/latest/api/token",
        "services": ["s3", "ec2", "lambda", "iam", "rds", "eks", "cloudtrail"],
    },
    "azure": {
        "metadata_url": "http://169.254.169.254/metadata/instance",
        "services": ["blob", "vm", "functions", "aks", "keyvault", "cosmosdb"],
    },
    "gcp": {
        "metadata_url": "http://metadata.google.internal/computeMetadata/v1/",
        "services": ["gcs", "compute", "cloudfunctions", "gke", "bigquery", "pubsub"],
    },
}

# Cloud misconfiguration patterns
_MISCONFIG_PATTERNS = {
    "public_s3":       r"(?:s3|bucket).*(?:public|acl.*all|open)",
    "open_security_group": r"security.?group.*(?:0\.0\.0\.0|::/0|open)",
    "unencrypted_storage": r"(?:storage|disk|rds|efs).*(?:unencrypt|no.?encrypt)",
    "excessive_iam":   r"(?:iam|role|policy).*(?:admin|\\*|wildcard)",
    "no_logging":      r"(?:cloudtrail|audit|log).*(?:disabled|off|none)",
    "public_database": r"(?:rds|dynamodb|cosmos).*(?:public|accessible)",
    "no_mfa":          r"(?:mfa|2fa|multi.?factor).*(?:disabled|not.?enabled)",
    "hardcoded_keys":  r"(?:AKIA|AIza|sk-|password|secret).*=.*['\"]",
}

# Cloud attack indicators
_CLOUD_ATTACK_INDICATORS = [
    r"unauthorized.*access|invalid.*credentials",
    r"root.*login|console.*login.*success",
    r"iam.*policy.*change|role.*creation",
    r"security.?group.*change|acl.*modification",
    r"bucket.*policy.*change",
    r"lambda.*creation|function.*deploy",
    r"instance.*creation|vm.*scale.*up",
    r"unusual.*region|impossible.*travel",
    r"data.*exfil|large.*download|bulk.*get",
]

# Compliance frameworks
_COMPLIANCE_FRAMESWORKS = {
    "SOC2":     ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC7.2", "CC7.3"],
    "PCI-DSS":  ["1.2.1", "2.2.1", "3.4.1", "6.4.1", "10.2.1", "11.3.1"],
    "HIPAA":    ["164.312.a", "164.312.b", "164.312.c", "164.312.d", "164.312.e"],
    "NIST-800": ["AC-2", "AC-3", "AC-6", "AU-2", "AU-6", "CM-2", "IA-2", "SC-8"],
    "ISO27001": ["A.9.1", "A.9.2", "A.10.1", "A.12.1", "A.12.4", "A.13.1"],
}


class CloudSecuritySentinelAgent:
    """Monitors cloud infrastructure security posture."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.active = False
        self._findings: list[dict] = []
        self._threat_count = 0
        self._last_scan = 0.0
        self._detected_providers: list[str] = []
        self._compliance_gaps: list[dict] = []
        _LOG.info("CloudSecuritySentinelAgent initialized.")

    def start(self) -> None:
        self.active = True
        _LOG.info("CloudSecuritySentinelAgent started.")

    def stop(self) -> None:
        self.active = False
        _LOG.info("CloudSecuritySentinelAgent stopped.")

    def scan(self) -> dict[str, Any]:
        """Scan for cloud misconfigurations and threats."""
        try:
            findings = []
            now = time.time()

            # 1. Detect cloud environment
            providers = self._detect_cloud_provider()
            self._detected_providers = providers

            # 2. Check for cloud credential exposure
            cred_findings = self._check_credential_exposure()
            findings.extend(cred_findings)

            # 3. Scan for misconfigurations in local configs
            config_findings = self._scan_misconfigurations()
            findings.extend(config_findings)

            # 4. Check for cloud attack indicators
            attack_findings = self._detect_cloud_attacks()
            findings.extend(attack_findings)

            # 5. Assess compliance posture
            compliance_findings = self._assess_compliance()
            findings.extend(compliance_findings)

            # 6. Check container security (if applicable)
            container_findings = self._check_container_security()
            findings.extend(container_findings)

            self._findings.extend(findings)
            self._threat_count += len(findings)
            self._last_scan = now

            return {
                "status": "ok",
                "cloud_threats": len(findings),
                "total_threats": self._threat_count,
                "providers": providers,
                "compliance_gaps": len(self._compliance_gaps),
                "findings": findings,
            }
        except Exception as exc:
            _LOG.error("Cloud security scan failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze cloud security findings."""
        try:
            findings = data.get("findings", [])
            if not findings:
                return {"cloud_risk": "low", "score": 0, "compliant": True}

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
                "cloud_risk": level,
                "score": score,
                "categories": categories,
                "compliant": score < 25,
                "recommendation": self._recommend(level, categories),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def report(self) -> dict[str, Any]:
        return {
            "agent": "CloudSecuritySentinel",
            "active": self.active,
            "total_threats": self._threat_count,
            "providers": self._detected_providers,
            "compliance_gaps": len(self._compliance_gaps),
            "last_findings": self._findings[-5:],
        }

    # --- internal checks ---

    def _detect_cloud_provider(self) -> list[str]:
        """Detect which cloud provider the cell is running on."""
        providers = []
        import urllib.request

        for name, info in _CLOUD_PROVIDERS.items():
            try:
                req = urllib.request.Request(
                    info["metadata_url"],
                    headers={"Metadata-Token": "AWS"} if name == "aws" else {},
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        providers.append(name)
                        _LOG.info("Detected cloud provider: %s", name)
            except Exception:
                pass

        # Also check for cloud-specific environment variables
        cloud_env_vars = {
            "AWS_EXECUTION_ENV": "aws",
            "AWS_LAMBDA_FUNCTION_NAME": "aws",
            "AZURE_FUNCTIONS_ENVIRONMENT": "azure",
            "GOOGLE_CLOUD_PROJECT": "gcp",
            "GCP_PROJECT": "gcp",
        }
        for var, provider in cloud_env_vars.items():
            if os.environ.get(var) and provider not in providers:
                providers.append(provider)

        return providers

    def _check_credential_exposure(self) -> list[dict]:
        """Check for exposed cloud credentials in local files."""
        findings = []
        home = str(Path.home())

        # Check for cloud credential files
        cred_files = [
            os.path.join(home, ".aws", "credentials"),
            os.path.join(home, ".aws", "config"),
            os.path.join(home, ".azure", "accessTokens.json"),
            os.path.join(home, ".gcloud", "credentials.json"),
            os.path.join(home, ".wraith", ".env"),
        ]

        for cf in cred_files:
            if os.path.exists(cf):
                try:
                    content = Path(cf).read_text(errors="ignore")
                    # Check for hardcoded keys
                    if re.search(r"AKIA[0-9A-Z]{16}", content):
                        findings.append({
                            "type": "exposed_aws_key",
                            "category": "credential",
                            "severity": "critical",
                            "file": cf,
                            "detail": "AWS access key found in credentials file",
                            "ts": time.time(),
                        })
                    if re.search(r"AIza[a-zA-Z0-9_-]{35}", content):
                        findings.append({
                            "type": "exposed_gcp_key",
                            "category": "credential",
                            "severity": "critical",
                            "file": cf,
                            "detail": "GCP API key found in credentials file",
                            "ts": time.time(),
                        })
                    # Check file permissions (should be 600 on Unix)
                    if platform.system() != "Windows":
                        import stat
                        st = os.stat(cf)
                        mode = stat.S_IMODE(st.st_mode)
                        if mode & 0o077:
                            findings.append({
                                "type": "cred_file_perms",
                                "category": "credential",
                                "severity": "high",
                                "file": cf,
                                "permissions": oct(mode),
                                "detail": f"Credential file has loose permissions: {oct(mode)}",
                                "ts": time.time(),
                            })
                except (PermissionError, OSError):
                    pass

        # Check environment variables for exposed secrets
        for key, val in os.environ.items():
            if any(s in key.upper() for s in ["SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL"]):
                if len(val) > 8 and not val.startswith("${"):
                    findings.append({
                        "type": "env_secret",
                        "category": "credential",
                        "severity": "medium",
                        "var": key,
                        "detail": f"Potential secret in environment variable: {key}",
                        "ts": time.time(),
                    })

        return findings

    def _scan_misconfigurations(self) -> list[dict]:
        """Scan local config files for cloud misconfigurations."""
        findings = []
        home = str(Path.home())

        # Check for IaC templates (Terraform, CloudFormation, etc.)
        ica_patterns = {
            "terraform": ["*.tf", "*.tfvars"],
            "cloudformation": ["*.yaml", "*.json"],
            "kubernetes": ["*.yml", "*.yaml"],
        }

        config_dirs = [
            os.path.join(home, ".wraith"),
            os.path.join(home, "Documents"),
        ]

        for d in config_dirs:
            if not os.path.isdir(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    if f.endswith((".tf", ".tfvars", ".yaml", ".yml", ".json")):
                        path = os.path.join(root, f)
                        try:
                            content = Path(path).read_text(errors="ignore")
                            for misconfig, pattern in _MISCONFIG_PATTERNS.items():
                                if re.search(pattern, content, re.IGNORECASE):
                                    findings.append({
                                        "type": f"iac_{misconfig}",
                                        "category": "misconfiguration",
                                        "severity": "high",
                                        "file": path,
                                        "detail": f"Misconfiguration '{misconfig}' in {f}",
                                        "ts": time.time(),
                                    })
                        except (PermissionError, OSError):
                            pass
                # Don't recurse too deep
                if root.count(os.sep) > 5:
                    break

        return findings

    def _detect_cloud_attacks(self) -> list[dict]:
        """Detect cloud-specific attack indicators."""
        findings = []

        # Check for suspicious processes (crypto miners, scanners)
        suspicious_procs = [
            "xmrig", "minerd", "stratum", "mining",
            "nmap", "masscan", "zmap",
            "sqlmap", "nikto", "dirb",
        ]
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["tasklist"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ps", "aux"], timeout=10).decode(errors="ignore")

            for proc in suspicious_procs:
                if proc.lower() in out.lower():
                    findings.append({
                        "type": "suspicious_process",
                        "category": "attack",
                        "severity": "high",
                        "process": proc,
                        "detail": f"Suspicious process '{proc}' detected — possible cloud attack tool",
                        "ts": time.time(),
                    })
        except Exception:
            pass

        # Check for unusual outbound connections (data exfil)
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["netstat", "-an"], timeout=10).decode(errors="ignore")
            else:
                out = subprocess.check_output(["ss", "-tunapl"], timeout=10).decode(errors="ignore")

            # Count connections per remote IP
            ip_counts = {}
            for line in out.splitlines():
                parts = line.split()
                for part in parts:
                    if ":" in part and not part.startswith("::"):
                        ip = part.rsplit(":", 1)[0]
                        if not ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            for ip, count in ip_counts.items():
                if count > 100:
                    findings.append({
                        "type": "data_exfil_indicator",
                        "category": "attack",
                        "severity": "high",
                        "dest_ip": ip,
                        "connections": count,
                        "detail": f"High outbound connections to {ip} — possible data exfiltration",
                        "ts": time.time(),
                    })
        except Exception:
            pass

        return findings

    def _assess_compliance(self) -> list[dict]:
        """Assess compliance posture against common frameworks."""
        findings = []

        # Check encryption at rest
        if platform.system() != "Windows":
            try:
                # Check if disk encryption is enabled (LUKS)
                out = subprocess.check_output(["lsblk", "-f"], timeout=5).decode(errors="ignore")
                if "crypto_LUKS" not in out and "crypt" not in out:
                    findings.append({
                        "type": "no_disk_encryption",
                        "category": "compliance",
                        "severity": "high",
                        "framework": "NIST-800/PCI-DSS/HIPAA",
                        "detail": "No disk encryption detected — violates multiple compliance frameworks",
                        "ts": time.time(),
                    })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Check for firewall
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    timeout=10,
                ).decode(errors="ignore")
                if "OFF" in out.upper():
                    findings.append({
                        "type": "firewall_disabled",
                        "category": "compliance",
                        "severity": "high",
                        "framework": "PCI-DSS/NIST-800",
                        "detail": "Firewall is disabled on one or more profiles",
                        "ts": time.time(),
                    })
            else:
                out = subprocess.check_output(["ufw", "status"], timeout=5).decode(errors="ignore")
                if "inactive" in out.lower():
                    findings.append({
                        "type": "firewall_disabled",
                        "category": "compliance",
                        "severity": "high",
                        "framework": "PCI-DSS/NIST-800",
                        "detail": "UFW firewall is inactive",
                        "ts": time.time(),
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check for automatic updates
        if platform.system() != "Windows":
            try:
                out = subprocess.check_output(
                    ["apt", "list", "--upgradable"],
                    timeout=10,
                ).decode(errors="ignore")
                upgradable = [l for l in out.splitlines() if "/" in l and "Listing" not in l]
                if len(upgradable) > 50:
                    findings.append({
                        "type": "updates_pending",
                        "category": "compliance",
                        "severity": "medium",
                        "framework": "PCI-DSS/NIST-800",
                        "detail": f"{len(upgradable)} security updates pending",
                        "ts": time.time(),
                    })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        self._compliance_gaps = findings
        return findings

    def _check_container_security(self) -> list[dict]:
        """Check container security posture."""
        findings = []

        # Check if running in container
        if os.path.exists("/.dockerenv") or os.environ.get("KUBERNETES_SERVICE_HOST"):
            findings.append({
                "type": "container_runtime",
                "category": "container",
                "severity": "low",
                "detail": "Running inside a container — checking security posture",
                "ts": time.time(),
            })

            # Check for privileged mode
            if os.path.exists("/dev/sda") or os.path.exists("/dev/vda"):
                findings.append({
                    "type": "privileged_container",
                    "category": "container",
                    "severity": "critical",
                    "detail": "Container appears to have host disk access — possible privileged mode",
                    "ts": time.time(),
                })

            # Check for root user
            if os.getuid() == 0:
                findings.append({
                    "type": "container_root",
                    "category": "container",
                    "severity": "high",
                    "detail": "Container running as root — use non-root user",
                    "ts": time.time(),
                })

        # Check Docker socket exposure
        docker_socket = Path("/var/run/docker.sock")
        if docker_socket.exists():
            import stat
            st = os.stat(docker_socket)
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o077:
                findings.append({
                    "type": "docker_socket_exposed",
                    "category": "container",
                    "severity": "critical",
                    "permissions": oct(mode),
                    "detail": "Docker socket has loose permissions — container escape risk",
                    "ts": time.time(),
                })

        return findings

    def _recommend(self, level: str, categories: dict) -> str:
        if level == "critical":
            return "IMMEDIATE: Rotate exposed credentials. Isolate compromised resources. Enable encryption."
        if level == "high":
            return "URGENT: Fix misconfigurations. Enable logging. Enforce least-privilege IAM."
        if "credential" in categories:
            return "Move credentials to vault (HashiCorp Vault/AWS Secrets Manager). Rotate all keys."
        if "misconfiguration" in categories:
            return "Review IaC templates. Apply CIS benchmarks. Enable cloud security posture management."
        if "compliance" in categories:
            return "Address compliance gaps. Enable encryption at rest. Keep systems patched."
        return "Enable cloud security monitoring. Review IAM policies. Implement least-privilege access."
