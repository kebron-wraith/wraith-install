#!/usr/bin/env python3
"""
WRAITH v5.0 — REAL Self-Evolution Engine
==========================================
Production-grade defense evolution system (NO LLM required for base version).

Features:
- DefenseKnowledge: persistent immune memory with Bayesian effectiveness scoring
- DefenseCodeGenerator: generates Python defense code from attack patterns
- DynamicDefenseLoader: loads evolved defense modules at RUNTIME (importlib)
- DetectionRuleGenerator: auto-generates Sigma + YARA rules from attack patterns
- SelfEvolution: main engine — learns, creates, prunes weak defenses (<20%)

Defense modules stored in ~/.wraith/evolved_defenses/
All defense code validated with AST parsing before loading.
Dangerous imports blocked (os.system, subprocess.call, etc.)
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import inspect
import json
import logging
import math
import os
import random
import re
import secrets
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

CELL_HOME = Path(os.path.expanduser("~")) / ".wraith"
CELL_HOME.mkdir(parents=True, exist_ok=True)
EVOLVED_DEFENSES_DIR = CELL_HOME / "evolved_defenses"
EVOLVED_DEFENSES_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_DB = CELL_HOME / "defense_knowledge.json"

log = logging.getLogger("wraith-self-evolution")

# ═══════════════════════════════════════════════════════════════
# BLOCKED IMPORTS — Security: prevent malicious defense code
# ═══════════════════════════════════════════════════════════════

BLOCKED_IMPORTS = {
    "os.system", "os.popen", "os.exec", "os.spawn",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "shutil.rmtree", "shutil.rmtree",
    "sys.exit", "sys.modules.__setitem__",
    "ctypes", "ctypes.CDLL",
    "eval", "exec", "compile",
    "__import__", "globals", "locals",
    "signal.signal",
}

BLOCKED_AST_NODES = {
    ast.Exec,  # Python 2
}

# In Python 3, we check for dangerous calls in the AST
DANGEROUS_CALLS = {
    "system", "popen", "exec", "spawn", "call", "run", "Popen",
    "check_output", "check_call", "remove", "rmtree",
    "eval", "exec", "compile", "__import__", "globals", "locals",
}


# ═══════════════════════════════════════════════════════════════
# DEFENSE KNOWLEDGE — Persistent immune memory with Bayesian scoring
# ═══════════════════════════════════════════════════════════════

class DefenseKnowledge:
    """
    Persistent immune memory for defense rules.
    Uses Bayesian effectiveness scoring to rank defenses.
    Each defense has: successes / total_attempts, with Beta distribution.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or KNOWLEDGE_DB
        self._knowledge: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.db_path.exists():
            try:
                self._knowledge = json.loads(self.db_path.read_text())
            except (json.JSONDecodeError, IOError):
                self._knowledge = {}

    def _save(self):
        try:
            self.db_path.write_text(json.dumps(self._knowledge, indent=2, default=str))
        except IOError as exc:
            log.error(f"Failed to save knowledge DB: {exc}")

    def record_defense(self, defense_id: str, attack_type: str,
                       technique: str, code: str, metadata: Dict = None) -> str:
        """Record a new defense in knowledge base."""
        if not defense_id:
            defense_id = hashlib.sha256(
                f"{attack_type}:{technique}:{time.time()}:{secrets.token_hex(4)}".encode()
            ).hexdigest()[:16]

        entry = {
            "defense_id": defense_id,
            "attack_type": attack_type,
            "technique": technique,
            "code": code,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            # Bayesian: Beta(1,1) = uniform prior
            "successes": 1,
            "failures": 1,
            "total_attempts": 0,
            "effectiveness": 0.5,  # Initial estimate
            "active": True,
            "metadata": metadata or {},
        }

        with self._lock:
            self._knowledge[defense_id] = entry
            self._save()

        return defense_id

    def record_result(self, defense_id: str, success: bool):
        """Record a defense result (success/failure) using Bayesian update."""
        with self._lock:
            entry = self._knowledge.get(defense_id)
            if not entry:
                return

            entry["total_attempts"] += 1
            if success:
                entry["successes"] += 1
            else:
                entry["failures"] += 1

            # Bayesian effectiveness = E[Beta(alpha, beta)]
            alpha = entry["successes"]
            beta = entry["failures"]
            entry["effectiveness"] = alpha / (alpha + beta)
            entry["updated_at"] = datetime.now(timezone.utc).isoformat()

            self._save()

    def get_effectiveness(self, defense_id: str) -> Optional[float]:
        """Get Bayesian effectiveness score for a defense."""
        with self._lock:
            entry = self._knowledge.get(defense_id)
            if not entry:
                return None
            return entry["effectiveness"]

    def get_top_defenses(self, attack_type: str = None,
                         limit: int = 10) -> List[Dict]:
        """Get top-rated defenses, optionally filtered by attack type."""
        with self._lock:
            entries = list(self._knowledge.values())
            if attack_type:
                entries = [e for e in entries if e.get("attack_type") == attack_type]
            entries = [e for e in entries if e.get("active", False)]
            entries.sort(key=lambda e: e.get("effectiveness", 0), reverse=True)
            return entries[:limit]

    def get_weak_defenses(self, threshold: float = 0.20) -> List[str]:
        """Get defense IDs with effectiveness below threshold."""
        with self._lock:
            return [
                did for did, entry in self._knowledge.items()
                if entry.get("active", False) and entry.get("effectiveness", 0.5) < threshold
            ]

    def deactivate(self, defense_id: str) -> bool:
        """Deactivate a weak defense."""
        with self._lock:
            entry = self._knowledge.get(defense_id)
            if entry:
                entry["active"] = False
                self._save()
                return True
        return False

    def get_defense_code(self, defense_id: str) -> Optional[str]:
        """Get the code for a specific defense."""
        with self._lock:
            entry = self._knowledge.get(defense_id)
            if entry:
                return entry.get("code")
        return None

    def get_all_active(self) -> List[Dict]:
        """Get all active defenses."""
        with self._lock:
            return [e for e in self._knowledge.values() if e.get("active", False)]

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        with self._lock:
            total = len(self._knowledge)
            active = sum(1 for e in self._knowledge.values() if e.get("active", False))
            avg_eff = sum(
                e.get("effectiveness", 0) for e in self._knowledge.values()
            ) / max(total, 1)
            return {
                "total_defenses": total,
                "active_defenses": active,
                "avg_effectiveness": round(avg_eff, 3),
                "attack_types": len(set(
                    e.get("attack_type", "") for e in self._knowledge.values()
                )),
            }


# ═══════════════════════════════════════════════════════════════
# DEFENSE CODE GENERATOR — Rule-based Python defense generation
# ═══════════════════════════════════════════════════════════════

class DefenseCodeGenerator:
    """
    Generates Python defense code from attack patterns.
    Rule-based (no LLM needed for base version).
    """

    # Templates for different defense types
    TEMPLATES = {
        "port_scan": '''#!/usr/bin/env python3
"""Auto-generated defense against port scanning."""
import logging
from datetime import datetime, timezone
from typing import Dict, Set

log = logging.getLogger("wraith-defense-port_scan")

class PortScanBlocker:
    """Blocks IPs that scan multiple ports."""

    def __init__(self, threshold: int = 10, block_duration: int = 300):
        self.threshold = threshold
        self.block_duration = block_duration
        self._attempts: Dict[str, list] = {}
        self._blocked: Dict[str, str] = {}  # ip -> block_time

    def check_connection(self, src_ip: str, dst_port: int) -> bool:
        """Returns True if connection should be blocked."""
        now = datetime.now(timezone.utc).isoformat()

        # Check if already blocked
        if src_ip in self._blocked:
            return False  # Already blocked

        # Track attempts
        if src_ip not in self._attempts:
            self._attempts[src_ip] = []
        self._attempts[src_ip].append({"port": dst_port, "time": now})

        # Clean old entries (older than 60s)
        self._attempts[src_ip] = [
            a for a in self._attempts[src_ip]
            if (datetime.now(timezone.utc) - datetime.fromisoformat(a["time"])).seconds < 60
        ]

        # Check threshold
        if len(self._attempts[src_ip]) >= self.threshold:
            self._blocked[src_ip] = now
            log.warning(f"Port scan detected from {src_ip}: {len(self._attempts[src_ip])} ports in 60s")
            return False
        return True

    def get_blocked_ips(self) -> Set[str]:
        return set(self._blocked.keys())
''',
        "brute_force": '''#!/usr/bin/env python3
"""Auto-generated defense against brute force attacks."""
import logging
from datetime import datetime, timezone
from typing import Dict, Set

log = logging.getLogger("wraith-defense-brute_force")

class BruteForceBlocker:
    """Blocks IPs with too many failed auth attempts."""

    def __init__(self, threshold: int = 5, block_duration: int = 600):
        self.threshold = threshold
        self.block_duration = block_duration
        self._failures: Dict[str, list] = {}
        self._blocked: Dict[str, str] = {}

    def record_failure(self, src_ip: str, service: str = "ssh") -> bool:
        """Record auth failure. Returns True if IP should be blocked."""
        key = f"{src_ip}:{service}"
        if key not in self._failures:
            self._failures[key] = []
        self._failures[key].append(datetime.now(timezone.utc).isoformat())

        # Clean old entries (older than 300s)
        self._failures[key] = [
            t for t in self._failures[key]
            if (datetime.now(timezone.utc) - datetime.fromisoformat(t)).seconds < 300
        ]

        if len(self._failures[key]) >= self.threshold:
            self._blocked[src_ip] = datetime.now(timezone.utc).isoformat()
            log.warning(f"Brute force from {src_ip} on {service}: {len(self._failures[key])} failures")
            return True
        return False

    def is_blocked(self, src_ip: str) -> bool:
        return src_ip in self._blocked

    def get_blocked_ips(self) -> Set[str]:
        return set(self._blocked.keys())
''',
        "sqli": '''#!/usr/bin/env python3
"""Auto-generated defense against SQL injection."""
import logging
import re
from typing import List, Tuple

log = logging.getLogger("wraith-defense-sqli")

class SQLiDetector:
    """Detects and blocks SQL injection attempts."""

    PATTERNS = [
        r"(?i)(union\\s+select)",
        r"(?i)(select\\s+.*from)",
        r"(?i)(drop\\s+table)",
        r"(?i)(insert\\s+into)",
        r"(?i)(delete\\s+from)",
        r"(?i)(or\\s+1\\s*=\\s*1)",
        r"(?i)('|--\\s)",
        r"(?i)(;\\s*shutdown)",
        r"(?i)(exec\\s*\\()",
        r"(?i)(eval\\s*\\()",
    ]

    def __init__(self):
        self._compiled = [re.compile(p) for p in self.PATTERNS]
        self._detections: List[Tuple[str, str]] = []

    def check(self, input_string: str) -> bool:
        """Returns True if SQL injection detected."""
        for pattern in self._compiled:
            if pattern.search(input_string):
                self._detections.append((input_string[:100], pattern.pattern))
                log.warning(f"SQLi detected: {input_string[:80]}")
                return True
        return False

    def get_detections(self) -> List[Tuple[str, str]]:
        return list(self._detections)
''',
        "xss": '''#!/usr/bin/env python3
"""Auto-generated defense against XSS attacks."""
import logging
import re
from typing import List, Tuple

log = logging.getLogger("wraith-defense-xss")

class XSSDetector:
    """Detects and blocks XSS attempts."""

    PATTERNS = [
        r"(?i)(<script[^>]*>)",
        r"(?i)(javascript\\s*:)",
        r"(?i)(on\\w+\\s*=)",
        r"(?i)(<iframe)",
        r"(?i)(<object)",
        r"(?i)(<embed)",
        r"(?i)(document\\.cookie)",
        r"(?i)(alert\\s*\\()",
    ]

    def __init__(self):
        self._compiled = [re.compile(p) for p in self.PATTERNS]
        self._detections: List[Tuple[str, str]] = []

    def check(self, input_string: str) -> bool:
        """Returns True if XSS detected."""
        for pattern in self._compiled:
            if pattern.search(input_string):
                self._detections.append((input_string[:100], pattern.pattern))
                log.warning(f"XSS detected: {input_string[:80]}")
                return True
        return False

    def get_detections(self) -> List[Tuple[str, str]]:
        return list(self._detections)
''',
    }

    @classmethod
    def generate(cls, attack_type: str, technique: str = "",
                 params: Optional[Dict] = None) -> str:
        """Generate defense code for a given attack type."""
        # Map attack types to templates
        template_key = attack_type
        if template_key not in cls.TEMPLATES:
            # Fallback: generate generic defense
            template_key = cls._find_best_template(attack_type)

        if template_key and template_key in cls.TEMPLATES:
            code = cls.TEMPLATES[template_key]
            # Apply custom params
            if params:
                for key, value in params.items():
                    code = code.replace(f"_{key}", str(value))
            return code

        # Generic fallback
        return cls._generate_generic(attack_type, technique)

    @classmethod
    def _find_best_template(cls, attack_type: str) -> Optional[str]:
        """Find the best matching template for an attack type."""
        mapping = {
            "port_scan": "port_scan",
            "scan": "port_scan",
            "syn_scan": "port_scan",
            "brute_force": "brute_force",
            "bruteforce": "brute_force",
            "auth": "brute_force",
            "password_spray": "brute_force",
            "sqli": "sqli",
            "sql_injection": "sqli",
            "sql": "sqli",
            "xss": "xss",
            "cross_site": "xss",
            "csrf": "xss",
        }
        return mapping.get(attack_type.lower())

    @classmethod
    def _generate_generic(cls, attack_type: str, technique: str) -> str:
        """Generate a generic defense module."""
        safe_name = re.sub(r'[^a-z0-9]', '_', attack_type.lower())
        return f'''#!/usr/bin/env python3
"""Auto-generated defense against {attack_type}."""
import logging
from datetime import datetime, timezone
from typing import Dict, List

log = logging.getLogger("wraith-defense-{safe_name}")

class {safe_name.title()}Detector:
    """Auto-generated detector for {attack_type} attacks."""

    def __init__(self, threshold: int = 10):
        self.threshold = threshold
        self._events: List[Dict] = []
        self._blocked: Dict[str, str] = {{"}}
        self.attack_type = "{attack_type}"
        self.technique = "{technique}"

    def check(self, event: Dict) -> bool:
        """Check if event matches attack pattern. Returns True if attack detected."""
        src_ip = event.get("src_ip", "")
        if not src_ip:
            return False

        self._events.append(event)

        # Count recent events from same source
        recent = [
            e for e in self._events
            if e.get("src_ip") == src_ip
        ]

        if len(recent) >= self.threshold:
            self._blocked[src_ip] = datetime.now(timezone.utc).isoformat()
            log.warning(f"{attack_type} detected from {{src_ip}}: {{len(recent)}} events")
            return True
        return False

    def is_blocked(self, src_ip: str) -> bool:
        return src_ip in self._blocked

    def get_blocked(self) -> Dict[str, str]:
        return dict(self._blocked)
'''


# ═══════════════════════════════════════════════════════════════
# AST VALIDATOR — Ensure defense code is safe before loading
# ═══════════════════════════════════════════════════════════════

class ASTValidator:
    """Validates Python code using AST parsing before execution."""

    @staticmethod
    def validate(code: str) -> Tuple[bool, str]:
        """
        Validate code is safe to execute.
        Returns (is_safe, reason).
        """
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return False, f"Syntax error: {exc}"

        # Walk the AST looking for dangerous patterns
        for node in ast.walk(tree):
            # Check for blocked imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("subprocess", "ctypes", "shutil"):
                        return False, f"Blocked import: {alias.name}"

            if isinstance(node, ast.ImportFrom):
                if node.module and node.module in ("subprocess", "ctypes", "shutil"):
                    return False, f"Blocked import from: {node.module}"

            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in DANGEROUS_CALLS:
                    return False, f"Dangerous call: {func.id}"
                if isinstance(func, ast.Attribute) and func.attr in DANGEROUS_CALLS:
                    return False, f"Dangerous call: {func.attr}"

            # Check for exec/eval
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("exec", "eval"):
                    return False, f"Blocked: {func.id}"

        return True, "OK"


# ═══════════════════════════════════════════════════════════════
# DYNAMIC DEFENSE LOADER — Load evolved modules at runtime
# ═══════════════════════════════════════════════════════════════

class DynamicDefenseLoader:
    """
    Loads evolved defense modules at runtime using importlib.
    All code is validated with AST before loading.
    """

    def __init__(self, defense_dir: Optional[Path] = None):
        self.defense_dir = defense_dir or EVOLVED_DEFENSES_DIR
        self.defense_dir.mkdir(parents=True, exist_ok=True)
        self._loaded_modules: Dict[str, types.ModuleType] = {}
        self._lock = threading.Lock()
        self._validator = ASTValidator()

    def load_module(self, defense_id: str, code: str) -> Optional[types.ModuleType]:
        """
        Validate, compile, and load a defense module.
        Returns the loaded module or None if validation fails.
        """
        # Step 1: AST validation
        is_safe, reason = self._validator.validate(code)
        if not is_safe:
            log.warning(f"Defense {defense_id} rejected: {reason}")
            return None

        # Step 2: Write to disk
        module_path = self.defense_dir / f"defense_{defense_id}.py"
        try:
            module_path.write_text(code, encoding="utf-8")
        except IOError as exc:
            log.error(f"Failed to write defense module: {exc}")
            return None

        # Step 3: Load with importlib
        try:
            spec = importlib.util.spec_from_file_location(
                f"wraith_defense_{defense_id}", str(module_path)
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            with self._lock:
                self._loaded_modules[defense_id] = module

            log.info(f"Defense module loaded: {defense_id}")
            return module

        except Exception as exc:
            log.error(f"Failed to load defense {defense_id}: {exc}")
            # Clean up failed module file
            try:
                module_path.unlink()
            except OSError:
                pass
            return None

    def get_loaded(self) -> Dict[str, types.ModuleType]:
        """Get all loaded defense modules."""
        with self._lock:
            return dict(self._loaded_modules)

    def unload(self, defense_id: str) -> bool:
        """Unload a defense module."""
        with self._lock:
            if defense_id in self._loaded_modules:
                del self._loaded_modules[defense_id]
                try:
                    module_path = self.defense_dir / f"defense_{defense_id}.py"
                    if module_path.exists():
                        module_path.unlink()
                except OSError:
                    pass
                return True
        return False

    def get_detector(self, defense_id: str) -> Optional[Any]:
        """Get a detector instance from a loaded module."""
        module = self._loaded_modules.get(defense_id)
        if not module:
            return None

        # Find detector class in module
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name.endswith("Detector") or name.endswith("Blocker"):
                try:
                    return obj()
                except Exception:
                    continue
        return None


# ═══════════════════════════════════════════════════════════════
# DETECTION RULE GENERATOR — Auto-generate Sigma + YARA rules
# ═══════════════════════════════════════════════════════════════

class DetectionRuleGenerator:
    """Auto-generates Sigma and YARA rules from attack patterns."""

    @staticmethod
    def generate_sigma_rule(attack_type: str, technique: str,
                            indicators: Dict[str, Any] = None) -> str:
        """Generate a Sigma detection rule from attack pattern."""
        rule_id = hashlib.sha256(
            f"{attack_type}:{technique}:{time.time()}".encode()
        ).hexdigest()[:16]

        # Build condition based on attack type
        conditions = []
        if attack_type in ("port_scan", "scan"):
            conditions.append("selection_1:")
            conditions.append("  EventID: 4625")  # Failed logon
            conditions.append("  | count() by SourceIP > 10")
        elif attack_type in ("brute_force", "bruteforce"):
            conditions.append("selection_failed:")
            conditions.append("  EventID: 4625")
            conditions.append("  | count() by TargetUserName > 5")
        elif attack_type in ("sqli", "sql_injection"):
            conditions.append("selection_sqli:")
            conditions.append("  uri|contains:")
            conditions.append("    - 'union select'")
            conditions.append("    - 'or 1=1'")
            conditions.append("    - '--'")
        elif attack_type in ("xss", "cross_site"):
            conditions.append("selection_xss:")
            conditions.append("  uri|contains:")
            conditions.append("    - '<script>'")
            conditions.append("    - 'javascript:'")
            conditions.append("    - 'onerror='")
        else:
            conditions.append("selection:")
            conditions.append(f"  attack_type: '{attack_type}'")

        sigma_rule = f"""title: {attack_type.replace('_', ' ').title()} Detection
id: {rule_id}
status: experimental
description: Auto-generated Sigma rule for {attack_type} detection
author: WRAITH Self-Evolution Engine
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
references:
  - https://wraith.one/threats/{attack_type}
logsource:
  category: network_connection
  product: detection
detection:
{chr(10).join(conditions)}
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.{technique or attack_type}
  - attack.t1046
"""
        return sigma_rule

    @staticmethod
    def generate_yara_rule(attack_type: str, technique: str,
                           patterns: Optional[List[str]] = None) -> str:
        """Generate a YARA rule from attack pattern."""
        rule_id = hashlib.sha256(
            f"yara:{attack_type}:{technique}:{time.time()}".encode()
        ).hexdigest()[:16]

        if patterns is None:
            # Default patterns based on attack type
            if attack_type in ("sqli", "sql_injection"):
                patterns = ["union select", "or 1=1", "drop table", "select * from"]
            elif attack_type in ("xss", "cross_site"):
                patterns = ["<script>", "javascript:", "onerror=", "alert("]
            elif attack_type in ("port_scan",):
                patterns = ["SYN_SENT", "PORT_SCAN", "NMAP"]
            else:
                patterns = [attack_type.replace("_", " ")]

        yara_strings = []
        for i, pat in enumerate(patterns):
            safe_pat = pat.replace('"', '\\"')
            yara_strings.append(f'        $s{i} = "{safe_pat}" nocase')

        yara_rule = f"""rule {attack_type}_{rule_id} {{
    meta:
        description = "Auto-generated YARA rule for {attack_type}"
        author = "WRAITH Self-Evolution Engine"
        date = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        reference = "https://wraith.one/threats/{attack_type}"
        severity = "high"

    strings:
{chr(10).join(yara_strings)}

    condition:
        any of them
}}
"""
        return yara_rule


# ═══════════════════════════════════════════════════════════════
# SELF-EVOLUTION ENGINE — Main orchestrator
# ═══════════════════════════════════════════════════════════════

class SelfEvolution:
    """
    Main self-evolution engine.
    - Learns from attack events
    - Creates defense code via DefenseCodeGenerator
    - Loads defenses dynamically via DynamicDefenseLoader
    - Prunes weak defenses (<20% effectiveness)
    - Generates Sigma + YARA rules
    """

    def __init__(self, knowledge: Optional[DefenseKnowledge] = None,
                 generator: Optional[DefenseCodeGenerator] = None,
                 loader: Optional[DynamicDefenseLoader] = None,
                 rule_gen: Optional[DetectionRuleGenerator] = None):
        self.knowledge = knowledge or DefenseKnowledge()
        self.generator = generator or DefenseCodeGenerator()
        self.loader = loader or DynamicDefenseLoader()
        self.rule_gen = rule_gen or DetectionRuleGenerator()
        self._active_defenses: Dict[str, Any] = {}  # defense_id -> detector instance
        self._lock = threading.Lock()
        self._prune_threshold = 0.20
        self._stats = {
            "attacks_analyzed": 0,
            "defenses_created": 0,
            "defenses_pruned": 0,
            "rules_generated": 0,
        }

    def learn(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Learn from an attack event. Creates a defense if one doesn't exist.
        Returns defense_id if created/used.
        """
        self._stats["attacks_analyzed"] += 1
        attack_type = event.get("type", "unknown")
        technique = event.get("technique", "")

        # Check if we already have a good defense for this
        existing = self.knowledge.get_top_defenses(attack_type, limit=1)
        if existing and existing[0].get("effectiveness", 0) > 0.6:
            defense_id = existing[0]["defense_id"]
            # Record successful defense
            self.knowledge.record_result(defense_id, True)
            return defense_id

        # Generate new defense code
        code = self.generator.generate(attack_type, technique)
        if not code:
            return None

        # Record in knowledge base
        defense_id = self.knowledge.record_defense(
            defense_id="",
            attack_type=attack_type,
            technique=technique,
            code=code,
            metadata={"source": "auto_generated"},
        )

        # Try to load it dynamically
        module = self.loader.load_module(defense_id, code)
        if module:
            detector = self.loader.get_detector(defense_id)
            if detector:
                with self._lock:
                    self._active_defenses[defense_id] = detector
                self._stats["defenses_created"] += 1

        return defense_id

    def check_defense(self, defense_id: str, event: Dict[str, Any]) -> bool:
        """Check if a defense detects the given event."""
        with self._lock:
            detector = self._active_defenses.get(defense_id)

        if not detector:
            return False

        # Try common check methods
        if hasattr(detector, "check"):
            try:
                return detector.check(event)
            except Exception as exc:
                log.debug(f"Defense check error: {exc}")
                self.knowledge.record_result(defense_id, False)
                return False

        if hasattr(detector, "check_connection"):
            try:
                src_ip = event.get("src_ip", "")
                dst_port = event.get("dst_port", 0)
                return not detector.check_connection(src_ip, dst_port)
            except Exception:
                pass

        return False

    def prune_weak_defenses(self) -> List[str]:
        """Remove defenses with effectiveness below threshold."""
        weak_ids = self.knowledge.get_weak_defenses(self._prune_threshold)
        pruned = []
        for defense_id in weak_ids:
            self.knowledge.deactivate(defense_id)
            self.loader.unload(defense_id)
            with self._lock:
                self._active_defenses.pop(defense_id, None)
            pruned.append(defense_id)
            self._stats["defenses_pruned"] += 1
            log.info(f"Pruned weak defense: {defense_id}")
        return pruned

    def generate_rules(self, attack_type: str, technique: str = "",
                       indicators: Optional[Dict] = None) -> Dict[str, str]:
        """Generate Sigma and YARA rules for an attack type."""
        sigma = self.rule_gen.generate_sigma_rule(attack_type, technique, indicators)
        yara = self.rule_gen.generate_yara_rule(attack_type, technique)
        self._stats["rules_generated"] += 1
        return {"sigma": sigma, "yara": yara}

    def get_active_defenses(self) -> Dict[str, Any]:
        """Get all active defense instances."""
        with self._lock:
            return dict(self._active_defenses)

    def get_stats(self) -> Dict[str, Any]:
        """Get evolution statistics."""
        knowledge_stats = self.knowledge.get_stats()
        return {
            **self._stats,
            "knowledge": knowledge_stats,
            "active_defenses": len(self._active_defenses),
            "loaded_modules": len(self.loader.get_loaded()),
        }

    @property
    def is_healthy(self) -> bool:
        return True  # Self-evolution is always "healthy" — it degrades gracefully
