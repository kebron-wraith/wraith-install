"""
WRAITH Cell v5.0 — Security Agent Framework (COMPLETE)
========================================================
26 security agents — ALL running on CELLS (user devices). v4.0: 22, v5.0: +4 (AIAttackDetector, ThreatIntelligenceFeed, PostQuantumDefense, IoTDefense, CloudSecuritySentinel).
Each agent uses the USER'S OWN LLM (Ollama, OpenRouter, Anthropic, etc).
Admin does NOT run agents. Admin only collects intel and pushes upgrades.
"""
from __future__ import annotations
__version__ = "5.0.0"
__author__  = "WRAITH Cell"

# ── v4.0 Agents (22) ──
from .ghost            import GhostAgent
from .scanner          import ScannerAgent
from .breach           import BreachAgent
from .sentinel         import SentinelAgent
from .guardian         import GuardianAgent
from .forge            import ForgeAgent
from .learner          import LearnerAgent
from .phantom          import PhantomAgent
from .specter          import SpecterAgent
from .mirror           import MirrorAgent
from .commander        import CommanderAgent
from .engineer         import EngineerAgent
from .analyst          import AnalystAgent
from .whitehat         import WhitehatAgent
from .blackhat         import BlackhatAgent
from .grayhat          import GrayhatAgent
from .neuron           import NeuronAgent
from .ledger           import LedgerAgent
from .searcher         import SearcherAgent
from .self_evolver     import SelfEvolverAgent
from .orchestrator     import OrchestratorAgent

# ── v5.0 Agents (2) — NEW ──
from .ai_attack_detector   import AIAttackDetectorAgent
from .threat_intel_feed     import ThreatIntelligenceFeed

# ── v5.0 Agents (3) — NEW (24-26) ──
from .post_quantum_defense     import PostQuantumDefenseAgent
from .iot_defense              import IoTDefenseAgent
from .cloud_security_sentinel  import CloudSecuritySentinelAgent

ALL_AGENTS = [
    # v4.0 — 22 agents
    GhostAgent, ScannerAgent, BreachAgent, SentinelAgent,
    GuardianAgent, ForgeAgent, LearnerAgent, PhantomAgent,
    SpecterAgent, MirrorAgent, CommanderAgent, EngineerAgent,
    AnalystAgent, WhitehatAgent, BlackhatAgent, GrayhatAgent,
    NeuronAgent, LedgerAgent, SearcherAgent, SelfEvolverAgent,
    OrchestratorAgent,
    # v5.0 — 5 new agents (23-26)
    AIAttackDetectorAgent,
    ThreatIntelligenceFeed,
    PostQuantumDefenseAgent,
    IoTDefenseAgent,
    CloudSecuritySentinelAgent,
]

__all__ = ALL_AGENTS + ["ALL_AGENTS"]
