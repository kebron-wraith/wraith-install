# WRAITH Cell — AI Security Organism

WRAITH Cell is the distributed intelligence layer of the WRAITH security platform.
Each cell runs 28 AI security agents on your device, operates independently,
and connects to other cells via P2P mesh networking.

## One-Line Install

```bash
# Linux/macOS
curl -fsSL https://wraith.one/install | bash

# Windows
powershell -c "iwr -useb https://wraith.one/install | iex"
```

## Architecture

- **28 AI Security Agents** — Scanner, Analyst, Sentinel, Ghost, and more
- **P2P Mesh** — Cells communicate via Biomesh protocol (UDP 7736, TCP 7737)
- **Ollama Support** — Auto-detects local LLM models
- **Self-Evolution** — Learns from attacks, shares intelligence P2P
- **Kill Switch** — Admin can remotely deactivate compromised cells

## License

MIT License — See [LICENSE](LICENSE) for details.

---

🦅 WRAITH — Forward-deployed Autonomous Knowledge Architecture
