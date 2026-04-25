# ENHANCEMENTS.md — access.sh

## Origin

`access.sh` is an **original Sharon-Needles tool** — not a fork of any upstream project. It was written from scratch as part of the bug bounty automation toolchain alongside `hunt.sh`, `social.sh`, `api.sh`, `cache.sh`, and `cloud.sh`.

---

## Enhancements Log

### 2026-04-24 — Cross-platform install.sh

**Added**: `install.sh`

The tool previously had no installer — users had to manually resolve dependencies. `install.sh` adds:

- Automatic package manager detection: apt (Debian/Ubuntu/Kali/Parrot), pacman (Arch/BlackArch), dnf (Fedora/RHEL), Homebrew (macOS)
- Required tool installation: curl, jq, git, python3/python, nmap, golang
- Optional tool installation: httpx, nuclei, ffuf, gobuster, sqlmap, hydra (via package manager or `go install` where not packaged)
- System-wide install: copies tool to `/usr/local/share/access`, symlinks `access` binary to `/usr/local/bin/access`
- Single command setup: `bash install.sh`

This makes the tool portable across any Linux distro or macOS without requiring manual setup steps.

### 2026-04-24 — CLAUDE.md

**Added**: `CLAUDE.md`

Comprehensive architecture and usage documentation for Claude Code sessions:
- Full phase-by-phase breakdown of all 10 phases
- Output file reference table
- Environment variable reference
- Extension guide for adding new phases
- Flag reference table

---

## Planned Enhancements

- JSON output mode for all phase scripts (machine-readable alongside human-readable)
- Integration with `hunt.sh` — auto-feed `ac_api_findings.txt` into api.sh pipeline
- `--notify` flag for desktop/Slack notification on priority findings
- Rate limiting controls per-phase (`--phase-delay`)
- Docker container for portable deployment without install.sh
