# access.sh — 7-Phase Access Control Testing

**Automated access control and authentication bypass testing. Tests IDOR/BOLA, privilege escalation, horizontal access control, broken API authentication, and JWT weaknesses.**

---

## Features

### 7-Phase Pipeline
1. **Endpoint Mapping** — Discover authenticated endpoints
2. **Authentication Testing** — Weak auth, session fixation, token reuse
3. **IDOR/BOLA** — Insecure Direct Object Reference (sequential/UUID IDs)
4. **Horizontal Escalation** — Access other users' data
5. **Vertical Escalation** — Privilege elevation (user → admin)
6. **API Auth Gaps** — Missing/weak authentication on API endpoints
7. **JWT Exploitation** — Algorithm confusion, key leakage, expiration bypass

### Quality
- **Dual-account testing** — Compares access between privileged & unprivileged accounts
- **IDOR-focused** — Highest ROI vulnerability (IDOR pays $1K-$5K avg)
- **Integration ready** — Consumes hunt.sh and api.sh output
- **VRT-ready** — Pre-categorized findings

---

## Requirements

### Required
```bash
sudo pacman -S curl jq
```

### Optional
```bash
jwt-cli python3-jwt
```

### Two Test Accounts
Need access to both:
- **Unprivileged user** — Regular account
- **Privileged user** — Admin/moderator account (or different user)

---

## Installation

```bash
git clone https://github.com/Sharon-Needles/access
cd access

sudo ln -s "$(pwd)/access.sh" /usr/local/bin/access
```

---

## Quick Start

### Interactive (Recommended for Auth Testing)
```bash
access
```
Prompts for test account credentials.

### CLI Mode
```bash
access --target "Company" --urls api.txt --user1 low@test.com --pass1 password123
```

### Resume
```bash
access --resume ./hunts/Company_AC_20260423_120000
```

---

## Usage

```
Usage: access.sh [OPTIONS]

Options:
  --target NAME           Target name
  --urls FILE             API/endpoint URLs
  --user1 EMAIL           Low-privilege account email
  --pass1 PASSWORD        Low-privilege password
  --user2 EMAIL           High-privilege account email (optional)
  --pass2 PASSWORD        High-privilege password (optional)
  --platform PLATFORM     bugcrowd | hackerone
  --resume PATH           Resume hunt
  -h, --help              Show help
```

### Examples

**Test with two different user accounts:**
```bash
access --target "Company" --urls endpoints.txt \
  --user1 user@test.com --pass1 pass123 \
  --user2 admin@test.com --pass2 adminpass
```

**IDOR hunting (sequential ID testing):**
```bash
access --target "Company" --urls "/api/users" --user1 test@company.com --pass1 test123
```

**API authentication gaps:**
```bash
access --target "Company" --urls api.txt --platform bugcrowd
```

---

## Output

```
Company_AC_20260423_*/
├── phase_1_endpoints.txt           # Discovered endpoints
├── phase_2_auth_testing.txt        # Auth mechanism findings
├── phase_3_idor.txt                # IDOR vulnerabilities
├── phase_4_horizontal.txt          # Lateral access
├── phase_5_vertical.txt            # Privilege escalation
├── phase_6_api_auth.txt            # Missing/weak API auth
├── phase_7_jwt.txt                 # JWT weaknesses
├── findings.txt                    # Consolidated
├── [SUBMIT:P1-P3].txt             # Ready-to-submit
└── report.md                       # Bugcrowd/H1 ready
```

---

## IDOR Testing Details

IDOR is the highest-ROI vulnerability ($1K-$5K average). Test by:

1. **Sequential IDs**: Replace `/users/123` with `/users/124`, `/users/125`, etc.
2. **UUID patterns**: Try reversing, incrementing, or fuzzing UUIDs
3. **Method switching**: Try GET, POST, PUT, DELETE on same endpoint
4. **Parameter mutation**: Change `user_id=123` to `userId=123`, `id=123`, etc.
5. **Version downgrade**: Try `/v1/` endpoints if `/v2/` has auth

---

## Integration with Other Tools

### From hunt.sh
```bash
cat ./hunts/Target_*/phase_3_sweep.json | jq '.[] | .url' > endpoints.txt
access --target "Target" --urls endpoints.txt --user1 test@test.com --pass1 pass
```

### From api.sh
```bash
cat ./hunts/Target_API_*/findings.txt | grep "endpoint" | cut -d' ' -f2 > api_urls.txt
access --target "Target" --urls api_urls.txt --user1 test@test.com --pass1 pass
```

---

## Tested On

- BlackArch Linux
- Bash 5.x

---

## License

MIT

---

## Disclaimer

Use responsibly with explicit written permission only.

**Important**: Only test access control on accounts you own or have explicit permission to use.
