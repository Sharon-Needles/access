# CLAUDE.md — access.sh

Access control & authentication testing — IDOR/BOLA, privilege escalation, JWT weaknesses, API auth gaps.

## What It Does

7-phase access control testing focused on authorization bypass:
1. Endpoint mapping (discovers authenticated API endpoints)
2. Auth mechanism testing (weak auth, session reuse, token bypass)
3. IDOR/BOLA (insecure direct object reference — highest ROI vulnerability)
4. Horizontal escalation (access other users' data)
5. Vertical escalation (user → admin privilege elevation)
6. API authentication gaps (missing auth, weak validation)
7. JWT exploitation (algorithm confusion, expiration bypass, key leakage)

Requires two test accounts (low-privilege and optionally high-privilege) for comparison testing.

## When to Use

- When hunt.sh/api.sh discover authenticated endpoints
- Dedicated IDOR hunting (sequential ID enumeration)
- API auth testing (missing Authorization headers)
- Privilege escalation assessment
- JWT token weaknesses

## Key Facts

**IDOR pays** — $1K-$5K average on bug bounty. Highest ROI vuln after business logic bugs.

**Requires test accounts** — Interactive mode prompts for credentials. Make sure you have explicit permission.

**Dual-account comparison** — Tests both unprivileged and privileged accounts to find escalation.

## Common Commands

```bash
# Interactive (prompts for creds)
access

# With two test accounts
access --target "Target" --urls endpoints.txt \
  --user1 user@test.com --pass1 pass123 \
  --user2 admin@test.com --pass2 adminpass

# IDOR focus (sequential ID testing)
access --target "Target" --urls "/api/users/{id}" \
  --user1 test@company.com --pass1 password

# Resume
access --resume ./hunts/Target_AC_20260423_120000
```

## Output

Findings tagged by phase:
- `phase_3_idor.txt` — IDOR results (primary target)
- `phase_5_vertical.txt` — Privilege escalation
- `[SUBMIT:P1].txt` — Critical (IDOR with data access)
- `[SUBMIT:P2].txt` — High (auth bypass)
- `report.md` — Bugcrowd/H1 ready

## IDOR Testing Strategy

1. Identify numeric IDs in URLs: `/api/users/123/profile`
2. Enumerate: Try 121, 122, 124, 125, ... does access work?
3. Compare accounts: Does user A access user B's data?
4. Test all methods: GET, POST, PUT, DELETE on same endpoint
5. Record first successful ID accessed by both accounts = IDOR

---

MIT License. Sharon-Needles OSINT toolkit.
