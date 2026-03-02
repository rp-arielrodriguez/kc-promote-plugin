# kc-promote

Claude Code plugin for Keycloak realm config promotion across environments.

Snapshot, diff, and apply Keycloak realm configurations between DEV, QA, PROD, and local.

## Install

```bash
claude plugin install https://github.com/rp-arielrodriguez/kc-promote-plugin
```

Or for local dev:

```bash
claude --plugin-dir /path/to/kc-promote-plugin
```

## Setup

Set environment variables for your Keycloak admin-cli secrets:

```bash
export KC_DEV_SECRET="your-dev-admin-cli-secret"
export KC_QA_SECRET="your-qa-admin-cli-secret"
export KC_PROD_SECRET="your-prod-admin-cli-secret"
export KC_LOCAL_SECRET="your-local-admin-cli-secret"
```

Optional overrides:

```bash
export KC_PROXY="socks5h://127.0.0.1:1080"  # default
export KC_PROMOTE_SCRIPT="/path/to/kc-promote.py"  # auto-discovered
export KC_PROMOTE_SNAPSHOTS="/path/to/snapshots"  # defaults to CWD
```

## Usage

```
/kc-promote:kc-promote diff DEV PROD
/kc-promote:kc-promote diff DEV PROD --filter clients/recarga
/kc-promote:kc-promote snapshot PROD
/kc-promote:kc-promote apply DEV->PROD clients/recarga,clients/service
/kc-promote:kc-promote status
```

## Requirements

- Python 3.8+
- `curl` (for SOCKS proxy support)
- SOCKS proxy to reach remote KC instances (SSH tunnel)

## What it does

- **snapshot**: Export and normalize a full realm config via Keycloak REST API
- **diff**: Compare two snapshots with human-readable output, filtering by entity
- **apply**: Generate and optionally execute kcadm.sh commands to sync environments

The diff normalizes away env-specific noise (UUIDs, secrets, timestamps, KC version defaults) so you see only meaningful config drift.

## Plugin Structure

```
kc-promote-plugin/
├── .claude-plugin/
│   └── plugin.json
├── agents/
│   └── kc-promote.md
├── skills/
│   └── kc-promote/
│       └── SKILL.md
├── scripts/
│   └── kc-promote.py
└── README.md
```
