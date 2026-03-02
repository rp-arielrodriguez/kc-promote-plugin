---
name: kc-promote
description: >
  Promote Keycloak config between environments. Use when user wants to
  diff, snapshot, compare, or apply Keycloak realm changes across
  DEV, QA, PROD, or local environments.
argument-hint: [command] [args...]
context: fork
agent: kc-promote
---

Keycloak config promotion task.

## Usage Examples

- `/kc-promote:kc-promote diff DEV PROD` - compare DEV and PROD
- `/kc-promote:kc-promote diff DEV PROD --filter clients/recarga` - compare specific client
- `/kc-promote:kc-promote snapshot PROD` - take fresh PROD snapshot
- `/kc-promote:kc-promote apply DEV->PROD clients/recarga,clients/service` - promote specific entities
- `/kc-promote:kc-promote status` - show what snapshots exist and their age

## Task

$ARGUMENTS

If no arguments provided, ask the user what they want to do:
1. Take a snapshot of an environment
2. Diff two environments
3. Apply specific changes from one env to another

Always consult your agent memory before starting work.
