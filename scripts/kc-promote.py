#!/usr/bin/env python3
"""
kc-promote: Keycloak config promotion tool.

Snapshot realm config via kcadm.sh, diff between environments, generate apply commands.

Usage:
    # Snapshot
    kc-promote.py snapshot --config /path/to/kcadm.config --realm recarga --output dev.json

    # Diff
    kc-promote.py diff --source dev.json --target qa.json

    # Apply (generates kcadm.sh commands, does NOT execute)
    kc-promote.py apply --source dev.json --target qa.json --config /path/to/target-kcadm.config
"""

import argparse
import json
import subprocess
import sys
import os
import tempfile
from collections import OrderedDict
from copy import deepcopy

# --- Constants ---

KCADM_DOCKER = (
    "docker run -i {network} -v {mount}:/home:rw keycloak:local "
    "/opt/bitnami/keycloak/bin/kcadm.sh"
)

# Fields to strip from snapshots (computed, env-specific, or noise)
STRIP_FIELDS_TOP = {
    "id",  # realm internal ID differs per env
}

STRIP_FIELDS_RECURSIVE = {
    "id",               # internal UUIDs differ per env
    "internalId",       # env-specific UUID (e.g. identity providers)
    "containerId",      # realm ID reference
    "flowId",           # auth flow internal ID
    "authenticationFlow",  # redundant bool in executions
    "createdTimestamp",  # env-specific creation time
}

# Attribute keys to strip (env-specific noise inside config/attributes dicts)
STRIP_ATTRIBUTE_KEYS = {
    "client.secret.creation.time",  # rotated per env
}

# IdP config keys that are KC version defaults (false/"false") — strip if default
IDP_DEFAULT_FALSE_KEYS = {
    "acceptsPromptNoneForwardFromClient",
    "caseSensitiveOriginalUsername",
    "disableUserInfo",
    "filteredByClaim",
}

# Regex for UUID pattern (used to filter authz noise)
import re
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# --- Environment presets ---
# Secrets are read from environment variables:
#   KC_DEV_SECRET, KC_QA_SECRET, KC_PROD_SECRET, KC_LOCAL_SECRET
# Override proxy with KC_PROXY (default: socks5h://127.0.0.1:1080)
_proxy = os.environ.get("KC_PROXY", "socks5h://127.0.0.1:1080")

ENVS = {
    "dev": {
        "server": os.environ.get("KC_DEV_SERVER", "https://keycloak-dev.recargapay.com/auth"),
        "realm": "recarga",
        "client_id": "admin-cli",
        "client_secret": os.environ.get("KC_DEV_SECRET", ""),
        "proxy": _proxy,
    },
    "qa": {
        "server": os.environ.get("KC_QA_SERVER", "https://keycloak-qa.recargapay.com/auth"),
        "realm": "recarga",
        "client_id": "admin-cli",
        "client_secret": os.environ.get("KC_QA_SECRET", ""),
        "proxy": _proxy,
    },
    "prod": {
        "server": os.environ.get("KC_PROD_SERVER", "https://keycloak.recargapay.com/auth"),
        "realm": "recarga",
        "client_id": "admin-cli",
        "client_secret": os.environ.get("KC_PROD_SECRET", ""),
        "proxy": _proxy,
    },
    "local": {
        "server": os.environ.get("KC_LOCAL_SERVER", "http://keycloak:9091/auth"),
        "realm": "recarga",
        "client_id": "admin-cli",
        "client_secret": os.environ.get("KC_LOCAL_SECRET", ""),
        "proxy": None,
        "docker_network": os.environ.get("KC_LOCAL_DOCKER_NETWORK", "keycloak_keycloak-network"),
    },
}

# Fields where secrets are masked in export (** or empty) — skip in diff
SECRET_FIELDS = {
    "secret",
    "credentials",
    "config.secret",
    "config.client.secret",
}

# Entity types with their sort key for stable ordering
ENTITY_SORT_KEYS = {
    "clients": "clientId",
    "clientScopes": "name",
    "identityProviders": "alias",
    "identityProviderMappers": "name",
    "authenticationFlows": "alias",
    "authenticatorConfig": "alias",
    "requiredActions": "alias",
    "roles.realm": "name",
    "groups": "name",
    "scopeMappings": "clientScope",
    "defaultDefaultClientScopes": "name",
    "defaultOptionalClientScopes": "name",
    "protocolMappers": "name",
}

# Sub-entities within clients that need sorting
CLIENT_SUB_ENTITIES = {
    "protocolMappers": "name",
    "defaultClientScopes": None,  # list of strings
    "optionalClientScopes": None,  # list of strings
}


# --- Snapshot ---

def run_kcadm(args, config_path, mount_dir, docker_network=None):
    """Run kcadm.sh via docker and return stdout.

    kcadm.sh expects: kcadm.sh <subcommand> --config <path> [options]
    The --config flag goes AFTER the subcommand, not before.
    """
    docker_config = config_path.replace(mount_dir, "/home")
    # Insert --config after the first word (subcommand) in args
    args_parts = args.split(None, 1)
    if len(args_parts) == 2:
        subcmd, rest = args_parts
        kcadm_args = f"{subcmd} --config {docker_config} {rest}"
    else:
        kcadm_args = f"{args} --config {docker_config}"

    net_flag = f"--network {docker_network}" if docker_network else ""
    cmd = KCADM_DOCKER.format(mount=mount_dir, network=net_flag) + " " + kcadm_args
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=120
    )
    # Filter bitnami banner noise — redirect stderr but banner leaks into stdout too
    stdout = result.stdout.strip()
    lines = stdout.split("\n")
    json_start = next(
        (i for i, l in enumerate(lines) if l.strip().startswith(("{", "["))), 0
    )
    clean = "\n".join(lines[json_start:])
    if result.returncode != 0 and not clean:
        print(f"kcadm error: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return clean


def snapshot(config_path, realm, mount_dir, docker_network=None):
    """Export full realm config via partial-export and enrich with scope bindings."""
    print(f"Exporting realm '{realm}'...", file=sys.stderr)
    kw = dict(config_path=config_path, mount_dir=mount_dir, docker_network=docker_network)

    # 1. Partial export (clients + groups + roles)
    raw = run_kcadm(
        f"create realms/{realm}/partial-export -o "
        f"-q exportClients=true -q exportGroupsAndRoles=true -r {realm}",
        **kw,
    )
    realm_data = json.loads(raw)

    # 2. Enrich: get client-level scope bindings (not in partial-export)
    clients = realm_data.get("clients", [])
    for client in clients:
        cid = client.get("id")
        if not cid:
            continue

        # Default client scopes
        raw_dcs = run_kcadm(
            f"get clients/{cid}/default-client-scopes -r {realm}", **kw,
        )
        dcs = json.loads(raw_dcs) if raw_dcs.strip() else []
        client["_defaultClientScopes"] = sorted(
            [s["name"] for s in dcs if "name" in s]
        )

        # Optional client scopes
        raw_ocs = run_kcadm(
            f"get clients/{cid}/optional-client-scopes -r {realm}", **kw,
        )
        ocs = json.loads(raw_ocs) if raw_ocs.strip() else []
        client["_optionalClientScopes"] = sorted(
            [s["name"] for s in ocs if "name" in s]
        )

    # 3. Enrich: get realm-level default/optional scope names
    raw_rdcs = run_kcadm(
        f"get realms/{realm}/default-default-client-scopes", **kw,
    )
    rdcs = json.loads(raw_rdcs) if raw_rdcs.strip() else []
    realm_data["_realmDefaultScopes"] = sorted([s["name"] for s in rdcs if "name" in s])

    raw_rocs = run_kcadm(
        f"get realms/{realm}/default-optional-client-scopes", **kw,
    )
    rocs = json.loads(raw_rocs) if raw_rocs.strip() else []
    realm_data["_realmOptionalScopes"] = sorted([s["name"] for s in rocs if "name" in s])

    return realm_data


def normalize(data):
    """Normalize snapshot for stable diffing."""
    data = deepcopy(data)

    # Strip top-level computed fields
    for f in STRIP_FIELDS_TOP:
        data.pop(f, None)

    # Strip users — service accounts are env-specific, not promotable
    data.pop("users", None)

    # Strip top-level fields that duplicate attributes.* (avoid double-counting)
    for dup in ("clientSessionIdleTimeout", "clientSessionMaxLifespan"):
        if dup in data and "attributes" in data and dup in data.get("attributes", {}):
            del data[dup]

    # Sort entity arrays by their natural key
    for path, key in ENTITY_SORT_KEYS.items():
        parts = path.split(".")
        target = data
        for p in parts[:-1]:
            if isinstance(target, dict):
                target = target.get(p, {})
        field = parts[-1]
        if isinstance(target, dict) and field in target:
            arr = target[field]
            if isinstance(arr, list) and arr:
                if key and isinstance(arr[0], dict):
                    target[field] = sorted(arr, key=lambda x: x.get(key, ""))
                elif not key:
                    target[field] = sorted(arr)

    # Sort clients and their sub-entities
    clients = data.get("clients", [])
    clients.sort(key=lambda c: c.get("clientId", ""))
    for client in clients:
        # Sort protocol mappers within clients
        pms = client.get("protocolMappers", [])
        if pms:
            client["protocolMappers"] = sorted(pms, key=lambda m: m.get("name", ""))
        # Sort string lists
        for field in ("defaultClientScopes", "optionalClientScopes",
                      "_defaultClientScopes", "_optionalClientScopes"):
            if field in client and isinstance(client[field], list):
                client[field] = sorted(client[field])

    # Sort client roles within roles
    roles = data.get("roles", {})
    if "client" in roles and isinstance(roles["client"], dict):
        for client_id, role_list in roles["client"].items():
            if isinstance(role_list, list):
                roles["client"][client_id] = sorted(
                    role_list, key=lambda r: r.get("name", "")
                )

    # Strip IdP config keys that are just KC version defaults (false/"false")
    for idp in data.get("identityProviders", []):
        cfg = idp.get("config", {})
        for key in IDP_DEFAULT_FALSE_KEYS:
            val = cfg.get(key)
            if val in (False, "false"):
                del cfg[key]

    # Sort auth flow executions
    for flow in data.get("authenticationFlows", []):
        execs = flow.get("authenticationExecutions", [])
        # Preserve order (priority matters), but strip computed IDs
        for ex in execs:
            for f in STRIP_FIELDS_RECURSIVE:
                ex.pop(f, None)

    # Strip UUID-keyed authz policies/resources from realm-management client
    # These contain env-specific UUIDs in their names and are auto-generated
    for client in data.get("clients", []):
        authz = client.get("authorizationSettings")
        if not authz:
            continue
        for key in ("policies", "resources"):
            items = authz.get(key)
            if not items or not isinstance(items, list):
                continue
            authz[key] = [
                item for item in items
                if not UUID_RE.search(item.get("name", ""))
            ]
            authz[key].sort(key=lambda x: x.get("name", ""))

    # Recursively strip IDs and secrets
    _strip_recursive(data)

    return data


def _strip_recursive(obj, parent_key=None):
    """Remove computed/secret fields recursively."""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if key in STRIP_FIELDS_RECURSIVE:
                del obj[key]
            elif key in SECRET_FIELDS:
                obj[key] = "<SECRET>"
            elif key in STRIP_ATTRIBUTE_KEYS:
                del obj[key]
            else:
                _strip_recursive(obj[key], key)
    elif isinstance(obj, list):
        for item in obj:
            _strip_recursive(item, parent_key)


# --- Filter ---

def parse_filter(filter_str):
    """Parse filter string like 'clients/recarga,clients/service,clientScopes/roles'.

    Returns list of (entity_type, entity_name) tuples.
    If entity_name is None, matches all entities of that type.
    """
    if not filter_str:
        return None
    filters = []
    for part in filter_str.split(","):
        part = part.strip()
        if "/" in part:
            etype, ename = part.split("/", 1)
            filters.append((etype.strip(), ename.strip()))
        else:
            filters.append((part.strip(), None))
    return filters


def filter_diffs(diffs, filters):
    """Filter diffs to only include paths matching the filter specs.

    Filter format: [(entity_type, entity_name), ...]
    - ("clients", "recarga") matches clients[clientId=recarga].*
    - ("clients", None) matches clients[*].* and clients.*
    - ("roles", None) matches roles.*
    """
    if not filters:
        return diffs

    # Build lookup: entity_type -> set of entity_names (None = all)
    fmap = {}
    for etype, ename in filters:
        if etype not in fmap:
            fmap[etype] = set()
        if ename is None:
            fmap[etype] = None  # match all
        elif fmap[etype] is not None:
            fmap[etype].add(ename)

    result = []
    for path, src, tgt in diffs:
        top = path.split(".")[0].split("[")[0].strip()

        if top not in fmap:
            continue

        names = fmap[top]
        if names is None:
            # Match all entities of this type
            result.append((path, src, tgt))
            continue

        # Extract entity name from path bracket
        # e.g. clients[clientId=recarga].foo -> recarga
        if "[" in path:
            bracket = path.split("[", 1)[1].split("]", 1)[0]
            if "=" in bracket:
                entity_name = bracket.split("=", 1)[1]
                if entity_name in names:
                    result.append((path, src, tgt))
        # Also match paths like "clients [only in source]" with no bracket
        # These are set-level diffs, include if type matches
        elif " [only in" in path:
            result.append((path, src, tgt))

    return result


# --- API-based snapshot (REST API via SOCKS proxy) ---

def api_get_token(env_cfg):
    """Get admin token via client_credentials grant."""
    import urllib.request
    import urllib.parse

    server = env_cfg["server"]
    realm = env_cfg["realm"]
    url = f"{server}/realms/{realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": env_cfg["client_id"],
        "client_secret": env_cfg["client_secret"],
    }).encode()

    if env_cfg.get("proxy"):
        # Use curl for SOCKS proxy support (urllib doesn't support socks5h)
        cmd = (
            f"curl -s -x {env_cfg['proxy']} '{url}' "
            f"-d 'grant_type=client_credentials' "
            f"-d 'client_id={env_cfg['client_id']}' "
            f"-d 'client_secret={env_cfg['client_secret']}'"
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"Token error: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        return json.loads(result.stdout)["access_token"]
    else:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["access_token"]


def api_request(env_cfg, token, path, method="GET", data=None):
    """Make authenticated admin API request, returns parsed JSON."""
    server = env_cfg["server"]
    realm = env_cfg["realm"]
    url = f"{server}/admin/realms/{realm}/{path}" if path else f"{server}/admin/realms/{realm}"

    if env_cfg.get("proxy"):
        method_flag = f"-X {method}" if method != "GET" else ""
        data_flag = ""
        if data is not None:
            json_str = json.dumps(data).replace("'", "'\\''")
            data_flag = f"-H 'Content-Type: application/json' -d '{json_str}'"

        cmd = (
            f"curl -s -x {env_cfg['proxy']} {method_flag} '{url}' "
            f"-H 'Authorization: Bearer {token}' {data_flag}"
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"API error: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        return json.loads(result.stdout) if result.stdout.strip() else None
    else:
        import urllib.request
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        if method != "GET":
            req.method = method
        if data is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(data).encode()
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            return json.loads(body) if body else None


def api_post(env_cfg, token, path, data=None):
    """POST request (e.g. partial-export)."""
    server = env_cfg["server"]
    realm = env_cfg["realm"]
    url = f"{server}/admin/realms/{realm}/{path}"

    if env_cfg.get("proxy"):
        data_flag = ""
        if data is not None:
            json_str = json.dumps(data).replace("'", "'\\''")
            data_flag = f"-H 'Content-Type: application/json' -d '{json_str}'"

        cmd = (
            f"curl -s -x {env_cfg['proxy']} -X POST '{url}' "
            f"-H 'Authorization: Bearer {token}' {data_flag}"
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"API error: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        return json.loads(result.stdout) if result.stdout.strip() else None
    else:
        import urllib.request
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(data).encode()
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read()
            return json.loads(body) if body else None


def api_snapshot(env_cfg):
    """Take a full realm snapshot via REST API (no docker/kcadm needed)."""
    print(f"Authenticating to {env_cfg['server']}...", file=sys.stderr)
    token = api_get_token(env_cfg)

    realm = env_cfg["realm"]
    print(f"Exporting realm '{realm}' via REST API...", file=sys.stderr)

    # 1. Partial export
    realm_data = api_post(
        env_cfg, token,
        f"partial-export?exportClients=true&exportGroupsAndRoles=true"
    )

    if not realm_data:
        print("Error: partial-export returned empty response", file=sys.stderr)
        sys.exit(1)

    # 2. Enrich: client scope bindings
    clients = realm_data.get("clients", [])
    for client in clients:
        cid = client.get("id")
        if not cid:
            continue

        dcs = api_request(env_cfg, token, f"clients/{cid}/default-client-scopes") or []
        client["_defaultClientScopes"] = sorted([s["name"] for s in dcs if "name" in s])

        ocs = api_request(env_cfg, token, f"clients/{cid}/optional-client-scopes") or []
        client["_optionalClientScopes"] = sorted([s["name"] for s in ocs if "name" in s])

    # 3. Realm-level default/optional scopes
    rdcs = api_request(env_cfg, token, "default-default-client-scopes") or []
    realm_data["_realmDefaultScopes"] = sorted([s["name"] for s in rdcs if "name" in s])

    rocs = api_request(env_cfg, token, "default-optional-client-scopes") or []
    realm_data["_realmOptionalScopes"] = sorted([s["name"] for s in rocs if "name" in s])

    return realm_data


# --- Diff ---

def diff_values(source, target, path=""):
    """Recursively diff two JSON structures. Returns list of (path, source_val, target_val)."""
    diffs = []

    if type(source) != type(target):
        diffs.append((path, source, target))
        return diffs

    if isinstance(source, dict):
        all_keys = sorted(set(list(source.keys()) + list(target.keys())))
        for key in all_keys:
            child_path = f"{path}.{key}" if path else key
            if key not in target:
                diffs.append((child_path, source[key], "<MISSING>"))
            elif key not in source:
                diffs.append((child_path, "<MISSING>", target[key]))
            else:
                diffs.extend(diff_values(source[key], target[key], child_path))

    elif isinstance(source, list):
        # Try to match by natural key if dicts
        if source and isinstance(source[0], dict):
            # Find the best key to match on
            match_key = _find_match_key(source)
            if match_key:
                diffs.extend(_diff_keyed_list(source, target, path, match_key))
            else:
                # Fall back to positional diff
                for i in range(max(len(source), len(target))):
                    child_path = f"{path}[{i}]"
                    if i >= len(source):
                        diffs.append((child_path, "<MISSING>", target[i]))
                    elif i >= len(target):
                        diffs.append((child_path, source[i], "<MISSING>"))
                    else:
                        diffs.extend(diff_values(source[i], target[i], child_path))
        else:
            # Primitive lists — compare as sets if order doesn't matter
            if sorted(str(x) for x in source) != sorted(str(x) for x in target):
                s_set = set(str(x) for x in source)
                t_set = set(str(x) for x in target)
                only_source = s_set - t_set
                only_target = t_set - s_set
                if only_source:
                    diffs.append((f"{path} [only in source]", sorted(only_source), None))
                if only_target:
                    diffs.append((f"{path} [only in target]", None, sorted(only_target)))
    else:
        if source != target:
            # Skip secret diffs
            if str(source) == "<SECRET>" or str(target) == "<SECRET>":
                return diffs
            diffs.append((path, source, target))

    return diffs


def _find_match_key(items):
    """Find the best key to use for matching list items."""
    for candidate in ("clientId", "alias", "name", "providerId", "clientScope"):
        if all(candidate in item for item in items):
            return candidate
    return None


def _diff_keyed_list(source, target, path, key):
    """Diff two lists of dicts matched by a key field."""
    diffs = []
    source_map = {item[key]: item for item in source}
    target_map = {item[key]: item for item in target}

    all_keys = sorted(set(list(source_map.keys()) + list(target_map.keys())))
    for k in all_keys:
        child_path = f"{path}[{key}={k}]"
        if k not in target_map:
            diffs.append((child_path, f"<EXISTS>", "<MISSING>"))
        elif k not in source_map:
            diffs.append((child_path, "<MISSING>", f"<EXISTS>"))
        else:
            diffs.extend(diff_values(source_map[k], target_map[k], child_path))

    return diffs


# --- Formatting ---

# Terminal colors
class C:
    """ANSI color codes. Disabled if not a TTY."""
    _enabled = sys.stdout.isatty()

    @staticmethod
    def _w(code, text):
        return f"\033[{code}m{text}\033[0m" if C._enabled else text

    @staticmethod
    def red(t):    return C._w("31", t)
    @staticmethod
    def green(t):  return C._w("32", t)
    @staticmethod
    def yellow(t): return C._w("33", t)
    @staticmethod
    def cyan(t):   return C._w("36", t)
    @staticmethod
    def bold(t):   return C._w("1", t)
    @staticmethod
    def dim(t):    return C._w("2", t)


# Known timeout/lifespan field names (values are seconds)
DURATION_FIELDS = {
    "accessTokenLifespan", "accessTokenLifespanForImplicitFlow",
    "ssoSessionIdleTimeout", "ssoSessionMaxLifespan",
    "offlineSessionIdleTimeout", "offlineSessionMaxLifespan",
    "clientSessionIdleTimeout", "clientSessionMaxLifespan",
    "access.token.lifespan", "client.session.idle.timeout",
    "client.session.max.lifespan", "actionTokenGeneratedByUserLifespan",
}

# Human-readable category names
CATEGORY_LABELS = {
    "_realmDefaultScopes": "Realm default scopes",
    "_realmOptionalScopes": "Realm optional scopes",
    "accessTokenLifespan": "Realm settings",
    "attributes": "Realm settings",
    "clientSessionIdleTimeout": "Realm settings",
    "clientSessionMaxLifespan": "Realm settings",
    "ssoSessionIdleTimeout": "Realm settings",
    "ssoSessionMaxLifespan": "Realm settings",
    "offlineSessionIdleTimeout": "Realm settings",
    "offlineSessionMaxLifespan": "Realm settings",
    "sslRequired": "Realm settings",
    "directGrantFlow": "Realm settings",
    "defaultLocale": "Realm settings",
    "eventsEnabled": "Realm settings",
    "eventsListeners": "Realm settings",
    "enabledEventTypes": "Realm settings",
    "webAuthnPolicyPasswordlessSignatureAlgorithms": "Realm settings",
    "webAuthnPolicySignatureAlgorithms": "Realm settings",
    "webAuthnPolicyRpEntityName": "Realm settings",
    "defaultDefaultClientScopes": "Realm scope bindings",
    "defaultOptionalClientScopes": "Realm scope bindings",
    "_realmDefaultScopes": "Realm scope bindings",
    "_realmOptionalScopes": "Realm scope bindings",
    "federatedUsers": "Federated users",
    "clientScopes": "Client scopes",
    "clients": "Clients",
    "identityProviders": "Identity providers",
    "identityProviderMappers": "IdP mappers",
    "authenticationFlows": "Auth flows",
    "authenticatorConfig": "Auth config",
    "requiredActions": "Required actions",
    "roles": "Roles",
    "groups": "Groups",
    "components": "Components",
    "federatedUsers": "Federated users",
    "scopeMappings": "Scope mappings",
}


def _fmt_duration(seconds):
    """Format seconds into human-readable duration."""
    try:
        seconds = int(seconds)
    except (ValueError, TypeError):
        return str(seconds)
    if seconds == 0:
        return "0"
    parts = []
    if seconds >= 31536000:
        y = seconds // 31536000
        parts.append(f"{y}y")
        seconds %= 31536000
    if seconds >= 86400:
        d = seconds // 86400
        parts.append(f"{d}d")
        seconds %= 86400
    if seconds >= 3600:
        h = seconds // 3600
        parts.append(f"{h}h")
        seconds %= 3600
    if seconds >= 60:
        m = seconds // 60
        parts.append(f"{m}m")
        seconds %= 60
    if seconds > 0:
        parts.append(f"{seconds}s")
    return "".join(parts)


def _is_duration_field(path):
    """Check if a diff path refers to a duration field."""
    leaf = path.rsplit(".", 1)[-1].split("[")[0]
    return leaf in DURATION_FIELDS


def _fmt_val(val, path=""):
    """Format a value compactly for inline display."""
    if val == "<MISSING>" or val == "<EXISTS>" or val is None:
        return str(val)
    if _is_duration_field(path):
        try:
            return _fmt_duration(int(val))
        except (ValueError, TypeError):
            pass
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, list):
        if all(isinstance(x, str) for x in val):
            if len(val) <= 4:
                return "[" + ", ".join(val) + "]"
            return f"[{val[0]}, ... +{len(val)-1} more]"
        return f"[{len(val)} items]"
    if isinstance(val, dict):
        return f"{{{len(val)} keys}}"
    s = str(val)
    if len(s) > 80:
        return s[:77] + "..."
    return s


def _get_category(path):
    """Map a diff path to a human-readable category."""
    # Strip trailing " [only in source]" / " [only in target]" from top key
    top = path.split(".")[0].split("[")[0].strip()
    return CATEGORY_LABELS.get(top, top)


def _get_entity_key(path):
    """Extract entity identifier from path like 'clients[clientId=recarga].foo'."""
    if "[" in path:
        bracket = path.split("[", 1)[1]
        key_part = bracket.split("]", 1)[0]
        return key_part
    return None


def _get_field(path):
    """Extract the leaf field from a path."""
    # Strip top-level and entity bracket, return remaining dotted path
    parts = path.split("]", 1)
    if len(parts) == 2 and parts[1]:
        return parts[1].lstrip(".")
    # No bracket — strip top-level key
    dot = path.find(".")
    if dot >= 0:
        return path[dot+1:]
    return ""


def _classify_diff(src, tgt):
    """Classify a diff as added/removed/modified."""
    if src == "<MISSING>":
        return "added"
    if tgt == "<MISSING>" or tgt is None:
        return "removed"
    return "modified"


def format_diff(diffs, detail="normal", from_label="FROM", to_label="TO"):
    """Format diff output for human reading.

    detail: 'summary' | 'normal' | 'full'
    """
    if not diffs:
        return C.green("No differences found.")

    # --- Phase 1: classify and group ---
    # {category: {entity_or_field: [(path, src, tgt, kind)]}}
    grouped = OrderedDict()
    cat_counts = OrderedDict()  # {category: {added: N, modified: N, removed: N}}

    for path, src, tgt in diffs:
        cat = _get_category(path)
        kind = _classify_diff(src, tgt)

        if cat not in cat_counts:
            cat_counts[cat] = {"added": 0, "modified": 0, "removed": 0}
        cat_counts[cat][kind] += 1

        if cat not in grouped:
            grouped[cat] = OrderedDict()

        entity = _get_entity_key(path)
        group_key = entity or "(realm-level)"
        if group_key not in grouped[cat]:
            grouped[cat][group_key] = []
        grouped[cat][group_key].append((path, src, tgt, kind))

    # --- Phase 2: summary table ---
    lines = []
    total_a = sum(c["added"] for c in cat_counts.values())
    total_m = sum(c["modified"] for c in cat_counts.values())
    total_r = sum(c["removed"] for c in cat_counts.values())

    lines.append("")
    lines.append(C.bold("  Summary"))
    lines.append(C.dim("  " + "-" * 56))
    only_to = f"Only {to_label}"
    only_from = f"Only {from_label}"
    hdr = f"  {'Category':<28} {C.green(only_to):>8}  {C.yellow('Different'):>8}  {C.red(only_from):>8}"
    lines.append(hdr)
    lines.append(C.dim("  " + "-" * 56))

    for cat, counts in cat_counts.items():
        a = counts["added"]
        m = counts["modified"]
        r = counts["removed"]
        a_s = C.green(str(a)) if a else C.dim("0")
        m_s = C.yellow(str(m)) if m else C.dim("0")
        r_s = C.red(str(r)) if r else C.dim("0")
        lines.append(f"  {cat:<28} {a_s:>8}  {m_s:>8}  {r_s:>8}")

    lines.append(C.dim("  " + "-" * 56))
    ta = C.green(str(total_a)) if total_a else "0"
    tm = C.yellow(str(total_m)) if total_m else "0"
    tr = C.red(str(total_r)) if total_r else "0"
    lines.append(C.bold(f"  {'Total':<28} {ta:>8}  {tm:>8}  {tr:>8}"))
    lines.append("")

    if detail == "summary":
        return "\n".join(lines)

    # --- Phase 3: detailed entity-grouped diffs ---
    for cat, entities in grouped.items():
        lines.append(C.bold(C.cyan(f"  {cat}")))
        lines.append(C.dim("  " + "=" * 56))

        for entity_key, changes in entities.items():
            # Entity header
            if entity_key != "(realm-level)":
                lines.append(f"    {C.bold(entity_key)}")
            else:
                pass  # realm-level fields listed directly

            # Separate into added/modified/removed
            added = [(p, s, t) for p, s, t, k in changes if k == "added"]
            modified = [(p, s, t) for p, s, t, k in changes if k == "modified"]
            removed = [(p, s, t) for p, s, t, k in changes if k == "removed"]

            # Check if entire entity is added/removed
            is_entity_add = (len(added) == 1 and added[0][1] == "<MISSING>"
                             and added[0][2] in ("<EXISTS>", None)
                             and not modified and not removed)
            is_entity_rm = (len(removed) == 1 and removed[0][0].count(".") == 0
                            and removed[0][0].count("]") <= 1
                            and removed[0][1] in ("<EXISTS>", None)
                            and not modified and not added)

            if is_entity_add:
                lines.append(C.green(f"      + (only in {to_label})"))
                continue
            if is_entity_rm:
                lines.append(C.red(f"      - (only in {from_label})"))
                continue

            if modified:
                if entity_key != "(realm-level)":
                    lines.append(C.yellow(f"      Modified:"))
                for p, s, t in modified:
                    field = _get_field(p) or p
                    sv = _fmt_val(s, p)
                    tv = _fmt_val(t, p)
                    if detail == "full" or len(sv) + len(tv) < 80:
                        lines.append(f"        {C.yellow('~')} {field:<40} {sv} {C.dim('->')} {tv}")
                    else:
                        lines.append(f"        {C.yellow('~')} {field}")
                        lines.append(f"            {C.dim(from_label + ':')} {sv}")
                        lines.append(f"            {C.dim(to_label + ':')} {tv}")

            if added:
                if entity_key != "(realm-level)":
                    lines.append(C.green(f"      Only in {to_label}:"))
                for p, s, t in added:
                    field = _get_field(p) or p
                    tv = _fmt_val(t, p)
                    lines.append(f"        {C.green('+')} {field:<40} {tv}")

            if removed:
                if entity_key != "(realm-level)":
                    lines.append(C.red(f"      Only in {from_label}:"))
                for p, s, t in removed:
                    field = _get_field(p) or p
                    sv = _fmt_val(s, p)
                    lines.append(f"        {C.red('-')} {field:<40} {sv}")

        lines.append("")

    return "\n".join(lines)


# --- Apply ---

def generate_apply(diffs, source_data, target_data, realm, config_path, mount_dir):
    """Generate kcadm.sh commands to bring target in sync with source."""
    commands = []
    docker_config = config_path.replace(mount_dir, "/home")
    kcadm = KCADM_DOCKER.format(mount=mount_dir) + f" --config {docker_config}"

    # Collect realm-level scalar changes
    realm_updates = {}
    # Collect entity-level changes
    entity_changes = {}  # {entity_type: {key: {action, data}}}

    for path, src, tgt in diffs:
        parts = path.split(".")

        # Skip internal/enriched fields
        if any(p.startswith("_") for p in parts):
            _handle_enriched_field(path, src, tgt, commands, kcadm, realm,
                                   source_data, target_data)
            continue

        top = parts[0].split("[")[0]

        if top in ("clients", "clientScopes", "identityProviders",
                    "identityProviderMappers", "authenticationFlows",
                    "authenticatorConfig", "requiredActions"):
            _collect_entity_change(path, src, tgt, entity_changes)
        elif top == "roles":
            _collect_entity_change(path, src, tgt, entity_changes)
        elif "[" not in parts[0]:
            # Top-level realm scalar
            realm_updates[parts[0]] = src

    # Generate realm update command
    if realm_updates:
        sets = " ".join(f"-s '{k}={json.dumps(v)}'" if isinstance(v, (dict, list, bool))
                        else f"-s {k}={v}"
                        for k, v in realm_updates.items())
        commands.append({
            "description": f"Update realm '{realm}' settings ({len(realm_updates)} fields)",
            "command": f"{kcadm} update realms/{realm} -r {realm} {sets}",
            "risk": "low",
        })

    # Generate partialImport for entity additions/overwrites
    import_entities = _build_partial_import(entity_changes, source_data)
    if import_entities:
        commands.append({
            "description": f"Partial import: create/overwrite changed entities",
            "command": f"# Save the following JSON to a file, then run:\n"
                       f"# {kcadm} create realms/{realm}/partialImport -r {realm} "
                       f"-s ifResourceExists=OVERWRITE -f <file.json>",
            "risk": "medium",
            "data": import_entities,
        })

    # Generate delete commands for entities only in target
    for path, src, tgt in diffs:
        if src == "<MISSING>" and tgt == "<EXISTS>":
            del_cmd = _generate_delete(path, target_data, kcadm, realm)
            if del_cmd:
                commands.append(del_cmd)

    return commands


def _handle_enriched_field(path, src, tgt, commands, kcadm, realm,
                           source_data, target_data):
    """Handle changes to enriched fields (_realmDefaultScopes, _defaultClientScopes, etc.)."""
    if path.startswith("_realmDefaultScopes"):
        if isinstance(src, list) and src is not None:
            # Scopes only in source — need to add to target
            for scope_name in src:
                scope_id = _find_scope_id(scope_name, source_data)
                if scope_id:
                    commands.append({
                        "description": f"Add realm default scope: {scope_name}",
                        "command": f"{kcadm} update realms/{realm}/default-default-client-scopes/{scope_id} -r {realm}",
                        "risk": "medium",
                    })
        if isinstance(tgt, list) and tgt is not None:
            # Scopes only in target — need to remove
            for scope_name in tgt:
                scope_id = _find_scope_id(scope_name, target_data)
                if scope_id:
                    commands.append({
                        "description": f"Remove realm default scope: {scope_name}",
                        "command": f"{kcadm} delete realms/{realm}/default-default-client-scopes/{scope_id} -r {realm}",
                        "risk": "high",
                    })

    elif path.startswith("_realmOptionalScopes"):
        if isinstance(src, list) and src is not None:
            for scope_name in src:
                scope_id = _find_scope_id(scope_name, source_data)
                if scope_id:
                    commands.append({
                        "description": f"Add realm optional scope: {scope_name}",
                        "command": f"{kcadm} update realms/{realm}/default-optional-client-scopes/{scope_id} -r {realm}",
                        "risk": "medium",
                    })
        if isinstance(tgt, list) and tgt is not None:
            for scope_name in tgt:
                scope_id = _find_scope_id(scope_name, target_data)
                if scope_id:
                    commands.append({
                        "description": f"Remove realm optional scope: {scope_name}",
                        "command": f"{kcadm} delete realms/{realm}/default-optional-client-scopes/{scope_id} -r {realm}",
                        "risk": "high",
                    })


def _find_scope_id(name, realm_data):
    """Find client scope ID by name in realm data."""
    for scope in realm_data.get("clientScopes", []):
        if scope.get("name") == name:
            return scope.get("id")
    return None


def _collect_entity_change(path, src, tgt, changes):
    """Collect entity-level changes for batching."""
    parts = path.split(".")
    top = parts[0]
    # Extract entity key from path like "clients[clientId=recarga].enabled"
    if "[" in top:
        entity_type = top.split("[")[0]
        key_match = top.split("[")[1].rstrip("]")
    else:
        entity_type = top
        key_match = None

    if entity_type not in changes:
        changes[entity_type] = {}
    if key_match:
        if key_match not in changes[entity_type]:
            changes[entity_type][key_match] = []
        changes[entity_type][key_match].append((path, src, tgt))


def _build_partial_import(entity_changes, source_data):
    """Build a partial import JSON from entity changes."""
    import_data = {}

    for entity_type, keyed_changes in entity_changes.items():
        for key_match, changes in keyed_changes.items():
            # Check if this is a new entity or modification
            has_addition = any(src == "<EXISTS>" or src != "<MISSING>" for _, src, _ in changes)
            if has_addition and entity_type in ("clients", "clientScopes",
                                                 "identityProviders", "roles"):
                # Find the full entity in source data
                source_list = source_data.get(entity_type, [])
                if isinstance(source_list, list):
                    for item in source_list:
                        # Match by key
                        if f"{_find_match_key([item]) or 'name'}={item.get(_find_match_key([item]) or 'name', '')}" == key_match:
                            if entity_type not in import_data:
                                import_data[entity_type] = []
                            import_data[entity_type].append(item)
                            break

    return import_data if import_data else None


def _generate_delete(path, target_data, kcadm, realm):
    """Generate a delete command for an entity only in target."""
    parts = path.split("[")
    if len(parts) < 2:
        return None

    entity_type = parts[0]
    key_match = parts[1].rstrip("]")

    # Map entity type to API path
    api_paths = {
        "clients": "clients",
        "clientScopes": "client-scopes",
        "identityProviders": "identity-provider/instances",
        "authenticationFlows": "authentication/flows",
    }

    api_path = api_paths.get(entity_type)
    if not api_path:
        return None

    # Find the entity ID in target data
    key_field, key_val = key_match.split("=", 1)
    target_list = target_data.get(entity_type, [])
    entity_id = None
    for item in target_list:
        if item.get(key_field) == key_val:
            entity_id = item.get("id")
            break

    if entity_id:
        return {
            "description": f"DELETE {entity_type}: {key_val} (only in target)",
            "command": f"{kcadm} delete {api_path}/{entity_id} -r {realm}",
            "risk": "high",
        }
    return None


def format_apply(commands):
    """Format apply commands for human reading."""
    if not commands:
        return "No changes to apply."

    lines = [
        "# KC Config Promotion — Apply Commands",
        f"# Generated commands: {len(commands)}",
        "",
    ]

    for i, cmd in enumerate(commands, 1):
        risk_icon = {"low": "[LOW]", "medium": "[MED]", "high": "[HIGH]"}
        lines.append(f"# --- Step {i}: {cmd['description']} {risk_icon.get(cmd['risk'], '')}")

        if "data" in cmd:
            lines.append(f"# Partial import data:")
            lines.append(f"# {json.dumps(cmd['data'], indent=2)[:500]}")

        lines.append(cmd["command"])
        lines.append("")

    return "\n".join(lines)


# --- CLI ---

def cmd_snapshot(args):
    mount_dir = args.mount or os.path.dirname(os.path.abspath(args.config))
    docker_network = getattr(args, 'docker_network', None)
    data = snapshot(args.config, args.realm, mount_dir, docker_network=docker_network)
    normalized = normalize(data)

    # Add metadata
    normalized["_meta"] = {
        "realm": args.realm,
        "server": "extracted-from-config",
        "tool": "kc-promote",
        "version": "0.1.0",
    }

    output = json.dumps(normalized, indent=2, sort_keys=False)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Snapshot saved to {args.output}", file=sys.stderr)
    else:
        print(output)


def cmd_diff(args):
    with open(args.from_snap) as f:
        from_data = json.load(f)
    with open(args.to_snap) as f:
        to_data = json.load(f)

    from_meta = from_data.pop("_meta", {})
    to_meta = to_data.pop("_meta", {})

    diffs = diff_values(from_data, to_data)

    # Apply filter
    filters = parse_filter(getattr(args, "filter", None))
    if filters:
        diffs = filter_diffs(diffs, filters)

    # Header
    from_label = os.path.basename(args.from_snap).replace("-snapshot.json", "").upper()
    to_label = os.path.basename(args.to_snap).replace("-snapshot.json", "").upper()
    realm = from_meta.get("realm", to_meta.get("realm", "?"))
    filter_note = f"  (filter: {args.filter})" if getattr(args, "filter", None) else ""
    print(C.bold(f"\n  Realm: {realm}   {from_label} -> {to_label}{filter_note}"))

    detail = getattr(args, "detail", "normal")
    print(format_diff(diffs, detail=detail, from_label=from_label, to_label=to_label))


def cmd_apply(args):
    with open(args.source) as f:
        source_raw = json.load(f)
    with open(args.target) as f:
        target_raw = json.load(f)

    source = deepcopy(source_raw)
    target = deepcopy(target_raw)

    realm = source.get("_meta", {}).get("realm", args.realm or "recarga")
    source.pop("_meta", None)
    target.pop("_meta", None)

    diffs = diff_values(source, target)

    # Apply filter
    filters = parse_filter(getattr(args, "filter", None))
    if filters:
        diffs = filter_diffs(diffs, filters)

    mount_dir = args.mount or os.path.dirname(os.path.abspath(args.config))
    commands = generate_apply(diffs, source_raw, target_raw, realm, args.config, mount_dir)
    print(format_apply(commands))


def cmd_api_snapshot(args):
    """Take snapshot via REST API (no docker/kcadm)."""
    env_name = args.env.lower()
    if env_name in ENVS:
        env_cfg = ENVS[env_name]
    else:
        # Custom env: require --server, --client-id, --client-secret
        if not all([args.server, args.client_id, args.client_secret]):
            print("For custom envs, provide --server, --client-id, --client-secret",
                  file=sys.stderr)
            sys.exit(1)
        env_cfg = {
            "server": args.server,
            "realm": args.realm or "recarga",
            "client_id": args.client_id,
            "client_secret": args.client_secret,
            "proxy": args.proxy,
        }

    data = api_snapshot(env_cfg)
    normalized = normalize(data)

    normalized["_meta"] = {
        "realm": env_cfg.get("realm", "recarga"),
        "server": env_cfg["server"],
        "env": env_name,
        "tool": "kc-promote",
        "version": "0.2.0",
    }

    output = json.dumps(normalized, indent=2, sort_keys=False)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Snapshot saved to {args.output}", file=sys.stderr)
    else:
        print(output)


def main():
    parser = argparse.ArgumentParser(
        description="Keycloak config promotion tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # snapshot
    p_snap = sub.add_parser("snapshot", help="Export and normalize realm config")
    p_snap.add_argument("--config", required=True, help="Path to kcadm config file")
    p_snap.add_argument("--realm", required=True, help="Realm name")
    p_snap.add_argument("--output", "-o", help="Output file (default: stdout)")
    p_snap.add_argument("--mount", help="Docker mount dir (default: config file dir)")
    p_snap.add_argument("--docker-network", help="Docker network to join (for local KC)")

    # diff
    p_diff = sub.add_parser("diff", help="Compare two realm snapshots")
    p_diff.add_argument("--from", dest="from_snap", required=True, help="First environment snapshot")
    p_diff.add_argument("--to", dest="to_snap", required=True, help="Second environment snapshot")
    p_diff.add_argument("--detail", choices=["summary", "normal", "full"],
                        default="normal", help="Detail level (default: normal)")
    p_diff.add_argument("--filter", help="Filter diffs: clients/recarga,clients/service,roles")

    # apply
    p_apply = sub.add_parser("apply", help="Generate kcadm.sh commands to sync target to source")
    p_apply.add_argument("--source", required=True, help="Source snapshot (promote FROM)")
    p_apply.add_argument("--target", required=True, help="Target snapshot (promote TO)")
    p_apply.add_argument("--config", required=True, help="Path to TARGET kcadm config")
    p_apply.add_argument("--realm", help="Override realm name")
    p_apply.add_argument("--mount", help="Docker mount dir")
    p_apply.add_argument("--filter", help="Filter diffs: clients/recarga,clients/service")

    # api-snapshot
    p_api = sub.add_parser("api-snapshot", help="Export realm via REST API (no docker needed)")
    p_api.add_argument("--env", required=True, help="Environment: dev|qa|prod|local or custom")
    p_api.add_argument("--output", "-o", help="Output file (default: stdout)")
    p_api.add_argument("--server", help="KC server URL (for custom env)")
    p_api.add_argument("--realm", default="recarga", help="Realm name")
    p_api.add_argument("--client-id", help="Client ID (for custom env)")
    p_api.add_argument("--client-secret", help="Client secret (for custom env)")
    p_api.add_argument("--proxy", help="SOCKS proxy URL (for custom env)")

    args = parser.parse_args()

    if args.command == "snapshot":
        cmd_snapshot(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "apply":
        cmd_apply(args)
    elif args.command == "api-snapshot":
        cmd_api_snapshot(args)


if __name__ == "__main__":
    main()
