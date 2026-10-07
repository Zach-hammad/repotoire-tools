#!/usr/bin/env python3
"""Manual inventory and bounded read-only observations.

Observation JSON is coordinator-custody evidence, not a cryptographic attestation.
Protect its path and obtain a fresh check after any config change.
"""

import argparse
import fcntl
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

MAX_CONFIG_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 32 * 1024
TIMEOUT_SECONDS = 3
MODEL_ID = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
ROLE_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
EXEC_KINDS = {"codex_native", "codex_cli", "claude_cli", "local_http", "api", "grok_cli"}


class ConfigError(ValueError):
    """A sanitized configuration or observation error."""


def _need(condition, code):
    if not condition:
        raise ConfigError(code)


def _keys(value, expected, code):
    _need(type(value) is dict and set(value) == set(expected), code)


def _validate_config(config):
    _keys(config, ("schema_version", "models", "preferences"), "invalid_config_shape")
    _need(type(config["schema_version"]) is int and config["schema_version"] == 1,
          "unsupported_schema_version")
    models = config["models"]
    _need(type(models) is list and len(models) <= 128, "invalid_models")
    by_id = {}
    for model in models:
        _need(type(model) is dict, "invalid_model")
        _keys(model, ("id", "provider", "pool_alias", "execution", "billing_policy", "enabled", "roles"),
              "invalid_model_shape")
        mid = model["id"]
        _need(type(mid) is str and MODEL_ID.fullmatch(mid), "invalid_model_id")
        _need(mid not in by_id, "duplicate_model_id")
        _need(model["provider"] in ("openai", "anthropic", "xai", "local"),
              "invalid_provider")
        _need(type(model["pool_alias"]) is str and ROLE_ID.fullmatch(model["pool_alias"]),
              "invalid_pool_alias")
        ex = model["execution"]
        _need(type(ex) is dict and type(ex.get("kind")) is str, "invalid_execution")
        kind = ex["kind"]
        _need(kind in EXEC_KINDS, "unsupported_execution_kind")
        expected_provider = ("openai" if kind in ("codex_native", "codex_cli") else
                             "anthropic" if kind == "claude_cli" else
                             "local" if kind == "local_http" else
                             "xai" if kind == "grok_cli" else model["provider"])
        _need(model["provider"] == expected_provider, "provider_execution_mismatch")
        _keys(ex, ("kind", "executable") if kind in ("codex_cli", "claude_cli") or
              (kind == "grok_cli" and (model["enabled"] or "executable" in ex)) else
              (("kind", "url") if kind == "local_http" else ("kind",)), "invalid_execution_shape")
        if kind in ("codex_cli", "claude_cli", "grok_cli") and "executable" in ex:
            executable = ex["executable"]
            expected_name = {"codex_cli":"codex", "claude_cli":"claude", "grok_cli":"grok"}[kind]
            _need(type(executable) is str and os.path.isabs(executable) and
                  Path(executable).name == expected_name and "\x00" not in executable,
                  "invalid_executable")
        if kind == "local_http":
            parts = urlsplit(ex["url"] if type(ex["url"]) is str else "")
            _need(parts.scheme == "http" and parts.username is None and parts.password is None
                  and parts.path in ("", "/") and parts.query == "" and parts.fragment == ""
                  and parts.hostname in ("localhost", "127.0.0.1", "::1")
                  and (parts.port is None or 1 <= parts.port <= 65535), "invalid_local_endpoint")
        _need(model["billing_policy"] in ("subscription_only", "local_only", "unsupported_pending"),
              "invalid_billing_policy")
        _need(type(model["enabled"]) is bool, "invalid_enabled")
        roles = model["roles"]
        _need(type(roles) is list and all(type(r) is str and ROLE_ID.fullmatch(r) for r in roles),
              "invalid_roles")
        _need(len(set(roles)) == len(roles), "invalid_roles")
        _need(not (model["enabled"] and (kind == "api" or
              model["billing_policy"] == "unsupported_pending")), "unsupported_model_must_be_disabled")
        by_id[mid] = model
    prefs = config["preferences"]
    _need(type(prefs) is dict and len(prefs) <= 64, "invalid_preferences")
    for role, ids in prefs.items():
        _need(type(role) is str and ROLE_ID.fullmatch(role), "invalid_preference_role")
        _need(type(ids) is list and all(type(mid) is str for mid in ids), "invalid_preferences")
        _need(len(set(ids)) == len(ids), "invalid_preferences")
        for mid in ids:
            _need(type(mid) is str and mid in by_id and role in by_id[mid]["roles"],
                  "preference_not_declared_for_role")
    return by_id


def load_config(path):
    """Read a private, bounded JSON config and return it with the byte hash."""
    try:
        raw = _read_private(path, "unsafe_config_permissions", "config_too_large")
        config = json.loads(raw.decode("utf-8"))
        _validate_config(config)
        return config, hashlib.sha256(raw).hexdigest()
    except ConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ConfigError("config_unavailable_or_invalid") from None


def _read_private(path, unsafe_code, large_code):
    """Validate and read from the same non-symlink file descriptor."""
    _need(hasattr(os, "O_NOFOLLOW"), "private_file_open_unsupported")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              info.st_mode & 0o077 == 0, unsafe_code)
        _need(info.st_size <= MAX_CONFIG_BYTES, large_code)
        raw = handle.read(MAX_CONFIG_BYTES + 1)
    _need(len(raw) <= MAX_CONFIG_BYTES, large_code)
    return raw


def save_config(path, config, expected_hash):
    """Atomically save a validated private config if its current hash matches."""
    _need(type(expected_hash) is str and re.fullmatch(r"[0-9a-f]{64}", expected_hash),
          "invalid_config_hash")
    try:
        _validate_config(config)
        raw = json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        target = Path(path)
    except ConfigError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ConfigError("invalid_config") from None
    _need(len(raw) <= MAX_CONFIG_BYTES, "config_too_large")

    parent = target.parent
    temp_path = None
    try:
        parent_info = os.lstat(parent)
        _need(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid() and
              parent_info.st_mode & 0o077 == 0, "unsafe_config_permissions")
        _need(hasattr(os, "O_NOFOLLOW"), "private_file_open_unsupported")
        lock_path = parent / (target.name + ".lock")
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            _need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == os.getuid() and
                  lock_info.st_mode & 0o077 == 0, "unsafe_config_permissions")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigError("config_busy") from None
            current = _read_private(target, "unsafe_config_permissions", "config_too_large")
            _need(hashlib.sha256(current).hexdigest() == expected_hash, "stale_config")
            fd, temp_name = tempfile.mkstemp(prefix="." + target.name + ".", suffix=".tmp", dir=parent)
            temp_path = Path(temp_name)
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, target)
            temp_path = None
            return hashlib.sha256(raw).hexdigest()
        finally:
            os.close(lock_fd)
    except ConfigError:
        raise
    except (OSError, ValueError, TypeError):
        raise ConfigError("config_save_failed") from None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def _probe_cli(executable, args, kind):
    try:
        info = os.stat(executable)
        if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
            return "unknown", "unavailable"
        # Read a single bounded stream while the child runs. Some Codex builds
        # report login status on stderr; neither stream is ever logged.
        process = subprocess.Popen([executable, *args], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   shell=False, start_new_session=True)
        output = bytearray()
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return "unknown", "unavailable"
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), min(4096, MAX_OUTPUT_BYTES + 1 - len(output)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_OUTPUT_BYTES:
                                return "unknown", "unavailable"
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                return "unknown", "unavailable"
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
            process.stdout.close()
        if len(output) > MAX_OUTPUT_BYTES:
            return "unknown", "unavailable"
        out = output.decode("utf-8", "strict")
        if kind == "codex_cli":
            logged_in = bool(re.search(r"(?i)\blogged in\b", out)) and not bool(
                re.search(r"(?i)\bnot logged in\b", out))
        else:
            data = json.loads(out)
            logged_in = (type(data) is dict and data.get("loggedIn") is True and
                         data.get("authMethod") in ("oauth", "api_key", "claudeai"))
        return ("ready", "auth_observed") if logged_in else ("unavailable", "auth_not_observed")
    except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError, ValueError):
        return "unknown", "unavailable"


def _probe_local(url, model_id):
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or 80
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT_SECONDS)
        conn.request("GET", "/api/v1/models", headers={"Accept": "application/json"})
        response = conn.getresponse()
        if response.status != 200:
            return "unknown", "runtime_unavailable"
        raw = response.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            return "unknown", "runtime_unavailable"
        data = json.loads(raw.decode("utf-8"))
        # Runtime readiness requires the documented models envelope and a matching loaded LLM.
        entries = data.get("models") if type(data) is dict else None
        if type(entries) is not list:
            return "unknown", "runtime_unavailable"
        for item in entries:
            loaded = item.get("loaded_instances") if type(item) is dict else None
            if (type(item) is dict and item.get("type") == "llm" and item.get("key") == model_id
                    and type(loaded) is list and any(
                        type(instance) is dict and type(instance.get("id")) is str and
                        bool(instance["id"]) and type(instance.get("config")) is dict and
                        type(instance["config"].get("context_length")) is int and
                        instance["config"]["context_length"] > 0 for instance in loaded)):
                return "ready", "loaded_model_observed"
        return "unavailable", "model_not_loaded"
    except (OSError, socket.timeout, UnicodeError, json.JSONDecodeError, ValueError):
        return "unknown", "runtime_unavailable"
    finally:
        if conn is not None:
            conn.close()


def check_config(config, config_sha256, *, now=None, host_observation=None):
    """Probe only configured read-only adapters and return a redacted receipt."""
    by_id = _validate_config(config)
    _need(type(config_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", config_sha256),
          "invalid_config_hash")
    observed = now or datetime.now(timezone.utc)
    _need(observed.tzinfo is not None, "invalid_observation_time")
    host_rows = {}
    if host_observation is not None:
        _keys(host_observation, ("schema_version", "source", "observed_at", "models"),
              "invalid_host_observation")
        _need(host_observation["schema_version"] == 1 and host_observation["source"] == "codex_app",
              "invalid_host_observation")
        try:
            host_time = datetime.fromisoformat(host_observation["observed_at"].replace("Z", "+00:00"))
        except (TypeError, ValueError, AttributeError):
            raise ConfigError("invalid_host_observation_time") from None
        _need(host_time.tzinfo is not None and -5 <= (observed - host_time.astimezone(timezone.utc)).total_seconds() <= 300,
              "stale_host_observation")
        host_rows = host_observation["models"]
        _need(type(host_rows) is dict and set(host_rows) <= set(by_id), "host_model_mismatch")
        for mid, row in host_rows.items():
            _keys(row, ("provider", "pool_alias", "execution_kind", "auth_observed",
                        "runtime_capability"), "invalid_host_model_observation")
            _need(by_id[mid]["execution"]["kind"] == "codex_native" and
                  row["provider"] == by_id[mid]["provider"] == "openai" and
                  row["pool_alias"] == by_id[mid]["pool_alias"] and
                  row["execution_kind"] == "codex_native" and
                  row["auth_observed"] in ("ready", "unknown") and
                  row["runtime_capability"] in ("ready", "unknown"), "invalid_host_model_observation")
    records = {}
    for mid, model in by_id.items():
        kind = model["execution"]["kind"]
        auth, runtime, reason = "unknown", "unknown", "pending"
        grok_billing, quota = None, "unknown"
        if not model["enabled"]:
            reason = "disabled"
        elif kind == "codex_cli":
            auth, reason = _probe_cli(model["execution"]["executable"], ["login", "status"], kind)
        elif kind == "claude_cli":
            auth, reason = _probe_cli(model["execution"]["executable"], ["auth", "status", "--json"], kind)
        elif kind == "grok_cli":
            import grok_connection
            try:
                status, listed = grok_connection.probe(model["execution"]["executable"], mid)
            except (OSError, ValueError):
                status, listed = "unknown", False
            auth = "ready" if status == "session" else "unavailable" if status == "signed_out" else "unknown"
            reason = ("grok_catalog_observed" if status == "session" and listed else
                      "grok_model_unavailable" if status == "session" else
                      "grok_auth_required" if status == "signed_out" else "grok_access_unconfirmed")
            if status == "session" and listed:
                grok_billing, reason = grok_connection.observe_billing(model["execution"]["executable"])
                if grok_billing is not None:
                    quota = grok_connection.billing_quota(grok_billing, observed)
        elif kind == "local_http":
            runtime, reason = _probe_local(model["execution"]["url"], mid)
        elif kind == "codex_native":
            reason = "host_observation_required"
            host_row = host_rows.get(mid)
            if host_row is not None:
                auth, runtime = host_row["auth_observed"], host_row["runtime_capability"]
                reason = "host_observation"
        records[mid] = {"auth_observed": auth, "runtime_capability": runtime,
                        "billing_status": "unknown", "quota": quota,
                        "model_inference": "unknown", "host_observation": mid in host_rows,
                        "reason": reason}
        if grok_billing is not None:
            records[mid]["grok_billing"] = grok_billing
    return {"schema_version": 1, "config_sha256": config_sha256,
            "observed_at": observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "models": records}


def validate_observation(config, config_sha256, observation, now=None, max_age_seconds=300):
    """Validate hash, shape, and freshness; return per-model routing readiness."""
    by_id = _validate_config(config)
    _need(type(config_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", config_sha256),
          "invalid_config_hash")
    _keys(observation, ("schema_version", "config_sha256", "observed_at", "models"),
          "invalid_observation")
    _need(observation["schema_version"] == 1 and observation["config_sha256"] == config_sha256,
          "config_hash_mismatch")
    _need(type(max_age_seconds) is int and 1 <= max_age_seconds <= 3600, "invalid_max_age")
    try:
        stamp = datetime.fromisoformat(observation["observed_at"].replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        raise ConfigError("invalid_observation_time") from None
    _need(stamp.tzinfo is not None, "invalid_observation_time")
    current = now or datetime.now(timezone.utc)
    age = (current - stamp.astimezone(timezone.utc)).total_seconds()
    _need(-5 <= age <= max_age_seconds, "stale_or_future_observation")
    records = observation["models"]
    _need(type(records) is dict and set(records) == set(by_id), "observation_model_mismatch")
    result = {}
    for mid, model in by_id.items():
        record = records[mid]
        fields = ("auth_observed", "runtime_capability", "billing_status", "quota",
                  "model_inference", "host_observation", "reason")
        has_billing = type(record) is dict and "grok_billing" in record
        has_billing_time = type(record) is dict and "grok_billing_observed_at" in record
        _keys(record, fields + (("grok_billing",) if has_billing else ()) +
              (("grok_billing_observed_at",) if has_billing_time else ()), "invalid_model_observation")
        _need(not has_billing_time or has_billing, "invalid_grok_billing_binding")
        _need(all(type(record[k]) is str for k in fields if k != "host_observation") and
              type(record["host_observation"]) is bool, "invalid_model_observation")
        _need(record["auth_observed"] in ("ready", "unavailable", "unknown") and
              record["runtime_capability"] in ("ready", "unavailable", "unknown") and
              record["billing_status"] in ("ready", "conflict", "unknown") and
              record["quota"] in ("ready", "exhausted", "unknown") and
              record["model_inference"] in ("ready", "unavailable", "unknown"),
              "invalid_model_observation")
        kind = model["execution"]["kind"]
        _need(not record["host_observation"] or kind == "codex_native", "invalid_host_evidence_binding")
        expected_grok_quota = "unknown"
        if has_billing:
            import grok_connection
            _need(kind == "grok_cli" and record["auth_observed"] == "ready" and
                  record["reason"] in ("grok_billing_observed", "bounded_grok_cli_smoke"),
                  "invalid_grok_billing_binding")
            try:
                normalized = grok_connection.normalize_billing(record["grok_billing"])
            except (TypeError, ValueError):
                raise ConfigError("invalid_grok_billing") from None
            _need(normalized == record["grok_billing"], "invalid_grok_billing")
            billing_stamp = stamp
            if has_billing_time:
                try:
                    billing_stamp = datetime.fromisoformat(record["grok_billing_observed_at"].replace("Z", "+00:00"))
                except (TypeError, ValueError, AttributeError):
                    raise ConfigError("invalid_grok_billing_time") from None
                _need(billing_stamp.tzinfo is not None, "invalid_grok_billing_time")
                _need(stamp <= billing_stamp and
                      -5 <= (current - billing_stamp).total_seconds() <= max_age_seconds,
                      "stale_or_future_billing_observation")
            expected_grok_quota = grok_connection.billing_quota(normalized, billing_stamp)
            _need(expected_grok_quota == grok_connection.billing_quota(normalized, current),
                  "expired_grok_billing_period")
        grok_smoke = (kind == "grok_cli" and
                      record["reason"] == "bounded_grok_cli_smoke" and
                      all(record[k] == "ready" for k in ("auth_observed", "runtime_capability",
                          "billing_status", "model_inference")) and record["quota"] == expected_grok_quota)
        _need(kind != "grok_cli" or grok_smoke or (record["runtime_capability"] == "unknown" and
              record["billing_status"] == "unknown" and record["quota"] == expected_grok_quota and
              record["model_inference"] == "unknown"), "unverified_grok_runtime")
        cli_smoke = (kind == "codex_cli" and record["reason"] == "bounded_codex_cli_smoke" and
                     record["auth_observed"] == "ready" and record["billing_status"] == "ready" and
                     record["model_inference"] == "ready")
        _need(kind not in ("codex_cli", "claude_cli") or record["runtime_capability"] == "unknown" or
              cli_smoke, "unverified_cli_runtime")
        _need(kind != "codex_native" or record["auth_observed"] != "ready" or
              record["host_observation"], "invalid_host_evidence_binding")
        _need(kind != "codex_native" or record["runtime_capability"] != "ready" or
              record["host_observation"], "unverified_native_runtime")
        _need(kind != "local_http" or record["auth_observed"] == "unknown",
              "local_auth_must_remain_unknown")
        selected = model["enabled"] and any(mid in ids for ids in config["preferences"].values())
        authenticated = (record["auth_observed"] == "ready" if kind != "local_http" else True)
        runtime_ok = record["runtime_capability"] == "ready"
        # Local HTTP uses its loaded model as the runtime check; CLI auth remains separate.
        if model["execution"]["kind"] == "local_http":
            authenticated = True
        expected_billing = "local_only" if model["execution"]["kind"] == "local_http" else "subscription_only"
        billing_ok = model["billing_policy"] == expected_billing
        observed_conflict = (record["billing_status"] == "conflict" or
                             record["quota"] == "exhausted" or
                             record["model_inference"] == "unavailable")
        ready = bool(model["enabled"] and selected and authenticated and runtime_ok and
                     billing_ok and not observed_conflict)
        reasons = []
        if not model["enabled"]: reasons.append("disabled")
        if not selected: reasons.append("not_selected")
        if not authenticated: reasons.append("authentication_unconfirmed")
        if not runtime_ok: reasons.append("runtime_unconfirmed")
        if not billing_ok: reasons.append("billing_policy_conflict")
        if record["billing_status"] == "conflict": reasons.append("billing_conflict_observed")
        if record["quota"] == "exhausted": reasons.append("quota_exhausted_observed")
        if record["model_inference"] == "unavailable": reasons.append("inference_unavailable_observed")
        if record["quota"] != "ready": reasons.append("quota_unconfirmed")
        if record["model_inference"] != "ready": reasons.append("inference_unproven")
        result[mid] = {"enabled": model["enabled"], "selected": selected,
                       "execution_kind": model["execution"]["kind"],
                       "provider": model["provider"], "pool_alias": model["pool_alias"],
                       "billing_policy": model["billing_policy"],
                       "role_selected": [role for role, ids in config["preferences"].items() if mid in ids],
                       "auth_observed": record["auth_observed"],
                       "runtime_capability": record["runtime_capability"],
                       "billing_status": record["billing_status"], "quota": record["quota"],
                       "model_inference": record["model_inference"], "ready": ready,
                       "reasons": reasons}
    return result


def merge_response_observation(config, digest, observation, response, *, now=None):
    """Reuse fresh response rows without replacing unrelated or negative evidence."""
    from copy import deepcopy
    current = now or datetime.now(timezone.utc)
    validate_observation(config, digest, observation, now=current)
    readiness = validate_observation(config, digest, response, now=current)
    merged = deepcopy(observation)
    adopted = []
    for mid, ready in readiness.items():
        if not ready["ready"] or ready["model_inference"] != "ready":
            continue
        previous = observation["models"][mid]
        _need(not any(previous[key] == value for key, value in (
            ("auth_observed", "unavailable"), ("runtime_capability", "unavailable"),
            ("billing_status", "conflict"), ("quota", "exhausted"),
            ("model_inference", "unavailable"))), "conflicting_response_observation")
        _need(previous["reason"] != "grok_model_unavailable", "conflicting_response_observation")
        if ready["execution_kind"] in ("local_http", "codex_native"):
            _need(previous["runtime_capability"] == "ready", "current_runtime_unconfirmed")
        if ready["execution_kind"] != "local_http":
            _need(previous["auth_observed"] == "ready", "current_authentication_unconfirmed")
        adopted_row = deepcopy(response["models"][mid])
        if ready["execution_kind"] == "grok_cli":
            # A past response proves inference; the current check owns account quota.
            adopted_row.pop("grok_billing", None)
            adopted_row.pop("grok_billing_observed_at", None)
            adopted_row["quota"] = previous["quota"]
            if "grok_billing" in previous:
                adopted_row["grok_billing"] = deepcopy(previous["grok_billing"])
                adopted_row["grok_billing_observed_at"] = previous.get(
                    "grok_billing_observed_at", observation["observed_at"])
        merged["models"][mid] = adopted_row
        adopted.append(mid)
    _need(bool(adopted), "no_ready_response_observation")
    # Parse before comparing: equivalent instants can have different UTC offsets.
    merged["observed_at"] = min(observation["observed_at"], response["observed_at"],
        key=lambda stamp: datetime.fromisoformat(stamp.replace("Z", "+00:00")))
    for mid, row in merged["models"].items():
        if "grok_billing" in row:
            row.setdefault("grok_billing_observed_at", observation["observed_at"])
    validate_observation(config, digest, merged, now=current)
    return merged


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--config", required=True)
    check.add_argument("--host-observation")
    check.add_argument("--response-observation", action="append", default=[],
                       help="Fresh raw response observation, or ready connection receipt; repeat per model")
    args = parser.parse_args(argv)
    try:
        config, digest = load_config(args.config)
        host = None
        if args.host_observation:
            host, _ = load_json_file(args.host_observation, "host_observation_unavailable")
        observation = check_config(config, digest, host_observation=host)
        for path in args.response_observation:
            response, _ = load_json_file(path, "response_observation_unavailable")
            if isinstance(response, dict) and "observation" in response:
                _need(response.get("state") == "ready", "response_not_ready")
                response = response["observation"]
            observation = merge_response_observation(config, digest, observation, response)
        validate_observation(config, digest, observation)
        print(json.dumps(observation, sort_keys=True, separators=(",", ":")))
        return 0
    except ConfigError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


def load_json_file(path, error_code):
    try:
        raw = _read_private(path, "unsafe_observation_permissions", "observation_too_large")
        return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()
    except ConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ConfigError(error_code) from None


if __name__ == "__main__":
    raise SystemExit(main())
