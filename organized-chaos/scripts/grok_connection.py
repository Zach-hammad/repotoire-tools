"""Grok discovery, explicit bounded response testing, and read-only billing."""
import re
import tempfile


def probe(executable, model_id, *, cancel=None, launch_guard=None):
    # Reuse the bounded process owner: sanitized env, capped output, cancellation,
    # process-group teardown. Import here to avoid onboarding's import cycle.
    from codex_connection import _run, PROBE_SECONDS
    with tempfile.TemporaryDirectory(prefix="grok-connect-") as empty:
        result, error, code = _run(executable, ["-m", model_id, "models"], timeout=PROBE_SECONDS,
                                  cwd=empty, cancel=cancel, launch_guard=launch_guard)
    if error or code != 0:
        return "unknown", False
    try:
        lines = result[0].decode("utf-8", "strict").splitlines()
    except UnicodeError:
        return "unknown", False
    if not lines:
        return "unknown", False
    banner = lines[0]
    if banner == "You are not authenticated.":
        auth = "signed_out"
    elif banner in ("You are logged in with grok.com.", "You are logged in with auth.x.ai."):
        auth = "session"
    elif (banner in ("You are using XAI_API_KEY.", "You are authenticated via deployment key.")
          or re.fullmatch(r"Model '[^\r\n]+' is using its own API key\.", banner)):
        auth = "non_subscription"
    else:
        auth = "unknown"
    # An exact catalog row is discovery, not evidence that inference succeeds.
    try:
        rows = lines[lines.index("Available models:") + 1:]
    except ValueError:
        rows = []
    listed = any(row in (f"  - {model_id}", f"  * {model_id} (default)") for row in rows)
    return auth, listed


def connect(executable, model_id, *, cancel=None, launch_guard=None):
    from codex_connection import _run, LOGIN_SECONDS
    auth, listed = probe(executable, model_id, cancel=cancel, launch_guard=launch_guard)
    if cancel is not None and cancel.is_set():
        return "cancelled"
    if auth == "signed_out":
        with tempfile.TemporaryDirectory(prefix="grok-login-") as empty:
            _, error, _ = _run(executable, ["login", "--oauth"], timeout=LOGIN_SECONDS,
                               cwd=empty, cancel=cancel, launch_guard=launch_guard)
        if error:
            return "cancelled" if cancel is not None and cancel.is_set() else "grok_login_failed"
        auth, listed = probe(executable, model_id, cancel=cancel, launch_guard=launch_guard)
    if cancel is not None and cancel.is_set():
        return "cancelled"
    if auth == "non_subscription":
        return "grok_billing_unconfirmed"
    if auth != "session":
        return "grok_login_failed"
    return "grok_connected" if listed else "grok_model_unavailable"


BILLING_SECONDS = 35


def normalize_billing(value):
    """Keep only typed account billing facts; absent scalars stay absent."""
    if type(value) is not dict or type(value.get("config")) is not dict:
        raise ValueError("grok_billing_invalid")
    result, config = {}, {}
    tier = value.get("subscription_tier")
    if type(tier) is str and tier in ("SuperGrok", "SuperGrok Heavy"):
        result["subscription_tier"] = tier
    if type(value.get("on_demand_enabled")) is bool:
        result["on_demand_enabled"] = value["on_demand_enabled"]
    raw = value["config"]
    percent = raw.get("creditUsagePercent")
    if type(percent) in (int, float) and 0 <= percent <= 100:
        config["creditUsagePercent"] = percent
    if type(raw.get("isUnifiedBillingUser")) is bool:
        config["isUnifiedBillingUser"] = raw["isUnifiedBillingUser"]
    for key in ("onDemandCap", "onDemandUsed", "prepaidBalance"):
        cents = raw.get(key)
        if type(cents) is dict and type(cents.get("val")) is int and 0 <= cents["val"] <= 2**63 - 1:
            config[key] = {"val": cents["val"]}
    period = raw.get("currentPeriod")
    if type(period) is dict and period.get("type") in ("USAGE_PERIOD_TYPE_WEEKLY", "USAGE_PERIOD_TYPE_MONTHLY"):
        from datetime import datetime
        try:
            dates = [datetime.fromisoformat(period[k].replace("Z", "+00:00")) for k in ("start", "end")]
            if all(d.tzinfo is not None for d in dates) and dates[0] < dates[1]:
                config["currentPeriod"] = {"type": period["type"], "start": dates[0].isoformat(), "end": dates[1].isoformat()}
        except (KeyError, TypeError, ValueError, AttributeError):
            pass
    result["config"] = config
    return result


def billing_quota(billing, now):
    """A reset date alone never establishes allowance."""
    from datetime import datetime
    config = billing["config"]
    period, percent = config.get("currentPeriod"), config.get("creditUsagePercent")
    if period is None or percent is None:
        return "unknown"
    if not datetime.fromisoformat(period["start"]) <= now < datetime.fromisoformat(period["end"]):
        return "unknown"
    return "exhausted" if percent == 100 else "ready"


def observe_billing(executable, *, cancel=None, launch_guard=None):
    """Read account billing over ACP without creating a session or sending a prompt."""
    from contextlib import nullcontext
    import json
    import os
    import selectors
    import subprocess
    import time
    from codex_connection import _safe_env, _terminate, MAX_OUTPUT

    with tempfile.TemporaryDirectory(prefix="grok-billing-") as empty:
        with (launch_guard() if launch_guard else nullcontext()):
            if cancel is not None and cancel.is_set():
                return None, "cancelled"
            try:
                process = subprocess.Popen([executable, "agent", "--no-leader", "stdio"],
                    cwd=empty, env=_safe_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=False, start_new_session=True)
            except OSError:
                return None, "grok_billing_unavailable"
        deadline = time.monotonic() + BILLING_SECONDS
        buffer, total = b"", 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                # Only these two read-only requests are ever sent. No session/new or session/prompt.
                requests = [("initialize", {"protocolVersion": 1, "clientCapabilities": {}}),
                            ("_x.ai/billing", {})]
                for request_id, (method, params) in enumerate(requests, 1):
                    if cancel is not None and cancel.is_set():
                        return None, "cancelled"
                    process.stdin.write((json.dumps({"jsonrpc": "2.0", "id": request_id,
                        "method": method, "params": params}) + "\n").encode())
                    process.stdin.flush()
                    response = None
                    while response is None:
                        if cancel is not None and cancel.is_set():
                            return None, "cancelled"
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return None, "grok_billing_timeout"
                        if b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            event = json.loads(line)
                            if type(event) is not dict or event.get("jsonrpc") != "2.0":
                                return None, "grok_billing_invalid"
                            if "method" in event:
                                if "id" in event:
                                    return None, "grok_billing_client_request"
                                continue
                            if type(event.get("id")) is not int or event["id"] != request_id:
                                return None, "grok_billing_invalid"
                            if "error" in event or type(event.get("result")) is not dict:
                                return None, "grok_billing_unavailable"
                            response = event["result"]
                            continue
                        if not selector.get_map():
                            return None, "grok_billing_unavailable"
                        for key, _ in selector.select(min(remaining, 0.1)):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            total += len(chunk)
                            if total > MAX_OUTPUT:
                                return None, "grok_billing_output_limit"
                            if not chunk:
                                selector.unregister(key.fileobj)
                            elif key.fileobj is process.stdout:
                                buffer += chunk
                    if request_id == 1 and (type(response.get("protocolVersion")) is not int or response["protocolVersion"] != 1):
                        return None, "grok_billing_protocol_mismatch"
                return normalize_billing(response), "grok_billing_observed"
        except (OSError, ValueError, UnicodeError, RecursionError):
            return None, "grok_billing_invalid"
        finally:
            _terminate(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass


SMOKE_SECONDS = 45


def smoke(executable, model_id, *, cancel=None, launch_guard=None):
    """One explicit tool-denied response. Authentication is checked by the caller."""
    import json
    from codex_connection import _run
    args = ["-m", model_id, "--tools", "", "--deny", "*",
            "--disable-web-search", "--no-subagents", "--max-turns", "1",
            "--permission-mode", "dontAsk",
            "--system-prompt-override", "Reply to the user directly. Do not use tools.",
            "--output-format", "json", "-p",
            "Reply with exactly GROK_CONNECTION_OK and nothing else."]
    with tempfile.TemporaryDirectory(prefix="grok-smoke-") as empty:
        result, error, code = _run(executable, args, timeout=SMOKE_SECONDS,
                                  cwd=empty, cancel=cancel, launch_guard=launch_guard)
    if error or code != 0:
        return False
    try:
        response = json.loads(result[0])
    except (ValueError, UnicodeError, RecursionError):
        return False
    return (type(response) is dict and response.get("text") == "GROK_CONNECTION_OK"
            and response.get("stopReason") == "end_turn"
            and type(response.get("num_turns")) is int and response["num_turns"] == 1)
