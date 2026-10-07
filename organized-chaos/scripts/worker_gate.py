"""Coordinator-owned approval gate for deterministic application of approved bytes.

This is an orchestration boundary, not a security boundary against the same OS user.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat

MAX_SOURCE = 32 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, limit=MAX_SOURCE):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode) or path.resolve() != path.absolute():
        raise ValueError("Expected a regular file without symlink components")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File exceeds gate size limit")
    return data


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode()


def selected_worker(inventory, model):
    import onboarding
    by_id = onboarding._validate_config(inventory)
    entry = by_id.get(model)
    if entry is None:
        raise ValueError("Model is absent from the validated inventory")
    if (entry.get("enabled") is not True or "implementation" not in entry.get("roles", [])
            or model not in inventory.get("preferences", {}).get("implementation", [])):
        raise ValueError("Model is not selected for implementation")
    execution = entry.get("execution", {})
    kind = execution.get("kind")
    if kind == "local_http":
        if entry["billing_policy"] != "local_only":
            raise ValueError("Local execution requires local_only billing")
        return {"model": model, "kind": kind, "url": execution["url"]}
    if kind not in ("grok_cli", "codex_cli"):
        raise ValueError("No tested implementation adapter for this execution kind")
    executable = execution.get("executable", "")
    if not Path(executable).is_absolute() or not os.access(executable, os.X_OK):
        raise ValueError("Worker executable is unavailable")
    return {"model": model, "kind": kind, "executable": executable}


def prepare(state, target, replacement, inventory, model):
    """Capture an already received proposal. This performs no worker/model call."""
    state, target, inventory = map(lambda p: Path(p).absolute(), (state, target, inventory))
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", target.name):
        raise ValueError("Use a plain source filename")
    baseline = read_file(target)
    proposed = read_file(replacement).decode("utf-8")
    if not proposed:
        raise ValueError("Replacement must contain source")
    inventory_bytes = read_file(inventory, 1024 * 1024)
    worker = selected_worker(json.loads(inventory_bytes), model)
    proposal = {"version": 1, "target": str(target), "baseline_sha256": digest(baseline),
                "source": proposed, "inventory": str(inventory),
                "inventory_sha256": digest(inventory_bytes), "worker": worker}
    state.mkdir(mode=0o700)  # A fresh directory prevents stale approval reuse.
    write_new(state / "proposal.json", encoded(proposal))
    return digest(encoded(proposal))


def load_current(state):
    raw = read_file(state / "proposal.json", 256 * 1024)
    proposal = json.loads(raw)
    if proposal["version"] != 1:
        raise ValueError("Unsupported proposal version")
    inventory_bytes = read_file(proposal["inventory"], 1024 * 1024)
    if digest(inventory_bytes) != proposal["inventory_sha256"]:
        raise ValueError("Model selections changed; prepare a new proposal")
    if selected_worker(json.loads(inventory_bytes), proposal["worker"]["model"]) != proposal["worker"]:
        raise ValueError("Worker changed")
    baseline = read_file(proposal["target"])
    if digest(baseline) != proposal["baseline_sha256"]:
        raise ValueError("Target baseline changed; review again")
    return proposal, digest(raw), baseline


def approve(state, reviewed_sha256):
    """Called by the coordinator after reviewing proposal.json, never by the worker."""
    state = Path(state)
    _, identity, _ = load_current(state)
    if identity != reviewed_sha256:
        raise ValueError("Proposal differs from the reviewed identity")
    write_new(state / "approval.json", encoded({"decision": "approved", "proposal_sha256": identity}))


def implement(state, *, cancel=None):
    """Consume one approval and materialize its exact source as a verified candidate."""
    state = Path(state).absolute()
    proposal, identity, baseline = load_current(state)
    approval = json.loads(read_file(state / "approval.json"))
    if approval != {"decision": "approved", "proposal_sha256": identity}:
        raise ValueError("Matching coordinator approval is required")
    # O_EXCL serializes competing attempts and consumes approval even on failure.
    write_new(state / "attempt.json", encoded({"proposal_sha256": identity, "status": "started"}))
    receipt = {"proposal_sha256": identity, "status": "failed", "target_written": False,
               "executor": "local-deterministic"}
    try:
        if load_current(state)[1] != identity:
            raise ValueError("Proposal changed before application")
        if cancel is not None and cancel.is_set():
            raise ValueError("Application was cancelled")
        result = proposal["source"].encode("utf-8")
        candidate = state / "candidate"
        created = False
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(fd, "wb") as stream:
                stream.write(result)
            saved = read_file(candidate)
            saved_digest = digest(saved)
            if saved != result or saved_digest != digest(result):
                raise ValueError("Saved candidate differs from approved source")
            if load_current(state)[1] != identity:
                raise ValueError("Proposal changed during application")
            # This final check is the acceptance boundary. Earlier cancellation
            # prevents a candidate; later signals do not revoke acceptance.
            if cancel is not None and cancel.is_set():
                raise ValueError("Application was cancelled")
        except BaseException:
            if created:
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass
            raise
        receipt.update(status="verified-candidate", candidate_sha256=saved_digest)
    finally:
        # A failed or interrupted attempt cannot be silently replayed.
        write_new(state / "result.json", encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("prepare")
    for flag in ("state", "target", "replacement", "inventory", "model"):
        capture.add_argument("--" + flag, required=True)
    approval = commands.add_parser("approve")
    approval.add_argument("--state", required=True)
    approval.add_argument("--reviewed-sha256", required=True)
    execution = commands.add_parser("implement")
    execution.add_argument("--state", required=True)
    options = vars(parser.parse_args())
    command = options.pop("command")
    if command == "implement":
        class CancellationFlag:
            cancelled = False

            def is_set(self):
                return self.cancelled

        cancellation = CancellationFlag()
        previous = {}

        def request_cancel(_signum, _frame):
            cancellation.cancelled = True

        try:
            for signum in (signal.SIGTERM, signal.SIGHUP):
                previous[signum] = signal.signal(signum, request_cancel)
            value = implement(**options, cancel=cancellation)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.exit(1, f"Worker gate blocked: {type(error).__name__}: {error}\n")
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        print(json.dumps(value))
        return
    try:
        value = {"prepare": prepare, "approve": approve, "implement": implement}[command](**options)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Worker gate blocked: {type(error).__name__}: {error}\n")
    print(json.dumps(value))


if __name__ == "__main__":
    main()
