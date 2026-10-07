#!/usr/bin/env python3
"""On-demand evaluation evidence. One coordinator, no scheduler or provider authority."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


def stamp():
    return {"utc": datetime.now(timezone.utc).isoformat(),
            "monotonic": time.monotonic(), "clock_origin": time.time() - time.monotonic()}


def duration(start, end):
    # Across commands the monotonic epoch must still describe this host/boot.
    if abs(start["clock_origin"] - end["clock_origin"]) > 2:
        return None
    value = end["monotonic"] - start["monotonic"]
    return round(value, 6) if value >= 0 else None


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def safe_id(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value):
        raise ValueError("Use a unique, path-safe attempt ID of at most 96 characters")
    return value


def init(run, manifest):
    started = stamp()  # Before any run-owned setup.
    if manifest.get("mode") not in ("matched", "rotation"):
        raise ValueError("Manifest mode must be matched or rotation")
    for name in ("owner_task_id", "question", "limits", "configurations"):
        if not manifest.get(name):
            raise ValueError(f"Manifest requires {name}")
    run = Path(run).resolve()
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_json(run / "manifest.json", manifest)
    (run / "events.jsonl").touch(mode=0o600, exist_ok=False)
    append(run, "init", data={"manifest_sha256": digest(run / "manifest.json")}, at=started)


def read_events(run):
    with (Path(run) / "events.jsonl").open() as source:
        fcntl.flock(source, fcntl.LOCK_SH)
        return [json.loads(line) for line in source]


def transition(events, kind, attempt, data=None):
    if kind == "check_correction":
        validate_correction(events, attempt, data)
        return
    if any(event["kind"] == "close" for event in events):
        raise ValueError("Run is closed; create a new run instead of overwriting evidence")
    prior = [event["kind"] for event in events if event["attempt"] == attempt]
    expected = {"prepare": [], "dispatch": ["prepare"],
                "finish": ["prepare", "dispatch"],
                "check_start": ["prepare", "dispatch", "finish"],
                "check_end": ["prepare", "dispatch", "finish", "check_start"]}
    if kind in expected and prior != expected[kind]:
        raise ValueError(f"Invalid or duplicate {kind} for {attempt}: {prior}")
    if kind == "init" and events:
        raise ValueError("Run already initialized")


def validate_correction(events, attempt, data):
    # Runs under the journal's exclusive lock, including the supersession check.
    if not isinstance(data, dict) or type(data.get("accepted")) is not bool:
        raise ValueError("Correction requires boolean acceptance")
    if type(data.get("supersedes")) is not int or not isinstance(data.get("reason"), str) or not data["reason"].strip():
        raise ValueError("Correction requires an event sequence and a nonempty reason")
    assessments = [event for event in events if event["attempt"] == attempt
                   and event["kind"] in ("check_end", "check_correction")]
    if not assessments or assessments[-1]["sequence"] != data["supersedes"]:
        raise ValueError("Correction must supersede this attempt's latest assessment")
    completed = next(event for event in events if event["attempt"] == attempt and event["kind"] == "finish")
    if data["accepted"] and completed["data"]["status"] != "completed":
        raise ValueError("A failed transport cannot pass independent acceptance")
    evidence = Path(data["evidence_ref"]).resolve(strict=True)
    if digest(evidence) != data["evidence_sha256"]:
        raise ValueError("Correction evidence changed before recording")


def _append_locked(journal, events, kind, attempt=None, data=None, at=None):
    """Append against the caller's snapshot while it holds the exclusive lock."""
    transition(events, kind, attempt, data)
    event = {"sequence": len(events), "kind": kind, "attempt": attempt,
             "at": at or stamp(), "data": data or {}}
    encoded = json.dumps(event, allow_nan=False) + "\n"
    journal.seek(0, os.SEEK_END)
    journal.write(encoded)
    journal.flush()
    os.fsync(journal.fileno())
    return event


def append(run, kind, attempt=None, data=None, at=None):
    path = Path(run) / "events.jsonl"
    with path.open("r+") as journal:
        fcntl.flock(journal, fcntl.LOCK_EX)
        events = [json.loads(line) for line in journal]
        return _append_locked(journal, events, kind, attempt, data, at)


def prepare(run, attempt, packet, model, task_class, boundary):
    safe_id(attempt)
    if not model or not task_class:
        raise ValueError("Exact model/configuration and task class are required")
    if boundary not in ("native_observation", "process"):
        raise ValueError("Unsupported timing boundary")
    transition(read_events(run), "prepare", attempt)
    packet = Path(packet).resolve(strict=True)
    data = packet.read_bytes()
    if not data or len(data) > 1_000_000:
        raise ValueError("Packet must contain 1 to 1,000,000 bytes; qualify context separately")
    cwd = Path(run).resolve() / "attempts" / attempt
    cwd.mkdir(parents=True, exist_ok=False, mode=0o700)
    admitted = cwd / "packet.txt"
    with admitted.open("xb") as target:
        target.write(data)
    if admitted.read_bytes() != data:
        raise ValueError("Staged packet differs from frozen source")
    return append(run, "prepare", attempt, {
        "model_requested": model, "task_class": task_class, "boundary": boundary,
        "cwd": str(cwd), "packet": str(admitted), "packet_sha256": digest(admitted)})


def attempt_event(run, attempt, kind):
    return next(event for event in read_events(run)
                if event["attempt"] == attempt and event["kind"] == kind)


def dispatch(run, attempt):
    manifest = next(event for event in read_events(run) if event["kind"] == "init")
    if digest(Path(run) / "manifest.json") != manifest["data"]["manifest_sha256"]:
        raise ValueError("Frozen manifest changed; dispatch refused")
    prepared = attempt_event(run, attempt, "prepare")["data"]
    packet = Path(prepared["packet"])
    cwd = Path(prepared["cwd"])
    if packet.is_symlink() or packet.resolve().parent != cwd.resolve():
        raise ValueError("Prompt must be a regular file inside the worker sandbox cwd")
    if digest(packet) != prepared["packet_sha256"]:
        raise ValueError("Packet changed after preparation")
    return append(run, "dispatch", attempt)


def extract_usage(provider, raw):
    """Allowlist exposed counters. Never copy response text, thoughts, or credentials."""
    fields = {"native_input_tokens": None, "native_output_tokens": None,
              "cached_input_tokens": None, "cache_creation_input_tokens": None,
              "reasoning_tokens": None, "provider_estimated_cost_usd": None,
              "cash_cost_usd": None, "local_energy_kwh": None,
              "provider_api_seconds": None, "provider_ttft_seconds": None}
    reasons = {key: "Provider did not expose this measurement" for key in fields}
    reasons["cash_cost_usd"] = "No per-call actual cash charge supplied; an estimate is not a charge"
    reasons["local_energy_kwh"] = "Energy was not measured"
    provenance = {}
    model_ids = []
    if not isinstance(raw, dict):
        raise ValueError("Provider response must be an object")
    def assign(name, container, key, scale=1):
        value = container.get(key) if isinstance(container, dict) else None
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            reasons[name] = f"Invalid provider value at {key}"
            return
        if name.endswith("tokens") and int(value) != value:
            reasons[name] = f"Noninteger provider token count at {key}"
            return
        fields[name] = value * scale
        provenance[name] = f"{provider}:{key}"
        reasons.pop(name, None)
    if provider in ("claude", "grok"):
        usage = raw.get("usage", {})
        for name, key in (("native_input_tokens", "input_tokens"), ("native_output_tokens", "output_tokens"),
                          ("cached_input_tokens", "cache_read_input_tokens"),
                          ("cache_creation_input_tokens", "cache_creation_input_tokens"),
                          ("reasoning_tokens", "reasoning_tokens")):
            assign(name, usage, key)
        if provider == "claude" and isinstance(usage, dict):
            assign("reasoning_tokens", usage.get("output_tokens_details", {}), "thinking_tokens")
            assign("provider_api_seconds", raw, "duration_api_ms", .001)
            assign("provider_ttft_seconds", raw, "ttft_ms", .001)
        assign("provider_estimated_cost_usd", raw, "total_cost_usd")
        models = raw.get("modelUsage", {})
        if isinstance(models, dict):
            model_ids = list(models)
        cost_basis = "provider-reported estimate; billing basis unavailable"
        if provider == "claude" and isinstance(models, dict) and models and all(
                isinstance(value, dict) and value.get("costBasis") == "list" for value in models.values()):
            cost_basis = "provider-reported list-price estimate"
    elif provider == "qwen":
        stats = raw.get("stats", {})
        for name, key in (("native_input_tokens", "input_tokens"),
                          ("native_output_tokens", "total_output_tokens"),
                          ("reasoning_tokens", "reasoning_output_tokens"),
                          ("provider_ttft_seconds", "time_to_first_token_seconds")):
            assign(name, stats, key)
        if isinstance(raw.get("model_instance_id"), str):
            model_ids = [raw["model_instance_id"]]
        cost_basis = "No metered inference price supplied; local operating cost unmeasured"
    elif provider == "native":
        cost_basis = "Native collaboration surface exposes no per-call tokens or cash charge"
    else:
        raise ValueError("Unsupported usage provider")
    return {"measurements": fields, "provenance": provenance, "unknown_reasons": reasons,
            "model_ids_observed": model_ids, "cost_basis": cost_basis}


def finish(run, attempt, status, provider, response=None, extra=None, at=None):
    if status not in ("completed", "process_failed", "launch_failed", "timeout", "cancelled"):
        raise ValueError("Unsupported transport status")
    data = {"status": status, "usage": extract_usage(provider, {})}
    if response:
        data["response_ref"] = str(Path(response).resolve())
        data["response_sha256"] = digest(response)
        try:
            raw = json.loads(Path(response).read_text())
            data["usage"] = extract_usage(provider, raw)
            if raw.get("is_error") is True and status == "completed":
                data["status"] = "process_failed"
        except (ValueError, UnicodeError, AttributeError) as error:
            data["usage_error"] = type(error).__name__  # No raw provider text in shared evidence.
    data.update(extra or {})
    return append(run, "finish", attempt, data, at=at)


def terminate_owned(proc):
    # Some macOS hosts deny group signals. Address only observed PIDs in the
    # session this invocation created, rechecking membership before each signal.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        listing = subprocess.run(["ps", "-axo", "pid=,pgid=,stat="], check=True,
                                 capture_output=True, text=True, timeout=5).stdout
        for row in listing.splitlines():
            pid, group, state = row.split()
            if int(group) != proc.pid or state.startswith("Z"):
                continue
            try:
                if os.getpgid(int(pid)) == proc.pid:
                    os.kill(int(pid), sig)
            except ProcessLookupError:
                pass
        if sig == signal.SIGTERM:
            time.sleep(.1)
    proc.wait(timeout=5)
    deadline = time.monotonic() + 2
    while True:
        listing = subprocess.run(["ps", "-axo", "pgid=,stat="], check=True,
                                 capture_output=True, text=True, timeout=5).stdout
        live = [row for row in listing.splitlines()
                if int(row.split()[0]) == proc.pid and not row.split()[1].startswith("Z")]
        if not live:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned processes still alive; cleanup evidence incomplete")
        time.sleep(.05)


def run_process(run, attempt, provider, command, timeout=120, stdin_packet=False, env=None):
    if not 0 < timeout <= 3600 or not command:
        raise ValueError("Supply a command and a deadline in (0, 3600] seconds")
    prepared = attempt_event(run, attempt, "prepare")["data"]
    if prepared["boundary"] != "process":
        raise ValueError("Process execution requires a process-boundary attempt")
    command = [part.replace("{packet}", prepared["packet"]).replace("{cwd}", prepared["cwd"])
               for part in command]
    cwd = Path(prepared["cwd"])
    response, stderr = cwd / "response.json", cwd / "stderr.txt"
    dispatch(run, attempt)
    proc = None
    status, code, error_type = "launch_failed", None, None
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    previous_handler = signal.signal(signal.SIGTERM, interrupted)
    with response.open("x") as out, stderr.open("x") as err:
        try:
            proc = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True,
                                    stdin=subprocess.PIPE if stdin_packet else subprocess.DEVNULL,
                                    stdout=out, stderr=err, text=True)
            proc.communicate(cwd.joinpath("packet.txt").read_text() if stdin_packet else None,
                             timeout=timeout)
            code = proc.returncode
            status = "completed" if code == 0 else "process_failed"
        except subprocess.TimeoutExpired:
            terminate_owned(proc)
            code, status = proc.returncode, "timeout"
        except (KeyboardInterrupt, SystemExit):
            if proc:
                terminate_owned(proc)
                code = proc.returncode
            status = "cancelled"
        except OSError as error:
            error_type = type(error).__name__
            if proc:
                terminate_owned(proc)
                code = proc.returncode
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
    finished = stamp()  # Parsing and report writing are outside process duration.
    return finish(run, attempt, status, provider, response,
                  {"exit_code": code, "error_type": error_type, "deadline_seconds": timeout,
                   "stderr_ref": str(stderr)}, at=finished)


def check_end(run, attempt, accepted, evidence):
    completed = attempt_event(run, attempt, "finish")
    if accepted and completed["data"]["status"] != "completed":
        raise ValueError("A failed transport cannot pass independent acceptance")
    evidence = Path(evidence).resolve(strict=True)
    return append(run, "check_end", attempt, {"accepted": accepted,
                  "evidence_ref": str(evidence), "evidence_sha256": digest(evidence)})



def correct_check(run, attempt, supersedes, accepted, evidence, reason):
    evidence = Path(evidence).resolve(strict=True)
    return append(run, "check_correction", attempt, {
        "supersedes": supersedes, "accepted": accepted, "reason": reason,
        "evidence_ref": str(evidence), "evidence_sha256": digest(evidence)})


def report(run):
    return _report_events(run, read_events(run))


def _report_events(run, events):
    attempts = []
    for prepared in (event for event in events if event["kind"] == "prepare"):
        group = {event["kind"]: event for event in events if event["attempt"] == prepared["attempt"]}
        dispatched, done, checked = (group.get(key) for key in ("dispatch", "finish", "check_end"))
        assessment = group.get("check_correction", checked)
        check_started = group.get("check_start")
        boundary = prepared["data"]["boundary"]
        elapsed = duration(dispatched["at"], done["at"]) if dispatched and done else None
        measurements = dict(done["data"]["usage"]["measurements"]) if done else {}
        measurements.update({"dispatch_to_observed_completion_seconds": elapsed if boundary == "native_observation" else None,
                             "process_seconds": elapsed if boundary == "process" else None,
                             "pre_dispatch_queue_seconds": duration(prepared["at"], dispatched["at"]) if dispatched else None,
                             "verification_seconds": duration(check_started["at"], checked["at"]) if check_started and checked else None,
                             "attempt_through_verification_seconds": duration(prepared["at"], checked["at"]) if checked else None})
        unknowns = dict(done["data"]["usage"]["unknown_reasons"]) if done else {}
        for key, value in measurements.items():
            if value is None and key not in unknowns:
                unknowns[key] = "Required event not recorded, or clock epoch changed"
        if boundary == "native_observation":
            unknowns["process_seconds"] = "Not applicable to a native tool dispatch"
        else:
            unknowns["dispatch_to_observed_completion_seconds"] = "Not applicable to a supervised process"
        for key, reason in (("provider_queue_seconds", "Internal provider queue duration is not exposed"),
                            ("human_minutes", "Human effort was not metered"),
                            ("retirement_wait_seconds", "Retirement is recorded separately by the coordinator")):
            measurements[key] = None
            unknowns[key] = reason
        attempts.append({"attempt": prepared["attempt"], **prepared["data"],
                         "transport_status": done["data"]["status"] if done else "pending",
                         "accepted": assessment["data"]["accepted"] if assessment else None,
                         "initial_accepted": checked["data"]["accepted"] if checked else None,
                         "assessment_sequence": assessment["sequence"] if assessment else None,
                         "measurements": measurements,
                         "measurement_unknown_reasons": unknowns,
                         "usage": done["data"]["usage"] if done else None,
                         "timing_limit": "Native timing includes tool scheduling and observation lag; provider queue and inference time are unavailable" if boundary == "native_observation" else "Process wall time includes CLI startup, provider queue, inference, and shutdown",
                         "times_utc": {key: event["at"]["utc"] for key, event in group.items()}})
    closed = next((event for event in events if event["kind"] == "close"), None)
    first_dispatch = next((event for event in events if event["kind"] == "dispatch"), None)
    return {"schema_version": 3, "run": str(Path(run).resolve()),
            "journal_sequence": events[-1]["sequence"],
            "closed_report_sequence": closed["sequence"] if closed else None,
            "assessment_corrections": sum(event["kind"] == "check_correction" for event in events),
            "disposition": closed["data"]["disposition"] if closed else "open",
            "whole_run_seconds": duration(events[0]["at"], closed["at"]) if closed else None,
            "setup_to_first_dispatch_seconds": duration(events[0]["at"], first_dispatch["at"]) if first_dispatch else None,
            "assigned": len(attempts), "attempted": sum(item["kind"] == "dispatch" for item in events),
            "accepted": sum(item["accepted"] is True for item in attempts),
            "failed_transport": sum(item["transport_status"] not in ("completed", "pending") for item in attempts),
            "pending": sum(item["transport_status"] == "pending" for item in attempts),
            "unverified": sum(item["accepted"] is None for item in attempts),
            "attempts": attempts,
            "limits": ["Intervals can overlap; do not sum them into campaign elapsed time",
                       "Preparation before init is outside this run; never reconstruct missing history",
                       "Coordinator and verifier token/cash usage are unavailable unless separately supplied as evidence",
                       "This recorder supplies evidence, not retirement authority or a model ranking",
                       "Corrections change assessment only; initial timing and close-time report.json remain frozen"]}


def close(run, disposition):
    if disposition not in ("complete", "incomplete"):
        raise ValueError("Invalid disposition")
    with (Path(run) / "events.jsonl").open("r+") as journal:
        fcntl.flock(journal, fcntl.LOCK_EX)
        events = [json.loads(line) for line in journal]
        current = _report_events(run, events)
        if disposition == "complete" and (not current["assigned"] or current["pending"] or current["unverified"]):
            raise ValueError("Complete requires terminal, independently checked outcomes for every attempt")
        events.append(_append_locked(journal, events, "close", data={"disposition": disposition}))
        write_json(Path(run) / "report.json", _report_events(run, events))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "prepare", "dispatch", "finish", "run", "check-start", "check-end", "correct-check", "close", "report"))
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--attempt")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--task-class")
    parser.add_argument("--boundary", choices=("process", "native_observation"))
    parser.add_argument("--provider", choices=("claude", "grok", "qwen", "native"), default="native")
    parser.add_argument("--status", default="completed")
    parser.add_argument("--response", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--stdin-packet", action="store_true")
    parser.add_argument("--accepted", choices=("yes", "no"))
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--supersedes", type=int)
    parser.add_argument("--reason")
    parser.add_argument("--disposition", choices=("complete", "incomplete"), default="complete")
    argv = sys.argv[1:]
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    command = argv[split + 1:]
    if command and args.action != "run":
        parser.error("Extra arguments are accepted only for run")
    if args.action == "init":
        init(args.run, json.loads(args.manifest.read_text()))
    elif args.action == "prepare":
        prepare(args.run, args.attempt, args.packet, args.model, args.task_class, args.boundary)
    elif args.action == "dispatch":
        dispatch(args.run, args.attempt)
    elif args.action == "finish":
        finish(args.run, args.attempt, args.status, args.provider, args.response)
    elif args.action == "run":
        event = run_process(args.run, args.attempt, args.provider, command, args.timeout, args.stdin_packet)
        print(json.dumps(event["data"]["status"]))
        return 0 if event["data"]["status"] == "completed" else 1
    elif args.action == "check-start":
        append(args.run, "check_start", args.attempt)
    elif args.action == "check-end":
        if args.accepted is None:
            parser.error("check-end requires --accepted yes/no")
        check_end(args.run, args.attempt, args.accepted == "yes", args.evidence)
    elif args.action == "correct-check":
        if args.accepted is None or args.supersedes is None or not args.reason or args.evidence is None:
            parser.error("correct-check requires --accepted, --supersedes, --reason, and --evidence")
        correct_check(args.run, args.attempt, args.supersedes, args.accepted == "yes", args.evidence, args.reason)
    elif args.action == "close":
        close(args.run, args.disposition)
    else:
        print(json.dumps(report(args.run), indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
