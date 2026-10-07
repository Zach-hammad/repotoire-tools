"""One session-local connection job for Codex CLI, Grok CLI or local LM Studio."""

import hashlib
from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
import shutil
import selectors
import signal
import stat
import sys
import subprocess
import tempfile
import threading
import time
import uuid

import onboarding

PROBE_SECONDS = 5
LOGIN_SECONDS = 180
SMOKE_SECONDS = 60
LOCAL_SECONDS = 45
MAX_OUTPUT = 128 * 1024
SUCCESS_TEXT = "CODEX_CONNECTION_OK"
_REDACTED = "connection_failed"


def discover_executable():
    """Return the exact absolute Codex executable selected from PATH."""
    path = shutil.which("codex")
    if not path:
        return None
    path = os.path.abspath(path)
    try:
        info = os.stat(path)
        if stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK):
            return path
    except OSError:
        pass
    return None


def _safe_env():
    # Keep runtime search paths for CLI wrappers, but never search the task cwd.
    runtime_path = os.pathsep.join(part for part in os.environ.get("PATH", os.defpath).split(os.pathsep)
                                  if os.path.isabs(part)) or os.defpath
    # Retain only login/runtime essentials, excluding keys and runtime overrides.
    env = {"PATH": runtime_path, "HOME": os.path.expanduser("~"), "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "CODEX_HOME": os.environ.get("CODEX_HOME", os.path.join(os.path.expanduser("~"), ".codex"))}
    for key in ("TMPDIR",):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _terminate(process):
    """Kill the owned process group and reap the direct child."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _run(executable, args, *, timeout, cwd=None, stdin=None, cancel=None, allow_nonzero=False,
         launch_guard=None):
    """Run one fixed argv with capped output, optional deadline and process-group ownership."""
    with (launch_guard() if launch_guard else nullcontext()):
        if cancel is not None and cancel.is_set():
            return None, "cancelled", None
        process = subprocess.Popen([executable, *args], cwd=cwd, env=_safe_env(),
                                   stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True)
    output, errors = bytearray(), bytearray()
    try:
        input_view = memoryview(stdin) if stdin is not None else None
        deadline = None if timeout is None else time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            if input_view is not None and input_view:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, input_view)
            elif input_view is not None:
                process.stdin.close()
            while selector.get_map():
                if cancel is not None and cancel.is_set():
                    return None, "cancelled", None
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return None, "timeout", None
                for key, _ in selector.select(0.1 if remaining is None else min(remaining, 0.1)):
                    if key.fileobj is process.stdin:
                        try:
                            written = os.write(process.stdin.fileno(), key.data[:4096])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            return None, "stdin_closed", None
                        pending = key.data[written:]
                        if pending:
                            selector.modify(process.stdin, selectors.EVENT_WRITE, pending)
                        else:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    target = key.data
                    chunk = os.read(key.fileobj.fileno(), min(4096, MAX_OUTPUT + 1 - len(output) - len(errors)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        target.extend(chunk)
                        if len(output) + len(errors) > MAX_OUTPUT:
                            return None, "output_too_large", None
        while process.poll() is None:
            if cancel is not None and cancel.is_set():
                return None, "cancelled", None
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return None, "timeout", None
            time.sleep(0.05 if remaining is None else min(0.05, remaining))
        code = process.returncode
        if code != 0 and not allow_nonzero:
            return None, _REDACTED, code
        return (bytes(output), bytes(errors)), None, code
    except subprocess.TimeoutExpired:
        return None, "timeout", None
    finally:
        process.stdout.close()
        process.stderr.close()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        _terminate(process)


def _status(executable, timeout=PROBE_SECONDS, cancel=None, launch_guard=None):
    result, error, code = _run(executable, ["login", "status"], timeout=timeout, cancel=cancel,
                               allow_nonzero=True, launch_guard=launch_guard)
    if error:
        return "unknown"
    stdout = " ".join(result[0].decode("utf-8", "replace").strip().lower().split())
    stderr = " ".join(result[1].decode("utf-8", "replace").strip().lower().split())
    text = stdout or stderr
    if stdout and stderr:
        return "unknown"
    if code == 0 and (text in ("logged in using an api key", "logged in using api key") or
                      text.startswith("logged in using an api key - ")):
        return "api_key"
    if code == 0 and text in ("logged in using chatgpt", "logged in using chatgpt on current machine",
                              "logged in using chatgpt account on current machine"):
        return "chatgpt"
    if code == 1 and text in ("not logged in", "not authenticated"):
        return "signed_out"
    return "unknown"


def _supports(executable, cancel=None, launch_guard=None):
    result, error, _ = _run(executable, ["exec", "--help"], timeout=PROBE_SECONDS, cancel=cancel,
                            launch_guard=launch_guard)
    if error:
        return False
    help_text = (result[0] + result[1]).decode("utf-8", "replace")
    return all(flag in help_text for flag in ("--json", "--model", "--sandbox", "--ephemeral",
                 "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--disable"))


def _smoke(executable, model_id, cancel=None, launch_guard=None):
    with tempfile.TemporaryDirectory(prefix="codex-connect-") as empty:
        args = ["exec", "--json", "--model", model_id, "--sandbox", "read-only",
                "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
                "--disable", "shell_tool", "--disable", "unified_exec", "-C", empty,
                "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
                "-c", 'model_provider="openai"', "-c", "project_doc_max_bytes=0",
                "-c", 'features.skill_mcp_dependency_install=false',
                "-c", 'features.apps=false', "-c", 'features.multi_agent=false',
                "Print exactly CODEX_CONNECTION_OK and nothing else. Do not use tools."]
        result, error, _ = _run(executable, args, timeout=SMOKE_SECONDS, cancel=cancel,
                                launch_guard=launch_guard)
    if error:
        return False
    try:
        events = [json.loads(line) for line in result[0].decode("utf-8", "strict").splitlines()]
    except (UnicodeError, json.JSONDecodeError):
        return False
    messages, completed, tool_activity = [], False, False
    for event in events:
        if type(event) is not dict:
            return False
        kind = event.get("type")
        if kind not in ("thread.started", "turn.started", "item.started", "item.completed", "turn.completed"):
            return False
        if kind in ("turn.failed", "error"):
            return False
        if kind == "item.started":
            if type(event.get("item")) is not dict or event["item"].get("type") not in ("agent_message", "reasoning"):
                tool_activity = True
        if kind == "item.completed" and type(event.get("item")) is dict:
            item = event["item"]
            if item.get("type") == "agent_message" and type(item.get("text")) is str:
                messages.append(item["text"])
            elif item.get("type") not in ("reasoning",):
                tool_activity = True
        if kind == "turn.completed":
            completed = True
    return completed and not tool_activity and messages == [SUCCESS_TEXT]


class _Cancelled(Exception):
    pass


class Connection:
    """At most one asynchronous job; all state is in memory and expires quickly."""
    def __init__(self, config_path):
        self.config_path = config_path
        self.lock = threading.Lock()
        self.config_lock = threading.Lock()
        self.job = None
        self.thread = None
        self.cancel_event = None
        self.process = None
        self.closed = False
        self.availability_job = None
        self.availability_thread = None
        self.availability_cancel = None

    def status(self):
        try:
            _, live_hash = onboarding.load_config(self.config_path)
        except onboarding.ConfigError:
            live_hash = None
        with self.lock:
            self._expire_locked()
            if self.availability_job and (live_hash is None or self.availability_job.get('config_sha256') != live_hash or time.monotonic() - self.availability_job.get('checked_epoch', time.monotonic()) >= 30):
                if self.availability_cancel: self.availability_cancel.set()
                self.availability_job = None
            if self.job and (live_hash is None or self.job.get("config_sha256") != live_hash):
                if self.cancel_event: self.cancel_event.set()
                self.job["state"] = "stale_config"
                self.job.pop("observation", None)
            result = dict(self.job) if self.job else {"state": "idle"}
            if self.availability_job:
                result['availability'] = {key:value for key,value in self.availability_job.items() if key != 'checked_epoch'}
            return result

    def refresh_availability(self, model_id, expected_hash):
        with self.config_lock:
            config, digest = onboarding.load_config(self.config_path)
            if digest != expected_hash: raise onboarding.ConfigError('stale_config')
            model = onboarding._validate_config(config).get(model_id)
            selected = model and model['enabled'] and model['execution']['kind'] == 'local_http' and model['billing_policy'] == 'local_only' and any(model_id in ids and role in model['roles'] for role, ids in config['preferences'].items())
            if not selected: raise onboarding.ConfigError('model_not_selected_or_billing_conflict')
            with self.lock:
                if self.closed: raise onboarding.ConfigError('connection_busy')
                if self.thread and self.thread.is_alive(): raise onboarding.ConfigError('connection_busy')
                if self.availability_thread and self.availability_thread.is_alive():
                    raise onboarding.ConfigError('connection_busy')
                cancel = threading.Event(); job_id = uuid.uuid4().hex
                self.availability_cancel = cancel
                self.availability_job = {'job_id': job_id, 'state': 'checking', 'model_id': model_id, 'config_sha256': digest}
                self.availability_thread = threading.Thread(target=self._work_availability, args=(job_id, model, digest, cancel), daemon=True)
                self.availability_thread.start()
                return {'state': 'checking', 'model_id': model_id, 'job_id': job_id}

    def _work_availability(self, job_id, model, digest, cancel):
        value = {'state': 'unavailable'}
        try:
            result, error, _ = _run(sys.executable, [str(Path(__file__).with_name('local_connection.py'))],
                stdin=json.dumps({'operation':'availability','model':model}).encode(), timeout=3, cancel=cancel,
                launch_guard=lambda: self._stage_guard(digest, cancel))
            if not error:
                parsed = json.loads(result[0])
                if type(parsed) is dict and parsed.get('state') in ('available','unloaded','unavailable'):
                    value = parsed
            with self.config_lock:
                _, live_hash = onboarding.load_config(self.config_path)
                with self.lock:
                    if self.closed or cancel.is_set() or live_hash != digest: value = {'state':'unsupported'}
                    if self.availability_job and self.availability_job.get('job_id') == job_id:
                        self.availability_job.update(value, checked_at=onboarding.datetime.now(onboarding.timezone.utc).isoformat().replace('+00:00','Z'), checked_epoch=time.monotonic())
        except Exception:
            with self.lock:
                if self.availability_job and self.availability_job.get('job_id') == job_id:
                    self.availability_job.update(state='unavailable', checked_at=onboarding.datetime.now(onboarding.timezone.utc).isoformat().replace('+00:00','Z'), checked_epoch=time.monotonic())

    def _expire_locked(self):
        if self.job and self.job.get("state") == "ready" and time.time() - self.job["finished"] > 300:
            self.job["state"] = "expired"
            self.job.pop("observation", None)

    def use_cli(self, model_id, expected_hash):
        with self.config_lock:
            with self.lock:
                if self.closed or (self.thread and self.thread.is_alive()):
                    raise onboarding.ConfigError("connection_busy")
            config, digest = onboarding.load_config(self.config_path)
            if digest != expected_hash:
                raise onboarding.ConfigError("stale_config")
            by_id = onboarding._validate_config(config)
            model = by_id.get(model_id)
            executable = discover_executable()
            selected = model and model["enabled"] and any(
                model_id in ids and role in model["roles"] for role, ids in config["preferences"].items())
            if not executable or not selected or model["provider"] != "openai":
                raise onboarding.ConfigError("codex_model_unavailable")
            if model["execution"]["kind"] not in ("codex_native", "codex_cli"):
                raise onboarding.ConfigError("wrong_execution_kind")
            model["execution"] = {"kind": "codex_cli", "executable": executable}
            new_hash = onboarding.save_config(self.config_path, config, expected_hash)
            with self.lock:
                self.job = None
        return new_hash

    def start(self, model_id, expected_hash):
        with self.config_lock:
            config, digest = onboarding.load_config(self.config_path)
            if digest != expected_hash:
                raise onboarding.ConfigError("stale_config")
            by_id = onboarding._validate_config(config)
            model = by_id.get(model_id)
            selected = model and model["enabled"] and model["execution"]["kind"] in ("codex_cli", "grok_cli", "local_http") and any(
                model_id in ids and role in model["roles"] for role, ids in config["preferences"].items())
            kind = model["execution"]["kind"] if model else None
            policy = "local_only" if kind == "local_http" else "subscription_only"
            if not selected or model["billing_policy"] != policy:
                raise onboarding.ConfigError("model_not_selected_or_billing_conflict")
            executable = model["execution"].get("executable")
            initial = "testing" if kind == "local_http" else "signing_in"
            with self.lock:
                self._expire_locked()
                if self.closed or (self.thread and self.thread.is_alive()):
                    raise onboarding.ConfigError("connection_busy")
                job_id = uuid.uuid4().hex
                if self.availability_cancel:
                    self.availability_cancel.set()
                self.availability_job = None
                self.cancel_event = threading.Event()
                self.job = {"job_id": job_id, "state": initial, "model_id": model_id,
                            "config_sha256": digest, "started": time.time()}
                self.thread = threading.Thread(target=self._work_local if kind == "local_http" else self._work_grok if kind == "grok_cli" else self._work, args=(job_id, config, digest, model_id,
                                           executable, self.cancel_event), name="codex-connection", daemon=True)
                self.thread.start()
                return {"job_id": job_id, "state": initial, "quota_cost_notice":
                        ("This signs in to Grok and runs one tool-denied response; usage counts toward your plan."
                         if kind == "grok_cli" else "This runs one response on your selected local model."
                         if kind == "local_http" else
                         "This runs one Codex CLI model response using your existing subscription.")}

    @contextmanager
    def _stage_guard(self, digest, cancel):
        # HTTP selection writes use this same lock; validation and Popen are atomic
        # with respect to an in-server save, so stale stages cannot start later.
        with self.config_lock:
            if cancel.is_set():
                raise _Cancelled
            _, current_hash = onboarding.load_config(self.config_path)
            if current_hash != digest:
                raise onboarding.ConfigError("stale_config")
            yield

    def _work_grok(self, job_id, config, digest, model_id, executable, cancel):
        import grok_connection
        state, observation = "test_failed", None
        try:
            guard = lambda: self._stage_guard(digest, cancel)
            state = grok_connection.connect(executable, model_id, cancel=cancel, launch_guard=guard)
            if state != "grok_connected":
                return self._finish(job_id, state)
            with self.lock:
                if self.job and self.job.get("job_id") == job_id:
                    self.job["state"] = "testing"
            if not grok_connection.smoke(executable, model_id, cancel=cancel, launch_guard=guard):
                return self._finish(job_id, "cancelled" if cancel.is_set() else "test_failed")
            if grok_connection.probe(executable, model_id, cancel=cancel, launch_guard=guard) != ("session", True):
                return self._finish(job_id, "cancelled" if cancel.is_set() else "login_changed")
            current, current_hash = onboarding.load_config(self.config_path)
            if current_hash != digest or current != config:
                return self._finish(job_id, "stale_config")
            rows = {mid: {"auth_observed": "unknown", "runtime_capability": "unknown",
                "billing_status": "unknown", "quota": "unknown", "model_inference": "unknown",
                "host_observation": False, "reason": "pending"} for mid in onboarding._validate_config(config)}
            rows[model_id].update(auth_observed="ready", runtime_capability="ready",
                billing_status="ready", model_inference="ready", reason="bounded_grok_cli_smoke")
            observation = {"schema_version": 1, "config_sha256": digest,
                "observed_at": onboarding.datetime.now(onboarding.timezone.utc).isoformat().replace("+00:00", "Z"),
                "models": rows}
            state = "ready" if onboarding.validate_observation(config, digest, observation)[model_id]["ready"] else "not_ready"
        except _Cancelled:
            state = "cancelled"
        except onboarding.ConfigError:
            state = "stale_config"
        except (OSError, ValueError, TypeError):
            state = "test_failed"
        self._finish(job_id, state, observation)

    def _work_local(self, job_id, config, digest, model_id, executable, cancel):
        state, observation = "test_failed", None
        try:
            model = onboarding._validate_config(config)[model_id]
            result, error, _ = _run(sys.executable,
                [str(Path(__file__).with_name("local_connection.py"))],
                stdin=json.dumps(model).encode(), timeout=LOCAL_SECONDS, cancel=cancel,
                launch_guard=lambda: self._stage_guard(digest, cancel))
            if error:
                state = "cancelled" if cancel.is_set() else "test_failed"
            else:
                data = json.loads(result[0])
                state = data.get("state") if type(data) is dict else "test_failed"
                if state not in ("ready", "test_failed", "model_not_loaded", "local_auth_required",
                                 "unsupported_local_controls"):
                    state = "test_failed"
                if state == "ready":
                    rows = {mid: {"auth_observed": "unknown", "runtime_capability": "unknown",
                        "billing_status": "unknown", "quota": "unknown", "model_inference": "unknown",
                        "host_observation": False, "reason": "pending"} for mid in onboarding._validate_config(config)}
                    rows[model_id].update(runtime_capability="ready", billing_status="ready",
                        model_inference="ready", reason="bounded_local_http_smoke")
                    observation = {"schema_version": 1, "config_sha256": digest,
                        "observed_at": onboarding.datetime.now(onboarding.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "models": rows}
                    if not onboarding.validate_observation(config, digest, observation)[model_id]["ready"]:
                        state = "not_ready"
        except _Cancelled:
            state = "cancelled"
        except onboarding.ConfigError:
            state = "stale_config"
        except (OSError, ValueError, TypeError):
            state = "test_failed"
        self._finish(job_id, state, observation)

    def _work(self, job_id, config, digest, model_id, executable, cancel):
        state, observation = "failed", None
        try:
            guard = lambda: self._stage_guard(digest, cancel)
            if not _supports(executable, cancel, guard):
                if cancel.is_set(): return self._finish(job_id, "cancelled")
                state = "unsupported_cli"
            else:
                auth = _status(executable, cancel=cancel, launch_guard=guard)
                if cancel.is_set(): return self._finish(job_id, "cancelled")
                if auth == "api_key":
                    state = "api_key_blocked"
                elif auth == "unknown":
                    state = "failed"
                else:
                    if auth == "signed_out":
                        with self.lock:
                            if self.job and self.job.get("job_id") == job_id: self.job["state"] = "signing_in"
                        _, err, _ = _run(executable, ["login"], timeout=LOGIN_SECONDS, cancel=cancel,
                                         launch_guard=guard)
                        if err:
                            state = "cancelled" if err == "cancelled" else "login_failed"
                            return self._finish(job_id, state)
                    if cancel.is_set():
                        return self._finish(job_id, "cancelled")
                    auth = _status(executable, cancel=cancel, launch_guard=guard)
                    if cancel.is_set(): return self._finish(job_id, "cancelled")
                    if auth != "chatgpt":
                        return self._finish(job_id, "login_failed")
                    with self.lock:
                        if self.job and self.job.get("job_id") == job_id: self.job["state"] = "testing"
                    if not _smoke(executable, model_id, cancel, guard):
                        return self._finish(job_id, "cancelled" if cancel.is_set() else "test_failed")
                    auth = _status(executable, cancel=cancel, launch_guard=guard)
                    if cancel.is_set(): return self._finish(job_id, "cancelled")
                    if auth != "chatgpt":
                        return self._finish(job_id, "login_changed")
                    # Re-read exact bytes and bind the fresh runtime receipt.
                    current, current_hash = onboarding.load_config(self.config_path)
                    if current_hash != digest or current != config:
                        return self._finish(job_id, "stale_config")
                    record = {"auth_observed":"ready", "runtime_capability":"ready",
                              "billing_status":"ready", "quota":"unknown",
                              "model_inference":"ready", "host_observation":False,
                              "reason":"bounded_codex_cli_smoke"}
                    rows = {mid:{"auth_observed":"unknown", "runtime_capability":"unknown",
                                 "billing_status":"unknown", "quota":"unknown",
                                 "model_inference":"unknown", "host_observation":False,
                                 "reason":"pending"} for mid in onboarding._validate_config(config)}
                    rows[model_id] = record
                    observation = {"schema_version":1, "config_sha256":digest,
                        "observed_at": onboarding.datetime.now(onboarding.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "models":rows}
                    checked = onboarding.validate_observation(config, digest, observation)
                    if not checked[model_id]["ready"]:
                        return self._finish(job_id, "not_ready")
                    state = "ready"
        except _Cancelled:
            state = "cancelled"
        except onboarding.ConfigError:
            state = "stale_config"
        except Exception:
            state = "failed"
        self._finish(job_id, state, observation)

    def _finish(self, job_id, state, observation=None):
        with self.config_lock:
            try:
                _, live_hash = onboarding.load_config(self.config_path)
            except onboarding.ConfigError:
                live_hash = None
            with self.lock:
                if not self.job or self.job.get("job_id") != job_id:
                    return
                if self.job.get("state") in ("stale_config", "cancelled"):
                    state = self.job["state"]
                elif live_hash != self.job.get("config_sha256"):
                    state = "stale_config"
                elif self.cancel_event and self.cancel_event.is_set():
                    state = "cancelled"
                elif self.closed:
                    state = "cancelled"
                self.job.update({"state":state, "finished":time.time()})
                self.job.pop("observation", None)
                if observation is not None and state == "ready": self.job["observation"] = observation

    def cancel(self, job_id):
        with self.lock:
            if not self.job or self.job.get("job_id") != job_id or not self.thread or not self.thread.is_alive():
                raise onboarding.ConfigError("job_not_active")
            self.cancel_event.set()
            if self.availability_cancel:
                self.availability_cancel.set()
            self.availability_job = None
            thread = self.thread
        thread.join(timeout=3)
        return self.status()

    def close(self):
        with self.lock:
            self.closed = True
            cancel, thread = self.cancel_event, self.thread
            if cancel: cancel.set()
            if self.availability_cancel: self.availability_cancel.set()
            availability_thread = self.availability_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=LOGIN_SECONDS + SMOKE_SECONDS + 10)
        if availability_thread and availability_thread is not threading.current_thread(): availability_thread.join(timeout=3)
        if availability_thread and availability_thread.is_alive():
            raise RuntimeError("availability_shutdown_incomplete")
        if thread and thread.is_alive():
            # Keep shutdown truthful if a child does not obey the bounded path.
            raise RuntimeError("codex_connection_shutdown_incomplete")
