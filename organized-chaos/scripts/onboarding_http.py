"""Small loopback-only browser editor for an existing private model inventory."""

import hmac
import argparse
import http.server
import json
import secrets
import signal
import socket
import sys
import threading
import time
import webbrowser

import onboarding
import codex_connection

MAX_BODY = onboarding.MAX_CONFIG_BYTES + 1024
HEADER_LIMIT = 16 * 1024
TOTAL_REQUEST_SECONDS = 5
MAX_WORKERS = 8

PAGE = r'''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Local model inventory</title><h1>Model inventory</h1>
<p id="status" role="status">Connecting…</p><form id="models"></form>
<button id="save" disabled>Save selections</button><p id="hash"></p>
<hr><h2>Connect your model</h2>
<label>Selected model <select id="codex-model"></select></label>
<button id="use-cli" disabled>Use Codex CLI</button>
<p id="test-notice"></p>
<button id="connect" disabled>Connect and test</button><button id="cancel" disabled>Cancel</button>
<p id="codex-status" role="status">Not tested.</p>
<button id="refresh-availability" disabled>Refresh availability</button><p id="availability-status" role="status">Availability not checked.</p>
<script>
"use strict";
const token = location.hash.slice(1); history.replaceState(null, "", location.pathname);
let baseline = "", current = null;
const status = document.getElementById("status"), form = document.getElementById("models");
const button = document.getElementById("save"), hash = document.getElementById("hash");
const modelSelect = document.getElementById("codex-model"), useCli = document.getElementById("use-cli");
const connect = document.getElementById("connect"), cancel = document.getElementById("cancel");
const connectionStatus = document.getElementById("codex-status"); let jobId = null, poller = null, dirty = false, jobActive=false;
const availabilityStatus=document.getElementById("availability-status"), availabilityButton=document.getElementById("refresh-availability");
let selectionEpoch=0, availabilityTimer=null, previousConnectionState=null, availabilityRequest=0, availabilityPending=null;
async function api(method, body) {
  const response = await fetch("/api/inventory", {method, cache:"no-store",
    headers:{"X-Session-Token":token, ...(body ? {"Content-Type":"application/json"}:{})},
    body:body ? JSON.stringify(body) : undefined});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "request_failed");
  return data;
}
async function connectionApi(path, method, body) {
  const response = await fetch(path, {method, cache:"no-store",
    headers:{"X-Session-Token":token, ...(body ? {"Content-Type":"application/json"}:{})},
    body:body ? JSON.stringify(body) : undefined});
  const data = await response.json(); if (!response.ok) throw new Error(data.error || "request_failed"); return data;
}
function selectedModel() { return modelSelect.value; }
function fillModels(busy=false) {
  const previous = modelSelect.value;
  modelSelect.replaceChildren();
  current.models.filter(m => (m.provider === "openai" || ["local_http", "grok_cli"].includes(m.execution.kind)) && m.enabled && m.roles.some(role =>
    (current.preferences[role] || []).includes(m.id))).forEach(m => {
    const o=document.createElement("option"); o.value=m.id; o.textContent=m.id+" ("+m.execution.kind+")"; modelSelect.append(o);
  });
  if ([...modelSelect.options].some(o=>o.value===previous)) modelSelect.value=previous;
  const model=current.models.find(m=>m.id===selectedModel());
  const local=model?.execution.kind === "local_http";
  if(dirty) { selectionEpoch++; availabilityRequest++; if(availabilityTimer) clearTimeout(availabilityTimer); availabilityStatus.textContent="Availability not checked."; }
  availabilityButton.disabled=!local || !baseline || dirty || busy;
  const grok=model?.execution.kind === "grok_cli";
  connect.textContent="Connect and test";
  useCli.hidden = !model || local || grok;
  useCli.disabled = !model || !baseline || dirty || busy;
  document.getElementById("test-notice").textContent = grok ? "Sign in using Grok CLI and run one tool-denied response. Usage counts toward your plan; quota remains unknown." : local ?
    "Load this model in LM Studio and start its local server. Test sends one short response request; it does not install or download models." :
    "Use Codex CLI selects your subscription connection. Test runs one model response; usage may count toward your plan.";
  connect.disabled = !model || !["codex_cli", "grok_cli", "local_http"].includes(model.execution.kind) || !baseline || dirty || busy;
}
modelSelect.addEventListener("change",()=>{ selectionEpoch++; fillModels(jobActive); pollConnection(); refreshAvailability(); });
function clearAvailability() {
  availabilityRequest++;
  availabilityPending=null;
  if(availabilityTimer) clearTimeout(availabilityTimer);
  availabilityStatus.textContent="Availability not checked.";
}
async function refreshAvailability() {
  const pendingKey=JSON.stringify([selectionEpoch,baseline,selectedModel()]);
  if(!dirty && availabilityPending===pendingKey) return;
  clearAvailability();
  const model=current?.models.find(m=>m.id===selectedModel()), epoch=selectionEpoch, hashAtStart=baseline, requestId=availabilityRequest;
  const valid=()=>requestId===availabilityRequest && epoch===selectionEpoch && hashAtStart===baseline && model?.id===selectedModel() && !dirty;
  if (!model || model.execution.kind!=="local_http" || dirty || jobActive) return;
  availabilityPending=pendingKey;
  availabilityStatus.textContent="Checking local model metadata…";
  try {
    const result=await connectionApi("/api/connection/availability","POST",{model_id:model.id,expected_hash:hashAtStart});
    if(!valid()) return;
    const started=Date.now();
    async function poll() {
      if(!valid()) return;
      try {
        const s=await connectionApi("/api/connection/status","GET"), a=s.availability;
        if(!valid()) return;
        if(!a || a.job_id!==result.job_id || a.model_id!==model.id || a.config_sha256!==hashAtStart) {
          availabilityPending=null;
          availabilityStatus.textContent="Availability not checked."; return;
        }
        if(a.state==="checking" && Date.now()-started<5000) {
          availabilityTimer=setTimeout(poll,250); return;
        }
        availabilityPending=null;
        const age=Date.now()-Date.parse(a.checked_at||"");
        if(!Number.isFinite(age) || age<0 || age>=30000) {
          availabilityStatus.textContent="Availability not checked."; return;
        }
        const checked=new Date(a.checked_at).toLocaleTimeString();
        availabilityStatus.textContent=a.state==="available" ? `Available now: loaded in LM Studio. Checked ${checked}. This does not reserve the model.` :
          a.state==="unloaded" ? `Not available now: no single usable loaded instance. Checked ${checked}.` : `Availability could not be confirmed. Checked ${checked}.`;
        availabilityTimer=setTimeout(()=>{if(valid()) availabilityStatus.textContent="Availability check expired. Refresh to check again.";},30000-age);
      } catch(e) { if(valid()) { availabilityPending=null; availabilityStatus.textContent="Availability could not be checked."; } }
    }
    availabilityTimer=setTimeout(poll,250);
  } catch(e) { if(valid()) { availabilityPending=null; availabilityStatus.textContent="Availability could not be checked. Retry refresh."; } }
}
availabilityButton.addEventListener("click",e=>{e.preventDefault();refreshAvailability();});
async function pollConnection() {
  try {
    const s=await connectionApi("/api/connection/status","GET"); jobId=s.job_id||null;
    const becameReady=s.state==="ready" && previousConnectionState!=="ready"; previousConnectionState=s.state;
    const historical=(s.finished ? "Test passed at "+new Date(s.finished*1000).toLocaleTimeString()+" for "+s.model_id+". " : "");
    connectionStatus.textContent=(s.state === "ready" || s.state === "expired") && historical ? historical+(s.model_id !== selectedModel() ? "Current selection has not been tested." : s.state === "expired" ? "Test evidence expired." : "") :
      s.state === "ready" ? "Test passed for " + s.model_id + "; " + (selectedModel() || "the current selection") + " has not been tested." :
      ({grok_connected:"Grok sign-in and model discovery confirmed. Billing, quota and task readiness remain unverified.",
        grok_login_failed:"Grok sign-in did not complete. Run grok login --oauth in your terminal, then reconnect.",
        grok_model_unavailable:"Signed in, but this Grok model is not listed.",
        grok_billing_unconfirmed:"Grok reports key-based access. Subscription billing remains unconfirmed.",
        login_changed:"The selected CLI login changed during the test; reconnect.",
        idle:"Not tested.", signing_in:"Signing in with the selected CLI…", testing:"Testing selected model…",
        api_key_blocked:"API key login detected. Sign in with ChatGPT in Codex CLI, then retry.",
        unsupported_cli:"This Codex CLI version lacks required safe test controls.",
        login_failed:"Codex sign-in did not complete.", test_failed:"The bounded model test did not pass.",
        stale_config:"Inventory changed; reload before testing.", model_not_loaded:"Load exactly one instance of the selected model in LM Studio, then retry.",
        local_auth_required:"The local server requires authentication; this connection currently supports unauthenticated loopback servers.",
        unsupported_local_controls:"This model does not support the bounded test controls (reasoning off).",
        cancelled:"Client test stopped. A local server may still finish its bounded response.", expired:"Readiness evidence expired; test again."}[s.state] || "Connection state: "+s.state);
    if (s.state.startsWith("grok_") && s.model_id) {
      const observed=s.finished ? " at "+new Date(s.finished*1000).toLocaleTimeString() : "";
      connectionStatus.textContent="For "+s.model_id+observed+": "+connectionStatus.textContent+
        (s.model_id !== selectedModel() ? " Current selection has not been checked." : "");
    }
    jobActive=!!s.job_active; cancel.disabled=!jobActive; fillModels(jobActive);
    if (becameReady && current?.models.find(m=>m.id===selectedModel())?.execution.kind==="local_http") refreshAvailability();
    if (s.job_active) { if (!poller) poller=setTimeout(()=>{poller=null;pollConnection();},1000); }
    else if (s.state === "ready") { if (poller) clearTimeout(poller); poller=setTimeout(()=>{poller=null;pollConnection();},5000); }
  } catch(e) { connectionStatus.textContent="Connection status unavailable."; }
}
function show(data) {
  current = data.config; baseline = data.hash; dirty = false; selectionEpoch++; availabilityRequest++; if(availabilityTimer) clearTimeout(availabilityTimer); availabilityStatus.textContent="Availability not checked."; form.replaceChildren();
  current.models.forEach((model, index) => {
    const label = document.createElement("label"), box = document.createElement("input");
    box.type = "checkbox"; box.checked = model.enabled;
    box.addEventListener("change", () => {
      current.models[index].enabled = box.checked;
      dirty = true; fillModels();
    });
    label.append(box, document.createTextNode(" " + model.id)); form.append(label, document.createElement("br"));
  });
  hash.textContent = "Current inventory hash: " + baseline; button.disabled = false;
  fillModels();
}
button.addEventListener("click", async event => {
  event.preventDefault(); button.disabled = true;
  for (const box of form.querySelectorAll("input")) box.disabled = true;
  const snapshot = structuredClone(current);
  try { const saved = await api("POST", {config:snapshot, expected_hash:baseline});
    status.textContent = "Saved."; show({config:snapshot, hash:saved.hash}); await pollConnection(); await refreshAvailability(); }
  catch (e) { status.textContent = "Save failed: " + e.message;
    for (const box of form.querySelectorAll("input")) box.disabled = false; button.disabled = false; }
});
useCli.addEventListener("click", async event=>{event.preventDefault(); useCli.disabled=true;
  try { const result=await connectionApi("/api/codex/use-cli","POST",{model_id:selectedModel(),expected_hash:baseline});
    status.textContent="Codex CLI selected."; dirty=false; show(await api("GET")); await pollConnection(); }
  catch(e){connectionStatus.textContent="Could not select Codex CLI: "+e.message; fillModels();}
});
connect.addEventListener("click",async event=>{event.preventDefault(); clearAvailability(); jobActive=true; fillModels(true);
  try { const result=await connectionApi("/api/connection/connect","POST",{model_id:selectedModel(),expected_hash:baseline}); jobId=result.job_id; connectionStatus.textContent=result.quota_cost_notice; await pollConnection(); }
  catch(e){connectionStatus.textContent="Could not start test: "+e.message; jobActive=false; fillModels();}
});
cancel.addEventListener("click",async event=>{event.preventDefault(); cancel.disabled=true;
  try {await connectionApi("/api/connection/cancel","POST",{job_id:jobId});}catch(e){} await pollConnection();
});
(async()=>{try { show(await api("GET")); status.textContent="Loaded."; refreshAvailability(); }
catch(e) { status.textContent="Load failed: "+e.message; } await pollConnection();})();
</script>'''


class _DeadlineReader:
    """Socket reader that applies one absolute deadline and byte cap to parsing."""
    def __init__(self, sock, deadline):
        self.sock, self.deadline, self.buffer = sock, deadline, bytearray()
        self.line_bytes = 0

    def _recv(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.sock.settimeout(remaining)
        chunk = self.sock.recv(4096)
        if not chunk:
            return False
        self.buffer.extend(chunk)
        return True

    def readline(self, limit=-1):
        while True:
            pos = self.buffer.find(b"\n")
            if pos >= 0:
                end = pos + 1
                if limit >= 0: end = min(end, limit)
                result = bytes(self.buffer[:end]); del self.buffer[:end]
                self.line_bytes += len(result)
                if self.line_bytes > HEADER_LIMIT: raise ValueError("headers_too_large")
                return result
            if limit >= 0 and len(self.buffer) >= limit:
                result = bytes(self.buffer[:limit]); del self.buffer[:limit]
                self.line_bytes += len(result)
                if self.line_bytes > HEADER_LIMIT: raise ValueError("headers_too_large")
                return result
            if len(self.buffer) > HEADER_LIMIT or not self._recv():
                result = bytes(self.buffer); self.buffer.clear(); return result

    def read(self, count):
        while len(self.buffer) < count:
            if not self._recv(): break
        result = bytes(self.buffer[:count]); del self.buffer[:len(result)]
        return result

    def close(self):
        pass  # BaseRequestHandler closes both streams; the handler owns this socket.


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, config_path):
        self.config_path = config_path
        self.connection = codex_connection.Connection(config_path)
        self.session_token = secrets.token_urlsafe(32)
        self._slots = threading.BoundedSemaphore(MAX_WORKERS)
        self._active_lock = threading.Lock()
        self._active_sockets = set()
        self._active_threads = set()
        self._closing = False
        super().__init__(address, handler, bind_and_activate=True)
        host, port = self.server_address
        self.origin = f"http://{host}:{port}"
        self.launch_url = self.origin + "/#" + self.session_token

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            with self._active_lock:
                if self._closing:
                    request.close(); self._slots.release(); return
                self._active_sockets.add(request)
                thread = threading.Thread(target=self.process_request_thread,
                                          args=(request, client_address), daemon=True)
                self._active_threads.add(thread)
                thread.start()
        except Exception:
            with self._active_lock:
                self._active_sockets.discard(request)
                if "thread" in locals(): self._active_threads.discard(thread)
            request.close()
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        thread = threading.current_thread()
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_sockets.discard(request)
                self._active_threads.discard(thread)
            self._slots.release()

    def shutdown(self):
        with self._active_lock:
            self._closing = True
            sockets = tuple(self._active_sockets)
        for active in sockets:
            try: active.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: active.close()
            except OSError: pass
        self.connection.close()
        super().shutdown()

    def server_close(self):
        super().server_close()
        with self._active_lock:
            sockets, threads = tuple(self._active_sockets), tuple(self._active_threads)
        for active in sockets:
            try: active.close()
            except OSError: pass
        deadline = time.monotonic() + 2
        for thread in threads:
            if thread is not threading.current_thread(): thread.join(max(0, deadline-time.monotonic()))
        with self._active_lock:
            live = [thread for thread in self._active_threads if thread.is_alive()]
        if live:
            raise RuntimeError("shutdown_incomplete")


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "LocalInventory"
    sys_version = ""

    def setup(self):
        self.connection = self.request
        self.request.settimeout(TOTAL_REQUEST_SECONDS)
        self._deadline = time.monotonic() + TOTAL_REQUEST_SECONDS
        self.rfile = _DeadlineReader(self.request, self._deadline)
        self.wfile = self.request.makefile("wb", buffering=0)

    def log_message(self, *args):
        pass

    def handle(self):
        try: super().handle()
        except (OSError, TimeoutError, ValueError): self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self._send(code if code < 500 else 400, {"error":"invalid_request"})

    def _send(self, status, obj=None, content_type="application/json; charset=utf-8"):
        body = PAGE.encode() if content_type.startswith("text/html") else json.dumps(obj or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _host_ok(self):
        host_headers = self.headers.get_all("Host", [])
        expected = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        return len(host_headers) == 1 and host_headers[0].lower() == expected.lower()

    def _origin_ok(self, mutation=False):
        origins = self.headers.get_all("Origin", [])
        if not mutation and not origins:
            return True  # Browsers omit Origin on same-origin GET; Host is still exact.
        return len(origins) == 1 and origins[0] == self.server.origin

    def _authorized(self):
        tokens = self.headers.get_all("X-Session-Token", [])
        if len(tokens) != 1: return False
        token = tokens[0]
        try: token.encode("ascii")
        except UnicodeEncodeError: return False
        return hmac.compare_digest(token, self.server.session_token)

    def do_GET(self):
        if not self._host_ok(): return self._send(421, {"error":"invalid_host"})
        if self.headers.get_all("Transfer-Encoding", []) or self.headers.get_all("Content-Length", []):
            return self._send(400, {"error":"invalid_framing"})
        if self.path == "/":
            if not self._origin_ok(): return self._send(403, {"error":"invalid_origin"})
            return self._send(200, None, "text/html; charset=utf-8")
        if self.path not in ("/api/inventory", "/api/codex/status", "/api/connection/status"): return self._send(404, {"error":"not_found"})
        if not self._origin_ok(): return self._send(403, {"error":"invalid_origin"})
        if not self._authorized(): return self._send(401, {"error":"unauthorized"})
        if self.path in ("/api/codex/status", "/api/connection/status"):
            state = self.server.connection.status()
            try:
                _, live_hash = onboarding.load_config(self.server.config_path)
            except onboarding.ConfigError:
                return self._send(400, {"error":"config_unavailable_or_invalid"})
            if state.get("config_sha256") and state.get("config_sha256") != live_hash:
                state = {"state":"stale_config"}
            result = {"state":state.get("state", "idle"), "job_id":state.get("job_id"),
                      "model_id":state.get("model_id"),
                      "job_active":state.get("state") in ("signing_in", "testing"),
                      "finished":state.get("finished"), "availability":state.get("availability")}
            observation = state.get("observation")
            if observation and state.get("state") == "ready":
                try:
                    config, digest = onboarding.load_config(self.server.config_path)
                    readiness = onboarding.validate_observation(config, digest, observation)
                    if digest == state.get("config_sha256") and readiness[state["model_id"]]["ready"]:
                        result["observation"] = observation
                        result["ready_for_model"] = state["model_id"]
                    else:
                        result["state"] = "expired"
                except (onboarding.ConfigError, KeyError):
                    result["state"] = "expired"
            return self._send(200, result)
        try:
            config, digest = onboarding.load_config(self.server.config_path)
            return self._send(200, {"config":config, "hash":digest})
        except onboarding.ConfigError as exc:
            return self._send(400, {"error":str(exc)})
        except RecursionError:
            return self._send(400, {"error":"config_unavailable_or_invalid"})

    def do_POST(self):
        if not self._host_ok(): return self._send(421, {"error":"invalid_host"})
        if self.path not in ("/api/inventory", "/api/codex/use-cli", "/api/codex/connect", "/api/codex/cancel",
                             "/api/connection/connect", "/api/connection/cancel", "/api/connection/availability"):
            return self._send(404, {"error":"not_found"})
        if not self._origin_ok(mutation=True): return self._send(403, {"error":"invalid_origin"})
        if not self._authorized(): return self._send(401, {"error":"unauthorized"})
        lengths = self.headers.get_all("Content-Length", [])
        transfers = self.headers.get_all("Transfer-Encoding", [])
        if transfers or len(lengths) != 1:
            return self._send(400, {"error":"invalid_framing"})
        try: length = int(lengths[0])
        except ValueError: return self._send(400, {"error":"invalid_length"})
        if length < 0 or length > MAX_BODY: return self._send(413, {"error":"body_too_large"})
        if self.headers.get_content_type() != "application/json": return self._send(415, {"error":"json_required"})
        try:
            raw = self.rfile.read(length)
            if len(raw) != length or time.monotonic() > self._deadline: raise ValueError
            data = json.loads(raw.decode("utf-8"))
            if self.path != "/api/inventory":
                if type(data) is not dict: raise ValueError
                if self.path == "/api/codex/use-cli":
                    if set(data) != {"model_id", "expected_hash"} or type(data["model_id"]) is not str or type(data["expected_hash"]) is not str: raise ValueError
                    digest = self.server.connection.use_cli(data["model_id"], data["expected_hash"])
                    return self._send(200, {"hash":digest})
                if self.path in ("/api/codex/connect", "/api/connection/connect"):
                    if set(data) != {"model_id", "expected_hash"} or type(data["model_id"]) is not str or type(data["expected_hash"]) is not str: raise ValueError
                    return self._send(202, self.server.connection.start(data["model_id"], data["expected_hash"]))
                if self.path == "/api/connection/availability":
                    if set(data) != {"model_id", "expected_hash"} or type(data["model_id"]) is not str or type(data["expected_hash"]) is not str: raise ValueError
                    return self._send(202, self.server.connection.refresh_availability(data["model_id"], data["expected_hash"]))
                if set(data) != {"job_id"}: raise ValueError
                return self._send(200, self.server.connection.cancel(data["job_id"]))
            if type(data) is not dict or set(data) != {"config", "expected_hash"}: raise ValueError
            with self.server.connection.config_lock:
                existing, live_hash = onboarding.load_config(self.server.config_path)
                submitted = data["config"]
                expected_hash = data["expected_hash"]
                if (type(expected_hash) is str and len(expected_hash) == 64 and
                        all(char in "0123456789abcdef" for char in expected_hash) and
                        not hmac.compare_digest(live_hash, expected_hash)):
                    return self._send(409, {"error":"stale_config"})
                if not _selection_edit_only(existing, submitted):
                    return self._send(400, {"error":"selection_changes_only"})
                digest = onboarding.save_config(self.server.config_path, submitted, expected_hash)
            with self.server.connection.lock:
                job = self.server.connection.job
                if job and job.get("config_sha256") != digest:
                    if self.server.connection.cancel_event:
                        self.server.connection.cancel_event.set()
                    job["state"] = "stale_config"
                    job.pop("observation", None)
            return self._send(200, {"hash":digest})
        except onboarding.ConfigError as exc:
            code = 409 if str(exc) == "stale_config" else 400
            return self._send(code, {"error":str(exc)})
        except (ValueError, UnicodeError, json.JSONDecodeError, TimeoutError, RecursionError):
            return self._send(400, {"error":"invalid_request"})

    def _method_not_allowed(self):
        self._send(405, {"error":"method_not_allowed"})
    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _method_not_allowed


def create_server(config_path):
    """Create a loopback server; call shutdown() and server_close() to retire it."""
    return _Server(("127.0.0.1", 0), _Handler, config_path)


def run(config_path, *, opener=webbrowser.open, server_factory=create_server,
        stop_event=None, install_signal_handlers=True, retry_wait=0.1):
    """Run the local selection editor in the foreground; return a process status."""
    try:
        onboarding.load_config(config_path)
    except onboarding.ConfigError:
        print("Inventory is missing, invalid, or unsafe; no browser session was started.", file=sys.stderr)
        return 2

    try:
        server = server_factory(config_path)
    except Exception:
        print("Could not start the loopback editor; check the local port and retry.", file=sys.stderr)
        return 2

    stopping = stop_event or threading.Event()
    serving_error = []

    def serve():
        try: server.serve_forever()
        except Exception: serving_error.append(True); stopping.set()

    worker = threading.Thread(target=serve, name="onboarding-http", daemon=False)
    previous_handlers = {}
    if install_signal_handlers:
        def request_stop(signum, frame): stopping.set()
        for signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
            if signum is not None:
                try: previous_handlers[signum] = signal.signal(signum, request_stop)
                except (ValueError, OSError): pass

    result = 0
    try:
        # Own every resource from the first worker-start attempt onward. Install
        # handlers first so an early SIGINT requests shutdown instead of
        # interrupting startup between Thread.start() and the cleanup block.
        worker.start()
        try: opened = opener(server.launch_url) is True
        except Exception: opened = False
        if not opened:
            print("Could not open the local editor. Check the default browser and retry.", file=sys.stderr)
            stopping.set()
            result = 2
        else:
            print(f"Selection editor opened at {server.origin}. Keep this terminal open; press Ctrl+C to stop.", flush=True)
            stopping.wait()
            if serving_error:
                result = 1
    except Exception:
        # Do not expose internal paths, browser errors, or traceback details.
        print("Could not start the loopback editor; check the local port and retry.", file=sys.stderr)
        result = 2
    finally:
        if worker.ident is not None:
            _finish_server(server, worker, stopping)
        else:
            # Thread.start() failed before a worker was registered; the bound
            # listener still belongs to this invocation.
            server.server_close()
        for signum, handler in previous_handlers.items():
            try: signal.signal(signum, handler)
            except (ValueError, OSError): pass
    if result == 0:
        print("Local selection editor stopped.", flush=True)
    elif result == 1:
        print("The local editor stopped after a server error.", file=sys.stderr)
    return result


def _finish_server(server, worker, stopping):
    """Stop accepting requests, then retry bounded close until handlers drain."""
    if worker.is_alive(): server.shutdown()
    worker.join()
    reported_wait = False
    while True:
        try:
            server.server_close()
            return
        except RuntimeError as exc:
            if str(exc) != "shutdown_incomplete": raise
            if not reported_wait:
                print("Shutdown is waiting for an active save to finish; this process will remain open.",
                      file=sys.stderr, flush=True)
                reported_wait = True
            time.sleep(0.1)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Edit model enable selections in a private local inventory.")
    parser.add_argument("--config", required=True, help="path to an existing private inventory JSON file")
    args = parser.parse_args(argv)
    return run(args.config)


def _selection_edit_only(existing, submitted):
    """Allow enabled flags to change while preserving role selections and order."""
    if type(submitted) is not dict or set(existing) != set(submitted): return False
    if existing.get("schema_version") != submitted.get("schema_version"): return False
    old_models, new_models = existing.get("models"), submitted.get("models")
    if type(old_models) is not list or type(new_models) is not list or len(old_models) != len(new_models): return False
    for old, new in zip(old_models, new_models):
        if type(old) is not dict or type(new) is not dict or set(old) != set(new): return False
        if any(old[key] != new[key] for key in old if key != "enabled"): return False
        if type(new.get("enabled")) is not bool: return False
    prefs = existing.get("preferences")
    new_prefs = submitted.get("preferences")
    if type(prefs) is not dict or type(new_prefs) is not dict: return False
    return new_prefs == prefs


if __name__ == "__main__":
    raise SystemExit(main())
