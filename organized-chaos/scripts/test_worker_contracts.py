"""Required worker, quota and evidence contracts. No paid transport."""
import os
import sys
from pathlib import Path
ROOT = Path(os.environ.get("CONTRACT_WORKER_ROOT", Path(__file__).parent))
sys.path.insert(0, str(ROOT))
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
import worker_gate as gate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import local_worker
import local_connection
import os
import onboarding
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
from unittest.mock import patch
import urllib.error
import jev_route as route
import jev_ledger
import fcntl
import signal
import subprocess
import time
import performance_record as record
from datetime import timedelta
import grok_connection

def snapshot():
    now = datetime.now(timezone.utc)
    return {
        "snapshot_id": "fixture", "observed_at_utc": now.isoformat(),
        "source": "Synthetic /usage fixture", "runtime_version": "2.1.280",
        "provider": "Anthropic", "billing_lane": "Claude Max subscription",
        "pool_alias": "claude-default", "usage_credits_enabled": False,
        "windows": [{
            "label": label, "scope": scope, "used_percent": used,
            "remaining_percent": 100 - used, "status": "observed",
            "kind": "subscription quota", "unit": "percent",
            "duration_minutes": None, "resets_at_utc": (now + timedelta(hours=1)).isoformat(),
        } for label, scope, used in (
            ("Current session", "subscription shared session window", 25),
            ("Current week (all models)", "subscription all models", 60),
            ("Current week (Fable)", "named model sublimit", 10),
        )],
    }

def packet():
    return {
        "goal": "Synthetic staffing rehearsal", "source_revision": "fixture-v1",
        "decision_criterion": "Which plan has the strongest supplied review evidence?",
        "capacity": {"total_workers": 4, "pool_workers": 3, "basis": "Synthetic capacity fixture"},
        "active_assignments": [{"task_id": "existing", "model_id": "gpt-6-sol", "pool_alias": "codex-default"}],
        "models": [{"id": "claude-opus-5-5", "pool_alias": "claude-default", "fit_evidence": "Synthetic eligible model"}],
        "tasks": [{"id": f"task-{i}", "work_item_id": f"task-{i}", "contract": "Independent read-only review",
                   "ready_evidence": "Synthetic independent inputs; no shared write custody",
                   "eligible_models": ["claude-opus-5-5"], "jev_requests_used": 0, "advice_stage": "review", "dispatch_ready": True,
                   "advice_basis": {"previous_state_sha256": None, "change_reason": None},
                   "excluded_models": {}} for i in range(3)],
        "plans": [{"id": "three-starts", "reason": "Exercise three new workers plus one active",
                   "target_worker_count": 4, "assignments": [
                       {"task_id": f"task-{i}", "model_id": "claude-opus-5-5"} for i in range(3)]}, {"id": "wait", "reason": "Queue pending work", "target_worker_count": 1, "assignments": []}],
    }

def response():
    return {
        "model": "jev-1.13.0",
        "answers": {"staffing_plan": {"type": "choice", "choice": "three-starts",
                    "probabilities": {"three-starts": 0.8, "return_to_coordinator": 0.2, "wait": 0.0}, "confidence": 0.7}},
        "usage": {"input_tokens": 300, "output_tokens": 30},
    }

def codex_snapshot():
    now = datetime.now(timezone.utc)
    bucket = {
        "limitId": "codex", "normalModelSlug": None, "individualLimit": None,
        "primary": {"usedPercent": 77, "windowDurationMins": 10080,
                    "resetsAt": int((now + timedelta(days=6)).timestamp())},
        "secondary": None, "spendControlReached": False, "rateLimitReachedType": None,
        "credits": {"hasCredits": False, "unlimited": False, "balance": "0"}, "planType": "pro",
    }
    return {
        "snapshot_id": "codex-fixture", "observed_at_utc": now.isoformat(),
        "source": "Synthetic get_usage_limits fixture", "runtime_version": "fixture",
        "provider": "OpenAI", "billing_lane": "Codex subscription", "pool_alias": "codex-default",
        "codex_usage": {"ordinaryUsageAllowed": True, "rateLimitsByLimitId": {"codex": bucket}},
    }

def codex_packet():
    data = packet()
    data["active_assignments"][0].update(model_id="grok-4.7", pool_alias="grok-default")
    data["models"] = [{"id": model, "pool_alias": "codex-default", "fit_evidence": "Synthetic eligible model"}
                      for model in ("gpt-6-sol", "gpt-6-luna")]
    for task in data["tasks"]:
        task["eligible_models"] = ["gpt-6-sol", "gpt-6-luna"]
    for index, assignment in enumerate(data["plans"][0]["assignments"]):
        assignment["model_id"] = "gpt-6-sol" if index == 0 else "gpt-6-luna"
    return data

def run_cli(data, usage, arguments=(), ledger_file=None):
    output = io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "usage.json"
        path.write_text(json.dumps(usage))
        inventory_path = Path(directory) / "inventory.json"
        observation_path = Path(directory) / "observation.json"
        inventory_path.write_text("{}")
        observation_path.write_text("{}")
        inventory_path.chmod(0o600)
        observation_path.chmod(0o600)
        declared = {model["id"] for model in data.get("models", [])}
        inventory = {"models": [{"id": model_id, "enabled": True,
                                  "roles": list({task.get("advice_stage") for task in data.get("tasks", [])
                                                 if task.get("advice_stage")})} for model_id in declared]}
        stream = io.TextIOWrapper(io.BytesIO(json.dumps(data).encode()))
        ledger_file = Path(ledger_file) if ledger_file is not None else Path(directory) / "advice.sqlite3"
        with patch.object(jev_ledger, "ledger_path", return_value=ledger_file), \
                patch("sys.argv", ["jev_route.py", "--usage-snapshot", str(path),
                                "--inventory-config", str(inventory_path),
                                "--inventory-observation", str(observation_path), *arguments]), \
                patch("sys.stdin", stream), patch("sys.stdout", output), \
                patch.object(route, "load_config", return_value=(inventory, "0" * 64)), \
                patch.object(route, "validate_observation", return_value={}), \
                patch.object(route, "validate_inventory"):
            code = route.main()
    return code, json.loads(output.getvalue())

def seed_previous_advice(data, usage, ledger_file):
    prior = deepcopy(data)
    for task in prior["tasks"]:
        task["jev_requests_used"] = 0
        task["advice_basis"] = {"previous_state_sha256": None, "change_reason": None}
    _, _, hashes = route.make_request(prior, usage, datetime.now(timezone.utc))
    requests, previous = {}, {}
    for task in data["tasks"]:
        work_id = task["work_item_id"]
        if task["jev_requests_used"] != 1 or work_id in requests:
            continue
        digest = "0" * 64
        while digest == hashes.state_hashes[work_id]:
            digest = "1" * 64
        previous[work_id] = digest
        requests[work_id] = {"expected_used": 0,
                             "basis": {"previous_state_sha256": None, "change_reason": None},
                             "state_hash": digest}
    with patch.object(jev_ledger, "ledger_path", return_value=Path(ledger_file)):
        jev_ledger.reserve(requests)
    for task in data["tasks"]:
        if task["work_item_id"] in previous and task["jev_requests_used"] == 1:
            task["advice_basis"] = {"previous_state_sha256": previous[task["work_item_id"]],
                                     "change_reason": "Synthetic evidence changed"}

def grok_snapshot():
    now = datetime.now(timezone.utc)
    return {
        "snapshot_id": "grok-fixture", "observed_at_utc": now.isoformat(),
        "source": "Synthetic Grok interactive /usage fixture", "runtime_version": "1.0.30",
        "provider": "xAI", "billing_lane": "Grok Build subscription", "pool_alias": "grok-default",
        "auth_method": "grok.com", "all_displayed_limits_recorded": True,
        "paid_allowance": {"status": "unavailable", "reason": "Not displayed by this fixture"},
        "windows": [{
            "label": "Weekly limit (SuperGrok)", "scope": "shared Grok Build subscription",
            "kind": "subscription quota", "unit": "percent", "status": "observed",
            "used_percent": 38, "remaining_percent": 62, "duration_minutes": 10080,
            "resets_at_utc": (now + timedelta(days=5)).isoformat(),
            "reset_text": "Synthetic future reset", "reset_timezone": "America/New_York",
            "reset_precision": "minute", "percentage_precision": "whole percent, floored",
            "reset_year_inferred": True,
        }],
    }

def grok_packet():
    data = packet()
    data["models"] = [{"id": "grok-4.7", "pool_alias": "grok-default", "fit_evidence": "Synthetic eligible model"}]
    for task in data["tasks"]:
        task["eligible_models"] = ["grok-4.7"]
    for assignment in data["plans"][0]["assignments"]:
        assignment["model_id"] = "grok-4.7"
    return data

def mac_snapshot():
    return {
        "snapshot_id": "mac-fixture", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "Synthetic LM Studio and host observation", "runtime_version": "fixture",
        "provider": "LM Studio", "billing_lane": "Local Mac inference", "pool_alias": "mac-qwen-review",
        "intended_mac_loopback_verified": True,
        "host": {"physical_memory_bytes": 137438953472, "free_percent": 13,
                 "memory_pressure_level": 2, "active_requests": 0,
                 "slot_evidence": "Synthetic coordinator owns the only review slot; other demand checked"},
        "local_model": {"key": "qwen3.8-flash-next", "type": "llm", "format": "gguf",
                        "quantization": {"name": "IQ4_XS"}, "size_bytes": 98585839520,
                        "max_context_length": 262144,
                        "loaded_instances": [{"id": "qwen3.8-flash-next",
                                              "config": {"context_length": 8192, "parallel": 1,
                                                         "speculative_draft_mtp": False,
                                                         "speculative_draft_simple": False,
                                                         "speculative_draft_model": ""}}]},
    }

def mac_packet():
    data = packet()
    data["capacity"].update(total_workers=2, pool_workers=1)
    data["models"] = [{"id": "qwen3.8-flash-next", "pool_alias": "mac-qwen-review", "fit_evidence": "Synthetic reviewer"}]
    data["tasks"] = data["tasks"][:1]
    data["tasks"][0].update(eligible_models=["qwen3.8-flash-next"], review={
        "mode": "tool_free_read_only", "input_tokens_upper_bound": 4096,
        "max_output_tokens": 2048, "budget_basis": "Synthetic complete packet bound including template overhead"})
    data["plans"] = [{"id": "one-review", "reason": "One bounded local review alongside cloud work",
                      "target_worker_count": 2,
                      "assignments": [{"task_id": "task-0", "model_id": "qwen3.8-flash-next"}]},
                     {"id": "wait", "reason": "Queue pending review", "target_worker_count": 1, "assignments": []}]
    return data

def config():
    return {
        "schema_version": 1,
        "models": [
            {"id": "codex-luna", "provider": "openai", "pool_alias": "codex_shared",
             "execution": {"kind": "codex_cli", "executable": "/mock/codex"},
             "billing_policy": "subscription_only", "enabled": True, "roles": ["implementation"]},
            {"id": "local-qwen", "provider": "local", "pool_alias": "local_mac",
             "execution": {"kind": "local_http", "url": "http://127.0.0.1:1234"},
             "billing_policy": "local_only", "enabled": True, "roles": ["implementation"]},
            {"id": "claude-review", "provider": "anthropic", "pool_alias": "claude_shared",
             "execution": {"kind": "claude_cli", "executable": "/mock/claude"},
             "billing_policy": "subscription_only", "enabled": False, "roles": ["review"]},
        ],
        "preferences": {"implementation": ["codex-luna", "local-qwen"], "review": []},
    }

NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)

class WorkerApprovalContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / "sample.py"
        self.target.write_text("value = 1\n")
        self.replacement = self.root / "replacement.py"
        self.replacement.write_text("value = 2\n")
        self.inventory = self.root / "inventory.json"
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        self.grok = bin_dir / "grok"
        self.codex = bin_dir / "codex"
        for executable in (self.grok, self.codex):
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
        self.inventory.write_text(json.dumps({
            "schema_version": 1,
            "models": [{"id": "fixture", "provider": "xai", "pool_alias": "xai_pool",
                        "billing_policy": "subscription_only", "enabled": True,
                        "roles": ["implementation"],
                        "execution": {"kind": "grok_cli", "executable": str(self.grok)}}],
            "preferences": {"implementation": ["fixture"]}}))
        self.state = self.root / "coordinator"
        self.identity = gate.prepare(self.state, self.target, self.replacement,
                                     self.inventory, "fixture")

    def approved(self):
        gate.approve(self.state, self.identity)

    def test_approval_materializes_exact_bytes_and_verifies_saved_candidate(self):
        """What: Exact approved bytes become the candidate.
        Why: Approval binds content, not an approximate rewrite.
        Verify: Real source files include CRLF, whitespace and missing final newline.
        Detects: Normalization or verification of different bytes.
        """
        cases = {
            "lf": b"value = 2\n",
            "no_final_newline": b"value = 2",
            "crlf": b"value = 2\r\n",
            "whitespace": b"\nvalue = 2  \n\n",
            "unicode": "value = 'caf\u00e9'\n".encode("utf-8"),
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.replacement.write_bytes(expected)
                state = self.root / name
                identity = gate.prepare(state, self.target, self.replacement,
                                        self.inventory, "fixture")
                gate.approve(state, identity)
                receipt = gate.implement(state)
                self.assertEqual(receipt["status"], "verified-candidate")
                self.assertEqual(receipt["executor"], "local-deterministic")
                self.assertEqual(receipt["candidate_sha256"], hashlib.sha256(expected).hexdigest())
                self.assertEqual((state / "candidate").read_bytes(), expected)
                self.assertEqual(self.target.read_bytes(), b"value = 1\n")
                with self.assertRaises(FileExistsError):
                    gate.implement(state)

    def test_missing_or_rejected_approval_never_materializes(self):
        """What: Only affirmative approval admits a write.
        Why: Prepared evidence does not authorize mutation.
        Verify: Missing and rejected approval leave no candidate.
        Detects: Implicit authorization.
        """
        with self.assertRaises(FileNotFoundError):
            gate.implement(self.state)
        self.assertFalse((self.state / "attempt.json").exists())
        self.approved()
        (self.state / "approval.json").write_text(json.dumps(
            {"decision": "revise", "proposal_sha256": self.identity}))
        with self.assertRaises(ValueError):
            gate.implement(self.state)
        self.assertFalse((self.state / "candidate").exists())

    def test_wrong_reviewed_identity_cannot_approve(self):
        """What: Approval matches the reviewed identity.
        Why: Changed work requires another decision.
        Verify: Wrong proposal identity is rejected.
        Detects: Approval replay on a different proposal.
        """
        with self.assertRaises(ValueError):
            gate.approve(self.state, "0" * 64)
        self.assertFalse((self.state / "approval.json").exists())
        with self.assertRaises(FileNotFoundError):
            gate.implement(self.state)

    def test_competing_attempts_allow_only_one_success(self):
        """What: One concurrent attempt owns materialization.
        Why: Two winners would violate write custody.
        Verify: Real threads contend while one candidate read is blocked.
        Detects: Both attempts claiming success.
        """
        self.approved()
        entered_candidate_read = threading.Event()
        release_candidate_read = threading.Event()
        outcome = {}
        original_read = gate.read_file

        def block_first_after_saved_candidate_read(path, *args, **kwargs):
            data = original_read(path, *args, **kwargs)
            if Path(path) == self.state / "candidate":
                entered_candidate_read.set()
                if not release_candidate_read.wait(5):
                    raise TimeoutError("test did not release first attempt")
            return data

        def first_attempt():
            try:
                outcome["receipt"] = gate.implement(self.state)
            except BaseException as exc:  # surfaced in the test thread
                outcome["error"] = exc

        with mock.patch.object(gate, "read_file", side_effect=block_first_after_saved_candidate_read):
            thread = threading.Thread(target=first_attempt)
            thread.start()
            self.assertTrue(entered_candidate_read.wait(5), "first attempt did not reach readback")
            with self.assertRaises(FileExistsError):
                gate.implement(self.state)
            release_candidate_read.set()
            thread.join(5)
        self.assertFalse(thread.is_alive(), "first attempt did not finish")
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["receipt"]["status"], "verified-candidate")
        self.assertEqual((self.state / "candidate").read_bytes(), self.replacement.read_bytes())

    def test_proposal_target_and_inventory_snapshots_are_rechecked(self):
        """What: Proposal, target and inventory remain the approved inputs.
        Why: Stale admission can apply unintended work.
        Verify: Each saved input changes independently before execution.
        Detects: Snapshot drift accepted as current.
        """
        self.approved()
        record = json.loads((self.state / "proposal.json").read_text())
        record["source"] = "value = 3\n"
        (self.state / "proposal.json").write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            gate.implement(self.state)

        state = self.root / "inventory-changed"
        identity = gate.prepare(state, self.target, self.replacement, self.inventory, "fixture")
        gate.approve(state, identity)
        self.inventory.write_text("{}")
        with self.assertRaises(ValueError):
            gate.implement(state)

        state = self.root / "target-changed"
        self.inventory.write_text(json.dumps({
            "schema_version": 1,
            "models": [{"id": "fixture", "provider": "xai", "pool_alias": "xai_pool",
                        "billing_policy": "subscription_only", "enabled": True,
                        "roles": ["implementation"],
                        "execution": {"kind": "grok_cli", "executable": str(self.grok)}}],
            "preferences": {"implementation": ["fixture"]}}))
        identity = gate.prepare(state, self.target, self.replacement, self.inventory, "fixture")
        gate.approve(state, identity)
        self.target.write_text("value = 99\n")
        with self.assertRaises(ValueError):
            gate.implement(state)
        self.assertEqual(self.target.read_text(), "value = 99\n")

    def test_preexisting_candidate_is_preserved(self):
        """What: An existing candidate is never overwritten.
        Why: Another owner may hold that file.
        Verify: Real existing bytes survive rejection.
        Detects: Destructive replacement of foreign evidence.
        """
        self.approved()
        candidate = self.state / "candidate"
        candidate.write_bytes(b"owned before this attempt")
        with self.assertRaises(FileExistsError):
            gate.implement(self.state)
        self.assertEqual(candidate.read_bytes(), b"owned before this attempt")
        receipt = json.loads((self.state / "result.json").read_text())
        self.assertEqual(receipt["status"], "failed")

class LocalTransportContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.requests = []
        self.loaded = True
        self.model_inventory = None
        self.http_status = 200
        self.tool = 'apply_approved_replacement'
        self.arguments = '{}'
        self.response_model = 'fixture'
        self.unload_after_response = False
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                owner.requests.append(('GET', self.path))
                self.send(owner.model_inventory if owner.model_inventory is not None else
                    {'models':[{'key':'fixture','type':'llm', 'loaded_instances':
                    [{'id':'fixture','config':{'context_length':8192}}] if owner.loaded else []}]})
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.requests.append(('POST', self.path, body))
                if owner.unload_after_response: owner.loaded = False
                self.send({'model':owner.response_model,'choices':[{'finish_reason':'tool_calls',
                    'message':{'role':'assistant','tool_calls':[{'id':'call-1','type':'function',
                    'function':{'name':owner.tool,'arguments':owner.arguments}}]}}]})
            def send(self, body):
                raw = json.dumps(body).encode()
                self.send_response(owner.http_status);self.send_header('Content-Length', str(len(raw)))
                self.end_headers();self.wfile.write(raw)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.target = self.root/'sample.py';self.target.write_text('value = 1\n')
        self.source = 'value = 2\n'
        self.config = {'schema_version':1,'models':[{'id':'fixture','provider':'local','pool_alias':'local',
            'enabled':True,'roles':['implementation'],'billing_policy':'local_only',
            'execution':{'kind':'local_http','url':f'http://127.0.0.1:{self.server.server_port}'}}],
            'preferences':{'implementation':['fixture']}}
        self.envelope = {'worker': {'model': 'fixture', 'kind': 'local_http',
            'url': f'http://127.0.0.1:{self.server.server_port}'},
            'filename': 'sample.py', 'source': self.source,
            'baseline_sha256': hashlib.sha256(self.target.read_bytes()).hexdigest()}

    def close_server(self):
        self.server.shutdown();self.thread.join();self.server.server_close()

    def run_adapter(self):
        with mock.patch('pathlib.Path.cwd', return_value=self.root):
            return local_worker.implement(self.envelope)

    def test_adapter_uses_real_local_transport_and_applies_exact_envelope_bytes(self):
        """What: Local transport materializes the exact valid envelope.
        Why: A transport response is not yet a verified source candidate.
        Verify: Real loopback HTTP and source bytes exercise the adapter.
        Detects: Protocol drift or changed output bytes.
        """
        result = self.run_adapter()
        self.assertEqual(result, {'status': 'applied', 'executor': 'local-file-tool', 'model': 'fixture'})
        self.assertEqual(self.target.read_text(), self.source)
        posts = [r for r in self.requests if r[0]=='POST']
        self.assertEqual(len(posts),1)
        self.assertEqual(posts[0][1],'/v1/chat/completions')
        body = posts[0][2]
        self.assertEqual(body['tools'][0]['function']['name'],'apply_approved_replacement')
        self.assertNotIn('max_tokens',body)
        self.assertEqual(body['tools'][0]['function']['parameters']['properties'],{})
        self.assertEqual(len([r for r in self.requests if r[0] == 'GET']), 2)

    def test_wrong_tool_arguments_model_or_runtime_change_produces_no_candidate(self):
        """What: Mismatched tool, model and changed runtime fail closed.
        Why: An available local server cannot authorize a different operation.
        Verify: Controlled HTTP responses vary identity and loaded runtime.
        Detects: Invalid response becoming a candidate.
        """
        for field,value in [('tool','shell'),('arguments','{"path":"../outside.py"}'),
                            ('response_model','other-model'),('unload_after_response',True)]:
            with self.subTest(field=field):
                original=getattr(self,field);setattr(self,field,value)
                try:
                    with self.assertRaises((ValueError, local_connection.TestFailed)):self.run_adapter()
                finally:setattr(self,field,original);self.loaded=True
                self.assertEqual(self.target.read_text(),'value = 1\n')

    def test_invalid_endpoint_and_billing_block_before_any_request(self):
        """What: Invalid transport or billing is rejected before a request.
        Why: Admission must precede spending and network access.
        Verify: Recorded local server requests stay empty for rejected inputs.
        Detects: Sending before admission.
        """
        for patch in [{'execution':{'kind':'local_http','url':'https://example.com'}}]:
            with self.subTest(patch=patch):
                cfg=json.loads(json.dumps(self.config));cfg['models'][0].update(patch)
                with self.assertRaises(ValueError):
                    import onboarding
                    onboarding._validate_config(cfg)
        self.assertEqual(self.requests,[])

    def test_onboarding_requires_the_selected_loaded_llm_from_real_http(self):
        """What: Onboarding recognizes the selected loaded LM Studio model.
        Why: A running server or a downloaded model alone is not ready capacity.
        Verify: Loopback HTTP supplies independent loaded, unloaded, wrong-model,
        non-LLM, malformed-instance and malformed-envelope responses; the ready
        response also reaches check_config's public runtime projection.
        Detects: Rejected documented envelopes or unavailable models marked ready.
        """
        url = self.config['models'][0]['execution']['url']
        loaded = {'key': 'fixture', 'type': 'llm', 'loaded_instances': [
            {'id': 'instance-1', 'config': {'context_length': 8192}}]}
        self.model_inventory = {'models': [loaded]}
        self.assertEqual(onboarding._probe_local(url, 'fixture'),
                         ('ready', 'loaded_model_observed'))
        observation = onboarding.check_config(self.config, 'a' * 64, now=NOW)
        self.assertEqual(observation['models']['fixture']['runtime_capability'], 'ready')
        for change in ({'loaded_instances': []}, {'key': 'other-model'},
                       {'type': 'embedding'}, {'loaded_instances': [{'id': ''}]},
                       {'loaded_instances': [{'id': 'instance-1', 'config': {'context_length': 0}}]}):
            with self.subTest(change=change):
                self.model_inventory = {'models': [dict(loaded, **change)]}
                self.assertEqual(onboarding._probe_local(url, 'fixture'),
                                 ('unavailable', 'model_not_loaded'))
        self.model_inventory = {'models': 'malformed'}
        self.assertEqual(onboarding._probe_local(url, 'fixture'),
                         ('unknown', 'runtime_unavailable'))
        self.model_inventory = {'models': [loaded]}
        self.http_status = 503
        self.assertEqual(onboarding._probe_local(url, 'fixture'),
                         ('unknown', 'runtime_unavailable'))
        self.assertTrue(all(request == ('GET', '/api/v1/models') for request in self.requests))

class InventoryPersistenceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "inventory.json"
        self.original = {"schema_version": 1, "models": [], "preferences": {}}
        self.original_bytes = json.dumps(self.original).encode()
        self.path.write_bytes(self.original_bytes)
        os.chmod(self.path, 0o600)
        self.original_hash = hashlib.sha256(self.original_bytes).hexdigest()

    def test_saves_valid_config_and_returns_hash_of_saved_bytes(self):
        """What: Saved inventory has the exact reported digest and private permissions.
        Why: Future approval binds the persisted inventory.
        Verify: Real filesystem bytes, independently hashed, and modes.
        Detects: Wrong hash or insecure saved permissions.
        """
        replacement = {"schema_version": 1, "models": [], "preferences": {"review": []}}

        digest = onboarding.save_config(self.path, replacement, self.original_hash)

        saved = self.path.read_bytes()
        self.assertEqual(digest, hashlib.sha256(saved).hexdigest())
        self.assertEqual(json.loads(saved), replacement)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.directory.glob("*.tmp")), [])

    def test_stale_hash_preserves_existing_bytes(self):
        """What: Stale updates preserve the current inventory.
        Why: A newer owner decision must not be lost.
        Verify: A wrong prior digest rejects the write and preserves bytes.
        Detects: Lost update.
        """
        replacement = {"schema_version": 1, "models": [], "preferences": {}}
        onboarding.save_config(self.path, replacement, self.original_hash)
        saved = self.path.read_bytes()

        with self.assertRaisesRegex(onboarding.ConfigError, "stale_config"):
            onboarding.save_config(self.path, self.original, self.original_hash)

        self.assertEqual(self.path.read_bytes(), saved)

    def test_rejects_symlink_without_touching_target(self):
        """What: Inventory saving refuses a symlink.
        Why: Path validation must preserve another file owner.
        Verify: Real symlink and target bytes remain unchanged.
        Detects: Following a symlink during save.
        """
        other = self.directory / "other.json"
        other.write_bytes(self.original_bytes)
        os.chmod(other, 0o600)
        self.path.unlink()
        self.path.symlink_to(other)

        with self.assertRaises(onboarding.ConfigError):
            onboarding.save_config(self.path, self.original, self.original_hash)

        self.assertEqual(other.read_bytes(), self.original_bytes)

    def test_fifo_target_is_rejected_without_blocking(self):
        """What: A FIFO cannot block inventory persistence.
        Why: Untrusted paths must not hang admission.
        Verify: Real FIFO is rejected without reading it.
        Detects: Unbounded FIFO read.
        """
        fifo = self.directory / "inventory.json"
        fifo.unlink()
        os.mkfifo(fifo, 0o600)

        with self.assertRaises(onboarding.ConfigError):
            onboarding.save_config(fifo, self.original, self.original_hash)

        self.assertTrue(fifo.is_fifo())

class AdviceAdmissionContracts(unittest.TestCase):
    def test_batch_distribution_error_identifies_the_question_and_sum_without_response_text(self):
        """What: A malformed batch distribution identifies its index, generated ID and sum.
        Why: Operators need to locate a failed judgment without exposing provider/request text.
        Verify: Two literal questions accept normalized answers; a bad second sum rejects with bounded diagnostics.
        Detects: Generic batch errors, relaxed sum validation, or private answer/identifier leakage.
        """
        questions = {"fit_0": {"local", "wait"}, "fit_1": {"local", "wait"}}
        reply = {"model": "jev-1.13.0", "answers": {
            key: {"type": "choice", "choice": "local",
                  "probabilities": {"local": 0.8, "wait": 0.2}, "confidence": 0.8,
                  "text": "private-response-text"} for key in questions
        }, "usage": {"input_tokens": 10, "output_tokens": 2}}
        self.assertEqual(set(route.read_choices(reply, questions)["judgments"]), set(questions))
        reply["answers"]["fit_1"]["probabilities"]["wait"] = 0.19
        with self.assertRaises(route.Unavailable) as failure:
            route.read_choices(reply, questions)
        diagnostic = str(failure.exception)
        self.assertIn("invalid_distribution_sum", diagnostic)
        self.assertIn("question_index=1", diagnostic)
        self.assertIn("question_id=fit_1", diagnostic)
        self.assertIn("observed_sum=0.99", diagnostic)
        self.assertNotIn("private-response-text", diagnostic)
        private_id = "private-request-identifier"
        reply["answers"][private_id] = reply["answers"].pop("fit_1")
        with self.assertRaises(route.Unavailable) as failure:
            route.read_choices(reply, {"fit_0": questions["fit_0"], private_id: questions["fit_1"]})
        self.assertIn("question_index=1", str(failure.exception))
        self.assertNotIn(private_id, str(failure.exception))

    def test_exhaustion_unknown_stale_and_reset_boundaries_do_not_call_provider(self):
        """What: Exhausted, unknown or stale quota never calls the provider.
        Why: Advice must not exceed observed budget.
        Verify: Clock-boundary fixtures and a request spy prove rejection.
        Detects: Speculative quota admitted to spending.
        """
        variants = []
        for index in range(3):
            exhausted = snapshot()
            exhausted["windows"][index].update(used_percent=100, remaining_percent=0)
            variants.append(exhausted)
        over = snapshot(); over["windows"][0].update(used_percent=105, remaining_percent=0); variants.append(over)
        unknown = snapshot(); unknown["windows"][0].update(used_percent=None, remaining_percent=None); variants.append(unknown)
        inconsistent = snapshot(); inconsistent["windows"][0]["remaining_percent"] = 99; variants.append(inconsistent)
        nonfinite = snapshot(); nonfinite["windows"][0]["used_percent"] = float("nan"); variants.append(nonfinite)
        boolean = snapshot(); boolean["windows"][0]["used_percent"] = True; variants.append(boolean)
        stale = snapshot(); stale["observed_at_utc"] = (datetime.now(timezone.utc) - timedelta(seconds=301)).isoformat(); variants.append(stale)
        future = snapshot(); future["observed_at_utc"] = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(); variants.append(future)
        reset = snapshot(); reset["windows"][0]["resets_at_utc"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(); variants.append(reset)
        missing = snapshot(); missing["windows"].pop(0); variants.append(missing)
        with patch.object(route, "call_api") as api, patch.object(route, "read_key") as key:
            for usage in variants:
                with self.subTest(usage=usage):
                    code, result = run_cli(packet(), usage)
                    self.assertEqual(code, 2)
                    self.assertFalse(result["request_attempted"])
        api.assert_not_called()
        key.assert_not_called()

    def test_dry_run_does_not_read_key_or_spend_budget(self):
        """What: Dry-run planning reads no credential and spends no advice attempt.
        Why: Inspection must remain read only.
        Verify: Credential and request spies plus a real ledger fixture.
        Detects: Dry run consuming paid authority.
        """
        with patch.object(route, "call_api") as api, patch.object(route, "read_key") as key:
            code, result = run_cli(packet(), snapshot(), ["--dry-run", "--gateway-config", "/missing"])
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["jev_requests_used_after"], {f"task-{i}": 0 for i in range(3)})
        api.assert_not_called(); key.assert_not_called()

    def test_provider_cannot_invent_plan_or_change_pinned_model(self):
        """What: Advice selects only a supplied plan and pinned model.
        Why: Provider output is evidence, not staffing authority.
        Verify: Invalid plan and model responses are rejected.
        Detects: Invented dispatch plan accepted.
        """
        replies = []
        wrong_model = response(); wrong_model["model"] = "jev-latest"; replies.append(wrong_model)
        unknown = response(); unknown["answers"]["staffing_plan"]["choice"] = "invented"; replies.append(unknown)
        distribution = response(); distribution["answers"]["staffing_plan"]["probabilities"]["three-starts"] = 0.1; replies.append(distribution)
        with patch.object(route, "read_key", return_value="fake"):
            for reply in replies:
                with self.subTest(reply=reply), patch.object(route, "call_api", return_value=reply):
                    code, result = run_cli(packet(), snapshot())
                    self.assertEqual(code, 2)
                    self.assertNotIn("plan", result)
                    self.assertEqual(result["jev_requests_used_after"]["task-0"], 1)

class EvidenceJournalContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / "run"
        self.packet = self.base / "outside-worker-packet.txt"
        self.packet.write_text("Frozen input\n")
        record.init(self.run, {"mode": "matched", "owner_task_id": "test", "question": "contract",
                              "limits": {"attempts": 1}, "configurations": {"test": "python"}})

    def prepare(self, boundary="process", attempt="a"):
        return record.prepare(self.run, attempt, self.packet, "test-model", "review", boundary)

    def verify(self, attempt="a", accepted=True):
        record.append(self.run, "check_start", attempt)
        evidence = self.base / f"{attempt}-evidence.json"
        evidence.write_text(json.dumps({"accepted": accepted}))
        record.check_end(self.run, attempt, accepted, evidence)

    def test_native_observation_is_measured_but_never_called_inference_time(self):
        """What: Native wall observation remains distinct from inference time.
        Why: Process timing cannot prove provider inference latency.
        Verify: Actual recorder boundary and explicit missing inference measurement.
        Detects: Unsupported inference-time claim.
        """
        self.prepare("native_observation")
        record.dispatch(self.run, "a")
        time.sleep(.002)
        record.finish(self.run, "a", "completed", "native")
        self.verify()
        row = record.report(self.run)["attempts"][0]
        self.assertGreater(row["measurements"]["dispatch_to_observed_completion_seconds"], 0)
        self.assertIsNone(row["measurements"]["process_seconds"])
        self.assertIsNone(row["measurements"]["provider_api_seconds"])
        self.assertIsNone(row["measurements"]["native_input_tokens"])

    def test_evidence_cannot_be_replaced_and_pending_is_not_complete(self):
        """What: Pending work cannot close complete and accepted evidence cannot be replaced.
        Why: Completion claims require settled immutable evidence.
        Verify: Real journal transitions reject replacement and pending close.
        Detects: False completion or changed evidence.
        """
        self.prepare()
        with self.assertRaises(ValueError):
            record.close(self.run, "complete")
        record.dispatch(self.run, "a")
        record.finish(self.run, "a", "launch_failed", "grok")
        with self.assertRaises(ValueError):
            record.finish(self.run, "a", "completed", "grok")
        record.append(self.run, "check_start", "a")
        with self.assertRaises(ValueError):
            record.check_end(self.run, "a", True, self.packet)
        record.check_end(self.run, "a", False, self.packet)
        record.close(self.run, "complete")
        with self.assertRaises(ValueError):
            record.prepare(self.run, "b", self.packet, "model", "review", "process")

    def test_provider_counters_preserve_unknowns_and_estimates(self):
        """What: Unknown counters and estimated cost retain their meaning.
        Why: Missing measurements must not become zero cash cost.
        Verify: Invalid scalar cases and independent literal counters.
        Detects: Fabricated counters or estimated cost labeled cash.
        """
        for value in (-1, float("nan"), float("inf"), True, "123", 1.5):
            with self.subTest(value=value):
                usage = record.extract_usage("grok", {"usage": {"input_tokens": value}})
                self.assertIsNone(usage["measurements"]["native_input_tokens"])
                self.assertIn("native_input_tokens", usage["unknown_reasons"])
        usage = record.extract_usage("claude", {"usage": {"input_tokens": 0, "output_tokens": 4},
                                               "total_cost_usd": .2, "modelUsage": {"opus": {"costBasis": "list"}}})
        self.assertEqual(usage["measurements"]["native_input_tokens"], 0)
        self.assertEqual(usage["measurements"]["provider_estimated_cost_usd"], .2)
        self.assertIsNone(usage["measurements"]["cash_cost_usd"])
        self.assertIn("list-price", usage["cost_basis"])
        qwen = record.extract_usage("qwen", {"model_instance_id": "qwen", "stats": {"total_output_tokens": 6}})
        self.assertEqual(qwen["measurements"]["native_output_tokens"], 6)
        self.assertIsNone(qwen["measurements"]["cash_cost_usd"])

    def test_sigterm_records_cancel_and_reaps_owned_process(self):
        """What: Cancellation records failure and reaps the owned child.
        Why: A cancelled run must not continue consuming resources.
        Verify: Real subprocess receives SIGTERM and its child PID disappears.
        Detects: Orphan process or cancellation reported as success.
        """
        self.prepare()
        pidfile = self.base / "child.pid"
        command = [sys.executable, record.__file__, "run", "--run", str(self.run), "--attempt", "a", "--",
                   sys.executable, "-c", f"import os,time,pathlib; pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(60)"]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(pidfile.exists())
            child_pid = int(pidfile.read_text())
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(record.report(self.run)["attempts"][0]["transport_status"], "cancelled")
            import os
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

class CurrentObservationContracts(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.config['models'].append({
            'id': 'grok-4.7', 'provider': 'xai', 'pool_alias': 'grok-default',
            'execution': {'kind': 'grok_cli', 'executable': '/mock/grok'},
            'billing_policy': 'subscription_only', 'enabled': True,
            'roles': ['implementation'],
        })
        self.config['preferences']['implementation'].append('grok-4.7')
        self.digest = 'a' * 64
        self.billing = {
            'subscription_tier': 'SuperGrok', 'on_demand_enabled': False,
            'config': {
                'creditUsagePercent': 40,
                'currentPeriod': {
                    'type': 'USAGE_PERIOD_TYPE_MONTHLY',
                    'start': (NOW - timedelta(hours=1)).isoformat(),
                    'end': (NOW + timedelta(hours=1)).isoformat(),
                },
            },
        }
        self.base = self.check()

    def check(self, status='session', listed=True):
        with patch.object(onboarding, '_probe_cli', return_value=('ready', 'authenticated')), \
             patch.object(onboarding, '_probe_local', return_value=('ready', 'loaded_model_observed')), \
             patch.object(grok_connection, 'probe', return_value=(status, listed)), \
             patch.object(grok_connection, 'observe_billing', return_value=(self.billing, 'grok_billing_observed')):
            return onboarding.check_config(self.config, self.digest, now=NOW)

    def smoke(self, model='grok-4.7'):
        receipt = deepcopy(self.base)
        receipt['observed_at'] = (NOW - timedelta(seconds=30)).isoformat()
        grok = receipt['models']['grok-4.7']
        grok.pop('grok_billing', None)
        grok.update(quota='unknown', reason='grok_catalog_observed')
        receipt['models'][model].update(
            auth_observed='ready', runtime_capability='ready',
            billing_status='ready', model_inference='ready',
            reason='bounded_grok_cli_smoke' if model == 'grok-4.7' else 'bounded_codex_cli_smoke',
        )
        return receipt

    def merge(self, response=None, base=None):
        return onboarding.merge_response_observation(
            self.config, self.digest, base or self.base, response or self.smoke(), now=NOW,
        )

    def test_current_local_runtime_must_still_be_available(self):
        """What: Local runtime must still be available after past success.
        Why: A previous inference is not current capacity.
        Verify: Current unavailable runtime plus old successful receipt.
        Detects: Stale runtime availability admitted.
        """
        response = deepcopy(self.base)
        response['models']['local-qwen'].update(model_inference='ready')
        current = deepcopy(self.base)
        current['models']['local-qwen'].update(runtime_capability='unknown', reason='runtime_unavailable')
        with self.assertRaisesRegex(onboarding.ConfigError, 'current_runtime_unconfirmed'):
            self.merge(response, current)

class SubscriptionObservationContracts(unittest.TestCase):
    def assert_rejected_before_credentials(self, variants):
        with patch.object(route, "call_api") as api, patch.object(route, "read_key") as key:
            for usage in variants:
                with self.subTest(usage=usage):
                    code, result = run_cli(grok_packet(), usage)
                    self.assertEqual(code, 2)
                    self.assertFalse(result["request_attempted"])
        api.assert_not_called(); key.assert_not_called()

    def test_stale_exhausted_and_invalid_quota_cannot_route(self):
        """What: Grok advice rejects invalid, exhausted, stale or already-reset subscription windows.
        Why: A subscription observation must establish current available quota before credentials are read.
        Verify: Literal invalid numbers, 100 percent use, inconsistent remaining quota, 301-second age and expired reset each return exit 2 with no attempted request or key read.
        Detects: Treating stale, exhausted or contradictory quota as current provider capacity.
        """
        variants = []
        for used in (None, True, -1, float("nan"), float("inf"), 100, 110):
            usage = grok_snapshot(); usage["windows"][0]["used_percent"] = used; variants.append(usage)
        mismatch = grok_snapshot(); mismatch["windows"][0]["remaining_percent"] = 38; variants.append(mismatch)
        stale = grok_snapshot(); stale["observed_at_utc"] = (datetime.now(timezone.utc) - timedelta(seconds=301)).isoformat(); variants.append(stale)
        reset = grok_snapshot(); reset["windows"][0]["resets_at_utc"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(); variants.append(reset)
        self.assert_rejected_before_credentials(variants)

class SharedQuotaContracts(unittest.TestCase):
    def test_unknown_bucket_scope_never_falls_back_to_legacy(self):
        """What: Codex advice refuses unrecognized current shared-bucket scope even when legacy quota looks valid.
        Why: Falling back would borrow authority from a different observation or model.
        Verify: Empty, malformed or multiple bucket maps, a changed model and unsupported individual limit return unsupported_codex_bucket_scope and make no key or transport call.
        Detects: Using a permissive legacy bucket to bypass failed current shared-quota admission.
        """
        variants = []
        for bad_map in ({}, [], {"codex": {}, "another-model": {}}):
            usage = codex_snapshot()
            usage["codex_usage"]["rateLimits"] = deepcopy(usage["codex_usage"]["rateLimitsByLimitId"]["codex"])
            usage["codex_usage"]["rateLimitsByLimitId"] = bad_map
            variants.append(usage)
        for field, value in (("normalModelSlug", "gpt-6-sol"), ("individualLimit", {})):
            usage = codex_snapshot()
            usage["codex_usage"]["rateLimitsByLimitId"]["codex"][field] = value
            variants.append(usage)
        self.assert_rejected_before_credentials(variants, "unsupported_codex_bucket_scope")

    def assert_rejected_before_credentials(self, variants, reason=None):
        with patch.object(route, "call_api") as api, patch.object(route, "read_key") as key:
            for usage in variants:
                with self.subTest(usage=usage):
                    code, result = run_cli(codex_packet(), usage)
                    self.assertEqual(code, 2)
                    self.assertFalse(result["request_attempted"])
                    if reason:
                        self.assertEqual(result["reason"], reason)
        api.assert_not_called()
        key.assert_not_called()

class LoadedRuntimeContracts(unittest.TestCase):
    def test_unknown_or_unready_runtime_rejects_before_auth_or_network(self):
        """What: Local Mac advice requires verified loopback, measured host capacity and the admitted loaded model.
        Why: Unavailable or unknown local runtime evidence cannot authorize execution.
        Verify: Independently alter loopback, billing lane, slot/memory observations and model load settings; require rejection before key reads or requests.
        Detects: Dispatching into an unready runtime or substituting another model or billing lane.
        """
        variants = []
        for key, value in (("intended_mac_loopback_verified", False), ("billing_lane", "Unknown local service")):
            usage = mac_snapshot(); usage[key] = value; variants.append(usage)
        for key, value in (("active_requests", None), ("active_requests", True),
                           ("slot_evidence", ""), ("memory_pressure_level", 4),
                           ("memory_pressure_level", None), ("free_percent", float("nan"))):
            usage = mac_snapshot(); usage["host"][key] = value; variants.append(usage)
        usage = mac_snapshot(); usage["local_model"]["loaded_instances"] = []; variants.append(usage)
        for key, value in (("parallel", 2), ("speculative_draft_mtp", True), ("context_length", 0)):
            usage = mac_snapshot(); usage["local_model"]["loaded_instances"][0]["config"][key] = value; variants.append(usage)
        with patch.object(route, "read_key") as auth, patch.object(route, "call_api") as api:
            for usage in variants:
                with self.subTest(usage=usage):
                    code, result = run_cli(mac_packet(), usage)
                    self.assertEqual(code, 2)
                    self.assertFalse(result["request_attempted"])
            auth.assert_not_called(); api.assert_not_called()

if __name__ == "__main__":
    unittest.main()
