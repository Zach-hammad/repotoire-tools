# Single-file exact-byte approval gate

Use `scripts/worker_gate.py` when a coordinator has received and reviewed an exact source replacement for one existing file. The gate validates the complete inventory with onboarding's authoritative schema validator, then checks the selected implementation entry against gate-specific adapter and billing requirements before binding the proposal to coordinator approval and the original baseline. A malformed inventory entry blocks preparation even when it is unrelated to the selected model. Its `implement` command does not launch a worker or call a model: the assigned `local-deterministic` executor materializes only the approved bytes, reads the saved candidate back, verifies exact bytes and SHA-256, and records a receipt. The coordinator owns tests, review, and final integration.

## Coordinator procedure

1. Obtain a proposal through the normal worker proposal process. Save its exact source as `replacement.py` outside the target directory and review it with its verification plan.
2. Capture the proposal. Read `proposal.json` and record the returned SHA-256 identity. `prepare` performs no model call and does not approve implementation.
3. Approve only the reviewed identity.
4. Run `implement` once. It consumes approval before deterministic application and saves a verified candidate beside the proposal, or a failed receipt.
5. Run behavior checks and independent review against the candidate. Integrate only after rechecking the original baseline. The gate itself never writes the original target.

Example:

```sh
python3 scripts/worker_gate.py prepare \
  --state /absolute/coordinator/task-1 \
  --target /absolute/project/clamp.py \
  --replacement /absolute/coordinator/replacement.py \
  --inventory /absolute/config/inventory.json \
  --model YOUR_SELECTED_MODEL

# Inspect task-1/proposal.json before approving its printed identity.
python3 scripts/worker_gate.py approve \
  --state /absolute/coordinator/task-1 --reviewed-sha256 REVIEWED_SHA256

python3 scripts/worker_gate.py implement --state /absolute/coordinator/task-1
```

The state directory must be new; its parent must exist. Source files are UTF-8 replacements up to 32 KiB. Keep state outside worker custody. Inventory selection remains part of the approved snapshot and is rechecked; it establishes eligibility, not that the selected model executed the application. Existing inventory billing, access, quota, and routing checks remain prerequisites.

## Final integration

After the candidate passes checks, recheck the original baseline and copy the candidate with binary file I/O. Read the saved target back and compare its SHA-256 with `candidate_sha256` in the successful receipt. A mismatch leaves integration unaccepted.

The saved source is the approved source, including its final newline (or absence), line endings, indentation, and trailing spaces. Applying it performs no formatting, trimming, newline insertion, or code-fence removal. Extract source from a worker response and perform any required formatting before review and approval. If checks require a formatting change, review and approve the changed source before applying it.

## What the gate proves

Matching approval binds the exact proposal, original path and baseline, selected inventory record, and inventory snapshot. Missing approval, changed inputs, or an already consumed attempt blocks application. An attempt is consumed before application, including failures. A process crash can leave `attempt.json` without `result.json`; treat it as consumed and unresolved.

The executor is local deterministic code. It does not contact a provider, generate or load a model, or infer a replacement. It writes only the approved source into a candidate file, verifies the candidate's saved bytes and SHA-256, and reports `executor: local-deterministic`. A candidate that fails readback or a final baseline/configuration/cancellation check is removed when owned by the attempt and receives a failed receipt. The original target remains unchanged. Cancellation observed before the final acceptance check prevents candidate acceptance; that final check is the commit boundary, and later signals do not revoke an accepted result. SIGKILL, process crashes, or host failure can still leave `attempt.json` without `result.json`. This verifies code identity, not correctness.

Coordinator records and file checks are not a security boundary against a malicious process running as the same OS user. Avoid concurrent writers to coordinator state. After integration, retain proposal and verification evidence under the task's normal custody rules.

## Offline verification

```sh
cd scripts
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_worker_gate test_local_worker test_worker_gate_signals -v
```

Tests use disposable files and named dummy CLI executables, a loopback fixture for the standalone local adapter, and real Python child processes for shared-runner pipe behavior. They exercise complete-inventory schema validation, adapter and selection checks, approval, stale inputs, exact-byte application, failed readback, replay prevention, cancellation, and zero transport calls from the deterministic gate. They do not establish provider access, billing, live inference, or hostile-process containment.
