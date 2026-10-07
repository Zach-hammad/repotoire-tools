# Match model evidence to task needs

Read before composing Jev fit questions. This is a coordinator recipe using existing packet fields; no profile loader or automatic research service is bundled.

## Prepare once, refresh when relevant

1. **Identify selected models.** Resolve each runtime ID to its upstream model/version when possible. Record harness, reasoning setting, tools, effective context, and local quantization. Keep unresolved aliases explicit. A local alias does not inherit another model's benchmark score.
2. **Collect relevant evidence.** Start with official model cards, technical reports, and benchmark maintainers. Record exact benchmark variant, metric, result, sample size when available, and evaluation conditions. Separate vendor claims, benchmark measurements, local observations, and coordinator inferences. Use `unknown` for absent details.
3. **Store a compact profile.** Keep profiles outside this package, alongside user configuration. Reuse verified sources. Refresh affected claims when model identity, runtime, task needs, source results, or observed performance changes. Dates establish provenance, not automatic expiry. Research only gaps material to this task.
4. **Match the role.** Describe the task with the template below. Copy relevant profile evidence into `models[].fit_evidence`; express each necessary semantic capability in `tasks[].qualification_criteria`. Put operational gates in the existing access/capacity fields. Batch independent writer and reviewer questions.
5. **Learn from results.** Append accepted outcomes and verified failures to the external profile, including revision, harness, checks, corrections, and cost/time when measured. Preserve contradictory evidence. A single success is limited evidence; an absent local receipt is not a demonstrated failure.

## Profile template

Use one record per model/runtime combination. This Markdown template is coordinator input, not a new JSON schema.

```text
Selected runtime ID / upstream identity / identity evidence:
Runtime: harness, reasoning, tools, effective context, quantization:
Evidence claim and capability dimension:
  Kind: vendor claim | benchmark measurement | local observation
  Source URL or local receipt; checked date; source date if available:
  Result, metric, benchmark variant, sample size, conditions:
  Known limitations or contradictory evidence:
Task relevance: direct | transferable with limits | unknown
  Coordinator inference and runtime differences:
Unknowns that matter for this task:
Cost and speed: actual billing lane; measured values or unknown:
```

Keep billing and speed in the local profile for preference decisions. Supply only relevant capability evidence to Jev; code owns cost and capacity decisions. API prices do not describe subscription quota or local inference costs.

## Task template

```text
Role and bounded outcome:
Required capabilities: language/domain, change complexity, tools:
Working context needed / available runtime context:
Risk and review obligations:
Acceptance checks:
Qualification criteria: one capability judgment per criterion:
```

Choose requirements before considering candidates. Avoid making a previous identical task a criterion unless the contract actually requires demonstrated experience. A coding benchmark can inform drafting suitability; it does not establish security-review ability or production readiness.

## Turn the contract into atomic questions

1. List the distinct capabilities needed for this role, such as Python edits, regression-test design, or HTTP trust-boundary review. Split a criterion when evidence could support one part but leave another unknown.
2. Keep access, selected-model membership, context limits, quota, review independence, and readiness in coordinator checks or existing operational fields. Jev evaluates semantic fit, not those gates.
3. Attach relevant evidence and its limits for each capability. A URL alone supplies no evidence: Jev does not fetch it. Missing evidence remains an explicit unknown.
4. Batch one Choice per eligible model and required capability. All criteria are mandatory; do not add nice-to-have dimensions as requirements. Separate review criteria belong to the reviewer task.
5. Read each criterion outcome before composing a plan. Code requires every criterion to pass the task's confidence threshold, then applies the complete declared model preference order and capacity limits. This preserves an inexpensive-first preference without asking Jev to estimate prices.

Broad question: “Can this model implement and test a secure onboarding wizard?” Better questions: “Does the evidence support bounded Python edits?” and “Does it support deriving regression cases from acceptance requirements?” Security acceptance still needs its own qualified review; decomposition does not remove that obligation.

## Worked packet fragments

The following evidence is **fictional** and illustrates shape only. Merge these fields into a complete packet; the fragments are not runnable packets.

```json
{
  "fit_evidence": "Fictional example: selected writer-v1 is the exact model in benchmark B, Python-fixes variant, revision r1. It resolved 72/100 tasks under harness H (fictional source https://example.org/benchmarks/B/r1; source date and checked date 2026-01-01). Current harness J differs; transfer to bounded Python drafting is plausible but unverified. No local Python outcome yet. No security-review evidence. Effective context is 16000 tokens; task estimate is 6000. These are research priors, not task-success probabilities."
}
```

```json
{
  "contract": "Draft a Python loopback setup form against the supplied design. A separate reviewer checks session, origin, and credential handling before acceptance.",
  "qualification_criteria": {
    "python_edits": "Evidence supports drafting bounded Python changes under the stated runtime.",
    "regression_cases": "Evidence supports deriving regression test cases from the supplied acceptance requirements."
  }
}
```

The fictional Python-fixes measurement is relevant to `python_edits`, though Jev may abstain if transfer is unclear. It says nothing specific about designing regression cases: `regression_cases` may remain insufficient. Even if Python edits pass, the model stays unqualified until both required criteria pass. These are illustrative possibilities, not a measured Jev response. For an unknown quantized alias, establish its identity and runtime before transferring this benchmark claim. Security review needs separate evidence and criteria; drafting results cannot answer it.

Use the dry-run command in [routing](routing.md) to validate the complete packet. Uncertainty leaves the existing threshold, request budget, and fallback policy intact. A profile update does not reset spent requests or authorize dispatch.

## Research references

- [TypeSafe questions](https://docs.typesafe.ai/primitives): batch independent questions over shared state; combine answers in code. Dependent answers require a later request.
- [SWE-bench](https://www.swebench.com/): distinguish benchmark variants and agent environments. Its Bash Only view standardizes the environment, which matters when comparing results.

These sources inform the recipe. They do not qualify any selected model; each profile needs its own evidence.
