---
name: organized-chaos
description: Coordinates delivery when users ask to split a large task across agents or models, run independent issues in parallel, or land dependent changes in order. Includes model onboarding, bounded delegation, independent review, and ordered acceptance.
---

# Organized Chaos

Turn an authorized goal into independently verifiable tasks. Use the user's selected models and access methods. The lead owns scope and acceptance. Jev chooses a staffing plan from options admitted by the coordinator, using availability and usage. The coordinator owns validation and dispatch.

1. **Select available models.** On first use, follow [onboarding](references/onboarding.md). Keep model choices, role preferences, billing policy, and routing policy in user configuration outside this package. Read `~/.config/organized-chaos/routing.md` when present; preserve it during updates. Refresh access and shared-usage evidence before staffing. Authentication, model availability, remaining quota, and task suitability are separate facts. Unsupported or unknown access stays pending.
2. **Define tasks before staffing.** Record outcomes, owned paths, acceptance checks, dependencies, and retirement order. Use the table below. Record required tools, context size, and execution constraints. Use available Symbol FS evidence to bound the code context; it does not establish model quality. Independent tasks may overlap when custody and capacity permit; dependent tasks start from accepted prerequisites. Verify consequential repository claims against source.
3. **Assign bounded work.** Follow [routing](references/routing.md). Default to local-first implementation and routine work, then balance overflow and reviews across the user's selected models. Check access, context capacity, current workload, and shared quota. Give the adapter capacity-valid plans; it selects a sole plan locally and asks Jev to choose among multiple plans based on usage balance. Do not require model-quality proof, qualification criteria, or a suitability confidence threshold. Exclude the patch's author model from its review. Jev suitability experiments remain separate opt-in work. Give each writer an outcome, owned paths, limits, and required evidence. Every model worker first proposes code changes without editing; the coordinator approves the proposal and scope before implementation. Follow the [proposal and approval procedure](references/delivery.md#proposal-before-implementation). For an already reviewed exact source replacement, the coordinator may assign the [single-file gate](references/worker-gate.md) to apply approved bytes deterministically; this executor does not dispatch a model.
4. **Verify, review, and accept in order.** Follow [delivery](references/delivery.md). Run behavior checks, freeze the patch, and obtain independent review. Validate findings against source. A completed worker result remains provisional until its acceptance checks pass on the cumulative accepted state. Retire only the next eligible task; a failed prerequisite blocks dependent acceptance.
5. **Report evidence and stop.** Use the receipt below. Separate edited, tested, installed, merged, and deployed states. Report unavailable checks and unresolved findings. Claim cost savings only from comparable measured runs, including coordination and failures. Skill updates require user authorization.

| Order / ID | Outcome and acceptance check | Prerequisites | Owned paths | Model / budget | State |
| --- | --- | --- | --- | --- | --- |
| 1 / A | Define contract; boundary checks pass | None | Contract files | Configured writer | Ready |
| 2 / B | Consume contract; journey passes | A accepted | Consumer files | Configured writer | Waiting for A |
| 3 / C | Independent documentation verified | None | Documentation | Configured writer | Ready |

```text
Decision: accepted | rejected | needs-evidence
Accepted tasks and exact revision:
Verification and independent review:
Unresolved findings, owner, next action:
Files changed and installation/delivery state:
```
