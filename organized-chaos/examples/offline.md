# Offline first run

From the extracted `organized-chaos/` directory, run the packaged synthetic suite:

```sh
(cd scripts && PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover)
```

It exercises local approval, evidence, and routing decisions using fixtures. It does not contact a model provider or prove that a selected model is available. If it passes, read [onboarding](../references/onboarding.md) and configure private model choices outside this package. Keep unknown access or quota pending.

For a real authorized task, start with a bounded request such as:

> Use organized-chaos for this task. First show the goal, owned paths, dependencies, available models, and acceptance checks. Have the writer propose changes before editing.

The coordinator checks runtime access and capacity before dispatch, reviews the fixed patch with a different model, and accepts it only after behavior checks. [SKILL.md](../SKILL.md) and [delivery](../references/delivery.md) define those steps.
