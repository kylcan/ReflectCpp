# SentinelAgent Eval

This folder contains a lightweight, reproducible evaluation harness.

## What it measures
- **Precision / Recall / F1** over expected CWEs per sample
- **False positive rate**
- **Reflection delta**: how many candidates were rejected/confirmed after the critic phase

## Quick start

Generate a deterministic dataset (60 cases) and run the eval:

```bash
python -m eval.run_eval --regen
```

Run without regeneration (uses existing dataset files):

```bash
python -m eval.run_eval
```

## Dataset format

- Index: `eval/dataset/cases.jsonl`
- Each case points to a **repo directory** via `repo_path`, e.g. `eval/dataset/repos/<case_id>/`
- The runner passes that directory to the agent so it can exercise repo mapping, file reading, grep, etc.

## Notes
- Set `SENTINEL_OFFLINE=1` to force deterministic (no-LLM) mode.
- Dataset is synthetic and intentionally small/fast; it is meant for CI and iteration.
