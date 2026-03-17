# Juliet Subset Eval (C/C++)

This eval is designed to be **more realistic than the synthetic dataset** by running SentinelAgent on a small subset of the Juliet C/C++ test suite.

Important: this repo does **not** vendor the Juliet test suite. You must download it yourself and generate a local subset using the builder.

## 1) Build a local subset

From the repo root:

```bash
python -m eval.juliet_subset.builder \
  --juliet-root /path/to/Juliet_Test_Suite_v1.3_for_C_Cpp \
  --out-dir eval/juliet_subset/samples \
  --per-cwe 20 \
  --seed 7
```

This creates ~60 sample directories (3 CWEs × 20 samples), each containing:
- one Juliet source file
- `metadata.json` with `cwe_id` and `expected_vulnerable`

The generated samples live under `eval/juliet_subset/samples/` and are ignored by git.

## 2) Run the eval

```bash
python -m eval.juliet_subset.evaluator --samples-dir eval/juliet_subset/samples
```

By default the evaluator runs:
- **Agent**: `sentinel_agent.graph.run_agent()`
- **Baseline**: cppcheck-only (via `sentinel_agent.tools.cppcheck.CppcheckTool`)

## Notes

- Set `SENTINEL_OFFLINE=1` for deterministic (no-LLM) mode.
- The builder uses filename heuristics (`good` vs `bad`) to set `expected_vulnerable`.
