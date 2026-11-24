# CTX benchmarks

The [main README](../README.md#benchmark-highlights) contains the results.

From the CTX root, run the local synthetic benchmark without model calls:

```bash
python3 -B benchmarks/run_benchmark.py --synthetic-only
```

The same runner accepts a list of live Antigravity tasks through
`--tasks-json`. Each entry specifies a question and the expected source
anchors:

```json
[
  {
    "id": "method_definition",
    "question": "Find the exact file and line that defines targetMethod.",
    "anchors": [["MyModule.cpp", ["MyModule::targetMethod("]]]
  }
]
```

```bash
python3 -B benchmarks/run_benchmark.py --workspace /path/to/repo \
  --tasks-json tasks.json --agy-model gemini-4-carbon-low
```
