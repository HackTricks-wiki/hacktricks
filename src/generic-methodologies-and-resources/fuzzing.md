# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, inputs are mutated while staying **grammar-valid**. In coverage-guided mode, only samples that trigger **new coverage** are saved as corpus seeds. For **language targets** (parsers, interpreters, engines), this can miss bugs that require **semantic/dataflow chains** where the output of one construct becomes the input to another.

**Failure mode:** the fuzzer finds seeds that individually exercise `document()` and `generate-id()` (or similar primitives), but **does not preserve the chained dataflow**, so the “closer-to-bug” sample is dropped because it doesn’t add coverage. With **3+ dependent steps**, random recombination becomes expensive and coverage feedback does not guide search.

**Implication:** for dependency-heavy grammars, consider **hybridizing mutational and generative phases** or biasing generation toward **function chaining** patterns (not just coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation is **greedy**: a new-coverage sample is saved immediately, often retaining large unchanged regions. Over time, corpora become **near-duplicates** with low structural diversity. Aggressive minimization can remove useful context, so a practical compromise is **grammar-aware minimization** that **stops after a minimum token threshold** (reduce noise while keeping enough surrounding structure to remain mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

A practical way to hybridize **generative novelty** with **coverage reuse** is to **restart short-lived workers** against a persistent server. Each worker starts from an empty corpus, syncs after `T` seconds, runs another `T` seconds on the combined corpus, syncs again, then exits. This yields **fresh structures each generation** while still leveraging accumulated coverage.

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequential workers (example loop):**

<details>
<summary>Jackalope worker restart loop</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Notes:**

- `-in empty` forces a **fresh corpus** each generation.
- `-server_update_interval T` approximates **delayed sync** (novelty first, reuse later).
- In grammar fuzzing mode, **initial server sync is skipped by default** (no need for `-skip_initial_server_sync`).
- Optimal `T` is **target-dependent**; switching after the worker has found most “easy” coverage tends to work best.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
