# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, inputs are mutated while staying **grammar-valid**. In coverage-guided mode, only samples that trigger **new coverage** are saved as corpus seeds. For **language targets** (parsers, interpreters, engines), this can miss bugs that require **semantic/dataflow chains** where the output of one construct becomes the input of another.

**Failure mode:** the fuzzer finds seeds that individually exercise `document()` and `generate-id()` (or similar primitives), but **does not preserve the chained dataflow**, so the “closer-to-bug” sample is dropped because it doesn’t add coverage. With **3+ dependent steps**, random recombination becomes expensive and coverage feedback does not guide search.

**Implication:** for dependency-heavy grammars, consider **hybridizing mutational and generative phases** or biasing generation toward **function chaining** patterns (not just coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation is **greedy**: a new-coverage sample is saved immediately, often retaining large unchanged regions. Over time, corpora become **near-duplicates** with low structural diversity. Aggressive minimization can remove useful context, so a practical compromise is **grammar-aware minimization** that **stops after a minimum token threshold** (reduce noise while keeping enough surrounding structure to remain mutation-friendly).

A practical corpus rule for mutational fuzzing is: **prefer a small set of structurally different seeds that maximize coverage** over a large pile of near-duplicates. In practice, this usually means:

- Start from **real-world samples** (public corpora, crawling, captured traffic, file sets from the target ecosystem).
- Distill them with **coverage-based corpus minimization** instead of keeping every valid sample.
- Keep seeds **small enough** that mutations land on meaningful fields rather than spending most cycles on irrelevant bytes.
- Re-run corpus minimization after major harness/instrumentation changes, because the “best” corpus changes when reachability changes.

## Comparison-Aware Mutation For Magic Values

A common reason fuzzers plateau is not syntax but **hard comparisons**: magic bytes, length checks, enum strings, checksums, or parser dispatch values guarded by `memcmp`, switch tables, or cascaded comparisons. Pure random mutation wastes cycles trying to guess these values byte-by-byte.

For these targets, use **comparison tracing** (for example AFL++ `CMPLOG` / Redqueen-style workflows) so the fuzzer can observe operands from failed comparisons and bias mutations toward values that satisfy them.

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Practical notes:**

- This is especially useful when the target gates deep logic behind **file signatures**, **protocol verbs**, **type tags**, or **version-dependent feature bits**.
- Pair it with **dictionaries** extracted from real samples, protocol specs, or debug logs. A small dictionary with grammar tokens, chunk names, verbs, and delimiters is often more valuable than a massive generic wordlist.
- If the target performs many sequential checks, solve the earliest “magic” comparisons first and then minimize the resulting corpus again so later stages start from already-valid prefixes.

## Stateful Fuzzing: Sequences Are Seeds

For **protocols**, **authenticated workflows**, and **multi-stage parsers**, the interesting unit is often not a single blob but a **message sequence**. Concatenating the whole transcript into one file and mutating it blindly is usually inefficient because the fuzzer mutates every step equally, even when only the later message reaches the fragile state.

A more effective pattern is to treat the **sequence itself as the seed** and use **observable state** (response codes, protocol states, parser phases, returned object types) as additional feedback:

- Keep **valid prefix messages** stable and focus mutations on the **transition-driving** message.
- Cache identifiers and server-generated values from prior responses when the next step depends on them.
- Prefer per-message mutation/splicing over mutating the whole serialized transcript as an opaque blob.
- If the protocol exposes meaningful response codes, use them as a **cheap state oracle** to prioritize sequences that progress deeper.

This is the same reason authenticated bugs, hidden transitions, or “only-after-handshake” parser bugs are often missed by vanilla file-style fuzzing: the fuzzer must preserve **order, state, and dependencies**, not just structure.

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

## Snapshot Fuzzing For Hard-To-Harness Targets

When the code you want to test only becomes reachable **after a large setup cost** (booting a VM, completing a login, receiving a packet, parsing a container, initializing a service), a useful alternative is **snapshot fuzzing**:

1. Run the target until the interesting state is ready.
2. Snapshot **memory + registers** at that point.
3. For every test case, write the mutated input directly into the relevant guest/process buffer.
4. Execute until crash/timeout/reset.
5. Restore only the **dirty pages** and repeat.

This avoids paying the full setup cost every iteration and is especially useful for **network services**, **firmware**, **post-auth attack surfaces**, and **binary-only targets** that are painful to refactor into a classic in-process harness.

A practical trick is to break immediately after a `recv`/`read`/packet-deserialization point, note the input buffer address, snapshot there, and then mutate that buffer directly in each iteration. This lets you fuzz the deep parsing logic without rebuilding the entire handshake every time.

## Harness Introspection: Find Shallow Fuzzers Early

When a campaign stalls, the problem is often not the mutator but the **harness**. Use **reachability/coverage introspection** to find functions that are statically reachable from your fuzz target but rarely or never covered dynamically. Those functions usually indicate one of three issues:

- The harness enters the target too late or too early.
- The seed corpus is missing a whole feature family.
- The target really needs a **second harness** instead of one oversized “do everything” harness.

If you use OSS-Fuzz / ClusterFuzz-style workflows, Fuzz Introspector is useful for this triage:

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

If you already have **static-analysis findings**, **mutation-testing survivors**, and **coverage reports**, don't triage them as independent lists. Build a **call graph** first, annotate nodes with **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, and any external findings, then ask graph questions:

- Which high-complexity functions are reachable from untrusted input?
- Which mutation survivors sit on paths from parsers/handlers to security-critical code?
- Which functions are architectural choke points with unusually high **blast radius**?

This usually surfaces better fuzz targets than "lowest coverage" alone. A parser/decoder with **high complexity** and confirmed **external reachability** is a stronger harness candidate than an isolated internal helper with weak coverage but no attacker-controlled path.

### Practical triage workflow

1. Build a **code graph** from the codebase and extract per-function complexity/branch metrics.
2. Enumerate **entrypoints** that accept attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Run **path queries** from those entrypoints to candidate functions to separate reachable attack surface from dead/internal-only code.
4. Prioritize nodes that combine:
   - high **cyclomatic complexity**
   - confirmed **reachability from untrusted input**
   - high **blast radius** or many downstream dependents
   - corroborating evidence such as **SARIF** findings, audit notes, or mutation survivors
5. Write focused harnesses for the best-scoring nodes first, especially **parsers/codecs** such as hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing often produces a noisy survivor list. Before treating every survivor as a security gap, use the graph to ask:

- Is the mutated function reachable from an attacker-controlled entrypoint?
- Are all call paths constrained by stronger invariants than the mutated check?
- Does the node sit in dead code, formatting-only logic, or in a high-impact arithmetic/parser path?

Survivors that remain unreachable or structurally constrained are often **equivalent mutants**. Survivors that stay **reachable** and touch **boundary conditions**, **overflow/carry paths**, or **security-critical arithmetic/parsing** should be promoted into:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

If your SAST pipeline exports **SARIF**, project findings onto graph nodes by **file + line range** and use the graph to expand the impact:

- compute the **blast radius** of the flagged function
- check whether the finding is on any path from an entrypoint
- cluster nearby findings that collapse into the same choke point

This is useful when deciding whether to spend fuzzing time on a specific function: a node that is **reachable**, **complex**, and already has **SAST hits** is often a better target than a merely complex node with no attacker path.

Example workflow with Trailmark:

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

The important methodology is the intersection: **complexity x exposure x impact**. Use the graph to pick fuzz targets with the highest expected security value, then use mutation survivors to decide which boundaries and invariants your harness must stress.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
