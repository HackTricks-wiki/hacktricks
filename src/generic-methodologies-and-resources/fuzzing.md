# Fuzzing Methodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, inputs are gemuteer terwyl hulle **grammar-valid** bly. In coverage-guided mode, only samples that trigger **new coverage** are saved as corpus seeds. For **language targets** (parsers, interpreters, engines), this can miss bugs that require **semantic/dataflow chains** where the output of one construct becomes the input of another.

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
**Praktiese notas:**

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** verberg.
- Kombineer dit met **dictionaries** wat uit regte monsters, protocol specs, of debug logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs, en delimiters is dikwels meer waardevol as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic” vergelykings op en minimaliseer dan die gevolglike corpus weer sodat latere stadiums vanaf reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences Are Seeds

Vir **protocols**, **authenticated workflows**, en **multi-stage parsers**, is die interessante eenheid dikwels nie ’n enkele blob nie maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die latere message die brose toestand bereik.

’n Meer effektiewe patroon is om die **sequence self as die seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as addisionele terugvoer te gebruik:

- Hou **valid prefix messages** stabiel en fokus mutasies op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo mutering van die hele geserialiseerde transcript as ’n ondeursigtige blob.
- As die protocol betekenisvolle response codes blootstel, gebruik hulle as ’n **cheap state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of “only-after-handshake” parser bugs dikwels gemis word deur vanilla file-style fuzzing: die fuzzer moet **order, state, and dependencies** behou, nie net struktuur nie.

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **kortlewende workers te herbegin** teen ’n persistente server. Elke worker begin met ’n leë corpus, sync na `T` sekondes, loop nog `T` sekondes op die combined corpus, sync weer, en sluit dan af. Dit lewer **fresh structures each generation** terwyl dit steeds die opgehoopte coverage benut.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Agtereenvolgende werkers (voorbeeld-lus):**

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

**Notas:**

- `-in empty` forseer 'n **nuwe korpus** elke generasie.
- `-server_update_interval T` benader **vertraagde sync** (nuutheid eerste, hergebruik later).
- In grammar fuzzing-modus word **aanvanklike server sync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **teiken-afhanklik**; om te skakel nadat die worker die meeste “maklike” coverage gevind het, werk geneig die beste.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wanneer die code wat jy wil test eers bereikbaar word **ná 'n groot setup-koste** (om 'n VM te boot, 'n login te voltooi, 'n packet te ontvang, 'n container te parse, 'n service te initialiseer), is 'n nuttige alternatief **snapshot fuzzing**:

1. Run die target totdat die interessante state gereed is.
2. Snapshot **memory + registers** op daardie punt.
3. Vir elke test case, skryf die gemuteerde input direk in die relevante guest/process buffer.
4. Execute totdat crash/timeout/reset.
5. Restore slegs die **dirty pages** en herhaal.

Dit vermy om die volle setup-koste by elke iterasie te betaal en is veral nuttig vir **network services**, **firmware**, **post-auth attack surfaces**, en **binary-only targets** wat pynlik is om in 'n klassieke in-process harness te refactor.

'n Praktiese truuk is om onmiddellik te breek ná 'n `recv`/`read`/packet-deserialization-punt, die input buffer address aan te teken, daar te snapshot, en dan daardie buffer direk in elke iterasie te mutate. Dit laat jou toe om die diep parsing logic te fuzz sonder om die hele handshake elke keer te rebuild.

## Harness Introspection: Find Shallow Fuzzers Early

Wanneer 'n campaign vasval, is die probleem dikwels nie die mutator nie maar die **harness**. Gebruik **reachability/coverage introspection** om functions te vind wat staties bereikbaar is vanaf jou fuzz target maar selde of nooit dinamies covered word. Daardie functions dui gewoonlik op een van drie issues:

- Die harness gaan die target te laat of te vroeg binne.
- Die seed corpus ontbreek 'n hele feature family.
- Die target het regtig 'n **second harness** nodig in plaas van een oorgroot “do everything” harness.

As jy OSS-Fuzz / ClusterFuzz-style workflows gebruik, is Fuzz Introspector nuttig vir hierdie triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of jy ’n nuwe harness moet byvoeg vir ’n ongetoetste parser-pad, die corpus moet uitbrei vir ’n spesifieke feature, of ’n monolitiese harness in kleiner entry points moet verdeel.

## Graph-First Fuzz Target Selection And Mutation Triage

As jy reeds **static-analysis findings**, **mutation-testing survivors**, en **coverage reports** het, moenie dit as onafhanklike lyste triageer nie. Bou eers ’n **call graph**, annoteer nodusse met **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, en enige eksterne findings, en vra dan graph-vrae:

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf untrusted input?
- Watter mutation survivors sit op paaie van parsers/handlers na security-critical code?
- Watter funksies is argitektoniese choke points met ongewoon hoë **blast radius**?

Dit onthul gewoonlik beter fuzz targets as net "lowest coverage" alleen. ’n Parser/decoder met **high complexity** en bevestigde **external reachability** is ’n sterker harness-kandidaat as ’n geïsoleerde interne helper met swak coverage maar geen attacker-controlled path nie.

### Practical triage workflow

1. Bou ’n **code graph** van die codebase en onttrek per-funksie complexity/branch metrics.
2. Lys **entrypoints** wat attacker-controlled input aanvaar: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Run **path queries** vanaf daardie entrypoints na kandidaat-funksies om reachable attack surface van dead/internal-only code te skei.
4. Prioritiseer nodusse wat kombineer:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** of baie downstream dependents
- corroborating evidence soos **SARIF** findings, audit notes, of mutation survivors
5. Skryf gefokusde harnesses vir die beste-scoring nodusse eerste, veral **parsers/codecs** soos hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing lewer dikwels ’n raserige survivor-lys. Voordat jy elke survivor as ’n security gap behandel, gebruik die graph om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n attacker-controlled entrypoint?
- Word alle call paths beperk deur sterker invariants as die gemuteerde check?
- Sit die node in dead code, formatting-only logic, of in ’n high-impact arithmetic/parser path?

Survivors wat steeds unreachable of struktureel beperk bly, is dikwels **equivalent mutants**. Survivors wat **reachable** bly en **boundary conditions**, **overflow/carry paths**, of **security-critical arithmetic/parsing** raak, moet gepromoveer word na:

- nuwe fuzz harnesses
- direkte property/invariant tests
- geteikende edge-case vectors

### Correlate external findings onto the graph

As jou SAST-pyplyn **SARIF** uitvoer, projekteer findings op graph-nodes volgens **file + line range** en gebruik die graph om die impak uit te brei:

- bereken die **blast radius** van die gemerkte funksie
- kyk of die finding op enige pad vanaf ’n entrypoint is
- groepeer nabye findings wat in dieselfde choke point saamval

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd op ’n spesifieke funksie moet spandeer: ’n node wat **reachable**, **complex**, en reeds **SAST hits** het, is dikwels ’n beter target as ’n bloot komplekse node sonder attacker path.

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
Die belangrike metodologie is die snypunt: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutation survivors om te besluit watter grense en invariants jou harness moet stres.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
