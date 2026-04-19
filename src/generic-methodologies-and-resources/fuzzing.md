# Fuzzing Methodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, inputs are gemuteer terwyl hulle **grammar-valid** bly. In coverage-guided mode, only samples that trigger **new coverage** are saved as corpus seeds. For **language targets** (parsers, interpreters, engines), this can miss bugs that require **semantic/dataflow chains** where the output of one construct becomes the input of another.

**Failure mode:** the fuzzer finds seeds that individually exercise `document()` and `generate-id()` (or similar primitives), but **does not preserve the chained dataflow**, so the “closer-to-bug” sample is dropped because it doesn’t add coverage. With **3+ dependent steps**, random recombination becomes expensive and coverage feedback does not guide search.

**Implication:** for dependency-heavy grammars, consider **hybridizing mutational and generative phases** or biasing generation toward **function chaining** patterns (not just coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation is **greedy**: a new-coverage sample is saved immediately, often retaining large unchanged regions. Over time, corpora become **near-duplicates** with low structural diversity. Aggressive minimization can remove useful context, so a practical compromise is **grammar-aware minimization** that **stops after a minimum token threshold** (reduce noise while keeping enough surrounding structure to remain mutation-friendly).

A practical corpus rule for mutational fuzzing is: **prefer a small set of structurally different seeds that maximize coverage** over a large pile of near-duplicates. In practice, this usually means:

- Begin met **real-world samples** (public corpora, crawling, captured traffic, file sets from the target ecosystem).
- Distilleer them met **coverage-based corpus minimization** instead of om elke geldige sample te hou.
- Keep seeds **small enough** that mutations land on meaningful fields rather than spending most cycles on irrelevant bytes.
- Run corpus minimization again after major harness/instrumentation changes, because the “best” corpus changes when reachability changes.

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

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** wegsluit.
- Kombineer dit met **dictionaries** wat uit regte samples, protocol specs, of debug logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs, en delimiters is dikwels meer waardevol as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende checks uitvoer, los eers die vroegste “magic” comparisons op en minimaliseer dan die gevolglike corpus weer sodat latere stadiums vanaf reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences Are Seeds

Vir **protocols**, **authenticated workflows**, en **multi-stage parsers**, is die interessante eenheid dikwels nie ’n enkele blob nie maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blind te muteer is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer net die later message die brose state bereik.

’n Meer effektiewe patroon is om die **sequence self as die seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as addisionele feedback te gebruik:

- Hou **valid prefix messages** stabiel en fokus mutations op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhang.
- Verkies per-message mutation/splicing bo die mutering van die hele geserialiseerde transcript as ’n ondeursigtige blob.
- As die protocol betekenisvolle response codes blootstel, gebruik dit as ’n **cheap state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of “only-after-handshake” parser bugs dikwels gemis word deur vanilla file-style fuzzing: die fuzzer moet **order, state, and dependencies** bewaar, nie net struktuur nie.

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **kortstondige workers te herbegin** teen ’n volhoubare server. Elke worker begin vanaf ’n leë corpus, sync ná `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sync weer, en tree dan uit. Dit lewer **fresh structures each generation** terwyl dit steeds opgehoopte coverage benut.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Opeenvolgende werkers (voorbeeld-lus):**

<details>
<summary>Jackalope werker herbegin-lus</summary>
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

- `-in empty` dwing 'n **vars korpus** elke generasie af.
- `-server_update_interval T` benader **vertraagde sync** (nuutheid eerste, hergebruik later).
- In grammar fuzzing-modus word **aanvanklike server sync by verstek oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **teiken-afhanklik**; om te skakel nadat die worker die meeste “maklike” coverage gevind het, werk geneig die beste.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wanneer die kode wat jy wil toets eers bereikbaar raak **ná ’n groot opstelkoste** (om 'n VM te boot, 'n login te voltooi, 'n packet te ontvang, 'n container te parse, 'n service te initialiseer), is ’n nuttige alternatief **snapshot fuzzing**:

1. Run die target totdat die interessante state gereed is.
2. Snapshot **memory + registers** op daardie punt.
3. Vir elke test case, skryf die gemuteerde input direk in die relevante guest/process buffer.
4. Execute totdat crash/timeout/reset.
5. Restore slegs die **dirty pages** en herhaal.

Dit vermy dat jy die volle opstelkoste elke iterasie betaal en is veral nuttig vir **network services**, **firmware**, **post-auth attack surfaces**, en **binary-only targets** wat lastig is om in ’n klassieke in-process harness om te bou.

’n Praktiese truuk is om onmiddellik na ’n `recv`/`read`/packet-deserialization-punt te breek, die input buffer address aan te teken, daar te snapshot, en dan daardie buffer direk in elke iterasie te mutate. Dit laat jou toe om die diep parsing logic te fuzz sonder om elke keer die hele handshake te herbou.

## Harness Introspection: Find Shallow Fuzzers Early

Wanneer ’n campaign vasval, is die probleem dikwels nie die mutator nie maar die **harness**. Gebruik **reachability/coverage introspection** om functions te vind wat staties bereikbaar is vanaf jou fuzz target maar selde of nooit dinamies gedek word. Daardie functions dui gewoonlik op een van drie issues:

- Die harness gaan die target te laat of te vroeg binne.
- Die seed corpus mis ’n hele feature family.
- Die target benodig regtig ’n **second harness** in plaas van een oorgroot “do everything” harness.

As jy OSS-Fuzz / ClusterFuzz-styl workflows gebruik, is Fuzz Introspector nuttig vir hierdie triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of jy 'n nuwe harness moet byvoeg vir 'n ongetoetste parser path, die corpus vir 'n spesifieke feature moet uitbrei, of 'n monolitiese harness in kleiner entry points moet split.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
