# Fuzzing Methodologie

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
**Praktiese notas:**

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** wegsteek.
- Kombineer dit met **dictionaries** wat uit werklike samples, protocol specs, of debug logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs, en delimiters is dikwels meer waardevol as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende checks uitvoer, los eers die vroegste “magic” comparisons op en minimaliseer dan die gevolglike corpus weer sodat latere stages vanaf reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences Are Seeds

Vir **protocols**, **authenticated workflows**, en **multi-stage parsers**, is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blindelings te mutate is gewoonlik ondoeltreffend, omdat die fuzzer elke stap ewe veel mutate, selfs wanneer net die latere message die brose state bereik.

’n Meer effektiewe patroon is om die **sequence self as die seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as bykomende feedback te gebruik:

- Hou **valid prefix messages** stabiel en fokus mutations op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo die mutating van die hele serialized transcript as ’n ondeursigtige blob.
- As die protocol betekenisvolle response codes blootstel, gebruik hulle as ’n **cheap state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of “only-after-handshake” parser bugs dikwels gemis word deur vanilla file-style fuzzing: die fuzzer moet **orde, state, en dependencies** behou, nie net struktuur nie.

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer is om **short-lived workers** teen ’n persistent server te herbegin. Elke worker begin vanaf ’n leë corpus, sync na `T` sekondes, hardloop nog `T` sekondes op die combined corpus, sync weer, en sluit dan af. Dit lewer **fresh structures each generation** terwyl dit steeds opgehoopte coverage benut.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Aaneenlopende werkers (voorbeeld-lus):**

<details>
<summary>Jackalope worker herbegin-lus</summary>
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

- `-in empty` forseer ’n **vars korpus** elke generasie.
- `-server_update_interval T` benader **vertraagde sync** (nuutheid eerste, hergebruik later).
- In grammar fuzzing mode word **initial server sync by default oorgeslaan** (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **target-dependent**; om oor te skakel nadat die worker die meeste “easy” coverage gevind het, werk geneig die beste.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wanneer die code wat jy wil test eers bereikbaar word **ná ’n groot setup cost** (’n VM boot, ’n login voltooi, ’n packet ontvang, ’n container parse, ’n service initialiseer), is ’n nuttige alternatief **snapshot fuzzing**:

1. Run die target totdat die interesting state gereed is.
2. Snapshot **memory + registers** op daardie punt.
3. Vir elke test case, skryf die gemuteerde input direk in die relevante guest/process buffer.
4. Execute totdat crash/timeout/reset.
5. Restore slegs die **dirty pages** en herhaal.

Dit vermy die volle setup cost by elke iterasie en is veral nuttig vir **network services**, **firmware**, **post-auth attack surfaces**, en **binary-only targets** wat lastig is om in ’n klassieke in-process harness om te bou.

’n Praktiese trick is om onmiddellik na ’n `recv`/`read`/packet-deserialization point te break, die input buffer address aan te teken, daar te snapshot, en dan daardie buffer direk in elke iterasie te mutate. Dit laat jou die deep parsing logic fuzz sonder om die hele handshake elke keer weer op te bou.

## Harness Introspection: Find Shallow Fuzzers Early

Wanneer ’n campaign stagneer, is die probleem dikwels nie die mutator nie maar die **harness**. Gebruik **reachability/coverage introspection** om functions te vind wat staties reachable is vanaf jou fuzz target maar selde of nooit dynamically covered word nie. Daardie functions dui gewoonlik op een van drie issues:

- Die harness gaan die target te laat of te vroeg binne.
- Die seed corpus kort ’n hele feature family.
- Die target het regtig ’n **second harness** nodig in plaas van een oorgroot “do everything” harness.

As jy OSS-Fuzz / ClusterFuzz-style workflows gebruik, is Fuzz Introspector nuttig vir hierdie triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of jy ’n nuwe harness vir ’n ongetoetste parser-pad moet byvoeg, die corpus vir ’n spesifieke funksie moet uitbrei, of ’n monolitiese harness in kleiner entry points moet verdeel.

## Graph-First Fuzz Target Selection And Mutation Triage

As jy reeds **static-analysis findings**, **mutation-testing survivors**, en **coverage reports** het, triage hulle nie as onafhanklike lyste nie. Bou eers ’n **call graph**, annoteer nodes met **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, en enige eksterne findings, en vra dan graph-vrae:

- Watter funksies met hoë kompleksiteit is bereikbaar vanaf ontrusted input?
- Watter mutation survivors sit op paaie van parsers/handlers na security-critical code?
- Watter funksies is argitektoniese choke points met ’n ongewoon hoë **blast radius**?

Dit onthul gewoonlik beter fuzz targets as net “laagste coverage”. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **external reachability** is ’n sterker harness-kandidaat as ’n geïsoleerde interne helper met swak coverage maar geen attacker-controlled path nie.

### Praktiese triage-workflow

1. Bou ’n **code graph** van die codebase en haal per-funksie complexity/branch metrics uit.
2. Lys **entrypoints** wat attacker-controlled input aanvaar: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Loop **path queries** vanaf daardie entrypoints na kandidaat-funksies om bereikbare attack surface van dooie/interne-only code te skei.
4. Prioritiseer nodes wat kombineer:
- hoë **cyclomatic complexity**
- bevestigde **reachability from untrusted input**
- hoë **blast radius** of baie downstream dependents
- bevestigende bewyse soos **SARIF** findings, audit notes, of mutation survivors
5. Skryf gefokusde harnesses vir die beste gescoorde nodes eerste, veral **parsers/codecs** soos hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing lewer dikwels ’n lawaaierige survivor-lys. Voordat jy elke survivor as ’n security gap behandel, gebruik die graph om te vra:

- Is die gemuteerde funksie bereikbaar vanaf ’n attacker-controlled entrypoint?
- Word alle call paths deur sterker invariants as die gemuteerde check beperk?
- Sit die node in dooie code, formatting-only logic, of in ’n high-impact arithmetic/parser path?

Survivors wat onbereikbaar bly of struktureel beperk is, is dikwels **equivalent mutants**. Survivors wat **bereikbaar** bly en **boundary conditions**, **overflow/carry paths**, of **security-critical arithmetic/parsing** raak, moet gepromoveer word na:

- nuwe fuzz harnesses
- direkte property/invariant tests
- geteikende edge-case vectors

### Korrelleer eksterne findings op die graph

As jou SAST pipeline **SARIF** uitvoer, projekteer findings op graph nodes deur **file + line range** en gebruik die graph om die impak uit te brei:

- bereken die **blast radius** van die gemerkte funksie
- kyk of die finding op enige pad vanaf ’n entrypoint is
- groepeer naby findings wat in dieselfde choke point saamval

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd op ’n spesifieke funksie moet spandeer: ’n node wat **bereikbaar**, **complex**, en reeds **SAST hits** het, is dikwels ’n beter target as ’n bloot komplekse node sonder attacker path.

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
Die belangrike metodologie is die snypunt: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutation survivors om te besluit watter grense en invariants jou harness moet stress.

## Go Fuzzing With gosentry: Sterker Engine, Getikte Inputs, En Differential Checks

As 'n Go-teiken reeds 'n native `testing.F` harness het, is 'n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop, 'n forked Go toolchain wat `go test -fuzz` behou maar die backend na **LibAFL** omruil.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dit is nuttig wanneer die native Go fuzzer vasval op **hard comparisons**, **typed inputs**, of **parser-heavy formats**. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar laat dit loop met gosentry se `go` binary in plaas van die stock toolchain.
- Behandel die gevolglike campaign as ’n normale coverage-guided run, maar met LibAFL scheduling/mutation en beter omliggende detectors.

### Turn silent failures into fuzz findings

’n Terugkerende probleem in Go assessments is dat dangerous behaviour dikwels by verstek nie **crash** nie. Met gosentry kan jy verskeie klasse van “bad but silent” state in findings omskep:

- `--panic-on=pkg.Func,...` om geselekteerde logging/error paths soos crashes te laat optree (nuttig vir `log.Fatal`-style code paths wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries met die Go race detector te herhaal.
- `--catch-leaks=true` om nuwe queue entries met `goleak` te herhaal en op goroutine leaks te stop.
- LibAFL hang handling om **infinite loops / very slow inputs** as fuzz findings te hou in plaas daarvan om hulle te laat verdwyn as timeouts.
- Built-in arithmetic overflow checks by default, plus optional truncation checks through go-panikint-style instrumentation.

Dit is veral waardevol vir targets waar die security impact ’n **panicless parser failure**, ’n **concurrency bug**, of ’n **DoS-only hang** is eerder as memory corruption.

### Struct-aware fuzzing for typed Go APIs

Native Go fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string`, en numbers. As die code under test typed objects verbruik, kan gosentry **composite values** direk fuzz (structs, slices, arrays, pointers) terwyl dit steeds bytes onder die oppervlak mutate.
```go
type Input struct {
Data []byte
S    string
N    int
}

func FuzzStructInput(f *testing.F) {
f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
f.Fuzz(func(t *testing.T, in Input) {
Process(in)
})
}
```
Gebruik dit wanneer jy 'n vals wire format bou net vir fuzzing; dit sal logika-bugs agter harness-slegs parsing-kode wegsteek. Vir differential of grammar-gebaseerde campaigns, hou die harness input eerder as 'n enkele `[]byte` of `string` en parse binne die callback.

### Grammar-based fuzzing vir parsers en protocol inputs

Vir parsers, formats, en input languages, kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL laat loop. Die grammar is 'n JSON array van production rules, en die harness moet gewoonlik 'n enkele `[]byte` of `string` argument neem.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodologie-notas:

- Gebruik grammar mode wanneer byte-level mutations meestal sterf in vroeë syntax checks.
- Hou die grammar gefokus op die **security-relevant subset** van die language/protocol in plaas daarvan om die volle specification te modelleer.
- Gebruik groot boundary values in terminals/nonterminals om integer-, length-, en state-machine edges te stress.
- Grammar mode hou inputs grammar-valid, maar die target ontvang steeds **bytes/strings**, so parsing en semantic checks bly binne die harnessed code.

### Differential fuzzing: vergelyk implementations, nie net crashes nie

’n Sterk patroon vir Go ecosystems is **grammar-based differential fuzzing**: genereer valid structured inputs en voer dit na twee parsers, clients, of state-transition engines.
```go
f.Fuzz(func(t *testing.T, data []byte) {
gotA, errA := ParseA(data)
gotB, errB := ParseB(data)
if (errA == nil) != (errB == nil) {
t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
}
_ = gotA
_ = gotB
})
```
Behandel die volgende as bevindings:

- een implementering panieker terwyl die ander skoon verwerp
- ooreenstemmende/verwerpte invoer-mismatches
- verskillende parsebome of gedekodeerde objekte
- divergerende toestandsoorgange, nonces, balances, of staatwortels

Dit is ’n praktiese manier om **consensus mismatches**, **parser ambiguity**, en **spec-vs-implementation drift** te vind wat suiwer crash fuzzing dikwels mis.

### Hergebruik die veldtog-korpus vir coverage reporting

Na ’n veldtog, speel die gestoorde queue-korpus weer om ’n Go coverage report te genereer sonder om handmatig ’n aparte korpus uit te voer:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Run die opdrag vanaf die **selfde package** en met dieselfde `-fuzz` target sodat gosentry die regte cached campaign state kan oplos.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
