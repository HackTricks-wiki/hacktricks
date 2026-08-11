# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage teenoor Semantiek

In **mutational grammar fuzzing** word inputs gemuteer terwyl dit **grammar-valid** bly. In coverage-guided-modus word slegs samples wat **nuwe coverage** aktiveer as corpus seeds gestoor. Vir **language targets** (parsers, interpreters, engines) kan dit bugs mis wat **semantic/dataflow chains** vereis, waar die uitvoer van een construct die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Failure mode:** die fuzzer vind seeds wat individueel `document()` en `generate-id()` (of soortgelyke primitives) uitvoer, maar **nie die chained dataflow behou nie**, dus word die “closer-to-bug”-sample weggegooi omdat dit nie coverage byvoeg nie. Met **3+ afhanklike steps** word random recombination duur en coverage-feedback rig nie die search nie.<sup>[[1]](#references)</sup>

**Implikasie:** vir dependency-heavy grammars, oorweeg dit om **mutational en generative phases te hybridize** of generation te bias na **function chaining**-patrone (nie net coverage nie).<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation is **greedy**: ’n new-coverage-sample word onmiddellik gestoor en behou dikwels groot onveranderde areas. Met verloop van tyd word corpora **near-duplicates** met lae structural diversity. Aggressive minimization kan nuttige context verwyder, dus is ’n praktiese kompromie **grammar-aware minimization** wat **stop ná ’n minimum token threshold** (verminder noise terwyl genoeg omliggende structure behoue bly om mutation-friendly te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat coverage maksimeer** bo ’n groot hoop near-duplicates. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **real-world samples** (public corpora, crawling, captured traffic, file sets uit die target ecosystem).
- Distill dit met **coverage-based corpus minimization** in plaas daarvan om elke valid sample te behou.
- Hou seeds **klein genoeg** sodat mutations op meaningful fields land, eerder as om die meeste cycles op irrelevant bytes te spandeer.
- Voer corpus minimization weer uit ná groot harness/instrumentation-veranderinge, omdat die “beste” corpus verander wanneer reachability verander.

## Comparison-Aware Mutation For Magic Values

’n Algemene rede waarom fuzzers ’n plateau bereik, is nie syntax nie maar **hard comparisons**: magic bytes, length checks, enum strings, checksums of parser dispatch values wat deur `memcmp`, switch tables of cascaded comparisons beskerm word. Pure random mutation mors cycles deur hierdie values byte vir byte te probeer raai.

Vir hierdie targets, gebruik **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-style workflows) sodat die fuzzer operands van failed comparisons kan waarneem en mutations kan bias na values wat daaraan voldoen.<sup>[[3]](#references)</sup>
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
**Praktiese aantekeninge:**

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** beskerm.
- Kombineer dit met **dictionaries** wat uit werklike voorbeelde, protocolspecificasies, of debug logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs, en delimiters is dikwels waardevoller as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende kontroles uitvoer, los eers die vroegste “magic”-vergelykings op en minimaliseer dan die resulterende corpus weer, sodat latere stadiums met reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences Are Seeds

Vir **protocols**, **authenticated workflows**, en **multi-stage parsers** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blindelings te mutate, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel mutateer, selfs wanneer slegs die latere message die fragile state bereik.<sup>[[4]](#references)</sup>

’n Meer effektiewe patroon is om die **sequence self as the seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as bykomende feedback te gebruik.<sup>[[4]](#references)</sup>

- Hou **valid prefix messages** stabiel en fokus mutations op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo mutating van die hele serialized transcript as ’n opaque blob.
- As die protocol betekenisvolle response codes blootstel, gebruik hulle as ’n **cheap state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of “only-after-handshake”-parserbugs dikwels deur vanilla file-style fuzzing gemis word: die fuzzer moet **order, state, en dependencies** behou, nie net structure nie.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **short-lived workers** teen ’n persistente server te herbegin. Elke worker begin met ’n leë corpus, sync na `T` seconds, loop nog `T` seconds op die combined corpus, sync weer, en exit dan. Dit lewer **fresh structures each generation** terwyl dit steeds accumulated coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Opeenvolgende workers (voorbeeldlus):**

<details>
<summary>Jackalope worker-herbeginlus</summary>
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

- `-in empty` dwing ’n **fresh corpus** by elke generasie af.
- `-server_update_interval T` benader **delayed sync** (novelty eerste, reuse later).
- In grammar fuzzing mode word **initial server sync** by verstek oorgeslaan (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **target-dependent**; om oor te skakel nadat die worker die meeste “easy” coverage gevind het, werk gewoonlik die beste.

## Snapshot Fuzzing vir Teikens wat Moeilik is om te-Harness

Wanneer die kode wat jy wil toets eers **bereikbaar** word ná ’n groot setup-koste (’n VM begin, ’n login voltooi, ’n packet ontvang, ’n container parse, of ’n diens initialiseer), is **snapshot fuzzing** ’n nuttige alternatief: vang die gereed proses- of VM-toestand vas, inject elke test case in die target se input path, voer uit totdat ’n crash/timeout plaasvind, en herstel die snapshot. Dit vermy die herhaling van initialisering of protocol prefixes en is nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die target loop totdat die interessante toestand gereed is.
2. Neem op daardie punt ’n snapshot van **memory + registers**.
3. Skryf die gemuteerde input vir elke test case direk na die relevante guest/process buffer.
4. Voer uit totdat ’n crash/timeout/reset plaasvind.
5. Herstel die snapshot; vir VM-teikens, herstel slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse/dispatch-stap, byvoorbeeld ná ’n `recv`/`read` of packet-deserialization-punt, en teken die input buffer aan wat deur die target gebruik word. Dit volg die adaptive-placement-beginsel om die snapshot dieper in input processing te skuif en sodoende herhaalde werk te vermy.<sup>[[11]](#references)</sup>

## Harness Introspection: Vind Shallow Fuzzers Vroeg

Wanneer ’n campaign vasval, is die probleem dikwels nie die **mutator** nie, maar die **harness**. Gebruik **reachability/coverage introspection** om funksies te vind wat staties vanaf jou fuzz target bereikbaar is, maar dinamies selde of nooit gedek word nie. Hierdie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die target te laat of te vroeg.
- Die seed corpus ontbreek ’n hele feature family.
- Die target het werklik ’n **second harness** nodig in plaas van een oorgroot “do everything”-harness.

As jy OSS-Fuzz / ClusterFuzz-style workflows gebruik, kan Fuzz Introspector statiese reachability met runtime coverage vergelyk en reports vanaf ’n timed run of public corpus genereer.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of ’n nuwe harness vir ’n ongetoetste parser-pad bygevoeg moet word, die corpus vir ’n spesifieke kenmerk uitgebrei moet word, of ’n monolitiese harness in kleiner entry points verdeel moet word.

## Grafiek-eerste Fuzz-teikenkeuse en Mutasie-triage

As jy reeds **static-analysis findings**, **mutation-testing survivors** en **coverage reports** het, moet jy dit nie as onafhanklike lyste triage nie. Bou eers ’n **call graph**, annoteer nodusse met **cyclomatic complexity**, **entrypoint/untrusted-input reachability** en enige eksterne findings, en stel dan grafiekvrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is vanaf onbetroubare invoer bereikbaar?
- Watter mutation survivors lê op paaie van parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met ’n buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as net “laagste coverage”. ’n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is ’n sterker harness-kandidaat as ’n geïsoleerde interne helper met swak coverage, maar sonder ’n aanvaller-beheerde pad.

### Praktiese triage-werkvloei

1. Bou ’n **code graph** uit die kodebasis en haal kompleksiteit-/branch-metrieke per funksie uit.
2. Lys **entrypoints** wat aanvaller-beheerde invoer aanvaar: request handlers, decoders, importers, protocol parsers, CLI-/file readers.
3. Voer **path queries** vanaf daardie entrypoints na kandidaatfunksies uit om bereikbare attack surface van dooie/slegs-interne kode te skei.
4. Prioritiseer nodusse wat die volgende kombineer:
- hoë **cyclomatic complexity**
- bevestigde **reachability from untrusted input**
- groot **blast radius** of baie afhanklike downstream-komponente
- ondersteunende bewyse soos **SARIF**-findings, audit notes of mutation survivors
5. Skryf eerste gefokusde harnesses vir die nodusse met die hoogste telling, veral **parsers/codecs** soos hex-/Base64-/IP-/message decoders.

### Mutation survivors: equivalent teenoor actionable

Mutation testing lewer dikwels ’n raserige survivor-lys op. Voordat jy elke survivor as ’n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie vanaf ’n aanvaller-beheerde entrypoint bereikbaar?
- Word alle call paths deur sterker invariants as die gemuteerde check beperk?
- Is die node in dooie kode, formatting-only logic, of in ’n hoë-impak arithmetic/parser-pad?

Survivors wat onbereikbaar bly of struktureel beperk word, is dikwels **equivalent mutants**. Survivors wat **bereikbaar** bly en aan **boundary conditions**, **overflow/carry paths**, of **security-critical arithmetic/parsing** raak, moet bevorder word tot:

- nuwe fuzz harnesses
- direkte property-/invariant-toetse
- geteikende edge-case vectors

### Korrelleer eksterne findings op die grafiek

As jou SAST-pipeline **SARIF** uitvoer, projekteer findings op grafieknodusse volgens **file + line range** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kontroleer of die finding op enige pad vanaf ’n entrypoint voorkom
- groepeer nabygeleë findings wat in dieselfde knelpunt saamval

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan ’n spesifieke funksie moet bestee: ’n node wat **bereikbaar**, **kompleks** is en reeds **SAST hits** het, is dikwels ’n beter teiken as ’n bloot komplekse node sonder ’n aanvallerpad.

Voorbeeldwerkvloei met Trailmark.<sup>[[6]](#references)</sup>
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
Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariants jou harnas moet stres.<sup>[[5]](#references)</sup>

## Go Fuzzing met gosentry: Kragtiger Enjin, Getipeerde Invoer En Differensiële Kontroles

As ’n Go-teiken reeds ’n native `testing.F`-harnas het, is ’n praktiese opgraderingspad om dieselfde harnas met [gosentry](https://github.com/trailofbits/gosentry) te laat loop — ’n gevurkte Go toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** verruil.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dit is nuttig wanneer die native Go fuzzer op **hard comparisons**, **typed inputs** of **parser-heavy formats** vasval. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go` binary in plaas van die stock toolchain.
- Behandel die gevolglike campaign as ’n normale coverage-guided run, maar met LibAFL-skedulering/mutasie en beter omliggende detectors.

### Verander stil foute in fuzz-bevindings

’n Herhalende probleem in Go-assessments is dat gevaarlike gedrag dikwels by verstek **nie** crash nie. Met gosentry kan jy verskeie klasse van “sleg maar stil” toestande in findings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging/error-paaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige code paths wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries weer met die Go race detector uit te voer.
- `--catch-leaks=true` om nuwe queue entries weer met `goleak` uit te voer en op goroutine-leaks te stop.
- LibAFL-hanghantering om **infinite loops / very slow inputs** as fuzz findings te behou, in plaas daarvan dat hulle as timeouts verdwyn.
- Ingeboude arithmetic overflow checks by verstek, plus opsionele truncation checks deur go-panikint-styl instrumentation.

Dit is veral waardevol vir targets waar die sekuriteitsimpak ’n **panicless parser failure**, ’n **concurrency bug** of ’n **DoS-only hang** eerder as memory corruption is.

### Struct-aware fuzzing vir getikte Go APIs

Native Go fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string` en getalle. As die code onder toets getikte objects verbruik, kan gosentry **composite values** direk fuzz (structs, slices, arrays, pointers), terwyl dit steeds bytes onderliggend muteer.<sup>[[7]](#references)[[8]](#references)</sup>
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
Gebruik dit wanneer jy ’n fake wire format bou, aangesien dit slegs vir fuzzing is; anders kan dit logikafoute agter harness-only parsing code verberg. Vir differential- of grammar-based campaigns, hou die harness-invoer as ’n enkele `[]byte` of `string` en parseer dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-invoer

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON-array van production rules, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te aanvaar.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodologie-aantekeninge:

- Gebruik Grammar mode wanneer byte-vlak-mutasies meestal in vroeë sintaksiskontroles tot stilstand kom.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om heelgetal-, lengte- en toestandsmasjiengrense te stres.
- Grammar mode hou insette grammar-valid, maar die teiken ontvang steeds **bytes/strings**, dus bly parsing en semantiese kontroles binne die geharnaste kode.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

’n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde insette en voer dit aan twee parsers, kliënte of toestandoorgangs-enjins.<sup>[[7]](#references)[[8]](#references)</sup>
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

- een implementering veroorsaak ’n panic, terwyl die ander een dit netjies verwerp
- teenstrydighede tussen aanvaarbare/verwerpte invoer
- verskillende parse trees of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, balances of state roots

Dit is ’n praktiese manier om **consensus mismatches**, **parser ambiguity** en **spec-vs-implementation drift** te vind wat pure crash fuzzing dikwels mis.

### Hergebruik die campaign corpus vir dekkingverslaggewing

Ná ’n campaign, speel die gestoorde queue corpus weer af om ’n Go coverage report te genereer sonder om handmatig ’n aparte corpus uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Voer die opdrag vanuit die **same package** en met die **same `-fuzz` target** uit sodat gosentry die korrekte gekaste veldtogtoestand oplos.

## References

- [1] [Mutasionele grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor dekking-geleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander code in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing het die helfte van die toolkit ontbreek. Ons het die toolchain gefork om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox fuzzer vir stateful netwerkprotokolle wat snapshots gebruik](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammar, geen probleem: Op pad na fuzzing van die Linux-kern sonder system-call-beskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met adaptiewe en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
