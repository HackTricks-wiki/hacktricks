# Fuzzing-metodologie

## Mutational Grammar Fuzzing: Coverage teenoor Semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl hulle **grammar-valid** bly. In coverage-guided-modus word slegs samples wat **new coverage** aktiveer, as corpus seeds gestoor. Vir **language targets** (parsers, interpreters, engines) kan dit bugs mis wat **semantic/dataflow chains** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Failure mode:** die fuzzer vind seeds wat individueel `document()` en `generate-id()` (of soortgelyke primitiewe) uitvoer, maar **nie die chained dataflow behou nie**, sodat die sample wat “closer-to-bug” is, weggegooi word omdat dit nie coverage byvoeg nie. Met **3+ dependent steps** word random recombination duur, en coverage-feedback lei nie die search nie.<sup>[[1]](#references)</sup>

**Implication:** vir grammars met baie dependencies, oorweeg dit om **mutational en generative phases te hybridize** of generation te bias na **function chaining**-patrone (nie net coverage nie).<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation is **greedy**: ’n sample met new coverage word onmiddellik gestoor, en behou dikwels groot onveranderde areas. Met verloop van tyd word corpora **near-duplicates** met lae strukturele diversity. Aggressive minimization kan nuttige konteks verwyder, dus is ’n praktiese kompromie **grammar-aware minimization** wat **stop ná ’n minimum token threshold** (verminder noise terwyl genoeg omliggende struktuur behou word om mutation-friendly te bly).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel seeds wat struktureel van mekaar verskil en coverage maksimeer** bo ’n groot versameling near-duplicates. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **real-world samples** (public corpora, crawling, captured traffic, file sets uit die target-ekosisteem).
- Distill hulle met **coverage-based corpus minimization** in plaas daarvan om elke valid sample te behou.
- Hou seeds **klein genoeg** sodat mutations op betekenisvolle fields land, eerder as om die meeste cycles aan irrelevante bytes te spandeer.
- Voer corpus minimization weer uit ná groot harness/instrumentation-veranderinge, omdat die “beste” corpus verander wanneer reachability verander.

## Comparison-Aware Mutation For Magic Values

’n Algemene rede waarom fuzzers plateau, is nie syntax nie, maar **hard comparisons**: magic bytes, length checks, enum strings, checksums of parser dispatch values wat deur `memcmp`, switch tables of cascaded comparisons beskerm word. Pure random mutation mors cycles deur hierdie values byte vir byte te probeer raai.

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
**Praktiese notas:**

- Dit is veral nuttig wanneer die teiken diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** verberg.
- Kombineer dit met **dictionaries** wat uit werklike voorbeelde, protokolspesifikasies of debug logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs en delimiters is dikwels meer waardevol as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende checks uitvoer, los eers die vroegste “magic”-vergelykings op en minimaliseer dan die resulterende corpus weer, sodat latere fases met reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences is Seeds

Vir **protocols**, **authenticated workflows** en **multi-stage parsers** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blindelings te muteer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel muteer, selfs wanneer slegs die latere message die brose state bereik.<sup>[[4]](#references)</sup>

’n Meer effektiewe patroon is om die **sequence self as die seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as addisionele feedback te gebruik.<sup>[[4]](#references)</sup>

- Hou **valid prefix messages** stabiel en fokus mutations op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo die mutering van die hele serialized transcript as ’n opaque blob.
- As die protocol betekenisvolle response codes blootstel, gebruik dit as ’n **goedkoop state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of parser bugs wat “only-after-handshake” voorkom, dikwels deur vanilla file-style fuzzing gemis word: die fuzzer moet **order, state en dependencies** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **short-lived workers** teen ’n persistente server te herbegin. Elke worker begin met ’n leë corpus, sync na `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sync weer, en exit dan. Dit lewer **fresh structures each generation** terwyl dit steeds opgehoopte coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Bediener:**
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

- `-in empty` dwing ’n **vars corpus** met elke generasie af.
- `-server_update_interval T` benader **vertraagde sinkronisering** (nuutheid eerste, hergebruik later).
- In grammar fuzzing mode word **aanvanklike server-sinkronisering** by verstek oorgeslaan (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **teikengebonden**; oorskakeling nadat die worker die meeste “maklike” coverage gevind het, werk gewoonlik die beste.

## Snapshot Fuzzing Vir Teikens Wat Moeilik Ge-Harness Kan Word

Wanneer die code wat jy wil toets slegs bereikbaar word **na ’n groot opstellingskoste** (’n VM begin, ’n login voltooi, ’n packet ontvang, ’n container parse, of ’n service initialiseer), is **snapshot fuzzing** ’n nuttige alternatief: neem die gereed proses- of VM-toestand vas, injecteer elke test case in die target se input-pad, voer dit uit totdat ’n crash/timeout plaasvind, en herstel die snapshot. Dit vermy die herhaling van initialisering of protocol-prefixes en is nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Laat die target loop totdat die interessante toestand gereed is.
2. Neem **memory + registers** op daardie punt as ’n snapshot.
3. Skryf vir elke test case die gemuteerde input direk na die relevante guest/process-buffer.
4. Voer dit uit totdat ’n crash/timeout/reset plaasvind.
5. Herstel die snapshot; vir VM-teikens, herstel slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse/dispatch-stap, soos ná ’n `recv`/`read`- of packet-deserialization-punt, en teken die input-buffer aan wat deur die target gebruik word. Dit volg die beginsel van adaptive placement: beweeg die snapshot dieper in input-verwerking om te voorkom dat werk herhaal word.<sup>[[11]](#references)</sup>

## Harness-introspeksie: Vind Vlak Fuzzers Vroeg

Wanneer ’n campaign vashaak, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **reachability/coverage-introspeksie** om funksies te vind wat staties bereikbaar is vanaf jou fuzz target, maar dinamies selde of nooit gedek word nie. Hierdie funksies dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die target te laat of te vroeg.
- Die seed corpus ontbreek ’n volledige feature-familie.
- Die target benodig werklik ’n **tweede harness** in plaas van een oorgroot “doen alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl workflows gebruik, kan Fuzz Introspector statiese bereikbaarheid met runtime-coverage vergelyk en reports uit ’n timed run of openbare corpus genereer.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of jy 'n nuwe harness vir 'n ongetoetste parser-pad moet byvoeg, die corpus vir 'n spesifieke kenmerk moet uitbrei, of 'n monolitiese harness in kleiner entry points moet verdeel.

## Grafiek-eerste seleksie van fuzz-teikens en mutation-triage

As jy reeds **static-analysis findings**, **mutation-testing survivors** en **coverage reports** het, moenie hulle as onafhanklike lyste triage nie. Bou eers 'n **call graph**, annoteer nodes met **cyclomatic complexity**, **entrypoint/untrusted-input reachability** en enige eksterne bevindings, en vra dan grafiekvrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is vanaf untrusted input bereikbaar?
- Watter mutation survivors lê op paaie vanaf parsers/handlers na security-critical code?
- Watter funksies is argitektoniese choke points met 'n buitengewoon hoë **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as slegs "laagste coverage". 'n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is 'n sterker harness-kandidaat as 'n geïsoleerde interne helper met swak coverage maar sonder 'n aanvaller-beheerde pad.

### Praktiese triage-werkvloei

1. Bou 'n **code graph** vanaf die codebase en onttrek kompleksiteit-/branch-metrieke per funksie.
2. Lys **entrypoints** wat aanvaller-beheerde input aanvaar: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Voer **path queries** vanaf daardie entrypoints na kandidaatfunksies uit om bereikbare attack surface van dooie/slegs-interne code te skei.
4. Prioritiseer nodes wat die volgende kombineer:
- hoë **cyclomatic complexity**
- bevestigde **bereikbaarheid vanaf untrusted input**
- hoë **blast radius** of baie downstream dependents
- ondersteunende bewyse soos **SARIF**-findings, audit notes of mutation survivors
5. Skryf eers gefokusde harnesses vir die nodes met die hoogste tellings, veral **parsers/codecs** soos hex/Base64/IP/message decoders.

### Mutation survivors: equivalent teenoor actionable

Mutation testing lewer dikwels 'n raserige survivor-lys. Voordat jy elke survivor as 'n security gap hanteer, gebruik die grafiek om te vra:

- Is die gemuteerde funksie vanaf 'n aanvaller-beheerde entrypoint bereikbaar?
- Word alle call paths deur sterker invariants as die gemuteerde check beperk?
- Lê die node in dooie code, formatting-only logic, of in 'n high-impact arithmetic/parser path?

Survivors wat onbereikbaar of struktureel beperk bly, is dikwels **equivalent mutants**. Survivors wat **bereikbaar** bly en **boundary conditions**, **overflow/carry paths** of **security-critical arithmetic/parsing** raak, moet bevorder word tot:

- nuwe fuzz harnesses
- direkte property/invariant tests
- geteikende edge-case vectors

### Korreleer eksterne bevindings met die grafiek

As jou SAST-pipeline **SARIF** uitvoer, projekteer bevindings op graph nodes volgens **file + line range** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kontroleer of die bevinding op enige pad vanaf 'n entrypoint is
- groepeer nabygeleë bevindings wat by dieselfde choke point aansluit

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan 'n spesifieke funksie moet bestee: 'n node wat **bereikbaar**, **kompleks** is en reeds **SAST hits** het, is dikwels 'n beter teiken as 'n bloot komplekse node sonder 'n aanvaller-pad.

Voorbeeld-werkvloei met Trailmark.<sup>[[6]](#references)</sup>
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
Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariants jou harness moet stres.<sup>[[5]](#references)</sup>

## Go Fuzzing met gosentry: Sterker enjin, getikte invoere en differensiële kontroles

As ’n Go-teiken reeds ’n native `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) te laat loop — ’n geforkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omruil.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dit is nuttig wanneer die native Go fuzzer vashaak op **moeilike vergelykings**, **getikte insette**, of **parser-swaar formate**. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binary in plaas van die standaard toolchain uit.
- Behandel die gevolglike campaign as ’n normale coverage-guided-lopie, maar met LibAFL-skedulering/mutasie en beter omliggende detectors.

### Verander stille mislukkings in fuzz-bevindings

’n Herhalende probleem in Go-assesseringe is dat gevaarlike gedrag dikwels **nie** by verstek crash nie. Met gosentry kan jy verskeie klasse van “sleg maar stil” toestande in findings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging/error-paaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige kodepaaie wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries met die Go race detector te herspeel.
- `--catch-leaks=true` om nuwe queue entries met `goleak` te herspeel en op goroutine-leaks te stop.
- LibAFL-hanghantering om **oneindige lusse / baie stadige insette** as fuzz-findings te behou, in plaas daarvan om dit as timeouts te laat verdwyn.
- Ingeboude rekenkundige overflow-kontroles by verstek, plus opsionele truncation-kontroles deur middel van go-panikint-styl instrumentering.

Dit is veral waardevol vir teikens waar die sekuriteitsimpak ’n **panicless parser failure**, ’n **concurrency bug**, of ’n **DoS-only hang** eerder as geheuekorrupsie is.

### Struct-aware fuzzing vir getikte Go-API's

Native Go fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string`, en getalle. As die kode onder toets getikte objekte verbruik, kan gosentry **saamgestelde waardes** direk fuzz (structs, slices, arrays, pointers), terwyl dit steeds die onderliggende bytes muteer.<sup>[[7]](#references)[[8]](#references)</sup>
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
Gebruik dit wanneer die bou van ’n fake wire format slegs vir fuzzing logikafoute agter harness-only parsing code sou versteek. Vir differential- of grammar-based campaigns, hou die harness-invoer as ’n enkele `[]byte` of `string` en parse dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-insette

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON-array van production rules, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te aanvaar.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodologie-aantekeninge:

- Gebruik grammar mode wanneer byte-level mutations meestal tydens vroeë syntax checks beëindig word.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol, eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om integer-, lengte- en state-machine-grense te stres.
- Grammar mode hou inputs grammar-valid, maar die teiken ontvang steeds **bytes/strings**, dus bly parsing en semantic checks binne die geharnessde kode.

### Differential fuzzing: vergelyk implementasies, nie net crashes nie

'n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde inputs en voer dit aan twee parsers, clients of state-transition engines.<sup>[[7]](#references)[[8]](#references)</sup>
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
Behandel die volgende as bevindinge:

- een implementering panieker terwyl die ander dit netjies verwerp
- nie-ooreenstemmende aanvaar/verwerp-insette
- verskillende parse-bome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, saldo's of toestand- roots

Dit is 'n praktiese manier om **konsensus-wanpassings**, **parser-ambiguïteit** en **spesifikasie-teenoor-implementering-afwyking** te vind wat suiwer crash fuzzing dikwels mis.

### Hergebruik die campaign corpus vir dekkingverslagdoening

Ná 'n campaign, speel die gestoorde queue corpus weer af om 'n Go-dekkingsverslag te genereer sonder om 'n aparte corpus handmatig uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Voer die opdrag vanuit die **same package** en met dieselfde `-fuzz`-teiken uit sodat gosentry die korrekte gekasde veldtogtoestand oplos.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Vyf jaar later: Oor dekking-geleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: 'n Vinnige greybox-fuzzer vir stateful netwerkprotokolle wat snapshots gebruik](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kern sonder stelseloproepbeskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met adaptiewe en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
