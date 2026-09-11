# Fuzzing-metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Dekking teenoor Semantiek

In **mutational grammar fuzzing** word invoere gemuteer terwyl dit **grammatikaal geldig** bly. In coverage-guided-modus word slegs monsters wat **nuwe dekking** aktiveer, as corpus seeds gestoor. Vir **language targets** (parsers, interpreters, engines) kan dit foute mis wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van ’n ander word.<sup>[[1]](#references)</sup>

**Failure mode:** die fuzzer vind seeds wat individueel `document()` en `generate-id()` (of soortgelyke primitives) uitvoer, maar **nie die gekoppelde dataflow behou nie**, en daarom word die “nader-aan-die-fout”-monster weggegooi omdat dit nie dekking byvoeg nie. Met **3+ afhanklike stappe** word ewekansige herkombinasie duur, en coverage-feedback lei nie die soektog nie.<sup>[[1]](#references)</sup>

**Implikasie:** vir grammatikas met baie afhanklikhede, oorweeg dit om **mutational- en generative-fases te kombineer** of generering na patrone van **function chaining** te laat neig (nie net na dekking nie).<sup>[[1]](#references)</sup>

## Slaggate van Corpus-diversiteit

Coverage-guided mutation is **gulsig**: ’n monster met nuwe dekking word onmiddellik gestoor en behou dikwels groot onveranderde gebiede. Met verloop van tyd word corpora **byna-duplikate** met lae strukturele diversiteit. Aggressiewe minimization kan nuttige konteks verwyder, dus is ’n praktiese kompromie **grammar-aware minimization** wat **stop ná ’n minimum token-drempel** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutation-vriendelik te wees).<sup>[[1]](#references)</sup>

’n Praktiese corpus-reël vir mutational fuzzing is: **verkies ’n klein stel struktureel verskillende seeds wat dekking maksimeer** bo ’n groot hoop byna-duplikate. In die praktyk beteken dit gewoonlik die volgende.<sup>[[1]](#references)[[3]](#references)</sup>

- Begin met **werklike monsters** (publieke corpora, crawling, vasgelegde verkeer, lêerstelle uit die target-ekosisteem).
- Distilleer hulle met **coverage-based corpus minimization** in plaas daarvan om elke geldige monster te behou.
- Hou seeds **klein genoeg** sodat mutations op betekenisvolle velde land, eerder as om die meeste siklusse aan irrelevante grepe te spandeer.
- Voer corpus minimization weer uit ná groot harness/instrumentation-veranderings, omdat die “beste” corpus verander wanneer reachability verander.

## Comparison-Aware Mutation Vir Magic Values

’n Algemene rede waarom fuzzers ’n plato bereik, is nie sintaksis nie maar **harde vergelykings**: magic bytes, lengte-kontroles, enum strings, checksums of parser-dispatch-waardes wat deur `memcmp`, switch tables of opeenvolgende vergelykings beskerm word. Suiwer ewekansige mutation mors siklusse deur hierdie waardes byte vir byte te probeer raai.

Vir hierdie targets, gebruik **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-style workflows) sodat die fuzzer operande uit mislukte vergelykings kan waarneem en mutations kan stuur na waardes wat daaraan voldoen.<sup>[[3]](#references)</sup>
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
- Kombineer dit met **dictionaries** wat uit werklike samples, protocol-spesifikasies, of debug-logs onttrek is. ’n Klein dictionary met grammar tokens, chunk names, verbs, en delimiters is dikwels meer waardevol as ’n massiewe generiese wordlist.
- As die teiken baie opeenvolgende checks uitvoer, los eers die vroegste “magic”-vergelykings op en minimaliseer dan die resulterende corpus weer sodat latere stages met reeds-geldige prefixes begin.

## Ryker terugvoer wanneer Edge Coverage verskillende paaie laat saamsmelt

Normale edge coverage kan nie onderskei tussen twee uitvoerings wat dieselfde helper deur verskillende callers deurloop of verskillende branch combinations binne ’n function neem nie. Dit is belangrik in shared decoders, protocol dispatchers, en interpreter helpers waar die **route** na ’n edge die aktiewe state bepaal. Om elke calling context naïef na te spoor, is ook gevaarlik: die coverage map en queue kan buitensporig groot word. Context-sensitive fuzzing-navorsing beveel daarom aan dat slegs belowende contexts verfyn word, eerder as om die hele call graph as context-sensitive te behandel.<sup>[[14]](#references)</sup>

Onlangse AFL++-builds bied **Ball-Larus per-function path coverage** benewens normale edge coverage. Dit ken ’n feature aan elke acyclic path deur ’n function toe; loop back-edges word verwyder, dus onderskei hierdie terugvoer branch combinations maar **nie loop iteration counts nie**. Begin met die meer toegeeflike level `1`, en beperk daarna strenger modes tot verdagte parser/state-machine-kode, omdat die aantal paaie eksponensieel kan groei.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Vir ’n helper wat vanaf baie sekuriteitsrelevante plekke geroep word, kan LTO-modus elke funksiepad met sy onmiddellike oproepplek kombineer:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Campaign guidance:** pas ryker feedback konserwatief toe en monitor die coverage-map/queue-koste.<sup>[[13]](#references)[[14]](#references)</sup>

- Begin ’n gewone edge-coverage-instansie parallel; ryker feedback is slegs nuttig indien die ekstra queue/map-koste nie executions per second vernietig nie.
- Gebruik `AFL_LLVM_ALLOWLIST` om path/caller-instrumentasie te beperk wanneer groot template-heavy libraries of generiese utility code die map oorheers.
- Funksies met buitensporig baie acyclic paths kan deur AFL++ oorgeslaan word; waarskuwings tydens compilation is ’n aanduiding dat die target allowlisting of ’n minder streng vlak benodig.
- Caller + path coverage ondersteun slegs een caller depth. Moenie dit met dieper context stacks kombineer nie.
- Path IDs kan oor LLVM major versions verander. Hou die toolchain konstant vir ’n campaign en moenie PATH-gebaseerde corpora sinkroniseer asof hul feature IDs oor builds heen stabiel is nie.
- Hierdie feedback vul `CMPLOG` aan: comparison tracing bepaal **watter waarde ’n guard slaag**, terwyl path/caller-feedback bewaar **watter roete en branch-kombinasie dit bereik het**.

## Stateful Fuzzing: Sequences Is Seeds

Vir **protokolle**, **geauthentiseerde workflows** en **multi-stage parsers** is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transcript in een lêer saam te voeg en dit blindelings te mutateer, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel mutateer, selfs wanneer slegs die latere boodskap die kwesbare toestand bereik.<sup>[[4]](#references)</sup>

’n Meer effektiewe patroon is om die **sequence self as die seed** te behandel en **waarneembare toestand** (response codes, protocol states, parser phases, returned object types) as bykomende feedback te gebruik.<sup>[[4]](#references)</sup>

- Hou **geldige prefix-boodskappe** stabiel en fokus mutations op die **transition-driving** boodskap.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo mutating van die hele serialized transcript as ’n ondeursigtige blob.
- Indien die protokol betekenisvolle response codes blootstel, gebruik dit as ’n **goedkoop state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions of parser-bugs wat “only-after-handshake” voorkom, dikwels deur vanilla file-style fuzzing gemis word: die fuzzer moet **orde, toestand en dependencies** behou, nie net struktuur nie.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **kortlewende workers** teen ’n persistent server te herbegin. Elke worker begin met ’n leë corpus, sync na `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sync weer en sluit dan af. Dit lewer **vars strukture per generation** terwyl dit steeds opgehoopte coverage benut.<sup>[[1]](#references)[[2]](#references)</sup>

**Bediener:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Opeenvolgende werkers (voorbeeldlus):**

<details>
<summary>Jackalope-werker-herbeginlus</summary>
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

- `-in empty` dwing ’n **fresh corpus** met elke generasie af.
- `-server_update_interval T` benader **delayed sync** (novelty eerste, reuse later).
- In grammar fuzzing mode word **initial server sync** by verstek oorgeslaan (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **target-dependent**; om oor te skakel nadat die worker die meeste “easy” coverage gevind het, werk gewoonlik die beste.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wanneer die code wat jy wil toets eers **bereikbaar** word **nadat ’n groot setup-koste** aangegaan is (’n VM begin, ’n login voltooi, ’n packet ontvang, ’n container geparseer of ’n service geïnisialiseer is), is **snapshot fuzzing** ’n nuttige alternatief: leg die gereed process- of VM-state vas, inject elke test case in die target se input path, voer dit uit totdat dit crash/timeout, en restore die snapshot. Dit vermy die herhaling van initialisering of protocol prefixes en is nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Run die target totdat die interessante state gereed is.
2. Snapshot **memory + registers** op daardie punt.
3. Skryf die gemuteerde input vir elke test case direk na die relevante guest/process-buffer.
4. Voer dit uit totdat dit crash/timeout/reset.
5. Restore die snapshot; vir VM targets, restore slegs die **dirty pages** wanneer dit ondersteun word, en herhaal dan.

Plaas die snapshot so na as prakties moontlik aan die eerste duur parse/dispatch-stap, soos ná ’n `recv`/`read`- of packet-deserialization-punt, en teken die input-buffer aan wat deur die target gebruik word. Dit volg die adaptive-placement-beginsel om die snapshot dieper in input processing te skuif en sodoende herhaalde werk te vermy.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Wanneer ’n campaign stagneer, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **reachability/coverage introspection** om functions te vind wat staties vanaf jou fuzz target bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie functions dui gewoonlik op een van drie probleme.<sup>[[12]](#references)</sup>

- Die harness betree die target te laat of te vroeg.
- Die seed corpus ontbreek ’n hele feature family.
- Die target benodig werklik ’n **second harness** in plaas van een oorgroot “do everything”-harness.

As jy OSS-Fuzz / ClusterFuzz-style workflows gebruik, kan Fuzz Introspector statiese reachability met runtime coverage vergelyk en reports vanaf ’n timed run of public corpus genereer.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of jy 'n nuwe harness vir 'n ongetoetste parser-pad moet byvoeg, die corpus vir 'n spesifieke funksie moet uitbrei, of 'n monolitiese harness in kleiner entry points moet opdeel.

## Grafiek-eerste Fuzz Target-seleksie en Mutasie-triage

As jy reeds **static-analysis findings**, **mutation-testing survivors** en **coverage reports** het, moenie dit as onafhanklike lyste triage nie. Bou eers 'n **call graph**, annoteer nodusse met **cyclomatic complexity**, **entrypoint/onbetroubare-invoer-bereikbaarheid**, en enige eksterne bevindings, en vra dan grafiekvrae.<sup>[[5]](#references)[[6]](#references)</sup>

- Watter hoë-kompleksiteitsfunksies is vanaf onbetroubare invoer bereikbaar?
- Watter mutation survivors lê op paaie vanaf parsers/handlers na sekuriteitskritieke kode?
- Watter funksies is argitektoniese knelpunte met buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz targets na vore as slegs "lowest coverage". 'n Parser/decoder met **hoë kompleksiteit** en bevestigde **eksterne bereikbaarheid** is 'n sterker harness-kandidaat as 'n geïsoleerde interne helper met swak coverage maar sonder 'n aanvaller-beheerde pad.

### Praktiese triage-werkvloei

1. Bou 'n **code graph** vanaf die codebase en onttrek kompleksiteits-/branch-metrieke per funksie.
2. Lys **entrypoints** wat aanvaller-beheerde invoer aanvaar: request handlers, decoders, importers, protokol-parsers, CLI-/lêerlesers.
3. Voer **path queries** vanaf daardie entrypoints na kandidaatfunksies uit om bereikbare attack surface van dooie/slegs-interne kode te onderskei.
4. Prioritiseer nodusse wat die volgende kombineer:
- hoë **cyclomatic complexity**
- bevestigde **bereikbaarheid vanaf onbetroubare invoer**
- groot **blast radius** of baie stroomaf-afhanklikes
- ondersteunende bewyse soos **SARIF**-bevindinge, ouditnotas of mutation survivors
5. Skryf eerstens gefokusde harnesses vir die nodusse met die hoogste telling, veral **parsers/codecs** soos hex-/Base64-/IP-/message-decoders.

### Mutation survivors: ekwivalent teenoor uitvoerbaar

Mutation testing lewer dikwels 'n raserige lys survivors op. Voordat jy elke survivor as 'n sekuriteitsgaping beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie vanaf 'n aanvaller-beheerde entrypoint bereikbaar?
- Word alle oproeppaaie deur sterker invariants as die gemuteerde kontrole beperk?
- Lê die nodus in dooie kode, slegs-formateringslogika, of in 'n hoë-impak-rekenkundige/parser-pad?

Survivors wat onbereikbaar bly of struktureel beperk word, is dikwels **equivalent mutants**. Survivors wat **bereikbaar** bly en aan **boundary conditions**, **overflow/carry paths**, of **sekuriteitskritieke rekenkunde/parsing** raak, moet bevorder word tot:

- nuwe fuzz harnesses
- direkte property/invariant-toetse
- geteikende edge-case-vektore

### Korrelleer eksterne bevindinge met die grafiek

As jou SAST-pipeline **SARIF** uitvoer, projekteer bevindinge op grafieknodusse volgens **file + line range** en gebruik die grafiek om die impak uit te brei.<sup>[[6]](#references)</sup>

- bereken die **blast radius** van die gemerkte funksie
- kontroleer of die bevinding op enige pad vanaf 'n entrypoint lê
- groepeer nabygeleë bevindinge wat tot dieselfde knelpunt saamval

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan 'n spesifieke funksie moet bestee: 'n nodus wat **bereikbaar**, **kompleks** is en reeds **SAST-hits** het, is dikwels 'n beter teiken as 'n bloot komplekse nodus sonder 'n aanvaller-pad.

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
Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutation survivors om te bepaal watter grense en invariants jou harness moet stres.<sup>[[5]](#references)</sup>

## Go Fuzzing met gosentry: Sterker Enjin, Getikte Insette En Differensiële Kontroles

As ’n Go-teiken reeds ’n native `testing.F` harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) uit te voer, ’n gevurkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** omruil.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dit is nuttig wanneer die native Go fuzzer vasval op **moeilike vergelykings**, **getipeerde invoere**, of **parser-swaar formate**. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go` binary in plaas van die standaard toolchain uit.
- Behandel die resulterende campaign as ’n normale coverage-guided run, maar met LibAFL-scheduling/mutation en beter omliggende detectors.

### Verander stil mislukkings in fuzz-bevindings

’n Algemene probleem in Go-assessments is dat gevaarlike gedrag dikwels **nie** by verstek crash nie. Met gosentry kan jy verskeie klasse van “sleg maar stil” toestande in findings omskep.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` om geselekteerde logging/error-paaie soos crashes te laat optree (nuttig vir `log.Fatal`-agtige code paths wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries weer met die Go race detector uit te voer.
- `--catch-leaks=true` om nuwe queue entries weer met `goleak` uit te voer en by goroutine leaks te stop.
- LibAFL-hanghantering om **oneindige lusse / baie stadige invoere** as fuzz-findings te behou, eerder as om hulle as timeouts te laat verdwyn.
- Ingeboude arithmetic overflow checks by verstek, plus opsionele truncation checks deur go-panikint-styl instrumentation.

Dit is veral waardevol vir targets waar die security-impak ’n **panicless parser failure**, ’n **concurrency bug**, of ’n **DoS-only hang** eerder as memory corruption is.

### Struct-aware fuzzing vir getipeerde Go APIs

Native Go fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string`, en getalle. As die code onder toets getipeerde objects verbruik, kan gosentry **composite values** direk fuzz (structs, slices, arrays, pointers), terwyl dit steeds bytes onderliggend muteer.<sup>[[7]](#references)[[8]](#references)</sup>
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
Gebruik dit wanneer die bou van ’n fake wire format net vir fuzzing logikafoute agter parsing code wat slegs vir die harness bestaan, sal versteek. Vir differential- of grammar-based campaigns, hou die harness input as ’n enkele `[]byte` of `string` en parse dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-insette

Vir parsers, formate en input languages kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON array van production rules, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te aanvaar.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodologienotas:

- Gebruik grammar mode wanneer byte-level mutations meestal in vroeë syntax checks doodloop.
- Hou die grammar gefokus op die **security-relevant subset** van die taal/protokol eerder as om die volledige specification te modelleer.
- Gebruik groot boundary values in terminals/nonterminals om integer-, length- en state-machine-grense te stres.
- Grammar mode hou inputs grammar-valid, maar die target ontvang steeds **bytes/strings**, dus bly parsing en semantic checks binne die geharnessde code.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

’n Sterk patroon vir Go ecosystems is **grammar-based differential fuzzing**: genereer geldige gestruktureerde inputs en voer hulle aan twee parsers, clients of state-transition engines.<sup>[[7]](#references)[[8]](#references)</sup>
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
Beskou die volgende as bevindings:

- een implementering panieker terwyl die ander dit netjies verwerp
- verskille tussen aanvaar/verwerpte invoer
- verskillende ontledingsbome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, saldo's of toestandswortels

Dit is ’n praktiese manier om **konsensuswanpassings**, **parser-ambiguïteit** en **spesifikasie-teenoor-implementering-drywing** te vind wat suiwer crash fuzzing dikwels mis.

### Hergebruik die campaign corpus vir dekkingverslagdoening

Ná ’n campaign, speel die gestoorde queue corpus weer af om ’n Go-dekkingsverslag te genereer sonder om handmatig ’n afsonderlike corpus uit te voer.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Voer die opdrag vanuit die **dieselfde pakket** en met die **dieselfde `-fuzz`-teiken** uit sodat gosentry die korrekte gekaste veldtogtoestand kan vind.



## References

- [1] [Mutasionele grammatika-fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in diepte](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet vyf jaar later: Oor dekking-geleide protokol-fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark omskep kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-fuzzing het die helfte van die gereedskapstel ontbreek. Ons het die toolchain gevurk om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: ’n Vinnige greybox-fuzzer vir toestandsgebaseerde netwerkprotokolle wat snapshots gebruik](https://arxiv.org/abs/2202.03643)
- [10] [Geen grammatika, geen probleem: Op pad na fuzzing van die Linux-kern sonder system-call-beskrywings](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Doeltreffende fuzzing met aanpasbare en veranderbare snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM-instrumentasie: pad- en caller-dekking](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Voorspellende kontekssensitiewe fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
