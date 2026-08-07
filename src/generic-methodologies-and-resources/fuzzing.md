# Fuzzing Methodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantiek

In **mutational grammar fuzzing** word inputs gemuteer terwyl hulle **grammar-valid** bly. In coverage-guided mode word slegs samples wat **nuwe coverage** aktiveer, as corpus seeds gestoor. Vir **language targets** (parsers, interpreters, engines) kan dit bugs miskyk wat **semantiese/dataflow-kettings** vereis, waar die uitvoer van een konstruk die invoer van 'n ander word.

**Failure mode:** die fuzzer vind seeds wat individueel `document()` en `generate-id()` (of soortgelyke primitives) uitvoer, maar **bewaar nie die gekoppelde dataflow nie**, sodat die sample wat “nader aan die bug” is, weggegooi word omdat dit nie coverage byvoeg nie. Met **3+ afhanklike stappe** word random recombination duur en coverage-feedback lei nie die soektog nie.

**Implikasie:** vir grammars met baie afhanklikhede, oorweeg dit om **mutational en generative fases te hybridiseer** of generation te bevoordeel wat op **function chaining**-patrone fokus (nie net coverage nie).<sup>[[1]](#references)</sup>

## Slaggate met Corpus Diversity

Coverage-guided mutation is **gulsig**: 'n sample met nuwe coverage word onmiddellik gestoor en behou dikwels groot onveranderde areas. Met verloop van tyd word corpora **byna-duplikate** met lae strukturele diversiteit. Aggressiewe minimization kan nuttige konteks verwyder, dus is 'n praktiese kompromie **grammar-aware minimization** wat **stop ná 'n minimum token-drempel** (verminder geraas terwyl genoeg omliggende struktuur behoue bly om mutation-friendly te wees).<sup>[[1]](#references)</sup>

'n Praktiese corpus-reël vir mutational fuzzing is: **verkies 'n klein stel struktureel verskillende seeds wat coverage maksimeer** bo 'n groot versameling byna-duplikate. In die praktyk beteken dit gewoonlik:<sup>[[1]](#references)</sup>

- Begin met **real-world samples** (public corpora, crawling, captured traffic, file sets uit die target-ekosisteem).
- Distilleer hulle met **coverage-based corpus minimization** eerder as om elke geldige sample te behou.
- Hou seeds **klein genoeg** sodat mutations op betekenisvolle velde land, eerder as om die meeste cycles aan irrelevante bytes te spandeer.
- Voer corpus minimization weer uit ná groot harness/instrumentation-veranderings, omdat die “beste” corpus verander wanneer reachability verander.

## Comparison-Aware Mutation Vir Magic Values

'n Algemene rede waarom fuzzers 'n plato bereik, is nie syntax nie, maar **hard comparisons**: magic bytes, length checks, enum strings, checksums of parser dispatch values wat deur `memcmp`, switch tables of cascaded comparisons beskerm word. Pure random mutation mors cycles deur hierdie waardes byte vir byte te probeer raai.

Vir hierdie targets, gebruik **comparison tracing** (byvoorbeeld AFL++ `CMPLOG` / Redqueen-style workflows) sodat die fuzzer operands van mislukte comparisons kan waarneem en mutations kan bevoordeel wat daarop gemik is om daaraan te voldoen.<sup>[[3]](#references)</sup>
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

- Dit is veral nuttig wanneer die target diep logika agter **file signatures**, **protocol verbs**, **type tags**, of **version-dependent feature bits** versteek.
- Kombineer dit met **dictionaries** wat uit werklike voorbeelde, protocol-spesifikasies, of debug logs onttrek is. ’n Klein dictionary met grammar-tokens, chunk-name, verbs, en delimiters is dikwels waardevoller as ’n massiewe generiese wordlist.
- As die target baie opeenvolgende checks uitvoer, los eers die vroegste “magic”-vergelykings op en minimizeer dan die resulterende corpus weer sodat latere fases vanaf reeds-geldige prefixes begin.

## Stateful Fuzzing: Sequences Are Seeds

Vir **protocols**, **authenticated workflows**, en **multi-stage parsers**, is die interessante eenheid dikwels nie ’n enkele blob nie, maar ’n **message sequence**. Om die hele transcript in een file saam te voeg en dit blindelings te mutate, is gewoonlik ondoeltreffend omdat die fuzzer elke stap ewe veel mutateer, selfs wanneer slegs die latere boodskap die fragile state bereik.

’n Meer doeltreffende patroon is om die **sequence self as die seed** te behandel en **observable state** (response codes, protocol states, parser phases, returned object types) as bykomende feedback te gebruik:<sup>[[4]](#references)</sup>

- Hou **valid prefix messages** stabiel en fokus mutations op die **transition-driving** message.
- Cache identifiers en server-generated values uit vorige responses wanneer die volgende stap daarvan afhanklik is.
- Verkies per-message mutation/splicing bo mutation van die hele serialized transcript as ’n opaque blob.
- As die protocol betekenisvolle response codes blootstel, gebruik dit as ’n **cheap state oracle** om sequences te prioritiseer wat dieper vorder.

Dit is dieselfde rede waarom authenticated bugs, hidden transitions, of parser bugs wat “only-after-handshake” voorkom, dikwels deur vanilla file-style fuzzing gemis word: die fuzzer moet **order, state, en dependencies** behou, nie slegs structure nie.

## Single-Machine Diversity Trick (Jackalope-Style)

’n Praktiese manier om **generative novelty** met **coverage reuse** te hybridiseer, is om **short-lived workers** teen ’n persistente server te restart. Elke worker begin met ’n leë corpus, sync na `T` sekondes, loop nog `T` sekondes op die gekombineerde corpus, sync weer, en exit dan. Dit lewer **fresh structures each generation** terwyl dit steeds opgehoopte coverage benut.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Opeenvolgende werkers (voorbeeldlus):**

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

- `-in empty` forseer ’n **vars corpus** met elke generering.
- `-server_update_interval T` benader **vertraagde sync** (novelty eerste, hergebruik later).
- In grammar fuzzing mode word **initial server sync** by verstek oorgeslaan (geen behoefte aan `-skip_initial_server_sync` nie).
- Optimale `T` is **target-dependent**; om te skakel nadat die worker die meeste “maklike” coverage gevind het, werk gewoonlik die beste.

## Snapshot Fuzzing Vir Moeilik-Om-Te-Harness Teikens

Wanneer die kode wat jy wil toets eers bereikbaar word **nadat ’n groot opstellingskoste aangegaan is** (’n VM begin, ’n login voltooi, ’n packet ontvang, ’n container ontleed of ’n diens geïnisialiseer is), is **snapshot fuzzing** ’n nuttige alternatief:

1. Laat die target loop totdat die interessante toestand gereed is.
2. Maak op daardie punt ’n snapshot van **geheue + registers**.
3. Skryf die gemuteerde input vir elke test case direk na die relevante guest/process buffer.
4. Voer dit uit totdat ’n crash/timeout/reset plaasvind.
5. Herstel slegs die **dirty pages** en herhaal.

Dit voorkom dat die volle opstellingskoste in elke iterasie betaal word en is veral nuttig vir **network services**, **firmware**, **post-auth attack surfaces** en **binary-only targets** wat moeilik is om in ’n klassieke in-process harness te herstruktureer.

’n Praktiese truuk is om onmiddellik ná ’n `recv`/`read`/packet-deserialization-punt te breek, die input buffer se adres aan te teken, en daar ’n snapshot te maak; daarna muteer jy daardie buffer direk in elke iterasie. Dit laat jou toe om die diep parsing-logika te fuzz sonder om elke keer die volledige handshake te herbou.

## Harness Introspection: Vind Shallow Fuzzers Vroeg

Wanneer ’n campaign vashaak, is die probleem dikwels nie die mutator nie, maar die **harness**. Gebruik **reachability/coverage introspection** om funksies te vind wat staties vanaf jou fuzz target bereikbaar is, maar dinamies selde of nooit gedek word nie. Daardie funksies dui gewoonlik op een van drie probleme:

- Die harness betree die target te laat of te vroeg.
- Die seed corpus ontbreek ’n volledige feature family.
- Die target benodig werklik ’n **tweede harness** in plaas van een oorgroot “doen alles”-harness.

As jy OSS-Fuzz / ClusterFuzz-styl workflows gebruik, is Fuzz Introspector nuttig vir hierdie triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gebruik die verslag om te besluit of 'n nuwe harness vir 'n ongetoetste parser-pad bygevoeg moet word, die corpus vir 'n spesifieke kenmerk uitgebrei moet word, of 'n monolitiese harness in kleiner entry points opgesplit moet word.

## Grafiek-eerste Fuzz-teikenkeuse en Mutation-triage

As jy reeds **static-analysis findings**, **mutation-testing survivors** en **coverage reports** het, moenie hulle as onafhanklike lyste triage nie. Bou eers 'n **call graph**, annoteer nodes met **cyclomatic complexity**, **entrypoint/untrusted-input reachability** en enige eksterne bevindings, en vra dan grafiekvrae:<sup>[[5]](#references)[[6]](#references)</sup>

- Watter funksies met hoë kompleksiteit is vanaf untrusted input bereikbaar?
- Watter mutation survivors lê op paaie vanaf parsers/handlers na security-critical code?
- Watter funksies is argitektoniese choke points met 'n buitengewoon groot **blast radius**?

Dit bring gewoonlik beter fuzz-teikens na vore as net "lowest coverage". 'n Parser/decoder met **high complexity** en bevestigde **external reachability** is 'n sterker harness-kandidaat as 'n geïsoleerde interne helper met swak coverage maar sonder 'n attacker-controlled path.

### Praktiese triage-werkvloei

1. Bou 'n **code graph** uit die codebase en onttrek kompleksiteit/branch-metrieke per funksie.
2. Lys **entrypoints** wat attacker-controlled input aanvaar: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Voer **path queries** vanaf daardie entrypoints na kandidaatfunksies uit om reachable attack surface van dooie/interne kode te onderskei.
4. Prioritiseer nodes wat die volgende kombineer:
- hoë **cyclomatic complexity**
- bevestigde **reachability from untrusted input**
- groot **blast radius** of baie downstream dependents
- ondersteunende bewyse soos **SARIF**-findings, ouditnotas of mutation survivors
5. Skryf eers gefokusde harnesses vir die nodes met die hoogste telling, veral **parsers/codecs** soos hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing lewer dikwels 'n raserige lys survivors op. Voordat jy elke survivor as 'n security gap beskou, gebruik die grafiek om te vra:

- Is die gemuteerde funksie vanaf 'n attacker-controlled entrypoint bereikbaar?
- Word alle call paths deur sterker invariants as die gemuteerde check beperk?
- Lê die node in dooie kode, formatting-only logic, of in 'n high-impact arithmetic/parser path?

Survivors wat onbereikbaar bly of struktureel beperk is, is dikwels **equivalent mutants**. Survivors wat **reachable** bly en aan **boundary conditions**, **overflow/carry paths**, of **security-critical arithmetic/parsing** raak, moet bevorder word tot:

- nuwe fuzz harnesses
- direkte property/invariant tests
- geteikende edge-case vectors

### Korrelleer eksterne bevindings met die grafiek

As jou SAST-pipeline **SARIF** uitvoer, projekteer bevindings op graph nodes volgens **file + line range** en gebruik die grafiek om die impak uit te brei:

- bereken die **blast radius** van die gemerkte funksie
- kontroleer of die bevinding op enige pad vanaf 'n entrypoint voorkom
- groepeer nabygeleë bevindings wat by dieselfde choke point aansluit

Dit is nuttig wanneer jy besluit of jy fuzzing-tyd aan 'n spesifieke funksie moet bestee: 'n node wat **reachable**, kompleks is en reeds **SAST hits** het, is dikwels 'n beter teiken as 'n bloot komplekse node sonder 'n attacker path.

Voorbeeld-werkvloei met Trailmark:<sup>[[6]](#references)</sup>
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
Die belangrike metodologie is die kruising: **kompleksiteit x blootstelling x impak**. Gebruik die grafiek om fuzz-teikens met die hoogste verwagte sekuriteitswaarde te kies, en gebruik dan mutasie-oorlewendes om te bepaal watter grense en invariants jou harness moet stres.

## Go Fuzzing met gosentry: Kragtiger enjin, getikte insette en differensiële kontroles

As ’n Go-teiken reeds ’n native `testing.F`-harness het, is ’n praktiese opgraderingspad om dieselfde harness met [gosentry](https://github.com/trailofbits/gosentry) uit te voer — ’n geforkte Go-toolchain wat `go test -fuzz` behou, maar die backend na **LibAFL** vervang.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Dit is nuttig wanneer die native Go fuzzer op **hard comparisons**, **typed inputs** of **parser-heavy formats** vasloop. Die metodologie bly dieselfde:

- Hou aan om `f.Add(...)` vir seeds en `f.Fuzz(...)` vir die callback te gebruik.
- Hergebruik dieselfde harness, maar voer dit met gosentry se `go`-binary in plaas van die standaard toolchain uit.
- Behandel die resulterende campaign as ’n normale coverage-guided run, maar met LibAFL-scheduling/mutation en beter omliggende detectors.

### Verander stil mislukkings in fuzz findings

’n Herhalende probleem in Go-assessments is dat gevaarlike gedrag dikwels by verstek **nie** crash nie. Met gosentry kan jy verskeie klasse van “sleg maar stil” toestande in findings omskep:

- `--panic-on=pkg.Func,...` om geselekteerde logging/error paths soos crashes te laat optree (nuttig vir `log.Fatal`-style code paths wat andersins net log en voortgaan).
- `--catch-races=true` om nuut ontdekte queue entries weer met die Go race detector uit te voer.
- `--catch-leaks=true` om nuwe queue entries weer met `goleak` uit te voer en by goroutine leaks te stop.
- LibAFL-hang handling om **infinite loops / very slow inputs** as fuzz findings te behou, in plaas daarvan om hulle as timeouts te laat verdwyn.
- Ingeboude arithmetic overflow checks by verstek, plus opsionele truncation checks deur go-panikint-style instrumentation.

Dit is veral waardevol vir targets waar die security impact ’n **panicless parser failure**, ’n **concurrency bug** of ’n **DoS-only hang** eerder as memory corruption is.

### Struct-aware fuzzing vir getikte Go-API’s

Native Go fuzzing verwag hoofsaaklik scalars soos `[]byte`, `string` en numbers. As die kode onder toets typed objects verbruik, kan gosentry **composite values** direk fuzz (structs, slices, arrays, pointers) terwyl dit steeds bytes onderliggend muteer.
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
Gebruik dit wanneer die bou van ’n fake wire format slegs vir fuzzing logikafoute agter harness-only parsing code sou verberg. Vir differential- of grammar-based campaigns, hou die harness-invoer as ’n enkele `[]byte` of `string` en parseer dit eerder binne die callback.

### Grammar-based fuzzing vir parsers en protokol-insette

Vir parsers, formate en invoertale kan gosentry **Nautilus grammar fuzzing** bo-op LibAFL uitvoer. Die grammar is ’n JSON-array van produksie-reëls, en die harness behoort gewoonlik ’n enkele `[]byte`- of `string`-argument te aanvaar.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodologienotas:

- Gebruik grammar mode wanneer byte-vlak-mutasies meestal tydens vroeë sintaksiskontroles misluk.
- Hou die grammar gefokus op die **sekuriteitsrelevante subset** van die taal/protokol eerder as om die volledige spesifikasie te modelleer.
- Gebruik groot grenswaardes in terminals/nonterminals om heelgetal-, lengte- en toestandsmasjiengrense te stres.
- Grammar mode hou invoere grammar-geldig, maar die teiken ontvang steeds **bytes/strings**, dus bly ontleding en semantiese kontroles binne die geharnaste kode.

### Differential fuzzing: vergelyk implementerings, nie net crashes nie

'n Sterk patroon vir Go-ekosisteme is **grammar-based differential fuzzing**: genereer geldige gestruktureerde invoere en voer dit aan twee parsers, kliënte of toestands- oorgangsenjins.
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
Beskou die volgende as bevindinge:

- een implementasie paniek, terwyl die ander een dit netjies verwerp
- verskille tussen aanvaar en verwerpte invoer
- verskillende parse-bome of gedekodeerde objekte
- uiteenlopende toestandsoorgange, nonces, balances of state roots

Dit is ’n praktiese manier om **consensus mismatches**, **parser ambiguity** en **spec-vs-implementation drift** te vind wat pure crash fuzzing dikwels mis.

### Hergebruik die campaign corpus vir coverage reporting

Ná ’n campaign, speel die gestoorde queue corpus weer af om ’n Go coverage report te genereer sonder om handmatig ’n aparte corpus uit te voer:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Voer die opdrag uit vanaf dieselfde **package** en met dieselfde `-fuzz`-teiken sodat gosentry die korrekte gekaste veldtogtoestand oplos.

## Verwysings

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Vyf Jaar Later: Oor Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verander kode in grafieke](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing het die helfte van die toolkit ontbreek. Ons het die toolchain gefork om dit reg te stel.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
