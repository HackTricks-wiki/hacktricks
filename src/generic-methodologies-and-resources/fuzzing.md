# Methodology ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikisalia kuwa **grammar-valid**. Katika hali inayoongozwa na coverage, ni samples zinazosababisha **new coverage** pekee zinazohifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo output ya construct moja inakuwa input ya nyingine.

**Failure mode:** fuzzer hupata seeds zinazotekeleza `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haihifadhi chained dataflow**, hivyo sample iliyo “karibu zaidi na bug” huondolewa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination huwa ghali na coverage feedback haielekezi search.

**Implication:** kwa grammars zilizo na dependencies nyingi, zingatia **hybridizing mutational and generative phases** au kuelekeza generation kwenye patterns za **function chaining** (sio coverage pekee).<sup>[[1]](#references)</sup>

## Pitfalls za Corpus Diversity

Coverage-guided mutation ni **greedy**: sample yenye new-coverage huhifadhiwa mara moja, mara nyingi ikiwa na sehemu kubwa ambazo hazijabadilishwa. Baada ya muda, corpora huwa **near-duplicates** zenye structural diversity ndogo. Minimization kali inaweza kuondoa context muhimu, hivyo suluhisho la kivitendo ni **grammar-aware minimization** ambayo **husimama baada ya kiwango cha chini cha token** (kupunguza noise huku ikihifadhi surrounding structure ya kutosha ili kubaki rahisi kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya kivitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye tofauti za kimuundo zinazoongeza coverage** badala ya rundo kubwa la near-duplicates. Kwa kawaida, hii humaanisha:<sup>[[1]](#references)</sup>

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka kwenye target ecosystem).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Hifadhi seeds zilizo **ndogo vya kutosha** ili mutations zilenge fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation For Magic Values

Sababu ya kawaida ya fuzzers kufika plateau si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Pure random mutation hupoteza cycles ikijaribu kubashiri values hizi byte kwa byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano workflows za AFL++ `CMPLOG` / Redqueen-style) ili fuzzer iweze kuona operands kutoka kwenye failed comparisons na kuelekeza mutations kwenye values zinazozitimiza.<sup>[[3]](#references)</sup>
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
**Vidokezo vya vitendo:**

- Hii ni muhimu hasa wakati target inaweka logic ya kina nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iambatanishe na **dictionaries** zilizotolewa kutoka kwa samples halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi huwa na thamani zaidi kuliko generic wordlist kubwa sana.
- Ikiwa target hufanya checks nyingi kwa mfuatano, suluhisha kwanza comparisons za mapema za “magic”, kisha minimize corpus inayotokana tena ili stages zinazofuata zianze kutoka kwa prefixes ambazo tayari ni valid.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit inayovutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript yote kuwa file moja na kuimutate bila mpangilio kwa kawaida si efficient kwa sababu fuzzer humutate kila hatua kwa kiwango sawa, hata wakati ni message ya baadaye pekee inayofikia state dhaifu.

Pattern yenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada:<sup>[[4]](#references)</sup>

- Weka **valid prefix messages** zikiwa stable na elekeza mutations kwenye message inayoendesha **transition**.
- Cache identifiers na values zinazozalishwa na server kutoka kwa responses zilizotangulia wakati hatua inayofuata inazitegemea.
- Pendelea per-message mutation/splicing badala ya ku-mutate transcript yote iliyoserializwa kama opaque blob.
- Ikiwa protocol inaonyesha response codes zenye maana, zitumie kama **cheap state oracle** ili kuzipa kipaumbele sequences zinazoendelea kwa kina zaidi.

Hii ndiyo sababu ileile kwa nini authenticated bugs, hidden transitions, au parser bugs za “only-after-handshake” mara nyingi hukosekana na vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuunganisha **generative novelty** na **coverage reuse** ni ku-restart workers wanaoishi kwa muda mfupi dhidi ya server persistent. Kila worker huanza kutoka corpus tupu, husync baada ya `T` seconds, huendesha `T` seconds nyingine kwenye corpus iliyounganishwa, husync tena, kisha hutoka. Hii hutoa **fresh structures kila generation** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers wa mfululizo (mfano wa loop):**

<details>
<summary>Loop ya kuanzisha upya worker wa Jackalope</summary>
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

- `-in empty` hulazimisha **fresh corpus** katika kila generation.
- `-server_update_interval T` hukadiria **delayed sync** (novelty kwanza, reuse baadaye).
- Katika grammar fuzzing mode, **initial server sync** hurukwa kwa default (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadilisha baada ya worker kupata sehemu kubwa ya “easy” coverage kwa kawaida hutoa matokeo bora.

## Snapshot Fuzzing Kwa Targets Zenye Ugumu wa Kutengeneza Harness

Wakati code unayotaka ku-test inafikika tu baada ya **setup cost** kubwa (kuwasha VM, kukamilisha login, kupokea packet, ku-parse container, kuanzisha service), njia mbadala muhimu ni **snapshot fuzzing**:

1. Endesha target hadi hali inayovutia iwe tayari.
2. Tengeneza snapshot ya **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Endesha hadi crash/timeout/reset.
5. Rejesha **dirty pages** pekee na urudie.

Hii huepuka kulipia setup cost kamili katika kila iteration na ni muhimu hasa kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets** ambazo ni ngumu kuzirefactor ziwe classic in-process harness.

Mbinu ya vitendo ni kusitisha mara moja baada ya sehemu ya `recv`/`read`/packet-deserialization, kuandika anwani ya input buffer, kisha kutengeneza snapshot hapo na kubadilisha buffer hiyo moja kwa moja katika kila iteration. Hii hukuruhusu ku-fuzz deep parsing logic bila kujenga upya handshake yote kila mara.

## Harness Introspection: Tambua Shallow Fuzzers Mapema

Campaign inapokwama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kutafuta functions ambazo zinaweza kufikiwa statically kutoka kwenye fuzz target yako lakini hazi-coverwi mara chache au kamwe dynamically. Functions hizo kwa kawaida huashiria moja ya matatizo matatu:

- Harness inaingia kwenye target ikiwa imechelewa sana au mapema sana.
- Seed corpus haina feature family nzima.
- Target inahitaji kweli **second harness** badala ya harness moja kubwa ya “do everything”.

Ikiwa unatumia workflows za OSS-Fuzz / ClusterFuzz-style, Fuzz Introspector ni muhimu kwa triage hii:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia ripoti kuamua ikiwa uongeze **harness** mpya kwa njia ya parser ambayo haijapimwa, upanue corpus kwa feature maalum, au ugawanye harness kubwa ya monolithic kuwa entry point ndogo.

## Uchaguzi wa Fuzz Target kwa Kipaumbele cha Graph na Triage ya Mutation

Ikiwa tayari una **static-analysis findings**, **mutation-testing survivors**, na **coverage reports**, usizifanyie triage kama orodha huru. Jenga **call graph** kwanza, weka maelezo ya **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, na findings zozote za nje kwenye nodes, kisha uliza maswali kuhusu graph:<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinaweza kufikiwa kupitia untrusted input?
- Ni mutation survivors zipi zilizo kwenye paths kutoka kwa parsers/handlers hadi kwenye security-critical code?
- Ni functions zipi ni architectural choke points zenye **blast radius** kubwa isivyo kawaida?

Kwa kawaida, hii hubainisha fuzz targets bora kuliko kutegemea "lowest coverage" pekee. Parser/decoder yenye **high complexity** na **external reachability** iliyothibitishwa ni candidate bora zaidi wa harness kuliko internal helper iliyojitenga yenye coverage dhaifu lakini isiyokuwa na path inayodhibitiwa na mshambulizi.

### Practical triage workflow

1. Jenga **code graph** kutoka kwenye codebase na utoe complexity/branch metrics kwa kila function.
2. Orodhesha **entrypoints** zinazopokea input inayodhibitiwa na mshambulizi: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka kwenye entrypoints hizo hadi kwenye candidate functions ili kutenganisha attack surface inayofikika na code iliyokufa/ya ndani pekee.
4. Wape kipaumbele nodes zinazochanganya:
- **cyclomatic complexity** kubwa
- **reachability from untrusted input** iliyothibitishwa
- **blast radius** kubwa au downstream dependents wengi
- Ushahidi unaothibitisha, kama **SARIF** findings, audit notes, au mutation survivors
5. Andika harnesses zilizolenga nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing mara nyingi hutoa orodha kubwa yenye kelele ya survivors. Kabla ya kuchukulia kila survivor kuwa pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye entrypoint inayodhibitiwa na mshambulizi?
- Je, call paths zote zinadhibitiwa na invariants zenye nguvu zaidi kuliko check iliyobadilishwa?
- Je, node hiyo iko kwenye dead code, logic inayohusu formatting pekee, au kwenye arithmetic/parser path yenye impact kubwa?

Survivors ambao hawawezi kufikiwa au ambao wamewekewa constraints za kimuundo mara nyingi ni **equivalent mutants**. Survivors wanaobaki **reachable** na kugusa **boundary conditions**, **overflow/carry paths**, au **security-critical arithmetic/parsing** wanapaswa kuendelezwa kuwa:

- fuzz harnesses mpya
- property/invariant tests za moja kwa moja
- targeted edge-case vectors

### Correlate external findings onto the graph

Ikiwa SAST pipeline yako inatoa **SARIF**, weka findings kwenye graph nodes kwa kutumia **file + line range** na utumie graph kupanua impact:

- Kokotoa **blast radius** ya function iliyo-flagged
- Kagua ikiwa finding hiyo iko kwenye path yoyote kutoka kwenye entrypoint
- Panga findings zilizo karibu ambazo zinaishia kwenye choke point ileile

Hii ni muhimu unapoamua kutumia muda wa fuzzing kwenye function maalum: node ambayo **reachable**, ina complexity kubwa, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node yenye complexity kubwa pekee bila attacker path.

Mfano wa workflow na Trailmark:<sup>[[6]](#references)</sup>
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
Methodology muhimu ni makutano ya: **complexity x exposure x impact**. Tumia graph kuchagua fuzz targets zenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kuamua ni boundaries na invariants zipi harness yako lazima izifanyie stress.

## Go Fuzzing With gosentry: Engine Imara Zaidi, Typed Inputs, Na Differential Checks

Ikiwa Go target tayari ina harness ya asili ya `testing.F`, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), toolchain ya Go iliyoforkiwa inayohifadhi `go test -fuzz` lakini kubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Hii ni muhimu wakati native Go fuzzer inakwama kwenye **hard comparisons**, **typed inputs**, au **parser-heavy formats**. Methodology inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya gosentry ya `go` badala ya stock toolchain.
- Chukulia campaign inayotokana kama coverage-guided run ya kawaida, lakini yenye LibAFL scheduling/mutation na detectors bora zaidi zinazozunguka.

### Badilisha failures zisizoonekana kuwa fuzz findings

Tatizo linalojirudia katika tathmini za Go ni kwamba behaviour hatari mara nyingi **haisababishi crash** kwa default. Ukiwa na gosentry, unaweza kubadilisha aina kadhaa za hali za “bad but silent” kuwa findings:

- `--panic-on=pkg.Func,...` ili kufanya logging/error paths zilizochaguliwa zitende kama crashes (ni muhimu kwa code paths za mtindo wa `log.Fatal` ambazo vinginevyo hu-log tu na kuendelea).
- `--catch-races=true` ili kurudia queue entries mpya zilizogunduliwa kwa Go race detector.
- `--catch-leaks=true` ili kurudia queue entries mpya kwa `goleak` na kusitisha inapogundua goroutine leaks.
- LibAFL hang handling ili kuhifadhi **infinite loops / very slow inputs** kama fuzz findings badala ya kuziacha zipotee kama timeouts.
- Built-in arithmetic overflow checks kwa default, pamoja na truncation checks za hiari kupitia instrumentation ya mtindo wa go-panikint.

Hii ni muhimu hasa kwa targets ambazo security impact yake ni **panicless parser failure**, **concurrency bug**, au **DoS-only hang**, badala ya memory corruption.

### Struct-aware fuzzing kwa typed Go APIs

Native Go fuzzing hutegemea zaidi scalars kama `[]byte`, `string`, na nambari. Ikiwa code inayofanyiwa test inapokea typed objects, gosentry inaweza kufuzz **composite values** moja kwa moja (structs, slices, arrays, pointers), huku ikiendelea ku-mutate bytes zilizo chini yake.
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
Tumia hii unapounda fake wire format kwa ajili ya fuzzing pekee, kwani kufanya hivyo kungejificha logic bugs nyuma ya parsing code ya harness pekee. Kwa kampeni za differential au grammar-based, weka harness input kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Grammar-based fuzzing kwa parsers na protocol inputs

Kwa parsers, formats, na input languages, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni JSON array ya production rules, na harness kwa kawaida inapaswa kupokea argument moja ya `[]byte` au `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Tumia grammar mode wakati byte-level mutations nyingi hufa katika ukaguzi wa awali wa syntax.
- Weka grammar ikilenga **security-relevant subset** ya language/protocol badala ya kuiga full specification.
- Tumia boundary values kubwa katika terminals/nonterminals ili kujaribu mipaka ya integers, lengths, na state-machine.
- Grammar mode huweka inputs zikiwa grammar-valid, lakini target bado hupokea **bytes/strings**, hivyo parsing na semantic checks hubaki ndani ya code inayoharnessiwa.

### Differential fuzzing: linganisha implementations, si crashes pekee

Muundo wenye nguvu katika Go ecosystems ni **grammar-based differential fuzzing**: tengeneza valid structured inputs na uzitumie kwa parsers, clients, au state-transition engines mbili.
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
Chukulia yafuatayo kama findings:

- implementation moja inapata panic huku nyingine ikikataa kwa usafi
- kutolingana kwa input inayokubaliwa/kukataliwa
- parse trees au objects zilizodecodewa zinatofautiana
- mabadiliko ya hali, nonces, salio, au state roots yanatofautiana

Hii ni njia ya kiutendaji ya kupata **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo fuzzing ya kutafuta crashes pekee mara nyingi hukosa.

### Tumia tena campaign corpus kwa kuripoti coverage

Baada ya campaign, replay saved queue corpus ili kuzalisha Go coverage report bila ku-export corpus tofauti wewe mwenyewe:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Tekeleza amri kutoka **package ile ile** na ukiwa na target ile ile ya `-fuzz`, ili gosentry itatue hali sahihi ya campaign iliyohifadhiwa kwenye cache.

## Marejeo

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing kwa Kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Protocol Fuzzing Inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha code kuwa graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya toolkit. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
