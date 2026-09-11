# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika hali inayoongozwa na coverage, sampuli zinazosababisha **coverage mpya** pekee ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo output ya construct moja inakuwa input ya nyingine.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haidumishi chained dataflow**, hivyo sampuli iliyo “karibu zaidi na bug” huondolewa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination huwa ghali na feedback ya coverage haielekezi search.<sup>[[1]](#references)</sup>

**Implication:** kwa grammars zenye dependencies nyingi, zingatia **hybridizing mutational and generative phases** au kuelekeza generation kwenye mifumo ya **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Changamoto za Corpus Diversity

Coverage-guided mutation ni **greedy**: sampuli yenye coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na maeneo makubwa ambayo hayajabadilika. Baada ya muda, corpora huwa **near-duplicates** zenye structural diversity ndogo. Minimization kali inaweza kuondoa context muhimu, hivyo suluhisho la kati la vitendo ni **grammar-aware minimization** ambayo **husimama baada ya kufikia minimum token threshold** (kupunguza noise huku ikihifadhi structure ya kutosha inayofanya ibaki rafiki kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye tofauti za kistructure zinazoongeza coverage** kuliko mkusanyiko mkubwa wa near-duplicates. Kwa vitendo, hii kwa kawaida humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka kwenye target ecosystem).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Hifadhi seeds zikiwa **ndogo vya kutosha** ili mutations ziguse fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa kwenye harness/instrumentation, kwa sababu corpus “bora zaidi” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation Kwa Magic Values

Sababu ya kawaida inayofanya fuzzers zifike plateau si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Random mutation pekee hupoteza cycles ikijaribu kukisia values hizi byte kwa byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano workflows za AFL++ `CMPLOG` / Redqueen-style) ili fuzzer iweze kuona operands kutoka kwenye comparisons zilizoshindikana na kuelekeza mutations kwenye values zinazokidhi comparisons hizo.<sup>[[3]](#references)</sup>
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
**Maelezo ya kiutendaji:**

- Hii ni muhimu hasa wakati target inaweka logic ya ndani nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iambatanishe na **dictionaries** zilizotolewa kutoka kwenye sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, majina ya chunks, verbs, na delimiters mara nyingi huwa na thamani zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target hufanya ukaguzi mwingi kwa mfuatano, tatua ulinganishaji wa kwanza wa “magic” kisha punguza corpus inayotokana tena ili hatua zinazofuata zianze na prefixes ambazo tayari ni halali.

## Feedback Bora Zaidi Wakati Edge Coverage Inapounganisha Njia Tofauti

Normal edge coverage haiwezi kutofautisha executions mbili zinazopitia helper ileile kupitia callers tofauti au kuchukua mchanganyiko tofauti wa branches ndani ya function. Hili ni muhimu katika shared decoders, protocol dispatchers, na interpreter helpers ambapo **route** kuelekea edge huamua hali inayotumika. Kufuatilia kila calling context bila mpangilio pia ni hatari: coverage map na queue vinaweza kukua kupita kiasi. Kwa hiyo, utafiti wa context-sensitive fuzzing unapendekeza kuboresha contexts zinazoahidi pekee badala ya kuuchukulia call graph wote kuwa context-sensitive.<sup>[[14]](#references)</sup>

AFL++ builds za hivi karibuni hutoa **Ball-Larus per-function path coverage** pamoja na normal edge coverage. Huipa kila acyclic path inayopitia function feature; loop back-edges huondolewa, kwa hiyo feedback hii hutofautisha mchanganyiko wa branches lakini **sio idadi ya loop iterations**. Anza na level `1` iliyo relaxed, kisha tumia modes kali zaidi kwenye parser/state-machine code yenye shaka, kwa sababu idadi ya paths inaweza kukua exponentially.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Kwa helper inayoitwa kutoka kwenye maeneo mengi yanayohusiana na usalama, hali ya LTO inaweza kuchanganya kila function path na call site yake ya moja kwa moja:<sup>[[13]](#references)</sup>
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
**Mwongozo wa campaign:** tumia feedback pana zaidi kwa tahadhari na fuatilia gharama yake kwenye coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Endesha instance ya kawaida ya edge-coverage kwa sambamba; feedback pana zaidi ni muhimu tu ikiwa gharama ya ziada ya queue/map haiharibu executions per second.
- Tumia `AFL_LLVM_ALLOWLIST` kuzuia instrumentation ya path/caller wakati libraries kubwa zenye templates nyingi au generic utility code zinatawala map.
- Functions zenye acyclic paths nyingi kupita kiasi zinaweza kurukwa na AFL++; warnings wakati wa compilation ni ushahidi kwamba target inahitaji allowlisting au level isiyo strict sana.
- Caller + path coverage inasaidia kina kimoja tu cha caller. Usiiunganishe na context stacks zenye kina zaidi.
- Path IDs zinaweza kubadilika kati ya LLVM major versions. Weka toolchain ileile kwa campaign na usisynchronize corpora za PATH kana kwamba feature IDs zake ni thabiti kati ya builds.
- Feedback hii inakamilisha `CMPLOG`: comparison tracing hutatua **ni value gani hupita guard**, ilhali path/caller feedback huhifadhi **ni route na mchanganyiko gani wa branches ulioifikisha hapo**.

## Stateful Fuzzing: Sequences ni Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit inayovutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kuwa file moja na kuimutate bila mpangilio kwa kawaida si efficient, kwa sababu fuzzer humutate kila step kwa kiwango sawa, hata wakati ni message ya baadaye pekee inayofikia state dhaifu.<sup>[[4]](#references)</sup>

Pattern yenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Weka **valid prefix messages** katika hali thabiti na lenga mutations kwenye message **transition-driving**.
- Cache identifiers na values zinazozalishwa na server kutoka kwa responses zilizotangulia wakati hatua inayofuata inazitegemea.
- Pendelea per-message mutation/splicing badala ya kumutate transcript nzima iliyoserializwa kama opaque blob.
- Ikiwa protocol inatoa response codes zenye maana, zitumie kama **cheap state oracle** ili kuzipa kipaumbele sequences zinazoendelea kwa kina zaidi.

Hii ndiyo sababu ileile kwa nini authenticated bugs, hidden transitions, au parser bugs za “only-after-handshake” mara nyingi hukosekana na vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya kiutendaji ya kuchanganya **generative novelty** na **coverage reuse** ni **kuanzisha upya workers wa muda mfupi** dhidi ya persistent server. Kila worker huanza na empty corpus, husynchronize baada ya sekunde `T`, huendesha sekunde nyingine `T` kwenye corpus iliyounganishwa, husynchronize tena, kisha hutoka. Hii huzalisha **fresh structures kila generation** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

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
- Katika grammar fuzzing mode, **initial server sync** hurukwa kwa chaguo-msingi (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadilisha baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hutoa matokeo bora.

## Snapshot Fuzzing Kwa Targets Ngumu Kuandalia Harness

Wakati code unayotaka ku-test inafikika tu baada ya **setup cost** kubwa (kuwasha VM, kukamilisha login, kupokea packet, ku-parse container, au kuanzisha service), njia mbadala muhimu ni **snapshot fuzzing**: hifadhi hali ya process au VM iliyo tayari, ingiza kila test case kwenye input path ya target, endesha hadi crash/timeout, kisha rejesha snapshot. Hii huepuka kurudia initialization au protocol prefixes na ni muhimu kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali muhimu iwe tayari.
2. Hifadhi **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye guest/process buffer husika.
4. Endesha hadi crash/timeout/reset.
5. Rejesha snapshot; kwa VM targets, rejesha **dirty pages** pekee inapowezekana, kisha rudia.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya parse/dispatch, kama baada ya sehemu ya `recv`/`read` au packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya adaptive-placement ya kupeleka snapshot ndani zaidi katika input processing ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Harness Introspection: Tambua Fuzzers Duni Mapema

Campaign inapokwama, tatizo mara nyingi si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kutafuta functions zinazofikika kwa njia ya kawaida kutoka kwenye fuzz target yako lakini ambazo hazifunikwi mara chache au kamwe wakati wa runtime. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness inaingia kwenye target ikiwa imechelewa sana au mapema sana.
- Seed corpus inakosa familia nzima ya features.
- Target inahitaji **second harness** badala ya harness moja kubwa ya “do everything”.

Ukitumia workflows za OSS-Fuzz / ClusterFuzz-style, Fuzz Introspector inaweza kulinganisha static reachability na runtime coverage na kutengeneza reports kutoka kwenye timed run au public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia report kuamua ikiwa uongeze harness mpya kwa parser path ambayo haijajaribiwa, upanue corpus kwa feature maalum, au ugawanye harness moja kubwa kuwa entry points ndogo.

## Uchaguzi wa Fuzz Target wa Graph-First na Triage ya Mutation

Ikiwa tayari una **static-analysis findings**, **mutation-testing survivors**, na **coverage reports**, usizifanyie triage kama orodha zinazojitegemea. Jenga **call graph** kwanza, weka kwenye nodes taarifa za **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, na findings zozote za nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwenye untrusted input?
- Ni mutation survivors zipi zilizo kwenye paths kutoka kwa parsers/handlers hadi kwenye security-critical code?
- Ni functions zipi zilizo architectural choke points zenye **blast radius** kubwa isivyo kawaida?

Hii kwa kawaida huonyesha fuzz targets bora kuliko kutumia "lowest coverage" pekee. Parser/decoder yenye **complexity kubwa** na **external reachability** iliyothibitishwa ni candidate bora wa harness kuliko internal helper iliyotengwa yenye coverage dhaifu lakini isiyo na attacker-controlled path.

### Practical triage workflow

1. Jenga **code graph** kutoka kwenye codebase na utoe complexity/branch metrics za kila function.
2. Orodhesha **entrypoints** zinazopokea input inayodhibitiwa na attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka kwenye entrypoints hizo hadi kwenye candidate functions ili kutenganisha attack surface inayoweza kufikiwa na code iliyokufa/ya ndani pekee.
4. Weka kipaumbele kwa nodes zinazochanganya:
- **cyclomatic complexity** kubwa
- **reachability from untrusted input** iliyothibitishwa
- **blast radius** kubwa au downstream dependents wengi
- ushahidi wa ziada kama **SARIF** findings, audit notes, au mutation survivors
5. Andika harnesses zinazolenga nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent dhidi ya actionable

Mutation testing mara nyingi hutengeneza orodha yenye kelele ya survivors. Kabla ya kuchukulia kila survivor kama pengo la usalama, tumia graph kuuliza:

- Je, function iliyobadilishwa inaweza kufikiwa kutoka kwenye attacker-controlled entrypoint?
- Je, call paths zote zimewekewa mipaka na invariants zenye nguvu kuliko check iliyobadilishwa?
- Je, node iko kwenye dead code, formatting-only logic, au arithmetic/parser path yenye impact kubwa?

Survivors ambazo bado hazifikiwi au zimewekewa mipaka kimuundo mara nyingi ni **equivalent mutants**. Survivors ambazo hubaki **reachable** na kugusa **boundary conditions**, **overflow/carry paths**, au **security-critical arithmetic/parsing** zinapaswa kupandishwa kuwa:

- fuzz harnesses mpya
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Ikiwa SAST pipeline yako inatoa **SARIF**, weka findings kwenye graph nodes kwa kutumia **file + line range** na utumie graph kupanua impact.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyoripotiwa
- angalia ikiwa finding iko kwenye path yoyote kutoka kwenye entrypoint
- panga findings za karibu ambazo huishia kwenye choke point ileile

Hii ni muhimu unapoamua kutumia muda wa fuzzing kwenye function maalum: node ambayo **reachable**, ina **complexity** kubwa, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node iliyo complex tu bila attacker path.

Example workflow with Trailmark.<sup>[[6]](#references)</sup>
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
Methodology muhimu ni makutano ya: **complexity x exposure x impact**. Tumia grafu kuchagua fuzz targets zenye thamani kubwa zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kuamua ni boundaries na invariants zipi harness yako lazima izijaribu kwa nguvu.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Injini Imara Zaidi, Inputs Zenye Aina, na Differential Checks

Ikiwa Go target tayari ina native `testing.F` harness, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), Go toolchain iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Hii ni muhimu wakati native Go fuzzer inakwama kwenye **hard comparisons**, **typed inputs**, au **parser-heavy formats**. Methodology inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya gosentry ya `go` badala ya toolchain ya kawaida.
- Ichukulie campaign inayotokana kama coverage-guided run ya kawaida, lakini ikiwa na LibAFL scheduling/mutation na detectors bora zaidi za pembeni.

### Geuza silent failures kuwa fuzz findings

Tatizo linalojirudia katika Go assessments ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa default. Ukiwa na gosentry, unaweza kubadilisha aina kadhaa za hali za “mbaya lakini kimya” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili kufanya logging/error paths zilizochaguliwa zifanye kazi kama crashes (ni muhimu kwa code paths za mtindo wa `log.Fatal` ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kurudia queue entries mpya zilizogunduliwa kwa kutumia Go race detector.
- `--catch-leaks=true` ili kurudia queue entries mpya kwa kutumia `goleak` na kusitisha inapogunduliwa goroutine leak.
- LibAFL hang handling ili kuweka **infinite loops / very slow inputs** kama fuzz findings badala ya kuziruhusu zipotee kama timeouts.
- Built-in arithmetic overflow checks kwa default, pamoja na truncation checks za hiari kupitia instrumentation ya mtindo wa go-panikint.

Hii ni muhimu hasa kwa targets ambazo security impact yake ni **panicless parser failure**, **concurrency bug**, au **DoS-only hang**, badala ya memory corruption.

### Struct-aware fuzzing kwa typed Go APIs

Native Go fuzzing hulenga zaidi scalars kama `[]byte`, `string`, na numbers. Ikiwa code inayofanyiwa test inatumia typed objects, gosentry inaweza kufuzz **composite values** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea ku-mutate bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>
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
Tumia hii unapounda wire format bandia kwa ajili ya fuzzing pekee, kwani inaweza kuficha hitilafu za logic nyuma ya msimbo wa parsing wa harness. Kwa kampeni za differential au grammar-based, weka ingizo la harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Grammar-based fuzzing kwa parser na ingizo za protocol

Kwa parser, format, na lugha za ingizo, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni array ya JSON iliyo na production rules, na kwa kawaida harness inapaswa kupokea argument moja ya aina ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Tumia grammar mode wakati byte-level mutations nyingi zinashindwa katika ukaguzi wa awali wa syntax.
- Weka grammar ilenge **security-relevant subset** ya language/protocol badala ya kuunda mfano wa specification nzima.
- Tumia boundary values kubwa kwenye terminals/nonterminals ili kujaribu mipaka ya integer, length, na state-machine.
- Grammar mode huweka inputs zikiwa grammar-valid, lakini target bado hupokea **bytes/strings**, hivyo parsing na semantic checks hubaki ndani ya code iliyo kwenye harness.

### Differential fuzzing: linganisha implementations, si crashes pekee

Mfumo imara kwa Go ecosystems ni **grammar-based differential fuzzing**: generate structured inputs halali na kuzipeleka kwa parsers, clients, au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>
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
- parse trees au objects zilizodecode zinatofautiana
- state transitions, nonces, balances, au state roots zinatofautiana

Hii ni njia ya kivitendo ya kugundua **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo mara nyingi hukosekana katika crash fuzzing pekee.

### Tumia tena campaign corpus kwa kuripoti coverage

Baada ya campaign, replay queue corpus iliyohifadhiwa ili kutengeneza ripoti ya Go coverage bila ku-export corpus tofauti mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Tekeleza amri kutoka kwenye **package ileile** na ukiwa na target ileile ya **`-fuzz`** ili gosentry itambue hali sahihi ya kampeni iliyo kwenye cache.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing kwa Kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark hubadilisha code kuwa graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya toolkit. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox Fuzzer ya Haraka kwa Stateful Network Protocols inayotumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Bila Grammar, Hakuna Tatizo: Kuelekea Kufuzz Linux Kernel bila Maelezo ya System-Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Bora kwa kutumia Adaptive na Mutable Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path na caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
