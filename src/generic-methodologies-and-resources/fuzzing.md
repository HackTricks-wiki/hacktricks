# Mbinu za Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika coverage-guided mode, samples zinazochochea **coverage mpya** pekee ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo output ya construct moja huwa input ya nyingine.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haihifadhi chained dataflow**, kwa hiyo sample iliyo “karibu zaidi na bug” huondolewa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination huwa ghali na coverage feedback haielekezi search.<sup>[[1]](#references)</sup>

**Implication:** kwa grammars zenye dependencies nyingi, fikiria **hybridizing mutational and generative phases** au kuelekeza generation kwenye patterns za **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Pitfalls za Corpus Diversity

Coverage-guided mutation ni **greedy**: sample yenye coverage mpya huhifadhiwa mara moja, mara nyingi ikiwa na maeneo makubwa ambayo hayajabadilika. Baada ya muda, corpora huwa **near-duplicates** zenye structural diversity ndogo. Minimization kali inaweza kuondoa context muhimu, kwa hiyo compromise ya vitendo ni **grammar-aware minimization** ambayo **husimama baada ya minimum token threshold** (kupunguza noise huku ikihifadhi structure ya kutosha inayobaki rafiki kwa mutation).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye tofauti za kimuundo zinazoongeza coverage** kuliko rundo kubwa la near-duplicates. Kwa vitendo, hii kwa kawaida humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka kwenye target ecosystem).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Hifadhi seeds **ndogo vya kutosha** ili mutations ziguse fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation Kwa Magic Values

Sababu ya kawaida inayofanya fuzzers zifike plateau si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Pure random mutation hupoteza cycles ikijaribu kubashiri values hizi byte-by-byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano workflows za AFL++ `CMPLOG` / Redqueen-style) ili fuzzer iweze kuona operands kutoka kwenye failed comparisons na kuelekeza mutations kuelekea values zinazozitimiza.<sup>[[3]](#references)</sup>
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

- Hii ni muhimu hasa target inapoficha logic ya ndani nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iambatanishe na **dictionaries** zilizotolewa kutoka kwenye sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi huwa na thamani zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target hufanya ukaguzi mwingi wa kufuatana, suluhisha kwanza ulinganishaji wa awali wa “magic”, kisha punguza corpus iliyopatikana tena ili hatua zinazofuata zianze na prefixes ambazo tayari ni valid.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, kitengo cha kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kuwa faili moja na kuimute bila mpangilio kwa kawaida huwa hakufanyi kazi vizuri kwa sababu fuzzer hubadilisha kila hatua kwa kiwango sawa, hata wakati ni message ya baadaye pekee inayofikia state dhaifu.<sup>[[4]](#references)</sup>

Mfumo wenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Weka **valid prefix messages** bila mabadiliko na elekeza mutations kwenye message inayoendesha **transition**.
- Hifadhi identifiers na values zinazozalishwa na server kutoka kwenye responses zilizotangulia wakati hatua inayofuata inazitegemea.
- Pendelea mutation/splicing kwa kila message badala ya kumute transcript nzima iliyoserializwa kama opaque blob.
- Ikiwa protocol inaonyesha response codes zenye maana, zitumie kama **cheap state oracle** ili kuzipa kipaumbele sequences zinazoendelea kwa kina zaidi.

Hii ndiyo sababu ileile ambayo bugs za authenticated, hidden transitions, au parser bugs za “only-after-handshake” mara nyingi hukosa kwenye vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni kuanzisha upya workers wanaodumu kwa muda mfupi dhidi ya server inayoendelea kuhifadhi state. Kila worker huanza na corpus tupu, husync baada ya sekunde `T`, huendesha sekunde nyingine `T` kwenye corpus iliyounganishwa, husync tena, kisha hutoka. Hii huzalisha **fresh structures kila generation** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (mfano wa loop):**

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

- `-in empty` hulazimisha **fresh corpus** katika kila generation.
- `-server_update_interval T` hukadiria **delayed sync** (novelty kwanza, reuse baadaye).
- Katika grammar fuzzing mode, **initial server sync** hurukwa kwa default (hakuna haja ya `-skip_initial_server_sync`).
- `T` inayofaa hutegemea **target**; kubadilisha baada ya worker kupata coverage kubwa ya “easy” kwa kawaida hutoa matokeo bora.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wakati code unayotaka ku-test inafikika tu baada ya gharama kubwa ya setup (ku-boot VM, kukamilisha login, kupokea packet, ku-parse container, ku-initialize service), mbadala muhimu ni **snapshot fuzzing**: capture hali ya process au VM iliyo tayari, inject kila test case kwenye input path ya target, execute hadi crash/timeout, kisha restore snapshot. Hii huepuka kurudia initialization au protocol prefixes na ni muhimu kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali muhimu iwe tayari.
2. Snapshot **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer husika ya guest/process.
4. Execute hadi crash/timeout/reset.
5. Restore snapshot; kwa VM targets, restore tu **dirty pages** inapoungwa mkono, kisha urudie.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya parse/dispatch, kama baada ya sehemu ya `recv`/`read` au packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii hufuata adaptive-placement principle ya kuhamisha snapshot ndani zaidi kwenye input processing ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Campaign inaposimama, tatizo mara nyingi si mutator bali **harness**. Tumia **reachability/coverage introspection** kupata functions ambazo zinaweza kufikiwa statically kutoka kwenye fuzz target yako lakini hufunikwa mara chache au kamwe dynamically. Functions hizo kwa kawaida huonyesha mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness inaingia kwenye target ikiwa imechelewa sana au mapema sana.
- Seed corpus haina family nzima ya feature.
- Target inahitaji kweli **second harness** badala ya harness moja kubwa ya “do everything”.

Ukitumia workflows za OSS-Fuzz / ClusterFuzz-style, Fuzz Introspector inaweza kulinganisha static reachability na runtime coverage na kutengeneza reports kutoka kwenye timed run au public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia ripoti kuamua ikiwa uongeze harness mpya kwa parser path ambayo haijajaribiwa, upanue corpus kwa feature maalum, au ugawanye harness kubwa ya monolithic kuwa entry points ndogo.

## Graph-First Fuzz Target Selection And Mutation Triage

Ikiwa tayari una **static-analysis findings**, **mutation-testing survivors**, na **coverage reports**, usizifanyie triage kama orodha zinazojitegemea. Anza kwa kujenga **call graph**, weka kwenye nodes maelezo ya **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, na findings zozote za nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwa untrusted input?
- Ni mutation survivors zipi zilizo kwenye paths kutoka kwa parsers/handlers hadi kwenye security-critical code?
- Ni functions zipi zilizo architectural choke points zenye **blast radius** kubwa isiyo ya kawaida?

Hii kwa kawaida huibua fuzz targets bora kuliko kutegemea "lowest coverage" pekee. Parser/decoder yenye **high complexity** na **external reachability** iliyothibitishwa ni candidate bora zaidi wa harness kuliko internal helper iliyojitenga yenye coverage dhaifu lakini isiyo na attacker-controlled path.

### Practical triage workflow

1. Jenga **code graph** kutoka kwenye codebase na utoe vipimo vya complexity/branch kwa kila function.
2. Orodhesha **entrypoints** zinazopokea input inayodhibitiwa na attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka kwenye entrypoints hizo hadi kwenye candidate functions ili kutenganisha attack surface inayofikika na code iliyokufa/internal-only.
4. Tanguliza nodes zinazochanganya:
- **high cyclomatic complexity**
- **confirmed reachability from untrusted input**
- **high blast radius** au downstream dependents wengi
- ushahidi wa ziada kama **SARIF** findings, audit notes, au mutation survivors
5. Andika harnesses zinazolenga nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing mara nyingi hutengeneza survivor list yenye kelele nyingi. Kabla ya kuchukulia kila survivor kama security gap, tumia graph kuuliza:

- Je, mutated function inaweza kufikiwa kutoka kwa attacker-controlled entrypoint?
- Je, call paths zote zimewekewa mipaka na invariants imara zaidi kuliko check iliyobadilishwa?
- Je, node iko kwenye dead code, formatting-only logic, au kwenye high-impact arithmetic/parser path?

Survivors zinazoendelea kutofikika au zilizozuiliwa kimuundo mara nyingi ni **equivalent mutants**. Survivors zinazoendelea **reachable** na kugusa **boundary conditions**, **overflow/carry paths**, au **security-critical arithmetic/parsing** zinapaswa kupandishwa kuwa:

- fuzz harnesses mpya
- property/invariant tests za moja kwa moja
- targeted edge-case vectors

### Correlate external findings onto the graph

Ikiwa SAST pipeline yako inatoa **SARIF**, project findings kwenye graph nodes kwa kutumia **file + line range**, kisha tumia graph kupanua impact.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya flagged function
- angalia ikiwa finding iko kwenye path yoyote kutoka kwa entrypoint
- cluster findings zilizo karibu ambazo zinaishia kwenye choke point ileile

Hii ni muhimu unapoamua ikiwa utumie muda wa fuzzing kwenye function maalum: node ambayo ni **reachable**, **complex**, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node iliyo complex tu bila attacker path.

Mfano wa workflow kwa kutumia Trailmark.<sup>[[6]](#references)</sup>
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
Mbinu muhimu ni makutano ya: **complexity x exposure x impact**. Tumia graph kuchagua fuzz targets zenye security value inayotarajiwa zaidi, kisha tumia mutation survivors kuamua ni boundaries na invariants zipi harness yako inapaswa ku-stress.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Injini Imara Zaidi, Typed Inputs, Na Differential Checks

Ikiwa Go target tayari ina native `testing.F` harness, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), Go toolchain iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Hii ni muhimu wakati native Go fuzzer inakwama kwenye **hard comparisons**, **typed inputs**, au **parser-heavy formats**. Methodology inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya gosentry `go` badala ya stock toolchain.
- Chukulia campaign inayotokana kama coverage-guided run ya kawaida, lakini ikiwa na LibAFL scheduling/mutation na detectors bora zaidi za pembeni.

### Geuza failures zisizoonekana kuwa fuzz findings

Tatizo linalojirudia katika tathmini za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa default. Ukiwa na gosentry, unaweza kubadilisha aina kadhaa za hali “mbaya lakini zisizoonekana” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` ili kufanya logging/error paths zilizochaguliwa zitende kama crashes (ni muhimu kwa code paths za mtindo wa `log.Fatal` ambazo vinginevyo hu-log tu na kuendelea).
- `--catch-races=true` ili kurudia queue entries mpya zilizogunduliwa kwa kutumia Go race detector.
- `--catch-leaks=true` ili kurudia queue entries mpya kwa kutumia `goleak` na kusitisha inapogunduliwa goroutine leak.
- LibAFL hang handling ili kuhifadhi **infinite loops / very slow inputs** kama fuzz findings badala ya kuziruhusu zipotee kama timeouts.
- Arithmetic overflow checks zilizojengwa ndani kwa default, pamoja na truncation checks za hiari kupitia instrumentation ya mtindo wa go-panikint.

Hii ni muhimu hasa kwa targets ambazo security impact yake ni **panicless parser failure**, **concurrency bug**, au **DoS-only hang**, badala ya memory corruption.

### Struct-aware fuzzing kwa typed Go APIs

Native Go fuzzing hulenga zaidi scalars kama `[]byte`, `string`, na numbers. Ikiwa code inayojaribiwa inatumia typed objects, gosentry inaweza kufuzz **composite values** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kubadilisha bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>
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
Tumia hii wakati wa kuunda wire format bandia kwa ajili ya fuzzing pekee, kwa sababu kufanya hivyo kunaweza kuficha hitilafu za logic nyuma ya code ya parsing ya harness pekee. Kwa kampeni za differential au grammar-based, weka input ya harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Grammar-based fuzzing kwa parsers na protocol inputs

Kwa parsers, formats, na input languages, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni array ya JSON iliyo na production rules, na harness kwa kawaida inapaswa kupokea argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Tumia grammar mode wakati byte-level mutations kwa kiasi kikubwa hufa katika ukaguzi wa sintaksia wa awali.
- Weka grammar ikilenga **security-relevant subset** ya language/protocol badala ya kuiga specification nzima.
- Tumia large boundary values katika terminals/nonterminals ili kusisitiza mipaka ya integer, length, na state-machine.
- Grammar mode huweka inputs grammar-valid, lakini target bado hupokea **bytes/strings**, hivyo parsing na semantic checks hubaki ndani ya code iliyowekwa kwenye harness.

### Differential fuzzing: linganisha implementations, si crashes pekee

Muundo madhubuti kwa Go ecosystems ni **grammar-based differential fuzzing**: tengeneza inputs halali zilizopangwa na uzipitishe kwa parsers, clients, au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>
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
Chukulia yafuatayo kuwa findings:

- implementation moja hupata panic huku nyingine ikikataa kwa usafi
- kutolingana kwa input inayokubaliwa/kukataliwa
- parse trees au objects zilizodecodewa zinazotofautiana
- state transitions, nonces, balances, au state roots zinazotofautiana

Hii ni njia ya vitendo ya kupata **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo fuzzing ya crash pekee mara nyingi hukosa.

### Tumia tena campaign corpus kwa kuripoti coverage

Baada ya campaign, replay saved queue corpus ili kutengeneza ripoti ya Go coverage bila ku-export corpus tofauti wewe mwenyewe.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Tumia amri hiyo kutoka **package ileile** na ukiwa na target ileile ya `-fuzz` ili gosentry itambue hali sahihi ya campaign iliyohifadhiwa.

## References

- [1] [Fuzzing ya grammar ya mutational](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing ya AFL++ kwa kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet miaka mitano baadaye: Kuhusu fuzzing ya protocols inayoongozwa na coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark inabadilisha code kuwa graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya toolkit. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox fuzzer ya haraka kwa stateful network protocols inayotumia snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna grammar, hakuna tatizo: Kuelekea kufuzz Linux kernel bila maelezo ya system-call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing yenye ufanisi kwa snapshots zinazobadilika na kujirekebisha](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
