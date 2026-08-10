# Mbinu ya Fuzzing

## Mutational Grammar Fuzzing: Coverage dhidi ya Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikiendelea kuwa **grammar-valid**. Katika coverage-guided mode, samples zinazochochea **new coverage** pekee ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains**, ambapo output ya construct moja huwa input ya nyingine.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer hupata seeds zinazotumia `document()` na `generate-id()` (au primitives zinazofanana) kila moja kivyake, lakini **haihifadhi chained dataflow**, hivyo sample iliyo “karibu zaidi na bug” hutupiliwa mbali kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination huwa ghali na coverage feedback haielekezi search.<sup>[[1]](#references)</sup>

**Implication:** kwa grammars zenye dependencies nyingi, zingatia **kuunganisha mutational na generative phases** au kuelekeza generation kwenye patterns za **function chaining** (si coverage pekee).<sup>[[1]](#references)</sup>

## Changamoto za Corpus Diversity

Coverage-guided mutation ni **greedy**: sample yenye new coverage huhifadhiwa mara moja, mara nyingi ikiwa na sehemu kubwa ambazo hazijabadilika. Baada ya muda, corpora huwa **near-duplicates** zenye structural diversity ndogo. Minimization kali inaweza kuondoa context muhimu, hivyo compromise ya vitendo ni **grammar-aware minimization** ambayo **husimama baada ya minimum token threshold** (kupunguza noise huku ikihifadhi structure ya kutosha inayofanya mutations ziwe rahisi).<sup>[[1]](#references)</sup>

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea seti ndogo ya seeds zenye tofauti za kimuundo zinazoongeza coverage** kuliko rundo kubwa la near-duplicates. Kwa vitendo, hii kwa kawaida humaanisha yafuatayo.<sup>[[1]](#references)[[3]](#references)</sup>

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka kwenye target ecosystem).
- Zichuje kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Weka seeds **ndogo vya kutosha** ili mutations ziguse meaningful fields badala ya kutumia cycles nyingi kwenye bytes zisizo muhimu.
- Rudia corpus minimization baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation kwa Magic Values

Sababu ya kawaida inayofanya fuzzers zifike plateau si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Pure random mutation hupoteza cycles ikijaribu kubashiri values hizi byte kwa byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano workflows za AFL++ `CMPLOG` / Redqueen-style) ili fuzzer iweze kuona operands kutoka kwenye comparisons zilizoshindwa na kuelekeza mutations kwenye values zinazozitimiza.<sup>[[3]](#references)</sup>
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
**Maelezo ya kivitendo:**

- Hii ni muhimu hasa wakati target inaweka logic ya kina nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwenye samples halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, majina ya chunks, verbs, na delimiters mara nyingi huwa na thamani zaidi kuliko wordlist kubwa ya jumla.
- Ikiwa target inafanya checks nyingi kwa mfuatano, tatua kwanza comparisons za awali za “magic”, kisha minimize corpus inayotokana tena ili stages za baadaye zianze na prefixes ambazo tayari ni valid.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit ya kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kuwa file moja na ku-mutate bila mpangilio kwa kawaida si efficient, kwa sababu fuzzer inabadilisha kila step kwa kiwango sawa, hata wakati message ya baadaye pekee ndiyo inafikia state dhaifu.<sup>[[4]](#references)</sup>

Pattern yenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada.<sup>[[4]](#references)</sup>

- Weka **valid prefix messages** zikiwa stable na elekeza mutations kwenye message inayoendesha **transition**.
- Cache identifiers na values zinazotengenezwa na server kutoka kwenye responses zilizotangulia wakati hatua inayofuata inazitegemea.
- Pendelea mutation/splicing ya kila message badala ya ku-mutate transcript nzima iliyoserializwa kama opaque blob.
- Ikiwa protocol inaonyesha response codes zenye maana, zitumie kama **cheap state oracle** ili kuipa kipaumbele sequences zinazoingia ndani zaidi.

Hii ndiyo sababu hiyo hiyo bugs za authenticated, transitions zilizofichwa, au parser bugs zinazotokea “only-after-handshake” mara nyingi hukosekana kwenye file-style fuzzing ya kawaida: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya kivitendo ya kuunganisha **generative novelty** na **coverage reuse** ni kuanzisha upya workers wanaoishi muda mfupi dhidi ya server inayoendelea kuwepo. Kila worker huanza na corpus tupu, husync baada ya sekunde `T`, huendesha sekunde nyingine `T` kwenye corpus iliyounganishwa, husync tena, kisha hu-exit. Hii huzalisha **structures mpya kila generation** huku ikiendelea kutumia coverage iliyokusanywa.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers wa mfululizo (mfano wa loop):**

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
- `T` bora hutegemea **target**; kubadilisha baada ya worker kupata sehemu kubwa ya coverage “rahisi” kwa kawaida hufanya kazi vizuri.

## Snapshot Fuzzing Kwa Targets Zenye Ugumu wa Kuandaliwa

Wakati code unayotaka ku-test inafikika tu baada ya gharama kubwa ya setup (ku-boot VM, kukamilisha login, kupokea packet, ku-parse container, au ku-initialize service), njia mbadala yenye manufaa ni **snapshot fuzzing**: capture hali ya process au VM ikiwa tayari, ingiza kila test case kwenye njia ya input ya target, endesha hadi crash/timeout, kisha restore snapshot. Hii huepuka kurudia initialization au protocol prefixes na ni muhimu kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Endesha target hadi hali inayohitajika iwe tayari.
2. Snapshot **memory + registers** wakati huo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye buffer inayohusika ya guest/process.
4. Endesha hadi crash/timeout/reset.
5. Restore snapshot; kwa VM targets, restore tu **dirty pages** inapowezekana, kisha rudia.

Weka snapshot karibu iwezekanavyo na hatua ya kwanza ya gharama kubwa ya parse/dispatch, kama vile baada ya sehemu ya `recv`/`read` au packet-deserialization, na rekodi input buffer inayotumiwa na target. Hii hufuata kanuni ya adaptive-placement ya kupeleka snapshot ndani zaidi katika input processing ili kuepuka kurudia kazi.<sup>[[11]](#references)</sup>

## Harness Introspection: Tambua Shallow Fuzzers Mapema

Campaign inapokwama, mara nyingi tatizo si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kutambua functions ambazo zinaweza kufikiwa statically kutoka kwenye fuzz target yako lakini hufunikwa mara chache au hazifunikwi kabisa dynamically. Functions hizo kwa kawaida huashiria mojawapo ya matatizo matatu.<sup>[[12]](#references)</sup>

- Harness inaingia kwenye target ikiwa imechelewa sana au mapema sana.
- Seed corpus haina family nzima ya feature.
- Target kwa kweli inahitaji **second harness** badala ya harness moja kubwa ya “do everything”.

Ukitumia workflows za OSS-Fuzz / ClusterFuzz-style, Fuzz Introspector inaweza kulinganisha static reachability na runtime coverage na kutengeneza reports kutoka timed run au public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Tumia ripoti kuamua ikiwa uongeze harness mpya kwa parser path ambayo haijajaribiwa, upanue corpus kwa feature mahususi, au ugawanye harness kubwa ya monolithic kuwa entry points ndogo.

## Uchaguzi wa Fuzz Target na Mutation Triage kwa Kipaumbele cha Graph

Ikiwa tayari una **static-analysis findings**, **mutation-testing survivors**, na **coverage reports**, usizifanyie triage kama orodha zinazojitegemea. Jenga **call graph** kwanza, weka maelezo kwenye nodes yenye **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, na findings zozote za nje, kisha uliza maswali kuhusu graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ni functions zipi zenye complexity kubwa zinazoweza kufikiwa kutoka kwenye untrusted input?
- Ni mutation survivors zipi zilizo kwenye paths kutoka kwa parsers/handlers hadi security-critical code?
- Ni functions zipi zilizo architectural choke points zenye **blast radius** kubwa isiyo ya kawaida?

Kwa kawaida, hii huibua fuzz targets bora kuliko kutumia "lowest coverage" pekee. Parser/decoder yenye **high complexity** na **external reachability** iliyothibitishwa ni candidate bora wa harness kuliko internal helper iliyojitenga yenye coverage dhaifu lakini isiyo na attacker-controlled path.

### Practical triage workflow

1. Jenga **code graph** kutoka kwenye codebase na utoe complexity/branch metrics kwa kila function.
2. Orodhesha **entrypoints** zinazopokea attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Endesha **path queries** kutoka kwenye entrypoints hizo hadi candidate functions ili kutenganisha attack surface inayofikika na code iliyokufa/ya ndani pekee.
4. Pa kipaumbele nodes zinazochanganya:
- **cyclomatic complexity** kubwa
- **reachability from untrusted input** iliyothibitishwa
- **blast radius** kubwa au downstream dependents wengi
- ushahidi wa ziada kama **SARIF** findings, audit notes, au mutation survivors
5. Andika harnesses zinazolenga nodes zenye alama bora kwanza, hasa **parsers/codecs** kama hex/Base64/IP/message decoders.

### Mutation survivors: equivalent dhidi ya actionable

Mutation testing mara nyingi hutoa orodha yenye kelele ya survivors. Kabla ya kuchukulia kila survivor kama security gap, tumia graph kuuliza:

- Je, mutated function inaweza kufikiwa kutoka kwenye attacker-controlled entrypoint?
- Je, call paths zote zimezuiwa na stronger invariants kuliko check iliyobadilishwa?
- Je, node iko kwenye dead code, formatting-only logic, au kwenye high-impact arithmetic/parser path?

Survivors zinazobaki hazifikiki au zilizozuiwa kimuundo mara nyingi ni **equivalent mutants**. Survivors zinazobaki **reachable** na kugusa **boundary conditions**, **overflow/carry paths**, au **security-critical arithmetic/parsing** zinapaswa kuendelezwa kuwa:

- fuzz harnesses mpya
- property/invariant tests za moja kwa moja
- targeted edge-case vectors

### Correlate external findings onto the graph

Ikiwa SAST pipeline yako inatoa **SARIF**, weka findings kwenye graph nodes kwa kutumia **file + line range**, kisha tumia graph kupanua impact.<sup>[[6]](#references)</sup>

- hesabu **blast radius** ya function iliyoripotiwa
- angalia ikiwa finding iko kwenye path yoyote kutoka kwa entrypoint
- panga findings zilizo karibu ambazo zinaishia kwenye choke point ileile

Hii ni muhimu unapoamua kutumia muda wa fuzzing kwenye function mahususi: node ambayo **reachable**, ina **complex**, na tayari ina **SAST hits** mara nyingi ni target bora kuliko node iliyo complex tu bila attacker path.

Mfano wa workflow na Trailmark.<sup>[[6]](#references)</sup>
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
Mbinu muhimu ni makutano ya: **complexity x exposure x impact**. Tumia grafu kuchagua fuzz targets zenye security value inayotarajiwa zaidi, kisha tumia mutation survivors kuamua ni boundaries na invariants zipi harness yako lazima izifanyie stress.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Injini Imara Zaidi, Typed Inputs, Na Differential Checks

Ikiwa Go target tayari ina native `testing.F` harness, njia ya vitendo ya kuiboresha ni kuendesha harness hiyo hiyo kwa [gosentry](https://github.com/trailofbits/gosentry), Go toolchain iliyoforkiwa ambayo huhifadhi `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Hii ni muhimu wakati Go fuzzer ya native inakwama kwenye **hard comparisons**, **typed inputs**, au **parser-heavy formats**. Methodology inabaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe kwa binary ya `go` ya gosentry badala ya toolchain ya kawaida.
- Chukulia campaign inayotokana nayo kama run ya kawaida inayoongozwa na coverage, lakini ikiwa na scheduling/mutation ya LibAFL na detectors bora zaidi zinazozunguka.

### Geuza failures zisizoonekana kuwa fuzz findings

Tatizo linalojirudia katika assessments za Go ni kwamba tabia hatari mara nyingi **haisababishi crash** kwa default. Kwa gosentry, unaweza kubadilisha aina kadhaa za hali “mbaya lakini tulivu” kuwa findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` kufanya logging/error paths zilizochaguliwa zitende kama crashes (muhimu kwa code paths za mtindo wa `log.Fatal` ambazo vinginevyo hu-log tu na kuendelea).
- `--catch-races=true` kurudia kucheza queue entries mpya zilizogunduliwa kwa kutumia Go race detector.
- `--catch-leaks=true` kurudia kucheza queue entries mpya kwa `goleak` na kusitisha inapogundua goroutine leaks.
- Utunzaji wa hangs wa LibAFL ili kuhifadhi **infinite loops / very slow inputs** kama fuzz findings badala ya kuziruhusu zipotee kama timeouts.
- Ukaguzi wa built-in arithmetic overflow kwa default, pamoja na ukaguzi wa hiari wa truncation kupitia instrumentation ya mtindo wa go-panikint.

Hii ni muhimu hasa kwa targets ambazo security impact ni **panicless parser failure**, **concurrency bug**, au **DoS-only hang**, badala ya memory corruption.

### Fuzzing inayotambua Struct kwa typed Go APIs

Go fuzzing ya native inatarajia hasa scalars kama `[]byte`, `string`, na numbers. Ikiwa code inayofanyiwa test inatumia typed objects, gosentry inaweza kufanya fuzzing ya **composite values** moja kwa moja (structs, slices, arrays, pointers) huku ikiendelea kubadilisha bytes zilizo chini yake.<sup>[[7]](#references)[[8]](#references)</sup>
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
Tumia hii wakati wa kuunda wire format ya uongo kwa ajili ya fuzzing pekee, kwa kuwa kufanya hivyo kunaweza kuficha logic bugs nyuma ya parsing code ya harness pekee. Kwa kampeni za differential au grammar-based, weka input ya harness kama `[]byte` au `string` moja na ufanye parsing ndani ya callback badala yake.

### Grammar-based fuzzing kwa parser na protocol inputs

Kwa parser, formats, na input languages, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni JSON array ya production rules, na harness kwa kawaida inapaswa kupokea argument moja ya `[]byte` au `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Vidokezo vya methodology:

- Tumia grammar mode wakati byte-level mutations nyingi hufa katika ukaguzi wa awali wa syntax.
- Weka grammar ikilenga **security-relevant subset** ya language/protocol badala ya kuiga specification nzima.
- Tumia boundary values kubwa katika terminals/nonterminals ili kujaribu mipaka ya integers, lengths, na state machines.
- Grammar mode huweka inputs zikiwa grammar-valid, lakini target bado hupokea **bytes/strings**, kwa hivyo parsing na semantic checks hubaki ndani ya code inayofanyiwa harness.

### Differential fuzzing: linganisha implementations, si crashes pekee

Pattern thabiti kwa Go ecosystems ni **grammar-based differential fuzzing**: tengeneza structured inputs halali na uzitumie kwa parsers, clients, au state-transition engines mbili.<sup>[[7]](#references)[[8]](#references)</sup>
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

- implementation moja inapata panic huku nyingine ikikataa kwa usafi
- kutolingana kwa input inayokubaliwa/kukataliwa
- parse trees au objects zilizodecodewa tofauti
- state transitions, nonces, balances, au state roots zinazotofautiana

Hii ni njia ya vitendo ya kugundua **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo pure crash fuzzing mara nyingi hukosa.

### Tumia tena campaign corpus kwa coverage reporting

Baada ya campaign, replay saved queue corpus ili kutengeneza Go coverage report bila ku-export corpus tofauti manually.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Endesha amri kutoka kwenye **package ileile** na kwa target ileile ya `-fuzz` ili gosentry itambue hali sahihi ya campaign iliyohifadhiwa kwenye cache.

## References

- [1] [Fuzzing ya grammar ya mabadiliko](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing kwa Kina](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Miaka Mitano Baadaye: Kuhusu Fuzzing ya Protocol Inayoongozwa na Coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark inabadilisha code kuwa graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing ilikosa nusu ya toolkit. Tulifork toolchain ili kurekebisha hilo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox Fuzzer ya Haraka kwa Stateful Network Protocols Inayotumia Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Hakuna Grammar, Hakuna Tatizo: Kuelekea Kufuzz Linux Kernel Bila Maelezo ya System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing Yenye Ufanisi kwa Snapshots Zinazobadilika na Kujirekebisha](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
