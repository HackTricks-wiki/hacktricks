# Mbinu ya Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing ya Grammar ya Kubadilisha: Coverage vs. Semantics

Katika **mutational grammar fuzzing**, inputs hubadilishwa huku zikibaki **grammar-valid**. Katika mode inayosukumwa na coverage, ni sampuli tu zinazosababisha **new coverage** ndizo huhifadhiwa kama corpus seeds. Kwa **language targets** (parsers, interpreters, engines), hii inaweza kukosa bugs zinazohitaji **semantic/dataflow chains** ambapo output ya construct moja inakuwa input ya nyingine.

**Failure mode:** fuzzer hupata seeds ambazo kila moja hutumia `document()` na `generate-id()` (au primitives zinazofanana), lakini **haidumishi chained dataflow**, hivyo sampuli iliyo “closer-to-bug” hutupwa kwa sababu haiongezi coverage. Kwa **3+ dependent steps**, random recombination inakuwa ghali na coverage feedback haiielekezi utafutaji.

**Implication:** kwa grammars zenye dependency nyingi, fikiria **kuchanganya mutational na generative phases** au kuelekeza generation kwenye mifumo ya **function chaining** (si coverage pekee).

## Pitfalls za Diversity ya Corpus

Coverage-guided mutation ni **greedy**: sampuli yenye new-coverage huhifadhiwa mara moja, mara nyingi ikibakiza maeneo makubwa ambayo hayajabadilishwa. Kadiri muda unavyopita, corpora zinakuwa **near-duplicates** zenye structural diversity ndogo. Aggressive minimization inaweza kuondoa context muhimu, hivyo compromise ya vitendo ni **grammar-aware minimization** inayosimama baada ya **minimum token threshold** (kupunguza noise huku ikihifadhi muundo wa kutosha kubaki mutation-friendly).

Kanuni ya vitendo ya corpus kwa mutational fuzzing ni: **pendelea set ndogo ya seeds zenye tofauti za kimuundo zinazoongeza coverage** kuliko rundo kubwa la near-duplicates. Kwa vitendo, hii kawaida inamaanisha:

- Anza na **real-world samples** (public corpora, crawling, captured traffic, file sets kutoka ecosystem ya target).
- Zisafishe kwa **coverage-based corpus minimization** badala ya kuhifadhi kila sample halali.
- Hifadhi seeds ziwe **ndogo vya kutosha** ili mutations zishukie kwenye fields zenye maana badala ya kutumia cycles nyingi kwenye bytes zisizo na umuhimu.
- Endesha corpus minimization tena baada ya mabadiliko makubwa ya harness/instrumentation, kwa sababu corpus “bora” hubadilika reachability inapobadilika.

## Comparison-Aware Mutation Kwa Magic Values

Sababu ya kawaida inayofanya fuzzers kusimama ni si syntax bali **hard comparisons**: magic bytes, length checks, enum strings, checksums, au parser dispatch values zinazolindwa na `memcmp`, switch tables, au cascaded comparisons. Random mutation pekee hupoteza cycles ikijaribu kukisia values hizi byte-by-byte.

Kwa targets hizi, tumia **comparison tracing** (kwa mfano AFL++ `CMPLOG` / Redqueen-style workflows) ili fuzzer iweze kuona operands kutoka kwenye failed comparisons na kuelekeza mutations kuelekea values zinazozitimiza.
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
**Maelezo ya vitendo:**

- Hii ni muhimu hasa wakati lengo linaficha logic ya kina nyuma ya **file signatures**, **protocol verbs**, **type tags**, au **version-dependent feature bits**.
- Iunganishe na **dictionaries** zilizotolewa kutoka kwa sampuli halisi, protocol specs, au debug logs. Dictionary ndogo yenye grammar tokens, chunk names, verbs, na delimiters mara nyingi ni ya thamani zaidi kuliko massive generic wordlist.
- Ikiwa lengo linafanya checks nyingi za mfululizo, tatua kulinganisha za kwanza za “magic” kwanza kisha punguza tena corpus inayotokana ili hatua za baadaye zianze kutoka kwa prefixes ambazo tayari ni sahihi.

## Stateful Fuzzing: Sequences Are Seeds

Kwa **protocols**, **authenticated workflows**, na **multi-stage parsers**, unit yenye kuvutia mara nyingi si blob moja bali ni **message sequence**. Kuunganisha transcript nzima kuwa faili moja na kuibadilisha bila mpango kwa kawaida si kwa ufanisi kwa sababu fuzzer hubadilisha kila hatua kwa usawa, hata kama ni ujumbe wa baadaye tu unaofika katika state dhaifu.

Mtindo wenye ufanisi zaidi ni kuchukulia **sequence yenyewe kama seed** na kutumia **observable state** (response codes, protocol states, parser phases, returned object types) kama feedback ya ziada:

- Weka **valid prefix messages** thabiti na elekeza mutations kwenye ujumbe unaoendesha **transition**.
- Hifadhi identifiers na thamani zinazozalishwa na server kutoka kwa majibu ya awali wakati hatua inayofuata inategemea hizo.
- Pendelea per-message mutation/splicing badala ya kubadilisha transcript nzima iliyoserialishwa kama opaque blob.
- Ikiwa protocol inaonyesha meaningful response codes, zitumie kama **cheap state oracle** ili kuipa kipaumbele sequences zinazosomeka zaidi ndani.

Hii ndiyo sababu bugs za authenticated, hidden transitions, au bugs za parser za “only-after-handshake” mara nyingi hukosa kugunduliwa na vanilla file-style fuzzing: fuzzer lazima ihifadhi **order, state, na dependencies**, si structure pekee.

## Single-Machine Diversity Trick (Jackalope-Style)

Njia ya vitendo ya kuchanganya **generative novelty** na **coverage reuse** ni **kuanzisha upya short-lived workers** dhidi ya persistent server. Kila worker huanza kutoka corpus tupu, husync baada ya `T` seconds, huendesha tena `T` seconds kwenye combined corpus, husync tena, kisha hutoka. Hii hutoa **fresh structures each generation** huku bado ikitumia coverage iliyokusanywa.

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

- `-in empty` memlazimisha **corpus mpya kabisa** kila kizazi.
- `-server_update_interval T` hukadiria **sync iliyocheleweshwa** (novelty kwanza, reuse baadaye).
- Katika mode ya grammar fuzzing, **initial server sync hurukwa kwa chaguo-msingi** (hakuna haja ya `-skip_initial_server_sync`).
- `T` bora hutegemea **target**; kubadili baada ya worker kupata coverage nyingi za “easy” huwa hufanya kazi vizuri zaidi.

## Snapshot Fuzzing For Hard-To-Harness Targets

Wakati code unayotaka kujaribu inafikiwa tu **baada ya gharama kubwa ya setup** (ku-boot VM, kukamilisha login, kupokea packet, kuchambua container, ku-initialize service), njia mbadala yenye manufaa ni **snapshot fuzzing**:

1. Run target hadi state ya kuvutia iwe tayari.
2. Chukua snapshot ya **memory + registers** katika hatua hiyo.
3. Kwa kila test case, andika input iliyobadilishwa moja kwa moja kwenye guest/process buffer husika.
4. Execute hadi crash/timeout/reset.
5. Rejesha tu **dirty pages** na urudie.

Hii huepuka kulipa gharama yote ya setup kila iteration na ni muhimu sana kwa **network services**, **firmware**, **post-auth attack surfaces**, na **binary-only targets** ambazo ni ngumu ku-refactor kuwa classic in-process harness.

Trick ya vitendo ni kusitisha mara moja baada ya point ya `recv`/`read`/packet-deserialization, kuandika mahali pa input buffer, snapshot hapo, kisha kubadilisha buffer hiyo moja kwa moja katika kila iteration. Hii hukuruhusu kufuzz logic ya kina ya parsing bila kujenga upya handshake nzima kila mara.

## Harness Introspection: Find Shallow Fuzzers Early

Wakati campaign inakwama, tatizo mara nyingi si mutator bali ni **harness**. Tumia **reachability/coverage introspection** kupata functions ambazo zinafikiwa kistatikia kutoka kwenye fuzz target yako lakini mara chache au kamwe hazifunikwi dinamik. Functions hizo kawaida zinaonyesha moja ya matatizo matatu:

- Harness inaingia target kuchelewa sana au mapema sana.
- Seed corpus inakosa familia nzima ya feature.
- Target kweli inahitaji **second harness** badala ya harness moja kubwa ya “fanya kila kitu”.

Ukitemia workflows za OSS-Fuzz / ClusterFuzz-style, Fuzz Introspector ni muhimu kwa triage hii:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Gunakan report untuk memutuskan apakah akan menambah harness baru untuk jalur parser yang belum diuji, memperluas corpus untuk fitur tertentu, atau memecah harness monolitik menjadi entry point yang lebih kecil.

## Pemilihan Fuzz Target dan Triage Mutasi Berbasis Graf

Jika Anda sudah memiliki **static-analysis findings**, **mutation-testing survivors**, dan **coverage reports**, jangan triase semuanya sebagai daftar yang independen. Bangun dulu **call graph**, beri anotasi node dengan **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, dan temuan eksternal apa pun, lalu ajukan pertanyaan graf:

- Fungsi mana yang berkompleksitas tinggi yang dapat dijangkau dari untrusted input?
- Mutation survivors mana yang berada pada jalur dari parser/handler ke kode yang kritis terhadap security?
- Fungsi mana yang menjadi choke point arsitektural dengan **blast radius** yang sangat besar?

Ini biasanya mengungkap target fuzz yang lebih baik daripada sekadar "coverage terendah". Sebuah parser/decoder dengan **kompleksitas tinggi** dan **external reachability** yang terkonfirmasi adalah kandidat harness yang lebih kuat daripada helper internal terisolasi dengan coverage lemah tetapi tanpa jalur yang dikendalikan attacker.

### Alur triase praktis

1. Bangun **code graph** dari codebase dan ekstrak metrik kompleksitas/branch per fungsi.
2. Enumerasi **entrypoint** yang menerima input yang dikontrol attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Jalankan **path queries** dari entrypoint tersebut ke fungsi kandidat untuk memisahkan attack surface yang reachable dari code internal-only yang mati.
4. Prioritaskan node yang menggabungkan:
- **cyclomatic complexity** tinggi
- **reachability from untrusted input** yang terkonfirmasi
- **blast radius** tinggi atau banyak downstream dependents
- bukti pendukung seperti temuan **SARIF**, catatan audit, atau mutation survivors
5. Tulis harness yang terfokus untuk node dengan skor terbaik terlebih dahulu, terutama **parsers/codecs** seperti hex/Base64/IP/message decoders.

### Mutation survivors: ekuivalen vs actionable

Mutation testing sering menghasilkan daftar survivor yang noisy. Sebelum memperlakukan setiap survivor sebagai celah security, gunakan graf untuk bertanya:

- Apakah fungsi yang dimutasi dapat dijangkau dari entrypoint yang dikendalikan attacker?
- Apakah semua call path dibatasi oleh invariant yang lebih kuat daripada pengecekan yang dimutasi?
- Apakah node berada di dead code, logika formatting-only, atau di jalur aritmetika/parser berdampak tinggi?

Survivor yang tetap tidak reachable atau dibatasi secara struktural sering kali merupakan **equivalent mutants**. Survivor yang tetap **reachable** dan menyentuh **boundary conditions**, **overflow/carry paths**, atau **security-critical arithmetic/parsing** sebaiknya dipromosikan menjadi:

- fuzz harness baru
- property/invariant tests langsung
- edge-case vectors yang ditargetkan

### Korelasikan temuan eksternal ke graf

Jika pipeline SAST Anda mengekspor **SARIF**, proyeksikan temuan ke node graf berdasarkan **file + line range** dan gunakan graf untuk memperluas dampaknya:

- hitung **blast radius** dari fungsi yang ditandai
- periksa apakah temuan tersebut berada di jalur mana pun dari entrypoint
- kelompokkan temuan yang berdekatan yang berujung pada choke point yang sama

Ini berguna saat memutuskan apakah layak menghabiskan waktu fuzzing pada fungsi tertentu: node yang **reachable**, **complex**, dan sudah memiliki **SAST hits** sering kali menjadi target yang lebih baik daripada node yang sekadar kompleks tanpa jalur attacker.

Contoh alur kerja dengan Trailmark:
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
Mchakato muhimu ni makutano: **ugumu x mfiduo x athari**. Tumia grafu kuchagua fuzz targets zenye thamani ya juu zaidi ya usalama inayotarajiwa, kisha tumia mutation survivors kuamua ni mipaka na invariants zipi harness yako lazima izisisitize.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Ikiwa target ya Go tayari ina native `testing.F` harness, njia ya uboreshaji ya vitendo ni kuendesha harness ile ile na [gosentry](https://github.com/trailofbits/gosentry), Go toolchain iliyoforkiwa ambayo huweka `go test -fuzz` lakini hubadilisha backend kuwa **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Hii ni muhimu wakati Go fuzzer asilia inakwama kwenye **hard comparisons**, **typed inputs**, au **parser-heavy formats**. Mbinu hubaki ileile:

- Endelea kutumia `f.Add(...)` kwa seeds na `f.Fuzz(...)` kwa callback.
- Tumia tena harness ileile, lakini iendeshe na binary ya `go` ya gosentry badala ya stock toolchain.
- Tibu campaign inayotokana na hilo kama run ya kawaida ya coverage-guided, lakini ikiwa na LibAFL scheduling/mutation na detectors bora zaidi za pembeni.

### Badilisha silent failures ziwe fuzz findings

Tatizo la mara kwa mara kwenye tathmini za Go ni kwamba tabia hatari mara nyingi **ha** crash kwa default. Kwa gosentry, unaweza kubadilisha aina kadhaa za hali za “mbaya lakini silent” ziwe findings:

- `--panic-on=pkg.Func,...` ili kufanya logging/error paths zilizochaguliwa ziwe kama crashes (inafaa kwa code paths za `log.Fatal`-style ambazo vinginevyo huandika log tu na kuendelea).
- `--catch-races=true` ili kurudia queue entries mpya zilizogunduliwa na Go race detector.
- `--catch-leaks=true` ili kurudia new queue entries kwa `goleak` na kusimama kwenye goroutine leaks.
- LibAFL hang handling ili kuweka **infinite loops / very slow inputs** kama fuzz findings badala ya kuziacha zipotee kama timeouts.
- Built-in arithmetic overflow checks kwa default, pamoja na optional truncation checks kupitia go-panikint-style instrumentation.

Hii ni muhimu hasa kwa targets ambako athari ya usalama ni **panicless parser failure**, **concurrency bug**, au **DoS-only hang** badala ya memory corruption.

### Struct-aware fuzzing kwa typed Go APIs

Native Go fuzzing hasa hutegemea scalars kama `[]byte`, `string`, na numbers. Ikiwa code inayojaribiwa hutumia typed objects, gosentry inaweza fuzz **composite values** moja kwa moja (structs, slices, arrays, pointers) huku bado ikibadilisha bytes chini yake.
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
Tumia hii unapounda fake wire format kwa ajili ya fuzzing tu, ingeweza kuficha logic bugs nyuma ya code ya parsing ya harness-pekee. Kwa differential au grammar-based campaigns, weka input ya harness kama `[]byte` au `string` moja na kisha parse ndani ya callback badala yake.

### Grammar-based fuzzing for parsers and protocol inputs

Kwa parsers, formats, na input languages, gosentry inaweza kuendesha **Nautilus grammar fuzzing** juu ya LibAFL. Grammar ni JSON array ya production rules, na kawaida harness inapaswa kuchukua `[]byte` moja au `string` argument.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Vidokezo vya methodology:

- Tumia grammar mode wakati byte-level mutations mara nyingi hufa katika syntax checks za mwanzo.
- Weka grammar ikizingatia **security-relevant subset** ya language/protocol badala ya kuiga specification nzima.
- Tumia large boundary values katika terminals/nonterminals ili kusukuma integer, length, na state-machine edges.
- Grammar mode huweka inputs zikiwa grammar-valid, lakini target bado inapokea **bytes/strings**, hivyo parsing na semantic checks hubaki ndani ya code inayotumiwa na harness.

### Differential fuzzing: linganisha implementations, si crashes tu

Pattern yenye nguvu kwa Go ecosystems ni **grammar-based differential fuzzing**: tengeneza valid structured inputs na uzitumie kwa parsers wawili, clients, au state-transition engines.
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

- moja ya implementation inapata panic wakati nyingine inakataa kwa usafi
- accepted/rejected input mismatches
- tofauti za parse trees au decoded objects
- state transitions, nonces, balances, au state roots zinazotofautiana

Hii ni njia ya vitendo ya kupata **consensus mismatches**, **parser ambiguity**, na **spec-vs-implementation drift** ambazo mara nyingi pure crash fuzzing hukosa.

### Tumia tena campaign corpus kwa coverage reporting

Baada ya campaign, rudia saved queue corpus ili kutengeneza Go coverage report bila kusafirisha manually corpus tofauti:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Endesha amri kutoka kwa **pakiti hiyo hiyo** na kwa **lengo lile lile la `-fuzz`** ili gosentry ipate hali sahihi ya kampeni iliyohifadhiwa kwenye cache.

## Marejeo

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
