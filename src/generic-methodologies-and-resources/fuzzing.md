# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Kapsama vs. Semantik

**Mutational grammar fuzzing** içinde girdiler, **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided modda, yalnızca **yeni coverage** tetikleyen örnekler corpus seed olarak kaydedilir. **Language targets** (parsers, interpreters, engines) için bu, bir yapının çıktısının başka bir yapının girdisi olduğu **semantic/dataflow chains** gerektiren bug’ları kaçırabilir.

**Failure mode:** fuzzer, tek tek `document()` ve `generate-id()` (veya benzer primitives) işleyen seed’leri bulur, ancak **zincirlenmiş dataflow’u korumaz**; bu yüzden “bug’a daha yakın” örnek coverage eklemediği için elenir. **3+ bağımlı adım** olduğunda, rastgele yeniden birleştirme pahalı hale gelir ve coverage feedback aramayı yönlendirmez.

**Implication:** dependency-heavy grammar’lar için, **mutational ve generative phases**’i hibritleştirmeyi veya üretimi **function chaining** pattern’lerine doğru önyargılı hale getirmeyi düşünün (sadece coverage değil).

## Corpus Diversity Tuzakları

Coverage-guided mutation **greedy**’dir: yeni coverage veren bir örnek hemen kaydedilir ve çoğu zaman büyük ölçüde değişmeden kalan bölgeler korunur. Zamanla corpus’lar, düşük yapısal çeşitliliğe sahip **near-duplicates** haline gelir. Aşırı minimization faydalı bağlamı kaldırabilir; bu yüzden pratik bir uzlaşım, **minimum token threshold** sonrasında duran **grammar-aware minimization** kullanmaktır (çevresel yapıyı mutasyon-dostu kalacak kadar korurken gürültüyü azaltmak).

Mutational fuzzing için pratik bir corpus kuralı şudur: **çok sayıda near-duplicate yerine coverage’ı maksimize eden, yapısal olarak farklı küçük bir seed seti** tercih edin. Pratikte bu genelde şunları ifade eder:

- **Gerçek dünya örnekleriyle** başlayın (public corpora, crawling, captured traffic, target ecosystem’den dosya setleri).
- Her valid örneği tutmak yerine bunları **coverage-based corpus minimization** ile damıtın.
- Seed’leri, mutasyonların çoğu çevrimi ilgisiz byte’larda harcamak yerine anlamlı alanlara düşeceği kadar **küçük** tutun.
- Büyük harness/instrumentation değişikliklerinden sonra corpus minimization’ı yeniden çalıştırın, çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Values İçin Comparison-Aware Mutation

Fuzzer’ların tıkanmasının yaygın nedenlerinden biri syntax değil, **hard comparisons**’dır: magic bytes, length checks, enum strings, checksums veya `memcmp`, switch tables ya da kademeli comparisons tarafından korunan parser dispatch values. Saf rastgele mutation, bu değerleri byte byte tahmin etmeye çalışırken çevrimi boşa harcar.

Bu hedefler için, fuzzer’ın başarısız comparisons’tan operand’ları gözlemleyip mutasyonları onları karşılayacak değerlere doğru eğebilmesi için **comparison tracing** kullanın (örneğin AFL++ `CMPLOG` / Redqueen-style workflows).
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
**Pratik notlar:**

- Bu özellikle hedef derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasına gizlediğinde çok faydalıdır.
- Bunu gerçek örneklerden, protocol specs’ten veya debug logs’tan çıkarılan **dictionaries** ile eşleştirin. Grammar token’ları, chunk adları, verb’ler ve ayırıcılar içeren küçük bir dictionary, çoğu zaman devasa bir genel wordlist’ten daha değerlidir.
- Hedef birçok ardışık kontrol yapıyorsa, önce en erken “magic” karşılaştırmaları çözün ve sonra oluşan corpus’u yeniden minimize edin; böylece sonraki aşamalar zaten geçerli prefix’lerle başlar.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows** ve **multi-stage parsers** için ilginç birim çoğu zaman tek bir blob değil, bir **message sequence**’tir. Tüm transcript’i tek bir file’a birleştirip körlemesine mutate etmek genelde verimsizdir; çünkü fuzzer her adımı eşit şekilde mutate eder, oysa kırılgan state’e çoğu zaman yalnızca sonraki message ulaşır.

Daha etkili bir yaklaşım, **sequence**’in kendisini seed olarak ele almak ve **observable state**’i (response codes, protocol states, parser phases, returned object types) ek feedback olarak kullanmaktır:

- **valid prefix messages**’leri sabit tutun ve mutasyonları **transition-driving** message’a odaklayın.
- Sonraki adım bunlara bağlıysa, önceki response’lardan identifier’ları ve server-generated değerleri önbelleğe alın.
- Tüm serialize transcript’i opak bir blob olarak mutate etmek yerine, message başına mutation/splicing tercih edin.
- Protocol anlamlı response codes sunuyorsa, bunları daha derinlere ilerleyen sequence’leri önceliklendirmek için ucuz bir state oracle olarak kullanın.

Vanilla file-style fuzzing’in authenticated bugs, hidden transitions veya “only-after-handshake” parser bugs’ları sık sık kaçırmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sıra, state ve dependencies**’i de korumalıdır.

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** ile **coverage reuse**’u hibritleştirmenin pratik bir yolu, **short-lived workers**’ı persistent bir server’a karşı yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra sync olur, birleşik corpus üzerinde bir `T` saniye daha çalışır, tekrar sync olur, sonra çıkar. Bu, birikmiş coverage’dan yararlanırken aynı zamanda **her generation’da fresh structures** üretir.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sıralı workers (örnek döngü):**

<details>
<summary>Jackalope worker yeniden başlatma döngüsü</summary>
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

**Notlar:**

- `-in empty` her oluşturma için **yeni bir corpus** zorlar.
- `-server_update_interval T` **gecikmeli sync**'i yaklaşıklar (önce novelty, sonra reuse).
- Grammar fuzzing modunda, **ilk server sync varsayılan olarak atlanır** (`-skip_initial_server_sync` gerekmez).
- En uygun `T` **target'a bağlıdır**; worker çoğu “easy” coverage'ı bulduktan sonra geçiş yapmak genelde en iyi sonucu verir.

## Snapshot Fuzzing For Hard-To-Harness Targets

Test etmek istediğiniz code yalnızca **büyük bir setup cost** sonrasında erişilebilir hale geliyorsa (bir VM boot etmek, bir login'i tamamlamak, bir packet almak, bir container'ı parse etmek, bir service'i initialize etmek), kullanışlı bir alternatif **snapshot fuzzing**'dir:

1. Target'ı ilginç state hazır olana kadar çalıştırın.
2. O noktada **memory + registers** snapshot'ını alın.
3. Her test case için, mutated input'u doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset olana kadar execute edin.
5. Yalnızca **dirty pages**'i restore edin ve tekrarlayın.

Bu, her iterasyonda tam setup cost'u ödemeyi önler ve özellikle **network services**, **firmware**, **post-auth attack surfaces** ve klasik in-process harness'e refactor edilmesi zahmetli **binary-only targets** için çok kullanışlıdır.

Pratik bir trick, `recv`/`read`/packet-deserialization noktasının hemen ardından break etmek, input buffer address'ini not etmek, orada snapshot almak ve sonra her iterasyonda o buffer'ı doğrudan mutate etmektir. Bu, tüm handshake'i her seferinde yeniden oluşturmeden derin parsing logic'i fuzz etmenizi sağlar.

## Harness Introspection: Find Shallow Fuzzers Early

Bir campaign takılıp kaldığında, problem çoğu zaman mutator değil **harness**'tır. Fuzz target'ınıza statik olarak reachable olan ama dinamik olarak nadiren ya da hiç covered edilmeyen functions'ları bulmak için **reachability/coverage introspection** kullanın. Bu functions genellikle üç sorundan birine işaret eder:

- Harness target'a çok geç ya da çok erken giriyordur.
- Seed corpus, bütün bir feature family'sini eksik bırakıyordur.
- Target'ın gerçekten tek bir büyük “her şeyi yap” harness yerine **ikinci bir harness**'e ihtiyacı vardır.

OSS-Fuzz / ClusterFuzz tarzı workflows kullanıyorsanız, Fuzz Introspector bu triage için kullanışlıdır:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu, test edilmemiş bir parser path için yeni bir harness ekleyip eklememeye, belirli bir özellik için corpus’u genişletmeye ya da monolithic bir harness’i daha küçük entry point’lere bölmeye karar vermek için kullanın.

## Graph-First Fuzz Target Selection And Mutation Triage

Eğer zaten **static-analysis findings**, **mutation-testing survivors** ve **coverage reports** varsa, bunları bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun, node’ları **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve herhangi bir external finding ile annotate edin, sonra graph soruları sorun:

- Hangi high-complexity fonksiyonlar untrusted input’tan reachable?
- Hangi mutation survivors parser/handler’lardan security-critical code’a giden path’lerde yer alıyor?
- Hangi fonksiyonlar unusually high **blast radius** olan architectural choke point’ler?

Bu yaklaşım genellikle yalnızca "lowest coverage" olmaktan daha iyi fuzz target’lar ortaya çıkarır. **High complexity** ve doğrulanmış **external reachability** içeren bir parser/decoder, zayıf coverage’a sahip ama attacker-controlled path’i olmayan izole bir internal helper’dan daha güçlü bir harness adayıdır.

### Pratik triage workflow

1. Codebase’den bir **code graph** oluşturun ve her fonksiyon için complexity/branch metrics çıkarın.
2. Attacker-controlled input kabul eden **entrypoints**’leri listeleyin: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Bu entrypoints’lerden candidate fonksiyonlara **path queries** çalıştırarak reachable attack surface ile dead/internal-only code’u ayırın.
4. Şu özellikleri birleştiren node’ları önceliklendirin:
- yüksek **cyclomatic complexity**
- untrusted input’tan doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** findings, audit notları veya mutation survivors gibi destekleyici kanıtlar
5. Önce en yüksek skorlu node’lar için odaklı harness’ler yazın, özellikle hex/Base64/IP/message decoders gibi **parsers/codecs** için.

### Mutation survivors: equivalent vs actionable

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor’ı security gap olarak ele almadan önce graph’i kullanarak şunları sorun:

- Mutated fonksiyon attacker-controlled bir entrypoint’ten reachable mı?
- Tüm call path’ler mutated check’ten daha güçlü invariant’lar tarafından kısıtlanıyor mu?
- Node dead code, formatting-only logic ya da yüksek etkili bir arithmetic/parser path üzerinde mi?

Reachable olmayan veya yapısal olarak kısıtlı kalan survivors çoğu zaman **equivalent mutants**’tır. **Reachable** kalan ve **boundary conditions**, **overflow/carry paths** veya **security-critical arithmetic/parsing** ile temas eden survivors ise şuralara yükseltilmelidir:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### External findings’i graph üzerine correlate edin

Eğer SAST pipeline’ınız **SARIF** dışa aktarıyorsa, findings’i **file + line range** ile graph node’larına projekte edin ve graph’i kullanarak etki alanını genişletin:

- flagged function’ın **blast radius**’unu hesaplayın
- finding’in herhangi bir entrypoint path’i üzerinde olup olmadığını kontrol edin
- aynı choke point’e düşen yakın findings’leri cluster edin

Bu, belirli bir fonksiyon üzerinde fuzzing zamanı harcayıp harcamamaya karar verirken faydalıdır: **reachable**, **complex** ve zaten **SAST hits** içeren bir node, attacker path’i olmayan sadece complex bir node’dan genellikle daha iyi bir hedeftir.

Trailmark ile örnek workflow:
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
Önemli metodoloji kesişimdir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın, ardından mutation survivor'ları hangi sınırları ve invariants'ları harness'inizin zorlaması gerektiğine karar vermek için kullanın.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Bir Go hedefi zaten yerel bir `testing.F` harness'ine sahipse, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır; bu, `go test -fuzz`'i koruyan ancak backend'i **LibAFL** ile değiştiren fork edilmiş bir Go toolchain'dir.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Bu, yerel Go fuzzer **hard comparisons**, **typed inputs** veya **parser-heavy formats** üzerinde takıldığında faydalıdır. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)` ve callback için `f.Fuzz(...)` kullanmaya devam et.
- Aynı harness'i yeniden kullan, ancak stock toolchain yerine gosentry'nin `go` binary'si ile çalıştır.
- Ortaya çıkan kampanyayı normal bir coverage-guided run olarak ele al, fakat LibAFL scheduling/mutation ve daha iyi çevresel detector'larla.

### Silent failure'ları fuzz finding'lere dönüştür

Go değerlendirmelerinde tekrar eden bir sorun, tehlikeli davranışların varsayılan olarak çoğu zaman **crash** etmemesidir. gosentry ile, birkaç “bad ama silent” durumu finding'e dönüştürebilirsin:

- Seçili logging/error path'lerini crash gibi davranacak şekilde yapmak için `--panic-on=pkg.Func,...` kullan (`log.Fatal` tarzı, aksi halde sadece loglayıp devam eden code path'ler için faydalı).
- Yeni keşfedilen queue entry'lerini Go race detector ile yeniden oynatmak için `--catch-races=true` kullan.
- Yeni queue entry'lerini `goleak` ile yeniden oynatmak ve goroutine leak'lerinde durmak için `--catch-leaks=true` kullan.
- Timeout olarak kaybolmalarına izin vermek yerine **infinite loops / very slow inputs**'ları fuzz finding olarak tutmak için LibAFL hang handling kullan.
- Varsayılan olarak built-in arithmetic overflow checks, ayrıca go-panikint-style instrumentation üzerinden opsiyonel truncation checks.

Bu, özellikle security impact'in memory corruption yerine **panicless parser failure**, **concurrency bug** veya yalnızca **DoS-only hang** olduğu hedefler için çok değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar'lar bekler. Test edilen kod typed objects tüketiyorsa, gosentry alttaki bytes'ları mutate etmeye devam ederken doğrudan **composite values** (structs, slices, arrays, pointers) fuzz edebilir.
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
Bunu, sadece fuzzing için sahte bir wire format oluştururken kullanmak, logic bug’ları harness-only parsing code arkasında gizlerdi. Differential veya grammar-based campaigns için, harness input’unu tek bir `[]byte` veya `string` olarak tutun ve bunun yerine parse işlemini callback içinde yapın.

### Parser’lar ve protocol input’ları için grammar-based fuzzing

Parser’lar, formatlar ve input dilleri için, gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule’lardan oluşan bir JSON array’idir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodoloji notları:

- Byte-level mutasyonlar erken syntax kontrollerinde çoğunlukla ölüyorsa grammar mode kullanın.
- Grammar’ı tam spesifikasyonu modellemek yerine dilin/protokolün **security-relevant subset**’ine odaklı tutun.
- Integer, length ve state-machine sınırlarını zorlamak için terminal/nonterminal’larda büyük boundary değerleri kullanın.
- Grammar mode girdileri grammar-valid tutar, ancak target yine de **bytes/strings** alır; bu yüzden parsing ve semantic kontroller harnessed code içinde kalır.

### Differential fuzzing: sadece crash’leri değil, implementations’ı karşılaştırın

Go ecosystem’leri için güçlü bir pattern **grammar-based differential fuzzing**’dir: geçerli structured inputs üretin ve bunları iki parser’a, client’a veya state-transition engine’ine verin.
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
Şunları findings olarak değerlendirin:

- bir implementation panics while the other rejects cleanly
- accepted/rejected input mismatches
- farklı parse tree’ler veya decoded object’ler
- divergent state transitions, nonces, balances veya state roots

Bu, saf crash fuzzing’in çoğu zaman kaçırdığı **consensus mismatches**, **parser ambiguity** ve **spec-vs-implementation drift** bulmak için pratik bir yoldur.

### Coverage reporting için campaign corpus’unu yeniden kullanın

Bir campaign’den sonra, ayrı bir corpus’u manuel olarak export etmeden bir Go coverage report üretmek için kaydedilmiş queue corpus’unu replay edin:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Komutu **aynı package** içinden ve aynı `-fuzz` target ile çalıştırın; böylece gosentry doğru cached campaign state’i çözer.

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
