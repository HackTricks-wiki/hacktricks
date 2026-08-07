# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing** işleminde input'lar **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided modda yalnızca **new coverage** tetikleyen örnekler corpus seed olarak kaydedilir. **Language target'ları** (parser'lar, interpreter'lar, engine'ler) için bu yaklaşım, bir construct'ın çıktısının diğerinin input'u haline geldiği ve **semantic/dataflow chain** gerektiren bug'ları kaçırabilir.

**Failure mode:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) fonksiyonlarını ayrı ayrı çalıştıran seed'ler bulur; ancak **chained dataflow** yapısını korumaz. Bu nedenle “bug'a daha yakın” örnek coverage eklemediği için silinir. **3+ bağımlı adım** olduğunda random recombination pahalı hale gelir ve coverage feedback aramayı yönlendiremez.

**Implication:** dependency-heavy grammar'lar için **mutational ve generative phase'leri hybridize etmeyi** veya generation'ı yalnızca coverage'a değil, **function chaining** pattern'lerine de yönlendirmeyi düşünün.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** çalışır: new coverage sağlayan bir örnek hemen kaydedilir ve çoğu zaman büyük, değişmeden kalan bölgeleri korur. Zamanla corpus'lar, düşük structural diversity'ye sahip **near-duplicate** örneklerle dolar. Aggressive minimization faydalı context'i kaldırabilir; bu nedenle pratik bir çözüm, **minimum token threshold** sonrasında duran **grammar-aware minimization** kullanmaktır (noise'u azaltırken mutation-friendly kalmak için yeterli çevre yapısını korur).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı şudur: çok sayıda near-duplicate yerine, **coverage'ı maksimize eden ve birbirinden yapısal olarak farklı küçük bir seed setini tercih edin**. Uygulamada bu genellikle şu anlama gelir:<sup>[[1]](#references)</sup>

- **Real-world sample'lar** ile başlayın (public corpus'lar, crawling, captured traffic, target ecosystem'dan file set'leri).
- Her valid sample'ı saklamak yerine bunları **coverage-based corpus minimization** ile distill edin.
- Mutation'ların irrelevant byte'lar üzerinde çoğu cycle'ı harcamak yerine anlamlı field'lara denk gelmesi için seed'leri **yeterince küçük** tutun.
- Major harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Comparison-Aware Mutation For Magic Values

Fuzzer'ların plateau yaşamasının yaygın bir nedeni syntax değil, **hard comparison** kontrolleridir: magic byte'lar, length check'leri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da cascaded comparison'lar tarafından korunan parser dispatch value'ları. Pure random mutation, bu değerleri byte-by-byte tahmin etmeye çalışırken cycle'ları boşa harcar.

Bu target'lar için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen-style workflow'ları) kullanın. Böylece fuzzer, başarısız comparison'larda kullanılan operand'ları gözlemleyebilir ve mutation'ları bu comparison'ları karşılayan değerlere yönlendirebilir.<sup>[[3]](#references)</sup>
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

- Bu, özellikle hedef; derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasında gated ettiğinde oldukça kullanışlıdır.
- Gerçek örneklerden, protocol spec'lerinden veya debug log'larından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token'ları, chunk adları, verb'ler ve delimiter'lar içeren küçük bir dictionary, çoğu zaman devasa bir generic wordlist'ten daha değerlidir.
- Hedef birçok ardışık check gerçekleştiriyorsa, en erken “magic” comparison'ları önce çözün ve ardından ortaya çıkan corpus'u tekrar minimize edin; böylece sonraki aşamalar zaten geçerli prefix'lerle başlar.

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** ve **multi-stage parsers** için ilginç birim çoğu zaman tek bir blob değil, bir **message sequence**'tir. Tüm transcript'i tek bir file'a birleştirip körlemesine mutate etmek genellikle verimsizdir; çünkü fuzzer, yalnızca sonraki message fragile state'e ulaşsa bile her step'i eşit şekilde mutate eder.

Daha etkili bir pattern, **sequence'in kendisini seed** olarak ele almak ve **observable state**'i (response code'ları, protocol state'leri, parser phase'leri, döndürülen object type'ları) ek feedback olarak kullanmaktır:<sup>[[4]](#references)</sup>

- **Valid prefix message**'larını sabit tutun ve mutation'ları **transition-driving** message üzerinde yoğunlaştırın.
- Sonraki step bunlara bağlı olduğunda, önceki response'larda dönen identifier'ları ve server-generated value'ları cache'leyin.
- Tüm serialized transcript'i opaque bir blob olarak mutate etmek yerine per-message mutation/splicing kullanmayı tercih edin.
- Protocol anlamlı response code'ları açığa çıkarıyorsa, daha derine ilerleyen sequence'leri önceliklendirmek için bunları **cheap state oracle** olarak kullanın.

Authenticated bug'ların, hidden transition'ların veya “only-after-handshake” parser bug'larının vanilla file-style fuzzing tarafından sıklıkla gözden kaçırılmasının nedeni de budur: fuzzer yalnızca structure'ı değil, **order, state ve dependencies**'i de korumalıdır.

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** ile **coverage reuse**'u hybrid hale getirmenin pratik bir yolu, kısa ömürlü worker'ları persistent server'a karşı **restart etmektir**. Her worker boş bir corpus ile başlar, `T` saniye sonra sync yapar, birleşik corpus üzerinde bir `T` saniye daha çalışır, tekrar sync yapar ve ardından çıkar. Bu, birikmiş coverage'dan yararlanmaya devam ederken her generation'da **fresh structure**'lar üretir.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (örnek döngü):**

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

- `-in empty`, her generation işleminde **fresh corpus** kullanılmasını zorlar.
- `-server_update_interval T`, **delayed sync** davranışını yaklaşık olarak simüle eder (önce yenilik, sonra yeniden kullanım).
- Grammar fuzzing modunda, **initial server sync** varsayılan olarak atlanır (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T` değeri **target-dependent**'dır; worker çoğu “kolay” coverage'ı bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Hard-To-Harness Targets İçin Snapshot Fuzzing

Test etmek istediğiniz code yalnızca **yüksek bir setup maliyetinden** sonra erişilebilir hâle geliyorsa (bir VM boot etmek, login işlemini tamamlamak, bir packet almak, bir container parse etmek veya bir service initialize etmek), kullanışlı bir alternatif **snapshot fuzzing**'dir:

1. Target'ı ilgi çekici state hazır olana kadar çalıştırın.
2. Bu noktada **memory + registers** için snapshot alın.
3. Her test case için mutated input'u doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Yalnızca **dirty pages**'i restore edin ve tekrarlayın.

Bu yöntem, her iteration'da tam setup maliyetini ödemeyi önler ve özellikle **network services**, **firmware**, **post-auth attack surfaces** ve klasik in-process harness'a dönüştürülmesi zahmetli olan **binary-only targets** için oldukça kullanışlıdır.

Pratik bir yöntem, bir `recv`/`read`/packet-deserialization noktasından hemen sonra durmak, input buffer adresini not etmek, o noktada snapshot almak ve ardından her iteration'da bu buffer'ı doğrudan mutate etmektir. Böylece her seferinde tüm handshake'i yeniden oluşturmadan deep parsing logic'i fuzz edebilirsiniz.

## Harness Introspection: Shallow Fuzzer'ları Erken Bulma

Bir campaign durduğunda sorun çoğu zaman mutator değil, **harness**'tır. Fuzz target'ınızdan statik olarak erişilebilir olan ancak dinamik olarak nadiren veya hiçbir zaman coverage almayan function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle şu üç sorundan birine işaret eder:

- Harness target'a çok geç veya çok erken giriyor.
- Seed corpus'ta bütün bir feature family eksik.
- Target'ın gerçekten tek ve aşırı büyük bir “do everything” harness yerine **second harness**'a ihtiyacı var.

OSS-Fuzz / ClusterFuzz tarzı workflow'lar kullanıyorsanız, Fuzz Introspector bu triage işlemi için kullanışlıdır:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu kullanarak test edilmemiş bir parser yoluna yeni bir harness ekleyip eklemeyeceğinize, belirli bir özellik için corpus'u genişletip genişletmeyeceğinize veya monolitik bir harness'i daha küçük giriş noktalarına bölüp bölmeyeceğinize karar verin.

## Graph-First Fuzz Target Selection And Mutation Triage

Elinizde zaten **static-analysis findings**, **mutation-testing survivors** ve **coverage reports** varsa bunları birbirinden bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve harici bulgularla açıklayın, ardından graph üzerinde şu soruları sorun:<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki fonksiyonlara untrusted input üzerinden erişilebiliyor?
- Hangi mutation survivors, parser/handler'lar ile security-critical code arasındaki yollarda bulunuyor?
- Hangi fonksiyonlar, alışılmadık derecede yüksek **blast radius** değerine sahip architectural choke point'ler?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz target'ları ortaya çıkarır. **High complexity** değerine sahip ve **external reachability** doğrulanmış bir parser/decoder, coverage'ı zayıf ancak attacker-controlled path'i olmayan izole bir internal helper'dan daha güçlü bir harness adayıdır.

### Practical triage workflow

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına complexity/branch metriklerini çıkarın.
2. Attacker-controlled input kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Reachable attack surface'i dead/internal-only code'dan ayırmak için bu entrypoint'lerden candidate function'lara **path queries** çalıştırın.
4. Şu özellikleri bir arada taşıyan düğümlere öncelik verin:
- yüksek **cyclomatic complexity**
- **untrusted input** üzerinden doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için odaklanmış harness'ler yazın; özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'lere öncelik verin.

### Mutation survivors: equivalent vs actionable

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor'ı bir security gap olarak değerlendirmeden önce graph'ı kullanarak şu soruları sorun:

- Mutasyona uğratılan fonksiyona attacker-controlled bir entrypoint üzerinden erişilebiliyor mu?
- Tüm call path'ler, mutasyona uğratılan check'ten daha güçlü invariant'lar tarafından kısıtlanıyor mu?
- Düğüm dead code, yalnızca formatting yapan logic veya high-impact arithmetic/parser path içinde mi bulunuyor?

Erişilemez kalan veya yapısal olarak kısıtlanan survivor'lar çoğunlukla **equivalent mutants**'tır. **Reachable** kalmaya devam eden ve **boundary conditions**, **overflow/carry paths** veya **security-critical arithmetic/parsing** alanlarına dokunan survivor'lar şu çıktılara dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant test'leri
- hedefli edge-case vector'leri

### Correlate external findings onto the graph

SAST pipeline'ınız **SARIF** export ediyorsa bulguları **file + line range** üzerinden graph düğümlerine yansıtın ve impact'i genişletmek için graph'ı kullanın:

- işaretlenen fonksiyonun **blast radius** değerini hesaplayın
- bulgunun bir entrypoint'ten başlayan herhangi bir path üzerinde olup olmadığını kontrol edin
- aynı choke point'te birleşen yakındaki bulguları cluster'layın

Bu, belirli bir fonksiyon üzerinde fuzzing zamanı harcayıp harcamamaya karar verirken faydalıdır: **reachable**, **complex** olan ve zaten **SAST hits** içeren bir düğüm, attacker path'i olmayan yalnızca complex bir düğümden çoğu zaman daha iyi bir target'tır.

Trailmark ile örnek workflow:<sup>[[6]](#references)</sup>
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
Önemli metodoloji kesişimdir: **karmaşıklık x maruz kalma x etki**. Beklenen güvenlik değeri en yüksek fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve invariant'ları zorlaması gerektiğine karar vermek için mutation survivor'larını kullanın.

## gosentry ile Go Fuzzing: Daha Güçlü Engine, Typed Input'lar ve Differential Check'ler

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan, ancak backend'i **LibAFL** ile değiştiren fork'lanmış bir Go toolchain'idir.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Bu, native Go fuzzer **hard comparisons**, **typed inputs** veya **parser-heavy formats** karşısında takıldığında kullanışlıdır. Methodology aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'si ile çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided run olarak değerlendirin; ancak bu kez LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanılır.

### Sessiz hataları fuzz finding'lerine dönüştürme

Go assessment'larında tekrarlanan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile birkaç “kötü ama sessiz” durumu finding'e dönüştürebilirsiniz:

- `--panic-on=pkg.Func,...`, seçilen logging/error path'lerini crash gibi davranacak şekilde ayarlar. Bu, aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı code path'leri için kullanışlıdır.
- `--catch-races=true`, yeni keşfedilen queue entry'lerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni queue entry'lerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang handling, **infinite loop / çok yavaş input** değerlerini timeout olarak kaybolmalarına izin vermek yerine fuzz finding'leri olarak korur.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri sunulur.

Bu, security impact'in memory corruption yerine **panicsiz parser hatası**, **concurrency bug** veya yalnızca **DoS oluşturan hang** olduğu target'lar için özellikle değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar değerleri bekler. Test edilen code typed object'ler tüketiyorsa gosentry, alttaki byte değerlerini değiştirmeye devam ederken composite value'ları (struct, slice, array, pointer) doğrudan fuzz edebilir.
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
Bunu yalnızca fuzzing için sahte bir wire format oluştururken kullanın; aksi hâlde mantık hataları yalnızca harness'e özgü parsing kodunun arkasında gizlenebilir. Differential veya grammar-based campaign'ler için harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde parse edin.

### Parser'lar ve protocol input'ları için grammar-based fuzzing

Parser'lar, formatlar ve input language'leri için gosentry, LibAFL üzerine **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule'ların JSON array'idir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Byte-level mutations çoğunlukla erken syntax kontrollerinde başarısız oluyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tüm spesifikasyonunu modellemek yerine **security-relevant subset** üzerinde odaklı tutun.
- Integer, length ve state-machine sınırlarını zorlamak için terminal'lerde/nonterminal'lerde büyük boundary değerleri kullanın.
- Grammar mode girdileri grammar açısından geçerli tutar; ancak target hâlâ **bytes/strings** alır, dolayısıyla parsing ve semantic kontroller harness edilmiş kodun içinde kalır.

### Differential fuzzing: yalnızca crash'leri değil, implementasyonları da karşılaştırın

Go ecosystems için güçlü bir yaklaşım **grammar-based differential fuzzing**'dir: geçerli yapılandırılmış girdiler üretin ve bunları iki parser'a, client'a veya state-transition engine'e gönderin.
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
Bunları bulgu olarak değerlendirin:

- bir implementasyon panic verirken diğerinin temiz şekilde reddetmesi
- kabul edilen/reddedilen girdilerdeki uyumsuzluklar
- farklı parse tree'leri veya decode edilmiş nesneler
- farklı state geçişleri, nonce'lar, bakiyeler veya state root'ları

Bu, yalnızca crash fuzzing'in sıklıkla gözden kaçırdığı **consensus mismatches**, **parser ambiguity** ve **spec-vs-implementation drift** durumlarını bulmanın pratik bir yoludur.

### Coverage raporlaması için campaign corpus'u yeniden kullanın

Bir campaign'den sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go coverage report oluşturmak için kaydedilmiş queue corpus'u yeniden oynatın:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Komutu **aynı package** içinden ve **aynı `-fuzz` target** ile çalıştırın; böylece gosentry doğru önbelleğe alınmış campaign state'i çözer.

## Referanslar

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
