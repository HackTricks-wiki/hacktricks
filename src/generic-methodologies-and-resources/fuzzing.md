# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage ve Semantik

**Mutational grammar fuzzing** işleminde girdiler, **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided modda yalnızca **new coverage** tetikleyen örnekler corpus seed olarak kaydedilir. **Language target**'ları (parser'lar, interpreter'lar, engine'ler) için bu yaklaşım, bir construct'ın çıktısının diğerinin girdisi haline geldiği **semantic/dataflow chain** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) işlevlerini ayrı ayrı çalıştıran seed'ler bulur, ancak **chained dataflow**'u **korumaz**. Bu nedenle “bug'a daha yakın” örnek, coverage eklemediği için elenir. **3+ dependent step** olduğunda random recombination maliyetli hale gelir ve coverage feedback aramayı yönlendiremez.<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar'lar için **mutational** ve **generative phase**'leri **hybridize etmeyi** veya generation'ı yalnızca coverage'a değil, **function chaining** pattern'lerine doğru bias etmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy**'dir: new-coverage örneği hemen kaydedilir ve çoğu zaman büyük, değişmeden kalan bölgeleri korur. Zamanla corpus'lar, düşük structural diversity'ye sahip **near-duplicate** örneklerden oluşur. Aggressive minimization faydalı context'i kaldırabilir; bu nedenle pratik bir uzlaşma, **minimum token threshold**'a ulaşıldıktan sonra duran **grammar-aware minimization** kullanmaktır (noise'u azaltırken mutation-friendly kalmak için yeterli çevre yapısını korumak).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı şudur: büyük bir near-duplicate yığını yerine, **coverage'ı maksimize eden ve yapısal olarak farklı küçük bir seed setini tercih edin**. Pratikte bu genellikle aşağıdakileri ifade eder.<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world sample**'lardan başlayın (public corpus'lar, crawling, captured traffic, target ecosystem'dan file set'leri).
- Her valid sample'ı saklamak yerine **coverage-based corpus minimization** ile bunları daraltın.
- Seed'leri, mutation'ların çoğu cycle'ı irrelevant byte'lar üzerinde harcamak yerine anlamlı field'lara ulaşacağı kadar küçük tutun.
- Major harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Value'lar İçin Comparison-Aware Mutation

Fuzzer'ların plateau yapmasının yaygın bir nedeni syntax değil, **hard comparison**'lardır: magic byte'lar, length check'leri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da cascaded comparison'larla korunan parser dispatch value'ları. Pure random mutation, bu value'ları byte-byte tahmin etmeye çalışırken cycle'ları boşa harcar.

Bu target'lar için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen-style workflow'ları) kullanın. Böylece fuzzer, başarısız comparison'ların operand'larını gözlemleyebilir ve mutation'ları bu comparison'ları karşılayan value'lara doğru bias edebilir.<sup>[[3]](#references)</sup>
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

- Bu, hedef **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasında derin mantığı gizlediğinde özellikle kullanışlıdır.
- Bunu gerçek örneklerden, protocol spesifikasyonlarından veya debug loglarından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token'ları, chunk adları, verb'ler ve delimiter'lar içeren küçük bir dictionary, çoğu zaman devasa bir generic wordlist'ten daha değerlidir.
- Hedef birçok ardışık kontrol gerçekleştiriyorsa, önce en erken “magic” karşılaştırmalarını çözün ve ardından ortaya çıkan corpus'u tekrar minimize edin; böylece sonraki aşamalar zaten geçerli prefix'lerle başlar.

## Stateful Fuzzing: Diziler Seed'dir

**Protocols**, **authenticated workflows** ve **multi-stage parsers** için ilgi çekici birim çoğu zaman tek bir blob değil, bir **message sequence**'tir. Tüm transcript'i tek bir dosyada birleştirip körlemesine mutate etmek genellikle verimsizdir; çünkü yalnızca sonraki message fragile state'e ulaşsa bile fuzzer her adımı eşit şekilde mutate eder.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **sequence'in kendisini seed** olarak ele almak ve **observable state**'i (response code'ları, protocol state'leri, parser phase'leri, döndürülen object type'ları) ek feedback olarak kullanmaktır.<sup>[[4]](#references)</sup>

- **Valid prefix message**'larını sabit tutun ve mutation'ları **transition-driving** message'a odaklayın.
- Sonraki adım bunlara bağlı olduğunda, önceki response'larda üretilen identifier'ları ve server-generated value'ları cache'leyin.
- Tüm serialized transcript'i opaque bir blob olarak mutate etmek yerine message başına mutation/splicing kullanmayı tercih edin.
- Protocol anlamlı response code'ları sunuyorsa, daha derine ilerleyen sequence'lere öncelik vermek için bunları **cheap state oracle** olarak kullanın.

Authenticated bug'ların, hidden transition'ların veya “only-after-handshake” parser bug'larının vanilla file-style Fuzzing tarafından sıklıkla gözden kaçırılmasının nedeni de budur: fuzzer yalnızca structure'ı değil, **order, state ve dependencies**'i de korumalıdır.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty**'yi **coverage reuse** ile hybridize etmenin pratik bir yolu, persistent bir server'a karşı kısa ömürlü worker'ları **restart** etmektir. Her worker boş bir corpus ile başlar, `T` saniye sonra sync eder, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar sync eder ve ardından çıkar. Bu yöntem, biriken coverage'dan yararlanmaya devam ederken **her generation'da fresh structure'lar** üretir.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sıralı worker'lar (örnek döngü):**

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

- `-in empty`, her generation işleminde **yeni bir corpus** kullanılmasını zorunlu kılar.
- `-server_update_interval T`, **gecikmeli sync** işlemini yaklaşık olarak taklit eder (önce yenilik, daha sonra yeniden kullanım).
- Grammar fuzzing mode'da **initial server sync** varsayılan olarak atlanır (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T` değeri **hedefe bağlıdır**; worker çoğu “kolay” coverage'ı bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Snapshot Fuzzing For Hard-To-Harness Targets

Test etmek istediğiniz kod yalnızca **yüksek bir kurulum maliyetinden** (bir VM'yi başlatmak, login işlemini tamamlamak, bir paket almak, bir container'ı parse etmek veya bir servisi initialize etmek) sonra erişilebilir hâle geliyorsa, kullanışlı bir alternatif **snapshot fuzzing** yöntemidir: hazır process veya VM durumunu yakalayın, her test case'i hedef input path'ine inject edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem initialization veya protocol prefix işlemlerinin tekrarlanmasını önler ve **network services**, **firmware**, **post-auth attack surfaces** ve **binary-only targets** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici state hazır olana kadar hedefi çalıştırın.
2. Bu noktada **memory + registers** snapshot'ını alın.
3. Her test case için mutate edilmiş input'u doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde destekleniyorsa yalnızca **dirty pages**'leri geri yükleyin, ardından tekrarlayın.

Snapshot'ı, ilk pahalı parse/dispatch adımına pratik olarak mümkün olduğunca yakın bir yere yerleştirin; örneğin bir `recv`/`read` işleminden veya packet-deserialization noktasından sonra. Ayrıca hedef tarafından kullanılan input buffer'ı kaydedin. Bu yaklaşım, tekrarlanan işlemleri önlemek için snapshot'ı input processing'in daha derinlerine taşıyan adaptive-placement ilkesini izler.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Bir campaign durduğunda sorun genellikle mutator değil, **harness** olur. Fuzz target'ınızdan statik olarak erişilebilir olan ancak dinamik olarak nadiren veya hiç coverage almayan function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness, hedefe çok geç veya çok erken girer.
- Seed corpus'ta bütün bir feature family eksiktir.
- Hedef, aşırı büyük bir “do everything” harness yerine gerçekten **ikinci bir harness** gerektirir.

OSS-Fuzz / ClusterFuzz-style workflow'lar kullanıyorsanız Fuzz Introspector, static reachability ile runtime coverage'ı karşılaştırabilir ve zaman sınırlı bir run'dan veya public corpus'tan report'lar oluşturabilir.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu kullanarak test edilmemiş bir parser yolculuğu için yeni bir harness ekleyip eklememeye, belirli bir özellik için corpus'u genişletmeye veya monolithic bir harness'i daha küçük entry point'lere bölmeye karar verin.

## Graph-First Fuzz Target Selection And Mutation Triage

Zaten **static-analysis findings**, **mutation-testing survivors** ve **coverage reports** varsa bunları birbirinden bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve mevcut external findings ile açıklayın, ardından graph sorularını yöneltin.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek complexity'li function'lar untrusted input'tan erişilebilir?
- Hangi mutation survivor'ları parser/handler'lar ile security-critical code arasındaki path'lerde bulunuyor?
- Hangi function'lar alışılmadık derecede yüksek **blast radius** değerine sahip architectural choke point'ler?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz target'ları ortaya çıkarır. **High complexity** değerine ve doğrulanmış **external reachability** özelliğine sahip bir parser/decoder, coverage'ı zayıf ancak attacker-controlled path'i olmayan izole bir internal helper'dan daha güçlü bir harness adayıdır.

### Practical triage workflow

1. Codebase'den bir **code graph** oluşturun ve function başına complexity/branch metric'lerini çıkarın.
2. Attacker-controlled input kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Erişilebilir attack surface'i dead/internal-only code'dan ayırmak için bu entrypoint'lerden candidate function'lara **path query**'leri çalıştırın.
4. Şu özellikleri birleştiren node'lara öncelik verin:
- yüksek **cyclomatic complexity**
- **untrusted input**'tan doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** finding'leri, audit note'ları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı node'lar için, özellikle hex/Base64/IP/message decoder gibi **parser/codec**'ler için odaklanmış harness'ler yazın.

### Mutation survivors: equivalent vs actionable

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor'ı bir security gap olarak değerlendirmeden önce graph'ı kullanarak şu soruları sorun:

- Mutasyona uğratılan function attacker-controlled bir entrypoint'ten erişilebilir mi?
- Tüm call path'ler, mutasyona uğratılan check'ten daha güçlü invariant'lar tarafından kısıtlanıyor mu?
- Node dead code, yalnızca formatting yapan logic veya yüksek etkili arithmetic/parser path'inde mi bulunuyor?

Erişilemez veya yapısal olarak kısıtlanmış survivor'lar çoğunlukla **equivalent mutant**'lardır. **Reachable** kalan ve **boundary condition**'lara, **overflow/carry path**'lerine veya **security-critical arithmetic/parsing** işlemlerine dokunan survivor'lar şu öğelere dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant test'leri
- hedefli edge-case vector'leri

### Correlate external findings onto the graph

SAST pipeline'ınız **SARIF** export ediyorsa graph node'larına **file + line range** üzerinden finding'ler ekleyin ve graph'ı kullanarak etkiyi genişletin.<sup>[[6]](#references)</sup>

- işaretlenen function'ın **blast radius** değerini hesaplayın
- finding'in bir entrypoint'ten gelen herhangi bir path üzerinde olup olmadığını kontrol edin
- aynı choke point'te birleşen yakın finding'leri cluster'layın

Bu, belirli bir function üzerinde fuzzing zamanı harcayıp harcamamaya karar verirken faydalıdır: **reachable**, **complex** olan ve zaten **SAST hit**'lerine sahip bir node, attacker path'i olmayan yalnızca complex bir node'dan genellikle daha iyi bir target'tır.

Trailmark ile örnek workflow.<sup>[[6]](#references)</sup>
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
Önemli metodoloji kesişimdir: **complexity x exposure x impact**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve invariant'ları zorlaması gerektiğine karar vermek için mutation survivors'ı kullanın.<sup>[[5]](#references)</sup>

## gosentry ile Go Fuzzing: Daha Güçlü Motor, Typed Inputs ve Differential Checks

Bir Go hedefinde zaten native bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan, ancak backend'i **LibAFL** ile değiştiren fork'lanmış bir Go toolchain'idir.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Bu, native Go fuzzer **hard comparisons**, **typed inputs** veya **parser-heavy formats** nedeniyle takıldığında kullanışlıdır. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'si ile çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided run olarak değerlendirin; ancak LibAFL scheduling/mutation ve daha iyi ek detector'lar kullanıldığını göz önünde bulundurun.

### Sessiz hataları fuzz bulgularına dönüştürme

Go assessment'larında tekrarlanan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçilen logging/error yollarını crash gibi davranacak şekilde yapılandırır (aksi hâlde yalnızca log'layıp devam eden `log.Fatal` tarzı code path'ler için kullanışlıdır).
- `--catch-races=true`, yeni keşfedilen queue entry'lerini Go race detector ile yeniden oynatır.
- `--catch-leaks=true`, yeni queue entry'lerini `goleak` ile yeniden oynatır ve goroutine leak'lerinde durur.
- LibAFL hang handling, **infinite loop / very slow input** durumlarını timeout olarak kaybolmalarına izin vermek yerine fuzz bulguları olarak korur.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, security impact'in memory corruption yerine **panicless parser failure**, **concurrency bug** veya yalnızca **DoS** oluşturan bir hang olduğu target'lar için özellikle değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen code typed object'ler tüketiyorsa gosentry, bytes'ları alt düzeyde mutate etmeye devam ederken **composite value**'ları (struct'lar, slice'lar, array'ler, pointer'lar) doğrudan fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>
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
Bunu, yalnızca fuzzing için sahte bir wire formatı oluştururken kullanmak, harness'e özgü parsing kodunun arkasındaki logic bug'larını gizleyebilir. Differential veya grammar-based campaign'ler için harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde parse edin.

### Parser'lar ve protokol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve input language'leri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, bir production rule JSON array'idir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notları:

- Byte-level mutations çoğunlukla erken syntax kontrollerinde sonlanıyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tamamını modellemek yerine **security-relevant subset** üzerine odaklayın.
- Integer, length ve state-machine sınırlarını zorlamak için terminal/nonterminal'larda büyük boundary değerleri kullanın.
- Grammar mode input'ları grammar-valid tutar; ancak target hâlâ **bytes/strings** alır, bu nedenle parsing ve semantic kontroller harness edilen kodun içinde kalır.

### Differential fuzzing: yalnızca crash'leri değil, implementasyonları karşılaştırın

Go ecosystem'leri için güçlü bir pattern **grammar-based differential fuzzing**'dir: geçerli structured input'lar üretin ve bunları iki parser'a, client'a veya state-transition engine'ine verin.<sup>[[7]](#references)[[8]](#references)</sup>
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

- bir uygulama panic verirken diğeri düzgün şekilde reddediyor
- kabul edilen/reddedilen girdiler arasında uyumsuzluklar
- farklı parse ağaçları veya decoded nesneler
- farklı state geçişleri, nonce'lar, bakiyeler veya state root'ları

Bu, yalnızca crash fuzzing'in çoğu zaman gözden kaçırdığı **consensus mismatches**, **parser ambiguity** ve **spec-vs-implementation drift** durumlarını bulmanın pratik bir yoludur.

### Coverage reporting için campaign corpus'u yeniden kullanın

Bir campaign'den sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus'u yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Komutu **aynı package** içinden ve **aynı `-fuzz` target** ile çalıştırın; böylece gosentry doğru önbelleğe alınmış campaign state'i çözer.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: A Fast Greybox Fuzzer for Stateful Network Protocols using Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Efficient Fuzzing with Adaptive and Mutable Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
