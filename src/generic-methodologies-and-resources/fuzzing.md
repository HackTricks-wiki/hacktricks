# Fuzzing Metodolojisi

## Mutational Grammar Fuzzing: Coverage ve Semantics

**Mutational grammar fuzzing** kapsamında input'lar **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided mode'da yalnızca **new coverage** tetikleyen sample'lar corpus seed olarak kaydedilir. **Language target'lar** (parser'lar, interpreter'lar, engine'ler) için bu yaklaşım, bir construct'ın çıktısının başka bir construct'ın input'u olduğu **semantic/dataflow chain** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) işlevlerini tek başına kullanan seed'ler bulur, ancak **chained dataflow**'u korumaz. Bu nedenle, “bug'a daha yakın” sample coverage eklemediği için elenir. **3+ dependent step** olduğunda random recombination pahalı hale gelir ve coverage feedback aramaya yön vermez.<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar'lar için **mutational** ve **generative** aşamaları **hybridize etmeyi** veya generation'ı yalnızca coverage'a değil, **function chaining** pattern'lerine de yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy**'dir: new coverage sağlayan bir sample hemen kaydedilir ve çoğu zaman büyük, değiştirilmemiş bölgeleri korur. Zamanla corpus'lar, düşük structural diversity'ye sahip **near-duplicate**'lara dönüşür. Aggressive minimization yararlı context'i kaldırabilir. Bu nedenle pratik bir uzlaşma, **minimum token threshold** sonrasında duran **grammar-aware minimization** uygulamaktır (gürültüyü azaltırken mutation-friendly kalmak için yeterli çevre yapısını korur).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı şudur: çok sayıda near-duplicate yerine, **coverage'ı maksimize eden ve yapısal olarak farklı küçük bir seed setini tercih edin**. Uygulamada bu genellikle aşağıdakiler anlamına gelir.<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world sample**'lardan başlayın (public corpus'lar, crawling, captured traffic, target ecosystem'den file set'leri).
- Her geçerli sample'ı saklamak yerine bunları **coverage-based corpus minimization** ile ayıklayın.
- Mutation'ların çoğu cycle'ı ilgisiz byte'lar üzerinde harcamak yerine anlamlı field'lara isabet etmesi için seed'leri yeterince küçük tutun.
- Major harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Comparison-Aware Mutation For Magic Values

Fuzzer'ların plateau yapmasının yaygın bir nedeni syntax değil, **hard comparison**'lar olmasıdır: `memcmp`, switch table'ları veya ardışık comparison'lar tarafından korunan magic byte'lar, length check'leri, enum string'leri, checksum'lar veya parser dispatch value'ları. Pure random mutation, bu value'ları byte byte tahmin etmeye çalışırken cycle'ları boşa harcar.

Bu target'lar için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen-style workflow'lar) kullanın. Böylece fuzzer, başarısız comparison'ların operand'larını gözlemleyebilir ve mutation'ları bu comparison'ları karşılayan value'lara yönlendirebilir.<sup>[[3]](#references)</sup>
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

- Bu, hedefin derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasında gizlediği durumlarda özellikle kullanışlıdır.
- Bunu gerçek örneklerden, protocol spesifikasyonlarından veya debug loglarından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token'ları, chunk adları, fiiller ve ayraçlardan oluşan küçük bir dictionary, genellikle devasa bir generic wordlist'ten daha değerlidir.
- Hedef art arda birçok kontrol gerçekleştiriyorsa, en erken “magic” karşılaştırmalarını önce çözün ve ardından ortaya çıkan corpus'u tekrar minimize edin; böylece sonraki aşamalar zaten geçerli prefix'lerden başlar.

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** ve **multi-stage parsers** için ilgi çekici birim genellikle tek bir blob değil, bir **message sequence**'tir. Tüm transcript'i tek bir dosyada birleştirip körü körüne mutate etmek genellikle verimsizdir; çünkü fuzzer, yalnızca sonraki message kırılgan duruma ulaşsa bile her adımı eşit şekilde mutate eder.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **sequence**'in kendisini seed olarak ele almak ve **observable state**'i (response codes, protocol states, parser phases, döndürülen object types) ek feedback olarak kullanmaktır.<sup>[[4]](#references)</sup>

- **Valid prefix messages**'ları sabit tutun ve mutation'ları **transition-driving** message'a odaklayın.
- Sonraki adım bunlara bağlı olduğunda, önceki response'larda bulunan identifier'ları ve server tarafından üretilen değerleri cache'leyin.
- Tüm serialized transcript'i opak bir blob olarak mutate etmek yerine, message başına mutation/splicing kullanmayı tercih edin.
- Protocol anlamlı response codes sunuyorsa, daha derine ilerleyen sequence'lere öncelik vermek için bunları **cheap state oracle** olarak kullanın.

Authenticated bug'ların, gizli transition'ların veya “only-after-handshake” parser bug'larının vanilla file-style fuzzing tarafından sıklıkla gözden kaçırılmasının nedeni de budur: fuzzer yalnızca structure'ı değil, **order, state ve dependencies**'i de korumalıdır.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** ile **coverage reuse**'u hybridize etmenin pratik bir yolu, persistent server'a karşı kısa ömürlü worker'ları **restart** etmektir. Her worker boş bir corpus ile başlar, `T` saniye sonra sync yapar, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar sync yapar ve ardından çıkar. Bu yaklaşım, birikmiş coverage'dan yararlanmaya devam ederken **her generation'da fresh structures** elde edilmesini sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

**Sunucu:**
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

- `-in empty`, her generation işleminde **fresh corpus** kullanılmasını zorunlu kılar.
- `-server_update_interval T`, **delayed sync** davranışını yaklaşık olarak simüle eder (önce novelty, sonra reuse).
- Grammar fuzzing modunda, **initial server sync** varsayılan olarak atlanır (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- Optimal `T` değeri **target-dependent**'tır; worker çoğu “kolay” coverage'ı bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Hard-To-Harness Target'lar İçin Snapshot Fuzzing

Test etmek istediğiniz kod yalnızca **büyük bir kurulum maliyetinden** sonra erişilebilir hâle geliyorsa (VM başlatmak, login işlemini tamamlamak, bir packet almak, bir container parse etmek veya bir service initialize etmek gibi), kullanışlı bir alternatif **snapshot fuzzing**'dir: hazır process veya VM state'ini yakalayın, her test case'i target input path'e enjekte edin, crash/timeout oluşana kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem initialization veya protocol prefix'lerinin tekrar tekrar yürütülmesini önler ve **network service'leri**, **firmware'i**, **post-auth attack surface'lerini** ve **binary-only target'ları** test etmek için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici state hazır olana kadar target'ı çalıştırın.
2. Bu noktada **memory + registers** snapshot'ını alın.
3. Her test case için mutated input'ı doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset oluşana kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM target'ları için destekleniyorsa yalnızca **dirty pages**'leri geri yükleyin, ardından tekrarlayın.

Snapshot'ı, ilk pahalı parse/dispatch adımına pratik olarak mümkün olduğunca yakın bir yere, örneğin bir `recv`/`read` veya packet-deserialization noktasının sonrasına yerleştirin ve target tarafından kullanılan input buffer'ını kaydedin. Bu yaklaşım, tekrarlanan işlemleri önlemek amacıyla snapshot'ı input processing'in daha derinlerine taşıyan adaptive-placement ilkesini izler.<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzer'ları Erken Bulma

Bir campaign durduğunda sorun çoğu zaman mutator değil, **harness**'tır. Fuzz target'ınızdan statik olarak erişilebilir olan ancak dinamik olarak nadiren veya hiç coverage edilmeyen function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness target'a çok geç veya çok erken giriyor.
- Seed corpus'ta bütün bir feature family eksik.
- Target'ın tek ve aşırı büyük bir “do everything” harness yerine gerçekten **second harness**'a ihtiyacı var.

OSS-Fuzz / ClusterFuzz tarzı workflow'lar kullanıyorsanız Fuzz Introspector, static reachability ile runtime coverage'ı karşılaştırabilir ve timed run veya public corpus'tan report'lar oluşturabilir.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu kullanarak test edilmemiş bir parser path'i için yeni bir harness ekleyip eklememeye, belirli bir özellik için corpus'u genişletmeye veya monolithic bir harness'i daha küçük entry point'lere bölmeye karar verin.

## Graph-First Fuzz Target Selection And Mutation Triage

Elinizde zaten **static-analysis findings**, **mutation-testing survivors** ve **coverage reports** varsa bunları bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve harici bulgularla açıklayın, ardından graph soruları sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki işlevlere untrusted input üzerinden erişilebiliyor?
- Hangi mutation survivor'lar parser/handler'lardan security-critical code'a giden path'ler üzerinde bulunuyor?
- Hangi işlevler olağandışı derecede yüksek **blast radius** değerine sahip architectural choke point'ler?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine göre daha iyi fuzz target'ları ortaya çıkarır. **High complexity** değerine ve doğrulanmış **external reachability** durumuna sahip bir parser/decoder, coverage'ı zayıf ancak attacker-controlled path'i bulunmayan izole bir internal helper'dan daha güçlü bir harness adayıdır.

### Practical triage workflow

1. Codebase'den bir **code graph** oluşturun ve işlev başına complexity/branch metriklerini çıkarın.
2. Attacker-controlled input kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Ulaşılabilir attack surface'i dead/internal-only code'dan ayırmak için bu entrypoint'lerden candidate function'lara **path query** çalıştırın.
4. Aşağıdaki özellikleri bir arada taşıyan düğümlere öncelik verin:
- yüksek **cyclomatic complexity**
- **untrusted input** üzerinden doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** findings, audit notes veya mutation survivor'lar gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için, özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için odaklanmış harness'ler yazın.

### Mutation survivors: equivalent vs actionable

Mutation testing genellikle gürültülü bir survivor listesi üretir. Her survivor'ı bir security gap olarak değerlendirmeden önce graph'ı kullanarak şu soruları sorun:

- Mutasyona uğratılan işleve attacker-controlled entrypoint üzerinden erişilebiliyor mu?
- Tüm call path'ler, mutasyona uğratılan check'ten daha güçlü invariant'lar tarafından kısıtlanıyor mu?
- Düğüm dead code, yalnızca formatting yapan logic veya yüksek etkili arithmetic/parser path'i içinde mi bulunuyor?

Ulaşılamayan veya yapısal olarak kısıtlanmış survivor'lar çoğunlukla **equivalent mutants**'tır. **Reachable** durumda kalan ve **boundary conditions**, **overflow/carry paths** veya **security-critical arithmetic/parsing** ile etkileşen survivor'lar aşağıdakilere dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant test'leri
- hedefli edge-case vector'leri

### Correlate external findings onto the graph

SAST pipeline'ınız **SARIF** export ediyorsa bulguları **file + line range** üzerinden graph düğümlerine yansıtın ve impact'i genişletmek için graph'ı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen işlevin **blast radius** değerini hesaplayın
- bulgunun bir entrypoint'ten başlayan herhangi bir path üzerinde olup olmadığını kontrol edin
- aynı choke point'te birleşen yakındaki bulguları cluster'layın

Bu, fuzzing zamanını belirli bir işleve harcayıp harcamamaya karar verirken faydalıdır: **reachable**, **complex** olan ve hâlihazırda **SAST hits** içeren bir düğüm, attacker path'i bulunmayan yalnızca complex bir düğümden genellikle daha iyi bir target'tır.

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
Önemli metodoloji kesişimdir: **complexity x exposure x impact**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve invariant'ları zorlaması gerektiğine karar vermek için mutasyon sonucunda hayatta kalan girdileri kullanın.<sup>[[5]](#references)</sup>

## gosentry ile Go Fuzzing: Daha Güçlü Engine, Typed Inputs ve Differential Checks

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan, ancak backend'i **LibAFL** ile değiştiren çatallanmış bir Go toolchain'idir.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Bu, native Go fuzzer'ın **hard comparisons**, **typed inputs** veya **parser-heavy formats** üzerinde takıldığı durumlarda kullanışlıdır. Methodology aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'si ile çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided run olarak değerlendirin; ancak bu kez LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanılır.

### Sessiz hataları fuzz bulgularına dönüştürme

Go assessment'larında tekrarlanan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile çeşitli “kötü ancak sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçilen logging/error path'lerini crash gibi davranacak şekilde değiştirir. Bu, aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı code path'leri için kullanışlıdır.
- `--catch-races=true`, yeni keşfedilen queue entry'lerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni queue entry'lerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang handling, **infinite loops / very slow inputs** değerlerini timeout olarak kaybolmalarına izin vermek yerine fuzz bulguları olarak korur.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint-style instrumentation aracılığıyla isteğe bağlı truncation kontrolleri sunar.

Bu özellik, güvenlik etkisinin memory corruption yerine **panicless parser failure**, **concurrency bug** veya yalnızca **DoS** etkili bir **hang** olduğu hedefler için özellikle değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing temel olarak `[]byte`, `string` ve sayılar gibi scalar değerleri bekler. Test edilen kod typed object'ler tüketiyorsa gosentry, altyapıda byte'ları mutate etmeye devam ederken **composite values**'ları (structs, slices, arrays, pointers) doğrudan fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>
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
Bunu, yalnızca fuzzing için sahte bir wire format oluştururken kullanmak, logic bug'larını yalnızca harness'a özgü parsing kodunun arkasında gizler. Differential veya grammar-based campaign'ler için harness input'unu tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde parse edin.

### Parser'lar ve protocol input'ları için grammar-based fuzzing

Parser'lar, formatlar ve input language'leri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule'larının bir JSON array'idir ve harness genellikle tek bir `[]byte` veya `string` argument'ı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodoloji notları:

- Byte-level mutations çoğunlukla erken syntax kontrollerinde sonlanıyorsa grammar mode kullanın.
- Tüm spesifikasyonu modellemek yerine grammar'ı dilin/protokolün **security-relevant subset** kısmına odaklayın.
- Integer, length ve state-machine sınırlarını zorlamak için terminallerde/nonterminallerde büyük boundary değerleri kullanın.
- Grammar mode girdileri grammar-valid tutar; ancak hedef yine de **bytes/strings** alır, bu nedenle parsing ve semantic kontroller harness edilen kodun içinde kalır.

### Differential fuzzing: yalnızca crash'leri değil, implementasyonları karşılaştırın

Go ekosistemleri için güçlü bir yaklaşım **grammar-based differential fuzzing**'dir: geçerli yapılandırılmış girdiler üretin ve bunları iki parser'a, client'a veya state-transition engine'e besleyin.<sup>[[7]](#references)[[8]](#references)</sup>
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

- bir implementation panic verirken diğeri düzgün şekilde reddediyor
- kabul edilen/reddedilen input uyuşmazlıkları
- farklı parse ağaçları veya decode edilmiş nesneler
- farklı state transitions, nonce'lar, bakiyeler veya state root'ları

Bu, pure crash fuzzing'in sıklıkla gözden kaçırdığı **consensus mismatches**, **parser ambiguity** ve **spec-vs-implementation drift** durumlarını bulmanın pratik bir yoludur.

### Coverage raporlaması için campaign corpus'u yeniden kullanın

Bir campaign'den sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus'u yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Komutu, gosentry'nin doğru cached campaign state'i çözümlemesi için **aynı package** içinden ve **aynı `-fuzz` target** ile çalıştırın.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshots kullanarak Stateful Network Protocols için Hızlı bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar yok, sorun yok: System-Call Descriptions olmadan Linux Kernel'ını Fuzzing'e doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive ve Mutable Snapshots ile Efficient Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
