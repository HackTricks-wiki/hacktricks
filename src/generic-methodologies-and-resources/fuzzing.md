# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage ve Semantics

**Mutational grammar fuzzing** yönteminde input'lar **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided modda yalnızca **yeni coverage** tetikleyen örnekler corpus seed olarak kaydedilir. **Language target'ları** (parser'lar, interpreter'lar, engine'ler) için bu yaklaşım, bir construct'ın çıktısının başka bir construct'ın input'u olduğu **semantic/dataflow chain** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) fonksiyonlarını ayrı ayrı çalıştıran seed'ler bulur; ancak **chained dataflow** yapısını korumaz. Bu nedenle “bug'a daha yakın” örnek, coverage eklemediği için elenir. **3+ bağımlı adımda** rastgele recombination pahalı hale gelir ve coverage feedback aramayı yönlendiremez.<sup>[[1]](#references)</sup>

**Implication:** dependency-heavy grammar'lar için **mutational** ve **generative** aşamaları hibritleştirmeyi veya üretimi yalnızca coverage'a değil, **function chaining** pattern'lerine de yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Diversity Tuzakları

Coverage-guided mutation **greedy** çalışır: yeni coverage sağlayan bir örnek hemen kaydedilir ve çoğu zaman büyük, değiştirilmemiş bölgeler korunur. Zamanla corpus'lar düşük yapısal çeşitliliğe sahip **near-duplicate** örneklerden oluşur. Aggressive minimization faydalı context'i kaldırabilir; bu nedenle pratik bir uzlaşma, **minimum token threshold** değerine ulaşıldığında duran **grammar-aware minimization** kullanmaktır (gürültüyü azaltırken mutation-friendly kalmak için yeterli çevre yapısını korumak).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı şudur: çok sayıda near-duplicate yerine, **coverage'ı maksimize eden ve yapısal olarak farklı seed'lerden oluşan küçük bir seti tercih edin**. Pratikte bu genellikle aşağıdakileri ifade eder.<sup>[[1]](#references)[[3]](#references)</sup>

- **Real-world sample'lar** ile başlayın (public corpus'lar, crawling, yakalanmış traffic, target ecosystem'ından alınan file set'leri).
- Her valid sample'ı saklamak yerine bunları **coverage-based corpus minimization** ile damıtın.
- Mutation'ların çoğu cycle'ı ilgisiz byte'lar üzerinde harcamak yerine anlamlı field'lara isabet etmesi için seed'leri **yeterince küçük** tutun.
- Büyük harness/instrumentation değişikliklerinden sonra corpus minimization işlemini yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Values İçin Comparison-Aware Mutation

Fuzzer'ların plateau'a ulaşmasının yaygın bir nedeni syntax değil, **hard comparison** işlemleridir: magic byte'lar, length check'leri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da art arda yapılan comparison'larla korunan parser dispatch value'ları. Pure random mutation, bu değerleri byte byte tahmin etmeye çalışırken cycle'ları boşa harcar.

Bu target'lar için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen-style workflow'lar) kullanın; böylece fuzzer başarısız comparison'ların operand'larını gözlemleyebilir ve mutation'ları bunları karşılayan değerlere doğru yönlendirebilir.<sup>[[3]](#references)</sup>
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
- Bunu gerçek örneklerden, protocol spesifikasyonlarından veya debug log'larından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token'ları, chunk adları, fiiller ve delimiter'lar içeren küçük bir dictionary, çoğu zaman devasa bir genel wordlist'ten daha değerlidir.
- Hedef art arda birçok kontrol gerçekleştiriyorsa önce en erken “magic” karşılaştırmalarını çözün, ardından ortaya çıkan corpus'u yeniden minimize edin; böylece sonraki aşamalar zaten geçerli prefix'lerden başlar.

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper'dan farklı caller'lar aracılığıyla geçen veya bir function içindeki farklı branch kombinasyonlarını izleyen iki execution'ı birbirinden ayırt edemez. Bu durum, **route**'un bir edge'e ulaşmasının canlı state'i belirlediği paylaşılan decoder'lar, protocol dispatcher'lar ve interpreter helper'larında önemlidir. Her calling context'i naif biçimde izlemek de tehlikelidir: coverage map ve queue kontrolden çıkarak büyüyebilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'ı context-sensitive olarak ele almak yerine yalnızca umut vadeden context'lerin ayrıntılandırılmasını önerir.<sup>[[14]](#references)</sup>

Güncel AFL++ build'leri, normal edge coverage'a ek olarak **Ball-Larus per-function path coverage** sunar. Bir function içindeki her acyclic path'e bir feature atar; loop back-edge'leri kaldırılır, bu nedenle bu geri bildirim branch kombinasyonlarını ayırt eder ancak **loop iteration counts**'ları ayırt etmez. Gevşek `1` seviyesiyle başlayın, ardından daha katı modları şüpheli parser/state-machine koduyla sınırlandırın; çünkü path sayısı üstel olarak artabilir.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Birçok güvenlikle ilgili konumdan çağrılan bir yardımcı için LTO modu, her işlev yolunu doğrudan çağrı sitesiyle birleştirebilir:<sup>[[13]](#references)</sup>
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
**Campaign guidance:** daha zengin geri bildirimi temkinli bir şekilde uygulayın ve coverage-map/queue maliyetini izleyin.<sup>[[13]](#references)[[14]](#references)</sup>

- Sıradan bir edge-coverage instance'ını paralel olarak çalıştırın; daha zengin geri bildirim yalnızca ek queue/map maliyeti saniye başına çalıştırma sayısını düşürmüyorsa faydalıdır.
- Büyük template-heavy kütüphaneler veya generic utility code map'e hakim olduğunda path/caller instrumentation'ı kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda acyclic path içeren functions AFL++ tarafından atlanabilir; derleme sırasındaki warnings, target'ın allowlisting'e veya daha az katı bir seviyeye ihtiyaç duyduğunun göstergesidir.
- Caller + path coverage yalnızca tek bir caller depth destekler. Bunu daha derin context stacks ile birleştirmeyin.
- Path IDs, LLVM major versions arasında değişebilir. Bir campaign için toolchain'i sabit tutun ve PATH tabanlı corpus'ları feature ID'leri build'ler arasında sabitmiş gibi synchronize etmeyin.
- Bu geri bildirim `CMPLOG`'u tamamlar: comparison tracing, **bir guard'dan hangi değerin geçtiğini** çözerken path/caller geri bildirimi, **hangi route ve branch kombinasyonunun** oraya ulaştığını korur.

## Stateful Fuzzing: Sequences Are Seeds

**Protocols**, **authenticated workflows** ve **multi-stage parsers** için ilgi çekici birim çoğu zaman tek bir blob değil, bir **message sequence**'dır. Tüm transcript'i tek bir dosyada birleştirip körlemesine mutate etmek genellikle verimsizdir; çünkü fuzzer, yalnızca daha sonraki message fragile state'e ulaştığında bile her step'i eşit şekilde mutate eder.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **sequence'in kendisini seed** olarak ele almak ve **observable state**'i (response codes, protocol states, parser phases, returned object types) ek feedback olarak kullanmaktır.<sup>[[4]](#references)</sup>

- **Valid prefix messages**'ı sabit tutun ve mutation'ları **transition-driving** message üzerinde yoğunlaştırın.
- Sonraki step bunlara bağlı olduğunda, önceki response'lardan gelen identifier'ları ve server-generated values'ları cache'leyin.
- Tüm serialized transcript'i opaque bir blob olarak mutate etmek yerine per-message mutation/splicing'i tercih edin.
- Protocol anlamlı response codes sunuyorsa bunları, daha derine ilerleyen sequences'lara öncelik vermek için **ucuz bir state oracle** olarak kullanın.

Authenticated bugs, hidden transitions veya “only-after-handshake” parser bugs'ın vanilla file-style fuzzing tarafından sıklıkla gözden kaçırılmasının nedeni de aynıdır: fuzzer yalnızca structure'ı değil, **order, state ve dependencies**'i de korumalıdır.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** ile **coverage reuse**'u hibritleştirmenin pratik bir yolu, **persistent server**'a karşı kısa ömürlü workers'ları yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra sync yapar, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar sync yapar ve ardından çıkar. Bu, birikmiş coverage'dan yararlanmaya devam ederken **her generation'da fresh structures** elde edilmesini sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty`, her generation işleminde **fresh corpus** kullanılmasını zorunlu kılar.
- `-server_update_interval T`, **delayed sync** davranışını yaklaşık olarak simüle eder (önce yenilik, sonra yeniden kullanım).
- Grammar fuzzing modunda **initial server sync** varsayılan olarak atlanır (`-skip_initial_server_sync` gerekmez).
- En uygun `T` değeri **target-dependent**'dır; worker çoğu “kolay” coverage'ı bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Hard-To-Harness Target'lar İçin Snapshot Fuzzing

Test etmek istediğiniz kod yalnızca **yüksek bir kurulum maliyetinden** sonra erişilebilir hâle geliyorsa (VM başlatma, login'i tamamlama, bir packet alma, bir container parse etme veya bir service'i initialize etme), kullanışlı bir alternatif **snapshot fuzzing**'dir: hazır process veya VM state'ini yakalayın, her test case'i target input path'e enjekte edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem initialization veya protocol prefix'lerini tekrarlama ihtiyacını ortadan kaldırır ve **network services**, **firmware**, **post-auth attack surfaces** ve **binary-only targets** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici state hazır olana kadar target'ı çalıştırın.
2. Bu noktada **memory + registers** snapshot'ını alın.
3. Her test case için mutated input'ı doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM target'larında destekleniyorsa yalnızca **dirty pages**'i geri yükleyin, ardından tekrarlayın.

Snapshot'ı, ilk pahalı parse/dispatch adımına pratik olarak mümkün olduğunca yakın bir yere yerleştirin; örneğin bir `recv`/`read` veya packet-deserialization noktasından sonra. Ayrıca target tarafından kullanılan input buffer'ını kaydedin. Bu yaklaşım, tekrarlanan işi önlemek için snapshot'ı input processing'in daha derinlerine taşıyan adaptive-placement ilkesini izler.<sup>[[11]](#references)</sup>

## Harness Introspection: Shallow Fuzzer'ları Erken Bulma

Bir campaign durduğunda sorun genellikle mutator değil, **harness**'tır. Fuzz target'ınızdan statik olarak erişilebilir olan ancak dinamik olarak nadiren veya hiç coverage almayan function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness target'a çok geç veya çok erken giriyor.
- Seed corpus'ta bütün bir feature family eksik.
- Target'ın tek ve aşırı büyük bir “do everything” harness yerine gerçekten **ikinci bir harness**'a ihtiyacı var.

OSS-Fuzz / ClusterFuzz tarzı workflow'lar kullanıyorsanız Fuzz Introspector, static reachability ile runtime coverage'ı karşılaştırabilir ve zaman sınırlı bir run'dan veya public corpus'tan report'lar oluşturabilir.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu kullanarak test edilmemiş bir parser yolculuğu için yeni bir harness ekleyip eklememeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük entry point'lere bölmeye karar verin.

## Grafik Öncelikli Fuzz Target Seçimi ve Mutation Triage

Elinizde zaten **static-analysis bulguları**, **mutation-testing survivor'ları** ve **coverage raporları** varsa bunları bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve harici bulgularla açıklamalı hâle getirin, ardından grafikle ilgili sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklığa sahip fonksiyonlara untrusted input üzerinden erişilebiliyor?
- Hangi mutation survivor'ları parser/handler'ların security-critical code'a giden yollarında bulunuyor?
- Hangi fonksiyonlar olağandışı derecede yüksek **blast radius**'a sahip architectural choke point'ler?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz target'lar ortaya çıkarır. **High complexity**'ye sahip ve doğrulanmış **external reachability** bulunan bir parser/decoder, coverage'ı zayıf ancak attacker-controlled path içermeyen izole bir internal helper'dan daha güçlü bir harness adayıdır.

### Practical triage workflow

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına complexity/branch metriklerini çıkarın.
2. Attacker-controlled input kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Bu entrypoint'lerden candidate function'lara **path query** çalıştırarak erişilebilir attack surface'i dead/internal-only code'dan ayırın.
4. Şu özellikleri birleştiren düğümlere öncelik verin:
- yüksek **cyclomatic complexity**
- **untrusted input**'tan doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için, özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için odaklanmış harness'ler yazın.

### Mutation survivor'ları: equivalent ve actionable

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor'ı bir security gap olarak değerlendirmeden önce, şu soruları sormak için graph'ı kullanın:

- Mutasyona uğratılan fonksiyona attacker-controlled bir entrypoint'ten erişilebiliyor mu?
- Tüm call path'ler, mutasyona uğratılan check'ten daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm dead code, yalnızca formatting yapan logic veya yüksek etkili arithmetic/parser path'i içinde mi bulunuyor?

Erişilemez veya yapısal olarak kısıtlanmış survivor'lar çoğu zaman **equivalent mutant**'lardır. **Reachable** kalan ve **boundary condition**'lara, **overflow/carry path**'lerine veya **security-critical arithmetic/parsing** işlemlerine dokunan survivor'lar şu öğelere dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant test'leri
- hedefli edge-case vector'leri

### Harici bulguları graph üzerine ilişkilendirme

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **file + line range** üzerinden graph düğümleriyle eşleştirin ve etkiyi genişletmek için graph'ı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius**'ını hesaplayın
- bulgunun bir entrypoint'ten başlayan herhangi bir path üzerinde olup olmadığını kontrol edin
- aynı choke point'te birleşen yakındaki bulguları cluster'layın

Bu yaklaşım, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken faydalıdır: **reachable**, **complex** olan ve zaten **SAST hit**'leri bulunan bir düğüm, attacker path'i olmayan yalnızca complex bir düğümden çoğu zaman daha iyi bir hedeftir.

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
Önemli metodoloji kesişimdir: **complexity x exposure x impact**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve invariant'ları zorlaması gerektiğine karar vermek için mutation survivor'larını kullanın.<sup>[[5]](#references)</sup>

## gosentry ile Go Fuzzing: Daha Güçlü Engine, Typed Inputs ve Differential Checks

Bir Go hedefinde zaten native bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan, ancak backend'i **LibAFL** ile değiştiren fork'lanmış bir Go toolchain'idir.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Bu, native Go fuzzer **hard comparisons**, **typed inputs** veya **parser-heavy formats** üzerinde takıldığında kullanışlıdır. Methodology aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan campaign'i normal coverage-guided run olarak değerlendirin; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanıldığını unutmayın.

### Sessiz hataları fuzz bulgularına dönüştürme

Go assessment'larında tekrarlanan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak crash oluşturmamasıdır. gosentry ile çeşitli “kötü ama sessiz” durumları finding'e dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçilen logging/error path'lerini crash gibi davranacak şekilde değiştirir. Bu, aksi hâlde yalnızca log'layıp devam eden `log.Fatal` tarzı code path'leri için kullanışlıdır.
- `--catch-races=true`, yeni keşfedilen queue entry'lerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni queue entry'lerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang handling, **infinite loops / very slow inputs** durumlarını timeout olarak kaybolmalarına izin vermek yerine fuzz finding olarak korur.
- Varsayılan olarak yerleşik arithmetic overflow check'leri ve go-panikint-style instrumentation aracılığıyla isteğe bağlı truncation check'leri.

Bu özellikle güvenlik etkisinin memory corruption yerine **panicless parser failure**, **concurrency bug** veya yalnızca **DoS-only hang** olduğu target'lar için değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing temel olarak `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen code typed object'ler tüketiyorsa gosentry, alttaki byte'ları mutasyona uğratmaya devam ederken **composite value**'ları (struct'lar, slice'lar, array'ler, pointer'lar) doğrudan fuzz'layabilir.<sup>[[7]](#references)[[8]](#references)</sup>
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
Bunu, yalnızca fuzzing için sahte bir wire format oluştururken kullanmak, harness'e özgü parsing kodunun arkasında logic bug'larını gizleyebilir. Differential veya grammar-based campaign'ler için harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde parse edin.

### Parser'lar ve protocol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve input language'leri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule'larının bir JSON array'idir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Metodoloji notları:

- Byte-level mutation'lar çoğunlukla erken syntax kontrollerinde başarısız oluyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tamamını modellemek yerine **security açısından önemli alt kümeye** odaklı tutun.
- Integer, length ve state machine sınırlarını zorlamak için terminal'lerde/nonterminal'lerde büyük boundary değerleri kullanın.
- Grammar mode input'ları grammar açısından geçerli tutar, ancak hedef yine de **byte/string** alır; bu nedenle parsing ve semantic kontrolleri harness edilen kodun içinde kalır.

### Differential fuzzing: yalnızca crash'leri değil, implementasyonları karşılaştırın

Go ekosistemlerinde güçlü bir yöntem **grammar-based differential fuzzing**'dir: geçerli yapılandırılmış input'lar üretin ve bunları iki parser'a, client'a veya state-transition engine'ine gönderin.<sup>[[7]](#references)[[8]](#references)</sup>
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

- bir implementation panic verirken diğeri temiz şekilde reddediyor
- kabul edilen/reddedilen input uyuşmazlıkları
- farklı parse tree'leri veya decoded object'ler
- birbirinden farklı state transition'ları, nonce'lar, balance'lar veya state root'ları

Bu, yalnızca crash fuzzing'in çoğunlukla gözden kaçırdığı **consensus mismatches**, **parser ambiguity** ve **spec-vs-implementation drift** durumlarını bulmanın pratik bir yoludur.

### Coverage reporting için campaign corpus'u yeniden kullanma

Bir campaign sonrasında, ayrı bir corpus'u manuel olarak export etmeden Go coverage report oluşturmak için kaydedilen queue corpus'u yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Komutu **aynı package** içinden ve **aynı `-fuzz` target** ile çalıştırın; böylece gosentry doğru cached campaign state'i çözer.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu graflara dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısından yoksundu. Düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar kullanan Stateful Network Protocols için hızlı bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar Yok, Sorun Yok: System-Call Açıklamaları Olmadan Linux Kernel Fuzzing'ine Doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive ve Mutable Snapshot'lar ile verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
