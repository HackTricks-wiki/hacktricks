# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing**'de girdiler, **grammar-valid** kalacak şekilde mutasyona uğratılır. Coverage-guided modda yalnızca **yeni coverage** oluşturan örnekler corpus seed'leri olarak saklanır. **Dil hedeflerinde** (parser'lar, interpreter'lar, engine'ler) bu yaklaşım, bir yapının çıktısının başka bir yapının girdisi olduğu **semantik/dataflow zincirleri** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Başarısızlık biçimi:** fuzzer, tek başlarına `document()` ve `generate-id()` (veya benzer primitive'leri) çalıştıran seed'ler bulur ancak **zincirlenmiş dataflow'u koruyamaz**; bu nedenle “bug'a daha yakın” örnek coverage'ı artırmadığı için elenir. **3 veya daha fazla bağımlı adımda**, rastgele yeniden birleştirme maliyetli hâle gelir ve coverage geri bildirimi aramaya yön vermez.<sup>[[1]](#references)</sup>

**Çıkarım:** bağımlılık ağırlıklı grammar'lar için **mutational ve generative aşamaları hibritleştirmeyi** veya üretimi (yalnızca coverage'a değil) **function chaining** kalıplarına göre ağırlıklandırmayı değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliği Tuzakları

Coverage-guided mutation **açgözlüdür**: yeni coverage sağlayan bir örnek hemen saklanır ve genellikle değiştirilmemiş büyük bölgeleri korur. Zamanla corpus'lar, yapısal çeşitliliği düşük, **neredeyse aynı örneklerle** dolar. Aşırı minimization yararlı bağlamı ortadan kaldırabilir; bu nedenle pratik bir uzlaşma, **minimum token eşiğine ulaşıldığında duran** ve böylece mutasyona elverişli kalacak kadar çevre yapıyı korurken gürültüyü azaltan **grammar-aware minimization** kullanmaktır.<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı: çok sayıda neredeyse aynı örnek yerine, coverage'ı en üst düzeye çıkaran, yapısal olarak farklı az sayıda seed'i **tercih edin**. Pratikte bu genellikle şunları gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (public corpus'lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Her geçerli örneği saklamak yerine **coverage-based corpus minimization** ile örnekleri damıtın.
- Mutasyonların çoğu döngüyü ilgisiz byte'lar üzerinde harcamak yerine anlamlı alanlara denk gelmesi için seed'leri **yeterince küçük** tutun.
- Harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Values için Comparison-Aware Mutation

Fuzzer'ların ilerlemesinin durmasının yaygın nedenlerinden biri syntax değil, **katı karşılaştırmalardır**: magic byte'lar, length check'ler, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da ardışık karşılaştırmalarla korunan parser dispatch değerleri. Tamamen rastgele mutasyon, bu değerleri byte byte tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedeflerde, fuzzer'ın başarısız karşılaştırmalardaki operand'ları gözlemlemesini ve mutasyonları bu karşılaştırmaları karşılayan değerlere yönlendirmesini sağlayan **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen tarzı iş akışları) kullanın.<sup>[[3]](#references)</sup>

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

- Bu, hedef derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasında tuttuğunda özellikle kullanışlıdır.
- Bunu gerçek örneklerden, protokol belirtimlerinden veya debug loglarından çıkarılan **dictionaries** ile eşleştirin. Grammar token'ları, chunk adları, verb'ler ve ayraçlardan oluşan küçük bir dictionary, genellikle devasa ve genel amaçlı bir wordlist'ten daha değerlidir.
- Hedef art arda birçok kontrol yapıyorsa önce en erken “magic” karşılaştırmalarını çözün, ardından sonraki aşamaların zaten geçerli prefix'lerle başlaması için elde edilen corpus'u yeniden minimize edin.

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper üzerinden farklı caller'larla ilerleyen veya bir function içindeki farklı branch kombinasyonlarını izleyen iki execution'ı ayırt edemez. Bu durum, bir edge'e giden **route**'un etkin state'i belirlediği paylaşımlı decoder'larda, protokol dispatcher'larında ve interpreter helper'larında önemlidir. Her calling context'i gelişigüzel izlemek de tehlikelidir: coverage map'i ve queue aşırı büyüyebilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'ı context-sensitive ele almak yerine yalnızca umut vadeden context'leri ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

Güncel AFL++ derlemeleri, normal edge coverage'a ek olarak **function başına Ball-Larus path coverage** sunar. Bir function içindeki her acyclic path'e bir feature atar; loop back-edge'ler kaldırılır, dolayısıyla bu geri bildirim branch kombinasyonlarını ayırt eder ancak **loop iteration sayılarını ayırt etmez**. Önce gevşek `1` seviyesini kullanın, ardından path sayısı üstel olarak artabileceğinden daha katı modları şüpheli parser/state-machine koduyla sınırlayın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Güvenlik açısından önemli birçok noktadan çağrılan bir yardımcı işlev için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

**Kampanya yönergeleri:** daha zengin feedback’i temkinli uygulayın ve coverage-map/queue maliyetini izleyin.<sup>[[13]](#references)[[14]](#references)</sup>

- Sıradan bir edge-coverage örneğini paralel çalıştırın; daha zengin feedback, yalnızca ek queue/map maliyeti saniyedeki execution sayısını düşürmüyorsa yararlıdır.
- Büyük, template ağırlıklı kütüphaneler veya genel amaçlı yardımcı kodlar map’i domine ediyorsa, path/caller instrumentation’ı sınırlandırmak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda acyclic path içeren işlevler AFL++ tarafından atlanabilir; derleme sırasındaki uyarılar, hedefin allowlisting’e veya daha düşük bir strictness seviyesine ihtiyaç duyduğunu gösterir.
- Caller + path coverage yalnızca tek bir caller depth seviyesini destekler. Bunu daha derin context stack’leriyle birleştirmeyin.
- Path ID’leri LLVM major sürümleri arasında değişebilir. Bir kampanya boyunca toolchain’i sabit tutun ve PATH tabanlı corpus’ları, feature ID’leri derlemeler arasında sabitmiş gibi senkronize etmeyin.
- Bu feedback, `CMPLOG`’u tamamlar: comparison tracing, **bir guard’dan hangi değerin geçtiğini** çözerken path/caller feedback, **hangi rota ve branch kombinasyonunun buraya ulaştığını** korur.

## Stateful Fuzzing: Diziler Seed'dir

**Protokoller**, **kimlik doğrulanmış iş akışları** ve **çok aşamalı parser’lar** için ilgi çekici birim genellikle tek bir blob değil, bir **mesaj dizisidir**. Tüm konuşma dökümünü tek bir dosyada birleştirip gelişigüzel mutate etmek genellikle verimsizdir; çünkü fuzzer her adımı eşit şekilde mutate eder, oysa kırılgan duruma yalnızca sonraki mesaj ulaşıyor olabilir.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **dizinin kendisini seed** olarak ele almak ve ek feedback olarak **gözlemlenebilir durumu** (yanıt kodları, protokol durumları, parser aşamaları, döndürülen nesne türleri) kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli prefix mesajlarını** sabit tutun ve mutasyonları **geçişi tetikleyen** mesaja odaklayın.
- Sonraki adımın önceki yanıtlara bağlı olduğu durumlarda, önceki yanıtlardan gelen tanımlayıcıları ve sunucu tarafından üretilen değerleri cache’leyin.
- Serileştirilmiş konuşma dökümünün tamamını opak bir blob olarak mutate etmek yerine, mesaj başına mutasyon/splicing’i tercih edin.
- Protokol anlamlı yanıt kodları sunuyorsa, daha derine ilerleyen dizilere öncelik vermek için bunları **düşük maliyetli bir durum oracle’ı** olarak kullanın.

Kimlik doğrulama gerektiren bug’ların, gizli geçişlerin veya “yalnızca handshake sonrasında” ortaya çıkan parser bug’larının vanilla file-style fuzzing ile sıklıkla gözden kaçmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sırayı, durumu ve bağımlılıkları** da korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: çok istemcili driver fuzzing

Yüksek edge coverage bile IPC-driver bug’larını gözden kaçırabilir; çünkü coverage **nesne sahipliğini, referans sayılarını, bekleyen mesajları, cleanup sırasını veya thread interleaving’lerini** açıklamaz. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfasında driver nesne modeli ele alınır; bu örnek ise fuzzer harness’ına odaklanır. Android Binder kullanışlı bir modeldir: Fuzzer birden fazla sürecin aynı kernel nesnesi üzerinde gerekli sırayla işlem yapmasını sağlayamıyorsa, allocation ve free path’lerinin ikisine de ulaşmak yeterli değildir.<sup>[[15]](#references)</sup>

#### Tek başına `ioctl` buffer’ları yerine protokolü modelleyin

Bir test case’i **istemci kimliği + işlem + yapılandırılmış argümanlardan** oluşan sıralı bir grammar olarak temsil edin. Binder LKL fuzzer’ı protobuf ve `libprotobuf-mutator` kullanır; bir persistent context-manager istemcisi ve iki sıradan istemcisi vardır. Ardından semantic harness, kör byte mutasyonunun bozacağı ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki işlemlerden döndürülen değerleri cache’leyin. Örneğin, `BC_FREE_BUFFER` önceki bir `ioctl` tarafından döndürülen transaction-buffer pointer’ını yeniden kullanmalıdır.
- Synchronous transaction’ların tamamlanabilmesi ve sonraki işlemlere erişilebilmesi için geçerli varsayılan yanıtlar üretin.
- Self-transaction’lar veya aynı hedefe birden fazla bekleyen transaction gibi imkânsız geçişleri reddedin.
- Singleton bootstrap durumunu input başına yapılan reset’in dışında tutun. Binder, her boot için yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; dolayısıyla bu istemciyi tekrar tekrar silip yeniden oluşturmak sonraki input’ları geçersiz kılar.

Kullanışlı bir lifetime-race şablonunda, bir istemciye nesne aktartın, thread veya process cleanup işlemini başlatın ve alıcı istemcinin transaction buffer’ını eşzamanlı olarak serbest bırakmasını sağlayın. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` işleminin `BC_FREE_BUFFER` ile yarışması, çıkan thread’in cleanup path’i hâlâ kullanırken gömülü bir `binder_work` nesnesini serbest bırakabiliyordu.<sup>[[15]](#references)</sup>

#### Userspace kernel’de kontrollü interleaving’leri yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness’a bağlar ve syscall arayüzünü `lkl_syscall` üzerinden sunar. Böylece protobuf durumu, coverage ve KASAN tek bir process içinde kolayca eşgüdümlenebilir. Ancak LKL, normalde bir syscall çalışırken başka bir kernel thread’inin araya girmesine izin vermez. Race kampanyaları için seçili lock/unlock ve lifetime sınırlarının çevresine `schedule()` noktaları ekleyin, ardından her yield noktasında sıradaki istemciyi harness’ın rastgele seçmesini sağlayın. Her nokta scheduling arama alanını büyüttüğünden bu noktaları hedefli seçin. Araştırmacıların tanımladığı randomized scheduler, upstream Binder fuzzer’ın bir parçası **değildir**.<sup>[[15]](#references)</sup>

#### Serileştirilmiş regression seed’leri derleyip yeniden oynatın

Upstream harness, uyumlu bir `libprotobuf-mutator` sürümünü sabitler, `LKL_FUZZING=1` ile LKL fuzzing instrumentation’ı ve KASAN’ı etkinleştirir, ayrıca Binder için `MMU=1` ile `CONFIG_MMU`’yu etkinleştirir.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Upstream'de belgelenen bilerek savunmasız bir revizyonu kontrol ettikten veya rollback yamalarını uyguladıktan sonra, serileştirilmiş bir seed tüm çok istemcili durum geçişini, bunu gelişigüzel bir C proof of concept'inde yeniden oluşturmaya gerek kalmadan tekrar üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free, seed’in savunmasız yaşam süresi yoluna ulaştığının doğrulanması olarak değerlendirin. Bu, kernel code execution veya privilege escalation için gereken sonraki primitive’leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makinede Çeşitlilik Hilesi (Jackalope Tarzı)

**Generative novelty** ile **coverage reuse** yöntemlerini birleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı kısa ömürlü worker’ları yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar senkronize olur ve ardından çıkar. Böylece biriken coverage’dan yararlanırken her nesilde **yeni yapılar** elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` her üretimde **yeni bir corpus** kullanılmasını sağlar.
- `-server_update_interval T`, **gecikmeli senkronizasyonu** (önce yenilik, sonra yeniden kullanım) yaklaşık olarak sağlar.
- Grammar fuzzing modunda **başlangıç sunucu senkronizasyonu varsayılan olarak atlanır** (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T` **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Harness Edilmesi Zor Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda erişim ancak **yüksek kurulum maliyetinden sonra** mümkün oluyorsa (bir VM'yi başlatmak, oturumu tamamlamak, paket almak, container'ı parse etmek, bir servisi başlatmak), kullanışlı bir alternatif **snapshot fuzzing** yöntemidir: hazır durumdaki process veya VM'in anlık görüntüsünü alın, her test case'i hedefin girdi yoluna enjekte edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem başlatma işlemlerini veya protokol öneklerini tekrarlamayı önler; **network servisleri**, **firmware**, **kimlik doğrulaması sonrası attack surface'ler** ve **binary-only hedefler** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici durum hazır olana kadar hedefi çalıştırın.
2. Bu noktada **bellek + register** snapshot'ı alın.
3. Her test case için, mutate edilmiş girdiyi doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde destekleniyorsa yalnızca **değişmiş sayfaları** geri yükleyin ve ardından tekrarlayın.

Snapshot'ı mümkün olduğunca ilk maliyetli parse/dispatch adımına yakın bir noktaya yerleştirin; örneğin `recv`/`read` işleminden veya paket deserialization noktasından sonra. Hedefin kullandığı input buffer'ı da kaydedin. Bu, tekrarlanan işlemleri önlemek için snapshot'ı input işleme sürecinin daha ilerisine taşımayı öngören uyarlanabilir yerleştirme ilkesini izler.<sup>[[11]](#references)</sup>

## MAccConc ile Linux Kernel Race Keşfi

[MAccConc](https://github.com/googleprojectzero/MAccConc), zamanlamaya duyarlı Linux-kernel race durumlarını tekrarlanabilir bellek erişim çizelgelerine dönüştürür. İki context içeren **A-B-A** yürütmelerini otomatik olarak listeleyebilir veya analistin terminal UI/GUI üzerinden sıra kısıtlamaları belirlemesine olanak tanır. Bu, tam kapsamlı bir concurrency fuzzer'dan ziyade deneysel bir araştırma aracıdır: şu anda LLVM 23+ ve projenin yamalanmış kernel'ini gerektirir; komut satırı araçları iki test thread'ini destekler ve önerilen userspace fuzzing katmanı henüz uygulanmamıştır.<sup>[[17]](#references)[[18]](#references)</sup>

### Context'ler arası iletişim noktalarını toplayın

KASAN outline callback'leri ve yamalanmış KCOV bellek kaydı desteği etkinleştirilmiş instrumented kernel'i derleyin. Projenin README dosyası, call stack'lerin kullanılabilir durumda kalması için sibling-call optimization'ı devre dışı bırakmayı da önerir.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`), enstrümante edilmiş erişimleri yardımcı çağrılarına dönüştürür. MAccConc kernel yamaları, ardışık erişimlerin birleştirilmesini önlemek için `asan-opt-same-temp` özelliğini devre dışı bırakır; global değişken yarışlarının görünür olması gerekiyorsa `asan-opt-globals` optimizasyonunu da devre dışı bırakın. KCOV, ortaya çıkan kayıtları userspace'e taşır. Farklı yürütme bağlamlarındaki erişimleri karşılaştırın ve bayt aralıkları çakışan, ayrıca taraflardan en az birinin yazma yaptığı çiftleri tutun; yaşam süresi geçişlerini de adaylara dahil etmek için `kfree()` işlemini yazma olarak modelleyin.<sup>[[17]](#references)</sup>

Başlatan task'tan taşan işler için (ör. paket işleme veya RCU callback'leri), alt sistemin bir KCOV remote-coverage tanıtıcısını aktarması gerekir. Upstream remote KCOV isteğe bağlıdır ve keyfî arka plan işleri için otomatik olarak kullanılabilir değildir; dolayısıyla tanıtıcının aktarılmaması gerçek bir etkileşimi görünmez kılabilir.<sup>[[17]](#references)[[19]](#references)</sup>

### Her çalıştırmada aynı dinamik erişimi belirleme

Her ayırmadan sonra değişebilecek somut bir heap adresine göre veya `memcpy()` ve `spin_lock()` gibi yardımcıların içindeki adres belirsiz olduğundan yalnızca bir komut adresine göre yeniden oynatmayın. MAccConc, **sayı eklenmiş bir çağrı yığını izi** kullanır: her çerçeve bir callee'yi ve caller'ı içindeki çağrı sayısını tanımlar; son öğe ise bellek erişimi komutunu tanımlar. SanitizerCoverage işlev giriş/çıkış kayıtları, userspace'in bu dinamik tanımlayıcıyı yeniden oluşturmasını sağlar. Bu tanımlayıcı, adres değişikliklerine ve ilgisiz kontrol akışı gürültüsüne rağmen kararlı kalır.<sup>[[17]](#references)</sup>

### Aday çiftleri zorunlu zamanlamalara dönüştürme

Yamalanmış `KCOV_SET_DI` ioctl'i, sayıyla zenginleştirilmiş bir erişim tanımlayıcısını paylaşılan bayrak eylemiyle ilişkilendirir.<sup>[[17]](#references)</sup>

| Eylem | Anlamı |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Seçilen erişimden hemen önce *N* bayrağını ayarlar. |
| `DI_STACK_WAIT` | Seçilen erişimden önce, *N* bayrağı ayarlanana veya yapılandırılmış süre sınırı dolana kadar bekler. |
| `DI_STACK_WAKE_POST` | Seçilen erişimden hemen sonra *N* bayrağını ayarlar. |

Kısmi bir **A-happens-before-B** kısıtı için aynı bayrağı kullanarak A'ya `DI_STACK_WAKE_POST`, B'ye ise `DI_STACK_WAIT` ekleyin. İki bağlam için tamamen belirlenmiş bir zamanlamada B'yi beklemeye alın; ardından A, ilk aktarım noktasında B'yi uyandırıp beklesin. B de sonraki aktarım noktasında bunun tersini yapsın. Bu yöntem deterministik context switching gibi çalışır ve otomatik A-B-A gezgininin kullandığı yöntemdir.<sup>[[17]](#references)</sup>

En küçük kampanya; dört hook'lu test durumunu (`test_setup`, iki thread işlevi ve `test_end`) paylaşılan bir kütüphane olarak derleyip kısıtlanmamış bir iz toplamak, ardından A-B-A adaylarını sıralamak veya şüpheli erişimlerin çevresine elle kısıtlar eklemektir.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeout'ları başarılı yeniden sıralamalardan ayrı değerlendirin: istenen bir sıralama, bir kilit veya başlatma/yayımlama bağımlılığı ikinci bağlamın enjeksiyon noktasına ulaşmasını engellediği için imkânsız olabilir. Ayrıca KASAN'ın kör noktalarını göz önünde bulundurun: doğrudan stack erişimleri, sınırların dışında olma ihtimali yoksa genellikle hook'lanmaz; varsayılan optimizasyonla global değişkenler kapsam dışı kalır ve mevcut derleyiciler ASAN ile TSAN hook'larını aynı anda üretemez. Son olarak, prototip bir guest panic yaşadığında KCOV buffer'ını kaybeder; bu yüzden bağımsız bir crash console/oracle bulundurun.<sup>[[17]](#references)</sup>

Gelecekteki concurrency-guided fuzzing için girdi veya syscall başına bellek erişimi özetleri kaydedin, bağlamlar arası iletişim noktaları oluşturabilecek işlemleri eşleştirin ve ardından yalnızca bu birleşimleri keşfedin. VM snapshot'ları global durumu ve adresleri sabitler; snapshot olmadan allocation-site metadata, çalıştırmalar arasındaki nesneleri soyutlayabilir. Bu, mevcut MAccConc userspace araçlarının bir özelliği değil, önerilen bir genişletmedir.<sup>[[17]](#references)</sup>

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir kampanya durduğunda sorun genellikle mutator değil, **harness**'tır. Fuzz hedefinizden statik olarak erişilebilen ancak dinamik olarak nadiren ya da hiç kapsanmayan işlevleri bulmak için **erişilebilirlik/kapsama incelemesi** kullanın. Bu işlevler genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness hedefe çok geç veya çok erken giriyordur.
- Seed corpus'ta bir özellik ailesinin tamamı eksiktir.
- Hedef için, her şeyi yapan aşırı büyük tek bir harness yerine gerçekten **ikinci bir harness** gerekiyordur.

OSS-Fuzz / ClusterFuzz tarzı iş akışları kullanıyorsanız Fuzz Introspector, statik erişilebilirliği çalışma zamanı kapsamıyla karşılaştırabilir ve süre sınırlı bir çalıştırmadan veya herkese açık corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak test edilmemiş bir parser yolu için yeni bir harness eklemeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük entrypoint'lere bölmeye karar verin.

## Önce Graf Tabanlı Fuzz Hedefi Seçimi ve Mutation Triyajı

Elinizde **static-analysis bulguları**, **mutation-testing survivor'ları** ve **coverage raporları** varsa, bunları birbirinden bağımsız listeler olarak triyaj etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/güvenilmeyen girdiye erişilebilirlik** ve harici bulgularla etiketleyin, sonra grafla ilgili sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki fonksiyonlara güvenilmeyen girdilerden erişilebilir?
- Hangi mutation survivor'ları parser/handler'lardan güvenlik açısından kritik koda giden yollar üzerinde bulunuyor?
- Hangi fonksiyonlar olağan dışı yüksek **blast radius** değerine sahip mimari darboğazlar?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz hedefleri ortaya çıkarır. **Yüksek karmaşıklığa** ve doğrulanmış **harici erişilebilirliğe** sahip bir parser/decoder, coverage'ı düşük olsa da saldırgan denetiminde bir yolu bulunmayan yalıtılmış bir dahili yardımcı fonksiyondan daha iyi bir harness adayıdır.

### Pratik triyaj iş akışı

1. Codebase'den bir **code graph** oluşturun ve fonksiyon bazında karmaşıklık/dal metriklerini çıkarın.
2. Saldırgan denetimindeki girdileri kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/dosya okuyucuları.
3. Erişilebilir saldırı yüzeyini ölü veya yalnızca dahili koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara **path query** çalıştırın.
4. Aşağıdaki özellikleri bir arada taşıyan düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - güvenilmeyen girdilerden doğrulanmış **erişilebilirlik**
   - yüksek **blast radius** veya çok sayıda downstream bağımlı
   - **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için, özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için odaklı harness'ler yazın.

### Mutation survivor'ları: eşdeğer mi, işlem gerektiriyor mu?

Mutation testing genellikle gürültülü bir survivor listesi üretir. Her survivor'ı güvenlik açığı olarak değerlendirmeden önce, şu soruları sormak için grafı kullanın:

- Mutasyona uğratılan fonksiyona saldırgan denetimindeki bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılmış kontrolden daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm ölü kodda, yalnızca biçimlendirme mantığında mı, yoksa yüksek etkili bir aritmetik/parser yolunda mı bulunuyor?

Erişilemez kalan veya yapısal olarak kısıtlanmış survivor'lar genellikle **eşdeğer mutant**'lardır. **Erişilebilir** kalan ve **sınır koşullarına**, **overflow/carry yollarına** veya **güvenlik açısından kritik aritmetik/parsing** işlemlerine dokunan survivor'lar şu çalışmalara alınmalıdır:

- yeni fuzz harness'leri
- doğrudan property/invariant testleri
- hedeflenmiş uç durum vektörleri

### Harici bulguları graf üzerinde ilişkilendirin

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **dosya + satır aralığı** ile graf düğümlerine yansıtın ve etkiyi genişletmek için grafı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius** değerini hesaplayın
- bulgunun herhangi bir entrypoint'ten başlayan bir yol üzerinde olup olmadığını kontrol edin
- aynı darboğazda birleşen yakın bulguları kümelendirin

Bu, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken işe yarar: **erişilebilir**, **karmaşık** ve halihazırda **SAST bulguları** olan bir düğüm, saldırgan yolu bulunmayan yalnızca karmaşık bir düğümden genellikle daha iyi bir hedeftir.

Trailmark ile örnek iş akışı.<sup>[[6]](#references)</sup>

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

Önemli olan metodolojilerin kesişimidir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın, ardından harness'inizin hangi sınırları ve değişmezleri zorlaması gerektiğine karar vermek için mutasyonlardan sağ kalanları kullanın.<sup>[[5]](#references)</sup>

## Go Fuzzing'i gosentry ile: Daha Güçlü Motor, Tipli Girdiler ve Diferansiyel Kontroller

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, uygulanabilir bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan ancak backend'i **LibAFL** ile değiştiren, çatallanmış bir Go araç zinciridir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, native Go fuzzer **zor karşılaştırmalarda**, **typed girdilerde** veya **parser ağırlıklı biçimlerde** takıldığında işe yarar. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan kampanyayı normal bir coverage-guided çalışma olarak ele alın; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanılır.

### Sessiz hataları fuzz bulgularına dönüştürün

Go değerlendirmelerinde sık karşılaşılan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash'e neden olmamasıdır**. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçili logging/error yollarının crash gibi davranmasını sağlar (aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı kod yollarında kullanışlıdır).
- `--catch-races=true`, yeni keşfedilen queue girdilerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni queue girdilerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang işleme özelliği, **sonsuz döngüleri / çok yavaş girdileri** timeout olarak kaybolmalarına izin vermek yerine fuzz bulgusu olarak tutar.
- Varsayılan olarak yerleşik aritmetik taşma kontrolleri; ayrıca go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, güvenlik etkisinin bellek bozulması yerine **panic oluşmayan bir parser hatası**, **concurrency bug'ı** veya yalnızca DoS'a yol açan bir **hang** olduğu hedeflerde özellikle değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing temel olarak `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen kod typed nesneler tüketiyorsa gosentry, alttaki byte'ları mutate etmeye devam ederken doğrudan **composite değerleri** (struct'lar, slice'lar, array'ler, pointer'lar) fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu, yalnızca fuzzing için sahte bir wire formatı oluşturmanın mantık hatalarını yalnızca harness'te bulunan ayrıştırma kodunun arkasında gizleyeceği durumlarda kullanın. Differential veya grammar-based kampanyalarda, harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde ayrıştırın.

### Ayrıştırıcılar ve protokol girdileri için grammar-based fuzzing

Ayrıştırıcılar, biçimler ve girdi dilleri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, üretim kurallarından oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Bayt düzeyindeki mutasyonlar çoğunlukla erken sözdizimi kontrollerinde başarısız oluyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tüm belirtimini modellemek yerine **güvenlikle ilgili alt kümesine** odaklayın.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminallerde/nonterminallerde büyük sınır değerleri kullanın.
- Grammar mode girdileri dilbilgisi açısından geçerli tutar, ancak hedef yine de **baytlar/dizeler** alır; dolayısıyla ayrıştırma ve anlamsal kontroller harness'e alınan kodun içinde kalır.

### Differential fuzzing: yalnızca çökmeleri değil, implementasyonları karşılaştırın

Go ekosistemlerinde güçlü bir yaklaşım **grammar-based differential fuzzing** uygulamaktır: geçerli, yapılandırılmış girdiler üretip bunları iki ayrıştırıcıya, istemciye veya durum geçişi motoruna vermek.<sup>[[7]](#references)[[8]](#references)</sup>

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

Aşağıdakileri bulgu olarak değerlendirin:

- Bir uygulama panic verirken diğeri düzgün şekilde reddediyor
- Kabul/ret edilen girdiler uyuşmuyor
- Ayrıştırma ağaçları veya çözümlenen nesneler farklı
- Durum geçişleri, nonce'lar, bakiyeler veya durum kökleri farklılaşıyor

Bu, saf crash fuzzing'in çoğu zaman gözden kaçırdığı **consensus mismatch**, **parser ambiguity** ve **spec-vs-implementation drift** sorunlarını bulmanın pratik bir yoludur.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage raporlaması için kampanya corpus'unu yeniden kullanın

Bir kampanyadan sonra, ayrı bir corpus'u elle dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus'unu yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Komutunu **aynı paketten** ve **aynı `-fuzz` hedefiyle** çalıştır; böylece gosentry doğru önbelleğe alınmış kampanya durumunu çözer.



## References

- [1] [Mutasyonel grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing'e Derinlemesine Bakış](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu grafiğe dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısı eksikti. Düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar Kullanarak Stateful Network Protocols için Hızlı Bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar Olmadan da Olur: System-Call Descriptions Olmadan Linux Kernel'ı Fuzzing'e Yönelik](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Uyarlanabilir ve Değiştirilebilir Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Öngörücü Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - derleme ve regression seed belgeleri](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kontrollü Memory-Access Interleavings ile Linux Kernel Race Conditions'ı İnceleme](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing için code coverage](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
