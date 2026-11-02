# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage ve Semantik

**Mutational grammar fuzzing** sırasında girdiler, **gramer açısından geçerli** kalacak şekilde mutasyona uğratılır. Coverage-guided modda, yalnızca **yeni coverage** tetikleyen örnekler corpus seed'leri olarak kaydedilir. **Dil hedeflerinde** (parser'lar, interpreter'lar, engine'ler) bu yaklaşım, bir yapının çıktısının başka bir yapının girdisi hâline geldiği **semantik/dataflow zincirleri** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Hata biçimi:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) işlevlerini ayrı ayrı çalıştıran seed'ler bulur, ancak **zincirlenmiş dataflow'u koruyamaz**. Bu nedenle, coverage'ı artırmadığı için bug'a daha çok yaklaşan örnek elenir. **3 veya daha fazla bağımlı adımda**, rastgele yeniden birleştirme maliyetli hâle gelir ve coverage feedback aramayı yönlendiremez.<sup>[[1]](#references)</sup>

**Çıkarım:** bağımlılık yoğun gramerlerde, **mutational ve generative aşamaları hibritleştirmeyi** veya üretimi yalnızca coverage'a değil, **function chaining** kalıplarına da yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliği Tuzakları

Coverage-guided mutation **açgözlüdür**: yeni coverage sağlayan örnek hemen kaydedilir ve genellikle büyük, değişmeden kalmış bölgeleri korur. Zamanla corpus'lar, yapısal çeşitliliği düşük **neredeyse kopyalardan** oluşur. Aşırı minimization yararlı bağlamı ortadan kaldırabilir. Bu nedenle pratik bir uzlaşma, **minimum token eşiğine ulaşıldığında duran** grammar-aware minimization'dır (gürültüyü azaltırken mutasyona elverişli kalması için yeterli çevre yapıyı korur).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı: çok sayıda neredeyse kopya yerine, **coverage'ı en üst düzeye çıkaran az sayıda yapısal olarak farklı seed'i** tercih edin. Uygulamada bu genellikle şu adımları içerir.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (public corpus'lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Geçerli her örneği tutmak yerine **coverage-based corpus minimization** ile örnekleri damıtın.
- Mutasyonların çoğu döngüyü ilgisiz baytlarla geçirmek yerine anlamlı alanlara denk gelmesi için seed'leri **yeterince küçük** tutun.
- Önemli harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Value'lar İçin Comparison-Aware Mutation

Fuzzer'ların ilerlemesinin durmasının yaygın nedenlerinden biri syntax değil, **katı karşılaştırmalardır**: magic byte'lar, uzunluk kontrolleri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da art arda yapılan karşılaştırmalarla korunan parser dispatch değerleri. Tamamen rastgele mutation, bu değerleri bayt bayt tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedefler için **comparison tracing** kullanın (örneğin, AFL++ `CMPLOG` / Redqueen tarzı workflow'lar). Böylece fuzzer, başarısız karşılaştırmalardaki operand'ları gözlemleyebilir ve mutasyonları bu karşılaştırmaları geçecek değerlere yönlendirebilir.<sup>[[3]](#references)</sup>

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

- Bu yöntem, hedef derin mantığı **file signatures**, **protocol verbs**, **type tags** veya sürüme bağlı feature bit’lerinin arkasında tuttuğunda özellikle kullanışlıdır.
- Gerçek örneklerden, protokol spesifikasyonlarından veya debug log’larından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token’ları, chunk adları, fiiller ve ayraçlar içeren küçük bir dictionary, çoğu zaman devasa ve genel amaçlı bir wordlist’ten daha değerlidir.
- Hedef art arda birçok kontrol yapıyorsa, önce en baştaki “magic” karşılaştırmalarını çözün; ardından sonraki aşamaların zaten geçerli öneklerle başlaması için ortaya çıkan corpus’u yeniden minimize edin.

## Filename Dilini Gizleyen File API’lerini Fuzzing

`filename`, `path` veya `URL` adlı bir parametre, doğrudan dosya arama noktası değil, bir interpreter giriş noktası olabilir. Örneğin, CFITSIO Extended Filename Syntax (EFS), açılan nesneyi döndürmeden önce köşeli parantez içindeki seçicileri, satır/piksel ifadelerini, hesaplanan sütunları, histogramları ve dönüşümleri değerlendirir; bazı biçimler geçici kopyalar da oluşturur. Attack-surface haritalaması sırasında her open/import API’sini **literal-path** veya **interpreted-path** olarak sınıflandırın, ardından uygulamaların gerçekten çağırdığı production giriş noktasını fuzzing’den geçirin.<sup>[[20]](#references)[[22]](#references)</sup>

Ortaya çıkan SSRF, dosya kopyalama ve protocol-handler primitive’leri ile daha güvenli literal-path API’leri için bkz. [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Backing object’i fuzzing’den geçirilen programdan ayrı tutun

Grammar bir filename suffix içinde bulunduğunda, yalnızca referans verilen dosya baytlarını değiştirmek parser’ı gözden kaçırır. Bunun yerine küçük bir harness, her testcase’i string olarak okuyup interpreted open API’sine aktarabilir; CFITSIO kampanyası, `fits_open_file()` işlevini salt okunur modda çağırarak EFS parser’larının ve evaluator’larının çoğuna ulaştı. Mutasyonların temel path’i sürekli bozmak yerine selector/expression diline odaklanabilmesi için geçerli backing file’ları ayrı tutun.<sup>[[22]](#references)</sup>

Her biri farklı bir grammar ailesine ulaşan seed’ler kullanın; ardından hem spesifikasyondan hem de lexer/parser kaynak kodundan kompakt bir dictionary oluşturun. Input’lar sürekli aynı syntax-error yolunda başarısız olurken coverage artışı durursa, yalnızca rastgele mutasyon süresini artırmak yerine geçerli önekleri koruyun ve ayraçlar, operatörler, anahtar sözcükler, function adları ve temsilî field adları ekleyin.<sup>[[22]](#references)</sup>

Harness’ı grammar dictionary ile çalıştırın; örneğin:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness yan etkilerini kontrol altına alma

Bir kütüphane için read-only flag kullanmak, testcase'in yan etki yaratmayacağını garanti etmez: dosya adı dili girdiyi yeniden yazabilir, çıktı dosyaları oluşturabilir veya geçici nesneleri belleğe alabilir. CFITSIO kampanyası başlangıçta seed dosyalarını yok etti ve dosya sisteminde beklenmedik dosyalar bıraktı; bu nedenle temizlik ve izolasyon gerekti.<sup>[[22]](#references)</sup>

- Her worker'a kullan-at bir çalışma dizini ve özel bir geçici dizin verin.
- Kanonik backing file'ların kopyalarını sunun; hedefin corpus'taki tek kopyayı değiştirmesine asla izin vermeyin.
- Remote backend'ler hedeflenmiyorsa ağ erişimini devre dışı bırakın ve yazılabilir yolları container, mount namespace veya eşdeğer bir sandbox ile kısıtlayın.
- Her çalıştırmadan veya worker grubundan sonra dizini sıfırlayın ve beklenmeyen dosya sistemi değişikliklerini ek bulgular olarak değerlendirin.

### Crash-to-patch-to-fuzz döngüsü

Onarım öncesinde crash'leri kümelendirin; böylece binlerce artifact, binlerce patch görevine dönüşmez. CFITSIO değerlendirmesinde AFLTriage, ilk crash kümesini birkaç kök nedene indirdi; ortaya çıkan danışma belgesi, hedef boyutunun yanlış denetlenmesi, `realloc()` sonrasında stale pointer'lar, aritmetik hatalar ve güvenli olmayan parser temizleme yolları gibi farklı hataları gösteriyor.<sup>[[21]](#references)[[22]](#references)</sup>

1. Her küme için temsili bir girdiyi küçültün ve AddressSanitizer ile yeniden üretin.
2. Hatanın oluştuğu kesin bellek erişimini, kaynak konumunu, ayırma/serbest bırakma geçmişini ve invariant'ı geçersiz kılan parser durumunu kaydedin.
3. Dar kapsamlı tek bir aday patch uygulayın ve aynı coverage ile sanitizer instrumentation'ı kullanarak yeniden derleyin.
4. Orijinal reproducer'ı **ve kümesindeki her girdiyi** yeniden çalıştırın; bir bellek güvenliği düzeltmesi hata yolundaki ownership'i bozabileceğinden leak detection'ı da etkinleştirin.
5. Gerçek dosyalarla functional test'leri çalıştırın, ardından birikmiş queue'dan devam edin (veya binary değiştikten sonra engine yeni bir çıktı dizini gerektiriyorsa bu queue'yu yeniden içe aktarın).
6. Tekrarlayın: İlk yüzeysel crash'i ortadan kaldırmak, mevcut seed'lerin daha derin bir parser durumuna ulaşmasını sağlayabilir.

LLM; crash'e neden olan girdiyi, sanitizer raporunu, harness'i ve ilgili kaynak kodunu aldığında 2. adımı hızlandırabilir ve 3. adım için taslak hazırlayabilir; ancak ürettiği patch'e güvenilmemelidir. Düzeltmenin kabul edilip edilmeyeceğine modelin açıklaması değil, sanitizer ile yeniden çalıştırma ve regresyon kontrolleri karar verir.<sup>[[22]](#references)</sup>

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper'dan farklı caller'lar üzerinden geçen veya bir fonksiyon içindeki farklı branch kombinasyonlarını izleyen iki çalıştırmayı ayırt edemez. Bu durum, **edge'e giden yolun** canlı durumu belirlediği paylaşılan decoder'larda, protocol dispatcher'larda ve interpreter helper'larında önemlidir. Her calling context'i gelişigüzel izlemek de tehlikelidir: coverage map ve queue kontrolden çıkabilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'ı context-sensitive ele almak yerine yalnızca umut vadeden context'leri ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

AFL++'ın güncel sürümleri, normal edge coverage'a ek olarak **fonksiyon başına Ball-Larus path coverage** sağlar. Her fonksiyon içindeki çevrimsiz path'lere bir feature atar; loop back-edge'ler kaldırıldığı için bu geri bildirim branch kombinasyonlarını ayırt eder, ancak **loop iterasyon sayılarını ayırt etmez**. Gevşek `1` seviyesinden başlayın; path sayısı üstel olarak artabileceğinden daha katı modları şüpheli parser/state-machine kodlarıyla sınırlayın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Birçok güvenlikle ilgili noktadan çağrılan bir yardımcı işlev için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** daha zengin feedback'i temkinli uygulayın ve coverage-map/queue maliyetini izleyin.<sup>[[13]](#references)[[14]](#references)</sup>

- Sıradan bir edge-coverage örneğini paralel çalıştırın; ek queue/map maliyeti saniyedeki execution sayısını düşürmüyorsa daha zengin feedback yararlıdır.
- Büyük, template ağırlıklı kütüphaneler veya genel amaçlı yardımcı kod map'e hâkim olduğunda path/caller instrumentation'ı kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda çevrimsiz path içeren fonksiyonlar AFL++ tarafından atlanabilir; derleme sırasında görülen uyarılar, hedefin allowlisting'e veya daha düşük bir seviyeye ihtiyaç duyduğuna işaret eder.
- Caller + path coverage yalnızca tek bir caller derinliğini destekler. Bunu daha derin context stack'leriyle birleştirmeyin.
- Path ID'leri LLVM major sürümleri arasında değişebilir. Campaign boyunca toolchain'i sabit tutun ve PATH tabanlı corpus'ları feature ID'leri derlemeler arasında sabitmiş gibi senkronize etmeyin.
- Bu feedback, `CMPLOG`'u tamamlar: comparison tracing **bir guard'dan hangi değerin geçtiğini** çözerken path/caller feedback **hangi rota ve branch kombinasyonunun oraya ulaştığını** korur.

## Stateful Fuzzing: Diziler Seed'dir

**Protokoller**, **kimlik doğrulanmış iş akışları** ve **çok aşamalı parser'lar** için ilgi çekici birim çoğu zaman tek bir blob değil, bir **mesaj dizisidir**. Tüm transcript'i tek bir dosyada birleştirip gelişigüzel mutate etmek genellikle verimsizdir; çünkü yalnızca sonraki mesaj kırılgan duruma ulaşsa bile fuzzer her adımı eşit şekilde mutate eder.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **dizinin kendisini seed** olarak ele almak ve ek feedback olarak **gözlemlenebilir durumu** (yanıt kodları, protokol durumları, parser aşamaları, döndürülen nesne türleri) kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli önek mesajlarını** sabit tutun ve mutasyonları **geçişi sağlayan** mesaja odaklayın.
- Sonraki adım önceki yanıtlara bağlıysa tanımlayıcıları ve sunucunun ürettiği değerleri önbelleğe alın.
- Serileştirilmiş transcript'in tamamını opak bir blob olarak mutate etmek yerine, mesaj başına mutasyon/splicing'i tercih edin.
- Protokol anlamlı yanıt kodları sunuyorsa, daha derine ilerleyen dizilere öncelik vermek için bunları **ucuz bir durum oracle'ı** olarak kullanın.

Kimlik doğrulamalı hataların, gizli geçişlerin veya “yalnızca handshake sonrasında” ortaya çıkan parser hatalarının vanilla dosya tarzı fuzzing ile sıkça gözden kaçmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sırayı, durumu ve bağımlılıkları** da korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: çok istemcili driver fuzzing

Yüksek edge coverage bile IPC driver hatalarını gözden kaçırabilir; çünkü coverage **nesne sahipliğini, referans sayılarını, bekleyen mesajları, temizleme sırasını veya thread interleaving'lerini** açıklamaz. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfasında driver nesne modeli ele alınır; bu örnek ise fuzzer harness'ine odaklanır. Android Binder yararlı bir modeldir: fuzzer birden çok sürecin aynı kernel nesnesi üzerinde gereken sırayla işlem yapmasını sağlayamıyorsa allocation ve free path'lerine ulaşmak yeterli olmaz.<sup>[[15]](#references)</sup>

#### Tekil `ioctl` buffer'ları yerine protokolü modelleyin

Bir test case'i **istemci kimliği + işlem + yapılandırılmış argümanlar** içeren sıralı bir grammar olarak temsil edin. Binder LKL fuzzer'ı, protobuf ve `libprotobuf-mutator` kullanır; bir kalıcı context-manager istemcisi ve iki sıradan istemci içerir. Ardından semantik bir harness, gelişigüzel byte mutasyonunun bozacağı ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki işlemlerden dönen değerleri önbelleğe alın. Örneğin `BC_FREE_BUFFER`, önceki bir `ioctl` tarafından döndürülen transaction-buffer pointer'ını yeniden kullanmalıdır.
- Senkron transaction'ların tamamlanabilmesi ve sonraki işlemlere ulaşılabilmesi için geçerli varsayılan yanıtlar üretin.
- Kendi kendine transaction veya aynı hedefe birden çok bekleyen transaction gibi imkânsız geçişleri reddedin.
- Tekil bootstrap durumunu input başına reset'in dışında tutun. Binder, her boot için yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; bu nedenle söz konusu istemciyi sürekli yok edip yeniden oluşturmak sonraki input'ları geçersiz kılar.

Yararlı bir lifetime-race şablonunda, bir istemciye nesne aktartın, thread veya process temizliğini başlatın ve alıcı istemciye transaction buffer'ını eşzamanlı olarak serbest bıraktırın. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` ile `BC_FREE_BUFFER` arasındaki yarış, çıkan thread'in temizleme yolu hâlâ kullanırken gömülü bir `binder_work` nesnesini serbest bırakabiliyordu.<sup>[[15]](#references)</sup>

#### Userspace kernel'de kontrollü interleaving'leri yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness'e bağlar ve syscall arayüzünü `lkl_syscall` üzerinden sunar. Böylece protobuf durumu, coverage ve KASAN tek bir process içinde kolayca koordine edilebilir. Ancak LKL, normalde bir syscall'ı başka bir kernel thread'i kesintiye uğratmadan çalıştırır. Race campaign'leri için seçili lock/unlock ve lifetime sınırlarına `schedule()` noktaları ekleyin, ardından her yield'de sıradaki istemciyi harness'in rastgele seçmesini sağlayın. Her nokta scheduling arama alanını katladığından, bu noktaları hedefli kullanın. Araştırmacıların tanımladığı rastgele scheduler, upstream Binder fuzzer'ının **parçası değildir**.<sup>[[15]](#references)</sup>

#### Serileştirilmiş regression seed'leri derleyip yeniden çalıştırın

Upstream harness, uyumlu bir `libprotobuf-mutator` sürümünü sabitler; `LKL_FUZZING=1` ile LKL fuzzing instrumentation'ını ve KASAN'ı etkinleştirir, ayrıca Binder için `MMU=1` ile `CONFIG_MMU`'yu açar.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Bilerek güvenlik açığı bulunan bir revizyonu kontrol ettikten veya upstream’de belgelenen geri alma yamalarını uyguladıktan sonra, serileştirilmiş bir seed, gelişigüzel bir C proof of concept’i yeniden oluşturmaya gerek kalmadan çok istemcili durum geçişinin tamamını yeniden üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free durumunu, seed'in güvenlik açığı bulunan yaşam süresi yoluna ulaştığının doğrulanması olarak değerlendirin. Bu, kernel kodu yürütme veya ayrıcalık yükseltme için gereken sonraki primitive'leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makinede Çeşitlilik Hilesi (Jackalope Tarzı)

**Üretken yeniliği** **coverage yeniden kullanımıyla** birleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı kısa ömürlü worker'ları **yeniden başlatmaktır**. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar senkronize olur ve ardından çıkar. Böylece biriken coverage'dan yararlanırken her nesilde **yeni yapılar** elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty`, her generation'da **yeni bir corpus** kullanılmasını sağlar.
- `-server_update_interval T`, **gecikmeli sync** yaklaşımını taklit eder (önce yenilik, sonra tekrar kullanım).
- Grammar fuzzing modunda **başlangıç server sync'i varsayılan olarak atlanır** (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T`, **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Harness Kurulumu Zor Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda yalnızca **yüksek kurulum maliyetinden sonra** (VM'i başlatma, login'i tamamlama, paket alma, container'ı parse etme, servisi başlatma) erişilebiliyorsa, kullanışlı bir alternatif **snapshot fuzzing**'dir: hazır process veya VM durumunu yakalayın, her test case'i hedef input yoluna enjekte edin, crash/timeout olana kadar çalıştırın ve snapshot'ı geri yükleyin. Böylece başlatma veya protokol prefix'lerini tekrarlamaktan kaçınılır; bu yöntem **network service'ler**, **firmware**, **post-auth attack surface'leri** ve **binary-only hedefler** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi duyulan durum hazır olana kadar hedefi çalıştırın.
2. O noktada **memory + register** snapshot'ı alın.
3. Her test case için mutated input'ı doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset olana kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde destekleniyorsa yalnızca **dirty page'leri** geri yükleyin ve ardından tekrarlayın.

Snapshot'ı, `recv`/`read` sonrasındaki veya packet-deserialization noktasındaki gibi, ilk maliyetli parse/dispatch adımına olabildiğince yakın bir yere koyun ve hedefin kullandığı input buffer'ı kaydedin. Böylece tekrarlanan işleri önlemek için snapshot'ı input işleme sürecinde daha ileriye taşıma yönündeki adaptive-placement ilkesi izlenir.<sup>[[11]](#references)</sup>

## MAccConc ile Linux Kernel Race Keşfi

[MAccConc](https://github.com/googleprojectzero/MAccConc), timing'e duyarlı Linux-kernel race'lerini tekrarlanabilir memory-access schedule'lerine dönüştürür. İki context'li **A-B-A** execution'ları otomatik olarak sıralayabilir veya analistin terminal UI/GUI üzerinden sıra kısıtları belirlemesine olanak tanır. Bu, tam bir concurrency fuzzer'ından ziyade deneysel bir araştırma aracıdır: şu anda LLVM 23+ ve projenin patched kernel'ini gerektirir, command-line araçları iki test thread'ini destekler ve önerilen userspace fuzzing katmanı henüz uygulanmamıştır.<sup>[[17]](#references)[[18]](#references)</sup>

### Context'ler arası iletişim noktalarını toplama

Instrumented kernel'i KASAN outline callback'leri ve patched KCOV memory-record desteğiyle build edin. Projenin README dosyası, call stack'lerin kullanılabilir kalması için sibling-call optimization'ı devre dışı bırakmayı da önerir.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`), enstrümante edilmiş erişimleri helper çağrılarına dönüştürür. MAccConc kernel yamaları, ardışık erişimlerin birleştirilmesini önlemek için `asan-opt-same-temp` seçeneğini devre dışı bırakır; global değişkenlere yönelik yarışların görünür olması gerektiğinde `asan-opt-globals` optimizasyonunu da devre dışı bırakın. KCOV, ortaya çıkan kayıtları userspace'e taşır. Farklı yürütme bağlamlarındaki erişimleri karşılaştırın ve bayt aralıkları çakışan, ayrıca taraflardan en az birinin yazma yaptığı çiftleri tutun; yaşam süresi geçişlerini de adaylara dahil etmek için `kfree()` işlemini yazma olarak modelleyin.<sup>[[17]](#references)</sup>

Başlatan görevden ayrılan işler, örneğin paket işleme veya RCU callback'leri için alt sistemin bir KCOV remote-coverage handle'ını aktarması gerekir. Upstream remote KCOV isteğe bağlıdır ve rastgele arka plan işleri için otomatik olarak kullanılamaz; bu nedenle aktarımın yapılmaması gerçek bir etkileşimi görünmez kılabilir.<sup>[[17]](#references)[[19]](#references)</sup>

### Her çalıştırmada aynı dinamik erişimi belirleme

Her ayırmadan sonra değişebilen somut bir heap adresini veya `memcpy()` ve `spin_lock()` gibi helper'ların içinde belirsiz olan yalnızca bir komut adresini kullanarak yeniden oynatmayın. MAccConc, **sayıyla zenginleştirilmiş bir stack trace** kullanır: her frame, bir callee'yi ve caller'ı içindeki çağrı sayısını tanımlar; son öğe ise bellek erişimi komutunu tanımlar. SanitizerCoverage function-entry/exit kayıtları, userspace'in bu dinamik tanımlayıcıyı yeniden oluşturmasını sağlar. Bu tanımlayıcı, adres değişikliklerine ve ilgisiz kontrol akışı gürültüsüne rağmen kararlı kalır.<sup>[[17]](#references)</sup>

### Aday çiftleri zorunlu çizelgelere dönüştürme

Yamalanmış `KCOV_SET_DI` ioctl'ı, sayı ile zenginleştirilmiş bir erişim tanımlayıcısını paylaşılan bir flag eylemiyle ilişkilendirir.<sup>[[17]](#references)</sup>

| Eylem | Anlamı |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Seçilen erişimden hemen önce *N* flag'ini ayarlar. |
| `DI_STACK_WAIT` | Seçilen erişimden önce, *N* flag'i ayarlanana veya yapılandırılmış sınır dolana kadar bekler. |
| `DI_STACK_WAKE_POST` | Seçilen erişimden hemen sonra *N* flag'ini ayarlar. |

Kısmi bir **A-happens-before-B** kısıtı için aynı flag'i kullanarak A'ya `DI_STACK_WAKE_POST`, B'ye `DI_STACK_WAIT` ekleyin. Tam olarak tanımlanmış iki bağlamlı bir çizelge için B'yi başlangıçta bloklanmış durumda başlatın; ardından A, ilk aktarım noktasında B'yi uyandırsın ve beklesin. B, sonraki aktarım noktasında bunun tersini yapsın. Bu yöntem deterministik bağlam değiştirme gibi çalışır ve otomatik A-B-A gezgininin kullandığı yöntemdir.<sup>[[17]](#references)</sup>

Asgari bir kampanya için dört hook'lu test senaryosunu (`test_setup`, iki thread fonksiyonu ve `test_end`) paylaşılan bir kütüphane olarak derleyin, kısıtlanmamış bir iz toplayın, ardından A-B-A adaylarını sıralayın veya şüpheli erişimlerin çevresine elle kısıtlar ekleyin.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeout'ları başarılı yeniden sıralamalardan ayrı değerlendirin: bir lock veya initialization/publication bağımlılığı, ikinci context'in injection point'ine ulaşmasını engelleyerek istenen sırayı imkânsız kılabilir. KASAN'ın kör noktalarını da göz önünde bulundurun: doğrudan stack erişimleri, out of bounds olma ihtimali yoksa genellikle hook'lanmaz; varsayılan optimizasyonla globals kapsam dışı kalır ve mevcut derleyiciler ASAN ile TSAN hook'larını aynı anda ekleyemez. Ayrıca guest panic yaptığında prototip KCOV buffer'ını kaybeder; bu yüzden bağımsız bir crash console/oracle bulundurun.<sup>[[17]](#references)</sup>

Gelecekteki concurrency-guided fuzzing için input veya syscall başına memory-access özetleri kaydedin, cross-context iletişim noktaları oluşturabilecek işlemleri eşleştirin ve ardından yalnızca bu kombinasyonları keşfedin. VM snapshot'ları global state'i ve adresleri sabitler; snapshot yoksa allocation-site metadata, nesneleri çalıştırmalar arasında soyutlayabilir. Bu, mevcut MAccConc userspace araçlarının bir özelliği değil, önerilen bir genişletmedir.<sup>[[17]](#references)</sup>

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign durakladığında, sorun çoğu zaman mutatörde değil, **harness**'tadır. Fuzz target'ınızdan statik olarak erişilebilen ancak dinamik olarak nadiren ya da hiç kapsanmayan fonksiyonları bulmak için **erişilebilirlik/kapsama introspection** kullanın. Bu fonksiyonlar genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness, target'a çok geç veya çok erken giriyor.
- Seed corpus'ta bir özellik ailesinin tamamı eksik.
- Target'ın gerçekten tek ve aşırı büyük bir “her şeyi yapan” harness yerine **ikinci bir harness**'a ihtiyacı var.

OSS-Fuzz / ClusterFuzz tarzı workflow'lar kullanıyorsanız Fuzz Introspector, statik erişilebilirliği çalışma zamanı kapsamıyla karşılaştırabilir ve süre sınırlı bir çalıştırmadan veya herkese açık corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak test edilmemiş bir parser yolu için yeni bir harness eklemeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük giriş noktalarına bölmeye karar verin.

## Önce Graph, Sonra Fuzz Target Seçimi Ve Mutation Triyajı

Elinizde **static-analysis bulguları**, **mutation-testing survivor'ları** ve **coverage raporları** varsa bunları birbirinden bağımsız listeler olarak triyaj etmeyin. Önce bir **call graph** oluşturun; ardından düğümlere **cyclomatic complexity**, **entrypoint/untrusted-input erişilebilirliği** ve harici bulguları ekleyip graph ile ilgili sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki fonksiyonlara untrusted input üzerinden erişilebilir?
- Hangi mutation survivor'ları, parser/handler'lardan güvenlik açısından kritik koda giden yollarda yer alıyor?
- Hangi fonksiyonlar, alışılmadık ölçüde büyük bir **blast radius**'a sahip mimari darboğazlar?

Bu yaklaşım genellikle yalnızca "en düşük coverage" ölçütüne göre daha iyi fuzz target'lar ortaya çıkarır. **Yüksek karmaşıklığa** ve doğrulanmış **harici erişilebilirliğe** sahip bir parser/decoder, zayıf coverage'a sahip ancak saldırgan denetimindeki bir yolda bulunmayan yalıtılmış bir dahili yardımcı fonksiyondan daha güçlü bir harness adayıdır.

### Pratik triyaj iş akışı

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına karmaşıklık/dal metriklerini çıkarın.
2. Saldırgan denetimindeki girdileri kabul eden **entrypoint**'leri belirleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'ları.
3. Erişilebilir saldırı yüzeyini yalnızca dahili/ölü koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara **path query**'leri çalıştırın.
4. Aşağıdakileri bir arada bulunduran düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - **untrusted input** kaynaklarından doğrulanmış **erişilebilirlik**
   - yüksek **blast radius** veya çok sayıda bağımlı öğe
   - **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için odaklı harness'ler yazın; özellikle hex/Base64/IP/message decoder'ları gibi **parser/codec**'lere öncelik verin.

### Mutation survivor'ları: eşdeğer mi, eyleme geçirilebilir mi?

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor'ı bir güvenlik açığı olarak değerlendirmeden önce graph'ı kullanarak şunları sorun:

- Mutasyona uğratılmış fonksiyona saldırgan denetimindeki bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılmış kontrolden daha güçlü invariant'larla sınırlandırılmış mı?
- Düğüm ölü kodda, yalnızca biçimlendirme mantığında mı, yoksa etkisi yüksek bir arithmetic/parser yolunda mı yer alıyor?

Erişilemez kalan veya yapısal olarak kısıtlanmış survivor'lar çoğu zaman **eşdeğer mutant**'lardır. **Erişilebilir** kalan ve **sınır koşullarını**, **overflow/carry yollarını** ya da güvenlik açısından kritik **arithmetic/parsing** işlemlerini etkileyen survivor'lar şunlara dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant testleri
- hedefli edge-case vektörleri

### Harici bulguları graph üzerinde ilişkilendirin

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **dosya + satır aralığı** üzerinden graph düğümlerine yansıtın ve etki alanını genişletmek için graph'ı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius**'unu hesaplayın
- bulgunun herhangi bir entrypoint'ten geçen yolda bulunup bulunmadığını kontrol edin
- aynı darboğazda birleşen yakın bulguları kümelendirin

Bu, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken işe yarar: **erişilebilir**, **karmaşık** ve zaten **SAST bulgularına** sahip bir düğüm, saldırgan yolu olmayan, yalnızca karmaşık bir düğümden genellikle daha iyi bir hedeftir.

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

Önemli metodoloji, şu üç unsurun kesişimidir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve değişmezleri zorlaması gerektiğine karar vermek için mutasyondan sağ çıkan girdilerden yararlanın.<sup>[[5]](#references)</sup>

## Kriptografik anahtar kodlamalarında differential fuzzing

Geçerli serileştirilmiş anahtarlarla veya standart test vektörleriyle başlayın. Import ve işlem yollarına ulaşmak için gereken uzunluk ve yapıyı bozmadan kodlanmış alanları mutasyona uğratın, ardından aynı baytları bağımsız implementasyonlara verin. Kabul durumlarını ve hataları karşılaştırın. Rastgeleleştirilmiş imzalar ve şifreli metinler için bayt bayta karşılaştırma değil, doğruluk oracle'ları gerekir: imzaları doğrulayın veya kapsülleme/açma tur işlemindeki ortak sırları karşılaştırın. Test vektörleri bilinen durumlar için standarda uygunluğu belirler; differential mutation ise bunların ötesindeki hatalı kodlamaları inceler.<sup>[[23]](#references)[[26]](#references)</sup>

Bu anahtar biçimleri için biçime özgü oracle'lar kullanın:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA genişletilmiş imzalama anahtarları:** Anahtarın parse edilebilir kalmasını sağlayarak paketlenmiş `s1` veya `s2` katsayılarını `[-η, η]` aralığının dışına çıkarın. Import veya imzalama işleminin bunları reddedip reddetmediğini ve ortaya çıkan imzaların doğrulanıp doğrulanmadığını kontrol edin. Yalnızca kabul farklılıkları standart ihlali sayılmaz; çünkü FIPS 204 ek özel anahtar kontrollerini zorunlu kılmaz. Bkz. [koşullu sızıntı mekanizması](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM anahtar çiftleri:** Gerekli kapsülleme anahtarı ve decapsulation girdisi kontrollerini, import edilen bir çift üzerinde yapılan isteğe bağlı pairwise-consistency check (PCT) kontrolünden ayrı değerlendirin. Açık anahtarıyla kapsülleme yapın, özel anahtarıyla decapsulation yapın ve ortak sırları karşılaştırın; bir uyuşmazlık, tek tek anahtarlar girdi kontrollerini geçse bile şifreli iletişimi bozabilir. API'nin girdileri işlem sırasında mı yoksa ayrı bir çağrıyla mı doğruladığını kontrol edin; libcrux, bir PCT'nin yerini tutmayan `validate_public_key(pk)` ve `validate_private_key(sk, ct)` işlevlerini sunar.
- **XMSS/XMSSMT ham anahtarları:** Yalnızca bellekteki anahtarlarla yapılan işlemleri değil, parametre kümeleri arasında serileştirilmiş **imzalama ve doğrulama** anahtarı gidiş-dönüşlerini de test edin. XMSS ve XMSSMT'nin birbirinden ayrı dört baytlık OID ad alanları vardır; bu nedenle önce XMSS'yi deneyen yalnızca OID kullanan bir parser, OID'si çakışan bir XMSSMT anahtarını yanlış sınıflandırıp import işlemini reddedebilir. Bildirilen RustCrypto parser'ı, imza sahteciliği değil, bir birlikte çalışabilirlik/kullanılabilirlik sorunu örneğidir.

## gosentry ile Go Fuzzing: Daha Güçlü Engine, Türlenmiş Girdiler ve Differential Kontroller

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` desteğini korurken arka ucu **LibAFL** olarak değiştiren, çatallanmış bir Go toolchain'dir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, yerel Go fuzzer'ı **zor karşılaştırmalarda**, **tipli girdilerde** veya **ayrıştırıcı ağırlıklı biçimlerde** takıldığında kullanışlıdır. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan kampanyayı normal bir coverage-guided çalışma olarak ele alın; ancak LibAFL scheduling/mutation ve daha iyi çevresel dedektörlerden yararlanın.

### Sessiz hataları fuzz bulgularına dönüştürme

Go değerlendirmelerinde sık karşılaşılan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile, “kötü ama sessiz” durumların birkaç sınıfını bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçilen logging/error yollarının crash gibi davranmasını sağlar (aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı kod yolları için kullanışlıdır).
- `--catch-races=true`, yeni keşfedilen kuyruk girdilerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni kuyruk girdilerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang işleme özelliği, **sonsuz döngüleri / çok yavaş girdileri** timeout olarak kaybolmalarına izin vermek yerine fuzz bulguları olarak tutar.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, özellikle güvenlik etkisinin memory corruption yerine **panic oluşturmayan bir parser hatası**, **concurrency bug'ı** veya **yalnızca DoS'a yol açan bir takılma** olduğu hedeflerde değerlidir.

### Tipli Go API'leri için struct-aware fuzzing

Yerel Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar değerler bekler. Test edilen kod tipli nesneler kullanıyorsa gosentry, temelindeki byte'ları mutasyona uğratmaya devam ederken **composite değerleri** (struct'lar, slice'lar, array'ler, pointer'lar) doğrudan fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu yalnızca fuzzing için sahte bir wire format oluştururken kullanın; aksi takdirde harness'e özel ayrıştırma kodu mantık hatalarını gizleyebilir. Differential veya grammar-based kampanyalarda harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde ayrıştırın.

### Parser'lar ve protokol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve girdi dilleri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule'lardan oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Byte-level mutasyonlar çoğunlukla erken sözdizimi denetimlerinde başarısız oluyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tüm belirtimini modellemek yerine, **güvenlikle ilgili alt kümesine** odaklı tutun.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminallerde/terminal olmayanlarda büyük sınır değerleri kullanın.
- Grammar mode girdileri grammar-valid tutar, ancak hedef yine de **byte/string** alır; dolayısıyla ayrıştırma ve anlamsal denetimler harness içindeki kodda kalır.

### Differential fuzzing: yalnızca çökmeleri değil, uygulamaları karşılaştırın

Go ekosistemleri için etkili bir yöntem **grammar-based differential fuzzing**'dir: geçerli yapılandırılmış girdiler üretin ve bunları iki ayrıştırıcıya, istemciye veya durum geçişi motoruna iletin.<sup>[[7]](#references)[[8]](#references)</sup>

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

- bir uygulama panic verirken diğeri girdiyi düzgün şekilde reddediyor
- kabul/ret uyuşmazlıkları
- farklı parse ağaçları veya decode edilmiş nesneler
- farklı durum geçişleri, nonce değerleri, bakiyeler veya state root değerleri

Bu, yalnızca crash fuzzing ile çoğunlukla gözden kaçan **konsensüs uyuşmazlıklarını**, **parser belirsizliğini** ve **spesifikasyon ile uygulama arasındaki sapmaları** bulmanın pratik bir yoludur.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage raporlaması için kampanya corpus’unu yeniden kullanın

Bir kampanyadan sonra ayrı bir corpus’u elle dışa aktarmadan Go coverage raporu oluşturmak için kaydedilen kuyruk corpus’unu yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Komutu, gosentry'nin doğru önbelleğe alınmış kampanya durumunu çözümlemesi için **aynı paketten** ve **aynı `-fuzz` hedefiyle** çalıştırın.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutasyonel grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing'e Derinlemesine Bakış](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet, Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu graflara dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısından yoksundu. Bunu düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'ları Kullanarak Durum Bilgili Network Protokollerini Fuzz Eden Hızlı Bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Dilbilgisi Yok, Sorun Yok: System-Call Açıklamaları Olmadan Linux Kernel'ı Fuzz Etmeye Doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Uyarlanabilir ve Değiştirilebilir Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Öngörülü Context-Sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build ve regression-seed belgeleri](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kontrollü Memory-Access Interleaving'leriyle Linux Kernel Race Condition'larını İnceleme](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Fuzzing için code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Genişletilmiş Dosya Adı Sözdizimi](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Güvenlik Duyurusu: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Genişletilmiş Dosya Adı Sözdizimini Fuzz Etme: 16 Bellek Güvenliği Açığı ve Codex Destekli Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Kriptografi için Differential Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Modül-Kafes Tabanlı Anahtar Kapsülleme Mekanizması Standardı](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID ayrıştırma hatası - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Kriptografi Uygulamalarının Durumu](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
