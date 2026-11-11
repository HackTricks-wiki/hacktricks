# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage ve Semantics

**Mutational grammar fuzzing** yönteminde input’lar **grammar’a uygun** kalacak şekilde mutate edilir. Coverage-guided modda, yalnızca **yeni coverage** sağlayan örnekler corpus seed’i olarak kaydedilir. **Dil hedeflerinde** (parser’lar, interpreter’lar, engine’ler) bu yöntem, bir yapının çıktısının başka bir yapının girdisi hâline geldiği **semantik/dataflow zincirleri** gerektiren bug’ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Hata biçimi:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive’ler) işlevlerini ayrı ayrı çalıştıran seed’ler bulur ancak **zincirlenmiş dataflow’u koruyamaz**. Böylece “bug’a daha yakın” örnek, coverage’ı artırmadığı için elenir. **3+ bağımlı adımda** rastgele yeniden birleştirme maliyetli hâle gelir ve coverage feedback aramaya yön vermez.<sup>[[1]](#references)</sup>

**Çıkarım:** bağımlılığı yüksek grammar’lar için **mutational ve generative aşamaları hibrit hâle getirmeyi** veya üretimi yalnızca coverage’a değil, **function chaining** kalıplarına da yöneltmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliğiyle İlgili Tuzaklar

Coverage-guided mutation **greedy** çalışır: yeni coverage sağlayan bir örnek, çoğu zaman değişmeden kalan büyük bölümleriyle birlikte hemen kaydedilir. Zamanla corpus’lar, yapısal çeşitliliği düşük **neredeyse yinelenen örneklerle** dolar. Aşırı minimization faydalı bağlamı silebilir. Bu nedenle pratik bir çözüm, **grammar-aware minimization** uygulayıp **minimum token eşiğine ulaşıldığında durmaktır** (gürültüyü azaltırken mutate etmeye elverişli olacak kadar çevre yapısını korumak).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik corpus kuralı: çok sayıda neredeyse yinelenen örnek yerine, **coverage’ı en üst düzeye çıkaran, yapısal açıdan farklı az sayıda seed’i tercih edin**. Uygulamada bu genellikle şunları ifade eder.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (public corpus’lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Geçerli her örneği saklamak yerine **coverage-based corpus minimization** ile örnekleri damıtın.
- Mutasyonların çoğu döngüyü ilgisiz byte’larda harcamaması ve anlamlı alanlara denk gelmesi için seed’leri **yeterince küçük tutun**.
- Harness veya instrumentation’da önemli değişiklikler yaptıktan sonra corpus minimization’ı yeniden çalıştırın; çünkü reachability değişince “en iyi” corpus da değişir.

## Magic Values İçin Comparison-Aware Mutation

Fuzzer’ların ilerlemesinin durmasının yaygın bir nedeni syntax değil, **katı karşılaştırmalardır**: magic byte’lar, uzunluk kontrolleri, enum string’leri, checksum’lar veya `memcmp`, switch table’ları ya da art arda yapılan karşılaştırmalarla korunan parser dispatch değerleri. Tamamen rastgele mutation, bu değerleri byte byte tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedeflerde, fuzzer’ın başarısız karşılaştırmaların operand’larını gözlemleyebilmesi ve mutation’ları bu karşılaştırmaları geçecek değerlere yönlendirebilmesi için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen tarzı workflow’lar) kullanın.<sup>[[3]](#references)</sup>

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

- Bu, hedef derin mantığı **dosya imzalarının**, **protokol fiillerinin**, **tür etiketlerinin** veya **sürüme bağlı özellik bitlerinin** arkasında tuttuğunda özellikle kullanışlıdır.
- Bunu gerçek örneklerden, protokol spesifikasyonlarından veya debug günlüklerinden çıkarılan **sözlüklerle** birlikte kullanın. Dilbilgisi belirteçleri, parça adları, fiiller ve ayraçlar içeren küçük bir sözlük, çoğu zaman devasa ve genel bir kelime listesinden daha değerlidir.
- Hedef art arda birçok kontrol yapıyorsa, önce en baştaki “magic” karşılaştırmalarını çözün; ardından sonraki aşamaların zaten geçerli öneklerle başlaması için elde edilen corpus'u yeniden küçültün.

## Dosya Adı Dili Gizleyen Dosya API'lerini Fuzzing

`filename`, `path` veya `URL` adlı bir parametre, doğrudan dosya araması yapmak yerine yorumlayıcı için bir giriş noktası olabilir. Örneğin CFITSIO Extended Filename Syntax (EFS), açılan nesneyi döndürmeden önce köşeli parantez içindeki seçicileri, satır/piksel ifadelerini, hesaplanmış sütunları, histogramları ve dönüşümleri değerlendirir; bazı biçimler ayrıca geçici kopyalar oluşturur. Saldırı yüzeyini haritalarken her açma/içe aktarma API'sini **literal-path** veya **interpreted-path** olarak sınıflandırın, ardından uygulamaların gerçekten çağırdığı üretim giriş noktasını fuzzing işlemine tabi tutun.<sup>[[20]](#references)[[22]](#references)</sup>

Ortaya çıkan SSRF, dosya kopyalama ve protokol işleyicisi primitive'leri ile daha güvenli literal-path API'leri için bkz. [SSRF/dosya primitive'leri olarak dosya adı mini dilleri](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Destek nesnesini fuzzing yapılan programdan ayrı tutun

Dilbilgisi dosya adı sonekinde bulunuyorsa, yalnızca başvurulan dosyanın baytlarını değiştirmek parser'ı gözden kaçırır. Bunun yerine küçük bir harness, her testcase'i bir dize olarak okuyup yorumlanan açma API'sine aktarabilir; CFITSIO kampanyası salt okunur modda `fits_open_file()` çağırarak EFS parser'larının ve değerlendiricilerinin çoğuna ulaştı. Mutasyonların temel yolu sürekli bozmak yerine seçici/ifade diline odaklanabilmesi için geçerli destek dosyalarını ayrı olarak hazır bulundurun.<sup>[[22]](#references)</sup>

Her biri farklı bir dilbilgisi ailesine ulaşan seed'ler kullanın; ardından hem spesifikasyondan hem de lexer/parser kaynak kodundan derli toplu bir sözlük oluşturun. Girdiler tekrar tekrar aynı söz dizimi hatası yolunda başarısız olurken coverage artışı duraklıyorsa, yalnızca rastgele mutasyon süresini artırmak yerine geçerli önekleri koruyun ve ayraçlar, operatörler, anahtar sözcükler, işlev adları ve örnek alan adları ekleyin.<sup>[[22]](#references)</sup>

Harness'ı, örneğin dilbilgisi sözlüğüyle çalıştırın:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness yan etkilerini sınırlama

Bir kütüphanenin read-only flag'i, testcase'in yan etkisiz olacağını garanti etmez: filename dili girdiyi yeniden yazabilir, output files oluşturabilir veya geçici nesneleri belleğe alabilir. CFITSIO campaign'i başlangıçta seed files'ı yok etti ve dosya sistemi genelinde beklenmedik dosyalar bıraktı; bu nedenle cleanup ve izolasyon gerekti.<sup>[[22]](#references)</sup>

- Her worker'a kullan-at bir çalışma dizini ve özel bir geçici dizin verin.
- Canonical backing files'ın kopyalarını sunun; target'ın corpus'taki tek kopyayı değiştirmesine asla izin vermeyin.
- Remote backend'ler hedeflenmiyorsa network erişimini devre dışı bırakın ve yazılabilir yolları bir container, mount namespace veya eşdeğer bir sandbox ile sınırlandırın.
- Her execution veya worker batch'inden sonra dizini sıfırlayın ve beklenmeyen dosya sistemi değişikliklerini ek bulgular olarak değerlendirin.

### Crash-to-patch-to-fuzz döngüsü

Binlerce artifact'ın binlerce patch görevine dönüşmesini önlemek için düzeltme yapmadan önce crash'leri kümelendirin. CFITSIO değerlendirmesinde AFLTriage, ilk crash set'ini birkaç kök nedene indirdi; ortaya çıkan advisory'de hatalı destination-size kontrolleri, `realloc()` sonrasında stale pointer'lar, aritmetik hatalar ve güvensiz parser cleanup yolları dahil olmak üzere farklı arızalar gösteriliyor.<sup>[[21]](#references)[[22]](#references)</sup>

1. Her küme için temsili bir input'u küçültün ve AddressSanitizer altında yeniden üretin.
2. Invariant'ı geçersiz kılan tam erişimi, kaynak konumunu, allocation/free geçmişini ve parser state'ini kaydedin.
3. Tek ve dar kapsamlı bir aday patch uygulayın; aynı coverage ve sanitizer instrumentation ile yeniden build edin.
4. Orijinal reproducer'ı **ve kümesindeki her input'u** yeniden çalıştırın; bir memory-safety fix'i hata yolundaki sahipliği bozabileceğinden leak detection'ı da etkinleştirin.
5. Gerçek files ile functional test'leri çalıştırın, ardından birikmiş queue'dan devam edin (veya engine binary değiştikten sonra yeni bir output directory gerektiriyorsa bu queue'yu yeniden import edin).
6. Tekrarlayın: ilk yüzeysel crash'i ortadan kaldırmak, mevcut seed'lerin daha derin bir parser state'ine ilerlemesini sağlayabilir.

Bir LLM'ye çöken input, sanitizer raporu, harness ve ilgili kaynak verildiğinde 2. adımı hızlandırabilir ve 3. adım için taslak hazırlayabilir; ancak patch'ine güvenilmemelidir. Onarımın kabul edilip edilmeyeceğine modelin açıklaması değil, sanitizer ile yeniden çalıştırma ve regression kapıları karar verir.<sup>[[22]](#references)</sup>

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper'dan geçen iki execution'ı farklı caller'lar üzerinden geldiklerinde veya bir function içindeki farklı branch kombinasyonlarını izlediklerinde ayırt edemez. Bu durum, **route**'un canlı state'i belirlediği paylaşılan decoder'larda, protocol dispatcher'larda ve interpreter helper'larında önemlidir. Her calling context'i safça izlemek de tehlikelidir: coverage map ve queue aşırı büyüyebilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'ı context-sensitive kabul etmek yerine yalnızca umut vadeden context'leri ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

Güncel AFL++ build'leri normal edge coverage'a ek olarak **Ball-Larus per-function path coverage** sağlar. Bir function içindeki her acyclic path'e bir feature atar; loop back-edge'leri kaldırılır, bu nedenle bu feedback branch kombinasyonlarını ayırt eder ancak **loop iteration sayılarını ayırt etmez**. Önce gevşek seviye `1` ile başlayın, ardından path sayısı üstel olarak artabileceğinden daha katı modları şüpheli parser/state-machine koduyla sınırlandırın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Birçok güvenlik açısından önemli noktadan çağrılan bir yardımcı işlev için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

- Paralelde sıradan bir edge-coverage örneği çalıştırın; daha zengin feedback, yalnızca ek queue/map maliyeti saniyedeki execution sayısını düşürmüyorsa faydalıdır.
- Büyük, template ağırlıklı kütüphaneler veya genel amaçlı yardımcı kodlar map'e hâkimse, path/caller instrumentation'ı kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda acyclic path içeren işlevler AFL++ tarafından atlanabilir; derleme sırasındaki uyarılar, hedefin allowlisting'e veya daha az katı bir seviyeye ihtiyaç duyduğunun göstergesidir.
- Caller + path coverage yalnızca tek bir caller derinliğini destekler. Bunu daha derin context stack'leriyle birlikte kullanmayın.
- Path ID'leri LLVM'nin ana sürümleri arasında değişebilir. Bir campaign boyunca toolchain'i sabit tutun ve PATH tabanlı corpus'ları, feature ID'leri derlemeler arasında kararlıymış gibi senkronize etmeyin.
- Bu feedback, `CMPLOG`'u tamamlar: comparison tracing, bir guard'dan **hangi değerin geçtiğini** bulurken path/caller feedback, **hangi rota ve branch kombinasyonunun oraya ulaştığını** korur.

## Stateful Fuzzing: Diziler Seed'dir

**Protokoller**, **kimlik doğrulamalı iş akışları** ve **çok aşamalı parser'lar** için ilgi çekici birim çoğu zaman tek bir blob değil, bir **mesaj dizisidir**. Tüm transcript'i tek bir dosyada birleştirip gelişigüzel mutate etmek genellikle verimsizdir; çünkü fuzzer, yalnızca sonraki mesaj hassas duruma ulaşırken bile her adımı eşit şekilde mutate eder.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **dizinin kendisini seed** olarak ele almak ve ek feedback olarak **gözlemlenebilir durumu** (yanıt kodları, protokol durumları, parser aşamaları, döndürülen nesne türleri) kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli önek mesajları** sabit tutun ve mutasyonları **durum geçişini sağlayan** mesaja odaklayın.
- Sonraki adım önceki yanıtlara bağlıysa, önceki yanıtlardan gelen tanımlayıcıları ve sunucunun ürettiği değerleri önbelleğe alın.
- Serileştirilmiş transcript'in tamamını opak bir blob olarak mutate etmek yerine mesaj başına mutasyon/splicing yöntemini tercih edin.
- Protokol anlamlı yanıt kodları sunuyorsa, daha derine ilerleyen dizilere öncelik vermek için bunları **düşük maliyetli bir durum oracle'ı** olarak kullanın.

Kimlik doğrulamalı bug'ların, gizli geçişlerin veya “yalnızca handshake sonrasında” ortaya çıkan parser bug'larının vanilla file-style fuzzing ile sıkça gözden kaçmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sırayı, durumu ve bağımlılıkları** korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: çok istemcili driver fuzzing

Yüksek edge coverage, IPC-driver bug'larını yine de gözden kaçırabilir; çünkü coverage, **nesne sahipliğini, referans sayılarını, bekleyen mesajları, temizleme sırasını veya thread interleaving'lerini** göstermez. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfasında driver nesne modeli ele alınır; bu örnek ise fuzzer harness'ine odaklanır. Android Binder faydalı bir modeldir: fuzzer birden fazla sürecin aynı kernel nesnesi üzerinde gereken sırayla çalışmasını sağlayamıyorsa, allocation ve free path'lerine ulaşmak yeterli olmaz.<sup>[[15]](#references)</sup>

#### Yalıtılmış `ioctl` buffer'ları yerine protokolü modelleyin

Bir test case'i **istemci kimliği + işlem + yapılandırılmış argümanlardan** oluşan sıralı bir grammar olarak temsil edin. Binder LKL fuzzer'ı protobuf ve `libprotobuf-mutator` kullanır; bir persistent context-manager istemcisi ve iki sıradan istemci içerir. Ardından semantic harness, gelişigüzel byte mutasyonunun yok edeceği ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki işlemlerin döndürdüğü değerleri önbelleğe alın. Örneğin, `BC_FREE_BUFFER` önceki bir `ioctl` tarafından döndürülen transaction-buffer pointer'ını yeniden kullanmalıdır.
- Synchronous transaction'ların tamamlanıp sonraki işlemlerin erişilebilir kalması için geçerli varsayılan yanıtlar üretin.
- Kendi kendine transaction veya aynı hedefe yönelik birden fazla bekleyen transaction gibi olanaksız geçişleri reddedin.
- Singleton bootstrap durumunu input başına yapılan reset'in dışında tutun. Binder, her boot için yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; bu nedenle o istemciyi tekrar tekrar yok edip yeniden oluşturmak sonraki input'ları geçersiz kılar.

Yararlı bir lifetime-race şablonu; bir istemcinin nesneyi aktarmasını, thread veya process temizliğini başlatmasını ve alıcı istemcinin transaction buffer'ını eşzamanlı olarak serbest bırakmasını sağlamaktır. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` ile `BC_FREE_BUFFER` arasındaki yarış, çıkan thread'in cleanup path'i hâlâ kullanırken gömülü bir `binder_work` nesnesini serbest bırakabiliyordu.<sup>[[15]](#references)</sup>

#### Kontrollü interleaving'leri bir userspace kernel'de yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness'ine bağlar ve syscall arayüzünü `lkl_syscall` üzerinden sunar. Bu sayede protobuf durumu, coverage ve KASAN tek bir process içinde kolayca koordine edilebilir. Ancak LKL, normalde bir syscall'ı başka bir kernel thread'i tarafından kesintiye uğratılmadan çalıştırır. Race campaign'leri için seçilen lock/unlock ve lifetime sınırlarının çevresine `schedule()` noktaları ekleyin, ardından harness'in her yield noktasında sıradaki istemciyi rastgele seçmesini sağlayın. Her nokta scheduling arama alanını genişlettiğinden bu noktaları hedefli seçin. Araştırmacıların açıkladığı randomized scheduler, upstream Binder fuzzer'ının bir parçası **değildir**.<sup>[[15]](#references)</sup>

#### Serileştirilmiş regression seed'lerini derleyip yeniden oynatın

Upstream harness, uyumlu bir `libprotobuf-mutator` sürümünü sabitler, `LKL_FUZZING=1` ile LKL fuzzing instrumentation ve KASAN'ı etkinleştirir, Binder için de `MMU=1` ile `CONFIG_MMU`'yu açar.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Upstream'de belgelenen rollback yamalarını uyguladıktan veya kasıtlı olarak savunmasız bir revizyonu kontrol ettikten sonra, serileştirilmiş bir seed, tüm çok istemcili durum geçişini geçici bir C proof of concept içinde yeniden oluşturmadan tekrar üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free hatasını, seed’in savunmasız yaşam süresi yoluna ulaştığının doğrulanması olarak değerlendirin. Bu, kernel code execution veya privilege escalation için gereken sonraki primitive’leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makineli Çeşitlilik Hilesi (Jackalope Tarzı)

**Generative novelty** ile **coverage reuse** yöntemlerini hibritleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı kısa ömürlü worker’ları **yeniden başlatmaktır**. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar senkronize olur ve ardından çıkar. Böylece biriken coverage’dan yararlanırken her nesilde **yeni yapılar** elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

**Sunucu:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Ardışık worker'lar (örnek döngü):**

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

- `-in empty`, her üretimde **yeni bir corpus** kullanılmasını sağlar.
- `-server_update_interval T`, **gecikmeli eşitlemeyi** (önce yenilik, sonra yeniden kullanım) yaklaşık olarak sağlar.
- Grammar fuzzing modunda **ilk server eşitlemesi varsayılan olarak atlanır** (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T` **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Harness Edilmesi Zor Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda ancak **yüksek maliyetli bir hazırlık sürecinden sonra** (VM'yi başlatma, oturum açma işlemini tamamlama, paket alma, container'ı ayrıştırma, hizmeti başlatma) erişilebiliyorsa, yararlı bir alternatif **snapshot fuzzing**'dir: hazır süreç veya VM durumunu yakalayın, her test case'i hedefin giriş yoluna enjekte edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem, başlatma işlemlerini veya protokol öneklerini tekrar etme ihtiyacını ortadan kaldırır; **network services**, **firmware**, **post-auth attack surfaces** ve **binary-only targets** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici durum hazır olana kadar hedefi çalıştırın.
2. Bu noktada **belleği + register'ları** snapshot olarak kaydedin.
3. Her test case için, değiştirilmiş girdiyi doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde, destekleniyorsa yalnızca **dirty pages**'i geri yükleyip işlemi tekrarlayın.

Snapshot'ı, `recv`/`read` sonrasındaki veya paket deserialization noktasındaki gibi, mümkün olduğunca ilk maliyetli parse/dispatch adımına yakın bir yere koyun ve hedefin kullandığı input buffer'ı kaydedin. Bu yaklaşım, tekrarlanan işlemleri önlemek için snapshot'ı input işleme sürecinin daha derinlerine taşıyan adaptif yerleştirme ilkesini izler.<sup>[[11]](#references)</sup>

### Protokol durumları için artımlı snapshot'lar

Sabit bir snapshot hazırlık maliyetini ortadan kaldırır, ancak birden fazla geçerli mesaj gerektiren geçişleri tek başına keşfedemez. LibAFL-Qemu harness'i, bir protokol durumu alanına yapılan yazmaları izleyebilir ve durum değiştiğinde yeni bir snapshot kaydedebilir. [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful), `tcpcb.t_state` alanını izler, snapshot'ları tekilleştirmek için durum ve yanıt flag'lerini hash'ler ve dirty pages'i bir parent'a göre saklar. Sonraki yapılandırılmış mesaj değiştirilmeden önce, seçilen snapshot parent zinciri üzerinden geri yüklenir. Test case, bir `SnapshotId` ve üretilen input byte'larını (`gen_bytes`) tutar; snapshot manager ise replay için gereken parent ilişkisini izler.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu'nun user-mode `SnapshotModule` bileşeni mapping'leri ve hedef belleğini kaydeder, ancak CPU register'larını kaydetmez; gerektiğinde bunları ayrıca koruyun. Açıklanan manager tek bir root snapshot tree'ini destekler ve snapshot ID'lerini worker'lar arasında paylaşamaz. Multi-snapshot modu da QASAN shadow state'ini doğrudan yeniden kullanamaz. Offline triage için input zincirini ayrı bir instrumented process'te yeniden oluşturun. `AsanHostModule` ve `DrCovModule` kullanırken, `fuzzer.evaluate_input` gerekli `pre_exec`/`post_exec` callback'lerini çalıştırır; yalnızca `qemu.run` bunları çalıştırmaz.<sup>[[27]](#references)[[28]](#references)</sup>

### Mantıksal ring-buffer taşmalarını yakalama

Bir buffer'ın *geçerli veri sayısının* ötesine yapılan bir okuma, host allocation sınırları içinde kalabilir ve standart ASAN'dan kaçabilir. [libslirp urgent-data örneği](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) ayrıca işaretsiz bir byte sayacının underflow olmasına yol açar. Kaynak kodu mevcutsa, signed/unsigned integer-overflow instrumentation bu yan etkiyi algılayabilir; raporları susturmadan önce kasıtlı TCP sequence-number wrap durumlarını ayırt edin. Daha güçlü bir oracle önerisi, özel ring allocation'ını poison'lamak, dahili allocator ilerledikçe yalnızca geçerli aralıkların poison'unu kaldırmak ve serbest bırakılan aralıkları yeniden poison'lamaktır. LibAFL-Qemu, source instrumentation uygulamanın pratik olmadığı hedefler için bir ASAN poisoning API sunar.<sup>[[27]](#references)</sup>

## MAccConc ile Linux Kernel Race Keşfi

[MAccConc](https://github.com/googleprojectzero/MAccConc), zamana duyarlı Linux-kernel race'lerini tekrarlanabilir memory-access schedule'larına dönüştürür. İki context'li **A-B-A** yürütmelerini otomatik olarak sıralayabilir veya analistin terminal UI/GUI üzerinden sıralama kısıtları belirlemesine olanak tanır. Bu araç, tamamlanmış bir concurrency fuzzer değil, deneysel bir araştırma aracıdır: şu anda LLVM 23+ ve projenin yamalanmış kernel'ini gerektirir; command-line araçları iki test thread'ini destekler ve önerilen userspace fuzzing katmanı henüz uygulanmamıştır.<sup>[[17]](#references)[[18]](#references)</sup>

### Context'ler arası iletişim noktalarını toplama

Instrumented kernel'i KASAN outline callback'leri ve yamalanmış KCOV memory-record desteğiyle derleyin. Projenin README dosyası, call stack'lerin kullanılabilir kalması için sibling-call optimization'ı devre dışı bırakmayı da önerir.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`), instrument edilmiş erişimleri helper çağrılarına dönüştürür. MAccConc kernel yamaları, ardışık erişimlerin birleştirilmemesi için `asan-opt-same-temp` seçeneğini devre dışı bırakır; global değişken yarışlarının görünür olması gerektiğinde `asan-opt-globals` optimizasyonunu da devre dışı bırakın. KCOV, ortaya çıkan kayıtları userspace'e taşır. Farklı yürütme bağlamlarındaki erişimleri karşılaştırın ve byte aralıkları örtüşen, en az bir tarafı yazma işlemi olan çiftleri tutun; yaşam döngüsü geçişlerinin de aday olması için `kfree()` işlevini yazma işlemi olarak modelleyin.<sup>[[17]](#references)</sup>

Başlatan görevden bağımsız çalışan işler (ör. paket işleme veya RCU callback'leri) için alt sistemin bir KCOV remote-coverage handle'ı iletmesi gerekir. Upstream remote KCOV isteğe bağlıdır ve rastgele arka plan işleri için otomatik olarak kullanılamaz; bu nedenle iletimin yapılmaması gerçek bir etkileşimin görünmez kalmasına yol açabilir.<sup>[[17]](#references)[[19]](#references)</sup>

### Her çalıştırmada aynı dinamik erişimi belirleyin

Her ayırmadan sonra değişebilecek somut bir heap adresine ya da yalnızca bir komut adresine göre tekrar oynatmayın; ikincisi `memcpy()` ve `spin_lock()` gibi helper'ların içinde belirsizdir. MAccConc, **count-augmented stack trace** kullanır: her frame, bir callee'yi ve çağıranındaki çağrılma sayısını tanımlar; son öğe ise bellek erişimi komutunu tanımlar. SanitizerCoverage function-entry/exit kayıtları userspace'in bu dinamik tanımlayıcıyı yeniden oluşturmasını sağlar; tanımlayıcı, adres değişikliklerine ve ilgisiz kontrol akışı gürültüsüne rağmen sabit kalır.<sup>[[17]](#references)</sup>

### Aday çiftleri zorlanmış zamanlamalara dönüştürün

Yamalanmış `KCOV_SET_DI` ioctl'ı, count-augmented erişim tanımlayıcısını bir shared-flag eylemiyle ilişkilendirir.<sup>[[17]](#references)</sup>

| Eylem | Anlamı |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Seçilen erişimden hemen önce *N* bayrağını ayarlar. |
| `DI_STACK_WAIT` | Seçilen erişimden önce, *N* bayrağı ayarlanana veya yapılandırılmış limit dolana kadar bekler. |
| `DI_STACK_WAKE_POST` | Seçilen erişimden hemen sonra *N* bayrağını ayarlar. |

Kısmi bir **A-happens-before-B** kısıtı için aynı bayrağı kullanarak A'ya `DI_STACK_WAKE_POST`, B'ye `DI_STACK_WAIT` atayın. Tam olarak tanımlanmış iki bağlamlı bir zamanlama için B'yi engellenmiş durumda başlatın; ardından A, ilk aktarım noktasında B'yi uyandırsın ve beklesin. B, sonraki aktarım noktasında bunun tersini yapsın. İkinci yöntem deterministik bağlam değiştirme gibi çalışır ve otomatik A-B-A gezgininin kullandığı yöntemdir.<sup>[[17]](#references)</sup>

Asgari bir kampanya için dört hook'lu test senaryosunu (`test_setup`, iki thread işlevi ve `test_end`) paylaşılan bir kitaplık olarak derleyin, kısıtlanmamış bir iz toplayın ve ardından A-B-A adaylarını sıralayın ya da şüpheli erişimlerin çevresine elle kısıtlar ekleyin.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Zaman aşımlarını başarılı yeniden sıralamalardan ayrı değerlendirin: bir kilit veya başlatma/yayımlama bağımlılığı, ikinci bağlamın enjeksiyon noktasına ulaşmasını engellediğinden istenen sıra mümkün olmayabilir. Ayrıca KASAN'ın kör noktalarını göz önünde bulundurun: doğrudan yığın erişimleri, sınırların dışına çıkma ihtimali yoksa genellikle hook'lanmaz; varsayılan optimizasyonla global değişkenler kapsam dışında kalır ve mevcut derleyiciler ASAN ve TSAN hook'larını aynı anda ekleyemez. Son olarak prototip, konuk panic verdiğinde KCOV arabelleğini kaybeder; bu nedenle bağımsız bir crash konsolu/oracle bulundurun.<sup>[[17]](#references)</sup>

Gelecekte concurrency-guided fuzzing için her girdi veya syscall bazında bellek erişimi özetlerini kaydedin, bağlamlar arası iletişim noktaları oluşturabilecek işlemleri eşleştirin ve ardından yalnızca bu kombinasyonları keşfedin. VM snapshot'ları global durumu ve adresleri sabitler; snapshot olmadan, allocation-site metadata nesneleri çalıştırmalar arasında soyutlayabilir. Bu, mevcut MAccConc userspace araçlarının bir özelliği değil, önerilen bir genişletmedir.<sup>[[17]](#references)</sup>

## Harness İçgörüsü: Sığ Fuzzer'ları Erken Bulun

Bir kampanya durduğunda sorun çoğunlukla mutator değil, **harness**'tır. Fuzz hedefinizden statik olarak erişilebilen ancak dinamik olarak nadiren veya hiç kapsanmayan işlevleri bulmak için **erişilebilirlik/kapsama içgörüsünden** yararlanın. Bu işlevler genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness hedefe çok geç veya çok erken giriyor.
- Seed corpus'ta bütün bir özellik ailesi eksik.
- Hedef için, her şeyi yapan tek ve aşırı büyük bir harness yerine gerçekten **ikinci bir harness** gerekiyor.

OSS-Fuzz / ClusterFuzz tarzı iş akışları kullanıyorsanız Fuzz Introspector, statik erişilebilirliği çalışma zamanı kapsamıyla karşılaştırabilir ve zaman sınırlı bir çalıştırmadan veya herkese açık bir corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak test edilmemiş bir parser yolu için yeni bir harness eklemeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük giriş noktalarına ayırmaya karar verin.

## Graph-First Fuzz Target Selection And Mutation Triage

Elinizde **static-analysis bulguları**, **mutation-testing sağ kalanları** ve **coverage raporları** varsa bunları birbirinden bağımsız listeler olarak değerlendirmeyin. Önce bir **call graph** oluşturun; düğümlere **cyclomatic complexity**, **entrypoint/untrusted-input erişilebilirliği** ve harici bulguları ek açıklama olarak ekleyin, ardından graph hakkında sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki fonksiyonlara untrusted input üzerinden erişilebiliyor?
- Hangi mutation survivor'ları parser/handler'lardan security-critical koda giden yollar üzerinde bulunuyor?
- Hangi fonksiyonlar, alışılmadık derecede büyük **blast radius**'a sahip mimari darboğaz noktaları?

Bu yaklaşım genellikle "en düşük coverage" ölçütünden daha iyi fuzz target'lar ortaya çıkarır. **Yüksek karmaşıklığa** ve doğrulanmış **harici erişilebilirliğe** sahip bir parser/decoder, saldırganın kontrolündeki bir yol üzerinde olmayan, coverage'ı düşük izole bir dahili yardımcı fonksiyondan daha güçlü bir harness adayıdır.

### Pratik triage iş akışı

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına karmaşıklık/dal metriklerini çıkarın.
2. Saldırganın kontrolündeki input'u kabul eden **entrypoint**'leri belirleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Erişilebilir saldırı yüzeyini yalnızca ölü/dahili koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara **path query**'leri çalıştırın.
4. Şu özellikleri bir arada taşıyan düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - untrusted input'tan doğrulanmış **erişilebilirlik**
   - yüksek **blast radius** veya çok sayıda aşağı akış bağımlısı
   - **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için, en yüksek puanlı düğümlere odaklanan harness'leri önce yazın.

### Mutation survivor'ları: eşdeğer mi, eyleme geçirilebilir mi?

Mutation testing genellikle gürültülü bir survivor listesi üretir. Her survivor'ı bir security gap olarak değerlendirmeden önce graph'i kullanarak şunları sorun:

- Mutasyona uğratılan fonksiyona saldırganın kontrolündeki bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılan kontrolden daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm ölü kodda, yalnızca biçimlendirme yapan mantıkta mı, yoksa yüksek etkili bir aritmetik/parser yolunda mı bulunuyor?

Erişilemez kalan veya yapısal olarak kısıtlanan survivor'lar çoğu zaman **eşdeğer mutant**'lardır. **Erişilebilir** kalan ve **sınır koşullarına**, **taşma/elde yollarına** veya **security-critical aritmetik/parsing** işlemlerine dokunan survivor'lar şunlara dönüştürülmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant test'leri
- hedefli edge-case vektörleri

### Harici bulguları graph ile ilişkilendirin

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **dosya + satır aralığı** üzerinden graph düğümlerine yansıtın ve etkiyi genişletmek için graph'i kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius**'unu hesaplayın
- bulgunun bir entrypoint'ten geçen herhangi bir yol üzerinde olup olmadığını kontrol edin
- aynı darboğaz noktasında birleşen yakındaki bulguları gruplandırın

Bu, belirli bir fonksiyona fuzzing zamanı ayırmaya karar verirken işe yarar: **erişilebilir**, **karmaşık** ve zaten **SAST bulguları** olan bir düğüm, saldırganın izlediği bir yol olmadan yalnızca karmaşık olan bir düğümden genellikle daha iyi bir hedeftir.

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

Önemli metodoloji, şu üç unsurun kesişimidir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve invariant'ları zorlaması gerektiğine karar vermek için mutasyonlardan sağ çıkan girdileri kullanın.<sup>[[5]](#references)</sup>

## Kriptografik anahtar kodlamalarında differential fuzzing

Geçerli serileştirilmiş anahtarlardan veya standart test vektörlerinden başlayın. Import ve işlem yollarına ulaşmak için gereken uzunluk ve yapıyı bozmadan kodlanmış alanları mutate edin, ardından aynı baytları bağımsız implementasyonlara gönderin. Kabul durumlarını ve hataları karşılaştırın. Rastgeleleştirilmiş imzalar ve ciphertext'ler için bayt bayt karşılaştırma değil, doğruluk oracle'ları gerekir: imzaları doğrulayın veya bir encapsulation/decapsulation round trip'inden elde edilen paylaşılan sırları karşılaştırın. Test vektörleri bilinen durumlar için uygunluğu belirler; differential mutation ise bunların ötesindeki hatalı kodlamaları araştırır.<sup>[[23]](#references)[[26]](#references)</sup>

Bu anahtar biçimleri için biçime özgü oracle'lar kullanın:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** Anahtar parse edilebilir durumda kalırken paketlenmiş `s1` veya `s2` katsayılarını `[-η, η]` aralığının dışına çıkaracak şekilde değiştirin. Import veya imzalama işleminin bunları reddedip reddetmediğini ve ortaya çıkan herhangi bir imzanın doğrulanıp doğrulanmadığını kontrol edin. Yalnızca kabul durumlarındaki farklılıklar standart ihlali değildir; çünkü FIPS 204 ek private-key kontrollerini zorunlu kılmaz. Bkz. [koşullu leakage mekanizması](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM key pairs:** Zorunlu encapsulation-key ve decapsulation-input kontrollerini, import edilen bir çift üzerinde yapılan isteğe bağlı pairwise-consistency check'ten (PCT) ayırın. Public key ile encapsulate edin, private key ile decapsulate edin ve paylaşılan sırları karşılaştırın; uyuşmazlık, tek tek anahtarlar girdi kontrollerinden geçse bile şifreli iletişimi bozabilir. API'nin girdileri işlem sırasında mı yoksa ayrı bir çağrıyla mı doğruladığını kontrol edin; libcrux, PCT'nin yerini tutmayan `validate_public_key(pk)` ve `validate_private_key(sk, ct)` işlevlerini sunar.
- **XMSS/XMSSMT raw keys:** Yalnızca bellekteki anahtarlarla işlem yapmak yerine, parametre kümeleri arasında serileştirilmiş **imzalama ve doğrulama** anahtarlarının round trip işlemlerini test edin. XMSS ve XMSSMT ayrı dört baytlık OID namespace'lerine sahiptir; bu nedenle önce XMSS'i deneyen, yalnızca OID kullanan bir parser çakışan bir XMSSMT anahtarını yanlış sınıflandırıp import işlemini reddedebilir. Bildirilen RustCrypto parser'ı, imza sahteciliğini değil birlikte çalışabilirlik/kullanılabilirlik hatasını örnekler.

## gosentry ile Go Fuzzing: Daha Güçlü Engine, Typed Inputs ve Differential Checks

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan ancak backend'i **LibAFL** ile değiştiren, fork edilmiş bir Go toolchain'dir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, native Go fuzzer **zor karşılaştırmalarda**, **typed input'larda** veya **parser ağırlıklı formatlarda** takıldığında kullanışlıdır. Yöntem aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'ı kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided run olarak değerlendirin; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanın.

### Sessiz hataları fuzz bulgularına dönüştürme

Go değerlendirmelerinde sık karşılaşılan bir sorun, tehlikeli davranışların varsayılan olarak **crash** etmemesidir. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` seçili logging/error yollarının crash gibi davranmasını sağlar (aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı kod yolları için kullanışlıdır).
- `--catch-races=true` yeni keşfedilen queue entry'lerini Go race detector ile yeniden oynatır.
- `--catch-leaks=true` yeni queue entry'lerini `goleak` ile yeniden oynatır ve goroutine leak'lerinde durur.
- LibAFL hang işleme özelliği, **sonsuz döngüleri / çok yavaş input'ları** timeout olarak kaybolmalarına izin vermek yerine fuzz bulguları olarak tutar.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, özellikle güvenlik etkisinin memory corruption yerine **panic oluşturmayan bir parser hatası**, **concurrency bug'ı** veya yalnızca DoS'a yol açan bir **hang** olduğu hedeflerde değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Native Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen kod typed object'ler tüketiyorsa gosentry, alttaki byte'ları mutate etmeye devam ederken doğrudan **composite value'ları** (struct'lar, slice'lar, array'ler, pointer'lar) fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu, yalnızca fuzzing için sahte bir wire format oluştururken kullanmak, mantık hatalarını yalnızca harness'te bulunan ayrıştırma kodunun arkasında gizler. Differential veya grammar-based kampanyalarda harness girdisini tek bir `[]byte` ya da `string` olarak tutun ve bunun yerine callback içinde ayrıştırın.

### Parser'lar ve protokol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve girdi dilleri için gosentry, LibAFL üzerine **Nautilus grammar fuzzing** çalıştırabilir. Grammar, üretim kurallarından oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Bayt düzeyindeki mutasyonlar çoğunlukla erken sözdizimi denetimlerinde başarısız oluyorsa grammar mode kullanın.
- Grameri, dilin/protokolün tüm belirtimini modellemek yerine **güvenlikle ilgili alt kümesine** odaklı tutun.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminallerde/terminal olmayanlarda büyük sınır değerleri kullanın.
- Grammar mode girdileri gramer açısından geçerli tutar, ancak hedef yine de **baytlar/dizeler** alır; dolayısıyla ayrıştırma ve anlamsal denetimler hâlâ harness kapsamındaki kodda gerçekleşir.

### Differential fuzzing: yalnızca çökmeleri değil, uygulamaları karşılaştırın

Go ekosistemleri için güçlü bir yaklaşım **gramer tabanlı differential fuzzing** yöntemidir: geçerli yapılandırılmış girdiler üretin ve bunları iki parser'a, istemciye veya durum geçişi motoruna verin.<sup>[[7]](#references)[[8]](#references)</sup>

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

- bir implementasyon panic verirken diğeri girdiyi sorunsuz biçimde reddediyor
- kabul edilen/reddedilen girdiler arasında uyuşmazlıklar
- farklı parse ağaçları veya decode edilmiş nesneler
- farklı state geçişleri, nonce değerleri, bakiyeler veya state root’ları

Bu, saf crash fuzzing’in sıklıkla gözden kaçırdığı **consensus uyuşmazlıklarını**, **parser belirsizliğini** ve **spec ile implementasyon arasındaki sapmaları** bulmanın pratik bir yoludur.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage raporlaması için campaign corpus’unu yeniden kullanın

Bir campaign’den sonra, ayrı bir corpus’u manuel olarak dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus’unu yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Komutu aynı paketten ve aynı `-fuzz` hedefiyle çalıştırın; böylece gosentry doğru önbelleğe alınmış kampanya durumunu çözümler.

## References

- [1] [Mutasyonel grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing'e Derinlemesine Bakış](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet, Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu grafiklere dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısından yoksundu. Bunu düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar Kullanarak Stateful Network Protocols için Hızlı bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar Yok, Sorun Yok: System-Call Açıklamaları Olmadan Linux Kernel Fuzzing](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Uyarlanabilir ve Değiştirilebilir Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Öngörülü Context-Sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - derleme ve regression-seed belgeleri](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kontrollü Memory-Access Interleaving'leriyle Linux Kernel Race Condition'larını İnceleme](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing için code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Extended Filename Syntax'ı Fuzzing: 16 Memory-Safety Açığı ve Codex Destekli Triyaj](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Kriptografi için Differential Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID ayrıştırma hatası - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Cryptography Uygulamalarının Durumu](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Snapshot Alma Yöntemiyle CVE-2026-9539'a Ulaşmak](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
