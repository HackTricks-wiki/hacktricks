# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage ve Semantics

**Mutational grammar fuzzing** sırasında girdiler, **grammar-valid** kalacak şekilde değiştirilir. Coverage-guided modda yalnızca **yeni coverage** tetikleyen örnekler corpus seed’i olarak kaydedilir. **Dil hedeflerinde** (parser’lar, interpreter’lar, engine’ler) bu yaklaşım, bir yapının çıktısının başka bir yapının girdisi olduğu **semantic/dataflow zincirleri** gerektiren bug’ları kaçırabilir.<sup>[[1]](#references)</sup>

**Hata modu:** Fuzzer, `document()` ve `generate-id()` (veya benzer primitive’ler) işlevlerini ayrı ayrı çalıştıran seed’ler bulur; ancak **zincirlenmiş dataflow’u korumaz**. Bu nedenle “bug’a daha yakın” örnek coverage’ı artırmadığı için elenir. **3 veya daha fazla bağımlı adımda**, rastgele yeniden birleştirme maliyetli hale gelir ve coverage feedback aramaya yön vermez.<sup>[[1]](#references)</sup>

**Çıkarım:** Bağımlılığı yüksek grammar’larda **mutational ve generative aşamaları hibritleştirmeyi** veya üretimi yalnızca coverage’a değil, **function chaining** kalıplarına da yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliğiyle İlgili Tuzaklar

Coverage-guided mutation **açgözlüdür**: yeni coverage sağlayan bir örnek hemen kaydedilir ve çoğu zaman değiştirilmemiş büyük bölümleri korur. Zamanla corpus’lar, yapısal çeşitliliği düşük **neredeyse kopyalarla** dolar. Aşırı minimization yararlı bağlamı ortadan kaldırabilir. Bu nedenle pratik bir uzlaşma, **minimum bir token eşiğine ulaşıldığında duran** grammar-aware minimization’dır (gürültüyü azaltırken mutation’a elverişli kalması için yeterli çevre yapısını korumak).<sup>[[1]](#references)</sup>

Mutational fuzzing için pratik bir corpus kuralı: çok sayıda neredeyse kopya yerine, **coverage’ı en üst düzeye çıkaran ve yapısal olarak farklı az sayıda seed’i tercih edin**. Uygulamada bu genellikle şunları ifade eder.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (public corpus’lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Geçerli her örneği tutmak yerine **coverage-based corpus minimization** ile örnekleri damıtın.
- Mutation’ların çoğu döngüyü ilgisiz byte’lara harcamak yerine anlamlı alanlara ulaşması için seed’leri **yeterince küçük tutun**.
- Harness veya instrumentation’da önemli değişiklikler yaptıktan sonra corpus minimization’ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Value’lar İçin Comparison-Aware Mutation

Fuzzer’ların ilerlemesinin durmasının yaygın nedenlerinden biri syntax değil, **katı karşılaştırmalardır**: magic byte’lar, uzunluk kontrolleri, enum string’leri, checksum’lar veya `memcmp`, switch table’ları ya da art arda yapılan karşılaştırmalarla korunan parser dispatch değerleri. Tamamen rastgele mutation, bu değerleri byte byte tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedeflerde, fuzzer’ın başarısız karşılaştırmalardaki operand’ları gözlemleyebilmesi ve mutation’ları bu karşılaştırmaları karşılayan değerlere yönlendirebilmesi için **comparison tracing** kullanın (örneğin AFL++ `CMPLOG` / Redqueen tarzı iş akışları).<sup>[[3]](#references)</sup>

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
- Bunu gerçek örneklerden, protokol özelliklerinden veya debug loglarından çıkarılan **sözlüklerle** birlikte kullanın. Dilbilgisi belirteçleri, parça adları, fiiller ve ayraçlardan oluşan küçük bir sözlük, çoğu zaman devasa ve genel bir kelime listesinden daha değerlidir.
- Hedef art arda çok sayıda kontrol gerçekleştiriyorsa, önce en baştaki “magic” karşılaştırmalarını çözün; ardından sonraki aşamalar zaten geçerli öneklerle başlasın diye ortaya çıkan corpus'u yeniden küçültün.

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı yardımcı işlevden geçen ancak farklı çağıranlar tarafından kullanılan veya bir işlev içinde farklı dal birleşimlerini izleyen iki yürütmeyi ayırt edemez. Bu durum, bir edge'e giden **yolun** canlı durumu belirlediği paylaşılan decoder'larda, protokol dispatcher'larında ve interpreter yardımcı işlevlerinde önemlidir. Her çağrı bağlamını gelişigüzel izlemek de tehlikelidir: coverage map ve queue aşırı büyüyebilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm çağrı grafiğini context-sensitive kabul etmek yerine yalnızca umut vadeden bağlamları ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

Son AFL++ sürümleri, normal edge coverage'a ek olarak **fonksiyon başına Ball-Larus path coverage** sunar. Bir işlevdeki her döngüsüz yola bir özellik atar; döngü geri kenarları kaldırılır, bu nedenle bu geri bildirim dal birleşimlerini ayırt eder ancak **döngü yineleme sayılarını ayırt etmez**. Esnek `1` düzeyiyle başlayın; yol sayısı üstel olarak artabileceğinden daha katı modları yalnızca şüpheli parser/state-machine koduyla sınırlandırın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Güvenlikle ilgili birçok noktadan çağrılan bir yardımcı işlev için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

**Campaign guidance:** daha zengin feedback'i temkinli kullanın ve coverage-map/queue maliyetini izleyin.<sup>[[13]](#references)[[14]](#references)</sup>

- Paralelde sıradan bir edge-coverage örneği çalıştırın; zengin feedback ancak ek queue/map maliyeti saniyedeki execution sayısını düşürmüyorsa yararlıdır.
- Büyük template ağırlıklı kütüphaneler veya genel amaçlı utility kodu map'i domine ediyorsa path/caller instrumentation'ı kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda acyclic path içeren fonksiyonlar AFL++ tarafından atlanabilir; derleme sırasında çıkan uyarılar, hedefin allowlisting veya daha az katı bir seviyeye ihtiyaç duyduğunu gösterir.
- Caller + path coverage yalnızca tek bir caller depth'i destekler. Bunu daha derin context stack'leriyle birleştirmeyin.
- Path ID'leri LLVM major sürümleri arasında değişebilir. Bir campaign boyunca toolchain'i sabit tutun ve PATH tabanlı corpus'ları, feature ID'leri build'ler arasında sabitmiş gibi senkronize etmeyin.
- Bu feedback, `CMPLOG`'u tamamlar: comparison tracing **bir guard'dan hangi değerin geçtiğini** çözerken, path/caller feedback **hangi route ve branch kombinasyonunun ona ulaştığını** korur.

## Stateful Fuzzing: Diziler Seed'dir

**Protokoller**, **kimliği doğrulanmış iş akışları** ve **çok aşamalı parser'lar** için ilgi çekici birim çoğunlukla tek bir blob değil, bir **mesaj dizisidir**. Tüm transcript'i tek bir dosyada birleştirip gelişigüzel mutate etmek genellikle verimsizdir; çünkü fuzzer her adımı eşit şekilde mutate eder, oysa kırılgan duruma yalnızca sonraki mesaj ulaşıyor olabilir.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **dizinin kendisini seed** olarak ele almak ve **gözlemlenebilir durumu** (yanıt kodları, protokol durumları, parser aşamaları, döndürülen nesne türleri) ek feedback olarak kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli prefix mesajlarını** sabit tutun ve mutasyonları **geçişi sağlayan** mesaja odaklayın.
- Sonraki adım önceki yanıtlara bağlıysa, önceki yanıtlardan gelen identifier'ları ve sunucunun ürettiği değerleri cache'leyin.
- Tüm serialize edilmiş transcript'i opak bir blob olarak mutate etmek yerine, mesaj başına mutasyon/splicing kullanmayı tercih edin.
- Protokol anlamlı yanıt kodları sunuyorsa, daha derine ilerleyen dizilere öncelik vermek için bunları **ucuz bir state oracle** olarak kullanın.

Kimliği doğrulanmış bug'ların, gizli geçişlerin veya “yalnızca handshake sonrasında” ortaya çıkan parser bug'larının vanilla file-style fuzzing ile sıkça gözden kaçmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sırayı, durumu ve bağımlılıkları** da korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: çok istemcili driver fuzzing

Yüksek edge coverage bile IPC-driver bug'larını gözden kaçırabilir; çünkü coverage **nesne sahipliğini, reference count'ları, bekleyen mesajları, cleanup sırasını veya thread interleaving'lerini** açıklamaz. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfasında driver nesne modeli ele alınır; bu örnek ise fuzzer harness'ına odaklanır. Android Binder yararlı bir modeldir: fuzzer birden fazla sürecin aynı kernel nesnesi üzerinde gereken sırayla çalışmasını sağlayamıyorsa, allocation ve free path'lerine ulaşmak yeterli değildir.<sup>[[15]](#references)</sup>

#### Yalıtılmış `ioctl` buffer'ları yerine protokolü modelleyin

Bir test case'i **istemci kimliği + işlem + yapılandırılmış argümanlar** içeren sıralı bir grammar olarak temsil edin. Binder LKL fuzzer'ı protobuf ve `libprotobuf-mutator` kullanır; bir persistent context-manager istemcisi ve iki sıradan istemci içerir. Ardından semantic harness, kör byte mutasyonunun bozacağı ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki işlemlerin döndürdüğü değerleri cache'leyin. Örneğin `BC_FREE_BUFFER`, önceki bir `ioctl` tarafından döndürülen transaction-buffer pointer'ını yeniden kullanmalıdır.
- Synchronous transaction'ların tamamlanmasını ve sonraki işlemlere erişilebilmesini sağlamak için geçerli varsayılan yanıtlar üretin.
- Kendi kendine transaction veya aynı hedefe birden fazla bekleyen transaction gibi imkânsız geçişleri reddedin.
- Singleton bootstrap durumunu input başına reset işleminin dışında tutun. Binder boot başına yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; bu nedenle istemciyi tekrar tekrar yok edip yeniden oluşturmak sonraki input'ları geçersiz kılar.

Yararlı bir lifetime-race şablonunda, bir istemcinin nesne aktarmasını sağlayın, thread veya process cleanup'ını başlatın ve alıcı istemcinin transaction buffer'ını eşzamanlı olarak serbest bırakmasını sağlayın. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` işlemiyle yarışan `BC_FREE_BUFFER`, çıkış yapan thread'in cleanup path'i hâlâ kullanırken gömülü bir `binder_work` öğesini serbest bırakabiliyordu.<sup>[[15]](#references)</sup>

#### Userspace kernel'de kontrollü interleaving'leri yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness'ına bağlar ve syscall arayüzünü `lkl_syscall` üzerinden sunar. Böylece protobuf durumu, coverage ve KASAN tek bir process içinde kolayca koordine edilebilir. Ancak LKL normalde bir syscall'ı, başka bir kernel thread'i kesintiye uğratmadan çalıştırır. Race campaign'leri için seçili lock/unlock ve lifetime sınırlarına `schedule()` noktaları ekleyin, ardından her yield'de sıradaki istemciyi harness'ın rastgele seçmesini sağlayın. Her nokta scheduling arama alanını büyüttüğü için bu noktaları hedefli tutun. Araştırmacıların tanımladığı randomized scheduler, upstream Binder fuzzer'ın bir parçası **değildir**.<sup>[[15]](#references)</sup>

#### Serialize edilmiş regression seed'lerini derleyip yeniden oynatın

Upstream harness uyumlu bir `libprotobuf-mutator` sürümünü sabitler, `LKL_FUZZING=1` ile LKL fuzzing instrumentation ve KASAN'ı etkinleştirir, ayrıca Binder için `CONFIG_MMU`'yu `MMU=1` ile etkinleştirir.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Bilerek güvenlik açığı bulunan bir revizyonu kontrol ettikten veya upstream'de belgelenen rollback yamalarını uyguladıktan sonra, serialized bir seed, durumu ad hoc bir C proof of concept ile yeniden oluşturmaya gerek kalmadan çok istemcili durum geçişinin tamamını yeniden üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free durumunu, seed'in savunmasız yaşam döngüsü yoluna ulaştığının doğrulanması olarak değerlendirin. Bu, kernel kodunun çalıştırılması veya yetki yükseltme için gereken sonraki primitive'leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makineli Çeşitlilik Hilesi (Jackalope-Style)

**Generative novelty** ile **coverage reuse** yöntemlerini hibritleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı kısa ömürlü worker'ları yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar senkronize olur ve ardından çıkar. Bu, birikmiş coverage'dan yararlanırken her nesilde **yeni yapılar** elde edilmesini sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

**Sunucu:**

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

- `-in empty`, her üretimde **yeni bir corpus** kullanılmasını sağlar.
- `-server_update_interval T`, **gecikmeli senkronizasyonu** (önce yenilik, sonra yeniden kullanım) yaklaşık olarak sağlar.
- Grammar fuzzing modunda **ilk sunucu senkronizasyonu varsayılan olarak atlanır** (`-skip_initial_server_sync` kullanmaya gerek yoktur).
- En uygun `T`, **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Harness Kurulumu Zor Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda ancak **yüksek kurulum maliyetinden sonra** (bir VM'i başlatmak, oturum açmayı tamamlamak, paket almak, bir container'ı ayrıştırmak, hizmeti başlatmak) erişilebiliyorsa, yararlı bir alternatif **snapshot fuzzing** yöntemidir: hazır süreç veya VM durumunu yakalayın, her test case'i hedefin girdi yoluna enjekte edin, crash/timeout oluşana kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem başlatma veya protokol öneklerini tekrar etmeyi önler ve **network services**, **firmware**, **post-auth saldırı yüzeyleri** ve **yalnızca binary olan hedefler** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlginç durum hazır olana kadar hedefi çalıştırın.
2. Bu noktada **bellek + register'ları** snapshot alın.
3. Her test case için, değiştirilmiş girdiyi doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset oluşana kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde, destekleniyorsa yalnızca **değişen sayfaları** geri yükleyin ve tekrarlayın.

Snapshot'ı mümkün olduğunca ilk maliyetli parse/dispatch adımına yakın bir noktaya, örneğin `recv`/`read` işleminden veya paket deserialization noktasından sonraya yerleştirin ve hedefin kullandığı input buffer'ı kaydedin. Bu, tekrarlanan işlemleri önlemek için snapshot'ı input işleme sürecinin daha ilerisine taşıma şeklindeki adaptif yerleştirme ilkesini izler.<sup>[[11]](#references)</sup>

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign durduğunda, sorun genellikle mutator değil, **harness** kaynaklıdır. Fuzz target'ınızdan statik olarak erişilebilen ancak dinamik olarak nadiren veya hiç kapsanmayan fonksiyonları bulmak için **erişilebilirlik/coverage introspection** kullanın. Bu fonksiyonlar genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness, hedefe çok geç veya çok erken giriyordur.
- Seed corpus'ta tüm bir özellik ailesi eksiktir.
- Hedefin, aşırı büyük tek bir “her şeyi yapan” harness yerine gerçekten **ikinci bir harness**'e ihtiyacı vardır.

OSS-Fuzz / ClusterFuzz tarzı iş akışları kullanıyorsanız, Fuzz Introspector statik erişilebilirliği runtime coverage ile karşılaştırabilir ve zaman sınırlı bir çalıştırmadan veya herkese açık bir corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak karar verin: test edilmemiş bir parser yolu için yeni bir harness ekleyin, belirli bir özellik için corpus'u genişletin veya monolitik bir harness'i daha küçük giriş noktalarına bölün.

## Graf Öncelikli Fuzz Hedefi Seçimi ve Mutation Triage

Elinizde **static-analysis bulguları**, **mutation-testing survivor'ları** ve **coverage raporları** varsa bunları birbirinden bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input erişilebilirliği** ve harici bulgularla işaretleyin, ardından grafla ilgili sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Yüksek karmaşıklığa sahip hangi fonksiyonlara untrusted input üzerinden erişilebilir?
- Hangi mutation survivor'ları, parser/handler'lardan güvenlik açısından kritik koda giden yollarda bulunuyor?
- Hangi fonksiyonlar, olağan dışı ölçüde yüksek **blast radius** değerine sahip mimari darboğazlar?

Bu yaklaşım genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz hedefleri ortaya çıkarır. **Yüksek karmaşıklığa** sahip ve **harici erişilebilirliği** doğrulanmış bir parser/decoder, saldırganın kontrol ettiği bir yol üzerinden erişilemeyen, coverage'ı düşük izole bir dahili yardımcı fonksiyondan daha güçlü bir harness adayıdır.

### Pratik triage iş akışı

1. Kod tabanından bir **code graph** oluşturun ve fonksiyon bazında karmaşıklık/dal metriklerini çıkarın.
2. Saldırgan kontrollü girdi alan **entrypoint**'leri listeleyin: request handler'ları, decoder'lar, importer'lar, protocol parser'ları, CLI/dosya okuyucuları.
3. Erişilebilir saldırı yüzeyini yalnızca ölü/dahili koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara **path query**'leri çalıştırın.
4. Şu özellikleri bir arada taşıyan düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - untrusted input kaynaklarından erişilebilirliğin doğrulanmış olması
   - yüksek **blast radius** veya çok sayıda downstream bağımlı
   - **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Önce en yüksek puanlı düğümler için, özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için odaklı harness'ler yazın.

### Mutation survivor'ları: eşdeğer mi, aksiyona değer mi?

Mutation testing genellikle gürültülü bir survivor listesi üretir. Her survivor'ı bir güvenlik açığı olarak değerlendirmeden önce şu soruları sormak için grafı kullanın:

- Mutasyona uğratılan fonksiyona saldırgan kontrollü bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılan kontrolden daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm ölü kodda, yalnızca biçimlendirme yapan mantıkta mı, yoksa etkisi yüksek bir aritmetik/parser yolunda mı bulunuyor?

Erişilemeyen veya yapısal olarak kısıtlanmış kalan survivor'lar genellikle **eşdeğer mutant**'lardır. **Erişilebilir** kalmaya devam eden ve **sınır koşullarına**, **overflow/carry yollarına** ya da güvenlik açısından kritik **aritmetik/parsing** işlemlerine dokunan survivor'lar şu çalışmalara aktarılmalıdır:

- yeni fuzz harness'leri
- doğrudan property/invariant testleri
- hedefli edge-case vektörleri

### Harici bulguları grafla ilişkilendirme

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **dosya + satır aralığı** üzerinden graf düğümlerine yansıtın ve etkiyi genişletmek için grafı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius** değerini hesaplayın
- bulgunun herhangi bir entrypoint yolunda olup olmadığını kontrol edin
- aynı darboğazda birleşen yakındaki bulguları kümelendirin

Bu, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken faydalıdır: **erişilebilir**, **karmaşık** ve zaten **SAST bulguları** olan bir düğüm, saldırgan yolu bulunmayan yalnızca karmaşık bir düğümden genellikle daha iyi bir hedeftir.

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

Önemli olan metodolojilerin kesişimidir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve değişmezleri zorlaması gerektiğine karar vermek için mutasyonlardan sağ çıkanları inceleyin.<sup>[[5]](#references)</sup>

## gosentry ile Go Fuzzing: Daha Güçlü Motor, Tipli Girdiler ve Diferansiyel Kontroller

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, uygulanabilir bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` desteğini korurken arka ucu **LibAFL** ile değiştiren, çatallanmış bir Go araç zinciridir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, yerel Go fuzzer'ı **zor karşılaştırmalarda**, **typed girdilerde** veya **parser ağırlıklı biçimlerde** takıldığında kullanışlıdır. Yöntem aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided çalışma olarak değerlendirin; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanın.

### Sessiz hataları fuzzing bulgularına dönüştürme

Go değerlendirmelerinde yinelenen bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, seçilen logging/error yollarının crash gibi davranmasını sağlar (aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı kod yolları için kullanışlıdır).
- `--catch-races=true`, yeni keşfedilen queue girdilerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true`, yeni queue girdilerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang işleme, **sonsuz döngüleri / çok yavaş girdileri** timeout olarak kaybolmalarına izin vermek yerine fuzzing bulguları olarak tutar.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, güvenlik etkisinin memory corruption yerine **panic oluşturmayan bir parser hatası**, **concurrency bug'ı** veya yalnızca **DoS'a yol açan bir takılma** olduğu hedefler için özellikle değerlidir.

### Typed Go API'leri için struct-aware fuzzing

Yerel Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar'lar bekler. Test edilen kod typed nesneler tüketiyorsa, gosentry byte'ları temel düzeyde mutate etmeye devam ederken doğrudan composite değerleri (struct'lar, slice'lar, array'ler, pointer'lar) fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu yalnızca fuzzing için sahte bir wire formatı oluştururken kullanmak, mantık hatalarını yalnızca harness'teki parsing kodunun arkasına gizler. Differential veya grammar-based fuzzing kampanyalarında harness girdisini tek bir `[]byte` ya da `string` olarak tutun ve bunun yerine callback içinde parse edin.

### Parser'lar ve protokol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve girdi dilleri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, production rule'lardan oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Byte-level mutasyonlar çoğunlukla erken sözdizimi kontrollerinde eleniyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tamamını modellemek yerine **güvenlikle ilgili alt kümeye** odaklayın.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminal ve nonterminal'lerde büyük sınır değerleri kullanın.
- Grammar mode girdileri grammar'a uygun tutar, ancak hedef yine de **byte/string** alır; dolayısıyla ayrıştırma ve anlamsal kontroller harness içine alınan kodda gerçekleşmeye devam eder.

### Differential fuzzing: yalnızca çökmeleri değil, uygulamaları karşılaştırın

Go ekosistemleri için güçlü bir yaklaşım, **grammar-based differential fuzzing**'dir: geçerli, yapılandırılmış girdiler üretin ve bunları iki ayrıştırıcıya, istemciye veya durum geçiş motoruna verin.<sup>[[7]](#references)[[8]](#references)</sup>

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

- Bir implementasyon panic olurken diğeri girdiyi düzgün şekilde reddediyor
- Kabul edilen/reddedilen girdiler uyuşmuyor
- Parse ağaçları veya decode edilmiş nesneler farklı
- Durum geçişleri, nonce'lar, bakiyeler veya durum kökleri farklılaşıyor

Bu, saf crash fuzzing'in çoğu zaman gözden kaçırdığı **consensus uyuşmazlıklarını**, **parser belirsizliğini** ve **spesifikasyon ile implementasyon arasındaki sapmaları** bulmanın pratik bir yoludur.

### Coverage raporlaması için kampanya corpus'unu yeniden kullanın

Bir kampanyadan sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus'unu yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Aynı paket içinden ve aynı `-fuzz` hedefiyle komutu çalıştırın; böylece gosentry doğru önbelleğe alınmış kampanya durumunu çözümler.



## References

- [1] [Mutasyonel dilbilgisi fuzzing'i](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing'e Derinlemesine Bakış](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu graflara dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısından yoksundu. Bunu düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar Kullanarak Stateful Network Protocols için Hızlı Bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Dilbilgisi Yok, Sorun Yok: System-Call Açıklamaları Olmadan Linux Kernel Fuzzing'e Doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Uyarlanabilir ve Değiştirilebilir Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Öngörülü Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build ve regression seed belgeleri](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
