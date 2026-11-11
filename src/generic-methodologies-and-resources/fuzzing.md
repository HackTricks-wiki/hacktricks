# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutasyonel Grammar Fuzzing: Coverage ve Semantik

**Mutasyonel grammar fuzzing** sırasında girdiler, **grammar'a uygun** kalacak şekilde mutate edilir. Coverage-guided modda yalnızca **yeni coverage** tetikleyen örnekler corpus seed'leri olarak kaydedilir. **Dil hedeflerinde** (parser'lar, interpreter'lar, engine'ler) bu yaklaşım, bir yapının çıktısının diğerinin girdisi hâline geldiği **semantik/dataflow zincirleri** gerektiren bug'ları kaçırabilir.<sup>[[1]](#references)</sup>

**Başarısızlık biçimi:** fuzzer, ayrı ayrı `document()` ve `generate-id()` (veya benzeri primitive'ler) çalıştıran seed'ler bulur, ancak **zincirlenmiş dataflow'u koruyamaz**; bu nedenle “bug'a daha yakın” örnek, coverage'ı artırmadığı için elenir. **3 veya daha fazla bağımlı adımda**, rastgele yeniden birleştirme maliyetli hâle gelir ve coverage feedback aramaya yön vermez.<sup>[[1]](#references)</sup>

**Çıkarım:** bağımlılığın yoğun olduğu grammar'larda, **mutasyonel ve generative aşamaları hibritleştirmeyi** veya üretimi yalnızca coverage'a göre değil, **function chaining** kalıplarına göre de yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliğiyle İlgili Tuzaklar

Coverage-guided mutation **açgözlüdür**: yeni coverage sağlayan bir örnek hemen kaydedilir ve çoğu zaman büyük, değişmemiş bölgelerini korur. Zamanla corpus'lar, yapısal çeşitliliği düşük **neredeyse kopyalarla** dolar. Aşırı minimizasyon yararlı bağlamı ortadan kaldırabilir; bu nedenle pratik bir uzlaşma, **minimum token eşiğine ulaşıldığında duran** grammar-aware minimizasyondur (gürültüyü azaltırken mutation'a elverişli kalması için yeterli çevre yapısını korumak).<sup>[[1]](#references)</sup>

Mutasyonel fuzzing için pratik bir corpus kuralı şudur: büyük bir neredeyse-kopya yığını yerine, **coverage'ı en üst düzeye çıkaran ve yapısal olarak farklı az sayıda seed'i tercih edin**. Uygulamada bu genellikle şunları ifade eder.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (herkese açık corpus'lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Her geçerli örneği saklamak yerine **coverage tabanlı corpus minimizasyonu** uygulayın.
- Mutasyonların çoğu çevrimini ilgisiz byte'lara harcamak yerine anlamlı alanlara denk gelmesi için seed'leri **yeterince küçük** tutun.
- Önemli harness/instrumentation değişikliklerinden sonra corpus minimizasyonunu yeniden çalıştırın; çünkü erişilebilirlik değiştiğinde “en iyi” corpus da değişir.

## Büyük Üretilmiş Programlar ve Timeout Yanlılığı

Compiler ve interpreter fuzzing'de bir girdinin yeni bir parser dalına ulaşması değil, **üretilen kod boyutu eşiğini** aşması gerekebilir. V8 [exception-handler offset örneğinde](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), kesilmiş handler offset'inin önem kazanması için geçerli bir testcase'in 256 MiB'tan fazla bytecode içermesi gerekiyordu. Tekrarlanan `yield*` yapıları bu sınıra ulaşabiliyordu, ancak testcase'i derlemek debug build'de saniyeler sürüyordu. Küçük girdileri tercih etmek ve kısa execution timeout'ları belirlemek, grammar coverage yüksek olsa bile bu sınıftaki girdileri dezavantajlı hâle getirebilir. Packed offset'leri veya uzunluğa duyarlı diğer metadata'yı denetlerken boyut eşiklerini ve timeout politikasını ayrı ayrı değerlendirin; bu campaign önerisi, raporlanan başarısızlık biçiminden çıkarılmıştır.<sup>[[29]](#references)</sup>

## Magic Value'lar İçin Comparison-Aware Mutation

Fuzzer'ların ilerlemesinin durmasının yaygın bir nedeni sözdizimi değil, **katı karşılaştırmalardır**: magic byte'lar, uzunluk kontrolleri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da art arda yapılan karşılaştırmalarla korunan parser dispatch değerleri. Tamamen rastgele mutation, bu değerleri byte byte tahmin etmeye çalışırken çevrimleri boşa harcar.

Bu hedeflerde **comparison tracing** kullanın (örneğin AFL++ `CMPLOG` / Redqueen tarzı iş akışları). Böylece fuzzer, başarısız karşılaştırmalardaki operand'ları gözlemleyebilir ve mutation'ları bu karşılaştırmaları karşılayan değerlere yönlendirebilir.<sup>[[3]](#references)</sup>

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

- Bu, özellikle hedef derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasında tuttuğunda işe yarar.
- Gerçek örneklerden, protokol belirtimlerinden veya debug loglarından çıkarılan **dictionaries** ile birlikte kullanın. Grammar token’ları, chunk adları, fiiller ve ayraçlar içeren küçük bir dictionary, çoğu zaman devasa ve genel bir wordlist’ten daha değerlidir.
- Hedef art arda birçok kontrol yapıyorsa, önce en baştaki “magic” karşılaştırmalarını çözün; ardından sonraki aşamaların zaten geçerli öneklerle başlaması için ortaya çıkan corpus’u yeniden minimize edin.

## Dosya API’lerinde Gizli Bir Dosya Adı Dilini Fuzzing Etme

`filename`, `path` veya `URL` adlı bir parametre, doğrudan dosya aramak yerine bir interpreter giriş noktası olabilir. Örneğin CFITSIO Extended Filename Syntax (EFS), açılan nesneyi döndürmeden önce köşeli parantez içindeki seçicileri, satır/piksel ifadelerini, hesaplanan sütunları, histogramları ve dönüşümleri değerlendirir; bazı biçimler geçici kopyalar da oluşturur. Attack surface haritalaması sırasında her open/import API’sini **literal-path** veya **interpreted-path** olarak sınıflandırın ve uygulamaların gerçekten çağırdığı production entry point’i fuzzing’e tabi tutun.<sup>[[20]](#references)[[22]](#references)</sup>

Ortaya çıkan SSRF, dosya kopyalama ve protocol handler primitive’leri ile daha güvenli literal-path API’leri için bkz. [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Temel nesneyi fuzz edilen programdan ayrı tutun

Grammar bir dosya adı sonekinde bulunuyorsa, yalnızca başvurulan dosyanın baytlarını değiştirmek parser’ı hedeflemez. Bunun yerine küçük bir harness, her testcase’i string olarak okuyup interpreted open API’ye aktarabilir; CFITSIO kampanyası, `fits_open_file()` işlevini salt okunur modda çağırarak EFS parser’larının ve değerlendiricilerinin çoğuna ulaştı. Değişikliklerin temel yolu sürekli bozmak yerine seçici/ifade diline odaklanabilmesi için geçerli temel dosyaları ayrı olarak hazır bulundurun.<sup>[[22]](#references)</sup>

Her biri farklı bir grammar ailesine ulaşan seed’ler kullanın; ardından hem belirtimden hem de lexer/parser kaynak kodundan kompakt bir dictionary oluşturun. Coverage aynı sözdizimi hatası yolunda tekrar tekrar başarısız olan girdiler nedeniyle duraklarsa, yalnızca random-mutation süresini artırmak yerine geçerli önekleri koruyup ayraçlar, operatörler, anahtar sözcükler, işlev adları ve örnek alan adları ekleyin.<sup>[[22]](#references)</sup>

Örneğin grammar dictionary ile harness’i çalıştırın:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "read-only" harness yan etkilerini kontrol altına alma

Bir kütüphane için read-only bayrağı, testcase'in yan etkisiz olacağını garanti etmez: dosya adı dili girdiyi yeniden yazabilir, çıktı dosyaları oluşturabilir veya geçici nesneleri belleğe alabilir. CFITSIO kampanyası başlangıçta seed dosyalarını yok etti ve dosya sisteminde beklenmedik dosyalar bıraktı; bu nedenle temizlik ve izolasyon gerekti.<sup>[[22]](#references)</sup>

- Her worker'a geçici bir çalışma dizini ve özel bir geçici dizin verin.
- Kanonik backing dosyalarının kopyalarını sunun; hedefin corpus'taki tek kopyayı değiştirmesine asla izin vermeyin.
- Uzak back-end'ler hedeflenmiyorsa ağ erişimini devre dışı bırakın ve yazılabilir yolları bir container, mount namespace veya eşdeğer bir sandbox ile kısıtlayın.
- Her çalıştırmadan veya worker grubundan sonra dizini sıfırlayın ve beklenmedik dosya sistemi değişikliklerini ek bulgular olarak değerlendirin.

### Crash-to-patch-to-fuzz döngüsü

Onarım yapmadan önce crash'leri kümelendirin; binlerce artifact'in binlerce patch görevine dönüşmesini önleyin. CFITSIO değerlendirmesinde AFLTriage, başlangıçtaki crash kümesini birkaç kök nedene indirdi; ortaya çıkan advisory, hatalı hedef boyutu kontrolleri, `realloc()` sonrasında stale pointer'lar, aritmetik hatalar ve güvenli olmayan parser temizleme yolları dahil olmak üzere farklı hataları gösteriyor.<sup>[[21]](#references)[[22]](#references)</sup>

1. Her küme için temsili bir girdiyi küçültün ve AddressSanitizer altında yeniden üretin.
2. Hatanın oluştuğu erişimi, kaynak konumunu, allocation/free geçmişini ve invariant'ı geçersiz kılan parser durumunu kaydedin.
3. Dar kapsamlı tek bir aday patch uygulayın ve aynı coverage ve sanitizer enstrümantasyonuyla yeniden derleyin.
4. Orijinal reproducer'ı **ve kümesindeki her girdiyi** yeniden oynatın; ayrıca leak detection'ı etkinleştirin, çünkü bir memory-safety düzeltmesi hata yolundaki sahipliği bozabilir.
5. Gerçek dosyalarla işlevsel testleri çalıştırın, ardından birikmiş queue'dan devam edin (veya binary değiştikten sonra engine yeni bir çıktı dizini gerektiriyorsa bu queue'yu yeniden içe aktarın).
6. Döngüyü tekrarlayın: ilk yüzeysel crash'i kaldırmak, mevcut seed'lerin daha derin bir parser durumuna ilerlemesini sağlayabilir.

Bir LLM, crashing input, sanitizer raporu, harness ve ilgili kaynak kodu verildiğinde 2. adımı hızlandırabilir ve 3. adım için taslak hazırlayabilir; ancak önerdiği patch güvenilir kabul edilmemelidir. Onarımın kabul edilip edilmeyeceğine modelin açıklaması değil, sanitizer ile yeniden oynatma ve regresyon kontrolleri karar verir.<sup>[[22]](#references)</sup>

## Edge Coverage Farklı Yolları Birbirinden Ayıramadığında Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper üzerinden geçen iki çalıştırmanın farklı caller'lar kullandığını veya bir fonksiyon içindeki farklı branch kombinasyonlarını izlediğini ayıramaz. Bu durum, bir edge'e giden **yolun** etkin durumu belirlediği paylaşılan decoder'larda, protocol dispatcher'larda ve interpreter helper'larında önemlidir. Her calling context'i gelişigüzel izlemek de tehlikelidir: coverage map ve queue kontrolden çıkabilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'ı context-sensitive kabul etmek yerine yalnızca umut vadeden context'leri ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

AFL++'ın yeni sürümleri, normal edge coverage'a ek olarak **fonksiyon başına Ball-Larus path coverage** sağlar. Her fonksiyon içindeki her çevrimsiz yola bir feature atar; loop back-edge'ler kaldırılır, dolayısıyla bu geri bildirim branch kombinasyonlarını ayırt eder ancak **loop iterasyon sayılarını ayırt etmez**. Gevşek `1` seviyesiyle başlayın; yol sayısı üstel olarak artabileceğinden daha katı kipleri şüpheli parser/state-machine koduyla sınırlayın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Birçok güvenlik açısından önemli noktadan çağrılan bir yardımcı için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

**Kampanya yönergesi:** Daha zengin geri bildirimi temkinli biçimde uygulayın ve kapsama haritası/kuyruk maliyetini izleyin.<sup>[[13]](#references)[[14]](#references)</sup>

- Sıradan bir edge-coverage örneğini paralel çalıştırın; daha zengin geri bildirim, yalnızca ek kuyruk/harita maliyeti saniyedeki çalıştırma sayısını düşürmüyorsa faydalıdır.
- Büyük şablon ağırlıklı kitaplıklar veya genel amaçlı yardımcı kod haritaya hâkim olduğunda, path/caller enstrümantasyonunu kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda döngüsüz yola sahip işlevler AFL++ tarafından atlanabilir; derleme sırasındaki uyarılar, hedefin allowlisting'e veya daha az katı bir düzeye ihtiyaç duyduğunu gösterir.
- Caller + path coverage yalnızca tek bir caller derinliğini destekler. Bunu daha derin context stack'leriyle birleştirmeyin.
- Path ID'leri LLVM ana sürümleri arasında değişebilir. Bir kampanya boyunca araç zincirini sabit tutun ve özellik ID'leri derlemeler arasında kararlıymış gibi PATH tabanlı corpus'ları senkronize etmeyin.
- Bu geri bildirim `CMPLOG`'u tamamlar: karşılaştırma izleme, **bir guard'dan hangi değerin geçtiğini** çözerken path/caller geri bildirimi **hangi rota ve dal birleşiminin o noktaya ulaştığını** korur.

## Stateful Fuzzing: Diziler Seed'dir

**Protokoller**, **kimlik doğrulamalı iş akışları** ve **çok aşamalı parser'lar** için ilgi çekici birim genellikle tek bir blob değil, bir **mesaj dizisidir**. Tüm dökümü tek bir dosyada birleştirip gelişigüzel mutasyona uğratmak genellikle verimsizdir; çünkü fuzzer her adımı eşit biçimde mutasyona uğratır, oysa kırılgan duruma yalnızca sonraki mesaj ulaşıyor olabilir.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **dizinin kendisini seed** olarak ele almak ve **gözlemlenebilir durumu** (yanıt kodları, protokol durumları, parser aşamaları, döndürülen nesne türleri) ek geri bildirim olarak kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli önek mesajlarını** sabit tutun ve mutasyonları **geçişi sağlayan** mesaja odaklayın.
- Sonraki adımın önceki yanıtlara bağlı olduğu durumlarda, tanımlayıcıları ve sunucu tarafından üretilen değerleri önbelleğe alın.
- Serileştirilmiş dökümün tamamını opak bir blob olarak mutasyona uğratmak yerine, mesaj başına mutasyon/birleştirme yöntemini tercih edin.
- Protokol anlamlı yanıt kodları sunuyorsa, daha derine ilerleyen dizilere öncelik vermek için bunları **ucuz bir durum oracle'ı** olarak kullanın.

Kimlik doğrulamalı hataların, gizli geçişlerin veya “yalnızca el sıkışmasından sonra” ortaya çıkan parser hatalarının vanilla dosya tarzı fuzzing ile sıklıkla gözden kaçmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sıralamayı, durumu ve bağımlılıkları** da korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: çok istemcili driver fuzzing

Yüksek edge coverage bile IPC driver hatalarını gözden kaçırabilir; çünkü coverage **nesne sahipliğini, referans sayaçlarını, bekleyen mesajları, temizleme sırasını veya iş parçacığı zamanlamalarını** açıklamaz. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfasında driver nesne modeli ele alınır; bu örnek ise fuzzer harness'ine odaklanır. Android Binder yararlı bir modeldir: fuzzer birden fazla sürecin aynı kernel nesnesi üzerinde gereken sırayla işlem yapmasını sağlayamıyorsa, ayırma ve serbest bırakma yollarının ikisine de ulaşmak yeterli değildir.<sup>[[15]](#references)</sup>

#### Yalıtılmış `ioctl` buffer'ları yerine protokolü modelleyin

Bir test örneğini **istemci kimliği + işlem + yapılandırılmış argümanlardan** oluşan sıralı bir gramer olarak temsil edin. Binder LKL fuzzer'ı, bir kalıcı context-manager istemcisi ve iki sıradan istemciyle birlikte protobuf ve `libprotobuf-mutator` kullanır. Ardından anlamsal bir harness, kör bayt mutasyonunun bozacağı ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki işlemlerin döndürdüğü değerleri önbelleğe alın. Örneğin `BC_FREE_BUFFER`, önceki bir `ioctl` tarafından döndürülen işlem arabelleği işaretçisini yeniden kullanmalıdır.
- Eşzamanlı işlemlerin tamamlanmasını ve sonraki işlemlere erişilebilmesini sağlamak için geçerli varsayılan yanıtlar üretin.
- Kendi kendine işlem veya aynı hedefe yönelik birden fazla bekleyen işlem gibi imkânsız geçişleri reddedin.
- Tekil başlangıç durumunu girdi başına sıfırlamanın dışında tutun. Binder, her açılışta yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; bu nedenle istemciyi tekrar tekrar yok edip yeniden oluşturmak sonraki girdileri geçersiz kılar.

Yararlı bir ömür yarışı şablonunda, bir istemciye nesne aktartın, iş parçacığı veya süreç temizliğini başlatın ve alıcı istemcinin işlem arabelleğini serbest bırakmasını eşzamanlı olarak sağlayın. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` işleminin `BC_FREE_BUFFER` ile yarışması, çıkan iş parçacığının temizleme yolu hâlâ kullanırken gömülü bir `binder_work` nesnesini serbest bırakabiliyordu.<sup>[[15]](#references)</sup>

#### Userspace kernel'de kontrollü zamanlamaları yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness'ine bağlar ve syscall arayüzünü `lkl_syscall` üzerinden sunar. Bu sayede protobuf durumu, coverage ve KASAN tek bir süreçte kolayca koordine edilebilir. Ancak LKL, normalde bir syscall'ı başka bir kernel iş parçacığının kesintisine uğratmadan çalıştırır. Yarış kampanyaları için belirli kilitleme/kilidi açma ve ömür sınırlarının çevresine `schedule()` noktaları ekleyin; ardından her yield noktasında sıradaki istemciyi harness'in rastgele seçmesini sağlayın. Bu noktaları hedefli tutun; çünkü her biri zamanlama arama uzayını çarpar. Araştırmacıların tanımladığı rastgele zamanlayıcı, upstream Binder fuzzer'ının **parçası değildir**.<sup>[[15]](#references)</sup>

#### Serileştirilmiş regresyon seed'leri oluşturun ve yeniden oynatın

Upstream harness, uyumlu bir `libprotobuf-mutator` sürümünü sabitler, `LKL_FUZZING=1` ile LKL fuzzing enstrümantasyonunu ve KASAN'ı etkinleştirir, ayrıca Binder için `MMU=1` ile `CONFIG_MMU`'yu etkinleştirir.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Upstream'de belgelenen rollback yamalarını uyguladıktan veya bilerek güvenlik açığı bulunan bir revizyonu kontrol ettikten sonra, serileştirilmiş bir seed, durumu geçici bir C proof of concept içinde baştan oluşturmaya gerek kalmadan çok istemcili durum geçişinin tamamını yeniden üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free, seed'in savunmasız lifetime path'e ulaştığını doğrular. Ancak bu, kernel'de kod yürütme veya ayrıcalık yükseltme için gereken sonraki primitive'leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makineli Çeşitlilik Hilesi (Jackalope-Style)

**Generative novelty** ile **coverage reuse** yöntemlerini hibritleştirmenin pratik bir yolu, kalıcı bir server'a karşı kısa ömürlü worker'ları yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, yeniden senkronize olur ve ardından çıkar. Böylece biriken coverage'dan yararlanırken her nesilde **yeni yapılar** elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` her üretimde **yeni bir corpus** oluşturur.
- `-server_update_interval T`, yaklaşık olarak **gecikmeli senkronizasyonu** sağlar (önce yenilik, sonra yeniden kullanım).
- Grammar fuzzing modunda **başlangıç sunucu senkronizasyonu varsayılan olarak atlanır** (`-skip_initial_server_sync` gerekmez).
- En uygun `T` **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Zor Harness Edilen Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda ancak **yüksek maliyetli bir hazırlık adımından sonra** (VM başlatma, giriş yapma, paket alma, container ayrıştırma, servis başlatma) erişilebiliyorsa, kullanışlı bir alternatif **snapshot fuzzing** yöntemidir: hazır süreç veya VM durumunu kaydedin, her test case'i hedefin input yoluna enjekte edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem, başlatma veya protokol öneklerini tekrar etmeyi önler; **network servisleri**, **firmware**, **kimlik doğrulama sonrası saldırı yüzeyleri** ve **yalnızca binary olarak sunulan hedefler** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. İlgi çekici durum hazır olana kadar hedefi çalıştırın.
2. O noktadaki **bellek + register** durumunun snapshot'ını alın.
3. Her test case için mutate edilmiş input'u doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde destekleniyorsa yalnızca **değişmiş sayfaları** geri yükleyin ve tekrarlayın.

Snapshot'ı mümkün olduğunca ilk maliyetli parse/dispatch adımına yakın bir noktaya, örneğin `recv`/`read` işleminden veya paket serileştirmesinin çözüldüğü noktadan sonraya yerleştirin ve hedefin kullandığı input buffer'ını kaydedin. Bu, tekrarlanan işi önlemek için snapshot'ı input işleme sürecinin daha ilerisine taşıma yönündeki uyarlanabilir yerleştirme ilkesini izler.<sup>[[11]](#references)</sup>

### Protokol durumları için artımlı snapshot'lar

Sabit bir snapshot hazırlık maliyetini önler, ancak birden fazla geçerli mesaj gerektiren geçişleri kendi başına keşfetmez. LibAFL-Qemu harness'i, protokol durumu alanına yapılan yazmaları izleyip durum değiştiğinde yeni bir snapshot kaydedebilir. [libslirp TCP harness'inde](https://github.com/quarkslab/slirp_snapshots_stateful), `tcpcb.t_state` izlenir; snapshot'ları tekilleştirmek için durum ve yanıt flag'leri hash'lenir ve değişmiş sayfalar bir üst snapshot'a göre saklanır. Sonraki yapılandırılmış mesaj mutate edilmeden önce seçilen snapshot, üst snapshot zinciri üzerinden geri yüklenir. Test case, bir `SnapshotId` ve üretilen input baytlarını (`gen_bytes`) tutar; snapshot yöneticisi ise replay için gereken üst-alt ilişkisini izler.<sup>[[27]](#references)[[28]](#references)</sup>

LibAFL-Qemu'nun user-mode `SnapshotModule`'ü mapping'leri ve hedef belleğini kaydeder, ancak CPU register'larını kaydetmez; gerektiğinde bunları ayrıca koruyun. Açıklanan yönetici tek bir kök snapshot ağacını destekler ve snapshot ID'lerini worker'lar arasında paylaşamaz. Ayrıca multi-snapshot modu, QASAN shadow state'ini doğrudan yeniden kullanamaz. Offline triage için input zincirini ayrı bir instrumented süreçte yeniden oluşturun. `AsanHostModule` ve `DrCovModule` kullanılırken, `fuzzer.evaluate_input` gerekli `pre_exec`/`post_exec` callback'lerini çalıştırır; tek başına `qemu.run` bunu yapmaz.<sup>[[27]](#references)[[28]](#references)</sup>

### Mantıksal ring buffer overread'lerini yakalama

Bir buffer'ın *geçerli veri sayısını* aşan bir okuma, host allocation sınırları içinde kalıp sıradan ASAN'den kaçabilir. [libslirp urgent-data örneği](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) ayrıca işaretsiz bir byte sayacının underflow'una neden olur. Kaynak kodu mevcutsa, signed/unsigned integer overflow instrumentation bu yan etkiyi tespit edebilir; raporları bastırmadan önce kasıtlı TCP sequence-number wrap durumlarını ayırt edin. Daha güçlü, önerilen bir oracle; custom ring allocation'ı poison etmek, dahili allocator ilerledikçe yalnızca geçerli aralıkların poison'unu kaldırmak ve serbest bırakılan aralıkları yeniden poison etmektir. LibAFL-Qemu, kaynak kodu instrumentation'ının pratik olmadığı hedefler için bir ASAN poisoning API'si sunar.<sup>[[27]](#references)</sup>

## MAccConc ile Linux Kernel Race Keşfi

[MAccConc](https://github.com/googleprojectzero/MAccConc), zamanlamaya duyarlı Linux kernel race durumlarını tekrarlanabilir bellek erişimi sıralamalarına dönüştürür. İki context içeren **A-B-A** yürütmelerini otomatik olarak sıralayabilir veya analistin terminal UI/GUI üzerinden sıralama kısıtları belirlemesine olanak tanır. Bu, eksiksiz bir concurrency fuzzer'dan ziyade deneysel bir araştırma aracıdır: şu anda LLVM 23+ ve projenin yamalanmış kernel'ini gerektirir, command-line araçları iki test thread'ini destekler ve önerilen userspace fuzzing katmanı henüz uygulanmamıştır.<sup>[[17]](#references)[[18]](#references)</sup>

### Context'ler arası iletişim noktalarını toplama

Instrumented kernel'i KASAN outline callback'leri ve yamalanmış KCOV memory-record desteğiyle derleyin. Projenin README dosyası ayrıca, call stack'lerin kullanılabilir kalması için sibling-call optimization'ın devre dışı bırakılmasını önerir.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`), instrumented erişimleri helper çağrılarına dönüştürür. MAccConc kernel yamaları, ardışık erişimlerin birleştirilmemesi için `asan-opt-same-temp` özelliğini devre dışı bırakır; global değişken yarışlarının görünür olması gerektiğinde `asan-opt-globals` optimizasyonunu da devre dışı bırakın. KCOV, ortaya çıkan kayıtları userspace'e taşır. Farklı yürütme bağlamlarındaki erişimleri karşılaştırın ve bayt aralıkları çakışan, en az bir tarafı yazma yapan çiftleri tutun; yaşam süresi geçişlerini de aday hâline getirmek için `kfree()` işlemini yazma olarak modelleyin.<sup>[[17]](#references)</sup>

Başlatan task'tan çıkan işler (ör. paket işleme veya RCU callback'leri) için alt sistem, bir KCOV remote-coverage handle'ını iletmelidir. Upstream remote KCOV varsayılan olarak etkin değildir ve isteğe bağlıdır; keyfî arka plan işleri için otomatik olarak kullanılamaz. Bu nedenle iletimin yapılmaması, gerçek bir etkileşimin görünmez kalmasına yol açabilir.<sup>[[17]](#references)[[19]](#references)</sup>

### Her çalıştırmada aynı dinamik erişimi belirleme

Her tahsisten sonra değişebilen somut bir heap adresine veya `memcpy()` ve `spin_lock()` gibi helper'ların içinde belirsiz olan yalnızca bir instruction adresine göre yeniden oynatmayın. MAccConc, **count-augmented stack trace** kullanır: her frame, bir callee'yi ve caller'ı içindeki çağrılma sayısını tanımlar; son öğe ise bellek erişimi instruction'ını tanımlar. SanitizerCoverage function-entry/exit kayıtları, userspace'in bu dinamik tanımlayıcıyı yeniden oluşturmasını sağlar. Tanımlayıcı, adres değişikliklerine ve ilgisiz control-flow gürültüsüne rağmen sabit kalır.<sup>[[17]](#references)</sup>

### Aday çiftleri zorunlu schedule'lara dönüştürme

Yamalanmış `KCOV_SET_DI` ioctl'ı, count-augmented erişim tanımlayıcısını bir shared-flag eylemiyle ilişkilendirir.<sup>[[17]](#references)</sup>

| Eylem | Anlamı |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Seçilen erişimden hemen önce *N* bayrağını ayarlar. |
| `DI_STACK_WAIT` | Seçilen erişimden önce, *N* bayrağı ayarlanana veya yapılandırılmış limit dolana kadar bekler. |
| `DI_STACK_WAKE_POST` | Seçilen erişimden hemen sonra *N* bayrağını ayarlar. |

Kısmi bir **A-happens-before-B** kısıtı için A'ya `DI_STACK_WAKE_POST`, B'ye ise aynı bayrağı kullanarak `DI_STACK_WAIT` ekleyin. Tam olarak belirtilmiş iki bağlamlı bir schedule için B'yi önce bloklayın; ardından A, ilk aktarım noktasında B'yi uyandırsın ve beklesin. B, bir sonraki aktarım noktasında işlemin tersini yapsın. Bu yöntem deterministik context switching gibi çalışır ve otomatik A-B-A gezgininin kullandığı yöntemdir.<sup>[[17]](#references)</sup>

En basit kampanyada, dört hook'lu test senaryosunu (`test_setup`, iki thread function ve `test_end`) shared library olarak derleyin, kısıtlanmamış bir trace toplayın ve ardından A-B-A adaylarını sıralayın ya da şüpheli erişimlerin çevresine manuel kısıtlar ekleyin.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeout'ları başarılı yeniden sıralamalardan ayrı değerlendirin: İstenen bir sıra, bir kilit veya başlatma/yayımlama bağımlılığı ikinci bağlamın injection noktasına ulaşmasını engellediği için mümkün olmayabilir. KASAN'ın kör noktalarını da göz önünde bulundurun: doğrudan stack erişimleri, out of bounds olma ihtimali yoksa genellikle hook'lanmaz; varsayılan optimizasyonla globals kapsam dışı kalır ve mevcut derleyiciler ASAN ile TSAN hook'larını aynı anda üretemez. Ayrıca prototip, guest panic yaptığında KCOV buffer'ını kaybeder; bu nedenle bağımsız bir crash console/oracle bulundurun.<sup>[[17]](#references)</sup>

Gelecekteki concurrency-guided fuzzing için her input veya syscall için memory-access özetleri kaydedin, cross-context communication point oluşturabilecek işlemleri eşleştirin ve ardından yalnızca bu kombinasyonları keşfedin. VM snapshot'ları global state'i ve adresleri sabitler; snapshot yoksa allocation-site metadata, çalıştırmalar arasındaki nesneleri soyutlayabilir. Bu, mevcut MAccConc userspace araçlarının bir özelliği değil, önerilen bir genişletmedir.<sup>[[17]](#references)</sup>

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign durakladığında sorun çoğu zaman mutator değil, **harness**'tır. Fuzz target'ınızdan statik olarak erişilebilen ancak dinamik olarak nadiren veya hiç kapsanmayan işlevleri bulmak için **erişilebilirlik/kapsama içgörüsünden** yararlanın. Bu işlevler genellikle üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness, target'a çok geç veya çok erken giriyordur.
- Seed corpus'ta bütün bir özellik ailesi eksiktir.
- Target için, aşırı büyük ve “her şeyi yapan” tek bir harness yerine gerçekten **ikinci bir harness** gerekiyordur.

OSS-Fuzz / ClusterFuzz tarzı iş akışları kullanıyorsanız Fuzz Introspector, statik erişilebilirliği çalışma zamanı kapsamıyla karşılaştırabilir ve zaman sınırlı bir çalıştırmadan veya herkese açık corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak, test edilmemiş bir parser yolu için yeni bir harness eklemeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük giriş noktalarına bölmeye karar verin.

## Graph-First Fuzz Target Selection And Mutation Triage

Elinizde **statik analiz bulguları**, **mutasyon testi sonuçları** ve **coverage raporları** varsa, bunları birbirinden bağımsız listeler olarak değerlendirmeyin. Önce bir **call graph** oluşturun; düğümleri **cyclomatic complexity**, **entrypoint/denetimsiz girdiye erişilebilirlik** ve harici bulgularla etiketleyin, ardından graph üzerinden sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Denetimsiz girdiden erişilebilen, karmaşıklığı yüksek fonksiyonlar hangileri?
- Hangi mutasyon testinden sağ çıkanlar, parser/handler'lardan güvenlik açısından kritik koda giden yollar üzerinde bulunuyor?
- Hangi fonksiyonlar mimari darboğazlar ve olağan dışı derecede yüksek **blast radius** değerine sahip?

Bu yaklaşım genellikle "en düşük coverage" ölçütünden daha iyi fuzz target'lar ortaya çıkarır. **Yüksek karmaşıklığa** ve doğrulanmış **harici erişilebilirliğe** sahip bir parser/decoder, zayıf coverage'a sahip ancak saldırgan denetimindeki bir yoldan erişilemeyen yalıtılmış bir dahili yardımcı fonksiyondan daha iyi bir harness adayıdır.

### Pratik önceliklendirme iş akışı

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına karmaşıklık/dal metriklerini çıkarın.
2. Saldırgan denetimindeki girdileri kabul eden **entrypoint**'leri belirleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'ları.
3. Erişilebilir saldırı yüzeyini ölü/dahili koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara giden **path query**'leri çalıştırın.
4. Aşağıdaki özellikleri bir arada taşıyan düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - denetimsiz girdiden doğrulanmış **erişilebilirlik**
   - yüksek **blast radius** veya çok sayıda bağımlı düğüm
   - **SARIF** bulguları, audit notları veya mutasyon testi sonuçları gibi destekleyici kanıtlar
5. Önce en yüksek puan alan düğümler için, özellikle hex/Base64/IP/message decoder'ları gibi **parser/codec**'ler için odaklı harness'ler yazın.

### Mutasyon testinden sağ çıkanlar: eşdeğer mi, eyleme geçirilebilir mi?

Mutasyon testi genellikle gürültülü bir sağ kalanlar listesi üretir. Her sağ kalanı bir güvenlik açığı olarak değerlendirmeden önce graph'ı kullanarak şunları sorun:

- Mutasyona uğratılan fonksiyona saldırgan denetimindeki bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılan kontrolden daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm ölü kodda, yalnızca biçimlendirme yapan mantıkta mı, yoksa etkisi yüksek bir aritmetik/parser yolunda mı bulunuyor?

Erişilemez veya yapısal olarak kısıtlanmış kalan sağ kalanlar genellikle **eşdeğer mutant**'lardır. **Erişilebilir** kalan ve **sınır koşullarına**, **overflow/carry yollarına** ya da güvenlik açısından kritik **aritmetik/parsing** işlemlerine dokunan sağ kalanlar şu çalışmalara dahil edilmelidir:

- yeni fuzz harness'leri
- doğrudan property/invariant testleri
- hedefli edge-case vektörleri

### Harici bulguları graph üzerinde ilişkilendirin

SAST pipeline'ınız **SARIF** dışa aktarıyorsa, bulguları **dosya + satır aralığı** üzerinden graph düğümlerine eşleyin ve etkinin kapsamını genişletmek için graph'ı kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius** değerini hesaplayın
- bulgunun herhangi bir entrypoint yolunda bulunup bulunmadığını kontrol edin
- aynı darboğazda birleşen yakındaki bulguları kümelendirin

Bu yaklaşım, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken yararlıdır: **erişilebilir**, **karmaşık** ve zaten **SAST bulguları** bulunan bir düğüm, saldırgan yolu olmayan yalnızca karmaşık bir düğümden genellikle daha iyi bir hedeftir.

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

Önemli metodoloji kesişimdir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve değişmezleri zorlaması gerektiğine karar vermek için mutasyondan sağ çıkan girdileri inceleyin.<sup>[[5]](#references)</sup>

## Kriptografik anahtar kodlamalarında differential fuzzing

Geçerli serileştirilmiş anahtarlardan veya standart test vektörlerinden başlayın. Import ve işlem yollarına ulaşmak için gerekli uzunluk ve yapıyı bozmadan kodlanmış alanları mutasyona uğratın, ardından aynı baytları birbirinden bağımsız implementasyonlara gönderin. Kabul durumlarını ve hataları karşılaştırın. Rastgeleleştirilmiş imzalar ve şifreli metinler için bayt bayt karşılaştırma değil, doğruluk oracle'ları gerekir: imzaları doğrulayın veya encapsulation/decapsulation gidiş dönüşündeki paylaşılan sırları karşılaştırın. Test vektörleri bilinen durumlar için uygunluğu gösterir; differential mutation ise bunların ötesindeki hatalı kodlamaları sınar.<sup>[[23]](#references)[[26]](#references)</sup>

Bu anahtar biçimleri için biçime özgü oracle'lar kullanın:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA genişletilmiş imzalama anahtarları:** Anahtarın parse edilebilirliğini koruyarak paketlenmiş `s1` veya `s2` katsayılarını `[-η, η]` aralığının dışına çıkaracak şekilde değiştirin. Import veya imzalama işleminin bunu reddedip reddetmediğini ve ortaya çıkan imzalardan herhangi birinin doğrulanıp doğrulanmadığını kontrol edin. Yalnızca kabul farklılıkları standart ihlali sayılmaz; çünkü FIPS 204 ek özel anahtar kontrollerini zorunlu kılmaz. Bkz. [koşullu sızıntı mekanizması](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM anahtar çiftleri:** Encapsulation anahtarı ve decapsulation girdisi için gereken kontrolleri, içe aktarılan bir çift üzerindeki isteğe bağlı çift tutarlılığı kontrolünden (PCT) ayırın. Açık anahtarıyla encapsulate edin, özel anahtarıyla decapsulate edin ve paylaşılan sırları karşılaştırın; uyuşmazlık, tek tek anahtarlar girdi kontrollerinden geçse bile şifreli iletişimi bozabilir. API'nin girdileri işlem sırasında mı yoksa ayrı bir çağrıyla mı doğruladığını kontrol edin; libcrux `validate_public_key(pk)` ve `validate_private_key(sk, ct)` işlevlerini sunar, ancak bunlar PCT'nin yerini almaz.
- **XMSS/XMSSMT ham anahtarları:** Yalnızca bellekteki anahtarlarla yapılan işlemleri değil, parametre kümeleri arasında serileştirilmiş **imzalama ve doğrulama** anahtarlarının gidiş dönüşünü de sınayın. XMSS ve XMSSMT'nin dört baytlık OID ad alanları ayrıdır; bu nedenle önce XMSS'yi deneyen, yalnızca OID'ye bakan bir parser, çakışan bir XMSSMT anahtarını yanlış sınıflandırıp içe aktarmayı reddedebilir. Bildirilen RustCrypto parser sorunu, imza sahteciliğini değil, birlikte çalışabilirlik/kullanılabilirlik hatasını örnekler.

## gosentry ile Go Fuzzing: Daha Güçlü Motor, Tipli Girdiler ve Differential Checks

Bir Go hedefinde yerel `testing.F` harness'i zaten varsa, pratik bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` desteğini koruyan ancak arka ucu **LibAFL** ile değiştiren, çatallanmış bir Go toolchain'dir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, native Go fuzzer **zor karşılaştırmalarda**, **tipli girdilerde** veya **ayrıştırıcı ağırlıklı biçimlerde** takıldığında kullanışlıdır. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i yeniden kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan campaign'i normal bir coverage-guided çalışma olarak ele alın; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanın.

### Sessiz hataları fuzzing bulgularına dönüştürün

Go değerlendirmelerinde sık karşılaşılan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash** oluşturmamasıdır. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` seçili logging/error yollarını crash gibi davranacak şekilde ayarlar (aksi durumda yalnızca log yazıp devam eden `log.Fatal` tarzı kod yolları için kullanışlıdır).
- `--catch-races=true` yeni keşfedilen queue entry'lerini Go race detector ile yeniden çalıştırır.
- `--catch-leaks=true` yeni queue entry'lerini `goleak` ile yeniden çalıştırır ve goroutine leak'lerinde durur.
- LibAFL hang işleme özelliği, **sonsuz döngüleri / çok yavaş girdileri** timeout olarak kaybolmalarına izin vermek yerine fuzzing bulgusu olarak tutar.
- Varsayılan olarak yerleşik aritmetik taşma kontrolleri ve go-panikint tarzı enstrümantasyon aracılığıyla isteğe bağlı truncation kontrolleri.

Bu, güvenlik etkisinin bellek bozulmasından ziyade **panic oluşturmayan bir ayrıştırıcı hatası**, **eşzamanlılık hatası** veya yalnızca **DoS'a yol açan bir takılma** olduğu hedefler için özellikle değerlidir.

### Tipli Go API'leri için struct-aware fuzzing

Native Go fuzzing temel olarak `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen kod tipli nesneler kullanıyorsa gosentry, alttaki byte'ları mutasyona uğratırken **bileşik değerleri** (struct'lar, slice'lar, array'ler, pointer'lar) doğrudan fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu yalnızca fuzzing için sahte bir wire formatı oluştururken kullanmak, mantık hatalarını yalnızca harness'te bulunan ayrıştırma kodunun arkasında gizler. Differential veya grammar-based kampanyalar için harness girdisini tek bir `[]byte` veya `string` olarak tutun ve bunun yerine callback içinde ayrıştırın.

### Parser'lar ve protokol girdileri için grammar-based fuzzing

Parser'lar, formatlar ve girdi dilleri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, üretim kurallarından oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Byte-level mutations çoğunlukla erken sözdizimi denetimlerinde başarısız oluyorsa grammar mode kullanın.
- Grammar'ı, dilin/protokolün tamamını modellemek yerine **güvenlikle ilgili alt kümesine** odaklı tutun.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminallerde/terminal olmayanlarda büyük sınır değerleri kullanın.
- Grammar mode girdileri grammar'a uygun tutar, ancak hedef yine de **byte/string** alır; bu nedenle ayrıştırma ve semantik denetimler harness edilen kod içinde kalır.

### Differential fuzzing: yalnızca çökmeleri değil, implementasyonları karşılaştırın

Go ekosistemlerinde etkili bir yöntem, **grammar-based differential fuzzing** kullanmaktır: geçerli yapılandırılmış girdiler üretip bunları iki parser'a, istemciye veya durum geçişi motoruna göndermek.<sup>[[7]](#references)[[8]](#references)</sup>

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
- kabul edilen/reddedilen girdiler uyuşmuyor
- ayrıştırma ağaçları veya çözümlenen nesneler farklı
- durum geçişleri, nonce'lar, bakiyeler veya durum kökleri farklılaşıyor

Bu, saf crash fuzzing'in çoğunlukla gözden kaçırdığı **consensus uyuşmazlıklarını**, **parser belirsizliğini** ve **spec ile uygulama arasındaki sapmaları** bulmanın pratik bir yoludur.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Kapsam raporlaması için campaign corpus'u yeniden kullanın

Bir campaign'den sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go kapsam raporu oluşturmak için kaydedilmiş kuyruk corpus'unu yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Aynı package içinden ve aynı `-fuzz` hedefiyle komutu çalıştırın; böylece gosentry doğru önbelleğe alınmış campaign state'i çözümler.

## References

- [1] [Mutasyonel grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing Derinlemesine](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [Beş Yıl Sonra AFLNet: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu graflara dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç takımının yarısından yoksundu. Düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar Kullanarak Stateful Network Protocols için Hızlı Bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar Yoksa Sorun Değil: System-Call Tanımları Olmadan Linux Kernel Fuzzing'e Doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Uyarlanabilir ve Değiştirilebilir Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Öngörülü Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build ve regression-seed belgeleri](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kontrollü Memory-Access Interleavings ile Linux Kernel Race Condition'larını İncelemek](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing için code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Genişletilmiş Dosya Adı Sözdizimi](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Danışma Bülteni: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Genişletilmiş Dosya Adı Sözdiziminin Fuzzing'i: 16 Memory-Safety Vulnerability ve Codex Destekli Triyaj](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Kriptografi için Differential Fuzzing](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [XMSSMT OID ayrıştırma hatası - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Post-Quantum Cryptography Uygulamalarının Durumu](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Snapshot Alma Yöntemiyle CVE-2026-9539'a Ulaşmak](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzer'lar ve AI: JavaScript Engine'lerinde Fuzzilli ve BigSleep Karşılaştırması](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
