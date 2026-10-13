# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutasyonel Grammar Fuzzing: Coverage ve Semantics

**Mutasyonel grammar fuzzing** sırasında input'lar, **grammar'a uygun** kalacak şekilde mutate edilir. Coverage-guided modda yalnızca **yeni coverage** sağlayan örnekler corpus seed'i olarak saklanır. **Dil hedeflerinde** (parser'lar, interpreter'lar, engine'ler) bu yaklaşım, bir yapının çıktısının başka bir yapının input'u olduğu **semantik/dataflow zincirleri** gerektiren bug'ları gözden kaçırabilir.<sup>[[1]](#references)</sup>

**Hata biçimi:** fuzzer, `document()` ve `generate-id()` (veya benzer primitive'ler) yapılarını ayrı ayrı çalıştıran seed'ler bulur ancak **zincirlenmiş dataflow'u korumaz**. Bu nedenle “bug'a daha yakın” örnek, coverage'ı artırmadığı için elenir. **3 veya daha fazla bağımlı adımda** rastgele yeniden birleştirme maliyetli hâle gelir ve coverage feedback aramaya yön vermez.<sup>[[1]](#references)</sup>

**Çıkarım:** bağımlılık ağırlıklı grammar'lar için **mutasyonel ve generative aşamaları hibrit hâle getirmeyi** veya üretimi yalnızca coverage'a değil, **function chaining** kalıplarına da yönlendirmeyi değerlendirin.<sup>[[1]](#references)</sup>

## Corpus Çeşitliliğiyle İlgili Tuzaklar

Coverage-guided mutation **açgözlüdür**: yeni coverage sağlayan örnek hemen saklanır ve çoğu zaman değişmemiş geniş bölgeleri de korur. Zamanla corpus'lar, yapısal çeşitliliği düşük **neredeyse kopyalarla** dolar. Aşırı minimization yararlı bağlamı kaldırabilir; bu nedenle pratik bir uzlaşma, **minimum token eşiğine ulaşıldığında duran** grammar-aware minimization uygulamaktır (gürültüyü azaltırken mutation'a elverişli olacak kadar çevre yapıyı korumak).<sup>[[1]](#references)</sup>

Mutasyonel fuzzing için pratik bir corpus kuralı: **çok sayıda neredeyse kopya yerine coverage'ı en üst düzeye çıkaran, yapısal açıdan farklı az sayıda seed'i tercih edin**. Pratikte bu genellikle şunları gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

- **Gerçek dünya örnekleriyle** başlayın (herkese açık corpus'lar, crawling, yakalanmış trafik, hedef ekosistemden dosya kümeleri).
- Geçerli her örneği saklamak yerine, **coverage tabanlı corpus minimization** ile örnekleri eleyin.
- Mutasyonların çoğu çevrimini ilgisiz byte'lara harcamak yerine anlamlı alanlara denk gelmesi için seed'leri **yeterince küçük** tutun.
- Büyük harness/instrumentation değişikliklerinden sonra corpus minimization'ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Magic Value'lar İçin Karşılaştırma Farkındalıklı Mutation

Fuzzer'ların takılmasının yaygın nedenlerinden biri syntax değil, **kesin karşılaştırmalardır**: magic byte'lar, uzunluk kontrolleri, enum string'leri, checksum'lar veya `memcmp`, switch table'ları ya da ardışık karşılaştırmalarla denetlenen parser dispatch değerleri. Tamamen rastgele mutation, bu değerleri byte byte tahmin etmeye çalışırken çevrimleri boşa harcar.

Bu hedeflerde, fuzzer'ın başarısız karşılaştırmalardaki operand'ları gözlemleyebilmesi ve mutation'ları bu karşılaştırmaları geçecek değerlere yönlendirebilmesi için **comparison tracing** (örneğin AFL++ `CMPLOG` / Redqueen tarzı iş akışları) kullanın.<sup>[[3]](#references)</sup>

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

- Bu yöntem, hedef derin mantığı **dosya imzalarının**, **protokol fiillerinin**, **tür etiketlerinin** veya **sürüme bağlı özellik bitlerinin** arkasında tuttuğunda özellikle kullanışlıdır.
- Gerçek örneklerden, protokol belirtimlerinden veya hata ayıklama günlüklerinden çıkarılan **dictionary**'lerle birlikte kullanın. Dilbilgisi belirteçleri, parça adları, fiiller ve ayraçlardan oluşan küçük bir dictionary, genellikle devasa ve genel amaçlı bir wordlist'ten daha değerlidir.
- Hedef art arda birçok kontrol yapıyorsa, önce en erken “magic” karşılaştırmalarını çözün; ardından sonraki aşamaların zaten geçerli öneklerle başlaması için ortaya çıkan corpus'u yeniden küçültün.

## Dosya Adı Dilini Gizleyen Dosya API'lerini Fuzzing

`filename`, `path` veya `URL` adlı bir parametre, dosyayı doğrudan aramak yerine bir yorumlayıcı giriş noktası olabilir. Örneğin, CFITSIO Extended Filename Syntax (EFS), açılan nesneyi döndürmeden önce köşeli parantez içindeki seçicileri, satır/piksel ifadelerini, hesaplanan sütunları, histogramları ve dönüşümleri değerlendirir; bazı biçimler geçici kopyalar da oluşturur. Saldırı yüzeyini haritalarken her açma/ içe aktarma API'sini **literal-path** veya **interpreted-path** olarak sınıflandırın ve uygulamaların gerçekten çağırdığı üretim giriş noktasını fuzzing'e tabi tutun.<sup>[[20]](#references)[[22]](#references)</sup>

Ortaya çıkan SSRF, dosya kopyalama ve protokol işleyicisi primitive'leri ile daha güvenli literal-path API'leri için bkz. [SSRF/dosya primitive'leri olarak dosya adı mini dilleri](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Destek nesnesini fuzz edilen programdan ayrı tutun

Dilbilgisi bir dosya adı sonekinde bulunuyorsa, yalnızca başvurulan dosyanın baytlarını değiştirmek ayrıştırıcıyı gözden kaçırır. Bunun yerine küçük bir harness, bir testcase'i dize olarak okuyup yorumlanan açma API'sine iletebilir; CFITSIO kampanyası `fits_open_file()` işlevini salt okunur modda çağırarak EFS ayrıştırıcılarının ve değerlendiricilerinin çoğuna ulaştı. Değişikliklerin temel yolu sürekli bozmaması ve seçici/ifade diline odaklanabilmesi için geçerli destek dosyalarını ayrı tutun.<sup>[[22]](#references)</sup>

Her biri farklı bir dilbilgisi ailesine ulaşan seed'ler kullanın, ardından hem belirtimden hem de lexer/ayrıştırıcı kaynak kodundan derli toplu bir dictionary oluşturun. Girdiler aynı sözdizimi hatası yolunda tekrar tekrar başarısız olurken coverage artmıyorsa, rastgele değişiklik süresini artırmak yerine geçerli önekleri koruyup ayraçlar, işleçler, anahtar sözcükler, işlev adları ve temsili alan adları ekleyin.<sup>[[22]](#references)</sup>

Örneğin, dilbilgisi dictionary'siyle harness'i çalıştırın:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### "Read-only" harness yan etkilerini kontrol altına alma

Salt okunur bir library flag'i, testcase'in yan etki oluşturmayacağını garanti etmez: filename dili girdiyi yeniden yazabilir, output dosyaları oluşturabilir veya geçici nesneleri belleğe alabilir. CFITSIO kampanyası başlangıçta seed dosyalarını yok etti ve dosya sisteminde beklenmedik dosyalar bıraktı; bu nedenle temizlik ve izolasyon gerekliydi.<sup>[[22]](#references)</sup>

- Her worker'a kullanılıp atılabilir bir çalışma dizini ve özel bir geçici dizin verin.
- Kanonik backing dosyaların kopyalarını sunun; target'ın corpus'taki tek kopyayı değiştirmesine asla izin vermeyin.
- Remote backend'ler hedeflenmiyorsa ağ erişimini devre dışı bırakın ve yazılabilir yolları bir container, mount namespace veya eşdeğer bir sandbox ile kısıtlayın.
- Her çalıştırmadan veya worker batch'inden sonra dizini sıfırlayın ve beklenmedik dosya sistemi değişikliklerini ek bulgular olarak değerlendirin.

### Crash-to-patch-to-fuzz döngüsü

Onarım öncesinde crash'leri kümelere ayırın; böylece binlerce artifact binlerce patch görevine dönüşmez. CFITSIO değerlendirmesinde AFLTriage, ilk crash kümesini birkaç kök nedene indirdi; ortaya çıkan advisory'de hedef boyutunun hatalı denetlenmesi, `realloc()` sonrasında stale pointer'lar, aritmetik hatalar ve güvenli olmayan parser temizleme yolları dahil olmak üzere farklı hatalar gösteriliyor.<sup>[[21]](#references)[[22]](#references)</sup>

1. Her küme için temsili bir girdiyi minimize edin ve AddressSanitizer altında yeniden üretin.
2. Hatanın oluştuğu erişimi, kaynak konumunu, allocation/free geçmişini ve invariant'ı geçersiz kılan parser durumunu kaydedin.
3. Dar kapsamlı tek bir aday patch uygulayın ve aynı coverage ve sanitizer enstrümantasyonuyla yeniden derleyin.
4. Orijinal reproducer'ı **ve kümesindeki her girdiyi** yeniden oynatın; bellek güvenliği düzeltmesi bir error path'teki ownership'i bozabileceğinden leak detection'ı da etkinleştirin.
5. Gerçek dosyalarla functional test'leri çalıştırın, ardından birikmiş queue'dan devam edin (veya binary değiştikten sonra engine yeni bir output directory gerektiriyorsa queue'yu yeniden içe aktarın).
6. Tekrarlayın: İlk yüzeysel crash'i gidermek, mevcut seed'lerin daha derin bir parser durumuna ilerlemesini sağlayabilir.

Bir LLM, crashing input, sanitizer report, harness ve ilgili kaynak kodu verildiğinde 2. adımı hızlandırabilir ve 3. adım için taslak hazırlayabilir; ancak patch'ine güvenilmemelidir. Onarımın kabul edilip edilmeyeceğine modelin açıklaması değil, sanitizer replay'i ve regression kontrolleri karar verir.<sup>[[22]](#references)</sup>

## Edge Coverage Farklı Yolları Birleştirdiğinde Daha Zengin Geri Bildirim

Normal edge coverage, aynı helper'dan geçen iki çalıştırmayı veya bir function içindeki farklı branch kombinasyonlarını ayırt edemez. Bu durum, bir edge'e giden **yolun** canlı durumu belirlediği paylaşılan decoder'larda, protocol dispatcher'larda ve interpreter helper'larında önemlidir. Her calling context'i gelişigüzel izlemek de tehlikelidir: coverage map'i ve queue aşırı büyüyebilir. Bu nedenle context-sensitive fuzzing araştırmaları, tüm call graph'i context-sensitive ele almak yerine yalnızca umut vadeden context'leri ayrıntılandırmayı önerir.<sup>[[14]](#references)</sup>

AFL++'ın güncel build'leri, normal edge coverage'a ek olarak **function başına Ball-Larus path coverage** sunar. Bir function içindeki her acyclic path için bir feature atar; loop back-edge'ler kaldırılır, dolayısıyla bu geri bildirim branch kombinasyonlarını ayırt eder, ancak **loop yineleme sayılarını ayırt etmez**. Gevşek `1` seviyesiyle başlayın, ardından path sayısı üstel olarak artabileceğinden daha katı modları şüpheli parser/state-machine kodlarıyla sınırlayın.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Güvenlikle ilgili birçok noktadan çağrılan bir yardımcı için LTO modu, her işlev yolunu doğrudan çağrı noktasıyla birleştirebilir:<sup>[[13]](#references)</sup>

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

- Paralelde sıradan bir edge-coverage instance çalıştırın; zengin feedback yalnızca ek queue/map maliyeti saniyedeki execution sayısını düşürmüyorsa yararlıdır.
- Büyük template ağırlıklı library'ler veya genel amaçlı utility kodu map'e hâkim olduğunda path/caller instrumentation'ı kısıtlamak için `AFL_LLVM_ALLOWLIST` kullanın.
- Aşırı sayıda acyclic path içeren function'lar AFL++ tarafından atlanabilir; derleme sırasındaki uyarılar, hedefin allowlisting'e veya daha az katı bir seviyeye ihtiyaç duyduğunu gösterir.
- Caller + path coverage yalnızca tek bir caller depth destekler. Bunu daha derin context stack'leriyle birleştirmeyin.
- Path ID'leri LLVM major version'ları arasında değişebilir. Bir campaign boyunca toolchain'i sabit tutun ve PATH tabanlı corpus'ları feature ID'leri derlemeler arasında sabitmiş gibi synchronize etmeyin.
- Bu feedback, `CMPLOG`'u tamamlar: comparison tracing **bir guard'dan hangi değerin geçtiğini** çözerken, path/caller feedback **hangi route ve branch kombinasyonunun oraya ulaştığını** korur.

## Stateful Fuzzing: Sequence'ler Seed'dir

**Protocol**'ler, **authenticated workflow**'lar ve **çok aşamalı parser**'lar için ilginç birim çoğu zaman tek bir blob değil, bir **message sequence**'tir. Tüm transcript'i tek bir dosyaya birleştirip gelişigüzel mutate etmek genellikle verimsizdir; çünkü fuzzer her step'i eşit şekilde mutate eder, oysa kırılgan state'e yalnızca sonraki message ulaşıyor olabilir.<sup>[[4]](#references)</sup>

Daha etkili bir yaklaşım, **sequence'in kendisini seed** olarak ele almak ve ek feedback olarak **gözlemlenebilir state**'leri (response code'ları, protocol state'leri, parser phase'leri, döndürülen object type'ları) kullanmaktır.<sup>[[4]](#references)</sup>

- **Geçerli prefix message**'ları sabit tutun ve mutation'ları **geçişi sağlayan** message'a odaklayın.
- Sonraki step önceki response'lardaki değerlere bağlıysa identifier'ları ve server tarafından oluşturulan değerleri cache'leyin.
- Serileştirilmiş transcript'in tamamını opaque bir blob olarak mutate etmek yerine, message başına mutation/splicing kullanmayı tercih edin.
- Protocol anlamlı response code'ları sunuyorsa, daha derine ilerleyen sequence'lere öncelik vermek için bunları **ucuz bir state oracle** olarak kullanın.

Authenticated bug'ların, gizli geçişlerin veya “yalnızca handshake sonrasında” görülen parser bug'larının vanilla file-style fuzzing ile sıklıkla kaçırılmasının nedeni de budur: fuzzer yalnızca yapıyı değil, **sırayı, state'i ve bağımlılıkları** da korumalıdır.<sup>[[4]](#references)</sup>

### Android Binder: multi-client driver fuzzing

Yüksek edge coverage, yine de IPC-driver bug'larını kaçırabilir; çünkü coverage **object ownership, reference count'lar, bekleyen message'lar, cleanup sırası veya thread interleaving'leri** hakkında bilgi vermez. [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) sayfası driver object model'ini ele alır; bu örnek ise fuzzer harness'ine odaklanır. Android Binder yararlı bir modeldir: fuzzer birden fazla process'in aynı kernel object üzerinde gereken sırayla çalışmasını sağlayamıyorsa, hem allocation hem de free path'lerine ulaşmak yeterli değildir.<sup>[[15]](#references)</sup>

#### Tekil `ioctl` buffer'ları yerine protocol'ü modelleyin

Bir test case'i **client identity + operation + yapılandırılmış argument**'lardan oluşan sıralı bir grammar olarak temsil edin. Binder LKL fuzzer'ı protobuf ve `libprotobuf-mutator` kullanır; bir persistent context-manager client'ı ve iki ordinary client'ı vardır. Semantic harness, kör byte mutation'ın bozacağı ilişkileri korur.<sup>[[15]](#references)</sup>

- Önceki operation'lardan dönen değerleri cache'leyin. Örneğin, `BC_FREE_BUFFER` önceki bir `ioctl`'un döndürdüğü transaction-buffer pointer'ını yeniden kullanmalıdır.
- Synchronous transaction'ların tamamlanabilmesi ve sonraki operation'lara erişilebilmesi için geçerli varsayılan reply'ler üretin.
- Self-transaction veya aynı target'a birden fazla pending transaction gibi imkânsız geçişleri reddedin.
- Singleton bootstrap state'ini her input'ta yapılan reset'in dışında tutun. Binder, boot başına yalnızca bir `BINDER_SET_CONTEXT_MGR` kaydına izin verir; bu client'ı sürekli yok edip yeniden oluşturmak sonraki input'ları geçersiz kılar.

Yararlı bir lifetime-race şablonu, bir client'ın object aktarmasını, thread veya process cleanup'ını başlatmasını ve alıcı client'ın transaction buffer'ını eşzamanlı olarak serbest bırakmasını sağlamaktır. CVE-2020-0423 örneğinde, `BINDER_TYPE_WEAK_BINDER` aktarımının ardından `BINDER_THREAD_EXIT` ile `BC_FREE_BUFFER`'ın yarışması, çıkan thread'in cleanup path'i hâlâ kullandığı sırada gömülü bir `binder_work`'ün serbest bırakılmasına yol açabiliyordu.<sup>[[15]](#references)</sup>

#### Userspace kernel'de kontrollü interleaving'leri yeniden oluşturun

[Linux Kernel Library (LKL)](https://github.com/lkl/linux), gerçek kernel kodunu bir userspace harness'ine bağlar ve syscall interface'ini `lkl_syscall` üzerinden sunar. Böylece protobuf state, coverage ve KASAN'ı tek bir process'te kolayca koordine edebilirsiniz. Ancak LKL normalde bir syscall'ı başka bir kernel thread'i kesintiye uğratmadan çalıştırır. Race campaign'leri için seçili lock/unlock ve lifetime sınırlarına `schedule()` noktaları ekleyin, ardından her yield'de sıradaki client'ı harness'in rastgele seçmesini sağlayın. Her nokta scheduling search space'i katladığından, bu noktaları hedefe yönelik seçin. Araştırmacıların tanımladığı randomized scheduler, upstream Binder fuzzer'ının bir parçası **değildir**.<sup>[[15]](#references)</sup>

#### Serileştirilmiş regression seed'leri derleyin ve yeniden oynatın

Upstream harness, uyumlu bir `libprotobuf-mutator` sürümünü sabitler; `LKL_FUZZING=1` ile LKL fuzzing instrumentation ve KASAN'ı, `MMU=1` ile Binder için `CONFIG_MMU`'yu etkinleştirir.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Bilerek güvenlik açığı içeren bir revizyonu checkout ettikten veya upstream'de belgelenen rollback yamalarını uyguladıktan sonra, serileştirilmiş bir seed, derme çatma bir C proof of concept içinde yeniden oluşturmaya gerek kalmadan çok istemcili durum geçişinin tamamını yeniden üretebilir:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Ortaya çıkan KASAN use-after-free, seed'in savunmasız yaşam süresi yoluna ulaştığının doğrulaması olarak değerlendirin. Bu, kernel kodu yürütme veya yetki yükseltme için gereken sonraki primitive'leri göstermez.<sup>[[16]](#references)</sup>

## Tek Makinede Çeşitlilik Hilesi (Jackalope Tarzı)

**Üretken yeniliği** **coverage yeniden kullanımıyla** hibritleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı kısa ömürlü worker'ları **yeniden başlatmaktır**. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleştirilmiş corpus üzerinde `T` saniye daha çalışır, tekrar senkronize olur ve ardından çıkar. Böylece biriken coverage'dan yararlanırken her nesilde **yeni yapılar** elde edilir.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty`, her üretimde **yeni bir corpus** oluşturulmasını sağlar.
- `-server_update_interval T`, **gecikmeli sync** davranışını yaklaşık olarak sağlar (önce yenilik, sonra yeniden kullanım).
- Grammar fuzzing modunda **başlangıç sunucu sync'i varsayılan olarak atlanır** (`-skip_initial_server_sync` gerekmez).
- En uygun `T` değeri **hedefe bağlıdır**; worker “kolay” coverage'ın çoğunu bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Zor Harness Edilebilen Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz koda yalnızca **büyük bir kurulum maliyetinden sonra** (VM başlatma, oturum açma işlemini tamamlama, paket alma, container ayrıştırma, hizmet başlatma) erişilebiliyorsa, **snapshot fuzzing** kullanışlı bir alternatiftir: hazır süreç veya VM durumunu yakalayın, her test case'i hedefin girdi yoluna enjekte edin, crash/timeout gerçekleşene kadar çalıştırın ve snapshot'ı geri yükleyin. Bu yöntem başlatma veya protokol öneklerini tekrarlama ihtiyacını ortadan kaldırır ve **network services**, **firmware**, **post-auth attack surfaces** ve **binary-only targets** için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

1. Hedefi, ilgi duyulan durum hazır olana kadar çalıştırın.
2. Bu noktada **memory + registers** snapshot'ı alın.
3. Her test case için, değiştirilmiş girdiyi doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset gerçekleşene kadar çalıştırın.
5. Snapshot'ı geri yükleyin; VM hedeflerinde destekleniyorsa yalnızca **dirty pages** öğelerini geri yükleyin, ardından tekrarlayın.

Snapshot'ı, `recv`/`read` işleminden veya paketin deserialization noktasından sonra olduğu gibi, mümkün olduğunca ilk maliyetli parse/dispatch adımına yakın bir yere yerleştirin ve hedefin kullandığı input buffer'ı kaydedin. Bu yaklaşım, tekrarlanan işi önlemek için snapshot'ı girdi işleme akışında daha derine taşıma yönündeki adaptif yerleştirme ilkesini izler.<sup>[[11]](#references)</sup>

## MAccConc ile Linux Kernel Race Keşfi

[MAccConc](https://github.com/googleprojectzero/MAccConc), zamanlamaya duyarlı Linux kernel race koşullarını tekrarlanabilir memory-access schedule'larına dönüştürür. İki context içeren **A-B-A** yürütmelerini otomatik olarak sıralayabilir veya analistin terminal UI/GUI üzerinden sıra kısıtları belirlemesine olanak tanır. Bu, eksiksiz bir concurrency fuzzer değil, deneysel bir araştırma aracıdır: şu anda LLVM 23+ ve projenin yamalı kernel'ini gerektirir, command-line araçları iki test thread'ini destekler ve önerilen userspace fuzzing katmanı henüz uygulanmamıştır.<sup>[[17]](#references)[[18]](#references)</sup>

### Context'ler arası iletişim noktalarını toplama

Enstrümante edilmiş kernel'i KASAN outline callback'leri ve yamalı KCOV memory-record desteğiyle derleyin. Proje README'si ayrıca call stack'lerin kullanılabilir kalması için sibling-call optimization'ı devre dışı bırakmayı önerir.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`), enstrümante edilmiş erişimleri helper çağrılarına dönüştürür. MAccConc kernel yamaları, ardışık erişimlerin birleştirilmemesi için `asan-opt-same-temp` seçeneğini devre dışı bırakır; global değişken yarışlarının görünür olması gerekiyorsa `asan-opt-globals` optimizasyonunu da devre dışı bırakın. KCOV, oluşan kayıtları userspace'e taşır. Farklı yürütme bağlamlarındaki erişimleri karşılaştırın ve bayt aralıkları örtüşen, en az bir tarafı yazma yapan çiftleri tutun; yaşam süresi geçişlerini de aday hâline getirmek için `kfree()` işlemini yazma olarak modelleyin.<sup>[[17]](#references)</sup>

Başlatıcı task'tan taşan işler (paket işleme veya RCU callback'leri gibi) için alt sistemin bir KCOV remote-coverage handle'ı aktarması gerekir. Upstream remote KCOV isteğe bağlıdır ve rastgele arka plan işleri için otomatik olarak kullanılamaz; bu nedenle aktarımın yapılmaması gerçek bir etkileşimi görünmez kılabilir.<sup>[[17]](#references)[[19]](#references)</sup>

### Her çalıştırmada aynı dinamik erişimi belirleme

Her ayırmadan sonra değişebilecek somut bir heap adresine veya `memcpy()` ve `spin_lock()` gibi helper'ların içindeki talimat adresine göre yeniden oynatmayın; ilki değişebilir, ikincisi ise belirsizdir. MAccConc, **sayıyla zenginleştirilmiş bir stack trace** kullanır: her frame bir callee'yi ve caller'ı içindeki çağrı sayısını tanımlar; son öğe ise bellek erişim talimatını tanımlar. SanitizerCoverage işlev giriş/çıkış kayıtları, userspace'in bu dinamik tanımlayıcıyı yeniden oluşturmasını sağlar. Tanımlayıcı, adres değişikliklerine ve ilgisiz control-flow gürültüsüne rağmen kararlı kalır.<sup>[[17]](#references)</sup>

### Aday çiftleri zorunlu zamanlamalara dönüştürme

Yamalanmış `KCOV_SET_DI` ioctl'ı, sayı ile zenginleştirilmiş bir erişim tanımlayıcısını paylaşılan bir flag eylemiyle ilişkilendirir.<sup>[[17]](#references)</sup>

| Eylem | Anlamı |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Seçilen erişimden hemen önce *N* flag'ini ayarlar. |
| `DI_STACK_WAIT` | Seçilen erişimden önce, *N* flag'i ayarlanana veya yapılandırılmış süre sınırı dolana kadar spin-wait yapar. |
| `DI_STACK_WAKE_POST` | Seçilen erişimden hemen sonra *N* flag'ini ayarlar. |

Kısmi bir **A, B'den önce gerçekleşir** kısıtı için A'ya `DI_STACK_WAKE_POST`, B'ye ise aynı flag'i kullanarak `DI_STACK_WAIT` ekleyin. Tam olarak belirlenmiş iki bağlamlı bir zamanlama için B'yi başlangıçta bloklanmış başlatın; ardından A, ilk aktarım noktasında B'yi uyandırıp beklesin. B de bir sonraki aktarım noktasında bunun tersini yapsın. İkincisi, deterministik bağlam değiştirme gibi çalışır ve otomatik A-B-A gezgininin kullandığı yöntemdir.<sup>[[17]](#references)</sup>

En küçük kampanya, dört hook'lu test senaryosunu (`test_setup`, iki thread işlevi ve `test_end`) paylaşılan bir kütüphane olarak derlemek, kısıtlanmamış bir trace toplamak ve ardından A-B-A adaylarını sıralamak veya şüpheli erişimlere manuel kısıtlar eklemektir.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Zaman aşımlarını başarılı yeniden sıralamalardan ayrı değerlendirin: istenen sıralama, bir kilit veya başlatma/yayımlama bağımlılığı ikinci bağlamın injection noktasına ulaşmasını engellediği için imkânsız olabilir. Ayrıca KASAN'ın kör noktalarını göz önünde bulundurun: doğrudan stack erişimleri, sınırların dışına çıkma olasılığı yoksa genellikle hook'lanmaz; varsayılan optimizasyonla global değişkenler kapsam dışı kalır ve mevcut derleyiciler ASAN ile TSAN hook'larını aynı anda üretemez. Son olarak, prototip bir guest panic yaptığında KCOV buffer'ını kaybeder; bu nedenle bağımsız bir crash console/oracle bulundurun.<sup>[[17]](#references)</sup>

Gelecekteki concurrency-guided fuzzing için girdi veya syscall başına bellek erişimi özetleri kaydedin, context'ler arası iletişim noktaları oluşturabilecek işlemleri eşleştirin ve ardından yalnızca bu kombinasyonları keşfedin. VM snapshot'ları global durumu ve adresleri sabitler; snapshot yoksa allocation-site metadata, nesneleri çalıştırmalar arasında soyutlayabilir. Bu, mevcut MAccConc userspace araçlarının bir özelliği değil, önerilen bir eklentidir.<sup>[[17]](#references)</sup>

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign durduğunda sorun çoğu zaman mutator değil, **harness**'tır. Fuzz target'ınızdan statik olarak erişilebilen ancak dinamik olarak nadiren ya da hiç kapsanmayan işlevleri bulmak için **erişilebilirlik/coverage introspection** kullanın. Bu işlevler genellikle şu üç sorundan birine işaret eder.<sup>[[12]](#references)</sup>

- Harness, target'a çok geç veya çok erken giriyordur.
- Seed corpus'ta bütün bir özellik ailesi eksiktir.
- Target, tek ve aşırı büyük bir “her şeyi yapan” harness yerine gerçekten **ikinci bir harness** gerektiriyordur.

OSS-Fuzz / ClusterFuzz tarzı iş akışları kullanıyorsanız Fuzz Introspector, statik erişilebilirliği çalışma zamanı coverage'ıyla karşılaştırabilir ve süre sınırı belirlenmiş bir çalıştırmadan veya herkese açık bir corpus'tan raporlar oluşturabilir.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Raporu kullanarak test edilmemiş bir parser yolu için yeni bir harness eklemeye, belirli bir özellik için corpus'u genişletmeye veya monolitik bir harness'i daha küçük giriş noktalarına bölmeye karar verin.

## Graph-First Fuzz Target Seçimi ve Mutation Triage

Elinizde **static-analysis bulguları**, **mutation-testing survivor'ları** ve **coverage raporları** varsa bunları birbirinden bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun, düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input erişilebilirliği** ve harici bulgularla etiketleyin, ardından graph üzerinden sorular sorun.<sup>[[5]](#references)[[6]](#references)</sup>

- Hangi yüksek karmaşıklıktaki fonksiyonlara untrusted input'tan erişilebilir?
- Hangi mutation survivor'ları parser/handler'lardan security-critical code'a giden yollarda yer alıyor?
- Hangi fonksiyonlar alışılmadık derecede geniş **blast radius**'a sahip mimari darboğazlar?

Bu yaklaşım genellikle "en düşük coverage" ölçütünden daha iyi fuzz target'ları ortaya çıkarır. **Yüksek karmaşıklığa** ve doğrulanmış **harici erişilebilirliğe** sahip bir parser/decoder, coverage'ı düşük ama saldırganın kontrolündeki bir yol üzerinde olmayan yalıtılmış bir iç yardımcı fonksiyondan daha güçlü bir harness adayıdır.

### Pratik triage iş akışı

1. Codebase'den bir **code graph** oluşturun ve fonksiyon başına karmaşıklık/dal metriklerini çıkarın.
2. Saldırganın kontrolündeki girdileri kabul eden **entrypoint**'leri listeleyin: request handler'lar, decoder'lar, importer'lar, protocol parser'ları, CLI/file reader'lar.
3. Erişilebilir saldırı yüzeyini ölü/kullanılmayan veya yalnızca dahili koddan ayırmak için bu entrypoint'lerden aday fonksiyonlara giden yollar üzerinde **path query** çalıştırın.
4. Aşağıdaki özellikleri bir arada taşıyan düğümlere öncelik verin:
   - yüksek **cyclomatic complexity**
   - untrusted input'tan doğrulanmış **erişilebilirlik**
   - yüksek **blast radius** veya çok sayıda aşağı akış bağımlısı
   - **SARIF** bulguları, audit notları veya mutation survivor'ları gibi destekleyici kanıtlar
5. Özellikle hex/Base64/IP/message decoder'lar gibi **parser/codec**'ler için, en yüksek puanlı düğümlere önce odaklanan harness'ler yazın.

### Mutation survivor'ları: eşdeğer mi, eyleme geçirilebilir mi?

Mutation testing genellikle gürültülü bir survivor listesi üretir. Her survivor'ı bir güvenlik açığı olarak değerlendirmeden önce graph'i kullanarak şunları sorun:

- Mutasyona uğratılan fonksiyona saldırganın kontrolündeki bir entrypoint'ten erişilebiliyor mu?
- Tüm çağrı yolları, mutasyona uğratılan kontrolden daha güçlü invariant'larla kısıtlanıyor mu?
- Düğüm; ölü kodda, yalnızca biçimlendirme mantığında mı, yoksa etkisi yüksek bir aritmetik/parser yolunda mı?

Erişilemez kalan veya yapısal olarak kısıtlanmış survivor'lar genellikle **eşdeğer mutant**'lardır. **Erişilebilir** olan ve **sınır koşullarına**, **overflow/carry yollarına** veya **security-critical aritmetik/parsing** işlemlerine dokunan survivor'lar şu çalışmalara taşınmalıdır:

- yeni fuzz harness'leri
- doğrudan property/invariant testleri
- hedefli uç durum vektörleri

### Harici bulguları graph üzerinde ilişkilendirme

SAST pipeline'ınız **SARIF** çıktısı veriyorsa, bulguları **dosya + satır aralığı** üzerinden graph düğümlerine yansıtın ve etki alanını genişletmek için graph'i kullanın.<sup>[[6]](#references)</sup>

- işaretlenen fonksiyonun **blast radius**'unu hesaplayın
- bulgunun herhangi bir entrypoint yolunda olup olmadığını kontrol edin
- aynı darboğazda birleşen yakındaki bulguları kümeleyin

Bu, belirli bir fonksiyona fuzzing zamanı ayırıp ayırmamaya karar verirken işe yarar: **erişilebilir**, **karmaşık** ve zaten **SAST bulguları** olan bir düğüm, saldırganın izlediği bir yol bulunmayan, yalnızca karmaşık bir düğümden genellikle daha iyi bir hedeftir.

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

Önemli olan metodolojilerin kesişimidir: **karmaşıklık x maruziyet x etki**. En yüksek beklenen güvenlik değerine sahip fuzz hedeflerini seçmek için grafiği kullanın; ardından harness'inizin hangi sınırları ve değişmezleri zorlaması gerektiğine karar vermek için mutasyonlardan sağ çıkanları kullanın.<sup>[[5]](#references)</sup>

## gosentry ile Go Fuzzing: Daha Güçlü Motor, Türlenmiş Girdiler ve Diferansiyel Kontroller

Bir Go hedefinde zaten yerel bir `testing.F` harness'i varsa, uygulanabilir bir yükseltme yolu aynı harness'i [gosentry](https://github.com/trailofbits/gosentry) ile çalıştırmaktır. gosentry, `go test -fuzz` özelliğini koruyan, ancak arka uçta **LibAFL** kullanan çatallanmış bir Go araç zinciridir.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Bu, yerel Go fuzzer'ı **zor karşılaştırmalarda**, **tipli girdilerde** veya **parser ağırlıklı biçimlerde** takıldığında işe yarar. Metodoloji aynı kalır:

- Seed'ler için `f.Add(...)`, callback için `f.Fuzz(...)` kullanmaya devam edin.
- Aynı harness'i kullanın, ancak stock toolchain yerine gosentry'nin `go` binary'siyle çalıştırın.
- Ortaya çıkan kampanyayı normal bir coverage-guided çalıştırma olarak ele alın; ancak LibAFL scheduling/mutation ve daha iyi çevresel detector'lar kullanır.

### Sessiz hataları fuzzing bulgularına dönüştürün

Go değerlendirmelerinde sık karşılaşılan bir sorun, tehlikeli davranışların çoğu zaman varsayılan olarak **crash'e yol açmamasıdır**. gosentry ile çeşitli “kötü ama sessiz” durumları bulguya dönüştürebilirsiniz.<sup>[[7]](#references)[[8]](#references)</sup>

- Seçili logging/error yollarının crash gibi davranmasını sağlamak için `--panic-on=pkg.Func,...` kullanın (aksi hâlde yalnızca log yazıp devam eden `log.Fatal` tarzı kod yolları için yararlıdır).
- Yeni keşfedilen queue girişlerini Go race detector ile yeniden oynatmak için `--catch-races=true` kullanın.
- Yeni queue girişlerini `goleak` ile yeniden oynatıp goroutine leak'lerinde durmak için `--catch-leaks=true` kullanın.
- **Sonsuz döngüleri / çok yavaş girdileri** timeout olarak kaybolmalarına izin vermek yerine fuzzing bulgusu olarak tutmak için LibAFL hang handling özelliğini kullanın.
- Varsayılan olarak yerleşik arithmetic overflow kontrolleri ve go-panikint tarzı instrumentation üzerinden isteğe bağlı truncation kontrolleri.

Bu özellikle, güvenlik etkisinin memory corruption yerine **panic oluşturmayan bir parser hatası**, **concurrency bug'ı** veya yalnızca DoS'a yol açan bir takılma olduğu hedeflerde değerlidir.

### Tipli Go API'leri için struct-aware fuzzing

Yerel Go fuzzing çoğunlukla `[]byte`, `string` ve sayılar gibi scalar'ları bekler. Test edilen kod tipli nesneler kullanıyorsa gosentry, alttaki byte'ları değiştirmeye devam ederken **bileşik değerleri** (struct'lar, slice'lar, array'ler, pointer'lar) doğrudan fuzz edebilir.<sup>[[7]](#references)[[8]](#references)</sup>

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

Bunu, yalnızca fuzzing için sahte bir wire formatı oluşturmanın mantık hatalarını yalnızca harness'te bulunan ayrıştırma kodunun arkasına gizleyeceği durumlarda kullanın. Differential veya grammar-based fuzzing kampanyalarında, harness girdisini tek bir `[]byte` ya da `string` olarak tutun ve bunun yerine callback içinde ayrıştırın.

### Parser'lar ve protokol girdileri için Grammar-based fuzzing

Parser'lar, formatlar ve girdi dilleri için gosentry, LibAFL üzerinde **Nautilus grammar fuzzing** çalıştırabilir. Grammar, üretim kurallarından oluşan bir JSON dizisidir ve harness genellikle tek bir `[]byte` veya `string` argümanı almalıdır.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Metodoloji notları:

- Byte düzeyindeki mutasyonlar çoğunlukla erken sözdizimi kontrollerinde eleniyorsa grammar mode kullanın.
- Grammar'ı dilin/protokolün tamamını modellemek yerine **güvenlik açısından önemli alt kümesine** odaklayın.
- Tamsayı, uzunluk ve durum makinesi sınırlarını zorlamak için terminal/nonterminal'lerde büyük sınır değerleri kullanın.
- Grammar mode girdileri grammar'a uygun tutar, ancak hedef yine de **baytlar/dizeler** alır; dolayısıyla ayrıştırma ve anlamsal kontroller harness içine alınmış kodda çalışmaya devam eder.

### Differential fuzzing: yalnızca çökmeleri değil, implementasyonları karşılaştırın

Go ekosistemlerinde etkili bir yöntem **grammar tabanlı differential fuzzing**'dir: geçerli yapılandırılmış girdiler üretip bunları iki ayrıştırıcıya, istemciye veya durum geçiş motoruna verin.<sup>[[7]](#references)[[8]](#references)</sup>

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

- bir implementasyon panic verirken diğeri girdiyi düzgünce reddediyor
- kabul edilen/reddedilen girdiler arasında uyumsuzluklar
- farklı parse ağaçları veya decode edilmiş nesneler
- farklı durum geçişleri, nonce'lar, bakiyeler veya state root'ları

Bu, saf crash fuzzing'in çoğu zaman gözden kaçırdığı **consensus uyumsuzluklarını**, **parser belirsizliğini** ve **spec ile implementasyon arasındaki sapmaları** bulmak için pratik bir yöntemdir.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Coverage raporlaması için campaign corpus'u yeniden kullanın

Bir campaign'den sonra, ayrı bir corpus'u manuel olarak dışa aktarmadan Go coverage raporu oluşturmak için kaydedilmiş queue corpus'u yeniden oynatın.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Aynı package içinden ve aynı `-fuzz` target'ıyla komutu çalıştırın; böylece gosentry doğru önbelleğe alınmış campaign state'i çözümler.



## References

- [1] [Mutasyonel gramer fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ ile Derinlemesine Fuzzing](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Beş Yıl Sonra: Coverage-Guided Protocol Fuzzing Üzerine](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark kodu graflara dönüştürüyor](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing araç setinin yarısından yoksundu. Düzeltmek için toolchain'i fork ettik.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Snapshot'lar Kullanarak Stateful Network Protocols için Hızlı Bir Greybox Fuzzer](https://arxiv.org/abs/2202.03643)
- [10] [Grammar Olmadan da Sorun Yok: System-Call Descriptions Olmadan Linux Kernel'ı Fuzzing Etmeye Doğru](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Adaptive ve Mutable Snapshot'larla Verimli Fuzzing](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++ LLVM instrumentation: path ve caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL Android Binder fuzzer - build ve regression-seed dokümantasyonu](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Kontrollü Memory-Access Interleavings ile Linux Kernel Race Condition'larını İnceleme](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: fuzzing için code coverage](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [CFITSIO Extended Filename Syntax](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [CFITSIO Extended Filename Syntax'i Fuzzing Etme: 16 Memory-Safety Vulnerability ve Codex Destekli Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
