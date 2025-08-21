# macOS Süreç İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın bir örneğidir, ancak süreçler kod çalıştırmaz, bunlar ipliklerdir. Bu nedenle **süreçler sadece çalışan iplikler için konteynerdir** ve bellek, tanımlayıcılar, portlar, izinler sağlar...

Geleneksel olarak, süreçler diğer süreçler içinde (PID 1 hariç) **`fork`** çağrısı yapılarak başlatılır, bu da mevcut sürecin tam bir kopyasını oluşturur ve ardından **çocuk süreç** genellikle yeni yürütülebilir dosyayı yüklemek ve çalıştırmak için **`execve`** çağrısı yapar. Daha sonra, bu süreci bellek kopyalamadan daha hızlı hale getirmek için **`vfork`** tanıtıldı.\
Ardından **`posix_spawn`** tanıtıldı ve **`vfork`** ile **`execve`**'yi tek bir çağrıda birleştirerek bayraklar kabul etti:

- `POSIX_SPAWN_RESETIDS`: Etkili kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grup bağlantısını ayarla
- `POSUX_SPAWN_SETSIGDEF`: Sinyal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec (daha fazla seçenekle `execve` gibi)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'un Nano ayıracısını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` iznine izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: exec(2) ile varsayılan olarak tüm dosya tanımlarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının yüksek bitlerini rastgeleleştir

Ayrıca, `posix_spawn`, oluşturulan sürecin bazı yönlerini kontrol eden bir **`posix_spawnattr`** dizisi belirtmeye ve tanımlayıcıların durumunu değiştirmek için **`posix_spawn_file_actions`** kullanmaya olanak tanır.

Bir süreç öldüğünde, **geri dönüş kodunu ana sürece** (eğer ana süreç öldüyse, yeni ana süreç PID 1'dir) `SIGCHLD` sinyali ile gönderir. Ana sürecin bu değeri almak için `wait4()` veya `waitid()` çağrısı yapması gerekir ve bu gerçekleşene kadar çocuk bir zombi durumunda kalır; hala listelenir ancak kaynak tüketmez.

### PID'ler

PID'ler, süreç tanımlayıcıları, benzersiz bir süreci tanımlar. XNU'da **PID'ler** **64bit** olup monotonik olarak artar ve **asla sarmaz** (istismarları önlemek için).

### Süreç Grupları, Oturumlar & Koalisyonlar

**Süreçler**, yönetimlerini kolaylaştırmak için **gruplara** yerleştirilebilir. Örneğin, bir kabuk betiğindeki komutlar aynı süreç grubunda olacaktır, böylece örneğin kill kullanarak **birlikte sinyal göndermek** mümkündür.\
Ayrıca süreçleri **oturumlarda gruplamak** da mümkündür. Bir süreç bir oturum başlattığında (`setsid(2)`), çocuk süreçler oturum içinde ayarlanır, aksi takdirde kendi oturumlarını başlatmadıkları sürece.

Koalisyon, Darwin'de süreçleri gruplamanın başka bir yoludur. Bir koalisyona katılan bir süreç, havuz kaynaklarına erişim sağlar, bir defter paylaşır veya Jetsam ile karşılaşır. Koalisyonların farklı rolleri vardır: Lider, XPC hizmeti, Uzantı.

### Kimlik Bilgileri & Kişilikler

Her süreç, sistemdeki **ayrıcalıklarını tanımlayan** **kimlik bilgilerini** taşır. Her süreç birincil bir `uid` ve birincil bir `gid` (birden fazla gruba ait olabilir) olacaktır.\
Ayrıca, ikili dosya `setuid/setgid` bitine sahipse kullanıcı ve grup kimliğini değiştirmek de mümkündür.\
Yeni `uids/gids` ayarlamak için birkaç işlev vardır.

Syscall **`persona`**, **alternatif** bir **kimlik bilgileri** seti sağlar. Bir kişiliği benimsemek, uid'sini, gid'sini ve grup üyeliklerini **bir anda** üstlenmeyi gerektirir. [**kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) yapı bulmak mümkündür:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Thread'ler Temel Bilgileri

1. **POSIX Thread'leri (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'taki pthread'lerin implementasyonu `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur ve bu, kamuya açık `libpthread` projesinden gelmektedir. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli fonksiyonları sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` fonksiyonu kullanılır. İçsel olarak, bu fonksiyon XNU çekirdeğine özgü daha düşük seviyeli bir sistem çağrısı olan `bsdthread_create()`'i çağırır. Bu sistem çağrısı, thread davranışını belirten `pthread_attr`'dan (özellikler) türetilen çeşitli bayrakları alır; bunlar arasında zamanlama politikaları ve yığın boyutu bulunur.
- **Varsayılan Yığın Boyutu:** Yeni thread'ler için varsayılan yığın boyutu 512 KB'dir; bu, tipik işlemler için yeterlidir ancak daha fazla veya daha az alana ihtiyaç varsa thread özellikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` fonksiyonu, thread kurulumu sırasında kritik öneme sahiptir ve yığın konumu ve boyutu hakkında ayrıntıları içerebilecek ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'leri Sonlandırma:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu fonksiyon, bir thread'in temiz bir şekilde çıkmasına olanak tanır, gerekli temizliği yapar ve thread'in herhangi bir katılımcıya geri dönüş değeri göndermesine izin verir.
2. **Thread Temizliği:** `pthread_exit()` çağrıldığında, tüm ilişkili thread yapılarının kaldırılmasını yöneten `pthread_terminate()` fonksiyonu çağrılır. Bu, Mach thread portlarını (Mach, XNU çekirdeğindeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili çekirdek düzeyindeki yapıları kaldıran bir sistem çağrısı olan `bsdthread_terminate`'i çağırır.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve yarış koşullarını önlemek için macOS, birkaç senkronizasyon ilkesini sağlar. Bu, çoklu thread ortamlarında veri bütünlüğünü ve sistem kararlılığını sağlamak için kritik öneme sahiptir:

1. **Mutex'ler:**
- **Normal Mutex (İmza: 0x4D555458):** 60 baytlık bellek ayak izi olan standart mutex (56 bayt mutex için ve 4 bayt imza için).
- **Hızlı Mutex (İmza: 0x4d55545A):** Normal mutex'e benzer ancak daha hızlı işlemler için optimize edilmiştir, boyutu da 60 bayttır.
2. **Koşul Değişkenleri:**
- Belirli koşulların gerçekleşmesini beklemek için kullanılır, boyutu 44 bayttır (40 bayt artı 4 bayt imza).
- **Koşul Değişkeni Özellikleri (İmza: 0x434e4441):** Koşul değişkenleri için yapılandırma özellikleri, boyutu 12 bayttır.
3. **Bir Kez Değişkeni (İmza: 0x4f4e4345):**
- Bir parça başlatma kodunun yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Okuma-Yazma Kilitleri:**
- Aynı anda birden fazla okuyucu veya bir yazar olmasına izin verir, paylaşılan verilere verimli erişimi kolaylaştırır.
- **Okuma Yazma Kilidi (İmza: 0x52574c4b):** Boyutu 196 bayttır.
- **Okuma Yazma Kilidi Özellikleri (İmza: 0x52574c41):** Okuma-yazma kilitleri için özellikler, boyutu 20 bayttır.

> [!TIP]
> Bu nesnelerin son 4 baytı taşmaları tespit etmek için kullanılır.

### Thread Yerel Değişkenler (TLV)

**Thread Yerel Değişkenler (TLV)**, Mach-O dosyaları (macOS'taki yürütülebilir dosyaların formatı) bağlamında, çoklu thread'li bir uygulamada **her thread** için özel olan değişkenleri tanımlamak için kullanılır. Bu, her thread'in bir değişkenin kendi ayrı örneğine sahip olmasını sağlar ve mutex'ler gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemeye ve veri bütünlüğünü korumaya olanak tanır.

C ve ilgili dillerde, bir thread yerel değişkeni tanımlamak için **`__thread`** anahtar kelimesini kullanabilirsiniz. İşte örneğinizde nasıl çalıştığı:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu kesit, `tlv_var`'ı bir thread-local değişken olarak tanımlar. Bu kodu çalıştıran her thread'in kendi `tlv_var`'ı olacak ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler, diğer thread'lerdeki `tlv_var`'ı etkilemeyecektir.

Mach-O ikili dosyasında, thread local değişkenlerle ilgili veriler belirli bölümlere organize edilmiştir:

- **`__DATA.__thread_vars`**: Bu bölüm, thread-local değişkenler hakkında türleri ve başlatma durumları gibi meta verileri içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış thread-local değişkenler için kullanılır. Sıfır ile başlatılmış veriler için ayrılmış bir bellek parçasıdır.

Mach-O ayrıca bir thread çıkarken thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sona erdiğinde thread-local verileri temizleyen **destructor'ları** kaydetmenize olanak tanır.

### Thread Öncelikleri

Thread önceliklerini anlamak, işletim sisteminin hangi thread'lerin ne zaman çalıştırılacağına nasıl karar verdiğine bakmayı içerir. Bu karar, her thread'e atanan öncelik seviyesi tarafından etkilenir. macOS ve Unix benzeri sistemlerde, bu `nice`, `renice` ve Hizmet Kalitesi (QoS) sınıfları gibi kavramlar kullanılarak yönetilir.

#### Nice ve Renice

1. **Nice:**
- Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir nice değeri vardır. Bir süreç oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri ( -20'ye daha yakın) bir süreci daha "bencil" hale getirir ve diğer daha yüksek nice değerine sahip süreçlere kıyasla daha fazla CPU süresi almasını sağlar.
2. **Renice:**
- `renice`, zaten çalışan bir sürecin nice değerini değiştirmek için kullanılan bir komuttur. Bu, süreçlerin önceliğini dinamik olarak ayarlamak için kullanılabilir; yeni nice değerlerine göre CPU zaman tahsisatını artırabilir veya azaltabilir.
- Örneğin, bir sürecin geçici olarak daha fazla CPU kaynağına ihtiyacı varsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Hizmet Kalitesi (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)**'yi destekleyen macOS gibi sistemlerde thread önceliklerini yönetmenin daha modern bir yaklaşımıdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyetlerine göre farklı seviyelere **kategorize** etmelerine olanak tanır. macOS, bu QoS sınıflarına dayalı olarak thread önceliklerini otomatik olarak yönetir:

1. **Kullanıcı Etkileşimli:**
- Bu sınıf, şu anda kullanıcı ile etkileşimde bulunan veya iyi bir kullanıcı deneyimi sağlamak için hemen sonuçlar gerektiren görevler içindir. Bu görevler, arayüzü duyarlı tutmak için en yüksek önceliği alır (örneğin, animasyonlar veya olay işleme).
2. **Kullanıcı Başlatılan:**
- Kullanıcının başlattığı ve hemen sonuç beklediği görevler, örneğin bir belge açma veya hesaplamalar gerektiren bir düğmeye tıklama gibi. Bu görevler yüksek önceliklidir ancak kullanıcı etkileşimli olanların altındadır.
3. **Yardımcı:**
- Bu görevler uzun süreli olup genellikle bir ilerleme göstergesi gösterir (örneğin, dosya indirme, veri içe aktarma). Kullanıcı başlatılan görevlerden daha düşük önceliğe sahiptir ve hemen bitmeleri gerekmez.
4. **Arka Plan:**
- Bu sınıf, arka planda çalışan ve kullanıcıya görünmeyen görevler içindir. Bunlar, dizin oluşturma, senkronizasyon veya yedekleme gibi görevler olabilir. En düşük önceliğe sahiptir ve sistem performansı üzerinde minimal etki yapar.

QoS sınıflarını kullanarak, geliştiricilerin tam öncelik numaralarını yönetmeleri gerekmez, bunun yerine görevin doğasına odaklanırlar ve sistem CPU kaynaklarını buna göre optimize eder.

Ayrıca, zamanlayıcının dikkate alacağı bir dizi zamanlama parametresi belirlemek için farklı **thread zamanlama politikaları** vardır. Bu, `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, yarış durumu saldırılarında faydalı olabilir.

## MacOS Süreç İstismarı

MacOS, diğer işletim sistemleri gibi, **süreçlerin etkileşimde bulunması, iletişim kurması ve veri paylaşması** için çeşitli yöntemler ve mekanizmalar sağlar. Bu teknikler, sistemin verimli çalışması için gerekli olsa da, tehdit aktörleri tarafından **kötü niyetli faaliyetler** gerçekleştirmek için de istismar edilebilir.

### Kütüphane Enjeksiyonu

Kütüphane Enjeksiyonu, bir saldırganın **bir süreci kötü niyetli bir kütüphaneyi yüklemeye zorladığı** bir tekniktir. Enjekte edildikten sonra, kütüphane hedef sürecin bağlamında çalışır ve saldırgana sürecin sahip olduğu izinler ve erişim ile aynı yetkileri sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Fonksiyon Hooking

Fonksiyon Hooking, bir yazılım kodu içindeki **fonksiyon çağrılarını** veya mesajları **yakalamayı** içerir. Fonksiyonları hooklayarak, bir saldırgan bir sürecin **davranışını değiştirebilir**, hassas verileri gözlemleyebilir veya hatta yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Süreçler Arası İletişim

Süreçler Arası İletişim (IPC), ayrı süreçlerin **veri paylaşma ve değiştirme** yöntemlerini ifade eder. IPC, birçok meşru uygulama için temel olsa da, süreç izolasyonunu altüst etmek, hassas bilgileri sızdırmak veya yetkisiz eylemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Uygulamaları Enjeksiyonu

Belirli çevresel değişkenlerle çalıştırılan Electron uygulamaları, süreç enjeksiyonuna karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Enjeksiyonu

`--load-extension` ve `--use-fake-ui-for-media-stream` bayraklarını kullanarak **tarayıcıda adam saldırısı** gerçekleştirmek mümkündür; bu, tuş vuruşlarını, trafiği, çerezleri çalmaya, sayfalara script enjekte etmeye olanak tanır:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Kirli NIB

NIB dosyaları, bir uygulama içindeki **kullanıcı arayüzü (UI) öğelerini** ve etkileşimlerini tanımlar. Ancak, **keyfi komutlar çalıştırabilirler** ve **Gatekeeper**, bir **NIB dosyası değiştirildiğinde** zaten çalıştırılmış bir uygulamanın çalışmasını durdurmaz. Bu nedenle, keyfi programların keyfi komutlar çalıştırmasını sağlamak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Uygulamaları Enjeksiyonu

Belirli java yeteneklerini (örneğin, **`_JAVA_OPTS`** çevresel değişkeni) kötüye kullanarak bir java uygulamasının **keyfi kod/komutlar** çalıştırmasını sağlamak mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Uygulamaları Enjeksiyonu

**.Net hata ayıklama işlevselliğini** (macOS korumaları gibi çalışma zamanı sertleştirmesi tarafından korunmayan) kötüye kullanarak .Net uygulamalarına kod enjekte etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Enjeksiyonu

Bir Perl scriptinin keyfi kod çalıştırmasını sağlamak için farklı seçenekleri kontrol edin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Enjeksiyonu

Ruby çevresel değişkenlerini kötüye kullanarak keyfi scriptlerin keyfi kod çalıştırmasını sağlamak da mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Enjeksiyonu

Eğer çevresel değişken **`PYTHONINSPECT`** ayarlanmışsa, python süreci tamamlandığında bir python cli'ye geçecektir. Ayrıca, etkileşimli bir oturumun başında çalıştırılacak bir python scriptini belirtmek için **`PYTHONSTARTUP`** kullanmak da mümkündür.\
Ancak, **`PYTHONINSPECT`** etkileşimli oturum oluşturduğunda **`PYTHONSTARTUP`** scripti çalıştırılmayacaktır.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer çevresel değişkenler de bir python komutunun keyfi kod çalıştırmasını sağlamak için faydalı olabilir.

**`pyinstaller`** ile derlenmiş yürütülebilir dosyaların, gömülü bir python kullanıyor olsalar bile bu çevresel değişkenleri kullanmayacağını unutmayın.

> [!CAUTION]
> Genel olarak, çevresel değişkenleri kötüye kullanarak python'un keyfi kod çalıştırmasını sağlamak için bir yol bulamadım.\
> Ancak, çoğu insan python'u **Hombrew** kullanarak kurar; bu, python'u varsayılan admin kullanıcı için **yazılabilir bir konuma** kurar. Bunu şöyle ele geçirebilirsiniz:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Ekstra ele geçirme kodu
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Hatta **root** bu kodu python çalıştırırken çalıştıracaktır.

## Tespit

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)), **süreç enjeksiyonu** eylemlerini **tespit edip engelleyebilen** açık kaynak bir uygulamadır:

- **Çevresel Değişkenler Kullanarak**: Aşağıdaki çevresel değişkenlerin varlığını izler: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** ve **`ELECTRON_RUN_AS_NODE`**
- **`task_for_pid`** çağrıları kullanarak: Bir sürecin başka birinin **görev portunu** almak istediğini bulmak için, bu da süreçte kod enjekte etmeye olanak tanır.
- **Electron uygulamaları parametreleri**: Birisi, bir Electron uygulamasını hata ayıklama modunda başlatmak için **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** komut satırı argümanlarını kullanabilir ve böylece ona kod enjekte edebilir.
- **Simli veya sert bağlantılar kullanarak**: Tipik olarak en yaygın istismar, **kendi kullanıcı ayrıcalıklarımızla bir bağlantı yerleştirmek** ve **daha yüksek bir ayrıcalık** konumuna işaret etmektir. Hem sert bağlantı hem de simli için tespit çok basittir. Bağlantıyı oluşturan sürecin hedef dosyadan **farklı bir ayrıcalık seviyesine** sahip olması durumunda bir **uyarı** oluştururuz. Ne yazık ki, simli bağlantılar durumunda engelleme mümkün değildir, çünkü bağlantının oluşturulmasından önce bağlantının varış yeri hakkında bilgiye sahip değiliz. Bu, Apple'ın EndpointSecurity çerçevesinin bir sınırlamasıdır.

### Diğer süreçler tarafından yapılan çağrılar

[**bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) **`task_name_for_pid`** fonksiyonunu kullanarak başka **süreçlerin bir süreçte kod enjekte ettiğini** tespit etmenin nasıl mümkün olduğunu bulabilirsiniz ve ardından o diğer süreç hakkında bilgi alabilirsiniz.

Bu fonksiyonu çağırmak için, süreci çalıştıranla **aynı uid**'ye sahip olmanız veya **root** olmanız gerektiğini unutmayın (ve bu, süreç hakkında bilgi döndürür, kod enjekte etme yolu sağlamaz).

## Referanslar

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{{#include ../../../banners/hacktricks-training.md}}
