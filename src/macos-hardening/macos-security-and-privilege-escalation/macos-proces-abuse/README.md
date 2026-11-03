# macOS Süreçlerinin Kötüye Kullanımı

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir; ancak süreçler kod çalıştırmaz, bunu thread'ler yapar. Dolayısıyla **süreçler, çalışan thread'ler için bellek, tanımlayıcılar, portlar, izinler... sağlayan kapsayıcılardır**.

Geleneksel olarak süreçler (PID 1 hariç) başka süreçlerin içinde, geçerli sürecin tam bir kopyasını oluşturan **`fork`** çağrısıyla başlatılırdı. Ardından **child process**, genellikle yeni yürütülebilir dosyayı yüklemek ve çalıştırmak için **`execve`** çağırırdı. Daha sonra bu süreci bellek kopyalamadan hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`vfork`** ile **`execve`**'i tek bir çağrıda birleştiren ve bayrakları kabul eden **`posix_spawn`** kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu üyeliğini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Varsayılan sinyal davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec et (`execve` gibi, ancak daha fazla seçenekle)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'un Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaymasının yüksek bitlerini rastgeleleştir

Ayrıca `posix_spawn`, başlatılan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç öldüğünde, **dönüş kodunu `SIGCHLD` sinyaliyle üst sürece gönderir** (üst süreç ölmüşse yeni üst süreç PID 1 olur). Üst süreç bu değeri `wait4()` veya `waitid()` çağrısıyla almalıdır; bu gerçekleşene kadar child, listelenmeye devam ettiği ancak kaynak tüketmediği zombie durumunda kalır.

### PID'ler

PID'ler (süreç tanımlayıcıları), benzersiz bir süreci tanımlar. XNU'da **PID'ler** **64 bittir**, monotonik olarak artar ve (kötüye kullanımı önlemek için) **asla başa sarmaz**.

### Süreç Grupları, Oturumlar ve Coalition'lar

**Süreçler**, yönetimi kolaylaştırmak için **gruplara** alınabilir. Örneğin, bir shell script'indeki komutlar aynı süreç grubunda yer alır; böylece örneğin kill kullanarak **hepsine birlikte sinyal göndermek** mümkün olur.\
Süreçleri **oturumlar hâlinde gruplamak** da mümkündür. Bir süreç oturum başlattığında (`setsid(2)`), kendi oturumlarını başlatmadıkları sürece child süreçler bu oturuma yerleştirilir.

Coalition, Darwin'deki süreçleri gruplamanın başka bir yoludur. Bir coalition'a katılan süreç; kaynak havuzlarına erişebilir, bir ledger'ı paylaşabilir veya Jetsam'e maruz kalabilir. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personalar

Her süreç, sistemdeki ayrıcalıklarını **belirleyen kimlik bilgilerini** taşır. Her sürecin birincil `uid` ve birincil `gid` değeri vardır (ancak birden fazla gruba ait olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliğini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli işlevler vardır.

**`persona`** syscall'ı, alternatif bir **kimlik bilgileri** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve grup üyeliklerini **aynı anda** üstlenir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) şu struct bulunabilir:

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

## Thread'ler Hakkında Temel Bilgiler

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'teki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` dosyasında bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak `bsdthread_create()` işlevini çağırır. Bu, XNU kernel'ine (macOS'in temel aldığı kernel) özgü daha düşük seviyeli bir sistem çağrısıdır. Sistem çağrısı, thread davranışını belirleyen ve zamanlama politikaları ile stack boyutunu içeren `pthread_attr` (öznitelikler) kaynaklı çeşitli flag'ler alır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu boyut tipik işlemler için yeterlidir, ancak daha fazla veya daha az alana ihtiyaç duyulursa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında önemlidir; stack'in konumu ve boyutu gibi bilgileri içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'te Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in temiz biçimde çıkmasını, gerekli temizleme işlemlerini yapmasını ve katılmasını bekleyen thread'lere bir dönüş değeri göndermesini sağlar.
2. **Thread Temizleme:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Mach thread portlarını (Mach, XNU kernel'indeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel seviyesindeki yapıları kaldıran bir syscall olan `bsdthread_terminate` işlevini çağırır.

#### Synchronization Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli synchronization primitive'leri sağlar. Bunlar, veri bütünlüğünü ve sistem kararlılığını sağlamak açısından multi-threading ortamlarında kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (Signature: 0x4D555458):** Bellekte 60 byte yer kaplayan standart mutex (mutex için 56 byte ve signature için 4 byte).
   - **Fast Mutex (Signature: 0x4d55545A):** Normal mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir; boyutu da 60 byte'tır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; 44 byte boyutundadır (40 byte artı 4 byte'lık bir signature).
   - **Condition Variable Attributes (Signature: 0x434e4441):** 12 byte boyutundaki condition variable yapılandırma öznitelikleri.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 byte'tır.
4. **Read-Write Lock'lar:**
   - Birden fazla okuyucuya veya aynı anda tek bir yazıcıya izin vererek paylaşılan verilere verimli erişim sağlar.
   - **Read Write Lock (Signature: 0x52574c4b):** 196 byte boyutundadır.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock öznitelikleri; boyutu 20 byte'tır.

> [!TIP]
> Bu nesnelerin son 4 byte'ı overflow'ları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'teki executable dosyalarının biçimi) bağlamında **Thread Local Variables (TLV)**, multi-threaded bir uygulamadaki **her thread'e özgü** değişkenleri tanımlamak için kullanılır. Böylece her thread'in bir değişkenden kendine ait ayrı bir örneği olur. Bu yöntem, mutex gibi açık synchronization mekanizmalarına gerek duymadan çakışmaları önlemeye ve veri bütünlüğünü korumaya yardımcı olur.

C ve ilgili dillerde, thread-local bir değişkeni **`__thread`** anahtar sözcüğünü kullanarak tanımlayabilirsiniz. Örneğinizde işleyişi şöyledir:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu snippet, `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary'sinde thread-local değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölümde thread-local değişkenlere ait türleri ve başlatılma durumları gibi metadata bulunur.
- **`__DATA.__thread_bss`**: Açıkça başlatılmamış thread-local değişkenler için kullanılır. Bellekte sıfırla başlatılan veriler için ayrılmış bir alandır.

Mach-O, bir thread sona erdiğinde thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API de sağlar. Bu API, thread sona erdiğinde thread-local verileri temizleyen özel işlevler olan **destructor'ları kaydetmenize** olanak tanır.

### Thread Öncelikleri

Thread önceliklerini anlamak için işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmak gerekir. Bu karar, her thread'e atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla yürütülür.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir nice değeri vardır. Bir süreç oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
   - Daha düşük bir nice değeri (-20'ye daha yakın), sürecin daha "bencil" davranmasına ve nice değeri daha yüksek olan diğer süreçlere kıyasla daha fazla CPU zamanı almasına neden olur.
2. **Renice:**
   - `renice`, çalışmakta olan bir sürecin nice değerini değiştirmek için kullanılan bir komuttur. Yeni nice değerlerine bağlı olarak CPU zamanı tahsisini artırmak veya azaltmak için süreçlerin önceliklerini dinamik biçimde ayarlayabilir.
   - Örneğin, bir süreç geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde thread önceliklerini yönetmek için daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre farklı kategorilere **ayırmasına** olanak tanır. macOS, thread önceliklerini bu QoS sınıflarına göre otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla etkileşim hâlinde olan veya iyi bir kullanıcı deneyimi sunmak için hemen sonuç gerektiren görevler içindir. Arayüzün yanıt vermeye devam etmesi için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açmak veya hesaplama gerektiren bir düğmeye tıklamak gibi, kullanıcının başlattığı ve hemen sonuç beklediği görevlerdir. Öncelikleri yüksektir ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Uzun süren ve genellikle ilerleme göstergesi sunan görevlerdir (ör. dosya indirme veya veri içe aktarma). Öncelikleri kullanıcı tarafından başlatılan görevlerden düşüktür ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Kullanıcıya görünmeden arka planda çalışan görevler içindir. Dizin oluşturma, senkronizasyon veya yedekleme gibi görevler buna örnektir. En düşük önceliğe sahiptirler ve sistem performansına etkileri azdır.

QoS sınıflarını kullanan geliştiricilerin kesin öncelik numaralarını yönetmesi gerekmez; bunun yerine görevin niteliğine odaklanabilirler. Sistem de CPU kaynaklarını buna göre en uygun biçimde kullanır.

Ayrıca, zamanlayıcının dikkate alacağı bir dizi zamanlama parametresi belirtmek için kullanılan farklı **thread zamanlama ilkeleri** vardır. Bunlar `thread_policy_[set/get]` kullanılarak ayarlanabilir. Bu, race condition saldırılarında yararlı olabilir.

## macOS Process Abuse

macOS, **süreçlerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar sistemin normal çalışması için gerekli olsa da saldırganlar bunları injection, code execution veya veri erişimi amacıyla kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir library yüklemeye zorladığı** bir tekniktir. Enjekte edilen library, hedef sürecin bağlamında çalışır ve saldırgana süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodundaki işlev çağrılarını veya mesajları **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir sürecin **davranışını değiştirebilir**, hassas verileri gözlemleyebilir veya yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind metadata, arm64e PAC kısıtlamaları ve sentetik çağrı zincirleri ele alınır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı süreçlerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC birçok yasal uygulama için temel nitelikte olsa da süreç izolasyonunu aşmak, hassas bilgileri leak etmek veya yetkisiz işlemler gerçekleştirmek için kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları process injection'a karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak tuş vuruşlarını, trafiği ve çerezleri çalmaya, sayfalara script enjekte etmeye olanak tanıyan bir **man in the browser attack** gerçekleştirmek mümkündür...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini ve bunların etkileşimlerini tanımlar**. Ancak **keyfi komutlar çalıştırabilirler** ve **NIB dosyası değiştirilmişse Gatekeeper, daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını engellemez**. Bu nedenle, keyfi programlara keyfi komutlar çalıştırmaları için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Uygulama başlamadan önce bir Java veya native agent yüklemek için **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ya da **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri enjekte etmek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (dosya) veya `--import data:text/javascript,…` (dosyasız, Node ≥ 20.6) üzerinden saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** bir modülü etkileşimli bir REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`**, Electron binary'lerinde bunların tümünü yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` çalışmadan önce **`DOTNET_STARTUP_HOOKS`** üzerinden .NET uygulamalarına kod enjekte etmek veya ön koşullar mevcut olduğunda .NET debugging işlevselliğini kötüye kullanmak mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını, zsh **`$ZDOTDIR/.zshenv`** dosyasını, fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırma dosyalarını okur. Her biri, hedeflenen komuttan önce denetlenen bir başlangıç dosyasını çalıştırabilir. xtrace etkin olduğunda (ör. devralınan **`SHELLOPTS=xtrace`** ile) Bash, **`PS4`** içine yerleştirilen command substitution'ı da çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` başlatıldığında shell, programı standart girdiden okur. Bu nedenle, güvenilmeyen yapılandırılmış bir belgeyi önce ayrıştırmadan çocuğun stdin'ine kopyalayan bir downloader, belgenin tamamını shell kaynak koduna dönüştürmüş olur. Gözlemlenen bir loader, herkese açık bir iCalendar dosyasını anonim pipe üzerinden satır satır aktarıyordu. Takvim metadata'sındaki satırlar komut olarak başarısız oldu, ancak zsh `DESCRIPTION:` sonrasına yerleştirilmiş çalıştırılabilir satırlara ulaşana kadar devam etti. Bu satırlar sonraki application bundle'ı indirip başlattı. Taşıyıcının beklenen içerik türü ve güvenilir bir sunucuda barındırılması bunu güvenli kılmadı; tehlikeli sınır, baytların bir yorumlayıcıya aktarılmasıydı.<sup>[[5]](#references)</sup>

İlgili aşamalar [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) ve [macOS auto-start locations](../../macos-auto-start-locations.md) bölümlerinde ele alınır.

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, hedef script'ten önce çalışan **`auto_prepend_file`** içeren denetlenebilir PHP yapılandırmasını yükleyebilir.

[PHP yapılandırması ve `auto_prepend_file` başlangıç injection'ı](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Bağımsız Lua yorumlayıcısı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özgü varyantı) üzerinden kod ya da bir `@file` çalıştırır.

[Lua `LUA_INIT` başlangıç injection'ı (dosya ve satır içi kod)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerinin konumunu değiştirir. Bunun yerine **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ve bir R library yolu, kurulu bir paketi otomatik olarak yükleyebilir.

[R başlangıç profilleri ve paket yükleme](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak çalıştırılan depot'un konumunu değiştirir.

[Julia `JULIA_DEPOT_PATH` ve `startup.jl` injection'ı](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, bir payload dosyası gerektirmeden Erlang VM'e **`-eval`** ifadesi enjekte edebilir; Elixir iş yükleri de genellikle aynı VM'i başlatır.

[Erlang/Elixir VM flag injection'ı](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerinin konumunu değiştirir.

[GNU Octave başlangıç dosyası injection'ı](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`, platformlar arası bir .NET uygulamasıdır. Bu nedenle, çeşitli env değişkenleri komut öncesi code execution olanağı sağlar: **`XDG_CONFIG_HOME`** başlangıçta çalıştırılan profile script'lerinin konumunu değiştirir, **`PSModulePath`** modüllerin otomatik yüklenmesini ele geçirmeye yarar (yerleştirilen bir `.psm1`, içe aktarma sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir) ve .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ile **`DOTNET_STARTUP_HOOKS`** değişkenleri, `Main` çalışmadan önce saldırgan kodunu sürece yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin keyfi kod çalıştırmasını sağlayacak farklı seçenekleri şurada inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lere keyfi kod çalıştırmak için Ruby env değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


[Ruby `RUBYOPT`/`RUBYLIB` loader seçenekleri](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standart library zinciri, uyarı filtreleri ayrıştırılırken bir komut çalıştırabilir. Dosya tabanlı bir alternatif olarak `sitecustomize.py`, **`PYTHONPATH`** üzerine yerleştirilir; böylece normal `site` başlatma işlemi bu dosyayı hedef script'ten önce içe aktarır. Kod `breakpoint()` noktasına ulaştığında **`PYTHONBREAKPOINT`**, seçilen callable'ı/modülü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli kullanımda geçerli olan değişkenlerin uygulama alanı daha dardır.

**`pyinstaller`** ile derlenen executable'ların, gömülü bir Python kullanarak çalışsalar bile bu env değişkenlerini kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve yedek olarak kullanılan `EXINIT`), normal başlangıç sırasında Ex komutları olarak çalıştırılır. Bu nedenle, kurban Vim/Neovim'i denetlenebilir bir env ile açtığında `:!cmd` / `:call system(...)` code execution sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrıca Homebrew, Python'ı genellikle `/opt/homebrew` altına yükler; burada yerel `admin` grubunun üyeleri launcher'ı değiştirebilir. Bu, env değişkeni injection'ı değil, yazılabilir binary'nin ele geçirilmesidir. Bunu exploitable olarak değerlendirmeden önce sahipliği ve ACL'leri doğrulayın.


## Tespit

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı tespit edip engelleyen, **EndpointSecurity** tabanlı açık kaynaklı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir referanstır; şu durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç başlatılırken görülen **injection env değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; bu, o sürece injection yapmanın ön koşuludur.
- **Electron debugging argümanları** — Electron uygulamasını debug modunda başlatan ve herkesin uygulamaya bağlanıp kod çalıştırmasına olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.<sup>[[3]](#references)</sup>
- **Farklı ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal kullanıcı olarak bir link oluşturup ayrıcalıklı bir konumu hedef göstermek" şeklindeki klasik yöntem. **Symlink'ler için uyarı üretilebilir ancak engelleme yapılamaz**: EndpointSecurity, link oluşturulmadan önce hedefi göstermez.

### Diğer süreçlerin yaptığı çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **süreçlere kod enjekte eden süreçler** hakkında bilgi edinmek ve ardından bu süreçle ilgili ayrıntıları almak için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için süreçle aynı **uid**'ye veya **root** erişimine sahip olmanız gerektiğini unutmayın (işlev süreçle ilgili bilgi döndürür; kod enjekte etme yöntemi sunmaz).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — macOS process injection tespiti için açık kaynaklı araç (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework'ü](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları neden sırlarınızı gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer'ın yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
