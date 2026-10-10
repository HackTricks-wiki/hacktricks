# macOS Süreç İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir. Ancak süreçler kod çalıştırmaz; kodu thread'ler çalıştırır. Dolayısıyla **süreçler, bellek, tanımlayıcılar, portlar, izinler... sağlayan thread kapsayıcılarından ibarettir**.

Geleneksel olarak süreçler, **`fork`** çağrısıyla başka süreçlerin içinde başlatılırdı (PID 1 hariç). `fork`, mevcut sürecin birebir kopyasını oluştururdu; ardından **alt süreç** genellikle yeni yürütülebilir dosyayı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Daha sonra, bellek kopyalama işlemi olmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`posix_spawn`**, **`vfork`** ile **`execve`** işlevlerini tek bir çağrıda birleştirmek ve bayrakları kabul etmek üzere kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu üyeliğini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Varsayılan sinyal davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec yap (`execve` gibi, ancak daha fazla seçenekle)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış durumda başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` iznine izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının yüksek bitlerini rastgeleleştir

Ayrıca `posix_spawn`, oluşturulan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç sonlandığında, `SIGCHLD` sinyaliyle **dönüş kodunu üst sürece gönderir** (üst süreç sonlanmışsa yeni üst süreç PID 1 olur). Üst sürecin bu değeri almak için `wait4()` veya `waitid()` çağrısı yapması gerekir. Bu gerçekleşene kadar alt süreç, hâlâ listelenmesine rağmen kaynak tüketmediği zombi durumunda kalır.

### PID'ler

PID'ler, yani süreç tanımlayıcıları, benzersiz bir süreci tanımlar. XNU'da **PID'ler** **64 bittir**, monoton biçimde artar ve **asla başa sarmaz** (istismarları önlemek için).

### Süreç Grupları, Oturumlar ve Koalisyonlar

**Süreçler**, yönetimlerini kolaylaştırmak için **gruplara** yerleştirilebilir. Örneğin, bir kabuk betiğindeki komutlar aynı süreç grubunda olur; böylece örneğin `kill` kullanarak **hepsine birlikte sinyal göndermek** mümkün olur.\
Süreçleri **oturumlarda gruplamak** da mümkündür. Bir süreç oturum başlattığında (`setsid(2)`), kendi oturumlarını başlatmadıkları sürece alt süreçler bu oturuma yerleştirilir.

Koalisyon, Darwin'de süreçleri gruplamanın başka bir yoludur. Bir koalisyona katılan süreç, havuz kaynaklarına erişebilir, bir ledger'ı paylaşabilir veya Jetsam'e tabi olabilir. Koalisyonların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personalar

Her süreç, sistemdeki **ayrıcalıklarını tanımlayan kimlik bilgilerine** sahiptir. Her sürecin bir birincil `uid` ve bir birincil `gid` değeri bulunur (ancak süreç birden fazla gruba üye olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliklerini değiştirmek de mümkündür.\
Yeni uid/gid değerleri **ayarlamak** için çeşitli işlevler vardır.

**`persona`** sistem çağrısı, **alternatif** bir **kimlik bilgileri** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve grup üyeliklerini **aynı anda** üstlenir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) şu yapıyı bulmak mümkündür:

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

## Threads Hakkında Temel Bilgiler

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir thread API'sinin parçası olan POSIX threads'ü (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak `bsdthread_create()` işlevini çağırır. Bu, XNU kernel'ine (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir sistem çağrısıdır. Sistem çağrısı, thread davranışını belirleyen ve zamanlama politikalarıyla stack boyutunu da içeren `pthread_attr` (öznitelikler) üzerinden alınan çeşitli flag'leri kullanır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu, tipik işlemler için yeterlidir ancak daha fazla ya da daha az alana ihtiyaç duyulursa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında önemli bir rol oynar. Stack'in konumu ve boyutuyla ilgili ayrıntıları içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in gerekli temizleme işlemlerini yaparak düzgün biçimde çıkmasını ve bir dönüş değerini bekleyen thread'lere göndermesini sağlar.
2. **Thread Temizleme:** `pthread_exit()` çağrıldığında, ilgili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread portlarını (Mach, XNU kernel'indeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel düzeyindeki yapıları kaldıran bir sistem çağrısı olan `bsdthread_terminate` işlevini çağırır.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli senkronizasyon ilkelleri sağlar. Bunlar, veri bütünlüğünü ve sistem kararlılığını sağlamak açısından çok thread'li ortamlarda kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (İmza: 0x4D555458):** Bellekte 60 bayt yer kaplayan standart mutex (mutex için 56 bayt, imza için 4 bayt).
   - **Fast Mutex (İmza: 0x4d55545A):** Normal mutex'e benzer ancak daha hızlı işlemler için optimize edilmiştir; boyutu yine 60 bayttır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık imza).
   - **Condition Variable Öznitelikleri (İmza: 0x434e4441):** Condition variable'lar için 12 bayt boyutundaki yapılandırma öznitelikleri.
3. **Once Variable (İmza: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Paylaşılan verilere verimli erişim sağlayarak aynı anda birden fazla okuyucuya ya da tek bir yazıcıya izin verir.
   - **Read Write Lock (İmza: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read Write Lock Öznitelikleri (İmza: 0x52574c41):** Read-write lock'lar için 20 bayt boyutundaki öznitelikler.

> [!TIP]
> Bu nesnelerin son 4 baytı taşmaları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'taki yürütülebilir dosya biçimi) bağlamında **Thread Local Variables (TLV)**, çok thread'li bir uygulamadaki **her thread'e özgü** değişkenleri tanımlamak için kullanılır. Böylece her thread'in bir değişkene ait kendine özgü bir örneği olur; bu da mutex gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemenin ve veri bütünlüğünü korumanın bir yolunu sağlar.

C ve ilgili dillerde, **`__thread`** anahtar sözcüğünü kullanarak thread-local bir değişken tanımlayabilirsiniz. Örneğinizde şöyle çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu snippet, `tlv_var`'ı thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread'in kendine ait bir `tlv_var` değişkeni olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary dosyasında thread-local değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, thread-local değişkenlerin türleri ve başlatılma durumu gibi metadata bilgilerini içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış thread-local değişkenler için kullanılır. Bellekte sıfırla başlatılan veriler için ayrılan bir alanın parçasıdır.

Mach-O ayrıca, bir thread sona erdiğinde thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verileri temizleyen özel işlevler olan **destructor'ları kaydetmenize** olanak tanır.

### Thread Öncelikleri

Thread önceliklerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla gerçekleştirilir.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir nice değeri vardır. Bir süreç oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
   - Daha düşük bir nice değeri (-20'ye daha yakın) süreci daha "bencil" hale getirir ve nice değeri daha yüksek olan diğer süreçlere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
   - `renice`, hâlihazırda çalışan bir sürecin nice değerini değiştirmek için kullanılan bir komuttur. Yeni nice değerlerine göre süreçlerin CPU zamanı tahsisini dinamik olarak artırmak veya azaltmak için kullanılabilir.
   - Örneğin, bir süreç geçici olarak daha fazla CPU kaynağına ihtiyaç duyarsa `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde, thread önceliklerini yönetmeye yönelik daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre farklı kategorilere **ayırmasına** olanak tanır. macOS, bu QoS sınıflarına göre thread önceliklerini otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla doğrudan etkileşim hâlinde olan veya iyi bir kullanıcı deneyimi sağlamak için anında sonuç gerektiren görevler içindir. Arayüzün duyarlı kalmasını sağlamak için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açmak veya hesaplama gerektiren bir düğmeye tıklamak gibi, kullanıcının başlattığı ve hemen sonuç beklediği görevler içindir. Bunlar yüksek önceliklidir ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Bunlar uzun süren ve genellikle ilerleme göstergesi sunan görevlerdir (ör. dosya indirme, veri içe aktarma). Kullanıcı tarafından başlatılan görevlere kıyasla daha düşük önceliğe sahiptirler ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Bu sınıf, arka planda çalışan ve kullanıcı tarafından görülmeyen görevler içindir. İndeksleme, eşitleme veya yedekleme gibi görevler bu sınıfa girebilir. En düşük önceliğe sahiptirler ve sistem performansına etkileri en azdır.

Geliştiriciler, QoS sınıflarını kullanarak kesin öncelik numaralarını yönetmek yerine görevin niteliğine odaklanabilir; sistem de CPU kaynaklarını buna göre optimize eder.

Ayrıca, scheduler'ın dikkate alacağı bir dizi zamanlama parametresi belirlemek için farklı **thread scheduling policy**'ler bulunur. Bu, `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition saldırılarında işe yarayabilir.

## macOS Süreçlerinin Kötüye Kullanımı

macOS, **süreçlerin etkileşime girmesi, iletişim kurması ve veri paylaşması** için pek çok mekanizma sağlar. Bu mekanizmalar normal sistem işleyişi için gerekli olsa da saldırganlar bunları injection, code execution veya data access için kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir library yüklemeye zorladığı** bir tekniktir. Library enjekte edildikten sonra hedef sürecin bağlamında çalışır ve saldırgana süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodundaki işlev çağrılarını veya mesajları **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir sürecin davranışını **değiştirebilir**, hassas verileri gözlemleyebilir ve hatta yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı süreçlerin **veri paylaşmak ve alışverişinde bulunmak** için kullandığı farklı yöntemleri ifade eder. IPC birçok meşru uygulamanın temelini oluştururken süreç yalıtımını bozmak, hassas bilgileri leak etmek veya yetkisiz eylemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları process injection'a karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak tuş vuruşlarını ve trafiği çalmaya, cookies'leri ele geçirmeye, sayfalara script enjekte etmeye izin veren bir **man in the browser attack** gerçekleştirmek mümkündür...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **user interface (UI) öğelerini** ve bunların etkileşimlerini **tanımlar**. Ancak **keyfi komutlar çalıştırabilirler** ve bir **NIB dosyası değiştirilmişse** Gatekeeper, daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını **engellemez**. Bu nedenle keyfi programlara keyfi komutlar çalıştırmak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Uygulama başlamadan önce bir Java veya native agent yüklemek için **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri enjekte etmek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) veya `--import data:text/javascript,…` (fileless, Node ≥ 20.6) aracılığıyla saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** bir modülü etkileşimli bir REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`** bu özelliklerin tümünü Electron binary'lerinde yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` çalışmadan önce **`DOTNET_STARTUP_HOOKS`** aracılığıyla .NET uygulamalarına kod enjekte etmek veya gerekli ön koşullar mevcutken .NET debugging işlevselliğini kötüye kullanmak mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmayı okur. Her biri, hedeflenen komuttan önce kontrol edilen bir startup dosyası çalıştırabilir. Bash ayrıca xtrace etkinleştirildiğinde (ör. devralınan **`SHELLOPTS=xtrace`** ile) **`PS4`** içine yerleştirilen bir command substitution'ı çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, **`auto_prepend_file`** yönergesi hedef script'ten önce çalışan, kontrol edilebilir bir PHP yapılandırma dosyasını yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Bağımsız Lua interpreter'ı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özel varyantı) içindeki kodu ya da `@file`'ı çalıştırır.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren startup profile'larını farklı konumlara yönlendirir. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ile bir R library path kullanılarak kurulu bir package'ın otomatik yüklenmesi de sağlanabilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyasının otomatik çalıştırıldığı depot'u farklı bir konuma yönlendirir.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload file gerektirmeden bir Erlang VM **`-eval`** ifadesi enjekte edebilir; Elixir workload'ları genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave startup script'lerini farklı konumlara yönlendirir.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` platformlar arası bir .NET uygulamasıdır; bu nedenle bazı env değişkenleri komuttan önce kod çalıştırılmasını sağlar: **`XDG_CONFIG_HOME`** başlangıçta çalışan profile script'lerini farklı konuma yönlendirir, **`PSModulePath`** module auto-loading'i ele geçirir (yerleştirilen bir `.psm1` import sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir) ve .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ile **`DOTNET_STARTUP_HOOKS`** değişkenleri, `Main` öncesinde saldırgan kodunu sürece yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin aşağıdaki yöntemlerle keyfi kod çalıştırmasını sağlayacak farklı seçenekleri inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için Ruby env değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standard-library zinciri, warning-filter ayrıştırması sırasında bir komut çalıştırabilir. File-backed bir alternatif olarak `sitecustomize.py` dosyasını **`PYTHONPATH`** üzerine yerleştirebilirsiniz; böylece normal `site` başlatma işlemi, hedef script'ten önce bu dosyayı import eder. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına geldiğinde seçilen bir callable/module'ü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli kullanımda geçerli değişkenler daha dar bir kullanım alanına sahiptir.

**`pyinstaller`** ile derlenen executable'ların, embedded python kullanarak çalışsalar bile bu env değişkenlerini kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve onun `EXINIT` fallback'i), normal başlangıç sırasında Ex komutları olarak çalıştırılır. Bu nedenle kurban, kontrollü bir ortamda Vim/Neovim açtığında `:!cmd` / `:call system(...)` code execution sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrıca Homebrew, Python'ı genellikle `/opt/homebrew` altına yükler; yerel `admin` grubunun üyeleri burada launcher'ı değiştirebilir. Bu, env değişkeni injection'ı değil, yazılabilir bir binary'nin ele geçirilmesidir; istismar edilebilir kabul etmeden önce sahipliği ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı algılayıp engelleyen, açık kaynaklı **EndpointSecurity** tabanlı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir kaynaktır; çünkü aşağıdaki durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç exec işlemlerindeki **injection env değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; o sürece injection yapmak için bu gereklidir.
- **Electron debugging argümanları** — `--inspect`, `--inspect-brk` ve `--remote-debugging-port`. Bunlar bir Electron uygulamasını debug mode'da başlatır ve herhangi birinin bağlanıp uygulamada kod çalıştırmasına olanak tanır.<sup>[[3]](#references)</sup>
- **Ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal kullanıcı olarak bir link oluşturup onu ayrıcalıklı bir konuma yönlendirme" şeklindeki klasik yöntem. **Symlink'ler için uyarı verilebilir ancak engellenemez**: EndpointSecurity, oluşturulmadan önce link'in hedefini göstermez.

### Other Processes tarafından yapılan çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **bir sürece kod enjekte eden süreçler** hakkında bilgi almak ve ardından söz konusu süreç hakkında bilgi edinmek için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için süreci çalıştıranla **aynı uid**'ye veya **root** yetkisine sahip olmanız gerektiğini unutmayın (işlev, sürece injection yapmanın yolunu değil, süreç hakkındaki bilgileri döndürür).

## References

- [1] [Shield — açık kaynaklı macOS process-injection algılama aracı (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları neden sırlarınızı gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini algılama](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
