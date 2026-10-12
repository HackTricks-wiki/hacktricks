# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Temel Bilgileri

Bir process, çalışan bir executable'ın örneğidir; ancak kodu process'ler değil, thread'ler çalıştırır. Dolayısıyla **process'ler, thread'leri çalıştırmak için bellek, descriptor'lar, port'lar, izinler... sağlayan kapsayıcılardır**.

Geleneksel olarak process'ler (PID 1 hariç) **`fork`** çağrısıyla başka process'lerin içinde başlatılırdı. Bu çağrı mevcut process'in birebir kopyasını oluştururdu; ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Sonra bu süreci bellek kopyalama olmadan hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`vfork`** ve **`execve`** işlevlerini tek çağrıda birleştiren ve flag'leri kabul eden **`posix_spawn`** kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Effective ID'leri real ID'lere sıfırlar
- `POSIX_SPAWN_SETPGROUP`: Process group üyeliğini ayarlar
- `POSUX_SPAWN_SETSIGDEF`: Varsayılan signal davranışını ayarlar
- `POSIX_SPAWN_SETSIGMASK`: Signal maskesini ayarlar
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde exec yapar (daha fazla seçeneğe sahip `execve` gibi)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlatır
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlatır
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'un Nano allocator'ını kullanır
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin verir
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapatır
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ının yüksek bitlerini rastgeleleştirir

Ayrıca `posix_spawn`, başlatılan process'in özelliklerini kontrol eden **`posix_spawnattr`** ayarlarını ve file descriptor'ları değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir process sonlandığında, `SIGCHLD` signal'ini kullanarak **return code'u parent process'e** gönderir (parent sonlanmışsa yeni parent PID 1 olur). Parent'ın bu değeri `wait4()` veya `waitid()` çağrısıyla alması gerekir. Bu gerçekleşene kadar child, listelenmeye devam ettiği ancak kaynak tüketmediği zombie durumunda kalır.

### PIDs

PID'ler (process identifier'lar), benzersiz bir process'i tanımlar. XNU'da **PID'ler** **64 bit** uzunluğundadır, monotonik olarak artar ve **asla sıfırlanmaz** (abuse'ları önlemek için).

### Process Groups, Sessions & Coalations

**Process'ler**, yönetimlerini kolaylaştırmak için **group'lara** eklenebilir. Örneğin, bir shell script'teki komutlar aynı process group içinde olur; böylece örneğin `kill` kullanarak **birlikte signal göndermek** mümkün olur.\
Process'leri **session'larda gruplamak** da mümkündür. Bir process session başlattığında (`setsid(2)`), kendi session'larını başlatmadıkları sürece child process'ler bu session'a dahil edilir.

Coalition, Darwin'de process'leri gruplamanın başka bir yoludur. Bir coalition'a katılan process, pool kaynaklarına erişebilir, bir ledger'ı paylaşabilir veya Jetsam'e maruz kalabilir. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **ayrıcalıklarını tanımlayan** **credentials** taşır. Her process'in bir primary `uid` ve bir primary `gid` değeri vardır (birden fazla group'a üye olabilmesine rağmen).\
Binary'de `setuid/setgid` biti varsa user ve group ID'lerini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credentials** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve group üyeliklerini **aynı anda** üstlenir. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:

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

## Threads Temel Bilgileri

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX threads'ü (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak XNU kernel'ine (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir sistem çağrısı olan `bsdthread_create()` işlevini çağırır. Bu sistem çağrısı, scheduling policies ve stack size dahil olmak üzere thread davranışını belirten `pthread_attr` (öznitelikler) üzerinden türetilen çeşitli flag'leri alır.
   - **Varsayılan Stack Size:** Yeni thread'ler için varsayılan stack size 512 KB'tır. Bu, tipik işlemler için yeterlidir; daha fazla veya daha az alana ihtiyaç duyulursa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında kritik bir rol oynar ve stack'in konumu ile boyutu hakkındaki bilgileri içerebilen environment variable'ları ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'leri Sonlandırma:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in temiz bir şekilde çıkmasını, gerekli temizleme işlemlerinin yapılmasını ve thread'in join işlemini bekleyenlere bir dönüş değeri göndermesini sağlar.
2. **Thread Temizliği:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread port'larını (Mach, XNU kernel'indeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel seviyesindeki yapıları kaldıran bir syscall olan `bsdthread_terminate` işlevini çağırır.

#### Synchronization Mechanisms

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli synchronization primitive'leri sağlar. Bunlar, data integrity ve system stability sağlamak için multi-threading ortamlarında kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Regular Mutex (Signature: 0x4D555458):** Bellekte 60 bayt yer kaplayan standart mutex (mutex için 56 bayt, signature için 4 bayt).
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir; boyutu da 60 bayttır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık signature).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variable'lar için yapılandırma öznitelikleri; boyutu 12 bayttır.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Birden fazla okuyucuya veya aynı anda tek bir yazıcıya izin vererek paylaşılan verilere verimli erişim sağlar.
   - **Read Write Lock (Signature: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için öznitelikler; boyutu 20 bayttır.

> [!TIP]
> Bu nesnelerin son 4 baytı, taşmaları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'taki yürütülebilir dosyaların formatı) bağlamında **Thread Local Variables (TLV)**, multi-threaded bir uygulamada **her thread'e özel** değişkenleri tanımlamak için kullanılır. Böylece her thread'in bir değişkene ait kendi ayrı örneği olur; mutex gibi açık synchronization mechanisms gerektirmeden çakışmaları önlemek ve data integrity'yi korumak mümkün hâle gelir.

C ve ilgili dillerde, **`__thread`** anahtar sözcüğünü kullanarak thread-local bir değişken tanımlayabilirsiniz. Örneğinizde şöyle çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu kod parçası `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary dosyasında thread-local değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, türleri ve başlatılma durumları gibi thread-local değişkenlere ilişkin metadata'yı içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış thread-local değişkenler için kullanılır. Belleğin sıfırla başlatılan verilere ayrılmış bir kısmıdır.

Mach-O ayrıca bir thread sona erdiğinde thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, thread sonlandığında thread-local verileri temizleyen özel işlevler olan **destructor'ları kaydetmenizi** sağlar.

### Thread Öncelikleri

Thread önceliklerini anlamak için işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmak gerekir. Bu karar, her thread'e atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla yönetilir.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir `nice` değeri vardır. Bir süreç oluşturulduğunda varsayılan `nice` değeri genellikle 0'dır.
   - Daha düşük bir `nice` değeri (-20'ye daha yakın), süreci daha "bencil" kılar ve daha yüksek `nice` değerlerine sahip süreçlere kıyasla daha fazla CPU süresi almasını sağlar.
2. **Renice:**
   - `renice`, çalışan bir sürecin `nice` değerini değiştirmek için kullanılan bir komuttur. Yeni `nice` değerlerine göre CPU süresi tahsisini artırıp azaltarak süreçlerin önceliğini dinamik olarak ayarlamak için kullanılabilir.
   - Örneğin, bir süreç geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa `renice` kullanarak `nice` değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde thread önceliklerini yönetmek için daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre **kategorilere ayırmasına** olanak tanır. macOS, bu QoS sınıflarına göre thread önceliklendirmesini otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla etkileşim hâlinde olan veya iyi bir kullanıcı deneyimi sunmak için anında sonuç gerektiren görevler içindir. Arayüzün yanıt verebilir kalması için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Kullanıcının başlattığı ve bir belgeyi açmak ya da hesaplama gerektiren bir düğmeye tıklamak gibi anında sonuç beklediği görevlerdir. Bunlar yüksek önceliklidir, ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Bunlar uzun süren ve genellikle bir ilerleme göstergesi sunan görevlerdir (ör. dosya indirme, veri içe aktarma). Kullanıcı tarafından başlatılan görevlere kıyasla daha düşük önceliklidir ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Bu sınıf, arka planda çalışan ve kullanıcıya görünmeyen görevler içindir. Dizin oluşturma, eşitleme veya yedekleme gibi görevler buna örnektir. Bunlar en düşük önceliğe sahiptir ve sistem performansını en az düzeyde etkiler.

QoS sınıfları sayesinde geliştiricilerin kesin öncelik sayılarıyla uğraşması gerekmez; bunun yerine görevin niteliğine odaklanabilirler. Sistem de CPU kaynaklarını buna göre en iyi şekilde kullanır.

Ayrıca, scheduler'ın dikkate alacağı bir dizi zamanlama parametresi belirlemek için kullanılan farklı **thread zamanlama politikaları** vardır. Bu, `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition saldırılarında yararlı olabilir.

## macOS Süreç Suistimali

macOS, **süreçlerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sunar. Bu mekanizmalar sistemin normal çalışması için gerekli olsa da saldırganlar bunları injection, code execution veya veri erişimi için suistimal edebilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir library yüklemeye zorladığı** bir tekniktir. Library enjekte edildikten sonra hedef sürecin bağlamında çalışır ve saldırgana süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodundaki işlev çağrılarını veya mesajları **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir sürecin davranışını **değiştirebilir**, hassas verileri gözlemleyebilir, hatta yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind metadata, arm64e PAC kısıtlamaları ve sentetik çağrı zincirleri ele alınmaktadır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Süreçler Arası İletişim

Süreçler Arası İletişim (IPC), ayrı süreçlerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC birçok meşru uygulama için temel olsa da süreç yalıtımını aşmak, hassas bilgileri sızdırmak veya yetkisiz eylemler gerçekleştirmek için de suistimal edilebilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Uygulamalarında Injection

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları process injection saldırılarına karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak tuş vuruşlarını, trafiği ve çerezleri çalmaya, sayfalara script enjekte etmeye olanak tanıyan bir **man in the browser attack** gerçekleştirmek mümkündür:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini ve bunların etkileşimlerini tanımlar**. Ancak bu dosyalar **keyfi komutlar çalıştırabilir** ve **Gatekeeper, bir NIB dosyası değiştirilmiş olsa bile** önceden çalıştırılmış bir uygulamanın yeniden çalıştırılmasını **engellemez**. Bu nedenle keyfi programların keyfi komutlar çalıştırmasını sağlamak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Uygulamalarında Injection

Uygulama başlamadan önce bir Java veya native agent yüklemek için **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri enjekte etmek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) veya `--import data:text/javascript,…` (fileless, Node ≥ 20.6) aracılığıyla saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** bir modülü etkileşimli bir REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`** tüm bunları Electron binary dosyalarında yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Uygulamalarında Injection

`Main` çalışmadan önce **`DOTNET_STARTUP_HOOKS`** aracılığıyla .NET uygulamalarına kod enjekte etmek veya gerekli ön koşullar mevcutken .NET debugging işlevselliğini suistimal etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmayı okur. Bunların her biri, hedeflenen komuttan önce denetlenen bir başlangıç dosyasını çalıştırabilir. Bash ayrıca xtrace etkin olduğunda (ör. devralınan **`SHELLOPTS=xtrace`** ile) **`PS4`** içine yerleştirilmiş bir command substitution çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, **`auto_prepend_file`** yönergesi hedef script'ten önce çalışan, denetlenen PHP yapılandırmasını yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Tek başına çalışan Lua interpreter'ı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özgü varyantı) içindeki kodu ya da `@file` dosyasını çalıştırır.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerine yönlendirme yapar. Bunun yerine **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ile bir R library path kullanılarak kurulu bir paket otomatik yüklenebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyasının otomatik olarak çalıştırıldığı depot'u başka bir konuma yönlendirir.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang ve Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload dosyası gerektirmeden bir Erlang VM **`-eval`** ifadesi enjekte edebilir; Elixir iş yükleri de genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerini başka bir konuma yönlendirir.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` platformlar arası bir .NET uygulamasıdır; bu nedenle çeşitli env değişkenleri komut öncesinde kod çalıştırılmasına olanak tanır: **`XDG_CONFIG_HOME`**, başlangıçta çalışan profil script'lerini başka bir konuma yönlendirir; **`PSModulePath`**, modüllerin otomatik yüklenmesini hijack eder (yerleştirilen bir `.psm1` içe aktarma sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir); .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ve **`DOTNET_STARTUP_HOOKS`** değişkenleri ise `Main` öncesinde saldırgan kodunu sürece yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin keyfi kod çalıştırmasını sağlamak için farklı seçenekleri inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için Ruby env değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) suistimal etmek de mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standart library zinciri, uyarı filtresi ayrıştırılırken bir komut çalıştırabilir. Dosya tabanlı bir alternatif, `site` başlatma işleminin hedef script'ten önce içe aktarması için **`PYTHONPATH`** üzerine `sitecustomize.py` yerleştirir. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına ulaştığında seçilen callable/module'ü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli kullanımda geçerli olan değişkenlerin uygulama alanı daha dardır.

**`pyinstaller`** ile derlenen executable dosyaların, gömülü bir Python kullanarak çalıştırılıyor olsalar bile bu env değişkenlerini kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve yedek olarak kullanılan `EXINIT`), normal başlangıç sırasında Ex komutları olarak çalıştırılır. Bu nedenle kurban Vim/Neovim'i denetlenen bir ortamla açtığında `:!cmd` / `:call system(...)` code execution sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrıca Homebrew, Python'ı genellikle `/opt/homebrew` altına kurar; yerel `admin` grubunun üyeleri burada launcher'ı değiştirebilir. Bu, env değişkeni injection'ı değil, yazılabilir bir binary hijack'tir; istismar edilebilir olduğunu varsaymadan önce sahiplik ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı tespit edip engelleyen, açık kaynaklı ve **EndpointSecurity** tabanlı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini göstermesi açısından iyi bir kaynaktır; çünkü şu durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç exec sırasında **injection env değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; bu, o sürece injection yapmanın ön koşuludur.
- **Electron debugging argümanları** — `--inspect`, `--inspect-brk` ve `--remote-debugging-port`; bunlar Electron uygulamasını debug mode'da başlatır ve herkesin uygulamaya bağlanıp kod çalıştırmasına olanak tanır.<sup>[[3]](#references)</sup>
- **Ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal bir kullanıcı olarak bir link oluşturup ayrıcalıklı bir konuma yönlendirme" şeklindeki klasik primitive. **Symlink'ler için uyarı verilebilir ancak engelleme yapılamaz**: EndpointSecurity, link oluşturulmadan önce hedefi göstermez.

### Diğer süreçlerin yaptığı çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), **`task_name_for_pid`** işlevinin başka **bir sürece kod enjekte eden süreçler** hakkında bilgi almak ve ardından o süreçle ilgili bilgi edinmek için nasıl kullanılabileceğini bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için süreci çalıştıranla **aynı uid'ye** veya **root** yetkisine sahip olmanız gerektiğini unutmayın (işlev injection yapmanın bir yolunu değil, süreç hakkında bilgi döndürür).

## References

- [1] [Shield — açık kaynaklı macOS process injection tespiti (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework'ü](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
