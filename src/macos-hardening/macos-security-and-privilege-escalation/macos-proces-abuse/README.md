# macOS Süreç İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir; ancak süreçler kod çalıştırmaz, bunu thread’ler yapar. Dolayısıyla **süreçler, çalışan thread’ler için bellek, tanımlayıcılar, portlar, izinler... sağlayan kapsayıcılardır**.

Geleneksel olarak süreçler, **`fork`** çağrılarak diğer süreçlerin içinde başlatılırdı (PID 1 hariç). Bu çağrı, mevcut sürecin tam bir kopyasını oluştururdu; ardından **child process** genellikle yeni yürütülebilir dosyayı yükleyip çalıştırmak için **`execve`** çağırırdı. Sonrasında, bellek kopyalama işlemi olmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Daha sonra **`posix_spawn`**, **`vfork`** ve **`execve`** işlemlerini tek bir çağrıda birleştirerek ve şu bayrakları kabul ederek kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu üyeliğini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Sinyal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec yap (`execve` gibi, ancak daha fazla seçenekle)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış durumda başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının yüksek bitlerini rastgeleleştir

Ayrıca `posix_spawn`, oluşturulan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç sonlandığında, `SIGCHLD` sinyaliyle **dönüş kodunu üst sürece gönderir** (üst süreç sonlanmışsa yeni üst süreç PID 1 olur). Üst süreç bu değeri `wait4()` veya `waitid()` çağrısıyla almalıdır; bu gerçekleşene kadar child, listelenmeye devam ettiği ancak kaynak tüketmediği zombie durumunda kalır.

### PID'ler

PID'ler (process identifier), benzersiz bir süreci tanımlar. XNU'da **PID'ler** 64 **bit** uzunluğundadır, monotonik olarak artar ve **asla başa sarmaz** (kötüye kullanımları önlemek için).

### Process Groups, Sessions ve Coalitions

**Süreçler**, yönetilmelerini kolaylaştırmak için **gruplara** yerleştirilebilir. Örneğin, bir shell script içindeki komutlar aynı süreç grubunda olur; böylece örneğin `kill` kullanarak **hepsine birlikte sinyal göndermek** mümkün olur.\
Süreçleri **session'larda gruplamak** da mümkündür. Bir süreç bir session başlattığında (`setsid(2)`), kendi session'larını başlatmadıkları sürece alt süreçler bu session'a dahil edilir.

Coalition, Darwin'de süreçleri gruplandırmanın başka bir yoludur. Bir coalition'a katılan süreç, havuz kaynaklarına erişebilir, bir ledger'ı paylaşabilir veya Jetsam'e tabi olabilir. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personae

Her süreç, sistemdeki **yetkilerini belirleyen kimlik bilgilerini** taşır. Her sürecin birincil `uid` ve birincil `gid` değeri vardır (ancak birden fazla gruba ait olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliklerini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli fonksiyonlar vardır.

**`persona`** sistem çağrısı, alternatif bir **kimlik bilgileri** kümesi sağlar. Bir persona benimsemek, onun uid, gid ve grup üyeliklerini **aynı anda** kullanmak anlamına gelir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) şu yapıyı bulmak mümkündür:

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

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir thread API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'teki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` dosyasında bulunur. Bu kütüphane, thread oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak `bsdthread_create()` işlevini çağırır. Bu, XNU kernel'ine (macOS'in temel aldığı kernel) özgü daha düşük seviyeli bir system call'dur. Bu system call, zamanlama politikaları ve stack boyutu dahil olmak üzere thread davranışını belirleyen, `pthread_attr` (özellikler) içinden türetilen çeşitli flag'ler alır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu boyut tipik işlemler için yeterlidir; daha fazla veya daha az alana ihtiyaç duyulursa thread özellikleri üzerinden ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında kritik öneme sahiptir. Stack'in konumu ve boyutuyla ilgili ayrıntıları içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'te Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, thread'in temiz bir şekilde çıkmasını, gerekli temizleme işlemlerini gerçekleştirmesini ve bir dönüş değerini thread'i bekleyen diğer thread'lere iletmesini sağlar.
2. **Thread Temizleme:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread portlarını (Mach, XNU kernel'indeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel düzeyindeki yapıları kaldıran `bsdthread_terminate` syscall'unu çağırır.

#### Senkronizasyon Mekanizmaları

macOS, paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için çeşitli senkronizasyon ilkelleri sağlar. Veri bütünlüğünü ve sistem kararlılığını sağlamak için bunlar çoklu thread ortamlarında kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (İmza: 0x4D555458):** Bellekte 60 bayt yer kaplayan standart mutex (mutex için 56 bayt, imza için 4 bayt).
   - **Fast Mutex (İmza: 0x4d55545A):** Normal mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir; boyutu yine 60 bayttır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık imza).
   - **Condition Variable Özellikleri (İmza: 0x434e4441):** Condition variable'lar için yapılandırma özellikleri; boyutu 12 bayttır.
3. **Once Variable (İmza: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez yürütülmesini sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Paylaşılan verilere verimli erişim sağlayarak aynı anda birden çok okuyucuya veya tek bir yazıcıya izin verir.
   - **Read Write Lock (İmza: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read Write Lock Özellikleri (İmza: 0x52574c41):** Read-write lock'lar için özellikler; boyutu 20 bayttır.

> [!TIP]
> Bu nesnelerin son 4 baytı taşmaları algılamak için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'teki yürütülebilir dosyaların biçimi) bağlamında **Thread Local Variables (TLV)**, çok thread'li bir uygulamada **her thread'e özgü** değişkenleri tanımlamak için kullanılır. Böylece her thread'in bir değişkene ait ayrı bir örneği olur; mutex gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemeye ve veri bütünlüğünü korumaya yardımcı olur.

C ve ilgili dillerde, thread'e özgü bir değişkeni **`__thread`** anahtar sözcüğünü kullanarak tanımlayabilirsiniz. Örneğinizde şu şekilde çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu snippet, `tlv_var` değişkenini thread-local olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler diğer thread'lerdeki `tlv_var` değişkenini etkilemez.

Mach-O binary'sinde thread-local değişkenlerle ilgili veriler belirli section'larda düzenlenir:

- **`__DATA.__thread_vars`**: Bu section, thread-local değişkenler hakkındaki türleri ve başlatılma durumlarını içeren metadata'yı barındırır.
- **`__DATA.__thread_bss`**: Bu section, açıkça başlatılmamış thread-local değişkenler için kullanılır. Sıfırla başlatılan verilere ayrılmış belleğin bir parçasıdır.

Mach-O ayrıca, bir thread sona erdiğinde thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, thread sonlandığında thread-local verileri temizleyen özel işlevler olan **destructor'ları kaydetmenize** olanak tanır.

### Thread Öncelikleri

Thread önceliklerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla yönetilir.

#### Nice ve Renice

1. **Nice:**
   - Bir process'in `nice` değeri, önceliğini etkileyen bir sayıdır. Her process'in -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında değişen bir nice değeri vardır. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
   - Daha düşük bir nice değeri (-20'ye daha yakın), process'i diğer yüksek nice değerine sahip process'lere kıyasla daha fazla CPU zamanı alacak şekilde "bencil" kılar.
2. **Renice:**
   - `renice`, zaten çalışmakta olan bir process'in nice değerini değiştirmek için kullanılan bir komuttur. Yeni nice değerlerine göre CPU zamanı tahsisini artırıp azaltarak process'lerin önceliğini dinamik olarak ayarlamak için kullanılabilir.
   - Örneğin, bir process geçici olarak daha fazla CPU kaynağına ihtiyaç duyarsa `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği olan macOS gibi sistemlerde thread önceliklerini yönetmeye yönelik daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre farklı kategorilere **ayırmasına** olanak tanır. macOS, bu QoS sınıflarına göre thread önceliklerini otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla o anda etkileşimde olan veya iyi bir kullanıcı deneyimi sunmak için hemen sonuç vermesi gereken görevler içindir. Arayüzün yanıt verebilir kalması için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açma veya hesaplama gerektiren bir düğmeye tıklama gibi, kullanıcının başlattığı ve hemen sonuç beklediği görevler içindir. Bunlar yüksek önceliklidir ancak user interactive görevlerin altında yer alır.
3. **Utility:**
   - Bunlar uzun süren ve genellikle ilerleme göstergesi sunan görevlerdir (ör. dosya indirme, veri içe aktarma). Öncelikleri user-initiated görevlerden düşüktür ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Bu sınıf, arka planda çalışan ve kullanıcı tarafından görülmeyen görevler içindir. Dizin oluşturma, eşitleme veya yedekleme gibi görevler buna örnektir. En düşük önceliğe sahiptirler ve sistem performansına etkileri minimumdur.

QoS sınıflarını kullanırken geliştiricilerin tam öncelik sayılarını yönetmesi gerekmez; bunun yerine görevin niteliğine odaklanırlar ve sistem CPU kaynaklarını buna göre optimize eder.

Ayrıca, scheduler'ın dikkate alacağı bir dizi zamanlama parametresini belirlemek için kullanılan farklı **thread scheduling policy**'leri de vardır. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition saldırılarında faydalı olabilir.

## macOS Process Abuse

macOS, **process'lerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar normal sistem işleyişi için gerekli olsa da saldırganlar bunları injection, kod yürütme veya veri erişimi için kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir process'i zararlı bir library yüklemeye zorladığı** bir tekniktir. Inject edildikten sonra library, hedef process'in bağlamında çalışır ve saldırgana process ile aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking, bir yazılımın içindeki işlev çağrılarını veya mesajları **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir process'in **davranışını değiştirebilir**, hassas verileri gözlemleyebilir, hatta yürütme akışının kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind metadata'sı, arm64e PAC kısıtlamaları ve sentetik çağrı zincirleri ele alınmaktadır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC birçok meşru uygulama için temel olsa da process izolasyonunu bozmak, hassas bilgileri leak etmek veya yetkisiz işlemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları process injection'a karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak tuş vuruşlarını, trafiği ve cookie'leri çalmaya, sayfalara script inject etmeye vb. olanak tanıyan bir **man in the browser saldırısı** gerçekleştirmek mümkündür:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini ve bunların etkileşimlerini tanımlar**. Ancak **keyfi komutlar çalıştırabilirler** ve **bir NIB dosyası değiştirilse bile Gatekeeper daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını engellemez**. Bu nedenle keyfi programların keyfi komutlar çalıştırmasını sağlamak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Uygulama başlamadan önce bir Java veya native agent yüklemek için **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri inject etmek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) veya `--import data:text/javascript,…` (fileless, Node ≥ 20.6) ile saldırganın JavaScript'ini önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** bir modülü etkileşimli REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`** Electron binary'lerinde bunların tümünü yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` öncesinde **`DOTNET_STARTUP_HOOKS`** aracılığıyla .NET uygulamalarına kod inject etmek veya gerekli ön koşullar sağlandığında .NET debugging işlevselliğini kötüye kullanmak mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash, **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını okur; zsh, **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmayı okur. Her biri, amaçlanan komuttan önce denetlenen bir başlangıç dosyasını çalıştırabilir. xtrace etkin olduğunda (ör. devralınan **`SHELLOPTS=xtrace`** ile) Bash, **`PS4`** içine yerleştirilmiş bir command substitution'ı da çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` başlatıldığında shell, bir programı standart girdiden okur. Bu nedenle, güvenilmeyen yapılandırılmış bir belgeyi önce ayrıştırmadan çocuğun stdin'ine kopyalayan bir downloader, belgenin tamamını shell kaynak koduna dönüştürmüş olur. Gözlemlenen bir loader, herkese açık bir iCalendar dosyasını anonim bir pipe üzerinden satır satır iletti. Takvim metadata'sı komut olarak başarısız oldu, ancak zsh `DESCRIPTION:` sonrasına yerleştirilen çalıştırılabilir satırlara ulaşana kadar devam etti. Bu satırlar bir sonraki application bundle'ı indirdi ve başlattı. Taşıyıcının beklenen içerik türü ve güvenilir barındırma yeri bunu güvenli hâle getirmedi; tehlikeli sınır, baytların bir interpreter'a aktarılmasıydı.<sup>[[5]](#references)</sup>

İlgili aşamalar [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) ve [macOS auto-start locations](../../macos-auto-start-locations.md) bölümlerinde ele alınmaktadır.

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, hedef script'ten önce çalışan **`auto_prepend_file`** içeren, denetlenen PHP yapılandırmasını yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Tek başına çalışan Lua interpreter'ı, hedef script'i işleme almadan önce **`LUA_INIT`** (veya sürüme özgü varyantı) üzerinden kod ya da bir `@file` çalıştırır.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerinin yolunu değiştirir. Bunun yerine **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ve bir R library path kullanılarak yüklü bir package otomatik yüklenebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyasının otomatik olarak çalıştırıldığı depot'un yolunu değiştirir.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, bir payload file gerektirmeden Erlang VM'e **`-eval`** ifadesi inject edebilir; Elixir iş yükleri genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerinin yolunu değiştirir.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`, cross-platform bir .NET uygulamasıdır; bu nedenle birkaç environment variable komut öncesi kod yürütme olanağı sağlar: **`XDG_CONFIG_HOME`** başlangıçta çalışan profil script'lerinin yolunu değiştirir, **`PSModulePath`** modüllerin otomatik yüklenmesini ele geçirir (yerleştirilen bir `.psm1` import sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir) ve .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ile **`DOTNET_STARTUP_HOOKS`** değişkenleri, `Main` öncesinde saldırgan kodunu process'e yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin keyfi kod çalıştırmasını sağlayan farklı seçenekleri inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için Ruby env değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standart library zinciri, warning-filter ayrıştırması sırasında bir komut çalıştırabilir. Dosya tabanlı bir alternatif, `site` başlatması sırasında hedef script'ten önce içe aktarılması için `sitecustomize.py` dosyasını **`PYTHONPATH`** üzerine yerleştirir. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına ulaştığında seçilen bir callable/module'ü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli modda kullanılan değişkenlerin kullanım alanı daha sınırlıdır.

**`pyinstaller`** ile derlenen executable'ların, embedded python kullanarak çalışsalar bile bu environment variable'ları kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve onun `EXINIT` fallback'i), normal başlatma sırasında Ex komutları olarak çalıştırılır. Bu nedenle kurban, denetlenen bir environment ile Vim/Neovim açtığında `:!cmd` / `:call system(...)` kod yürütülmesine yol açar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrıca Homebrew, Python'ı genellikle `/opt/homebrew` altına kurar; burada yerel `admin` grubunun üyeleri launcher'ı değiştirebilir. Bu, environment variable injection değil, yazılabilir binary'nin ele geçirilmesidir; istismar edilebilir olarak değerlendirmeden önce sahipliği ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı tespit edip engelleyen, **EndpointSecurity** tabanlı açık kaynaklı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir referanstır; çünkü aşağıdakiler için uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec sırasında kullanılan **injection environment variable'ları**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection yapmak için ön koşuldur.
- **Electron debugging argümanları** — `--inspect`, `--inspect-brk` ve `--remote-debugging-port`. Bunlar bir Electron uygulamasını debug mode'da başlatır ve herkesin uygulamaya bağlanıp içinde kod çalıştırmasına olanak tanır.<sup>[[3]](#references)</sup>
- **Ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal kullanıcı olarak bir link oluşturup ayrıcalıklı bir konuma yönlendirme" şeklindeki klasik primitive. **Symlink'ler için uyarı verilebilir ancak engellenemez**: EndpointSecurity, link oluşturulmadan önce hedefini göstermez.

### Other processes tarafından yapılan çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **process'lere kod inject eden process'ler** hakkında bilgi almak ve ardından bu diğer process hakkında bilgi edinmek için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için process'i çalıştıranla **aynı uid'ye** veya **root** yetkisine sahip olmanız gerekir (işlev, process hakkında bilgi döndürür; kod inject etme yöntemi sağlamaz).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — açık kaynaklı macOS process-injection tespiti (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework'ü](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer'ın yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
