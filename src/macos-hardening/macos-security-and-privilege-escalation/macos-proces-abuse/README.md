# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Bir process, çalışan bir executable'ın örneğidir; ancak process'ler kod çalıştırmaz, bunu thread'ler yapar. Bu nedenle **process'ler, çalışan thread'ler için yalnızca container'lardır** ve bellek, descriptor'lar, port'lar, izinler...

Geleneksel olarak process'ler (PID 1 hariç) **`fork`** çağrılarak diğer process'lerin içinde başlatılırdı. Bu çağrı mevcut process'in birebir kopyasını oluşturur ve ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağırırdı. Daha sonra, herhangi bir bellek kopyalaması yapmadan bu süreci hızlandırmak için **`vfork`** tanıtıldı.\
Ardından **`posix_spawn`**, **`vfork`** ve **`execve`** işlemlerini tek bir çağrıda birleştirerek ve flag'leri kabul ederek tanıtıldı:

- `POSIX_SPAWN_RESETIDS`: Effective id'leri real id'lere sıfırlar
- `POSIX_SPAWN_SETPGROUP`: Process group üyeliğini ayarlar
- `POSUX_SPAWN_SETSIGDEF`: Signal varsayılan davranışını ayarlar
- `POSIX_SPAWN_SETSIGMASK`: Signal maskesini ayarlar
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde Exec gerçekleştirir (daha fazla seçenekle `execve` gibi)
- `POSIX_SPAWN_START_SUSPENDED`: Suspended olarak başlatır
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlatır
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullanır
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin verir
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapatır
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ının yüksek bitlerini randomize eder

Buna ek olarak, `posix_spawn` oluşturulan process'in bazı yönlerini kontrol eden bir **`posix_spawnattr`** dizisi ve descriptor'ların durumunu değiştirmek için **`posix_spawn_file_actions`** belirtmeye izin verir.

Bir process öldüğünde, **return code'u parent process'e** (parent öldüyse yeni parent PID 1'dir) `SIGCHLD` signal'i ile gönderir. Parent'ın bu değeri `wait4()` veya `waitid()` çağrısıyla alması gerekir; bu gerçekleşene kadar child, hâlâ listelenen ancak kaynak tüketmeyen zombie durumunda kalır.

### PIDs

PID'ler (process identifier'lar) benzersiz bir process'i tanımlar. XNU'da **PID'ler** 64 bit'tir, monotonik olarak artar ve **asla wrap olmaz** (abuse'ları önlemek için).

### Process Groups, Sessions & Coalations

**Process'ler**, yönetilmelerini kolaylaştırmak için **group'lara** eklenebilir. Örneğin, bir shell script içindeki komutlar aynı process group içinde olur; böylece örneğin kill kullanılarak **birlikte signal gönderilebilir**.\
Process'leri **session'lar içinde group'lamak** da mümkündür. Bir process bir session başlattığında (`setsid(2)`), child process'ler kendi session'larını başlatmadıkları sürece bu session'ın içine yerleştirilir.

Coalition, Darwin'de process'leri gruplamanın başka bir yoludur. Bir process'in bir coalition'a katılması, pool kaynaklarına erişmesini, bir ledger paylaşmasını veya Jetsam ile karşılaşmasını sağlar. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **privilege'larını tanımlayan** **credential'ları** barındırır. Her process'in bir primary `uid` ve bir primary `gid` değeri vardır (birden fazla group'a ait olabilir).\
Binary'de `setuid/setgid` bit'i varsa user ve group id'sini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credential** set'i sağlar. Bir persona'yı benimsemek, onun uid, gid ve group üyeliklerini **tek seferde** devralmak anlamına gelir. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:
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

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX threads (`pthreads`) desteği sunar. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu library, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak XNU kernel'e (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir system call olan `bsdthread_create()` işlevini çağırır. Bu system call, scheduling policy ve stack size dahil olmak üzere thread davranışını belirleyen `pthread_attr` (attributes) değerlerinden türetilen çeşitli flag'leri alır.
- **Varsayılan Stack Size:** Yeni thread'ler için varsayılan stack size 512 KB'dir. Bu değer tipik işlemler için yeterlidir, ancak daha fazla veya daha az alana ihtiyaç duyulursa thread attributes aracılığıyla ayarlanabilir.
3. **Thread Initialization:** `__pthread_init()` işlevi thread setup sırasında kritik öneme sahiptir ve stack'in konumu ile size bilgilerini içerebilen environment variable'ları ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Termination

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in gerekli cleanup işlemlerini gerçekleştirerek düzgün şekilde çıkmasını ve herhangi bir joiner'a return value göndermesini sağlar.
2. **Thread Cleanup:** `pthread_exit()` çağrıldığında, tüm ilişkili thread structure'larının kaldırılmasını yöneten `pthread_terminate()` işlevi çağrılır. Mach thread port'larını (Mach, XNU kernel içindeki communication subsystem'dir) deallocate eder ve thread ile ilişkili kernel-level structure'larını kaldıran bir syscall olan `bsdthread_terminate` işlevini çağırır.

#### Synchronization Mechanisms

Shared resource'lara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli synchronization primitive'leri sunar. Bunlar, data integrity ve system stability sağlamak için multi-threading environment'larında kritik öneme sahiptir:

1. **Mutex'ler:**
- **Regular Mutex (Signature: 0x4D555458):** 60 byte memory footprint'e sahip standard mutex (mutex için 56 byte ve signature için 4 byte).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir ve yine 60 byte boyutundadır.
2. **Condition Variables:**
- Belirli condition'ların gerçekleşmesini beklemek için kullanılır ve 44 byte boyutundadır (40 byte artı 4 byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variable'lar için configuration attributes'tur ve 12 byte boyutundadır.
3. **Once Variable (Signature: 0x4f4e4345):**
- Bir initialization code parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 byte'tır.
4. **Read-Write Locks:**
- Birden fazla reader'a veya aynı anda tek bir writer'a izin vererek shared data'ya verimli erişim sağlar.
- **Read Write Lock (Signature: 0x52574c4b):** 196 byte boyutundadır.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için attributes'tur ve 20 byte boyutundadır.

> [!TIP]
> Bu object'lerin son 4 byte'ı overflow'ları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O file'lar (macOS'taki executable'ların formatı) bağlamında **Thread Local Variables (TLV)**, multi-threaded application içindeki **her thread'e** özgü variable'ları tanımlamak için kullanılır. Bu, her thread'in bir variable'ın kendine ait ayrı bir instance'ına sahip olmasını sağlar ve mutex gibi explicit synchronization mechanism'lere ihtiyaç duymadan conflict'leri önlemeye ve data integrity'yi korumaya olanak tanır.

C ve ilişkili language'lerde, **`__thread`** keyword'ünü kullanarak thread-local variable tanımlayabilirsiniz. Örneğimizde şu şekilde çalışır:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu snippet, `tlv_var` öğesini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary içinde thread-local değişkenlerle ilgili veriler belirli section'larda düzenlenir:

- **`__DATA.__thread_vars`**: Bu section, thread-local değişkenler hakkındaki türleri ve initialization durumlarını belirten metadata'yı içerir.
- **`__DATA.__thread_bss`**: Bu section, açıkça initialize edilmemiş thread-local değişkenler için kullanılır. Sıfırla initialize edilen veriler için ayrılmış memory'nin bir parçasıdır.

Mach-O ayrıca thread sona erdiğinde thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verileri temizleyen özel fonksiyonlar olan **destructor'ları register etmenize** olanak tanır.

### Threading Priorities

Thread priority'lerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan priority level'dan etkilenir. macOS ve Unix-like sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) class'ları gibi kavramlar kullanılarak gerçekleştirilir.

#### Nice and Renice

1. **Nice:**
- Bir process'in `nice` değeri, priority'sini etkileyen bir sayıdır. Her process'in -20 (en yüksek priority) ile 19 (en düşük priority) arasında değişen bir nice değeri vardır. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri (-20'ye daha yakın), bir process'i daha "selfish" hale getirir ve daha yüksek nice değerlerine sahip diğer process'lere kıyasla daha fazla CPU time almasını sağlar.
2. **Renice:**
- `renice`, zaten çalışmakta olan bir process'in nice değerini değiştirmek için kullanılan bir command'dir. Bu, process'lerin priority'sini dinamik olarak ayarlamak ve yeni nice değerlerine göre CPU time allocation'ını artırmak veya azaltmak için kullanılabilir.
- Örneğin, bir process geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Classes

QoS class'ları, özellikle **Grand Central Dispatch (GCD)** destekleyen macOS gibi sistemlerde thread priority'lerini yönetmek için daha modern bir yaklaşımdır. QoS class'ları, geliştiricilerin çalışmaları önem veya aciliyetlerine göre farklı level'lara **categorize etmelerine** olanak tanır. macOS, bu QoS class'larına göre thread prioritization işlemini otomatik olarak yönetir:

1. **User Interactive:**
- Bu class, kullanıcıyla o anda etkileşim hâlinde olan veya iyi bir user experience sağlamak için anında sonuç gerektiren task'ler içindir. Interface'in responsive kalması için bu task'lere en yüksek priority verilir (ör. animation'lar veya event handling).
2. **User Initiated:**
- Kullanıcının başlattığı ve bir document açmak veya computation gerektiren bir button'a tıklamak gibi anında sonuç beklediği task'lerdir. Bunlar yüksek priority'ye sahiptir ancak user interactive seviyesinin altındadır.
3. **Utility:**
- Bunlar uzun süren ve genellikle bir progress indicator gösteren task'lerdir (ör. file download etme veya data import etme). User-initiated task'lerden daha düşük priority'ye sahiptirler ve hemen tamamlanmaları gerekmez.
4. **Background:**
- Bu class, arka planda çalışan ve kullanıcı tarafından görünür olmayan task'ler içindir. Indexing, syncing veya backup gibi task'ler olabilir. En düşük priority'ye ve system performance üzerinde minimum etkiye sahiptirler.

QoS class'larını kullanan geliştiricilerin kesin priority numaralarını yönetmesi gerekmez; bunun yerine task'in niteliğine odaklanabilirler ve system CPU kaynaklarını buna göre optimize eder.

Ayrıca scheduler'ın dikkate alacağı bir scheduling parameter set'i belirtmek için kullanılan farklı **thread scheduling policies** vardır. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition attack'lerinde faydalı olabilir.

## MacOS Process Abuse

MacOS, diğer tüm işletim sistemleri gibi **process'lerin etkileşim kurması, iletişim sağlaması ve data paylaşması** için çeşitli method ve mechanism'ler sunar. Bu teknikler system'in verimli çalışması için gerekli olsa da threat actor'lar tarafından **malicious activity gerçekleştirmek** için abuse edilebilir.

### Library Injection

Library Injection, bir attacker'ın **bir process'i malicious bir library load etmeye zorladığı** bir tekniktir. Inject edildikten sonra library, target process'in context'inde çalışır ve attacker'a process ile aynı permission ve access seviyelerini sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, bir software code içindeki **function call'ları** veya mesajları **intercept etmeyi** içerir. Bir attacker function'ları hook ederek bir process'in **davranışını değiştirebilir**, sensitive data'yı gözlemleyebilir veya execution flow'un kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **data paylaşmasını ve exchange etmesini** sağlayan farklı method'ları ifade eder. IPC birçok legitimate application için temel öneme sahip olsa da process isolation'ı subvert etmek, sensitive information'ı leak etmek veya unauthorized action gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env variable'lar ile çalıştırılan Electron application'ları process injection'a karşı vulnerable olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak **man in the browser attack** gerçekleştirmek mümkündür. Bu, keystroke'ları ve traffic'i çalmaya, cookie'leri ele geçirmeye ve page'lere script inject etmeye olanak tanır...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file'ları bir application içindeki **user interface (UI) element'lerini** ve bunların etkileşimlerini **tanımlar**. Ancak arbitrary command'ler **execute edebilirler** ve bir **NIB file modify edilmişse**, **Gatekeeper zaten çalıştırılmış bir application'ın yeniden çalıştırılmasını engellemez**. Bu nedenle arbitrary program'ları arbitrary command'ler execute edecek şekilde kullanmak mümkündür:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Belirli Java capability'lerini (`**_JAVA_OPTS**` env variable'ı gibi) abuse ederek bir Java application'ının **arbitrary code/command execute etmesini** sağlamak mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

.Net application'larına, **.Net debugging functionality'sini abuse ederek** (runtime hardening gibi macOS protection'ları tarafından korunmaz) code inject etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin arbitrary code execute etmesini sağlamak için farklı option'ları inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary script'lerin arbitrary code execute etmesini sağlamak için Ruby env variable'larını abuse etmek de mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONINSPECT`** environment variable'ı set edilirse Python process'i tamamlandığında bir Python CLI'ye geçer. Interactive session'ın başlangıcında bir Python script'i execute edilmesini belirtmek için **`PYTHONSTARTUP`** da kullanılabilir.\
Ancak **`PYTHONINSPECT`** interactive session'ı oluşturduğunda **`PYTHONSTARTUP`** script'inin execute edilmeyeceğini unutmayın.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer env variable'lar da bir Python command'inin arbitrary code execute etmesini sağlamak için faydalı olabilir.

`pyinstaller` ile compile edilen executable'ların embedded Python kullanarak çalışıyor olsalar bile bu environment variable'ları kullanmayacağını unutmayın.

> [!CAUTION]
> Genel olarak environment variable'larını abuse ederek Python'a arbitrary code execute ettirmenin bir yolunu bulamadım.\
> Ancak insanların çoğu Python'u **Hombrew** kullanarak install eder; bu işlem Python'u varsayılan admin user için **writable bir location'a** install eder. Şuna benzer bir yöntemle bunu hijack edebilirsiniz:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Python çalıştırıldığında **root** bile bu code'u çalıştırır.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı detect edip block eden, open source ve **EndpointSecurity** tabanlı bir application'dır. ES üzerinden hangi signal'ların gerçekten gözlemlenebildiği konusunda iyi bir reference'tır; aşağıdaki durumlarda alert verir:<sup>[[1]](#references)</sup>

- Process exec sırasında **injection environment variable'ları**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call'ları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection yapmak için ön koşuldur.
- **Electron debugging argument'ları** — Electron application'ını debug mode'da başlatan ve herkesin bağlanarak code çalıştırmasına olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.
- **Privilege level'lar arasında symlink/hardlink oluşturma** — normal bir user olarak bir link oluşturup bunu privileged bir location'a yönlendirmeye dayanan klasik primitive. **Symlink'ler alert'e konu olabilir ancak block edilemez**: EndpointSecurity, link oluşturulmadan önce link destination'ını expose etmez.

### Calls made by other processes

[**Bu blog post'ta**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), **`task_name_for_pid`** function'ının bir process'e code inject eden diğer **process'ler** hakkında information almak ve ardından o diğer process hakkında bilgi edinmek için nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu function'ı call etmek için process'i çalıştıran user ile **aynı uid'ye** veya **root** yetkisine sahip olmanız gerektiğini unutmayın (function process hakkında bilgi döndürür; code inject etmek için bir yöntem sunmaz).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
