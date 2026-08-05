# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Bir process, çalışan bir executable'ın örneğidir; ancak process'ler code çalıştırmaz, bunu thread'ler yapar. Bu nedenle **process'ler, çalışan thread'ler için yalnızca container'lardır** ve memory, descriptor, port, permission gibi kaynakları sağlarlar.

Geleneksel olarak process'ler (PID 1 hariç) diğer process'lerin içinde **`fork`** çağrılarak başlatılırdı. Bu çağrı mevcut process'in birebir kopyasını oluşturur ve ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağırırdı. Daha sonra, herhangi bir memory kopyalaması yapmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`posix_spawn`**, **`vfork`** ve **`execve`** işlevlerini tek bir çağrıda birleştirecek ve flag'leri kabul edecek şekilde kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Effective id'leri real id'lere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Process group ilişkisini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Signal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Signal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde Exec yap (`execve` gibi, ancak daha fazla seçenekle)
- `POSIX_SPAWN_START_SUSPENDED`: Suspended olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ının yüksek bitlerini randomize et

Ayrıca `posix_spawn`, oluşturulan process'in bazı yönlerini kontrol eden **`posix_spawnattr`** dizisini ve descriptor'ların durumunu değiştirmek için **`posix_spawn_file_actions`** belirtmeye olanak tanır.

Bir process öldüğünde, **return code'u parent process'e** (parent öldüyse yeni parent PID 1'dir) `SIGCHLD` signal'iyle gönderir. Parent'ın bu değeri `wait4()` veya `waitid()` çağrısıyla alması gerekir; bu gerçekleşene kadar child, hâlâ listelenen ancak kaynak tüketmeyen zombie state'te kalır.

### PIDs

PID'ler, yani process identifier'lar, benzersiz bir process'i tanımlar. XNU'da **PID'ler** 64 bit'tir, monotonik olarak artar ve **asla wrap olmaz** (abuse'ları önlemek için).

### Process Groups, Sessions & Coalations

**Process'ler**, yönetilmelerini kolaylaştırmak için **group'lara** yerleştirilebilir. Örneğin bir shell script'teki komutlar aynı process group içinde olur; böylece örneğin kill kullanılarak **hep birlikte signal gönderilmeleri** mümkün olur.\
Process'leri **session'lar içinde gruplamak** da mümkündür. Bir process bir session başlattığında (`setsid(2)`), child process'ler kendi session'larını başlatmadıkları sürece bu session içine yerleştirilir.

Coalition, Darwin'de process'leri gruplamanın başka bir yoludur. Bir process'in coalition'a katılması, pool kaynaklarına erişmesine, bir ledger'ı paylaşmasına veya Jetsam ile karşılaşmasına olanak tanır. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **privilege'larını tanımlayan** **credential'ları** taşır. Her process'in bir primary `uid` ve bir primary `gid` değeri vardır (birden fazla group'a ait olabilmesine rağmen).\
Binary'de `setuid/setgid` biti varsa user ve group id'lerini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credential** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve group üyeliklerini **aynı anda** kabul eder. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:
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

1. **POSIX Thread'leri (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'taki pthreads implementasyonu, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu library, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** `pthread_create()` function'ı yeni thread'ler oluşturmak için kullanılır. Bu function, dahili olarak XNU kernel'ine (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir system call olan `bsdthread_create()` function'ını çağırır. Bu system call, scheduling policy'leri ve stack size dahil olmak üzere thread davranışını belirleyen `pthread_attr` (attributes) kaynaklı çeşitli flag'leri alır.
- **Default Stack Size:** Yeni thread'ler için default stack size 512 KB'tır. Bu değer tipik işlemler için yeterlidir, ancak daha fazla veya daha az alan gerekirse thread attribute'ları aracılığıyla ayarlanabilir.
3. **Thread Initialization:** `__pthread_init()` function'ı, thread setup'ı sırasında kritik bir rol oynar ve stack'in konumu ile size'ı hakkındaki ayrıntıları içerebilen environment variable'larını ayrıştırmak için `env[]` argument'ını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu function, bir thread'in temiz bir şekilde çıkmasını, gerekli cleanup işlemlerini gerçekleştirmesini ve herhangi bir joiner'a return value göndermesini sağlar.
2. **Thread Cleanup:** `pthread_exit()` çağrıldığında, ilgili tüm thread structure'larının kaldırılmasını yöneten `pthread_terminate()` function'ı çağrılır. Mach thread port'larını (Mach, XNU kernel'indeki communication subsystem'dir) deallocate eder ve thread ile ilişkili kernel-level structure'larını kaldıran bir syscall olan `bsdthread_terminate`'ı çağırır.

#### Synchronization Mechanism'leri

Shared resource'lara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli synchronization primitive'leri sağlar. Bunlar, data integrity ve system stability'yi garanti etmek için multi-threading environment'larında kritik öneme sahiptir:

1. **Mutex'ler:**
- **Regular Mutex (Signature: 0x4D555458):** Mutex ve signature için sırasıyla 56 ve 4 byte olmak üzere toplam 60 byte memory footprint'e sahip standart mutex.
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer, ancak daha hızlı operation'lar için optimize edilmiştir ve yine 60 byte boyutundadır.
2. **Condition Variable'lar:**
- Belirli condition'ların gerçekleşmesini beklemek için kullanılır; 44 byte boyutundadır (40 byte artı 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variable'lar için configuration attribute'larıdır ve 12 byte boyutundadır.
3. **Once Variable (Signature: 0x4f4e4345):**
- Bir initialization code parçasının yalnızca bir kez execute edilmesini sağlar. Boyutu 12 byte'tır.
4. **Read-Write Lock'lar:**
- Aynı anda birden fazla reader'a veya tek bir writer'a izin vererek shared data'ya verimli erişim sağlar.
- **Read Write Lock (Signature: 0x52574c4b):** 196 byte boyutundadır.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için attribute'lar olup boyutu 20 byte'tır.

> [!TIP]
> Bu object'lerin son 4 byte'ı overflow'ları tespit etmek için kullanılır.

### Thread Local Variable'lar (TLV)

Mach-O file'ları (macOS'taki executable'ların formatı) bağlamında **Thread Local Variable'lar (TLV)**, multi-threaded application'larda **her thread'e** özgü variable'ları tanımlamak için kullanılır. Bu, her thread'in bir variable'ın kendine ait ayrı bir instance'ına sahip olmasını sağlar ve mutex gibi explicit synchronization mechanism'lerine ihtiyaç duymadan conflict'leri önlemek ve data integrity'yi korumak için bir yöntem sunar.

C ve ilgili language'larda, **`__thread`** keyword'ünü kullanarak thread-local variable tanımlayabilirsiniz. Örneğinizde bunun nasıl çalıştığı aşağıda gösterilmiştir:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu snippet, `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary içinde, thread local değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, thread-local değişkenlerin türleri ve initialization durumu gibi metadata bilgilerini içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça initialize edilmemiş thread-local değişkenler için kullanılır. Sıfırla initialize edilen veriler için ayrılmış bellek alanının bir parçasıdır.

Mach-O ayrıca thread sonlandığında thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verileri temizleyen özel fonksiyonlar olan **destructor**'ları **register** etmenize olanak tanır.

### Threading Priorities

Thread priority'lerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan priority seviyesi tarafından etkilenir. macOS ve Unix-like sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) class'ları gibi kavramlar kullanılarak gerçekleştirilir.

#### Nice ve Renice

1. **Nice:**
- Bir process'in `nice` değeri, priority'sini etkileyen bir sayıdır. Her process'in -20 (en yüksek priority) ile 19 (en düşük priority) arasında bir nice değeri vardır. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri (-20'ye daha yakın) bir process'i daha "selfish" hale getirir ve daha yüksek nice değerlerine sahip diğer process'lere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
- `renice`, halihazırda çalışan bir process'in nice değerini değiştirmek için kullanılan bir command'dir. Bu, yeni nice değerlerine göre CPU zamanı allocation'ını artırarak veya azaltarak process'lerin priority'sini dinamik şekilde ayarlamak için kullanılabilir.
- Örneğin, bir process'in geçici olarak daha fazla CPU kaynağına ihtiyacı varsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Classes

QoS class'ları, özellikle **Grand Central Dispatch (GCD)** destekleyen macOS gibi sistemlerde thread priority'lerini yönetmek için daha modern bir yaklaşımdır. QoS class'ları, geliştiricilerin çalışmaları önem veya aciliyet seviyelerine göre farklı düzeylerde **categorize** etmelerini sağlar. macOS, bu QoS class'larına göre thread prioritization işlemini otomatik olarak yönetir:

1. **User Interactive:**
- Bu class, kullanıcıyla o anda etkileşimde olan veya iyi bir user experience sağlamak için anında sonuç gerektiren task'ler içindir. Interface'in responsive kalması için bu task'lere en yüksek priority verilir (ör. animation'lar veya event handling).
2. **User Initiated:**
- Kullanıcının başlattığı ve bir document açmak veya computation gerektiren bir button'a tıklamak gibi anında sonuç beklediği task'lerdir. Bunlar yüksek priority'ye sahiptir ancak user interactive seviyesinin altındadır.
3. **Utility:**
- Bunlar uzun süre çalışan ve genellikle bir progress indicator gösteren task'lerdir (ör. file download veya data import). User-initiated task'lere göre daha düşük priority'ye sahiptir ve hemen tamamlanmaları gerekmez.
4. **Background:**
- Bu class, arka planda çalışan ve kullanıcı tarafından görünmeyen task'ler içindir. Indexing, syncing veya backup gibi task'ler bu kapsama girer. En düşük priority'ye ve system performance üzerinde minimum etkiye sahiptirler.

QoS class'larını kullanan geliştiricilerin kesin priority numaralarını yönetmesi gerekmez; bunun yerine task'in niteliğine odaklanabilirler ve system CPU kaynaklarını buna göre optimize eder.

Ayrıca scheduler'ın dikkate alacağı bir scheduling parameter set'i belirtmek için kullanılan farklı **thread scheduling policies** vardır. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition attacks için yararlı olabilir.

## MacOS Process Abuse

MacOS, diğer tüm işletim sistemleri gibi **process'lerin etkileşim kurması, communication gerçekleştirmesi ve data paylaşması** için çeşitli yöntemler ve mekanizmalar sağlar. Bu teknikler system'in verimli şekilde çalışması için gerekli olsa da threat actor'lar tarafından **malicious activities gerçekleştirmek** amacıyla abuse edilebilir.

### Library Injection

Library Injection, attacker'ın **bir process'i malicious bir library yüklemeye zorladığı** bir tekniktir. Inject edildikten sonra library, target process'in context'inde çalışır ve attacker'a process ile aynı permission ve access seviyelerini sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, software code içindeki **function call'ları** veya mesajları **intercept etmeyi** içerir. Bir attacker function'ları hook'layarak bir process'in **behavior'ını modify** edebilir, sensitive data'yı gözlemleyebilir veya execution flow'un kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **data paylaşması ve exchange etmesi** için kullanılan farklı yöntemleri ifade eder. IPC birçok legitimate application için temel bir işlev olsa da process isolation'ı subvert etmek, sensitive information'ı leak etmek veya unauthorized action'lar gerçekleştirmek için de misuse edilebilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env variable'lar ile çalıştırılan Electron application'ları process injection'a karşı vulnerable olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'leri kullanılarak **man in the browser attack** gerçekleştirmek mümkündür. Bu, keystroke'ları ve traffic'i çalmaya, cookie'leri ele geçirmeye, page'lere script inject etmeye vb. olanak tanır:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file'ları bir application içindeki **user interface (UI) element'lerini** ve bunların etkileşimlerini **tanımlar**. Ancak arbitrary command'ler **execute edebilirler** ve **Gatekeeper, bir NIB file modify edilmişse daha önce execute edilmiş bir application'ın yeniden execute edilmesini engellemez**. Bu nedenle arbitrary program'ları arbitrary command'ler execute edecek şekilde kullanmak mümkün olabilir:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Belirli Java capability'leri (örneğin **`_JAVA_OPTS`** env variable'ı) abuse edilerek bir Java application'ının **arbitrary code/command execute etmesi** sağlanabilir.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

macOS protections (runtime hardening gibi) tarafından korunmayan **.Net debugging functionality** abuse edilerek .Net application'larına code inject etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin arbitrary code execute etmesini sağlamak için kullanılabilecek farklı seçenekleri burada inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary script'lerin arbitrary code execute etmesini sağlamak için Ruby env variable'ları da abuse edilebilir:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONINSPECT`** env variable'ı set edilirse Python process'i tamamlandıktan sonra Python CLI'ya düşer. Interactive session'ın başlangıcında bir Python script'i execute etmek için **`PYTHONSTARTUP`** da kullanılabilir.\
Ancak **`PYTHONINSPECT`** interactive session'ı oluşturduğunda **`PYTHONSTARTUP`** script'inin execute edilmeyeceğini unutmayın.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer env variable'lar da bir Python command'inin arbitrary code execute etmesini sağlamak için yararlı olabilir.

**`pyinstaller`** ile compile edilmiş executable'ların embedded Python kullanarak çalışıyor olsalar bile bu environment variable'ları kullanmayacağını unutmayın.

> [!CAUTION]
> Genel olarak environment variable'ları abuse ederek Python'a arbitrary code execute ettirmenin bir yolunu bulamadım.\
> Ancak çoğu kişi Python'ı **Hombrew** kullanarak install eder. Bu işlem Python'ı varsayılan admin user için **writable bir location** içine install eder. Şuna benzer bir yöntemle hijack edebilirsiniz:
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

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı detect edip block eden, open source ve **EndpointSecurity** tabanlı bir application'dır. ES üzerinden gerçekten gözlemlenebilen signal'lar için iyi bir reference'tır; çünkü şunlarda alert verir:<sup>[1]</sup>

- Process exec sırasında **injection environment variable**'ları: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call'ları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection yapmanın prerequisite'idir.
- **Electron debugging argument'ları** — Electron app'ini debug mode'da başlatan ve herkesin app'e attach olup code çalıştırmasına olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.
- **Privilege level'lar arasında symlink/hardlink oluşturma** — klasik "normal user olarak bir link oluşturup privileged bir location'ı işaret ettirme" primitive'i. **Symlink'ler alert'e konu olabilir ancak block edilemez**: EndpointSecurity, oluşturulmadan önce link destination'ını expose etmez.

### Calls made by other processes

[**Bu blog postunda**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **process'lerin bir process'e code inject ettiğine** dair information almak ve ardından bu diğer process hakkında bilgi edinmek için **`task_name_for_pid`** function'ının nasıl kullanılabileceğini görebilirsiniz.<sup>[4]</sup>

Bu function'ı çağırmak için process'i çalıştıran user ile **aynı uid'ye** veya **root** yetkisine sahip olmanız gerekir (function, process hakkında information döndürür; code inject etme yöntemi sağlamaz).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
