# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Bir process, çalışan bir executable örneğidir; ancak process'ler code çalıştırmaz, bunları thread'ler çalıştırır. Bu nedenle **process'ler, çalışan thread'ler için yalnızca container'lardır** ve memory, descriptor'lar, port'lar, permission'lar sağlarlar...

Geleneksel olarak process'ler, **`fork`** çağrılarak diğer process'lerin (PID 1 hariç) içinde başlatılırdı. Bu işlem mevcut process'in birebir kopyasını oluşturur ve ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağırırdı. Daha sonra, herhangi bir memory copying işlemi olmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`posix_spawn`**, **`vfork`** ve **`execve`** işlemlerini tek bir çağrıda birleştirerek ve flag'leri kabul ederek kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Effective id'leri real id'lere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Process group ilişkisini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Signal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Signal mask'ını ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde Exec gerçekleştir (`execve` ile daha fazla seçenek)
- `POSIX_SPAWN_START_SUSPENDED`: Suspended olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ının yüksek bit'lerini randomize et

Ayrıca `posix_spawn`, oluşturulan process'in bazı özelliklerini kontrol eden bir **`posix_spawnattr`** array'inin ve descriptor'ların durumunu değiştiren **`posix_spawn_file_actions`** öğelerinin belirtilmesine izin verir.

Bir process öldüğünde, **return code'u parent process'e** (parent ölmüşse yeni parent PID 1'dir) `SIGCHLD` signal'i ile gönderir. Parent'ın bu değeri `wait4()` veya `waitid()` çağırarak alması gerekir; bu gerçekleşene kadar child, hâlâ listelenen ancak resource tüketmeyen zombie state'te kalır.

### PIDs

PID'ler, yani process identifier'ları, benzersiz bir process'i tanımlar. XNU'da **PID'ler** 64 bit'tir, monotonik olarak artar ve abuse'ları önlemek için **asla wrap olmaz**.

### Process Groups, Sessions & Coalations

**Process'ler**, yönetilmelerini kolaylaştırmak için **group'lar** içine yerleştirilebilir. Örneğin, bir shell script içindeki command'lar aynı process group içinde olur; böylece örneğin kill kullanılarak **birlikte signal gönderilebilir**.\
Ayrıca **process'leri session'lar içinde group'lamak** da mümkündür. Bir process bir session başlattığında (`setsid(2)`), child process'ler kendi session'larını başlatmadıkları sürece bu session içine yerleştirilir.

Coalition, Darwin'de process'leri gruplamanın başka bir yoludur. Bir process'in coalition'a katılması, pool resource'larına erişmesini, bir ledger'ı paylaşmasını veya Jetsam ile karşı karşıya kalmasını sağlar. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **privilege'larını tanımlayan** **credential'ları** barındırır. Her process'in bir primary `uid`'si ve bir primary `gid`'si vardır (birden fazla group'a ait olabilir).\
Binary'de `setuid/setgid` biti varsa user ve group id'sini değiştirmek de mümkündür.\
**Yeni uid/gid'ler ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credential** set'i sağlar. Bir persona'yı benimsemek, onun uid, gid ve group üyeliklerini **aynı anda** devralmak anlamına gelir. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:
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

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'nin parçası olan POSIX threads (`pthreads`) desteği sunar. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu library, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` function'ı kullanılır. Bu function dahili olarak, XNU kernel'ine (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir system call olan `bsdthread_create()` function'ını çağırır. Bu system call, scheduling policy'leri ve stack size dahil olmak üzere thread davranışını belirleyen `pthread_attr`'dan (attributes) türetilen çeşitli flag'leri alır.
- **Varsayılan Stack Size:** Yeni thread'ler için varsayılan stack size 512 KB'dir. Bu boyut tipik işlemler için yeterlidir, ancak daha fazla veya daha az alana ihtiyaç duyulması halinde thread attributes aracılığıyla ayarlanabilir.
3. **Thread Initialization:** `__pthread_init()` function'ı, thread kurulumu sırasında kritik bir role sahiptir ve stack'in konumu ile size'ı hakkında ayrıntılar içerebilen environment variable'ları ayrıştırmak için `env[]` argument'ını kullanır.

#### macOS'ta Thread Termination

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu function, bir thread'in gerekli cleanup işlemlerini gerçekleştirerek düzgün şekilde çıkmasını ve join işlemi yapan thread'lere bir return value göndermesini sağlar.
2. **Thread Cleanup:** `pthread_exit()` çağrıldığında, ilişkili tüm thread structure'larının kaldırılmasını yöneten `pthread_terminate()` function'ı çağrılır. Mach thread port'larını (Mach, XNU kernel içindeki communication subsystem'dir) deallocate eder ve thread ile ilişkili kernel-level structure'larını kaldıran bir syscall olan `bsdthread_terminate`'ı çağırır.

#### Synchronization Mechanism'leri

macOS, shared resource'lara erişimi yönetmek ve race condition'ları önlemek için çeşitli synchronization primitive'leri sunar. Bunlar, data integrity ve system stability sağlamak için multi-threading environment'larında kritik öneme sahiptir:

1. **Mutex'ler:**
- **Regular Mutex (Signature: 0x4D555458):** 60 byte memory footprint'e sahip standart mutex (56 byte mutex ve 4 byte signature için).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir ve yine 60 byte boyutundadır.
2. **Condition Variable'lar:**
- Belirli condition'ların gerçekleşmesini beklemek için kullanılır; 44 byte boyutundadır (40 byte ve 4 byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variable'lar için configuration attributes'tur ve 12 byte boyutundadır.
3. **Once Variable (Signature: 0x4f4e4345):**
- Bir initialization code parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 byte'tır.
4. **Read-Write Lock'lar:**
- Aynı anda birden fazla reader'a veya tek bir writer'a izin vererek shared data'ya verimli erişim sağlar.
- **Read Write Lock (Signature: 0x52574c4b):** 196 byte boyutundadır.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için attributes'tur ve 20 byte boyutundadır.

> [!TIP]
> Bu object'lerin son 4 byte'ı overflow'ları detect etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O file'ları (macOS'taki executable'lar için kullanılan format) bağlamında **Thread Local Variables (TLV)**, multi-threaded application'daki **her thread'e** özgü variable'ları tanımlamak için kullanılır. Bu, her thread'in bir variable'ın kendi ayrı instance'ına sahip olmasını sağlar ve mutex gibi explicit synchronization mechanism'lerine ihtiyaç duymadan conflict'leri önlemek ve data integrity'yi korumak için bir yol sunar.

C ve ilişkili language'lerde, **`__thread`** keyword'ünü kullanarak thread-local variable tanımlayabilirsiniz. Örneğinizde bunun çalışma şekli şöyledir:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu snippet, `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary içinde thread-local değişkenlerle ilgili veriler belirli section'larda düzenlenir:

- **`__DATA.__thread_vars`**: Bu section, thread-local değişkenlerle ilgili türleri ve başlatma durumlarını belirten metadata'yı içerir.
- **`__DATA.__thread_bss`**: Bu section, açıkça başlatılmamış thread-local değişkenler için kullanılır. Sıfırla başlatılan veriler için ayrılmış belleğin bir parçasıdır.

Mach-O ayrıca bir thread sonlandığında thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verilerini temizleyen özel fonksiyonlar olan **destructor'ları kaydetmenize** olanak tanır.

### Threading Priorities

Thread priority'lerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan priority seviyesinden etkilenir. macOS ve Unix-like sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlar kullanılarak gerçekleştirilir.

#### Nice and Renice

1. **Nice:**
- Bir process'in `nice` değeri, priority'sini etkileyen bir sayıdır. Her process'in -20 (en yüksek priority) ile 19 (en düşük priority) arasında bir nice değeri vardır. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri (-20'ye daha yakın), bir process'i daha "bencil" hâle getirir ve daha yüksek nice değerlerine sahip diğer process'lere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
- `renice`, hâlihazırda çalışan bir process'in nice değerini değiştirmek için kullanılan bir command'dir. Bu, yeni nice değerlerine göre CPU zamanı tahsisini artırarak veya azaltarak process'lerin priority'sini dinamik olarak ayarlamak için kullanılabilir.
- Örneğin, bir process'in geçici olarak daha fazla CPU kaynağına ihtiyacı varsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Classes

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** destekleyen macOS gibi sistemlerde thread priority'lerini yönetmek için daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyetlerine göre farklı seviyelerde **kategorilere ayırmasına** olanak tanır. macOS, bu QoS sınıflarına göre thread prioritization işlemini otomatik olarak yönetir:

1. **User Interactive:**
- Bu sınıf, hâlihazırda kullanıcıyla etkileşim hâlinde olan veya iyi bir kullanıcı deneyimi sağlamak için anında sonuç gerektiren task'ler içindir. Interface'in yanıt verebilir kalmasını sağlamak için bu task'lere en yüksek priority verilir (ör. animation'lar veya event handling).
2. **User Initiated:**
- Kullanıcının başlattığı ve bir document açmak veya computation gerektiren bir button'a tıklamak gibi anında sonuç beklediği task'lerdir. Bunlar yüksek priority'ye sahiptir ancak user interactive seviyesinin altındadır.
3. **Utility:**
- Bunlar uzun süren ve genellikle bir progress indicator gösteren task'lerdir (ör. file download veya data import). User-initiated task'lere göre daha düşük priority'ye sahiptir ve hemen tamamlanmaları gerekmez.
4. **Background:**
- Bu sınıf, background'da çalışan ve kullanıcı tarafından görünür olmayan task'ler içindir. Indexing, syncing veya backup gibi task'ler buna örnektir. En düşük priority'ye ve system performance üzerinde minimum etkiye sahiptirler.

QoS sınıflarını kullanırken geliştiricilerin kesin priority numaralarını yönetmesi gerekmez; bunun yerine task'in niteliğine odaklanabilirler ve system CPU kaynaklarını buna göre optimize eder.

Ayrıca, scheduler'ın dikkate alacağı bir dizi scheduling parametresini belirtmek için kullanılan farklı **thread scheduling policies** vardır. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition attack'lerinde faydalı olabilir.

## MacOS Process Abuse

MacOS, diğer tüm işletim sistemleri gibi **process'lerin etkileşim kurması, iletişim kurması ve data paylaşması** için çeşitli yöntem ve mekanizmalar sağlar. Bu teknikler system'in verimli çalışması için gerekli olsa da threat actor'lar tarafından **malicious activity gerçekleştirmek** amacıyla abuse edilebilir.

### Library Injection

Library Injection, bir attacker'ın **bir process'i malicious bir library yüklemeye zorladığı** bir tekniktir. Inject edildikten sonra library, target process'in context'inde çalışır ve attacker'a process ile aynı permission ve access seviyesini sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, bir software code içindeki **function call'larını** veya message'ları **intercept etmeyi** içerir. Bir attacker function'ları hook'layarak bir process'in **davranışını değiştirebilir**, sensitive data'yı gözlemleyebilir veya execution flow'un kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **data paylaşması ve exchange etmesi** için kullanılan farklı yöntemleri ifade eder. IPC birçok legitimate application için temel önem taşısa da process isolation'ı bypass etmek, sensitive information leak etmek veya unauthorized action gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env variable'larla çalıştırılan Electron application'ları process injection'a karşı vulnerable olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak **browser içi bir man in the browser attack** gerçekleştirmek mümkündür. Bu sayede keystroke'lar ve traffic çalınabilir, cookie'ler ele geçirilebilir, page'lere script inject edilebilir...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file'ları bir application içindeki **user interface (UI) element'lerini** ve bunların etkileşimlerini **tanımlar**. Ancak arbitrary command'ler **execute edebilirler** ve **NIB file değiştirilirse Gatekeeper hâlihazırda çalıştırılmış bir application'ın yeniden çalıştırılmasını engellemez**. Bu nedenle arbitrary program'ları arbitrary command'ler execute ettirmek için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Belirli Java capability'lerini (örneğin **`_JAVA_OPTS`** env variable'ını) abuse ederek bir Java application'a **arbitrary code/command execute ettirmek** mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

.Net application'larına, **.Net debugging functionality'sini abuse ederek** code inject etmek mümkündür (runtime hardening gibi macOS protection'ları tarafından korunmaz).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'ine arbitrary code execute ettirmek için farklı seçenekleri şu adreste inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary script'lere arbitrary code execute ettirmek için Ruby env variable'larını abuse etmek de mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONINSPECT`** environment variable'ı set edilirse Python process'i tamamlandığında bir Python CLI'ye düşer. Ayrıca interaktif bir session'ın başlangıcında execute edilecek bir Python script'i belirtmek için **`PYTHONSTARTUP`** kullanılabilir.\
Ancak **`PYTHONINSPECT`** interaktif session'ı oluşturduğunda **`PYTHONSTARTUP`** script'inin execute edilmeyeceğini unutmayın.

**`PYTHONPATH`** ve **`PYTHONHOME`** gibi diğer env variable'lar da bir Python command'inin arbitrary code execute etmesini sağlamak için faydalı olabilir.

`pyinstaller` ile compile edilmiş executable'ların embedded Python kullanarak çalışsalar bile bu environment variable'ları kullanmayacağını unutmayın.

> [!CAUTION]
> Genel olarak environment variable'ları abuse ederek Python'a arbitrary code execute ettirmenin bir yolunu bulamadım.\
> Ancak çoğu kişi Python'u **Hombrew** kullanarak install eder; bu işlem Python'u varsayılan admin user için **writable bir location'a** kurar. Şuna benzer bir yöntemle hijack edebilirsiniz:
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

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı detect edip block eden, open source ve **EndpointSecurity** tabanlı bir application'dır. ES üzerinden hangi signal'ların gerçekten gözlemlenebilir olduğunu anlamak için iyi bir reference'tır; çünkü şu durumlarda alert verir:<sup>[[1]](#references)[[2]](#references)</sup>

- Process exec sırasında **injection environment variable'ları**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call'ları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection yapmak için ön koşuldur.
- **Electron debugging argument'ları** — Electron application'ını debug mode'da başlatan ve herkesin ona attach olup code çalıştırmasına olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port` flag'leri.<sup>[[3]](#references)</sup>
- **Privilege seviyeleri arasında symlink/hardlink oluşturma** — normal bir user olarak link oluşturup bunu privileged bir location'ı gösterecek şekilde ayarlamaya dayanan klasik primitive. **Symlink'ler alert üretmek için izlenebilir ancak block edilemez**: EndpointSecurity, link oluşturulmadan önce link destination'ını expose etmez.

### Calls made by other processes

[**Bu blog post'ta**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) başka **process'lerin bir process'e code inject ettiğini** tespit etmek ve ardından bu diğer process hakkında bilgi almak için **`task_name_for_pid`** function'ının nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu function'ı çağırmak için process'i çalıştıran user ile **aynı uid'ye** veya **root** yetkisine sahip olmanız gerektiğini unutmayın (ayrıca bu function injection yöntemi sağlamaz; process hakkında bilgi döndürür).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
