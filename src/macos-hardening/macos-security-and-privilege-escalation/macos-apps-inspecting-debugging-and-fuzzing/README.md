# macOS Uygulamaları - İnceleme, hata ayıklama ve Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statik Analiz

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (old jtool2)

[**disarm'ı buradan indirebilirsiniz**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> **`disarm`**'ın sıkıştırılmış IM4P dosyalarıyla (ör. `kernelcache`) de çalışabildiğini ve yalnızca gerekli bölümleri çıkarabildiğini, hatta bu bölümü çıkarmadan analiz edebildiğini unutmayın.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`**, **macOS**'te bulunabilir; **`ldid`** ise **iOS**'te bulunabilir.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html), **.pkg** dosyalarını (yükleyicileri) incelemek ve yüklemeden önce içeriklerini görmek için kullanışlı bir araçtır.\
Bu yükleyicilerde, malware yazarlarının genellikle malware'i **persist** etmek için kötüye kullandığı `preinstall` ve `postinstall` bash script'leri bulunur.

### hdiutil

Bu araç, Apple disk imajı (`.dmg`) dosyalarını herhangi bir şey çalıştırılmadan önce incelenebilmeleri için **mount** eder:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It will be mounted in `/Volumes`

### Packed binaries

- Yüksek entropy olup olmadığını kontrol edin
- String'leri kontrol edin (anlaşılabilir string neredeyse hiç yoksa, packed'dır)
- macOS için UPX packer, `__XHDR` adlı bir section oluşturur.

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C ile yazılmış programların, [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) olarak **derlendiklerinde** sınıf bildirimlerini **koruduğunu** unutmayın. Bu sınıf bildirimleri şunların adını ve türünü **içerir**:

- Tanımlanan arayüzler
- Arayüz metotları
- Arayüz örnek değişkenleri
- Tanımlanan protokoller

Binary'nin tersine mühendisliğini zorlaştırmak için bu adların obfuscate edilmiş olabileceğini unutmayın.

### Function calling

Objective-C kullanan bir binary'de bir fonksiyon çağrıldığında, derlenmiş kod o fonksiyonu doğrudan çağırmak yerine **`objc_msgSend`** çağrısı yapar. Bu da nihai fonksiyonu çağırır:

![Metadata - Function calling: Objective-C kullanan bir binary'de bir fonksiyon çağrıldığında, derlenmiş kod o fonksiyonu doğrudan çağırmak yerine objc_msgSend çağrısı yapar. Bu da...](<../../../images/image (305).png>)

Bu fonksiyonun beklediği parametreler:

- İlk parametre (**self**), "mesajı alacak sınıfın **örneğine işaret eden bir pointer**"dır. Daha basitçe, metot hangi nesne üzerinde çağrılıyorsa o nesnedir. Metot bir sınıf metoduyse bu, sınıf nesnesinin (bütün olarak) bir örneği olur; örnek metoduysa `self`, sınıfın örneklenmiş bir örneğini nesne olarak gösterir.
- İkinci parametre (**op**), "mesajı işleyen metodun selector'ı"dır. Daha basitçe, bu yalnızca **metodun adıdır.**
- Geri kalan parametreler, metodun (**op**) gerektirdiği **değerlerdir**.

**ARM64'te `lldb` ile bu bilgileri kolayca nasıl edinebileceğinizi** bu sayfada görün:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argüman**         | **Register**                                                    | **objc_msgSend için**                                    |
| ------------------- | --------------------------------------------------------------- | -------------------------------------------------------- |
| **1. argüman**      | **rdi**                                                         | **self: metodun çağrıldığı nesne**                       |
| **2. argüman**      | **rsi**                                                         | **op: metodun adı**                                      |
| **3. argüman**      | **rdx**                                                         | **metodun 1. argümanı**                                 |
| **4. argüman**      | **rcx**                                                         | **metodun 2. argümanı**                                 |
| **5. argüman**      | **r8**                                                          | **metodun 3. argümanı**                                 |
| **6. argüman**      | **r9**                                                          | **metodun 4. argümanı**                                 |
| **7. ve sonraki argümanlar** | <p><strong>rsp+</strong><br><strong>(stack'te)</strong></p> | **metodun 5. ve sonraki argümanları**             |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump), Objective-C binaries'lerini class-dump etmek için kullanılan bir araçtır. GitHub'da dylib'lerden bahsediliyor ancak bu araç executable'larla da çalışır.

```bash
./dynadump dump /path/to/bin
```

Yazım sırasında, şu anda en iyi çalışan seçenek budur.

#### Standart araçlar

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) Objective-C biçimindeki kodda bulunan sınıflar, kategoriler ve protokoller için bildirimler oluşturan özgün araçtır.

Eski ve bakımı yapılmıyor; bu nedenle muhtemelen düzgün çalışmayacaktır.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) modern ve platformlar arası bir Objective-C class dump aracıdır. Mevcut araçlarla karşılaştırıldığında iCDump, Apple ekosisteminden bağımsız olarak çalışabilir ve Python bağlamaları sunar.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statik Swift analizi

Swift binary'lerinde Objective-C uyumluluğu bulunduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak bildirimleri çıkarabilirsiniz, ancak bu her zaman mümkün değildir.

**`jtool -l`** veya **`otool -l`** komut satırlarıyla **`__swift5`** önekiyle başlayan çeşitli bölümleri bulmak mümkündür:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

[**bu bölümlerde saklanan bilgiler hakkında daha fazla bilgiyi bu blog yazısında bulabilirsiniz**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ayrıca, **Swift binary'lerinde semboller bulunabilir** (örneğin, kütüphanelerin işlevlerinin çağrılabilmesi için sembolleri saklaması gerekir). **Semboller genellikle işlev adları ve öznitelikleri hakkında bilgileri çirkin bir biçimde içerir**, bu yüzden çok kullanışlıdırlar. Orijinal adı elde edebilen "**demangler**" araçları da vardır:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamik Analiz

> [!WARNING]
> **SIP'yi varsayılan bir hata ayıklama adımı olarak devre dışı bırakmayın.** `com.apple.security.get-task-allow` içeren geliştirme derlemeleri, SIP etkin durumdayken hata ayıklanabilir. LLDB'yi denemeden önce hedefi `codesign -d --entitlements :- /path/to/binary` ile kontrol edin. Tek başına debugger yetkisi, SIP tarafından korunan hedeflere erişim sağlamaz.<sup>[[15]](#references)</sup>
>
> Dağıtılan bir uygulamada hardened runtime varsa genellikle `get-task-allow` bulunmaz ve uygulamaya debugger bağlanması engellenir. Mümkünse geliştirici tarafından sağlanan bir debug derlemesi kullanın; kullan-at bir kopyayı yeniden imzalamak, test edilen davranışı değiştirebilir. Korunan bir hedef için SIP'nin devre dışı bırakılması gerekiyorsa, güvendiğiniz bir makine yerine özel bir test makinesi veya VM kullanın.<sup>[[16]](#references)</sup>
>
> Daha önce, yalıtılmış bir test ortamındaki korunan bir hedef için şu alternatifler önerilmişti:
>
> İkili dosyalarda hata ayıklamak için SIP'nin devre dışı bırakılması (`csrutil disable` veya `csrutil enable --without debug)`, ikili dosyaların geçici bir klasöre kopyalanıp imzasının `codesign --remove-signature <binary-path>` ile kaldırılması ya da ikili dosyada hata ayıklamaya izin verilmesi gerektiğini unutmayın ([bu scripti](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) kullanabilirsiniz).
>
> SIP için genel bir gereklilik yoktur: bir debug derlemesini tercih edin ve bir kopyayı imzalamanın veya imzasını değiştirmenin test edilen davranışı değiştirebileceğini unutmayın.

> [!WARNING]
> macOS'ta `cloudconfigurationd` gibi **sistem ikili dosyalarını instrument etmek** için **SIP'nin devre dışı bırakılması gerektiğini** unutmayın (yalnızca imzayı kaldırmak işe yaramaz).

### API'ler

macOS, süreçler hakkında bilgi sağlayan bazı ilginç API'ler sunar:

- `proc_info`: Her süreç hakkında çok sayıda bilgi sağlayan temel API'dir. Diğer süreçler hakkında bilgi almak için root olmanız gerekir; ancak özel yetkilere veya mach portlarına ihtiyacınız yoktur.
- `libsysmon.dylib`: XPC işlevleri aracılığıyla süreç bilgisi sunar; ancak çağıranların `com.apple.sysmond.client` yetkisine sahip olması gerekir.

### Stackshot ve microstackshots

**Stackshotting**, tüm çalışan thread'lerin çağrı yığınları da dahil olmak üzere süreçlerin durumunu yakalamak için kullanılan bir tekniktir. Bu, özellikle hata ayıklama, performans analizi ve sistemin belirli bir andaki davranışını anlamak için kullanışlıdır. iOS ve macOS'ta stackshotting, **`sample`** ve **`spindump`** gibi araçlarla ve çeşitli yöntemlerle gerçekleştirilebilir.

### Sysdiagnose

Bu araç (`/usr/bini/ysdiagnose`), `ps`, `zprint` gibi onlarca farklı komutu çalıştırarak bilgisayarınızdan çok miktarda bilgi toplar.

**root** olarak çalıştırılmalıdır. `/usr/libexec/sysdiagnosed` daemon'ı, `com.apple.system-task-ports` ve `get-task-allow` gibi oldukça ilginç yetkilere sahiptir.

plist dosyası `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` konumundadır ve 3 MachServices tanımlar:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp içindeki eski arşivleri siler
- `com.apple.sysdiagnose.kernel.ipc`: Özel port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C sınıfı üzerinden kullanıcı modu arayüzü. Bir sözlükte üç argüman geçirilebilir (`compress`, `display`, `run`)

### Birleşik Günlükler

macOS, bir uygulamanın davranışını analiz ederken işe yarayan kapsamlı günlükler oluşturur.

Bazı günlük alanlarında, kullanıcıyı veya cihazı tanımlayabilecek bilgileri gizlemek için `<private>` etiketi bulunur. Eski yönergelerde bu alanları göstermek için bir sertifika yüklenmesi önerilir; güncel hata ayıklama yönergelerinde ise açıkça kapsamı belirlenmiş bir yapılandırma profiliyle `Enable-Private-Data` veya uygulama başına `OSLogPreferences` kullanılır. Davranış, alt sisteme ve macOS sürümüne göre değişebilir. Eski sertifika/profil tartışması referanslarda korunmuştur. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Sol panel

Hopper'ın sol panelinde ikili dosyanın sembollerini (**Labels**), yordam ve işlev listesini (**Proc**) ve dizeleri (**Str**) görebilirsiniz. Bunlar tüm dizeler değildir; Mac-O dosyasının çeşitli bölümlerinde tanımlanan dizelerdir (ör. _cstring veya_ `objc_methname`).

#### Orta panel

Orta panelde **disassemble edilmiş kodu** görebilirsiniz. İlgili simgeye tıklayarak kodu **ham** disassemble edilmiş biçimde, **grafik**, **decompile edilmiş** biçimde veya **binary** olarak görüntüleyebilirsiniz:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Bir kod nesnesine sağ tıkladığınızda, **o nesneye yapılan/nesneden yapılan referansları** görebilir, hatta nesnenin adını değiştirebilirsiniz (bu, decompile edilmiş sözde kodda çalışmaz):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ayrıca **orta panelin alt kısmına Python komutları yazabilirsiniz**.

#### Sağ panel

Sağ panelde **gezinme geçmişi** (mevcut duruma nasıl ulaştığınızı görmenizi sağlar), bu işlevi **çağıran tüm işlevleri** ve bu işlevin **çağırdığı tüm işlevleri** gösteren **çağrı grafiği** ve **yerel değişkenler** hakkında bilgi gibi ilginç bilgiler görebilirsiniz.

### dtrace

Kullanıcıların uygulamalara son derece **düşük seviyede** erişmesini sağlar; kullanıcıların **programları** izleyebilmesine ve hatta yürütme akışlarını değiştirebilmesine olanak tanır. Dtrace, **kernel boyunca yerleştirilen** ve sistem çağrılarının başlangıcı ile sonu gibi konumlarda bulunan **probelar** kullanır.

DTrace, her sistem çağrısı için bir probe oluşturmak üzere **`dtrace_probe_create`** işlevini kullanır. Bu probelar, her sistem çağrısının **giriş ve çıkış noktalarında** tetiklenebilir. DTrace ile etkileşim, yalnızca root kullanıcısının erişebildiği /dev/dtrace üzerinden gerçekleşir.<sup>[[1]](#references)</sup>

> [!TIP]
> SIP korumasını tamamen devre dışı bırakmadan Dtrace'i etkinleştirmek için Recovery Mode'da şu komutu çalıştırabilirsiniz: `csrutil enable --without dtrace`
>
> Ayrıca **derlediğiniz** ikili dosyalarda **`dtrace`** veya **`dtruss`** kullanabilirsiniz.

dtrace'in kullanılabilir probelarını şu komutla alabilirsiniz:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Probe adı dört bölümden oluşur: provider, module, function ve name (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz DTrace, bu bölümler için joker karakter kullanır.

DTrace'i probe'ları etkinleştirecek ve tetiklendiklerinde gerçekleştirilecek eylemleri belirtecek şekilde yapılandırmak için D dilini kullanmamız gerekir.

Daha ayrıntılı bir açıklama ve daha fazla örnek için [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) sayfasına bakabilirsiniz.

#### Örnekler

**Kullanılabilir DTrace script'lerini** listelemek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`

- Satır içi

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

Bu bir kernel tracing aracıdır. Belgelenmiş kodları **`/usr/share/misc/trace.codes`** dosyasında bulabilirsiniz.

`latency`, `sc_usage`, `fs_usage` ve `trace` gibi araçlar bu aracı dahili olarak kullanır.

`kdebug` ile etkileşim kurmak için `sysctl`, `kern.kdebug` namespace'i üzerinden kullanılır. Kullanılacak MIB'ler `sys/sysctl.h` dosyasında bulunabilir; işlevler ise `bsd/kern/kdebug.c` dosyasında uygulanmıştır.

Özel bir client ile kdebug ile etkileşim kurmak için genellikle şu adımlar izlenir:

- KERN_KDSETREMOVE ile mevcut ayarları kaldırın
- KERN_KDSETBUF ve KERN_KDSETUP ile trace'i ayarlayın
- Buffer girdilerinin sayısını öğrenmek için KERN_KDGETBUF kullanın
- KERN_KDPINDEX ile kendi client'ınızı trace'den çıkarın
- KERN_KDENABLE ile tracing'i etkinleştirin
- KERN_KDREADTR çağrısıyla buffer'ı okuyun
- Her thread'i kendi process'iyle eşleştirmek için KERN_KDTHRMAP çağrısını kullanın.

Bu bilgileri almak için Apple'ın **`trace`** aracını veya özel [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** aracını kullanabilirsiniz.

**Kdebug'in aynı anda yalnızca 1 kullanıcı tarafından kullanılabildiğini unutmayın.** Bu nedenle k-debug kullanan araçlardan aynı anda yalnızca biri çalıştırılabilir.

### ktrace

`ktrace_*` API'leri, `Kdebug` API'lerini sarmalayan `libktrace.dylib` kitaplığından gelir. Böylece bir client, belirli kodlara callback'ler ayarlamak için `ktrace_session_create` ve `ktrace_events_[single/class]` çağrılarını yapıp ardından `ktrace_start` ile başlatabilir.

Bunu **SIP etkin durumdayken** de kullanabilirsiniz.

Client olarak `ktrace` aracını kullanabilirsiniz:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Veya `tailspin`.

### kperf

Bu, kernel düzeyinde profiling yapmak için kullanılır ve `Kdebug` callout'ları kullanılarak oluşturulmuştur.

Temel olarak, `kernel_debug_active` global değişkeni kontrol edilir ve etkinse, çağrı yapan kernel frame'inin `Kdebug` kodu ve adresiyle `kperf_kdebug_handler` çağrılır. `Kdebug` kodu seçilen kodlardan biriyle eşleşirse, bitmap olarak yapılandırılmış "actions" uygulanır (seçenekler için `osfmk/kperf/action.h` dosyasına bakın).

Kperf'in bir sysctl MIB tablosu da vardır: (root olarak) `sysctl kperf`. Bu kodlar `osfmk/kperf/kperfbsd.c` dosyasında bulunabilir.

Ayrıca, Kperf işlevselliğinin bir alt kümesi, makine performans sayaçları hakkında bilgi sağlayan `kpc` içinde yer alır.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir sürecin gerçekleştirdiği süreçle ilgili eylemleri kontrol etmek için çok kullanışlı bir araçtır (örneğin, bir sürecin hangi yeni süreçleri oluşturduğunu izlemek).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/), süreçler arasındaki ilişkileri gösteren bir araçtır.\
Mac'inizi **`sudo eslogger fork exec rename create > cap.json`** gibi bir komutla izlemeniz gerekir (bu komutu çalıştıran terminalin FDA izni olmalıdır). Ardından, tüm ilişkileri görüntülemek için json dosyasını bu araca yükleyebilirsiniz:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), oluşturma, değiştirme ve silme gibi dosya olaylarını izler.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Windows kullanıcılarının Microsoft Sysinternal’ın _Procmon_ aracından aşina olabileceği görünüm ve hisse sahip bir GUI aracıdır. Bu araç, çeşitli olay türlerinin kaydını başlatıp durdurmanıza, dosya, süreç, ağ vb. kategorilere göre bu olayları filtrelemenize ve kaydedilen olayları json biçiminde kaydetmenize olanak tanır.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode’un Developer araçlarının bir parçasıdır; uygulama performansını izlemek, bellek leak'lerini belirlemek ve dosya sistemi etkinliğini takip etmek için kullanılır.

![Crescendo - Apple Instruments: Apple Instruments, Xcode’un Developer araçlarının bir parçasıdır; uygulama performansını izlemek, bellek leak'lerini belirlemek ve dosya sistemi etkinliğini takip etmek için kullanılır](<../../../images/image (1138).png>)

### fs_usage

Süreçlerin gerçekleştirdiği eylemleri takip etmenizi sağlar:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html), bir binary'nin kullandığı **kütüphaneleri**, kullandığı **dosyaları** ve **ağ** bağlantılarını görmek için kullanışlıdır.\
Ayrıca binary süreçlerini **virustotal** ile karşılaştırır ve binary hakkında bilgi gösterir.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**Bu blog yazısında**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), SIP devre dışı olsa bile debugging'i önlemek için **`PT_DENY_ATTACH`** kullanan **çalışan bir daemon'da debug yapma** örneğini bulabilirsiniz.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH`, değeri **31** (`0x1f`) olan, Darwin'e özgü bir `ptrace(2)` isteğidir; diğer argümanlar yok sayılır. Bir süreç, daha sonra üst süreç tarafından izlenmeyi reddetmek için bu isteği fork etmeden doğrudan çağırabilir.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU durumu ve çağrı sıralaması

Sonuç, XNU'ya ilk hangi `ptrace` isteğinin ulaştığına bağlıdır:<sup>[[11]](#references)[[12]](#references)</sup>

- **Önce LLDB attach olur:** `debugserver`, `PT_ATTACHEXC` kullanır; XNU bunu `PT_ATTACH`'e dönüştürür, `KAUTH_PROCESS_CANTRACE` yetkilendirmesini gerçekleştirir ve hedefte `P_LTRACED` ayarını yapar. Ardından gelen `PT_DENY_ATTACH` bu bayrağı görür ve hedefi `W_EXITCODE(ENOTSUP, 0)` ile sonlandırır; LLDB bunu genellikle **45** (`0x2d`) durumu olarak gösterir.
- **Önce hedef deny eder:** XNU, `P_LNOATTACH` ayarını yapar. Daha sonraki bir attach, süreç izleme yetkilendirmesi tarafından reddedilir; attach hata yolu `P_LNOATTACH`'i görür ve attach olmaya çalışan sürece `SIGSEGV` gönderir. Bu durum LLDB'de `debugserver` bağlantısının kesilmesi olarak görünebilir.

Bu yolları ayırt etmek için başlatmadan veya attach olmadan önce `debugserver` loglamasını etkinleştirin ve `ptrace` isteklerini inceleyin:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 statik tanımlama ve atlatma

Obfuscate edilmemiş bir ARM64 Mach-O için, içe aktarılan `_ptrace` stub'ını bulun ve çağrı noktalarını inceleyin. İlk tamsayı argümanı `w0` üzerinden iletilir; dolayısıyla bu dizi anti-debug isteğini doğrudan gösterir. İçe aktarılan öğenin bulunmaması kesin kanıt değildir; çünkü kod `ptrace`'i dinamik olarak çözümleyebilir. İçe aktarılan bir `_sysctl` de anti-debug kontrollerine işaret edebilir; ancak o da dinamik olarak çözümlenebilir.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Gösterilen örnekte, immediate değerini `0x1f`'ten `0x0`'a yamalamak isteği `PT_TRACE_ME` olarak değiştirir ve programın LLDB altında devam etmesini sağlar. Bu, **yalnızca bu örneğe özgü bir bypass** olup genel bir no-op değildir: İsteği değiştirmeye, çağrıyı atlamaya veya başarılı bir dönüşü zorlamaya karar vermeden önce çağıranın dönüş değeri kontrollerini ve kontrol akışını inceleyin.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb**, **macOS** ikililerinde **debugging** için **fiilî araçtır**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

lldb kullanırken, ana klasörünüzde aşağıdaki satırı içeren **`.lldbinit`** adlı bir dosya oluşturarak Intel sözdizimini ayarlayabilirsiniz:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb içinde bir process'i `process save-core` ile dump edin

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Açıklama</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Çalıştırmayı başlatır; bir breakpoint'e ulaşılana veya process sonlanana kadar devam eder.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Çalıştırmayı başlatır ve giriş noktasında durur.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Debug edilen process'in çalıştırılmasına devam eder.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Sonraki instruction'ı çalıştırır. Bu komut, function çağrılarının üzerinden atlar.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Sonraki instruction'ı çalıştırır. <code>nexti</code> komutundan farklı olarak bu komut, function çağrılarının içine girer.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Mevcut function'daki (frame'deki) kalan instruction'ları çalıştırır, geri döner ve durur.</td></tr>
<tr><td><strong>control + c</strong></td><td>Çalıştırmayı duraklatır. Process çalıştırılmışsa (<code>r</code>) veya devam ettirilmişse (<code>c</code>), o anda çalıştığı yerde durmasını sağlar.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Memory'yi null ile sonlandırılmış bir string olarak görüntüler.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Memory'yi bir assembly instruction olarak görüntüler.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Memory'yi bir byte olarak görüntüler.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Parametrenin referans verdiği object'i yazdırır.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Çoğu Apple Objective-C API'si veya method'u object döndürür; bu nedenle “print object” (<code>po</code>) komutuyla görüntülenmelidir. <code>po</code> anlamlı bir çıktı vermezse <code>x/b</code> kullanın.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Mevcut process memory'sinin haritasını yazdırır.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** function'ı çağrılırken **rsi** register'ı, null ile sonlandırılmış (“C”) bir string olarak **method'un adını** tutar. Adı lldb ile yazdırmak için:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Dinamik Analiz Karşıtı

#### VM tespiti

- **`sysctl hw.model`** komutu fiziksel donanımda normalde bir Mac model tanımlayıcısı döndürür; VM'de farklı bir değer döndürebilir.<sup>[[3]](#references)</sup>
- Bazı malware'ler VM olup olmadığını tespit etmek için **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynar.<sup>[[4]](#references)</sup>
- Bir loader, sonraki aşamasını unpack etmeden önce VM kontrolü yaparken `sysctl` üzerinden `kern.hv_vmm_present` ve `machdep.cpu.brand_string` değerlerini de sorgulayabilir. Bu kontroller, aşağıda açıklanan debugger'a bağlanma kontrolünü tamamlar; onun yerine geçmez.<sup>[[20]](#references)</sup>
- Bazı malware'ler MAC adresine (00:50:56) bakarak makinenin **VMware** olup olmadığını da **tespit edebilir**.
- **Bir process'in debug edilip edilmediğini** aşağıdaki gibi basit bir kodla kontrol etmek de mümkündür:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- `PT_DENY_ATTACH` flag'iyle `ptrace` system call'unu da çağırabilir. Bu, debugger'ın bağlanmasını ve tracing yapmasını engeller. XNU'nun çağrı sırasına bağlı davranışı, `debugserver` logging'i ve ARM64 patching iş akışı için [PT_DENY_ATTACH section](#page-title) bölümüne bakın.<sup>[[7]](#references)[[12]](#references)</sup>
- **`PT_DENY_ATTACH`** flag'iyle **`ptrace`** system call'unu da çağırabilir. XNU'nun çağrı sırasına bağlı davranışı, `debugserver` logging'i ve ARM64 patching iş akışı için [PT_DENY_ATTACH section](#page-title) bölümüne bakın.<sup>[[7]](#references)[[12]](#references)</sup>
  - **`sysctl`** veya **`ptrace`** function'ının **import edilip edilmediğini** kontrol edebilirsiniz (ancak malware bunu dinamik olarak import edebilir).
  - Bu writeup'ta belirtildiği gibi, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”
#### `fork()` process devri

Bir process, başlangıç sırasında `fork()` çağırıp parent'ı sonlandırarak ( `fork()` pozitif bir child PID döndürür) ve korunan mantığı yalnızca child'da sürdürerek ( `fork()` `0` döndürür), orijinal PID'ye bağlı kalmış bir debugger'dan kaçabilir. `dlsym(RTLD_DEFAULT, "fork")` ile `fork`'u çözümlemek `_fork` doğrudan çağrı noktasını da ortadan kaldırır; ancak bu yalnızca bir anti-analysis engelidir: symbol adı string'i ve dinamik çözümleme veri akışı Mach-O binary'sinde görünür kalır.<sup>[[13]](#references)[[14]](#references)</sup>

arm64'te bu örüntüyü sabit adresleri izlemek yerine veri akışını takip ederek tespit edin: `dlsym`'in ilk iki argümanı `x0` ve `x1` register'larına aktarılır, `RTLD_DEFAULT` `-2` olarak görünebilir (örneğin, `movn x0, #1`) ve bir `adrp`/`add` çifti genellikle `"fork"` string'inin adresini oluşturur. `dlsym` stub'ına yapılan `bl` çağrısından sonra, döndürülen pointer'ı `x0`'dan null kontrolüne ve depolandığı yere, ardından daha sonraki bir dolaylı `blr` çağrısına kadar izleyin. Sonra `fork()` sonucunu `w0` içinde takip edin: sıfır child'ın devam yolunu seçerken pozitif ve `-1` değerleri parent/hata yolunu seçer.<sup>[[13]](#references)[[14]](#references)</sup>

Statik bir bypass yöntemi, dolaylı çağrıyı bastırıp mevcut sonuç kontrolünü child yoluna yönlendirmektir. Örneğin, compiler aşağıda gösterilen sequence'i oluşturduysa `blr` çağrısını ve sonuç depolamasını `nop` ile patch edin, sentetik bir sıfır sonucu verin ve karşılaştırma/dallanma mantığını koruyun. Böylece uygulama child oluşturmadan orijinal PID altında devam eder; instruction register'ları ve branch hedefleri analiz edilen build'e göre uyarlanmalıdır.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dump'lar

Core dump'lar şu durumlarda oluşturulur:

- `kern.coredump` sysctl değeri 1 ise (varsayılan)
- İşlem suid/sgid değilse veya `kern.sugid_coredump` değeri 1 ise (varsayılanı 0'dır)
- `AS_CORE` limiti işleme izin veriyorsa. `ulimit -c 0` çağrısıyla core dump oluşturulmasını devre dışı bırakmak, `ulimit -c unlimited` ile yeniden etkinleştirmek mümkündür.

Bu durumlarda core dump'lar `kern.corefile` sysctl ayarına göre oluşturulur ve genellikle `/cores/core/.%P` konumunda saklanır.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash, **çöken işlemleri analiz eder ve bir crash raporunu diske kaydeder**. Crash raporu, **geliştiricinin** çökmenin nedenini teşhis etmesine yardımcı olabilecek bilgiler içerir.\
**Kullanıcı başına launchd bağlamında çalışan** uygulamalar ve diğer işlemler için ReportCrash bir LaunchAgent olarak çalışır ve crash raporlarını kullanıcının `~/Library/Logs/DiagnosticReports/` dizinine kaydeder.\
Daemon'lar, **sistem launchd bağlamında çalışan** diğer işlemler ve diğer ayrıcalıklı işlemler için ReportCrash bir LaunchDaemon olarak çalışır ve crash raporlarını sistemdeki `/Library/Logs/DiagnosticReports` dizinine kaydeder.

Crash raporlarının **Apple'a gönderilmesinden** endişeleniyorsanız bu özelliği devre dışı bırakabilirsiniz. Aksi takdirde crash raporları, **bir sunucunun nasıl çöktüğünü anlamak** için faydalı olabilir.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Uyku

macOS'te fuzzing yaparken Mac'in uykuya geçmesini önleyin:

- systemsetup -setsleep Never
- pmset, Sistem Tercihleri
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısının Kesilmesi

SSH bağlantısı üzerinden fuzzing yapıyorsanız oturumun kapanmayacağından emin olmanız önemlidir. Bu nedenle sshd_config dosyasını şu şekilde değiştirin:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Dahili İşleyiciler

**Belirtilen scheme veya protocol'ü hangi uygulamanın işlediğini nasıl bulabileceğinizi öğrenmek için aşağıdaki sayfaya göz atın:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Ağ Süreçlerini Listeleme

Ağ verilerini yöneten süreçleri bulmak için bu yöntem ilginçtir:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ya da `netstat` veya `lsof` kullanın

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Durum bilgisi tutan Mach IPC fuzzing

Ayrıcalıklı daemon'ların sunduğu Mach servisleri, ayrıcalıksız veya sandbox'lı bir istemci send right alabildiğinde kullanışlı fuzz hedefleridir. Daemon'ın `MachServices` launchd girdisinden başlayın ve mesaj ID'lerini handler'lara eşlemek için [MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) kullanın. Byte'ları değiştirmeden önce, normal bir istemci servisi kullanırken MIG server routine üzerinde breakpoint koyun ve geçerli istek mesajlarını seed input olarak kaydedin. Mutasyonların dispatch sırasında hemen başarısız olmak yerine handler'a ulaşması için gerekli header alanlarını, mesaj boyutlarını ve descriptor düzenini koruyun.<sup>[[17]](#references)</sup>

Birçok handler önceki çağrılara bağlıdır. Harness ile servis durumunu başlatın, ardından her fuzz input'u **işlemler ve argümanlar** dizisi olarak kullanın: setup istekleri gönderin (ör. open veya create), döndürülen identifier'ları saklayın ve sonraki isteklerde kullanın. Böylece coverage feedback, sürekli başlatılmamış nesne denetimine takılmak yerine durum geçişlerini keşfedebilir.<sup>[[17]](#references)</sup>

Closed-source bir hedef için MIG dispatch routine'ini çağıran in-process harness, Jackalope/TinyInst ile instrument edilebilir. [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz), başka servisler için doğrudan kullanıma hazır bir harness değil, somut bir uygulamadır.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Her crash'i gerçek IPC yolu üzerinden doğrulayın.** Doğrudan dispatch yapan bir harness, Mach mesajlarının kernel tarafından doğrulanmasını atlar ve özellikle geçersiz out-of-line (OOL) bellek veya port descriptor'ları sağladığında false positive üretebilir. Harness'te geçerli OOL backing memory ayırın, ardından küçültülmüş testcase'i özgün servis erişimine sahip bir istemciden `mach_msg` aracılığıyla yeniden oynatın ve daemon'ın hâlâ crash ettiğini doğrulayın.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI araçlarıyla çalışır

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Birçok macOS GUI aracıyla "**doğrudan çalışır**". Bazı uygulamaların benzersiz dosya adları, belirli bir uzantı veya dosyaları sandbox container'ından (`~/Library/Containers/com.apple.Safari/Data`) okuma gibi ek gereksinimleri vardır.

Bazı örnekler:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### macOS Fuzzing Hakkında Daha Fazla Bilgi

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X Olay Müdahalesi: Betikleme ve Analiz](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzzing Yazı: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware Sanatı, Cilt I: Analiz](https://taomm.org/)
- [4] [No Starch Press - Mac Malware Sanatı: Kötü Amaçlı Yazılımları Analiz Etme Rehberi](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - bu blog gönderisindeki bu bölümlerde saklanan bilgiler](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach Kullanan Apple İkilerinde Hata Ayıklama](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Tekniklerini Aşma: macOS ptrace Varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode yapılandırılmış günlükleri ve `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log'da private data gösterme](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` request tanımları](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `mach_process.c` içindeki `ptrace` uygulaması](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace iç işleyişi: hata ayıklayıcı eklenmesini nasıl engeller](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork örnekleri](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsym ve fork kullanan anti-debugging tekniği](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Hata ayıklama aracı entitlement'ı](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Güvenliği sıkılaştırılmış üçüncü taraf bir uygulamada hata ayıklama](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Ses Engelini Aşmak Bölüm I: Mach Mesajlarıyla CoreAudio Fuzzing](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness'ı](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer'ı](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - MacSync macOS stealer'ının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
