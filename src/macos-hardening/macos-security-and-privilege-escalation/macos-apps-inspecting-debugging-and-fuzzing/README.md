# macOS Uygulamaları - İnceleme, Hata Ayıklama ve Fuzzing

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

### Disarm (eski jtool2)

[**disarm'ı buradan indirebilirsiniz**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> **`disarm`**'ın sıkıştırılmış IM4P dosyalarıyla da (ör. `kernelcache`) çalışabildiğini ve yalnızca gerekli bölümleri çıkarabildiğini, hatta gerekli bölümü çıkarmadan analiz edebildiğini unutmayın.

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
> **`Codesign`**, **macOS**'ta bulunabilir; **`ldid`** ise **iOS**'ta bulunabilir.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html), **.pkg** dosyalarını (yükleyicileri) incelemek ve yüklemeden önce içlerinde ne olduğunu görmek için kullanışlı bir araçtır.\
Bu yükleyicilerde, malware yazarlarının genellikle **malware**'i **persist** etmek için kötüye kullandığı `preinstall` ve `postinstall` bash script'leri bulunur.

### hdiutil

Bu araç, Apple disk imajı (`.dmg`) dosyalarını herhangi bir şey çalıştırılmadan önce incelenebilmeleri için **mount** eder:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

`/Volumes` altına bağlanacaktır.

### Packed binaries

- Entropinin yüksek olup olmadığını kontrol edin
- Strings değerlerini kontrol edin (anlaşılır neredeyse hiç strings yoksa binary packed demektir)
- macOS için UPX packer, `__XHDR` adlı bir section oluşturur.

## Static Objective-C analizi

### Metadata

> [!CAUTION]
> Objective-C ile yazılmış programların, [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) olarak [compile](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) edildiğinde sınıf bildirimlerini **koruduğunu** unutmayın. Bu sınıf bildirimleri şunların adını ve türünü **içerir**:

- Tanımlanan arayüzler
- Arayüz metotları
- Arayüz örnek değişkenleri
- Tanımlanan protokoller

Binary'yi tersine çevirmeyi zorlaştırmak için bu adların obfuscate edilmiş olabileceğini unutmayın.

### Function calling

Objective-C kullanan bir binary'de bir function çağrıldığında, derlenmiş kod bu function'ı doğrudan çağırmak yerine **`objc_msgSend`** çağrısı yapar. Bu da son function'ı çağırır:

![Metadata - Function calling: Objective-C kullanan bir binary'de bir function çağrıldığında, derlenmiş kod bu function'ı doğrudan çağırmak yerine objc msgSend çağrısı yapar. Bu da...](<../../../images/image (305).png>)

Bu function'ın beklediği parametreler:

- İlk parametre (**self**), "**mesajı alacak sınıfın örneğine işaret eden bir pointer**"dır. Daha basitçe, metodun çağrıldığı nesnedir. Metot bir sınıf metoduyse bu, sınıf nesnesinin (bütün olarak) bir örneği olur; örnek metodunda ise `self`, sınıfın örneklenmiş bir nesnesine işaret eder.
- İkinci parametre (**op**), "mesajı işleyen metodun selector'ı"dır. Daha basitçe, bu yalnızca **metodun adıdır.**
- Geri kalan parametreler, metodun (**op**) gerektirdiği **değerlerdir.**

**ARM64'te `lldb` ile bu bilgileri kolayca nasıl elde edeceğinizi** bu sayfada görebilirsiniz:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argüman**       | **Register**                                                   | **(objc_msgSend için)**                                 |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argüman**    | **rdi**                                                        | **self: metodun çağrıldığı nesne**                     |
| **2. argüman**    | **rsi**                                                        | **op: metodun adı**                                     |
| **3. argüman**    | **rdx**                                                        | **metoda verilen 1. argüman**                          |
| **4. argüman**    | **rcx**                                                        | **metoda verilen 2. argüman**                          |
| **5. argüman**    | **r8**                                                         | **metoda verilen 3. argüman**                          |
| **6. argüman**    | **r9**                                                         | **metoda verilen 4. argüman**                          |
| **7. ve sonraki argümanlar** | <p><strong>rsp+</strong><br><strong>(stack'te)</strong></p> | **metoda verilen 5. ve sonraki argümanlar**             |

### Objective-C metadata'yı dökme

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump), Objective-C binaries üzerinde class-dump yapmak için kullanılan bir araçtır. GitHub sayfasında dylib'lerden bahsediliyor, ancak bu araç executable'larla da çalışır.

```bash
./dynadump dump /path/to/bin
```

Yazım sırasında **şu anda en iyi çalışan yöntem budur**.

#### Standart araçlar

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/), Objective-C biçimli kodda sınıflar, kategoriler ve protokoller için bildirimler oluşturan özgün araçtır.

Eski ve bakımı yapılmıyor; bu nedenle düzgün çalışmayabilir.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump), modern ve platformlar arası bir Objective-C class dump aracıdır. Mevcut araçlarla karşılaştırıldığında iCDump, Apple ekosisteminden bağımsız olarak çalışabilir ve Python bindings sunar.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statik Swift analizi

Swift ikililerinde Objective-C uyumluluğu olduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak bildirimleri çıkarabilirsiniz, ancak bu her zaman mümkün değildir.

**`jtool -l`** veya **`otool -l`** komutlarıyla **`__swift5`** önekiyle başlayan birkaç bölüm bulmak mümkündür:

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

[**bu bölümlerde depolanan bilgiler hakkında daha fazla bilgiyi bu blog gönderisinde bulabilirsiniz**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ayrıca **Swift binary'lerinde semboller bulunabilir** (örneğin, kütüphanelerin işlevlerinin çağrılabilmesi için sembolleri depolaması gerekir). **Semboller genellikle işlev adı ve öznitelikleri hakkında bilgiyi çirkin bir biçimde içerir**; bu nedenle çok kullanışlıdırlar ve özgün adı elde edebilen "**demangler'lar"** vardır:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamik Analiz

> [!WARNING]
> İkili dosyalarda debug yapmak için **SIP'nin devre dışı bırakılması** (`csrutil disable` veya `csrutil enable --without debug`) ya da ikili dosyaların geçici bir klasöre kopyalanıp `codesign --remove-signature <binary-path>` ile **imzalarının kaldırılması** veya ikili dosyanın debug edilmesine izin verilmesi gerektiğini unutmayın ([bu scripti](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) kullanabilirsiniz).

> [!WARNING]
> macOS'te **sistem ikili dosyalarını (ör. `cloudconfigurationd`) instrument etmek** için **SIP devre dışı olmalıdır** (yalnızca imzayı kaldırmak işe yaramaz).

### API'ler

macOS, süreçlerle ilgili bilgi sağlayan bazı ilgi çekici API'ler sunar:

- `proc_info`: Her süreç hakkında çok fazla bilgi sağlayan başlıca API'dir. Diğer süreçlerin bilgilerine erişmek için root olmanız gerekir; ancak özel entitlement'lara veya mach portlarına ihtiyacınız yoktur.
- `libsysmon.dylib`: XPC işlevleri aracılığıyla süreç bilgisi sunar, ancak çağıranların `com.apple.sysmond.client` entitlement'ına sahip olması gerekir.

### Stackshot & microstackshots

**Stackshot alma**, çalışan tüm thread'lerin çağrı yığınları da dahil olmak üzere süreçlerin durumunu yakalamak için kullanılan bir tekniktir. Bu yöntem özellikle debug, performans analizi ve sistemin belirli bir andaki davranışını anlamak için yararlıdır. iOS ve macOS'te stackshot alma, **`sample`** ve **`spindump`** gibi araçlarla ve çeşitli yöntemlerle gerçekleştirilebilir.

### Sysdiagnose

Bu araç (`/usr/bini/ysdiagnose`), `ps`, `zprint` gibi onlarca farklı komut çalıştırarak bilgisayarınızdan çok sayıda bilgi toplar.

**Root** olarak çalıştırılmalıdır ve `/usr/libexec/sysdiagnosed` daemon'ı `com.apple.system-task-ports` ve `get-task-allow` gibi oldukça ilgi çekici entitlement'lara sahiptir.

Plist dosyası `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` konumundadır ve 3 MachService tanımlar:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp içindeki eski arşivleri siler
- `com.apple.sysdiagnose.kernel.ipc`: Özel port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C sınıfı üzerinden kullanıcı modu arayüzü. Bir dict içinde üç argüman (`compress`, `display`, `run`) iletilebilir.

### Birleşik Günlükler

macOS, bir uygulamanın davranışını analiz ederken yararlı olan kapsamlı günlükler oluşturur.

Bazı günlük alanlarında kullanıcıyı veya cihazı tanımlayabilecek bilgileri gizlemek için `<private>` etiketi bulunur. Eski yönergelerde bazen bu alanları göstermek için bir sertifika yüklemekten bahsedilir; güncel debug yönergeleri ise bunun yerine açıkça kapsamı belirlenmiş bir yapılandırma profiliyle `Enable-Private-Data` ayarını veya uygulama başına `OSLogPreferences` kullanımını önerir. Davranış alt sisteme ve macOS sürümüne göre değişebilir. Eski sertifika/profil açıklaması referanslarda korunmuştur. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Sol panel

Hopper'ın sol panelinde ikili dosyanın sembollerini (**Labels**), prosedür ve fonksiyon listesini (**Proc**) ve string'leri (**Str**) görebilirsiniz. Bunlar tüm string'ler değil, Mac-O dosyasının çeşitli bölümlerinde (ör. _cstring veya `objc_methname`) tanımlanan string'lerdir.

#### Orta panel

Orta panelde **disassemble edilmiş kodu** görebilirsiniz. İlgili simgeye tıklayarak kodu **raw** disassembly, **graph**, **decompiled** veya **binary** olarak görüntüleyebilirsiniz:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Bir kod nesnesine sağ tıklayarak o nesneye **yönelik/nesneden gelen referansları** görebilir, hatta adını değiştirebilirsiniz (bu, decompiled pseudocode'da çalışmaz):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ayrıca **orta panelin alt kısmında Python komutları yazabilirsiniz**.

#### Sağ panel

Sağ panelde **gezinme geçmişi** (böylece mevcut konuma nasıl geldiğinizi bilirsiniz), bu fonksiyonu **çağıran tüm fonksiyonları** ve **bu fonksiyonun çağırdığı tüm fonksiyonları** görebileceğiniz **çağrı grafiği** ve **yerel değişkenler** hakkında bilgi gibi ilgi çekici bilgiler bulunur.

### dtrace

Kullanıcıların uygulamalara son derece **düşük seviyede** erişmesini sağlar ve **programları** izlemelerine, hatta yürütme akışlarını değiştirmelerine olanak tanır. Dtrace, kernel boyunca ve sistem çağrılarının başlangıç ve bitiş noktaları gibi konumlara **yerleştirilen probe'ları** kullanır.

DTrace, her sistem çağrısı için probe oluşturmak üzere **`dtrace_probe_create`** fonksiyonunu kullanır. Bu probe'lar her sistem çağrısının **giriş ve çıkış noktasında** tetiklenebilir. DTrace ile etkileşim, yalnızca root kullanıcısının erişebildiği /dev/dtrace üzerinden gerçekleşir.<sup>[[1]](#references)</sup>

> [!TIP]
> SIP korumasını tamamen devre dışı bırakmadan Dtrace'ı etkinleştirmek için recovery mode'da şu komutu çalıştırabilirsiniz: `csrutil enable --without dtrace`
>
> Ayrıca **derlediğiniz** ikili dosyalarda **`dtrace`** veya **`dtruss`** kullanabilirsiniz.

dtrace'ın kullanılabilir probe'ları şu komutla listelenebilir:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Probe adı dört bölümden oluşur: provider, module, function ve name (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz DTrace, bu bölümleri joker karakter olarak kullanır.

DTrace’i probe’ları etkinleştirecek ve tetiklendiklerinde hangi eylemleri gerçekleştirecek şekilde yapılandırmak için D dilini kullanmamız gerekir.

Daha ayrıntılı bir açıklama ve daha fazla örnek için [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) adresine bakabilirsiniz.

#### Örnekler

**Kullanılabilir DTrace scriptlerini** listelemek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`

- Satır içinde

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

Bir kernel tracing tesisidir. Belgelenmiş kodlar **`/usr/share/misc/trace.codes`** dosyasında bulunabilir.

`latency`, `sc_usage`, `fs_usage` ve `trace` gibi araçlar bunu dahili olarak kullanır.

`kdebug` ile arayüz oluşturmak için `sysctl`, `kern.kdebug` namespace'i üzerinden kullanılır. Kullanılacak MIB'ler `sys/sysctl.h` dosyasında bulunabilir; işlevler ise `bsd/kern/kdebug.c` içinde uygulanmıştır.

Özel bir istemciyle kdebug ile etkileşim kurmak için genellikle şu adımlar izlenir:

- KERN_KDSETREMOVE ile mevcut ayarları kaldırın
- KERN_KDSETBUF ve KERN_KDSETUP ile trace ayarlayın
- Arabellek girdilerinin sayısını almak için KERN_KDGETBUF kullanın
- KERN_KDPINDEX ile kendi istemcinizi trace'den alın
- KERN_KDENABLE ile tracing'i etkinleştirin
- KERN_KDREADTR çağrısıyla arabelleği okuyun
- Her thread'i işlemiyle eşleştirmek için KERN_KDTHRMAP çağırın.

Bu bilgileri almak için Apple'ın **`trace`** aracını veya özel [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** aracını kullanabilirsiniz.

**Kdebug'in aynı anda yalnızca 1 istemci için kullanılabildiğini unutmayın.** Bu nedenle, k-debug kullanan yalnızca bir araç aynı anda çalıştırılabilir.

### ktrace

`ktrace_*` API'leri, `Kdebug` API'lerini sarmalayan `libktrace.dylib` kütüphanesinden gelir. Böylece bir istemci, belirli kodlara callback'ler ayarlamak için `ktrace_session_create` ve `ktrace_events_[single/class]` işlevlerini çağırıp ardından `ktrace_start` ile tracing'i başlatabilir.

Bunu **SIP etkin durumdayken** de kullanabilirsiniz.

İstemci olarak `ktrace` aracını kullanabilirsiniz:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Veya `tailspin`.

### kperf

Bu, kernel düzeyinde profil oluşturmak için kullanılır ve `Kdebug` çağrıları kullanılarak oluşturulmuştur.

Temel olarak, `kernel_debug_active` global değişkeni kontrol edilir. Etkinse, çağrı yapan kernel frame’inin `Kdebug` kodu ve adresiyle `kperf_kdebug_handler` çağrılır. `Kdebug` kodu seçilen kodlardan biriyle eşleşirse, bitmap olarak yapılandırılmış “actions” uygulanır (seçenekler için `osfmk/kperf/action.h` dosyasına bakın).

Kperf’in bir sysctl MIB tablosu da vardır: (root olarak) `sysctl kperf`. Bu kodlar `osfmk/kperf/kperfbsd.c` dosyasında bulunabilir.

Ayrıca, Kperf işlevselliğinin bir alt kümesi makine performans sayaçları hakkında bilgi sağlayan `kpc` içinde yer alır.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir sürecin gerçekleştirdiği süreçle ilgili eylemleri (örneğin, hangi yeni süreçleri oluşturduğunu) izlemek için çok kullanışlı bir araçtır.

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/), süreçler arasındaki ilişkileri gösteren bir araçtır.\
`sudo eslogger fork exec rename create > cap.json` gibi bir komutla Mac’inizi izlemeniz gerekir (bu komutu çalıştıran terminalin FDA erişimi olması gerekir). Ardından tüm ilişkileri görüntülemek için JSON dosyasını bu araca yükleyebilirsiniz:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), oluşturma, değiştirme ve silme gibi dosya olaylarını izler.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Windows kullanıcılarının Microsoft Sysinternal’ın _Procmon_ aracından tanıyabileceği görünüme ve kullanım hissine sahip bir GUI aracıdır. Bu araç, çeşitli olay türlerinin kaydını başlatıp durdurmanıza, bu olayları dosya, süreç, ağ gibi kategorilere göre filtrelemenize ve kaydedilen olayları JSON biçiminde kaydetmenize olanak tanır.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode’un Developer Tools araçlarının bir parçasıdır; uygulama performansını izlemek, bellek leak’lerini belirlemek ve dosya sistemi etkinliğini takip etmek için kullanılır.

![Crescendo - Apple Instruments: Apple Instruments, Xcode’un Developer Tools araçlarının bir parçasıdır; uygulama performansını izlemek, bellek leak’lerini belirlemek ve dosya sistemi etkinliğini takip etmek için kullanılır](<../../../images/image (1138).png>)

### fs_usage

Süreçlerin gerçekleştirdiği eylemleri izlemenizi sağlar:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html), bir binary'nin kullandığı **kütüphaneleri**, kullandığı **dosyaları** ve **ağ** bağlantılarını görmek için kullanışlıdır.\
Ayrıca binary süreçlerini **VirusTotal** ile karşılaştırır ve binary hakkında bilgi gösterir.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**Bu blog yazısında**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), SIP devre dışı olsa bile debugging'i engellemek için **`PT_DENY_ATTACH`** kullanan **çalışan bir daemon'un nasıl debug edileceğine** dair bir örnek bulabilirsiniz.<sup>[[6]](#references)</sup>

### lldb

**lldb**, macOS binary **debugging** için **fiili standart araçtır**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

lldb kullanırken, home klasörünüzde aşağıdaki satırı içeren **`.lldbinit`** adlı bir dosya oluşturarak Intel sözdizimi biçimini ayarlayabilirsiniz:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb içinde bir process'i `process save-core` ile dump edin

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Açıklama</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Yürütmeyi başlatır; bir breakpoint'e ulaşılana veya process sonlanana kadar devam eder.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Yürütmeyi başlatır ve giriş noktasında durdurur.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Debug edilen process'in yürütülmesini sürdürür.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Bir sonraki talimatı yürütür. Bu komut, fonksiyon çağrılarının üzerinden atlar.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Bir sonraki talimatı yürütür. <code>nexti</code> komutundan farklı olarak, bu komut fonksiyon çağrılarının içine girer.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Geçerli fonksiyondaki (frame) kalan talimatları yürütür, fonksiyondan döner ve durur.</td></tr>
<tr><td><strong>control + c</strong></td><td>Yürütmeyi duraklatır. Process çalıştırılmışsa (<code>r</code>) veya devam ettirilmişse (<code>c</code>), o anda nerede yürütülüyorsa orada durmasını sağlar.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main olarak adlandırılan herhangi bir fonksiyon</p>
<p><code>b &lt;binname&gt;`main</code> # Binary'nin main fonksiyonu</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Belirtilen binary'nin main fonksiyonu</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Herhangi bir NSFileManager metodu</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Bu kütüphanedeki tüm fonksiyonlarda dur</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint listesi</p>
<p><code>br e/dis &lt;num&gt;</code> # Breakpoint'i etkinleştir/devre dışı bırak</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpoint komutu hakkında yardım al</p>
<p><code>help memory write</code> # Belleğe yazma hakkında yardım al</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Belleği null ile sonlandırılmış bir string olarak görüntüler.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Belleği assembly talimatı olarak görüntüler.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Belleği bir byte olarak görüntüler.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Parametrenin başvurduğu nesneyi yazdırır.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Apple'ın Objective-C API'lerinin veya metotlarının çoğu nesne döndürür; bu nedenle “print object” (<code>po</code>) komutuyla görüntülenmelidir. <code>po</code> anlamlı bir çıktı üretmezse <code>x/b</code> kullanın.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Bu adrese AAAA yaz<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Adrese AAAA yaz
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Geçerli fonksiyonu disassemble et</p>
<p><code>dis -n &lt;funcname&gt;</code> # Bir fonksiyonu disassemble et</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Bir fonksiyonu disassemble et<br>
<code>dis -c 6</code> # Altı satırı disassemble et<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Bir adresten diğerine kadar disassemble et<br>
<code>dis -p -c 4</code> # Disassemble işlemine geçerli adresten başla</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> register'ındaki üç bileşenli bir diziyi incele</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Geçerli process belleğinin haritasını yazdırır.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP'deki tüm sembollerin adresini al</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** fonksiyonu çağrılırken **rsi** register'ı, **metodun adını** null ile sonlandırılmış (“C”) bir string olarak tutar. Adı lldb ile yazdırmak için:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Dinamik Analizden Kaçınma

#### VM tespiti

- **`sysctl hw.model`** komutu fiziksel donanımda normalde Mac model tanımlayıcısı döndürür; VM'de ise farklı bir değer döndürebilir.<sup>[[3]](#references)</sup>
- Bazı malware'ler, VM olup olmadığını tespit etmek için **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynar.<sup>[[4]](#references)</sup>
- Bazı malware'ler MAC adresine (00:50:56) bakarak makinenin **VMware** tabanlı olduğunu da **tespit edebilir**.
- Basit bir kodla **bir process'in debug edilip edilmediğini** bulmak da mümkündür:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- **`PT_DENY_ATTACH`** flag'iyle **`ptrace`** system call'unu da çağırabilir. Bu, bir debugger'ın bağlanmasını ve izleme yapmasını **engeller**.
  - **`sysctl`** veya **`ptrace`** fonksiyonunun **import** edilip edilmediğini kontrol edebilirsiniz (ancak malware bunu dinamik olarak import edebilir)
  - Bu writeup'ta belirtildiği üzere, “[Anti-Debug Tekniklerini Aşma: macOS ptrace varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Process # exited with **status = 45 (0x0000002d)** mesajı genellikle debug edilen hedefin **PT_DENY_ATTACH** kullandığını gösterir_”

#### `fork()` process devri

Bir process, başlangıca yakın bir noktada `fork()` çağırıp parent process'i sonlandırarak ( `fork()` pozitif bir child PID döndürür) ve korunan mantığı yalnızca child process'te sürdürerek (`fork()` `0` döndürür), özgün PID'ye bağlı kalan bir debugger'dan kaçabilir. `dlsym(RTLD_DEFAULT, "fork")` ile `fork` fonksiyonunu çözümlemek doğrudan `_fork` çağrı noktasını da ortadan kaldırır; ancak bu yalnızca bir anti-analysis engelidir: sembol adı string'i ve dinamik çözümleme veri akışı Mach-O binary'sinde hâlâ görülebilir.<sup>[[10]](#references)[[11]](#references)</sup>

arm64 üzerinde bu kalıbı sabit adresler yerine veri akışını izleyerek tespit edin: `dlsym` fonksiyonunun ilk iki argümanı `x0` ve `x1` register'larına aktarılır, `RTLD_DEFAULT` `-2` olarak görünebilir (örneğin, `movn x0, #1`) ve `"fork"` string'inin adresi genellikle bir `adrp`/`add` çiftiyle oluşturulur. `dlsym` stub'ına yapılan `bl` çağrısından sonra, döndürülen işaretçiyi `x0` register'ından null kontrolü ve depolandığı yer üzerinden daha sonraki bir dolaylı `blr` çağrısına kadar izleyin. Ardından `w0` içindeki `fork()` sonucunu takip edin: sıfır child process'in devam yolunu, pozitif ve `-1` değerleri ise parent process/hata yolunu seçer.<sup>[[10]](#references)[[11]](#references)</sup>

Statik bir bypass yöntemi, dolaylı çağrıyı devre dışı bırakıp mevcut sonuç kontrolünü child process yoluna yönlendirmektir. Örneğin, derleyici aşağıda gösterilen talimat dizisini oluşturduysa `blr` ve sonuç depolama talimatlarını `nop` ile yamalayın, sentetik bir sıfır sonucu sağlayın ve karşılaştırma/dallanma mantığını koruyun. Böylece uygulama child process oluşturmadan özgün PID altında çalışmaya devam eder; talimat register'ları ve dallanma hedefleri incelenen build'e göre uyarlanmalıdır.<sup>[[10]](#references)[[11]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Core dump'lar şu durumlarda oluşturulur:

- `kern.coredump` sysctl değeri 1 ise (varsayılan)
- İşlem suid/sgid değilse veya `kern.sugid_coredump` değeri 1 ise (varsayılan değer 0'dır)
- `AS_CORE` limiti işleme izin veriyorsa. `ulimit -c 0` çağrısıyla core dump oluşturulmasını engellemek ve `ulimit -c unlimited` ile yeniden etkinleştirmek mümkündür.

Bu durumlarda core dump'lar `kern.corefile` sysctl ayarına göre oluşturulur ve genellikle `/cores/core/.%P` konumunda saklanır.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **çöken işlemleri analiz eder ve bir çökme raporunu diske kaydeder**. Çökme raporu, **bir geliştiricinin** çökme nedenini teşhis etmesine **yardımcı olabilecek** bilgiler içerir.\
**Kullanıcı başına launchd bağlamında çalışan** uygulamalar ve diğer işlemler için ReportCrash, bir LaunchAgent olarak çalışır ve çökme raporlarını kullanıcının `~/Library/Logs/DiagnosticReports/` dizinine kaydeder.\
Daemon'lar, **sistem launchd bağlamında çalışan** diğer işlemler ve diğer ayrıcalıklı işlemler için ReportCrash, bir LaunchDaemon olarak çalışır ve çökme raporlarını sistemin `/Library/Logs/DiagnosticReports` dizinine kaydeder.

Çökme raporlarının **Apple'a gönderilmesinden** endişe ediyorsanız bunları devre dışı bırakabilirsiniz. Aksi hâlde çökme raporları, **bir sunucunun nasıl çöktüğünü anlamak** için yararlı olabilir.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Uyku

macOS üzerinde fuzzing yaparken Mac'in uykuya geçmesini önleyin:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısının Kesilmesi

SSH bağlantısı üzerinden fuzzing yapıyorsanız oturumun kesilmemesini sağlamak önemlidir. Bu nedenle sshd_config dosyasını şu şekilde değiştirin:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Dahili İşleyiciler

Belirtilen **şemayı veya protokolü işlemekten hangi uygulamanın sorumlu olduğunu** nasıl bulabileceğinizi öğrenmek için **aşağıdaki sayfaya göz atın:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Ağ Süreçlerini Listeleme

Bu, ağ verilerini yöneten süreçleri bulmak için kullanışlıdır:

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

### Fuzzer'lar

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI araçları için çalışır

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Birçok macOS GUI aracıyla "**sorunsuz çalışır**". Bazı uygulamaların ek gereksinimleri vardır; örneğin benzersiz dosya adları, belirli bir uzantı veya dosyaların sandbox kapsayıcılarından (`~/Library/Containers/com.apple.Safari/Data`) okunması.

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

### Daha Fazla macOS Fuzzing Bilgisi

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X Olay Müdahalesi: Betikleme ve Analiz](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: macOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware Sanatı, Cilt I: Analiz](https://taomm.org/)
- [4] [No Starch Press - Mac Malware Sanatı: Kötü Amaçlı Yazılımları Analiz Etme Rehberi](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - bu blog yazısında bu bölümde saklanan bilgiler](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach Kullanan Apple Binary'lerinde Debugging](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Tekniklerini Aşma: macOS ptrace varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode yapılandırılmış logları ve `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log'da özel verileri gösterme](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - fork örnekleri](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - dlsym ve fork kullanan Anti-debugging tekniği](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
