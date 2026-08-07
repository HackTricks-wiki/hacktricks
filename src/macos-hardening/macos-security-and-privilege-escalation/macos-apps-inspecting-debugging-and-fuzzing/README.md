# macOS Apps - İnceleme, debugging ve Fuzzing

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
> **`disarm`**'ın sıkıştırılmış IM4P dosyalarıyla (örneğin `kernelcache`) de çalışabildiğini ve yalnızca gerekli bölümleri çıkarabildiğini veya gerekli bölümü çıkarmadan analiz edebildiğini unutmayın.
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
> **`Codesign`** **macOS**'ta, **`ldid`** ise **iOS**'ta bulunabilir.
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
Bu yükleyiciler, malware yazarlarının genellikle **malware**'i **kalıcı** hale getirmek için abuse ettiği `preinstall` ve `postinstall` bash script'lerine sahiptir.

### hdiutil

Bu araç, herhangi bir şeyi çalıştırmadan önce incelemek için Apple disk image (**.dmg**) dosyalarını **mount** etmenizi sağlar:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
`/Volumes` içine mount edilecektir

### Packed binaries

- High entropy değerini kontrol edin
- String'leri kontrol edin (anlaşılabilir neredeyse hiç string var mı, packed olabilir)
- MacOS için UPX packer, "\_\_XHDR" adlı bir section oluşturur

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C ile yazılmış programların, [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) içine **compiled** edildiklerinde class declaration'larını **koruduğunu** unutmayın. Bu class declaration'ları aşağıdakilerin adını ve türünü **içerir**:

- Tanımlanan interface'ler
- Interface method'ları
- Interface instance variable'ları
- Tanımlanan protocol'ler

Binary'nin reverse edilmesini zorlaştırmak için bu adların obfuscate edilebileceğini unutmayın.

### Function calling

Objective-C kullanan bir binary'de bir function çağrıldığında, compiled code doğrudan bu function'ı çağırmak yerine **`objc_msgSend`** çağırır. Bu da son function'ı çağırır:

![Metadata - Function calling: Objective-C kullanan bir binary'de bir function çağrıldığında, compiled code doğrudan bu function'ı çağırmak yerine objc msgSend çağırır. Bu da...](<../../../images/image (305).png>)

Bu function'ın beklediği parametreler şunlardır:

- İlk parametre (**self**), "**mesajı alacak class instance'ını gösteren bir pointer**"dır. Daha basit ifade etmek gerekirse, method'un üzerinde çağrıldığı object'tir. Method bir class method'uysa bu, class object'inin (bütün olarak) bir instance'ı olur; instance method'uysa self, class'ın instantiate edilmiş bir instance'ını object olarak gösterir.
- İkinci parametre (**op**), "mesajı işleyen method'un selector'ı"dır. Yine daha basit ifade etmek gerekirse bu, yalnızca **method'un adıdır.**
- Kalan parametreler, method'un (**op**) gerektirdiği **değerlerdir**.

ARM64'te `lldb` ile bu bilgiyi nasıl kolayca **elde edebileceğinizi** bu sayfada görün:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: method'un üzerinde çağrıldığı object**         |
| **2nd argument**  | **rsi**                                                         | **op: method'un adı**                                  |
| **3rd argument**  | **rdx**                                                         | **method'a gönderilen 1. argument**                    |
| **4th argument**  | **rcx**                                                         | **method'a gönderilen 2. argument**                    |
| **5th argument**  | **r8**                                                          | **method'a gönderilen 3. argument**                    |
| **6th argument**  | **r9**                                                          | **method'a gönderilen 4. argument**                    |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method'a gönderilen 5.+ argument**                   |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump), Objective-C binaries üzerinde class-dump yapmak için kullanılan bir tool'dur. GitHub açıklamasında dylib'ler belirtilmiş olsa da bu tool executables üzerinde de çalışır.
```bash
./dynadump dump /path/to/bin
```
Yazım sırasında **şu anda en iyi çalışan seçenek budur**.

#### Normal araçlar
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ObjectiveC biçimli kodda bulunan class, category ve protocol'ler için declaration'lar oluşturan orijinal araçtır.

Eski ve bakımı yapılmıyor, bu nedenle muhtemelen düzgün çalışmayacaktır.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) modern ve cross-platform bir Objective-C class dump aracıdır. Mevcut araçlarla karşılaştırıldığında iCDump, Apple ekosisteminden bağımsız olarak çalışabilir ve Python binding'leri sunar.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analizi

Swift binary'lerinde Objective-C uyumluluğu bulunduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak declaration'ları çıkarabilirsiniz; ancak bu her zaman mümkün değildir.

**`jtool -l`** veya **`otool -l`** komut satırlarıyla **`__swift5`** prefix'iyle başlayan birkaç section bulmak mümkündür:
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
Bu bölümlerde depolanan [**bilgiler hakkında daha fazla bilgiyi bu blog yazısında bulabilirsiniz**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ayrıca, **Swift binary'leri symbols içerebilir** (örneğin, kütüphanelerin işlevlerinin çağrılabilmesi için symbols depolaması gerekir). **Symbols genellikle function name** ve attr bilgilerini çirkin bir biçimde içerir; bu nedenle oldukça kullanışlıdırlar ve orijinal adı elde edebilen "**demanglers"** vardır:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> Binary'leri debug edebilmek için **SIP'nin devre dışı bırakılması** (`csrutil disable` veya `csrutil enable --without debug`) ya da binary'lerin geçici bir klasöre kopyalanıp `codesign --remove-signature <binary-path>` ile **signature'larının kaldırılması** veya binary'nin debug edilmesine izin verilmesi gerekir ([bu script'i](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) kullanabilirsiniz).

> [!WARNING]
> macOS üzerinde `cloudconfigurationd` gibi **system binary'lerini instrument etmek** için **SIP devre dışı bırakılmalıdır** (yalnızca signature'ı kaldırmak işe yaramaz).

### APIs

macOS, process'ler hakkında bilgi sağlayan bazı ilginç API'ler sunar:

- `proc_info`: Her process hakkında çok fazla bilgi sağlayan temel API'dir. Diğer process'lerin bilgilerini almak için root olmanız gerekir, ancak özel entitlement'lara veya mach port'larına ihtiyacınız yoktur.
- `libsysmon.dylib`: XPC üzerinden sunulan function'lar aracılığıyla process'ler hakkında bilgi almayı sağlar; ancak `com.apple.sysmond.client` entitlement'ına sahip olmak gerekir.

### Stackshot & microstackshots

**Stackshotting**, tüm çalışan thread'lerin call stack'leri de dahil olmak üzere process'lerin durumunu yakalamak için kullanılan bir tekniktir. Bu teknik özellikle debugging, performans analizi ve sistemin belirli bir andaki davranışını anlamak için kullanışlıdır. iOS ve macOS üzerinde stackshotting, **`sample`** ve **`spindump`** araçları gibi çeşitli araçlar ve yöntemler kullanılarak gerçekleştirilebilir.

### Sysdiagnose

Bu araç (`/usr/bini/ysdiagnose`), temelde `ps`, `zprint` gibi onlarca farklı command çalıştırarak bilgisayarınızdan çok miktarda bilgi toplar.

**root** olarak çalıştırılmalıdır ve `/usr/libexec/sysdiagnosed` daemon'ı `com.apple.system-task-ports` ve `get-task-allow` gibi oldukça ilginç entitlement'lara sahiptir.

Plist'i `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` konumunda bulunur ve 3 MachService tanımlar:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp içindeki eski arşivleri siler
- `com.apple.sysdiagnose.kernel.ipc`: Özel port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class'ı üzerinden user mode interface. Bir dict içinde üç argument geçirilebilir (`compress`, `display`, `run`)

### Unified Logs

MacOS, bir uygulamayı çalıştırırken **ne yaptığını** anlamaya çalıştığınızda oldukça faydalı olabilecek çok sayıda log üretir.

Ayrıca bazı log'larda, **user** veya **computer** hakkındaki **tanımlanabilir** bilgileri **gizlemek** için `<private>` etiketi bulunur. Ancak, bu bilgileri açığa çıkarmak için **bir certificate yüklemek** mümkündür. Açıklamaları [**burada**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) bulabilirsiniz.

### Hopper

#### Left panel

Hopper'ın left panel'inde binary'nin symbol'lerini (**Labels**), procedure ve function listesini (**Proc**) ve string'lerini (**Str**) görebilirsiniz. Bunlar tüm string'ler değil, Mac-O file'ın çeşitli bölümlerinde tanımlanan string'lerdir (`_cstring` veya `objc_methname` gibi).

#### Middle panel

Middle panel'de **dissasembled code**'u görebilirsiniz. Ayrıca ilgili icon'a tıklayarak bunu **raw** disassemble, **graph**, **decompiled** veya **binary** olarak görüntüleyebilirsiniz:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Bir code object'e sağ tıklayarak **o object'e yönelik/ondan gelen referansları** görebilir veya adını değiştirebilirsiniz (bu işlem decompiled pseudocode'da çalışmaz):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ayrıca **middle panel'in alt kısmında python command'leri yazabilirsiniz**.

#### Right panel

Right panel'de **navigation history** (böylece mevcut duruma nasıl ulaştığınızı bilirsiniz), bu function'ı **çağıran tüm function'ları** ve **bu function'ın çağırdığı tüm function'ları** görebileceğiniz **call graph** ve **local variable** bilgileri gibi ilginç bilgileri görebilirsiniz.

### dtrace

Kullanıcıların uygulamalara son derece **low level** düzeyde erişmesini sağlar ve kullanıcılara **program'ları trace etme** ve hatta execution flow'larını değiştirme olanağı sunar. Dtrace, **kernel boyunca yerleştirilen** ve system call'ların başlangıcı ve bitişi gibi konumlarda bulunan **probe**'ları kullanır.

DTrace, her system call için bir probe oluşturmak üzere **`dtrace_probe_create`** function'ını kullanır. Bu probe'lar her system call'un **entry ve exit point'lerinde** tetiklenebilir. DTrace ile etkileşim, yalnızca root user için kullanılabilen /dev/dtrace üzerinden gerçekleşir.<sup>[[1]](#references)</sup>

> [!TIP]
> SIP protection'ı tamamen devre dışı bırakmadan Dtrace'i etkinleştirmek için recovery mode'da şu command'i çalıştırabilirsiniz: `csrutil enable --without dtrace`
>
> Ayrıca **derlediğiniz** binary'ler üzerinde **`dtrace`** veya **`dtruss`** kullanabilirsiniz.

Dtrace'in kullanılabilir probe'ları şu şekilde alınabilir:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Probe adı dört bölümden oluşur: provider, module, function ve name (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz Dtrace, o bölümü wildcard olarak uygular.

DTrace'i probe'ları etkinleştirecek ve tetiklendiklerinde hangi eylemlerin gerçekleştirileceğini belirleyecek şekilde yapılandırmak için D language kullanmamız gerekir.

Daha ayrıntılı bir açıklama ve daha fazla örnek [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) adresinde bulunabilir.

#### Örnekler

Mevcut **DTrace scripts** listesini görmek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`

- Satırda
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

Bir kernel tracing facility'sidir. Documented kodlar **`/usr/share/misc/trace.codes`** içinde bulunabilir.

`latency`, `sc_usage`, `fs_usage` ve `trace` gibi araçlar bunu dahili olarak kullanır.

`kdebug` ile interface kurmak için `sysctl`, `kern.kdebug` namespace'i ve kullanılacak MIB'ler üzerinden kullanılır; bunların implement edildiği fonksiyonlar `bsd/kern/kdebug.c` içinde bulunur.

Özel bir client ile kdebug ile etkileşim kurmak için genellikle şu adımlar izlenir:

- KERN_KDSETREMOVE ile mevcut ayarları kaldırın
- KERN_KDSETBUF ve KERN_KDSETUP ile trace'i ayarlayın
- Buffer entry sayısını almak için KERN_KDGETBUF kullanın
- KERN_KDPINDEX ile kendi client'ınızı trace'den çıkarın
- KERN_KDENABLE ile tracing'i etkinleştirin
- KERN_KDREADTR çağrısı yaparak buffer'ı okuyun
- Her thread'i process'iyle eşleştirmek için KERN_KDTHRMAP çağrısı yapın.

Bu bilgileri almak için Apple aracı **`trace`** veya özel araç [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** kullanılabilir.**

**Kdebug'in aynı anda yalnızca 1 client için kullanılabildiğini unutmayın.** Bu nedenle aynı anda yalnızca bir k-debug tabanlı araç çalıştırılabilir.

### ktrace

`ktrace_*` API'leri, `Kdebug` API'lerini wrap eden `libktrace.dylib` içinden gelir. Böylece bir client yalnızca `ktrace_session_create` ve `ktrace_events_[single/class]` çağrılarını kullanarak belirli kodlar üzerinde callback'ler ayarlayabilir ve ardından `ktrace_start` ile başlatabilir.

Bunu **SIP etkinleştirilmişken** bile kullanabilirsiniz.

Client olarak `ktrace` utility'sini kullanabilirsiniz:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Veya `tailspin`.

### kperf

Bu, kernel seviyesinde profiling yapmak için kullanılır ve `Kdebug` callout'ları kullanılarak oluşturulmuştur.

Temel olarak, global `kernel_debug_active` değişkeni kontrol edilir ve etkinse, `Kdebug` kodu ve çağrıyı yapan kernel frame'inin adresi ile `kperf_kdebug_handler` çağrılır. `Kdebug` kodu seçilen kodlardan biriyle eşleşirse, bitmap olarak yapılandırılmış "actions" alınır (seçenekler için `osfmk/kperf/action.h` dosyasını kontrol edin).

Kperf'in ayrıca bir sysctl MIB tablosu vardır: (root olarak) `sysctl kperf`. Bu kodlar `osfmk/kperf/kperfbsd.c` içinde bulunabilir.

Ayrıca Kperf işlevselliğinin bir alt kümesi, machine performance counter'ları hakkında bilgi sağlayan `kpc` içinde bulunur.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir process'in gerçekleştirdiği process ile ilgili actions'ları kontrol etmek için çok kullanışlı bir araçtır (örneğin, bir process'in hangi yeni process'leri oluşturduğunu izlemek).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/), process'ler arasındaki ilişkileri yazdıran bir araçtır.\
Mac'inizi **`sudo eslogger fork exec rename create > cap.json`** benzeri bir komutla izlemelisiniz (bunu başlatan terminal FDA gerektirir). Ardından tüm ilişkileri görüntülemek için json dosyasını bu araca yükleyebilirsiniz:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), bu olaylar hakkında ayrıntılı bilgiler sağlayarak file event'lerini (oluşturma, değiştirme ve silme gibi) izlemeye olanak tanır.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Windows kullanıcılarının Microsoft Sysinternal'ın _Procmon_ aracından tanıyabileceği görünüm ve kullanıma sahip bir GUI aracıdır. Bu araç, çeşitli event türlerinin kaydının başlatılıp durdurulmasına olanak tanır; file, process, network vb. kategorilere göre bu event'lerin filtrelenmesini sağlar ve kaydedilen event'leri json formatında kaydetme işlevi sunar.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode'un Developer tools bileşenlerinin bir parçasıdır ve application performance'ını izlemek, memory leak'lerini belirlemek ve filesystem activity'sini takip etmek için kullanılır.

![Crescendo - Apple Instruments: Apple Instruments are part of Xcode’s Developer tools – used for monitoring application performance, identifying memory leaks and tracking filesystem activity](<../../../images/image (1138).png>)

### fs_usage

Process'ler tarafından gerçekleştirilen actions'ları takip etmeye olanak tanır:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) bir binary tarafından kullanılan **libraries**, kullandığı **files** ve **network** bağlantılarını görmek için kullanışlıdır.\
Ayrıca binary process'lerini **virustotal** ile kontrol eder ve binary hakkında bilgi gösterir.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**bu blog postunda**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), SIP devre dışı bırakılmış olsa bile debugging'i önlemek için **`PT_DENY_ATTACH`** kullanan **çalışan bir daemon'u debug etme** örneğini bulabilirsiniz.<sup>[[6]](#references)</sup>

### lldb

**lldb**, macOS binary **debugging** için kullanılan fiili araçtır.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Ana klasörünüzde **`.lldbinit`** adlı bir dosya oluşturarak lldb kullanırken intel flavour ayarlayabilirsiniz; dosyaya şu satırı ekleyin:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb içinde `process save-core` ile bir process dump'layın

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Açıklama</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Çalıştırmayı başlatır; bir breakpoint'e ulaşılana veya process sonlanana kadar kesintisiz devam eder.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Çalıştırmayı entry point'te duracak şekilde başlatır</td></tr><tr><td><strong>continue (c)</strong></td><td>Debug edilen process'in çalışmasını sürdürür.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Sonraki instruction'ı çalıştırır. Bu command function call'larını atlar.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Sonraki instruction'ı çalıştırır. nexti command'inin aksine bu command function call'larının içine girer.</td></tr><tr><td><strong>finish (f)</strong></td><td>Mevcut function'daki (“frame”) kalan instruction'ları çalıştırır, geri döner ve durur.</td></tr><tr><td><strong>control + c</strong></td><td>Çalışmayı duraklatır. Process çalıştırılmışsa (r) veya devam ettirilmişse (c), process'in o anda çalıştığı yerde durmasına neden olur.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Memory'yi null-terminated string olarak görüntüler.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Memory'yi assembly instruction olarak görüntüler.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Memory'yi byte olarak görüntüler.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Bu, parametre tarafından referans verilen object'i yazdırır</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple'ın Objective-C API'lerinin veya method'larının çoğunun object döndürdüğünü ve bu nedenle “print object” (po) command'iyle görüntülenmesi gerektiğini unutmayın. po anlamlı bir çıktı üretmezse <code>x/b</code> kullanın</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Mevcut process memory'sinin map'ini yazdırır</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> **`objc_sendMsg`** function'ı çağrılırken **rsi** register'ı method'un adını null-terminated (“C”) string olarak tutar. Adı lldb üzerinden yazdırmak için:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** command'ı, **host MacOS** olduğunda "Mac", VM olduğunda ise farklı bir değer döndürür.<sup>[[3]](#references)</sup>
- Bazı malware'ler, **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynayarak bunun bir VM olup olmadığını anlamaya çalışır.<sup>[[4]](#references)</sup>
- Bazı malware'ler MAC adresine (00:50:56) dayanarak makinenin **VMware** olup olmadığını da **detect** edebilir.
- Bir process'in debug edilip edilmediğini aşağıdaki gibi basit bir code ile bulmak da mümkündür:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Ayrıca **`PT_DENY_ATTACH`** flag'iyle **`ptrace`** system call'ını çağırabilir. Bu, bir deb**u**gger'ın attach olup trace etmesini **engeller**.
- **`sysctl`** veya **`ptrace`** function'ının **import** edilip edilmediğini kontrol edebilirsiniz (ancak malware bunu dinamik olarak import edebilir)
- Bu writeup'ta belirtildiği üzere, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
“_Process # exited with **status = 45 (0x0000002d)** mesajı, debug target'ın **PT_DENY_ATTACH** kullandığını gösteren tipik bir işarettir_”

## Core Dumps

Core dump'lar şu durumlarda oluşturulur:

- `kern.coredump` sysctl değeri 1 olarak ayarlanmışsa (varsayılan olarak)
- Process suid/sgid değilse veya `kern.sugid_coredump` değeri 1 ise (varsayılan olarak 0)
- `AS_CORE` limit'i işleme izin veriyorsa. `ulimit -c 0` çağrılarak code dump'larının oluşturulması engellenebilir ve `ulimit -c unlimited` ile yeniden etkinleştirilebilir.

Bu durumlarda core dump, `kern.corefile` sysctl'ına göre oluşturulur ve genellikle `/cores/core/.%P` konumunda saklanır.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash, **crash olan process'leri analiz eder ve diske bir crash report kaydeder**. Bir crash report, **bir developer'ın crash'in nedenini teşhis etmesine yardımcı olabilecek** bilgiler içerir.\
**Per-user launchd context'inde çalışan application'lar ve diğer process'ler** için ReportCrash, bir LaunchAgent olarak çalışır ve crash report'larını kullanıcının `~/Library/Logs/DiagnosticReports/` dizinine kaydeder.\
Daemon'lar, **system launchd context'inde çalışan diğer process'ler** ve diğer privileged process'ler için ReportCrash, bir LaunchDaemon olarak çalışır ve crash report'larını sistemin `/Library/Logs/DiagnosticReports` dizinine kaydeder.

Crash report'ların **Apple'a gönderilmesinden** endişeleniyorsanız bunları devre dışı bırakabilirsiniz. Aksi takdirde crash report'lar, **bir server'ın nasıl crash olduğunu anlamak** için yararlı olabilir.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uyku

MacOS üzerinde fuzzing yaparken Mac'in uykuya geçmesine izin vermemek önemlidir:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısının Kesilmesi

SSH bağlantısı üzerinden fuzzing yapıyorsanız session'ın sonlanmayacağından emin olmanız önemlidir. Bunun için sshd_config dosyasını şu şekilde değiştirin:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Aşağıdaki sayfayı inceleyin**; belirtilen scheme veya protocol'ü **hangi uygulamanın yönettiğini** nasıl bulabileceğinizi öğrenin:


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Network Processes'ı Enumerate Etme

Ağ verilerini yöneten process'leri bulmak için kullanışlıdır:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Veya `netstat` veya `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI tools için çalışır

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI tools ile "**sadece çalışır**". Bazı macOS uygulamalarının unique filenames, doğru extension ve dosyaları sandbox'tan (`~/Library/Containers/com.apple.Safari/Data`) okuma gibi özel gereksinimleri olduğunu unutmayın...

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
### Daha Fazla Fuzzing MacOS Bilgisi

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referanslar

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)
- [5] [knight.sc - bu blog gönderisindeki bu bölümde depolanan bilgiler](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach kullanan Apple Binary'lerini Debugging](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Tekniklerini Aşma: macOS ptrace varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
