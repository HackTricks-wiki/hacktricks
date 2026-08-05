# macOS Uygulamaları - İnceleme, debugging ve Fuzzing

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
> **`disarm`**'ın sıkıştırılmış IM4P dosyalarıyla (örneğin `kernelcache`) de çalışabildiğini ve yalnızca gerekli bölümleri çıkarabildiğini, hatta gerekli bölümü çıkarmadan analiz edebildiğini unutmayın.
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
> **`Codesign`**, **macOS** içinde bulunabilirken **`ldid`**, **iOS** içinde bulunabilir.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html), **.pkg** dosyalarını (installer'ları) incelemek ve yüklemeden önce içlerinde ne olduğunu görmek için kullanışlı bir araçtır.\
Bu installer'lar, malware yazarlarının **malware'i** **persist** etmek için genellikle kötüye kullandığı `preinstall` ve `postinstall` bash script'lerine sahiptir.

### hdiutil

Bu araç, herhangi bir şeyi çalıştırmadan önce incelemek amacıyla Apple disk image (**.dmg**) dosyalarını **mount** etmenizi sağlar:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It `/Volumes` içine mount edilecektir.

### Packed binaries

- Yüksek entropy olup olmadığını kontrol edin
- String'leri kontrol edin (anlaşılabilir neredeyse hiç string yoksa packed olabilir)
- MacOS için UPX packer, "\_\_XHDR" adlı bir section oluşturur

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Objective-C ile yazılmış programların [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) içine **compiled** edildiğinde sınıf bildirimlerini **koruduğunu** unutmayın. Bu tür sınıf bildirimleri aşağıdakilerin adını ve türünü **içerir**:

- Tanımlanan interface'ler
- Interface method'ları
- Interface instance variable'ları
- Tanımlanan protocol'ler

Binary'nin reversing işlemini zorlaştırmak için bu isimlerin obfuscate edilmiş olabileceğini unutmayın.

### Function calling

Objective-C kullanan bir binary'de bir function çağrıldığında, compiled code bu function'ı doğrudan çağırmak yerine **`objc_msgSend`** çağrısını yapar. Bu çağrı da nihai function'ı çağırır:

![Metadata - Function calling: When a function is called in a binary that uses objective-C, the compiled code instead of calling that function, it will call objc msgSend . Which will be...](<../../../images/image (305).png>)

Bu function'ın beklediği parametreler şunlardır:

- İlk parametre (**self**), "**mesajı alacak class instance'ını gösteren bir pointer**"dır. Daha basit ifade etmek gerekirse, method'un üzerinde çağrıldığı object'tir. Method bir class method'uysa bu, class object'inin (bütün olarak) bir instance'ı olur; instance method'u içinse self, class'ın object olarak instantiate edilmiş bir instance'ını gösterir.
- İkinci parametre (**op**), "mesajı işleyen method'un selector'ı"dır. Yine daha basit ifade etmek gerekirse bu yalnızca **method'un adıdır.**
- Kalan parametreler, method'un (**op**) ihtiyaç duyduğu **değerlerdir**.

ARM64'te `lldb` ile bu bilgilerin nasıl kolayca **alınacağını** şu sayfada görebilirsiniz:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: method'un üzerinde çağrıldığı object**         |
| **2nd argument**  | **rsi**                                                         | **op: method'un adı**                                  |
| **3rd argument**  | **rdx**                                                         | **method'a ait 1. argument**                           |
| **4th argument**  | **rcx**                                                         | **method'a ait 2. argument**                           |
| **5th argument**  | **r8**                                                          | **method'a ait 3. argument**                           |
| **6th argument**  | **r9**                                                          | **method'a ait 4. argument**                           |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method'a ait 5.+ argument**                         |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump), Objective-C binary'lerini class-dump etmek için kullanılan bir tool'dur. Github sayfasında dylib'ler belirtilmiş olsa da bu tool executable'larla da çalışır.
```bash
./dynadump dump /path/to/bin
```
Yazım sırasında **şu anda en iyi çalışan seçenek budur**.

#### Standart araçlar
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/), Objective-C ile biçimlendirilmiş kodda bulunan class, category ve protocol'ler için declaration'lar oluşturan orijinal araçtır.

Eski ve artık bakımı yapılmıyor; bu nedenle muhtemelen düzgün çalışmayacaktır.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump), modern ve cross-platform bir Objective-C class dump aracıdır. Mevcut araçlarla karşılaştırıldığında iCDump, Apple ekosisteminden bağımsız olarak çalışabilir ve Python bindings sunar.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analizi

Swift binary'lerinde Objective-C uyumluluğu bulunduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak bildirimleri çıkarabilirsiniz, ancak bu her zaman mümkün değildir.

**`jtool -l`** veya **`otool -l`** komut satırlarıyla, **`__swift5`** önekiyle başlayan çeşitli bölümleri bulmak mümkündür:
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
Bu bölümlerde depolanan [**bilgiler hakkında daha fazla bilgiyi bu blog yazısında bulabilirsiniz**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Ayrıca, **Swift binaries symbols içerebilir** (örneğin, kütüphanelerin işlevlerinin çağrılabilmesi için symbols depolaması gerekir). **Symbols genellikle işlev adı ve öznitelikleri hakkında bilgileri** okunması zor bir biçimde içerir; bu nedenle oldukça kullanışlıdırlar ve özgün adı elde edebilen **"demanglers"** vardır:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> İkili dosyalarda debug işlemi yapabilmek için **SIP'nin devre dışı bırakılması** (`csrutil disable` veya `csrutil enable --without debug) ya da ikili dosyaların geçici bir klasöre kopyalanıp imzanın `codesign --remove-signature <binary-path>` ile **kaldırılması** veya ikilinin debug edilmesine izin verilmesi gerekir ([bu scripti](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) kullanabilirsiniz).

> [!WARNING]
> macOS'ta `cloudconfigurationd` gibi **sistem ikililerini instrument etmek** için **SIP devre dışı bırakılmalıdır** (yalnızca imzayı kaldırmak işe yaramaz).

### APIs

macOS, süreçler hakkında bilgi sağlayan bazı ilginç API'ler sunar:

- `proc_info`: Her süreç hakkında çok miktarda bilgi sağlayan temel API'dir. Diğer süreçlerin bilgilerini almak için root olmanız gerekir, ancak özel entitlements veya mach port'larına ihtiyacınız yoktur.
- `libsysmon.dylib`: XPC üzerinden sunulan işlevler aracılığıyla süreçler hakkında bilgi edinmenizi sağlar; ancak `com.apple.sysmond.client` entitlement'ına sahip olmanız gerekir.

### Stackshot & microstackshots

**Stackshotting**, çalışan tüm thread'lerin çağrı stack'leri de dahil olmak üzere süreçlerin durumunu yakalamak için kullanılan bir tekniktir. Bu teknik özellikle debug, performans analizi ve sistemin belirli bir zamandaki davranışını anlamak için yararlıdır. iOS ve macOS'ta stackshotting, **`sample`** ve **`spindump`** gibi çeşitli araçlar ve yöntemler kullanılarak gerçekleştirilebilir.

### Sysdiagnose

Bu araç (`/usr/bini/ysdiagnose`), `ps`, `zprint` gibi onlarca farklı komutu çalıştırarak bilgisayarınızdan temel olarak çok miktarda bilgi toplar.

**root** olarak çalıştırılmalıdır ve `/usr/libexec/sysdiagnosed` daemon'ı, `com.apple.system-task-ports` ve `get-task-allow` gibi oldukça ilginç entitlements'lara sahiptir.

plist'i `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` konumunda bulunur ve 3 MachServices tanımlar:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp içindeki eski arşivleri siler
- `com.apple.sysdiagnose.kernel.ipc`: Özel port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C sınıfı üzerinden user mode arayüzü. Bir dict içinde üç argüman (`compress`, `display`, `run`) aktarılabilir

### Unified Logs

MacOS, bir uygulamayı çalıştırırken **ne yaptığını** anlamaya çalıştığınızda oldukça yararlı olabilecek çok sayıda log üretir.

Ayrıca bazı loglarda, bazı **user** veya **computer** **identifiable** bilgilerini **gizlemek** için `<private>` etiketi bulunur. Ancak, bu bilgileri açığa çıkarmak için **bir sertifika yüklemek** mümkündür. Açıklamaları [**buradan**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) takip edin.

### Hopper

#### Left panel

Hopper'ın sol panelinde ikilinin sembollerini (**Labels**), prosedür ve işlev listesini (**Proc**) ve string'leri (**Str**) görebilirsiniz. Bunlar tüm string'ler değil, Mac-O dosyasının çeşitli bölümlerinde (örneğin _cstring veya_ `objc_methname`) tanımlanan string'lerdir.

#### Middle panel

Orta panelde **dissasembled code** görebilirsiniz. Ayrıca ilgili simgeye tıklayarak bunu **raw** disassemble, **graph**, **decompiled** veya **binary** olarak görüntüleyebilirsiniz:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Bir code object'e sağ tıklayarak **bu nesneye yapılan/nesneden yapılan referansları** görebilir veya adını değiştirebilirsiniz (bu işlem decompiled pseudocode'da çalışmaz):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ayrıca, **orta panelin alt kısmına Python komutları yazabilirsiniz**.

#### Right panel

Sağ panelde **navigation history** (böylece mevcut duruma nasıl geldiğinizi bilirsiniz), bu **function'ı çağıran tüm function'ları** ve **bu function'ın çağırdığı tüm function'ları** görebileceğiniz **call grap**h ve **local variables** bilgileri gibi ilginç bilgiler bulunur.

### dtrace

Kullanıcıların uygulamalara son derece **low level** erişmesini sağlar ve kullanıcılara **programları trace etme** ve hatta yürütme akışlarını değiştirme olanağı sunar. Dtrace, **kernel boyunca yerleştirilen** ve system call'ların başlangıcı ile sonu gibi konumlarda bulunan **probe**'ları kullanır.

DTrace, her system call için bir probe oluşturmak amacıyla **`dtrace_probe_create`** işlevini kullanır. Bu probe'lar her system call'ın **entry ve exit noktalarında** tetiklenebilir. DTrace ile etkileşim, yalnızca root kullanıcısı tarafından kullanılabilen /dev/dtrace üzerinden gerçekleşir.

> [!TIP]
> SIP korumasını tamamen devre dışı bırakmadan Dtrace'i etkinleştirmek için recovery mode'da şu komutu çalıştırabilirsiniz: `csrutil enable --without dtrace`
>
> Ayrıca **derlediğiniz** **`dtrace`** veya **`dtruss`** ikililerini de kullanabilirsiniz.

Kullanılabilir dtrace probe'ları şu komutla elde edilebilir:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Probe adı dört bölümden oluşur: provider, module, function ve name (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz, DTrace bu bölümü wildcard olarak uygular.

DTrace'i probe'ları etkinleştirecek ve tetiklendiklerinde gerçekleştirilecek eylemleri belirtecek şekilde yapılandırmak için D dilini kullanmamız gerekir.

Daha ayrıntılı bir açıklama ve daha fazla örnek [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) adresinde bulunabilir.

#### Örnekler

Mevcut **DTrace script'lerini** listelemek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`

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

Bir kernel tracing facility'sidir. Belgelenmiş kodlar **`/usr/share/misc/trace.codes`** içinde bulunabilir.

`latency`, `sc_usage`, `fs_usage` ve `trace` gibi araçlar bunu dahili olarak kullanır.

`kdebug` ile arayüz oluşturmak için `kern.kdebug` namespace'i üzerinden `sysctl` kullanılır; kullanılacak MIB'ler `sys/sysctl.h` içinde bulunabilir ve fonksiyonlar `bsd/kern/kdebug.c` dosyasında uygulanmıştır.

Özel bir client ile kdebug ile etkileşim kurmak için genellikle şu adımlar izlenir:

- KERN_KDSETREMOVE ile mevcut ayarları kaldırın
- KERN_KDSETBUF ve KERN_KDSETUP ile trace'i ayarlayın
- Buffer entry sayısını almak için KERN_KDGETBUF kullanın
- KERN_KDPINDEX ile kendi client'ınızı trace'ten çıkarın
- KERN_KDENABLE ile tracing'i etkinleştirin
- KERN_KDREADTR çağrısıyla buffer'ı okuyun
- Her thread'i process'iyle eşleştirmek için KERN_KDTHRMAP çağrısını kullanın.

Bu bilgileri almak için Apple aracı **`trace`** veya özel araç [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** kullanılabilir.**

**Kdebug'in aynı anda yalnızca 1 müşteri için kullanılabildiğini unutmayın.** Bu nedenle aynı anda yalnızca bir k-debug destekli araç çalıştırılabilir.

### ktrace

`ktrace_*` API'leri, `Kdebug` API'lerini saran `libktrace.dylib` içinden gelir. Ardından bir client, belirli kodlar üzerinde callback'leri ayarlamak için `ktrace_session_create` ve `ktrace_events_[single/class]` çağrılarını yapabilir ve sonra `ktrace_start` ile başlatabilir.

Bunu **SIP etkin durumdayken** bile kullanabilirsiniz.

Client olarak `ktrace` yardımcı programını kullanabilirsiniz:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Veya `tailspin`.

### kperf

Bu, kernel seviyesinde profiling yapmak için kullanılır ve `Kdebug` callout'ları kullanılarak oluşturulmuştur.

Temel olarak, global `kernel_debug_active` değişkeni kontrol edilir ve etkinse, çağrı yapan kernel frame'inin `Kdebug` kodu ve adresiyle birlikte `kperf_kdebug_handler` çağrılır. `Kdebug` kodu seçilen kodlardan biriyle eşleşirse, bitmap olarak yapılandırılmış "actions" alınır (seçenekler için `osfmk/kperf/action.h` dosyasına bakın).

Kperf'in ayrıca bir sysctl MIB tablosu vardır: (root olarak) `sysctl kperf`. Bu kodlar `osfmk/kperf/kperfbsd.c` içinde bulunabilir.

Bununla birlikte, Kperf işlevselliğinin bir alt kümesi, makine performance counter'ları hakkında bilgi sağlayan `kpc` içinde bulunur.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir process'in gerçekleştirdiği process ile ilgili action'ları kontrol etmek için çok kullanışlı bir tool'dur (örneğin, bir process'in hangi yeni process'leri oluşturduğunu izlemek için).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/), process'ler arasındaki ilişkileri yazdıran bir tool'dur.\
Mac'inizi **`sudo eslogger fork exec rename create > cap.json`** gibi bir command ile monitor etmeniz gerekir (bunu başlatan terminal FDA gerektirir). Ardından tüm ilişkileri görüntülemek için json dosyasını bu tool'a yükleyebilirsiniz:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), file event'lerini (oluşturma, değiştirme ve silme gibi) monitor etmeyi ve bu event'ler hakkında ayrıntılı bilgi sağlamayı mümkün kılar.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Windows kullanıcılarının Microsoft Sysinternal'ın _Procmon_'undan aşina olabileceği görünüm ve kullanım deneyimine sahip bir GUI tool'udur. Bu tool, çeşitli event türlerinin kaydının başlatılıp durdurulmasına, bu event'lerin file, process, network vb. kategorilere göre filtrelenmesine ve kaydedilen event'lerin json formatında saklanmasına olanak tanır.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode'un Developer tools'larının bir parçasıdır; application performance'ını monitor etmek, memory leak'lerini tespit etmek ve filesystem activity'sini takip etmek için kullanılır.

![Crescendo - Apple Instruments: Apple Instruments, Xcode'un Developer tools'larının bir parçasıdır; application performance'ını monitor etmek, memory leak'lerini tespit etmek ve filesystem activity'sini takip etmek için kullanılır](<../../../images/image (1138).png>)

### fs_usage

Process'ler tarafından gerçekleştirilen action'ları takip etmeyi sağlar:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html), bir binary tarafından kullanılan **libraries**'leri, kullandığı **files**'ları ve **network** bağlantılarını görmek için kullanışlıdır.\
Ayrıca binary process'lerini **virustotal** ile karşılaştırır ve binary hakkında bilgi gösterir.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**bu blog gönderisinde**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), SIP devre dışı olsa bile debugging'i önlemek için **`PT_DENY_ATTACH`** kullanan **çalışan bir daemon'ın debugging** işleminin nasıl yapılacağına dair bir örnek bulabilirsiniz.

### lldb

**lldb**, macOS binary **debugging** işlemi için kullanılan de facto araçtır.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
`lldb` kullanırken, ana klasörünüzde aşağıdaki satırı içeren **`.lldbinit`** adlı bir dosya oluşturarak Intel syntax'ını ayarlayabilirsiniz:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb içinde `process save-core` ile bir process dump'ı alın

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Açıklama</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Çalıştırmayı başlatır; bir breakpoint'e ulaşılana veya process sonlanana kadar kesintisiz şekilde devam eder.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Çalıştırmayı başlatır ve entry point'te durur</td></tr><tr><td><strong>continue (c)</strong></td><td>Debug edilen process'in çalıştırılmasına devam eder.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Sonraki instruction'ı çalıştırır. Bu komut function call'larını atlar.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Sonraki instruction'ı çalıştırır. nexti komutunun aksine bu komut function call'larının içine girer.</td></tr><tr><td><strong>finish (f)</strong></td><td>Mevcut function'daki (“frame”) kalan instruction'ları çalıştırır, return eder ve durur.</td></tr><tr><td><strong>control + c</strong></td><td>Çalıştırmayı duraklatır. Process run (r) ile çalıştırılmış veya continue (c) ile devam ettirilmişse, process'in o anda çalıştığı ...herhangi bir yerde durmasına neden olur.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #main olarak adlandırılan herhangi bir func</p><p><code>b <binname>`main</code> #Bin'in main func'ı</p><p><code>b set -n main --shlib <lib_name></code> #Belirtilen bin'in main func'ı</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Herhangi bir NSFileManager method'u</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Bu library'deki tüm function'larda break</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint listesi</p><p><code>br e/dis <num></code> #Breakpoint'i etkinleştirir/devre dışı bırakır</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Breakpoint komutu hakkında yardım al</p><p>help memory write #Memory'ye yazma hakkında yardım al</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Memory'yi null-terminated string olarak görüntüler.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Memory'yi assembly instruction olarak görüntüler.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Memory'yi byte olarak görüntüler.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Bu, parametre tarafından referans verilen object'i yazdırır</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple'ın Objective-C API'lerinin veya method'larının çoğunun object döndürdüğünü ve bu nedenle “print object” (po) komutuyla görüntülenmesi gerektiğini unutmayın. po anlamlı bir çıktı üretmezse <code>x/b</code> kullanın</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Bu address'e AAAA yaz<br>memory write -f s $rip+0x11f+7 "AAAA" #Address'e AAAA yaz</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Mevcut function'ın disassembly'si</p><p>dis -n <funcname> #Func'ın disassembly'si</p><p>dis -n <funcname> -b <basename> #Func'ın disassembly'si<br>dis -c 6 #6 satırın disassembly'si<br>dis -c 0x100003764 -e 0x100003768 # Bir add'den diğerine kadar<br>dis -p -c 4 #Mevcut address'ten başlayarak disassembly yapar</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 reg'indeki 3 bileşenden oluşan array'i kontrol et</td></tr><tr><td><strong>image dump sections</strong></td><td>Mevcut process memory'sinin map'ini yazdırır</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #CoreNLP'deki tüm symbol'lerin address'ini alır</td></tr></tbody></table>

> [!TIP]
> **`objc_sendMsg`** function'ı çağrılırken **rsi** register'ı method'un adını null-terminated (“C”) string olarak tutar. Adı lldb aracılığıyla yazdırmak için:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** komutu, **host MacOS** olduğunda "Mac", VM olduğunda ise farklı bir değer döndürür.
- Bazı malware'ler bunun bir VM olup olmadığını anlamaya çalışmak için **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynar.
- Bazı malware'ler ayrıca MAC address'e (00:50:56) dayanarak makinenin **VMware** olup olmadığını **tespit edebilir**.
- Bir process'in debug edilip edilmediğini basit bir kod ile bulmak da mümkündür:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Ayrıca **`PT_DENY_ATTACH`** flag'iyle **`ptrace`** system call'ını çağırabilir. Bu, bir **deb**u**gger'ın** attach olup trace etmesini **engeller**.
- **`sysctl`** veya **`ptrace`** function'ının **import** edilip edilmediğini kontrol edebilirsiniz (ancak malware bunu dinamik olarak import edebilir)
- Bu writeup'ta belirtildiği üzere, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Process # exited with **status = 45 (0x0000002d)** mesajı, genellikle debug hedefinin **PT_DENY_ATTACH** kullandığının açık bir göstergesidir_”

## Core Dumps

Core dump'lar şu durumlarda oluşturulur:

- `kern.coredump` sysctl değeri 1 olarak ayarlanmışsa (varsayılan olarak böyledir)
- Process suid/sgid değilse veya `kern.sugid_coredump` değeri 1 ise (varsayılan değer 0'dır)
- `AS_CORE` limiti işlemi izin veriyorsa. `ulimit -c 0` çağrılarak core dump oluşturulması engellenebilir ve `ulimit -c unlimited` ile yeniden etkinleştirilebilir.

Bu durumlarda core dump'lar `kern.corefile` sysctl değerine göre oluşturulur ve genellikle `/cores/core/.%P` konumunda saklanır.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **crash olan process'leri analiz eder ve diske bir crash report kaydeder**. Bir crash report, **bir developer'ın** crash'in nedenini **teşhis etmesine yardımcı olabilecek** bilgiler içerir.\
**Per-user launchd context'inde çalışan** application'lar ve diğer process'ler için ReportCrash, bir LaunchAgent olarak çalışır ve crash report'larını kullanıcının `~/Library/Logs/DiagnosticReports/` konumuna kaydeder.\
Daemon'lar, **system launchd context'inde çalışan diğer process'ler** ve diğer privileged process'ler için ReportCrash, bir LaunchDaemon olarak çalışır ve crash report'larını sistemin `/Library/Logs/DiagnosticReports` konumuna kaydeder

Crash report'larının **Apple'a gönderilmesinden endişe ediyorsanız** bunları devre dışı bırakabilirsiniz. Aksi halde crash report'ları **bir server'ın neden crash olduğunu anlamak** için yararlı olabilir.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uyku

Bir Mac üzerinde fuzzing yaparken Mac'in uykuya geçmesine izin vermemek önemlidir:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısının Kesilmesi

Bir SSH bağlantısı üzerinden fuzzing yapıyorsanız oturumun kesilmeyeceğinden emin olmanız önemlidir. Bu nedenle sshd_config dosyasını şu şekilde değiştirin:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Dahili Handler'lar

**Aşağıdaki sayfaya göz atın** ve belirtilen **şema veya protokolü işlemekten** hangi uygulamanın sorumlu olduğunu nasıl bulabileceğinizi öğrenin:


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Ağ Süreçlerini Listeleme

Ağ verilerini yöneten süreçleri bulmak ilginç olabilir:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Veya `netstat` veya `lsof` kullanın

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzer'lar

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI araçlarıyla çalışır

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI araçlarıyla "**sadece çalışır**". Bazı macOS uygulamalarının benzersiz dosya adları, doğru uzantı, dosyaları sandbox içinden (`~/Library/Containers/com.apple.Safari/Data`) okuma gibi özel gereksinimleri olduğunu unutmayın...

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
### MacOS Fuzzing Hakkında Daha Fazla Bilgi

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referanslar

- [1] [OS X Olay Müdahalesi: Scripting ve Analiz](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware Sanatı, Cilt I: Analiz](https://taomm.org/vol1/analysis.html)
- [4] [Mac Malware Sanatı: Malicious Software Analiz Rehberi](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
