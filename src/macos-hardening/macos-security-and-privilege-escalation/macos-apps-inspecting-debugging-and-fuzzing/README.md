# macOS Apps - Inspecting, debugging और Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Static Analysis

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

आप [**disarm को यहां से download कर सकते हैं**](https://newosxbook.com/tools/disarm.html)।

> [!TIP]
> ध्यान दें कि **`disarm`** compressed IM4P files (जैसे `kernelcache`) के साथ भी काम कर सकता है और केवल आवश्यक parts को extract कर सकता है या उन्हें extract किए बिना भी आवश्यक part का analyze कर सकता है।
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
> **`Codesign`** **macOS** में मिल सकता है, जबकि **`ldid`** **iOS** में मिल सकता है।
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) एक ऐसा tool है जो **.pkg** files (installers) को inspect करने और उन्हें install करने से पहले यह देखने के लिए उपयोगी है कि उनके अंदर क्या है।\
इन installers में `preinstall` और `postinstall` bash scripts होती हैं, जिनका malware authors आमतौर पर **persist** करने और **the** **malware** को बनाए रखने के लिए दुरुपयोग करते हैं।

### hdiutil

यह tool Apple disk images (**.dmg**) files को **mount** करने की अनुमति देता है, ताकि कुछ भी run करने से पहले उनका निरीक्षण किया जा सके:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
इसे `/Volumes` में mount किया जाएगा।

### Packed binaries

- High entropy की जाँच करें
- Strings की जाँच करें (यदि लगभग कोई समझ में आने वाली string नहीं है, तो यह packed है)
- MacOS के लिए UPX packer `\_\_XHDR` नामक section generate करता है

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए programs [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) में **compiled** होने के **बाद भी** अपनी class declarations **retain** करते हैं। ऐसी class declarations में निम्न के नाम और type शामिल होते हैं:

- Defined interfaces
- Interface methods
- Interface instance variables
- Defined protocols

ध्यान दें कि binary को reverse करना अधिक कठिन बनाने के लिए इन names को obfuscate किया जा सकता है।

### Function calling

जब Objective-C का उपयोग करने वाले binary में किसी function को call किया जाता है, तो compiled code उस function को सीधे call करने के बजाय **`objc_msgSend`** को call करेगा। यह final function को call करेगा:

![Metadata - Function calling: जब Objective-C का उपयोग करने वाले binary में किसी function को call किया जाता है, तो compiled code उस function को सीधे call करने के बजाय objc msgSend को call करेगा। जो ...](<../../../images/image (305).png>)

इस function को अपेक्षित params हैं:

- पहला parameter (**self**) "एक ऐसा pointer है जो उस **class के instance की ओर point करता है जिसे message receive करना है**।" या सरल शब्दों में, यह वह object है जिस पर method invoke किया जा रहा है। यदि method एक class method है, तो यह class object (पूरे रूप में) के एक instance को refer करेगा, जबकि instance method के लिए, self class के instantiated instance को object के रूप में point करेगा।
- दूसरा parameter, (**op**), "उस method का selector है जो message को handle करता है।" सरल शब्दों में, यह केवल **method का name** है।
- शेष parameters वे **values हैं जो method** (op) के लिए आवश्यक हैं।

देखें कि **ARM64 में `lldb` के साथ यह info आसानी से कैसे प्राप्त करें**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: वह object जिस पर method invoke किया जा रहा है** |
| **2nd argument**  | **rsi**                                                         | **op: method का name**                             |
| **3rd argument**  | **rdx**                                                         | **method का 1st argument**                         |
| **4th argument**  | **rcx**                                                         | **method का 2nd argument**                         |
| **5th argument**  | **r8**                                                          | **method का 3rd argument**                         |
| **6th argument**  | **r9**                                                          | **method का 4th argument**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method का 5th+ argument**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) Objective-C binaries को class-dump करने का एक tool है। github पर dylibs का उल्लेख है, लेकिन यह executables के साथ भी काम करता है।
```bash
./dynadump dump /path/to/bin
```
लेखन के समय, **वर्तमान में यही सबसे अच्छा काम करता है**।

#### सामान्य tools
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) Objective-C formatted code में classes, categories और protocols के लिए declarations generate करने वाला original tool है।

यह पुराना और unmaintained है, इसलिए संभवतः ठीक से काम नहीं करेगा।

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) एक आधुनिक और cross-platform Objective-C class dump है। मौजूदा tools की तुलना में, iCDump Apple ecosystem से स्वतंत्र रूप से run कर सकता है और यह Python bindings expose करता है।
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analysis

Swift binaries में, Objective-C compatibility होने के कारण, कभी-कभी आप [class-dump](https://github.com/nygard/class-dump/) का उपयोग करके declarations extract कर सकते हैं, लेकिन हमेशा नहीं।

**`jtool -l`** या **`otool -l`** command lines के साथ **`__swift5`** prefix से शुरू होने वाले कई sections खोजे जा सकते हैं:
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
आप इन sections में stored **information के बारे में आगे की जानकारी [इस blog post में पा सकते हैं](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)।<sup>[[5]](#references)</sup>

इसके अलावा, **Swift binaries में symbols हो सकते हैं** (उदाहरण के लिए, libraries को symbols store करने की आवश्यकता होती है ताकि उनके functions को call किया जा सके)। **symbols में आमतौर पर function name और attr की information एक अव्यवस्थित तरीके से होती है**, इसलिए वे बहुत उपयोगी होते हैं और ऐसे "**demanglers"** मौजूद हैं जो original name प्राप्त कर सकते हैं:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> ध्यान दें कि binaries को debug करने के लिए, **SIP को disabled** होना आवश्यक है (`csrutil disable` या `csrutil enable --without debug`) या binaries को किसी temporary folder में copy करके `codesign --remove-signature <binary-path>` से **signature remove** करें या binary की debugging की अनुमति दें (आप [इस script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) का उपयोग कर सकते हैं)

> [!WARNING]
> ध्यान दें कि macOS पर **system binaries को instrument** करने के लिए, (जैसे `cloudconfigurationd`) **SIP को disabled** होना आवश्यक है (सिर्फ signature remove करना काम नहीं करेगा)।

### APIs

macOS कुछ interesting APIs expose करता है जो processes के बारे में information देते हैं:

- `proc_info`: यह मुख्य API है, जो प्रत्येक process के बारे में बहुत सारी information देता है। अन्य processes की information प्राप्त करने के लिए आपको root होना आवश्यक है, लेकिन आपको special entitlements या mach ports की आवश्यकता नहीं होती।
- `libsysmon.dylib`: यह XPC exposed functions के माध्यम से processes की information प्राप्त करने की अनुमति देता है, हालांकि इसके लिए `com.apple.sysmond.client` entitlement होना आवश्यक है।

### Stackshot & microstackshots

**Stackshotting** एक technique है जिसका उपयोग processes की state capture करने के लिए किया जाता है, जिसमें सभी running threads के call stacks शामिल होते हैं। यह debugging, performance analysis और किसी विशेष समय पर system के behavior को समझने के लिए विशेष रूप से उपयोगी है। iOS और macOS पर stackshotting को **`sample`** और **`spindump`** जैसे कई tools और methods का उपयोग करके किया जा सकता है।

### Sysdiagnose

यह tool (`/usr/bini/ysdiagnose`) मूल रूप से आपके computer से बहुत सारी information collect करता है और `ps`, `zprint` जैसे दर्जनों अलग-अलग commands execute करता है...

इसे **root** के रूप में run करना आवश्यक है और daemon `/usr/libexec/sysdiagnosed` के पास `com.apple.system-task-ports` और `get-task-allow` जैसे बहुत interesting entitlements हैं।

इसकी plist `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` में स्थित है, जो 3 MachServices declare करती है:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp में पुराने archives delete करता है
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class के माध्यम से User mode interface। एक dict में तीन arguments (`compress`, `display`, `run`) pass किए जा सकते हैं

### Unified Logs

MacOS बहुत सारे logs generate करता है, जो किसी application को run करते समय यह समझने के लिए बहुत उपयोगी हो सकते हैं कि वह **क्या कर रहा है**।

इसके अलावा, कुछ logs में `<private>` tag होगा, जो कुछ **user** या **computer** की **identifiable** information को **hide** करेगा। हालांकि, इस information को **disclose करने के लिए certificate install करना** संभव है। [**यहां**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) दिए गए explanations का पालन करें।

### Hopper

#### Left panel

Hopper के left panel में binary के symbols (**Labels**), procedures और functions की list (**Proc**) और strings (**Str**) देखना संभव है। ये सभी strings नहीं हैं, बल्कि Mac-O file के कई parts (जैसे _cstring या `objc_methname`) में defined strings हैं।

#### Middle panel

Middle panel में आप **dissasembled code** देख सकते हैं। और respective icon पर click करके इसे **raw** disassemble, **graph**, **decompiled** और **binary** के रूप में देख सकते हैं:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

किसी code object पर right click करने से आप **उस object के references to/from** देख सकते हैं या उसका नाम बदल सकते हैं (यह decompiled pseudocode में काम नहीं करता):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

इसके अलावा, **middle के नीचे आप python commands लिख सकते हैं**।

#### Right panel

Right panel में आप navigation history जैसी interesting information देख सकते हैं (जिससे आपको पता चलता है कि आप current situation तक कैसे पहुंचे), **call grap**h, जिसमें आप देख सकते हैं कि **कौन से functions इस function को call करते हैं** और **यह function किन functions को call करता है**, तथा **local variables** की information।

### dtrace

यह users को applications तक अत्यंत **low level** पर access देता है और users को **programs trace** करने तथा उनके execution flow को बदलने का तरीका प्रदान करता है। Dtrace **probes** का उपयोग करता है, जिन्हें **kernel में विभिन्न स्थानों पर place** किया जाता है, जैसे system calls की शुरुआत और अंत में।

DTrace प्रत्येक system call के लिए probe create करने हेतु **`dtrace_probe_create`** function का उपयोग करता है। ये probes प्रत्येक system call के **entry और exit point** पर fire किए जा सकते हैं। DTrace के साथ interaction /dev/dtrace के माध्यम से होता है, जो केवल root user के लिए उपलब्ध है।<sup>[[1]](#references)</sup>

> [!TIP]
> SIP protection को पूरी तरह disabled किए बिना Dtrace enable करने के लिए आप recovery mode पर यह execute कर सकते हैं: `csrutil enable --without dtrace`
>
> आप अपने द्वारा **compiled** किए गए **`dtrace`** या **`dtruss`** binaries को भी **dtrace** कर सकते हैं।

dtrace के available probes इस command से प्राप्त किए जा सकते हैं:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Probe का नाम चार भागों से बना होता है: provider, module, function और name (`fbt:mach_kernel:ptrace:entry`)। यदि आप नाम का कोई भाग निर्दिष्ट नहीं करते हैं, तो Dtrace उस भाग को wildcard के रूप में लागू करेगा।

Probes को activate करने और उनके fire होने पर की जाने वाली actions निर्दिष्ट करने के लिए, हमें D language का उपयोग करना होगा।

अधिक विस्तृत explanation और अधिक examples [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) में मिल सकते हैं।

#### Examples

**DTrace scripts available** की सूची देखने के लिए `man -k dtrace` चलाएँ। Example: `sudo dtruss -n binary`

- Line में
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

यह एक kernel tracing facility है। Documented codes **`/usr/share/misc/trace.codes`** में मिल सकते हैं।

`latency`, `sc_usage`, `fs_usage` और `trace` जैसे tools इसे internally use करते हैं।

`kdebug` के साथ interface करने के लिए `kern.kdebug` namespace पर `sysctl` का उपयोग किया जाता है और इस्तेमाल किए जाने वाले MIBs `sys/sysctl.h` में मिल सकते हैं, जिनके functions `bsd/kern/kdebug.c` में implemented हैं।

Custom client के साथ kdebug से interact करने के सामान्य steps ये हैं:

- KERN_KDSETREMOVE के साथ existing settings हटाएँ
- KERN_KDSETBUF और KERN_KDSETUP के साथ trace set करें
- Buffer entries की संख्या प्राप्त करने के लिए KERN_KDGETBUF का उपयोग करें
- KERN_KDPINDEX के साथ अपने client को trace से बाहर निकालें
- KERN_KDENABLE के साथ tracing enable करें
- KERN_KDREADTR को call करके buffer पढ़ें
- प्रत्येक thread को उसके process से match करने के लिए KERN_KDTHRMAP का उपयोग करें।

यह information प्राप्त करने के लिए Apple tool **`trace`** या custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** का उपयोग किया जा सकता है।**

**ध्यान दें कि Kdebug एक समय में केवल 1 customer के लिए available है।** इसलिए एक ही समय में केवल एक k-debug powered tool execute किया जा सकता है।

### ktrace

`ktrace_*` APIs `libktrace.dylib` से आती हैं, जो `Kdebug` की APIs को wrap करती हैं। इसके बाद, client `ktrace_session_create` और `ktrace_events_[single/class]` को call करके specific codes पर callbacks set कर सकता है और फिर `ktrace_start` के साथ इसे start कर सकता है।

आप इसका उपयोग **SIP activated** होने पर भी कर सकते हैं।

आप clients के रूप में `ktrace` utility का उपयोग कर सकते हैं:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

इसका उपयोग kernel level profiling करने के लिए किया जाता है और इसे `Kdebug` callouts का उपयोग करके बनाया गया है।

मूल रूप से, global variable `kernel_debug_active` को check किया जाता है और यदि यह set है, तो यह `Kdebug` code और calling kernel frame के address के साथ `kperf_kdebug_handler` को call करता है। यदि `Kdebug` code चुने गए code से match करता है, तो इसे bitmap के रूप में configured "actions" मिलते हैं (विकल्पों के लिए `osfmk/kperf/action.h` check करें)।

Kperf में एक sysctl MIB table भी है: (root के रूप में) `sysctl kperf`। ये code `osfmk/kperf/kperfbsd.c` में पाए जा सकते हैं।

इसके अलावा, Kperf की functionality का एक subset `kpc` में मौजूद है, जो machine performance counters के बारे में जानकारी प्रदान करता है।

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) किसी process द्वारा किए जा रहे process-related actions को check करने के लिए एक बहुत उपयोगी tool है (उदाहरण के लिए, यह monitor करना कि कोई process कौन से नए processes create कर रहा है)।

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) processes के बीच relations print करने वाला एक tool है।\
आपको अपने Mac को **`sudo eslogger fork exec rename create > cap.json`** जैसे command से monitor करना होगा (इसे launch करने वाले terminal को FDA की आवश्यकता होती है)। इसके बाद आप सभी relations देखने के लिए इस tool में json load कर सकते हैं:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) file events (जैसे creation, modifications और deletions) को monitor करने की सुविधा देता है और ऐसे events के बारे में detailed information प्रदान करता है।

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) एक GUI tool है, जिसका look and feel Windows users को Microsoft Sysinternal के _Procmon_ से परिचित लग सकता है। यह tool विभिन्न event types की recording को start और stop करने देता है, file, process, network आदि categories के अनुसार इन events को filter करने देता है और recorded events को json format में save करने की functionality प्रदान करता है।

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) Xcode के Developer tools का हिस्सा हैं - इनका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है।

![Crescendo - Apple Instruments: Apple Instruments Xcode के Developer tools का हिस्सा हैं - इनका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है](<../../../images/image (1138).png>)

### fs_usage

Processes द्वारा किए गए actions को follow करने की सुविधा देता है:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) किसी binary द्वारा उपयोग की जाने वाली **libraries**, उसके द्वारा उपयोग की जा रही **फ़ाइलों** और **network** connections को देखने के लिए उपयोगी है।\
यह binary processes को **virustotal** के विरुद्ध भी check करता है और binary के बारे में information दिखाता है।

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**इस blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) में आप एक ऐसे **running daemon** को **debug** करने का example पा सकते हैं, जो SIP disabled होने पर भी debugging को रोकने के लिए **`PT_DENY_ATTACH`** का उपयोग करता था।<sup>[[6]](#references)</sup>

### lldb

**lldb**, **macOS** binary **debugging** के लिए de **facto tool** है।
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
आप अपने home folder में **`.lldbinit`** नाम की file बनाकर और उसमें निम्नलिखित line जोड़कर lldb का intel flavour सेट कर सकते हैं:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Inside lldb, dump a process with `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>विवरण</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Execution शुरू करता है, जो breakpoint हिट होने या process terminate होने तक बिना रुके जारी रहता है।</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Entry point पर execution रोककर शुरू करता है</td></tr><tr><td><strong>continue (c)</strong></td><td>Debug किए जा रहे process का execution जारी रखता है।</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>अगला instruction execute करता है। यह command function calls को skip कर देगा।</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>अगला instruction execute करता है। nexti command के विपरीत, यह command function calls के अंदर step करेगा।</td></tr><tr><td><strong>finish (f)</strong></td><td>वर्तमान function (“frame”) के बाकी instructions execute करके return और halt करता है।</td></tr><tr><td><strong>control + c</strong></td><td>Execution को pause करता है। यदि process को run (r) या continue (c) किया गया है, तो process वहीं halt हो जाएगा ...जहाँ वह वर्तमान में execute हो रहा है।</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Memory को null-terminated string के रूप में display करता है।</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Memory को assembly instruction के रूप में display करता है।</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Memory को byte के रूप में display करता है।</td></tr><tr><td><strong>print object (po)</strong></td><td><p>यह param द्वारा referenced object को print करेगा</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>ध्यान दें कि Apple के अधिकांश Objective-C APIs या methods objects return करते हैं, इसलिए उन्हें “print object” (po) command के माध्यम से display किया जाना चाहिए। यदि po कोई meaningful output उत्पन्न नहीं करता है, तो <code>x/b</code> का उपयोग करें</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Current process memory का map print करता है</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> **`objc_sendMsg`** function को call करते समय, **rsi** register में null-terminated (“C”) string के रूप में **method का नाम** होता है। lldb के माध्यम से नाम print करने के लिए:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** command तब "Mac" return करता है जब **host MacOS** हो, लेकिन VM होने पर कुछ अलग return करता है।<sup>[[3]](#references)</sup>
- **`hw.logicalcpu`** और **`hw.physicalcpu`** की values के साथ छेड़छाड़ करके कुछ malwares यह detect करने का प्रयास करते हैं कि system VM है या नहीं।<sup>[[4]](#references)</sup>
- कुछ malwares MAC address (00:50:56) के आधार पर यह भी **detect** कर सकते हैं कि machine **VMware** है।
- यह पता लगाना भी संभव है कि **process debug किया जा रहा है** या नहीं, एक simple code से, जैसे:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- यह **`ptrace`** system call को **`PT_DENY_ATTACH`** flag के साथ invoke भी कर सकता है। यह deb**u**gger को attach और tracing करने से **रोकता** है।
- आप check कर सकते हैं कि **`sysctl`** या **`ptrace`** function **import** किया जा रहा है या नहीं (लेकिन malware इसे dynamically import कर सकता है)
- जैसा कि इस writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” में बताया गया है :<sup>[[7]](#references)</sup>\
“_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”

## Core Dumps

Core dumps तब create होते हैं जब:

- `kern.coredump` sysctl को 1 पर set किया गया हो (default रूप से)
- यदि process suid/sgid नहीं था या `kern.sugid_coredump` 1 हो (default रूप से 0)
- `AS_CORE` limit operation की अनुमति देती हो। `ulimit -c 0` call करके core dumps creation को suppress करना और `ulimit -c unlimited` से उन्हें फिर enable करना संभव है।

इन परिस्थितियों में core dump `kern.corefile` sysctl के अनुसार generate होता है और आमतौर पर `/cores/core/.%P` में store किया जाता है।

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **crashing processes का analysis करता है और crash report को disk पर save करता है**। Crash report में ऐसी information होती है जो **developer को crash का कारण diagnose करने में सहायता** कर सकती है।\
Applications और अन्य **per-user launchd context में चलने वाले processes** के लिए, ReportCrash LaunchAgent के रूप में run होता है और crash reports को user की `~/Library/Logs/DiagnosticReports/` में save करता है।\
Daemons, अन्य **system launchd context में चलने वाले processes** और अन्य privileged processes के लिए, ReportCrash LaunchDaemon के रूप में run होता है और crash reports को system के `/Library/Logs/DiagnosticReports` में save करता है।

यदि आपको crash reports के **Apple को भेजे जाने** की चिंता है, तो आप उन्हें disable कर सकते हैं। अन्यथा, crash reports यह **पता लगाने में उपयोगी हो सकती हैं कि server कैसे crash हुआ**।
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

MacOS में fuzzing करते समय यह महत्वपूर्ण है कि Mac sleep न करे:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Disconnect

यदि आप SSH connection के माध्यम से fuzzing कर रहे हैं, तो यह सुनिश्चित करना महत्वपूर्ण है कि session समाप्त न हो। इसलिए `sshd_config` file में ये बदलाव करें:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**इस पेज को देखें** ताकि पता लगाया जा सके कि **निर्दिष्ट scheme या protocol को handle करने के लिए कौन-सा app ज़िम्मेदार है:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Network data को manage करने वाले processes को ढूँढने के लिए यह उपयोगी है:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
या `netstat` या `lsof` का उपयोग करें

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI tools के लिए काम करता है

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

यह macOS GUI tools के साथ "**बस काम करता है**"। ध्यान दें कि कुछ macOS apps की कुछ विशिष्ट आवश्यकताएँ होती हैं, जैसे unique filenames, सही extension, files को sandbox (`~/Library/Containers/com.apple.Safari/Data`) से पढ़ने की आवश्यकता...

कुछ examples:
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
### अधिक Fuzzing macOS जानकारी

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## संदर्भ

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)
- [5] [knight.sc - इस blog post के इन sections में stored information](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach का उपयोग करने वाले Apple Binaries को Debugging करना](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Techniques को पराजित करना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
