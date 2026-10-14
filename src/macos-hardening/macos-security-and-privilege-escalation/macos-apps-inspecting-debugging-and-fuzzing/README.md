# macOS Apps - निरीक्षण, डीबगिंग और Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## स्थिर विश्लेषण

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

आप [**यहाँ से disarm डाउनलोड कर सकते हैं**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> ध्यान दें कि **`disarm`** compressed IM4P files (जैसे `kernelcache`) के साथ भी काम कर सकता है और केवल आवश्यक हिस्से extract कर सकता है, या उन्हें extract किए बिना भी आवश्यक हिस्से का विश्लेषण कर सकता है।

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
> **`Codesign`** **macOS** में मिल सकता है, जबकि **`ldid`** **iOS** में मिल सकता है.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) **.pkg** फ़ाइलों (installers) की जाँच करने और उन्हें install करने से पहले उनकी सामग्री देखने के लिए उपयोगी tool है।\
इन installers में `preinstall` और `postinstall` bash scripts होती हैं, जिनका malware लेखक आमतौर पर malware को **persist** करने के लिए दुरुपयोग करते हैं।

### hdiutil

यह tool Apple disk image (`.dmg`) फ़ाइलों को **mount** करता है, ताकि कुछ भी चलाए जाने से पहले उनकी जाँच की जा सके:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

इसे `/Volumes` में mount किया जाएगा

### Packed binaries

- High entropy जाँचें
- Strings जाँचें (अगर लगभग कोई भी समझ में आने वाली string नहीं है, तो binary packed है)
- macOS के लिए UPX packer `__XHDR` नाम का section बनाता है।

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए programs, [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) में **compile** होने पर भी अपनी class declarations **बनाए रखते हैं**। ऐसी class declarations में ये नाम और प्रकार **शामिल होते हैं**:

- परिभाषित interfaces
- Interface methods
- Interface instance variables
- परिभाषित protocols

ध्यान दें कि binary को reverse करना अधिक कठिन बनाने के लिए इन नामों को obfuscate किया जा सकता है।

### Function calling

Objective-C इस्तेमाल करने वाली binary में किसी function को call करने पर, compiled code उस function को सीधे call करने के बजाय **`objc_msgSend`** को call करेगा। यही अंतिम function को call करेगा:

![Metadata - Function calling: Objective-C इस्तेमाल करने वाली binary में किसी function को call करने पर, compiled code उस function को सीधे call करने के बजाय objc msgSend को call करेगा। यही...](<../../../images/image (305).png>)

इस function को जिन params की अपेक्षा होती है, वे हैं:

- पहला parameter (**self**) "एक ऐसा pointer है जो **उस class के instance की ओर point करता है जिसे message प्राप्त करना है**"। सरल शब्दों में, यह वह object है जिस पर method invoke किया जा रहा है। यदि method class method है, तो यह class object (समग्र रूप में) का instance होगा; जबकि instance method के लिए, self class के instantiated instance को object के रूप में point करेगा।
- दूसरा parameter (**op**) "उस method का selector है जो message को handle करता है"। सरल शब्दों में, यह केवल **method का नाम** है।
- बाकी parameters वे **values हैं जिनकी method (op) को आवश्यकता होती है**।

देखें कि **ARM64 में `lldb` से यह जानकारी आसानी से कैसे प्राप्त करें**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **पहला argument**  | **rdi**                                                         | **self: वह object जिस पर method invoke किया जा रहा है** |
| **दूसरा argument**  | **rsi**                                                         | **op: method का नाम**                             |
| **तीसरा argument**  | **rdx**                                                         | **method का पहला argument**                         |
| **चौथा argument**  | **rcx**                                                         | **method का दूसरा argument**                         |
| **पाँचवाँ argument**  | **r8**                                                          | **method का तीसरा argument**                         |
| **छठा argument**  | **r9**                                                          | **method का चौथा argument**                         |
| **सातवाँ+ argument** | <p><strong>rsp+</strong><br><strong>(stack पर)</strong></p> | **method का पाँचवाँ+ argument**                        |

### ObjectiveC metadata dump करना

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) Objective-C binaries को class-dump करने का एक tool है। GitHub पर dylibs का उल्लेख है, लेकिन यह executables के साथ भी काम करता है।

```bash
./dynadump dump /path/to/bin
```

लेखन के समय, **फिलहाल यही सबसे अच्छा काम करता है**।

#### सामान्य टूल्स

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ObjectiveC formatted code में classes, categories और protocols के declarations generate करने वाला मूल tool है।

यह पुराना है और इसका maintenance नहीं होता, इसलिए संभव है कि यह ठीक से काम न करे।

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) एक आधुनिक और cross-platform Objective-C class dump है। मौजूदा tools की तुलना में, iCDump Apple ecosystem से स्वतंत्र रूप से चल सकता है और Python bindings उपलब्ध कराता है।

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Static Swift analysis

Swift binaries में, Objective-C compatibility के कारण, कभी-कभी [class-dump](https://github.com/nygard/class-dump/) का उपयोग करके declarations निकाली जा सकती हैं, लेकिन हमेशा नहीं।

**`jtool -l`** या **`otool -l`** command lines से **`__swift5`** prefix से शुरू होने वाले कई sections ढूँढे जा सकते हैं:

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

आप इन sections में **stored information के बारे में और जानकारी इस blog post में पा सकते हैं**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

इसके अलावा, **Swift binaries में symbols हो सकते हैं** (उदाहरण के लिए, libraries को symbols store करने पड़ते हैं ताकि उनके functions को call किया जा सके)। **आमतौर पर symbols में function name और attributes की जानकारी बदसूरत रूप में होती है**, इसलिए वे बहुत उपयोगी होते हैं और ऐसे "**demanglers"** भी हैं जो original name पा सकते हैं:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## गतिशील विश्लेषण

> [!WARNING]
> **डिफ़ॉल्ट debugging step के रूप में SIP को disable न करें।** `com.apple.security.get-task-allow` वाले development builds को SIP enabled रहते हुए debug किया जा सकता है। LLDB चलाने से पहले `codesign -d --entitlements :- /path/to/binary` से target जाँचें। केवल debugger entitlement होने से SIP-protected targets तक access नहीं मिलता।<sup>[[15]](#references)</sup>
>
> Hardened runtime वाली distributed app में आम तौर पर `get-task-allow` नहीं होता और वह attachment को block करती है। हो सके तो developer से debug build लें; disposable copy को re-sign करने से जाँचे जा रहे behavior में बदलाव हो सकता है। अगर किसी protected target के लिए SIP disable करना ज़रूरी हो, तो ऐसी मशीन के बजाय dedicated test machine या VM इस्तेमाल करें जिस पर आप निर्भर हैं।<sup>[[16]](#references)</sup>

> [!WARNING]
> ध्यान दें कि macOS पर **system binaries** (जैसे `cloudconfigurationd`) को **instrument** करने के लिए **SIP disable होना चाहिए** (केवल signature हटाने से काम नहीं चलेगा)।

### APIs

macOS कुछ दिलचस्प APIs उपलब्ध कराता है जो processes के बारे में जानकारी देते हैं:

- `proc_info`: यह मुख्य API है, जो हर process के बारे में बहुत सारी जानकारी देता है। दूसरे processes की जानकारी पाने के लिए root होना ज़रूरी है, लेकिन special entitlements या mach ports की ज़रूरत नहीं होती।
- `libsysmon.dylib`: XPC functions के ज़रिए process की जानकारी देता है, लेकिन इसे call करने वालों के पास `com.apple.sysmond.client` entitlement होना चाहिए।

### Stackshot & microstackshots

**Stackshotting** एक ऐसी technique है जिसका इस्तेमाल processes की स्थिति कैप्चर करने के लिए किया जाता है। इसमें चल रहे सभी threads के call stacks शामिल होते हैं। यह debugging, performance analysis और किसी खास समय पर system के behavior को समझने के लिए विशेष रूप से उपयोगी है। iOS और macOS पर stackshotting कई tools और methods से किया जा सकता है, जैसे **`sample`** और **`spindump`** tools।

### Sysdiagnose

यह tool (`/usr/bini/ysdiagnose`) आपके computer से बहुत सारी जानकारी इकट्ठा करता है। इसके लिए यह `ps`, `zprint` जैसे दर्जनों अलग-अलग commands चलाता है।

इसे **root** के रूप में चलाना ज़रूरी है। इसके daemon `/usr/libexec/sysdiagnosed` के पास `com.apple.system-task-ports` और `get-task-allow` जैसे बहुत दिलचस्प entitlements हैं।

इसकी plist `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` में है, जिसमें 3 MachServices घोषित हैं:

- `com.apple.sysdiagnose.CacheDelete`: `/var/rmp` में पुराने archives हटाता है
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class के ज़रिए user-mode interface। एक dict में तीन arguments (`compress`, `display`, `run`) दिए जा सकते हैं।

### Unified Logs

macOS व्यापक logs बनाता है, जो किसी application के behavior का विश्लेषण करते समय उपयोगी होते हैं।

कुछ log fields में user या device की पहचान उजागर करने वाली जानकारी छिपाने के लिए `<private>` tag होता है। पुराने निर्देशों में कभी-कभी इन fields को दिखाने के लिए certificate install करने की बात होती है; मौजूदा debugging guidance में इसके बजाय स्पष्ट रूप से scoped configuration profile में `Enable-Private-Data` या per-application `OSLogPreferences` का उपयोग किया जाता है। इसका behavior subsystem और macOS release के अनुसार अलग-अलग हो सकता है। पुराने certificate/profile से जुड़ी चर्चा references में रखी गई है। <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### बायाँ पैनल

Hopper के बाएँ पैनल में binary के symbols (**Labels**), procedures और functions की सूची (**Proc**), और strings (**Str**) देखी जा सकती हैं। इनमें सभी strings शामिल नहीं होतीं, बल्कि Mac-O file के कई हिस्सों में परिभाषित strings होती हैं (जैसे _cstring या_ `objc_methname`)।

#### मध्य पैनल

मध्य पैनल में **disassembled code** दिखता है। संबंधित icon पर click करके इसे **raw** disassembly, **graph**, **decompiled** या **binary** रूप में देखा जा सकता है:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

किसी code object पर right-click करने से आप उस object के **references to/from** देख सकते हैं या उसका नाम बदल सकते हैं (यह decompiled pseudocode में काम नहीं करता):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

इसके अलावा, **मध्य पैनल के निचले हिस्से में आप Python commands लिख सकते हैं**।

#### दायाँ पैनल

दाएँ पैनल में navigation history जैसी उपयोगी जानकारी दिखती है (जिससे पता चलता है कि आप मौजूदा स्थिति तक कैसे पहुँचे), **call graph** जिसमें इस function को call करने वाले सभी **functions** और इस function द्वारा call किए गए सभी functions दिखते हैं, और **local variables** की जानकारी।

### dtrace

यह users को applications तक बेहद **low level** पर access देता है और **programs** को **trace** करने, यहाँ तक कि उनके execution flow को बदलने का तरीका भी उपलब्ध कराता है। Dtrace **probes** का उपयोग करता है, जिन्हें **kernel में जगह-जगह रखा जाता है**—जैसे system calls की शुरुआत और अंत में।

DTrace हर system call के लिए probe बनाने हेतु **`dtrace_probe_create`** function का इस्तेमाल करता है। ये probes हर system call के **entry और exit point** पर fire हो सकते हैं। DTrace के साथ interaction `/dev/dtrace` के ज़रिए होता है, जो केवल root user के लिए उपलब्ध है।<sup>[[1]](#references)</sup>

> [!TIP]
> SIP protection को पूरी तरह disable किए बिना Dtrace enable करने के लिए, recovery mode में यह command चला सकते हैं: `csrutil enable --without dtrace`
>
> आप **वे `dtrace` या `dtruss` binaries** भी इस्तेमाल कर सकते हैं **जिन्हें आपने compile किया है**।

dtrace के उपलब्ध probes इस command से प्राप्त किए जा सकते हैं:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Probe का नाम चार भागों से मिलकर बनता है: provider, module, function और name (`fbt:mach_kernel:ptrace:entry`)। यदि आप नाम का कोई भाग निर्दिष्ट नहीं करते हैं, तो DTrace उस भाग को wildcard के रूप में लागू करेगा।

DTrace को probes सक्रिय करने और उनके fire होने पर किए जाने वाले actions निर्दिष्ट करने के लिए, हमें D language का उपयोग करना होगा।

अधिक विस्तृत व्याख्या और अतिरिक्त उदाहरण [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) पर मिल सकते हैं।

#### उदाहरण

**उपलब्ध DTrace scripts** की सूची देखने के लिए `man -k dtrace` चलाएँ। उदाहरण: `sudo dtruss -n binary`

- इन-लाइन

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

यह kernel tracing facility है। इसके documented codes **`/usr/share/misc/trace.codes`** में मिल सकते हैं।

`latency`, `sc_usage`, `fs_usage` और `trace` जैसे tools आंतरिक रूप से इसका उपयोग करते हैं।

`kdebug` के साथ interface करने के लिए `kern.kdebug` namespace पर `sysctl` का उपयोग किया जाता है। इस्तेमाल किए जाने वाले MIBs `sys/sysctl.h` में मिल सकते हैं, और इनके functions `bsd/kern/kdebug.c` में implemented हैं।

Custom client के साथ kdebug से interact करने के लिए आम तौर पर ये चरण होते हैं:

- KERN_KDSETREMOVE से मौजूदा settings हटाएँ
- KERN_KDSETBUF और KERN_KDSETUP से trace set करें
- Buffer entries की संख्या पाने के लिए KERN_KDGETBUF का उपयोग करें
- KERN_KDPINDEX से अपने client को trace से प्राप्त करें
- KERN_KDENABLE से tracing enable करें
- KERN_KDREADTR को call करके buffer पढ़ें
- प्रत्येक thread को उसके process से match करने के लिए KERN_KDTHRMAP call करें।

यह जानकारी पाने के लिए Apple tool **`trace`** या custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** का उपयोग किया जा सकता है।

**ध्यान दें कि Kdebug एक समय में केवल 1 ग्राहक के लिए उपलब्ध है।** इसलिए एक ही समय में k-debug powered tool में से केवल एक चलाया जा सकता है।

### ktrace

`ktrace_*` APIs `libktrace.dylib` से आती हैं, जो `Kdebug` की APIs को wrap करती हैं। इसके बाद, client `ktrace_session_create` और `ktrace_events_[single/class]` को call करके specific codes पर callbacks set कर सकता है और फिर `ktrace_start` से इसे शुरू कर सकता है।

आप इसे **SIP activated** होने पर भी इस्तेमाल कर सकते हैं।

Clients के रूप में आप `ktrace` utility का उपयोग कर सकते हैं:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

या `tailspin`।

### kperf

इसका उपयोग kernel level profiling करने के लिए किया जाता है और इसे `Kdebug` callouts का उपयोग करके बनाया गया है।

मूल रूप से, global variable `kernel_debug_active` की जाँच की जाती है और यदि यह set है, तो यह `Kdebug` code और कॉल करने वाले kernel frame के address के साथ `kperf_kdebug_handler` को call करता है। यदि `Kdebug` code चुने गए code से मेल खाता है, तो इसे bitmap के रूप में configured "actions" मिलते हैं (विकल्पों के लिए `osfmk/kperf/action.h` देखें)।

Kperf में एक sysctl MIB table भी है: (root के रूप में) `sysctl kperf`। ये code `osfmk/kperf/kperfbsd.c` में मिल सकते हैं।

इसके अलावा, Kperf की कुछ functionality `kpc` में मौजूद है, जो machine performance counters के बारे में जानकारी देता है।

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) यह देखने के लिए एक बहुत उपयोगी tool है कि कोई process कौन-सी process-related actions कर रही है (उदाहरण के लिए, यह monitor करना कि कोई process कौन-सी नई processes बना रही है)।

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) एक tool है जो processes के बीच संबंधों को दिखाता है।\
आपको अपने Mac को **`sudo eslogger fork exec rename create > cap.json`** जैसी command से monitor करना होगा (इसे launch करने वाले terminal को FDA की आवश्यकता है)। इसके बाद आप सभी संबंध देखने के लिए json को इस tool में load कर सकते हैं:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) file events जैसे creation, modification और deletion को monitor करता है।

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) एक GUI tool है, जिसका look and feel Windows users को Microsoft Sysinternal के _Procmon_ जैसा लग सकता है। यह tool विभिन्न event types की recording शुरू और बंद करने देता है, file, process, network आदि जैसी categories के आधार पर इन events को filter करने देता है, और recorded events को json format में save करने की सुविधा देता है।

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) Xcode के Developer tools का हिस्सा हैं। इनका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है।

![Crescendo - Apple Instruments: Apple Instruments, Xcode के Developer tools का हिस्सा हैं। इनका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है](<../../../images/image (1138).png>)

### fs_usage

Processes द्वारा की गई actions को देखने देता है:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) binary द्वारा उपयोग की जाने वाली **libraries**, उसके द्वारा उपयोग की जा रही **files** और **network** connections देखने के लिए उपयोगी है।\
यह binary processes को **virustotal** पर भी जांचता है और binary के बारे में जानकारी दिखाता है।

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**इस blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) में **running daemon को debug** करने का एक उदाहरण है, जो SIP disabled होने पर भी debugging रोकने के लिए **`PT_DENY_ATTACH`** का उपयोग करता था।<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` Darwin-specific `ptrace(2)` request है, जिसका value **31** (`0x1f`) है; अन्य arguments को अनदेखा किया जाता है। कोई process इसे सीधे, fork किए बिना, बाद में parent tracing से इनकार करने के लिए invoke कर सकता है।<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU की स्थिति और कॉल का क्रम

परिणाम इस बात पर निर्भर करता है कि कौन-सी `ptrace` request पहले XNU तक पहुँचती है:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB पहले attach करता है:** `debugserver` `PT_ATTACHEXC` का इस्तेमाल करता है; XNU इसे `PT_ATTACH` में बदलता है, `KAUTH_PROCESS_CANTRACE` authorization करता है और target पर `P_LTRACED` सेट करता है। इसके बाद आने वाला `PT_DENY_ATTACH` यह flag देखता है और target को `W_EXITCODE(ENOTSUP, 0)` के साथ समाप्त कर देता है। LLDB आम तौर पर इसे status **45** (`0x2d`) के रूप में दिखाता है।
- **Target पहले deny करता है:** XNU `P_LNOATTACH` सेट करता है। बाद में आने वाला attach process-tracing authorization द्वारा अस्वीकार कर दिया जाता है; attach error path `P_LNOATTACH` देखता है और attaching process को `SIGSEGV` भेजता है। LLDB में यह `debugserver` connection टूटने के रूप में दिख सकता है।

इन paths में अंतर करने के लिए, launch करने या attach करने से पहले `debugserver` logging चालू करें और उसकी `ptrace` requests देखें:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 स्थिर पहचान और bypass

गैर-obfuscated ARM64 Mach-O में, imported `_ptrace` stub ढूँढें और call sites की जाँच करें। पहला integer argument `w0` में पास किया जाता है, इसलिए यह sequence anti-debug request को सीधे उजागर करती है। Import का न होना निर्णायक नहीं है, क्योंकि code `ptrace` को dynamically resolve कर सकता है। Imported `_sysctl` भी anti-debug checks का संकेत हो सकता है, हालाँकि उसे भी dynamically resolve किया जा सकता है।<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

दिखाए गए sample में, immediate को `0x1f` से `0x0` में patch करने से request `PT_TRACE_ME` में बदल जाती है और प्रोग्राम LLDB के तहत आगे चल पाता है। यह **केवल इसी sample के लिए bypass है**, सामान्य no-op नहीं: request बदलनी है, call को skip करना है या successful return लागू करना है—यह तय करने से पहले caller के return-value checks और control flow की जाँच करें।<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** **macOS** binary **debugging** के लिए **de facto tool** है।

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

आप अपने home folder में **`.lldbinit`** नाम की फ़ाइल बनाकर और उसमें यह लाइन जोड़कर lldb का intel flavour सेट कर सकते हैं:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb के अंदर, `process save-core` से process का dump लें

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>विवरण</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Execution शुरू करें; यह breakpoint आने या process समाप्त होने तक जारी रहेगा।</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Execution शुरू करें और entry point पर रोकें।</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Debug किए जा रहे process का execution जारी रखें।</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>अगला instruction execute करें। यह command function calls को छोड़कर आगे बढ़ती है।</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>अगला instruction execute करें। <code>nexti</code> command के विपरीत, यह command function calls के अंदर जाती है।</td></tr>
<tr><td><strong>finish (f)</strong></td><td>मौजूदा function (frame) के बाकी instructions execute करें, return करें और execution रोकें।</td></tr>
<tr><td><strong>control + c</strong></td><td>Execution रोकें। यदि process चलाया (<code>r</code>) गया है या जारी रखा (<code>c</code>) गया है, तो यह उसे मौजूदा execution स्थान पर रोक देता है।</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main नाम से call किया गया कोई भी function</p>
<p><code>b &lt;binname&gt;`main</code> # Binary का main function</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # दिए गए binary का main function</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # कोई भी NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # उस library के सभी functions में रुकें</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint सूची</p>
<p><code>br e/dis &lt;num&gt;</code> # Breakpoint सक्षम/अक्षम करें</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpoint command के लिए सहायता लें</p>
<p><code>help memory write</code> # Memory में लिखने के लिए सहायता लें</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Memory को null-terminated string के रूप में दिखाएँ।</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Memory को assembly instruction के रूप में दिखाएँ।</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Memory को byte के रूप में दिखाएँ।</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>यह parameter द्वारा संदर्भित object को print करता है।</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Apple के ज़्यादातर Objective-C APIs या methods objects return करते हैं, इसलिए उन्हें “print object” (<code>po</code>) command से दिखाना चाहिए। यदि <code>po</code> से उपयोगी output न मिले, तो <code>x/b</code> का उपयोग करें।</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # उस address पर AAAA लिखें<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # उस address पर AAAA लिखें
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # मौजूदा function को disassemble करें</p>
<p><code>dis -n &lt;funcname&gt;</code> # किसी function को disassemble करें</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # किसी function को disassemble करें<br>
<code>dis -c 6</code> # छह lines disassemble करें<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # एक address से दूसरे address तक disassemble करें<br>
<code>dis -p -c 4</code> # मौजूदा address से disassemble करना शुरू करें</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> register में तीन components वाले array की जाँच करें</td></tr>
<tr><td><strong>image dump sections</strong></td><td>मौजूदा process memory का map print करें।</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP के हर symbol का address प्राप्त करें</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** function को call करते समय, **rsi** register में **method का नाम** null-terminated (“C”) string के रूप में होता है। lldb से नाम print करने के लिए:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM का पता लगाना

- **`sysctl hw.model`** command आम तौर पर physical hardware पर Mac model identifier लौटाता है और VM में अलग value लौटा सकता है।<sup>[[3]](#references)</sup>
- कुछ malware, **`hw.logicalcpu`** और **`hw.physicalcpu`** की values के साथ छेड़छाड़ करके यह पता लगाने की कोशिश करते हैं कि system VM है या नहीं।<sup>[[4]](#references)</sup>
- कुछ malware MAC address (00:50:56) के आधार पर यह भी **पता लगा सकते हैं** कि machine **VMware** पर चल रही है या नहीं।
- साधारण code से यह भी पता लगाया जा सकता है कि **किसी process को debug किया जा रहा है**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- यह **`PT_DENY_ATTACH`** flag के साथ **`ptrace`** system call भी invoke कर सकता है। इसके order-dependent XNU behavior, `debugserver` logging और ARM64 patching workflow के लिए [PT_DENY_ATTACH section](#page-title) देखें।<sup>[[7]](#references)[[12]](#references)</sup>

- यह **`PT_DENY_ATTACH`** flag के साथ **`ptrace`** system call भी invoke कर सकता है। इससे debugger को attach होने और tracing करने से **रोका** जाता है।
  - जाँच सकते हैं कि **`sysctl`** या **`ptrace`** function **import** हो रहा है या नहीं (हालाँकि malware इसे dynamically import कर सकता है)
  - इस writeup में बताया गया है, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”
#### `fork()` के ज़रिए process handoff

कोई process startup के करीब `fork()` call करके, parent को terminate करके (`fork()` positive child PID लौटाता है) और protected logic को केवल child में जारी रखकर (`fork()` `0` लौटाता है), उस debugger से बच सकता है जो original PID से जुड़ा रहता है। `dlsym(RTLD_DEFAULT, "fork")` से `fork` resolve करने पर सीधा `_fork` call site भी हट जाता है, लेकिन यह केवल anti-analysis की एक बाधा है: symbol-name string और dynamic-resolution data flow Mach-O binary में अब भी दिखते हैं।<sup>[[13]](#references)[[14]](#references)</sup>

arm64 पर, तय addresses के बजाय data flow का अनुसरण करके इस pattern का पता लगाएँ: `dlsym` के पहले दो arguments `x0` और `x1` में pass किए जाते हैं, `RTLD_DEFAULT` `-2` के रूप में दिख सकता है (उदाहरण के लिए, `movn x0, #1`), और `adrp`/`add` की जोड़ी आम तौर पर `"fork"` string का address बनाती है। `dlsym` stub पर `bl` के बाद, लौटाए गए pointer को `x0` से उसके null check और storage तक, फिर आगे के indirect `blr` तक trace करें। इसके बाद `fork()` के result को `w0` में follow करें: zero से child continuation चुना जाता है, जबकि positive और `-1` values से parent/error path चुना जाता है।<sup>[[13]](#references)[[14]](#references)</sup>

एक static bypass यह है कि indirect call को suppress करें और मौजूदा result check को child path लेने के लिए बाध्य करें। उदाहरण के लिए, यदि compiler ने नीचे दिखाया गया sequence बनाया हो, तो `blr` और result store को `nop` से patch करें, synthetic zero result दें और comparison/branch logic को बनाए रखें। इससे application child बनाए बिना original PID के अंतर्गत जारी रहती है; instruction registers और branch targets को analyzed build के अनुसार ढालना होगा।<sup>[[13]](#references)[[14]](#references)</sup>

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

Core dumps बनाए जाते हैं, यदि:

- `kern.coredump` sysctl 1 पर सेट हो (डिफ़ॉल्ट रूप से)
- यदि process suid/sgid न हो या `kern.sugid_coredump` 1 हो (डिफ़ॉल्ट रूप से 0)
- `AS_CORE` limit इस operation की अनुमति देती हो। `ulimit -c 0` चलाकर core dumps बनना रोकना और `ulimit -c unlimited` से उन्हें फिर से सक्षम करना संभव है।

इन स्थितियों में, core dumps `kern.corefile` sysctl के अनुसार बनाए जाते हैं और आमतौर पर `/cores/core/.%P` में संग्रहीत होते हैं।

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **crash होने वाली processes का विश्लेषण करता है और crash report को disk पर सहेजता है**। Crash report में ऐसी जानकारी होती है जो **developer को crash का कारण पता लगाने में मदद कर सकती है**।\
**per-user launchd context में चल रहे** applications और अन्य processes के लिए, ReportCrash LaunchAgent के रूप में चलता है और crash reports को उपयोगकर्ता की `~/Library/Logs/DiagnosticReports/` में सहेजता है।\
Daemons, **system launchd context में चल रही अन्य processes** और अन्य privileged processes के लिए, ReportCrash LaunchDaemon के रूप में चलता है और crash reports को system की `/Library/Logs/DiagnosticReports` में सहेजता है।

अगर आपको चिंता है कि crash reports **Apple को भेजी जा रही हैं**, तो आप उन्हें disable कर सकते हैं। अन्यथा, crash reports यह **पता लगाने में उपयोगी हो सकती हैं कि server कैसे crash हुआ**।

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### स्लीप

macOS पर fuzzing करते समय, Mac को स्लीप होने से रोकें:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH डिस्कनेक्ट

अगर आप SSH connection के ज़रिए fuzzing कर रहे हैं, तो यह सुनिश्चित करना ज़रूरी है कि session डिस्कनेक्ट न हो। इसलिए sshd_config फ़ाइल में ये बदलाव करें:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Internal Handlers

**यह जानने के लिए यह पेज देखें** कि **निर्दिष्ट scheme या protocol को handle करने के लिए कौन-सा app जिम्मेदार है:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Network Processes की गणना करना

यह उन processes को खोजने के लिए उपयोगी है जो network data manage कर रहे हैं:

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

### Stateful Mach IPC fuzzing

Privileged daemons द्वारा exposed Mach services उपयोगी fuzz targets हैं, जब कोई unprivileged या sandboxed client send right प्राप्त कर सकता हो। Daemon की `MachServices` launchd entry से शुरू करें और message IDs को handlers से map करने के लिए [MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) का उपयोग करें। Bytes mutate करने से पहले, जब कोई सामान्य client service का उपयोग कर रहा हो, तब MIG server routine पर break करें और valid request messages को seed inputs के रूप में सहेजें। आवश्यक header fields, message sizes और descriptor layout को बनाए रखें, ताकि mutations dispatch में तुरंत fail होने के बजाय handler तक पहुँचें।<sup>[[17]](#references)</sup>

कई handlers पिछली calls पर निर्भर करते हैं। Harness से service state initialize करवाएँ, फिर हर fuzz input को **operations plus arguments** के sequence के रूप में उपयोग करें: setup requests (जैसे open या create) भेजें, लौटाए गए identifiers को बनाए रखें और बाद की requests में उनका उपयोग करें। इससे coverage feedback बार-बार uninitialized-object check तक पहुँचने के बजाय state transitions को explore कर सकता है।<sup>[[17]](#references)</sup>

Closed-source target के लिए, MIG dispatch routine को call करने वाले in-process harness को Jackalope/TinyInst से instrument किया जा सकता है। [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) इसका एक ठोस implementation है, अन्य services के लिए drop-in harness नहीं।<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**हर crash को real IPC path से validate करें।** Direct-dispatch harness Mach messages की kernel validation को bypass करता है और false positives दे सकता है, खासकर जब वह invalid out-of-line (OOL) memory या port descriptors देता हो। Harness में valid OOL backing memory allocate करें, फिर original service access वाले client से `mach_msg` के ज़रिए reduced testcase को replay करें और verify करें कि daemon अब भी crash होता है।<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI tools के लिए काम करता है

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

यह कई macOS GUI tools के साथ "**बस काम करता है**"। कुछ applications की अतिरिक्त आवश्यकताएँ होती हैं, जैसे unique filenames, कोई खास extension, या उनकी sandbox container (`~/Library/Containers/com.apple.Safari/Data`) से files पढ़ना।

कुछ उदाहरण:

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

### macOS Fuzzing के बारे में और जानकारी

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [OS X Incident Response: Scripting और Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzz का Summer: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware की कला, Volume I: Analysis](https://taomm.org/)
- [4] [No Starch Press - Mac Malware की कला: Malicious Software का विश्लेषण करने की मार्गदर्शिका](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - इस blog post के section में संग्रहीत जानकारी](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach का उपयोग करने वाले Apple Binaries को Debug करना](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Techniques को मात देना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode structured logs और `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log में private data दिखाना](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` request परिभाषाएँ](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `mach_process.c` में `ptrace` implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace internals: यह debugger attachment को कैसे रोकता है](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork examples](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsym और fork का उपयोग करने वाली Anti-debugging technique](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Debugging tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Hardened third-party app को Debug करना](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Sound Barrier को तोड़ना, भाग I: Mach Messages के साथ CoreAudio को Fuzz करना](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
