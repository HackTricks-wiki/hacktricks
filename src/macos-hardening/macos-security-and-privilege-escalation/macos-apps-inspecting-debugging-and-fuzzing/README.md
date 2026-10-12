# macOS ऐप्स - निरीक्षण, debugging और Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## स्थैतिक विश्लेषण

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
> ध्यान दें कि **`disarm`** compressed IM4P files (जैसे `kernelcache`) के साथ भी काम कर सकता है और केवल आवश्यक हिस्से निकाल सकता है या उन्हें निकाले बिना भी आवश्यक हिस्से का विश्लेषण कर सकता है।

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
> **`Codesign`** **macOS** में मिलता है, जबकि **`ldid`** **iOS** में मिलता है।

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) **.pkg** files (installers) की जाँच करने और उन्हें install करने से पहले यह देखने के लिए उपयोगी tool है कि उनके अंदर क्या है।\
इन installers में `preinstall` और `postinstall` bash scripts होती हैं, जिनका malware authors आमतौर पर **malware** को **persist** करने के लिए दुरुपयोग करते हैं।

### hdiutil

यह tool Apple disk image (`.dmg`) files को **mount** करता है, ताकि कुछ भी run करने से पहले उनकी जाँच की जा सके:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

इसे `/Volumes` में mount किया जाएगा

### Packed binaries

- High entropy की जाँच करें
- Strings की जाँच करें (क्या लगभग कोई समझ में आने वाली string नहीं है? तो यह packed है)
- macOS के लिए UPX packer `__XHDR` नाम का section बनाता है।

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए प्रोग्राम [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) में **compile** होने पर भी अपनी class declarations **बनाए रखते हैं**। ऐसी class declarations में निम्न के नाम और प्रकार **शामिल होते हैं**:

- परिभाषित interfaces
- interface methods
- interface instance variables
- परिभाषित protocols

ध्यान दें कि binary को reverse करना अधिक कठिन बनाने के लिए इन नामों को obfuscate किया जा सकता है।

### Function calling

Objective-C का उपयोग करने वाली binary में जब किसी function को call किया जाता है, तो compiled code उस function को call करने के बजाय **`objc_msgSend`** को call करता है। यह अंतिम function को call करेगा:

![Metadata - Function calling: Objective-C का उपयोग करने वाली binary में जब किसी function को call किया जाता है, तो compiled code उस function को call करने के बजाय objc msgSend को call करता है। यह...](<../../../images/image (305).png>)

इस function को जिन params की अपेक्षा होती है, वे हैं:

- पहला parameter (**self**) "एक pointer है जो उस **class के instance की ओर इंगित करता है जिसे message प्राप्त करना है**"। आसान शब्दों में, यह वह object है जिस पर method invoke किया जा रहा है। यदि method class method है, तो यह class object (पूरे के पूरे) का instance होगा; जबकि instance method के लिए, `self` class के instantiated instance को object के रूप में इंगित करेगा।
- दूसरा parameter (**op**) "उस method का selector है जो message को handle करता है"। आसान शब्दों में, यह **method का नाम** है।
- बाकी parameters वे **values हैं जिनकी method (op) को आवश्यकता होती है**।

इस page में देखें कि **ARM64 में `lldb` के साथ यह जानकारी आसानी से कैसे प्राप्त करें**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **पहला argument** | **rdi**                                                         | **self: वह object जिस पर method invoke किया जा रहा है** |
| **दूसरा argument** | **rsi**                                                        | **op: method का नाम**                                  |
| **तीसरा argument** | **rdx**                                                        | **method का पहला argument**                            |
| **चौथा argument** | **rcx**                                                         | **method का दूसरा argument**                           |
| **पाँचवाँ argument** | **r8**                                                        | **method का तीसरा argument**                           |
| **छठा argument** | **r9**                                                          | **method का चौथा argument**                            |
| **7वाँ+ argument** | <p><strong>rsp+</strong><br><strong>(stack पर)</strong></p> | **method का 5वाँ+ argument**                           |

### ObjectiveC metadata dump करें

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

[**class-dump**](https://github.com/nygard/class-dump/) ObjetiveC formatted code में classes, categories और protocols के declarations जनरेट करने वाला मूल tool है।

यह पुराना है और इसका रखरखाव नहीं किया जाता, इसलिए संभवतः यह ठीक से काम नहीं करेगा।

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) एक आधुनिक और cross-platform Objective-C class dump है। मौजूदा tools की तुलना में, iCDump Apple ecosystem से स्वतंत्र रूप से चल सकता है और Python bindings उपलब्ध कराता है।

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Static Swift विश्लेषण

Swift binaries में, Objective-C compatibility होने के कारण, कभी-कभी [class-dump](https://github.com/nygard/class-dump/) का उपयोग करके declarations निकाले जा सकते हैं, लेकिन हमेशा नहीं।

**`jtool -l`** या **`otool -l`** command lines से **`__swift5`** prefix से शुरू होने वाले कई sections ढूँढ़ना संभव है:

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

आप [**इस section में stored information के बारे में इस blog post में और जानकारी पा सकते हैं**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)।<sup>[[5]](#references)</sup>

इसके अलावा, **Swift binaries में symbols हो सकते हैं** (उदाहरण के लिए, libraries को symbols store करने पड़ते हैं, ताकि उनके functions call किए जा सकें)। **आमतौर पर symbols में function name और attributes की जानकारी उलझे हुए रूप में होती है**, इसलिए वे बहुत उपयोगी होते हैं। ऐसे "**demanglers"** भी हैं जो original name प्राप्त कर सकते हैं:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dynamic Analysis

> [!WARNING]
> ध्यान दें कि binaries को debug करने के लिए, **SIP अक्षम होना चाहिए** (`csrutil disable` या `csrutil enable --without debug`), या binaries को किसी temporary folder में copy करके `codesign --remove-signature <binary-path>` से **signature हटाना** होगा, या binary की debugging की अनुमति देनी होगी (आप [इस script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) का उपयोग कर सकते हैं)।

> [!WARNING]
> ध्यान दें कि macOS पर **system binaries को instrument करने** (जैसे `cloudconfigurationd`) के लिए **SIP अक्षम होना चाहिए** (केवल signature हटाने से काम नहीं चलेगा)।

### APIs

macOS कुछ दिलचस्प APIs उपलब्ध कराता है, जो processes के बारे में जानकारी देते हैं:

- `proc_info`: यह मुख्य API है, जो हर process के बारे में बहुत-सी जानकारी देता है। दूसरे processes की जानकारी पाने के लिए root होना ज़रूरी है, लेकिन विशेष entitlements या mach ports की आवश्यकता नहीं होती।
- `libsysmon.dylib`: XPC functions के माध्यम से process की जानकारी देता है, लेकिन callers के पास `com.apple.sysmond.client` entitlement होना चाहिए।

### Stackshot & microstackshots

**Stackshotting** एक technique है, जिसका उपयोग processes की स्थिति—जिसमें चल रहे सभी threads के call stacks शामिल हैं—capture करने के लिए किया जाता है। यह debugging, performance analysis और किसी विशेष समय पर system के व्यवहार को समझने के लिए खास तौर पर उपयोगी है। iOS और macOS पर, stackshotting को **`sample`** और **`spindump`** जैसे tools तथा तरीकों से किया जा सकता है।

### Sysdiagnose

यह tool (`/usr/bini/ysdiagnose`) आपके computer से बहुत-सी जानकारी इकट्ठा करता है। इसके लिए यह `ps`, `zprint` जैसे दर्जनों अलग-अलग commands चलाता है।

इसे **root** के रूप में चलाना ज़रूरी है। इसके daemon `/usr/libexec/sysdiagnosed` के पास `com.apple.system-task-ports` और `get-task-allow` जैसे बेहद दिलचस्प entitlements हैं।

इसकी plist `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` में है, जिसमें 3 MachServices घोषित हैं:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp में पुराने archives हटाता है
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class के माध्यम से User mode interface। एक dict में तीन arguments पास किए जा सकते हैं (`compress`, `display`, `run`)

### Unified Logs

macOS व्यापक logs बनाता है, जो किसी application के व्यवहार का विश्लेषण करते समय उपयोगी होते हैं।

कुछ log fields में user या device की पहचान बताने वाली जानकारी छिपाने के लिए `<private>` tag होता है। पुराने निर्देशों में कभी-कभी इन fields को दिखाने के लिए certificate install करने का उल्लेख होता है; मौजूदा debugging guidance में इसके बजाय `Enable-Private-Data` वाला स्पष्ट रूप से scoped configuration profile, या प्रति-application `OSLogPreferences` का उपयोग किया जाता है। व्यवहार subsystem और macOS release के अनुसार अलग हो सकता है। पुराने certificate/profile पर चर्चा references में रखी गई है। <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Left panel

Hopper के left panel में binary के symbols (**Labels**), procedures और functions की सूची (**Proc**), और strings (**Str**) देखी जा सकती हैं। इसमें सभी strings नहीं होतीं, बल्कि Mac-O file के कई हिस्सों (जैसे _cstring या `objc_methname`) में परिभाषित strings होती हैं।

#### Middle panel

Middle panel में **disassembled code** दिखता है। संबंधित icon पर click करके इसे **raw** disassembly, **graph**, **decompiled** या **binary** रूप में देखा जा सकता है:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

किसी code object पर right-click करके आप उस object के **references to/from** देख सकते हैं, या उसका नाम बदल सकते हैं (यह decompiled pseudocode में काम नहीं करता):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

इसके अलावा, **नीचे के मध्य भाग में आप Python commands लिख सकते हैं**।

#### Right panel

Right panel में **navigation history** जैसी उपयोगी जानकारी दिखती है (ताकि पता रहे कि आप मौजूदा स्थिति तक कैसे पहुँचे), **call graph**, जिसमें वे सभी **functions दिखते हैं जो इस function को call करते हैं** और वे सभी functions जिन्हें **यह function call करता है**, और **local variables** की जानकारी।

### dtrace

यह users को applications तक बेहद **low level** पर पहुँच देता है और **programs को trace करने** तथा उनके execution flow को बदलने का तरीका भी देता है। Dtrace **probes** का उपयोग करता है, जिन्हें **kernel में जगह-जगह रखा जाता है**, जैसे system calls के शुरू और अंत में।

DTrace हर system call के लिए probe बनाने हेतु **`dtrace_probe_create`** function का उपयोग करता है। ये probes हर system call के **entry और exit points** पर fire हो सकते हैं। DTrace के साथ interaction /dev/dtrace के माध्यम से होता है, जो केवल root user के लिए उपलब्ध है।<sup>[[1]](#references)</sup>

> [!TIP]
> SIP protection को पूरी तरह अक्षम किए बिना Dtrace सक्षम करने के लिए, आप recovery mode में यह चला सकते हैं: `csrutil enable --without dtrace`
>
> आप उन binaries को **`dtrace`** या **`dtruss`** भी कर सकते हैं **जिन्हें आपने compile किया है**।

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

probe name में चार हिस्से होते हैं: provider, module, function और name (`fbt:mach_kernel:ptrace:entry`)। अगर आप name का कोई हिस्सा निर्दिष्ट नहीं करते हैं, तो DTrace उस हिस्से को wildcard मान लेगा।

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

यह एक kernel tracing facility है। इसके documented codes **`/usr/share/misc/trace.codes`** में मिल सकते हैं।

`latency`, `sc_usage`, `fs_usage` और `trace` जैसे tools इसे internally इस्तेमाल करते हैं।

`kdebug` के साथ interface करने के लिए `kern.kdebug` namespace पर `sysctl` का इस्तेमाल किया जाता है। इस्तेमाल किए जाने वाले MIBs `sys/sysctl.h` में मिल सकते हैं और इनके functions `bsd/kern/kdebug.c` में implemented हैं।

Custom client से kdebug के साथ interact करने के आम steps ये हैं:

- KERN_KDSETREMOVE से मौजूदा settings हटाएँ
- KERN_KDSETBUF और KERN_KDSETUP से trace set करें
- Buffer entries की संख्या पाने के लिए KERN_KDGETBUF का इस्तेमाल करें
- KERN_KDPINDEX से trace में अपना client पाएँ
- KERN_KDENABLE से tracing enable करें
- KERN_KDREADTR को call करके buffer पढ़ें
- हर thread को उसके process से match करने के लिए KERN_KDTHRMAP call करें।

यह जानकारी पाने के लिए Apple tool **`trace`** या custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** इस्तेमाल किया जा सकता है।

**ध्यान दें कि Kdebug एक समय में केवल 1 client के लिए उपलब्ध है।** इसलिए k-debug का इस्तेमाल करने वाला केवल एक tool एक समय में चलाया जा सकता है।

### ktrace

`ktrace_*` APIs `libktrace.dylib` से आती हैं, जो `Kdebug` की APIs को wrap करती हैं। इसके बाद, client `ktrace_session_create` और `ktrace_events_[single/class]` को call करके specific codes पर callbacks set कर सकता है और फिर `ktrace_start` से इसे start कर सकता है।

आप इसे **SIP activated** होने पर भी इस्तेमाल कर सकते हैं।

आप `ktrace` utility को client के रूप में इस्तेमाल कर सकते हैं:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

या `tailspin`।

### kperf

इसका उपयोग kernel level profiling के लिए किया जाता है और इसे `Kdebug` callouts का उपयोग करके बनाया गया है।

मूल रूप से, global variable `kernel_debug_active` की जाँच की जाती है और यदि यह सेट है, तो कॉल करने वाले kernel frame के `Kdebug` code और address के साथ `kperf_kdebug_handler` को कॉल किया जाता है। यदि `Kdebug` code चुने गए किसी code से मेल खाता है, तो उसे bitmap के रूप में कॉन्फ़िगर किए गए "actions" मिलते हैं (विकल्पों के लिए `osfmk/kperf/action.h` देखें)।

Kperf में sysctl MIB table भी है: (root के रूप में) `sysctl kperf`। यह code `osfmk/kperf/kperfbsd.c` में मिल सकता है।

इसके अलावा, Kperf की कुछ कार्यक्षमता `kpc` में मौजूद है, जो machine performance counters के बारे में जानकारी देता है।

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) यह जाँचने का बहुत उपयोगी tool है कि कोई process कौन-सी process-related कार्रवाइयाँ कर रहा है (उदाहरण के लिए, यह monitor करना कि कोई process कौन-सी नई processes बना रहा है)।

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) एक ऐसा tool है जो processes के बीच संबंध दिखाता है।\
आपको **`sudo eslogger fork exec rename create > cap.json`** जैसे command से अपने Mac को monitor करना होगा (इसे launch करने वाले terminal को FDA की आवश्यकता है)। फिर आप सभी संबंध देखने के लिए json को इस tool में load कर सकते हैं:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) file events जैसे creation, modification और deletion को monitor करता है।

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) एक GUI tool है, जिसका look and feel Windows users को Microsoft Sysinternal के _Procmon_ जैसा लग सकता है। यह tool विभिन्न event types की recording शुरू और बंद करने की सुविधा देता है, साथ ही file, process, network आदि जैसी categories के आधार पर इन events को filter करने देता है। यह रिकॉर्ड किए गए events को json format में save करने की सुविधा भी देता है।

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) Xcode के Developer tools का हिस्सा है—इसका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है।

![Crescendo - Apple Instruments: Apple Instruments Xcode के Developer tools का हिस्सा है—इसका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है](<../../../images/image (1138).png>)

### fs_usage

Processes द्वारा की गई कार्रवाइयों को follow करने देता है:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) किसी binary द्वारा उपयोग की जाने वाली **libraries**, उपयोग की जा रही **files** और **network** connections देखने के लिए उपयोगी है।\
यह binary processes को **virustotal** पर भी जाँचता है और binary के बारे में जानकारी दिखाता है।

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**इस blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) में आप **`PT_DENY_ATTACH`** का उपयोग करने वाले **running daemon को debug** करने का एक उदाहरण पा सकते हैं, ताकि SIP disabled होने पर भी debugging रोकी जा सके।<sup>[[6]](#references)</sup>

### lldb

**lldb** macOS binary **debugging** के लिए **de facto tool** है।

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

आप अपने होम फ़ोल्डर में **`.lldbinit`** नाम की फ़ाइल बनाकर और उसमें निम्न पंक्ति जोड़कर, lldb का उपयोग करते समय intel flavour सेट कर सकते हैं:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb के अंदर, `process save-core` से process का dump लें

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>विवरण</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>एक्ज़ीक्यूशन शुरू करें; यह तब तक जारी रहेगा जब तक breakpoint नहीं आता या process terminate नहीं होता।</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>एक्ज़ीक्यूशन शुरू करें और entry point पर रुकें।</td></tr>
<tr><td><strong>continue (c)</strong></td><td>debug किए जा रहे process का एक्ज़ीक्यूशन जारी रखें।</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>अगला instruction एक्ज़ीक्यूट करें। यह command function calls को छोड़कर आगे बढ़ती है।</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>अगला instruction एक्ज़ीक्यूट करें। <code>nexti</code> command के विपरीत, यह command function calls के अंदर जाती है।</td></tr>
<tr><td><strong>finish (f)</strong></td><td>मौजूदा function (frame) के बाकी instructions एक्ज़ीक्यूट करें, उससे return करें और रुक जाएँ।</td></tr>
<tr><td><strong>control + c</strong></td><td>एक्ज़ीक्यूशन रोकें। यदि process को चलाया (<code>r</code>) या जारी रखा (<code>c</code>) गया है, तो यह उसे मौजूदा execution point पर रोक देता है।</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main नाम वाले किसी भी function पर</p>
<p><code>b &lt;binname&gt;`main</code> # binary के main function पर</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # निर्दिष्ट binary के main function पर</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # किसी भी NSFileManager method पर</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # उस library के सभी functions पर breakpoint लगाएँ</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint सूची</p>
<p><code>br e/dis &lt;num&gt;</code> # Breakpoint को सक्षम/अक्षम करें</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # breakpoint command के लिए help लें</p>
<p><code>help memory write</code> # memory में लिखने के लिए help लें</p>
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
<p>यह parameter द्वारा refer किए गए object को print करता है।</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
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
<code>dis -p -c 4</code> # मौजूदा address से disassembly शुरू करें</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> register में तीन components वाले array की जाँच करें</td></tr>
<tr><td><strong>image dump sections</strong></td><td>मौजूदा process memory का map print करें।</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # CoreNLP के हर symbol का address प्राप्त करें</td></tr>
</tbody>
</table>

> [!TIP]
> **`objc_sendMsg`** function को call करते समय, **rsi** register में null-terminated (“C”) string के रूप में **method का नाम** होता है। lldb के ज़रिए नाम print करने के लिए:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- **`sysctl hw.model`** command आम तौर पर physical hardware पर Mac model identifier लौटाता है और VM में अलग value लौटा सकता है।<sup>[[3]](#references)</sup>
- **`hw.logicalcpu`** और **`hw.physicalcpu`** की values के साथ छेड़छाड़ करके, कुछ malware यह पता लगाने की कोशिश करते हैं कि system VM है या नहीं।<sup>[[4]](#references)</sup>
- कुछ malware MAC address (00:50:56) के आधार पर यह **detect** भी कर सकते हैं कि machine **VMware** पर चल रही है या नहीं।
- यह पता लगाना भी संभव है कि **किसी process को debug किया जा रहा है या नहीं**, इसके लिए साधारण code इस्तेमाल किया जा सकता है:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- यह **`PT_DENY_ATTACH`** flag के साथ **`ptrace`** system call भी invoke कर सकता है। इससे deb**u**gger को attach करने और trace करने से **रोक दिया जाता है**।
  - जाँचें कि **`sysctl`** या **`ptrace`** function **import** हो रहा है या नहीं (हालाँकि malware इसे dynamically import कर सकता है)
  - जैसा कि इस writeup में बताया गया है, “[Anti-Debug Techniques को हराना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_संदेश Process # exited with **status = 45 (0x0000002d)** आम तौर पर इस बात का स्पष्ट संकेत होता है कि debug target **PT_DENY_ATTACH** का इस्तेमाल कर रहा है_”

#### `fork()` process handoff

कोई process startup के पास `fork()` call करके, parent को terminate करके (`fork()` positive child PID लौटाता है) और protected logic को केवल child में जारी रखकर (`fork()` `0` लौटाता है), उस debugger से बच सकता है जो original PID से जुड़ा रहता है। `dlsym(RTLD_DEFAULT, "fork")` से `fork` resolve करने पर direct `_fork` call site भी हट जाता है, लेकिन यह केवल anti-analysis की बाधा है: symbol-name string और dynamic-resolution data flow Mach-O binary में फिर भी दिखाई देते हैं।<sup>[[10]](#references)[[11]](#references)</sup>

arm64 पर, fixed addresses के बजाय data flow को follow करके इस pattern को detect करें: `dlsym` के पहले दो arguments `x0` और `x1` में pass होते हैं, `RTLD_DEFAULT` `-2` के रूप में दिख सकता है (उदाहरण के लिए, `movn x0, #1`), और `adrp`/`add` की जोड़ी आम तौर पर `"fork"` string का address बनाती है। `dlsym` stub के `bl` के बाद, लौटाए गए pointer को `x0` से लेकर उसके null check और storage तक, फिर बाद के indirect `blr` तक trace करें। इसके बाद `w0` में `fork()` के result को follow करें: zero child continuation चुनता है, जबकि positive और `-1` values parent/error path चुनती हैं।<sup>[[10]](#references)[[11]](#references)</sup>

एक static bypass यह है कि indirect call को suppress करके मौजूदा result check को child path चुनने के लिए मजबूर किया जाए। उदाहरण के लिए, यदि compiler ने नीचे दिखाया गया sequence बनाया हो, तो `blr` और result store को `nop` से patch करें, synthetic zero result दें और comparison/branch logic को बनाए रखें। इसके बाद application child बनाए बिना original PID के तहत जारी रहती है; instruction registers और branch targets को analyzed build के अनुसार अनुकूलित करना होगा।<sup>[[10]](#references)[[11]](#references)</sup>

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

Core dumps बनाए जाते हैं यदि:

- `kern.coredump` sysctl 1 पर सेट हो (डिफ़ॉल्ट रूप से)
- यदि process suid/sgid नहीं था या `kern.sugid_coredump` 1 पर हो (डिफ़ॉल्ट रूप से 0)
- `AS_CORE` limit इस operation की अनुमति देता हो। `ulimit -c 0` call करके core dumps का निर्माण रोका जा सकता है और `ulimit -c unlimited` से उन्हें फिर से सक्षम किया जा सकता है।

इन मामलों में core dumps, `kern.corefile` sysctl के अनुसार generate होते हैं और आमतौर पर `/cores/core/.%P` में store किए जाते हैं।

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **crashing processes का विश्लेषण करता है और crash report को disk पर save करता है**। Crash report में ऐसी जानकारी होती है जो crash का कारण diagnose करने में **developer की मदद कर सकती है**।\
Applications और अन्य processes के लिए जो **per-user launchd context में चल रहे हैं**, ReportCrash LaunchAgent के रूप में चलता है और crash reports को user के `~/Library/Logs/DiagnosticReports/` में save करता है\
Daemons, अन्य processes जो **system launchd context में चल रहे हैं**, और अन्य privileged processes के लिए, ReportCrash LaunchDaemon के रूप में चलता है और crash reports को system के `/Library/Logs/DiagnosticReports` में save करता है

यदि आपको crash reports के **Apple को भेजे जाने** की चिंता है, तो आप उन्हें disable कर सकते हैं। अन्यथा, crash reports यह **पता लगाने में उपयोगी हो सकती हैं कि server कैसे crash हुआ**।

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

अगर आप SSH कनेक्शन के ज़रिए fuzzing कर रहे हैं, तो यह सुनिश्चित करना ज़रूरी है कि आपका session डिस्कनेक्ट न हो। इसलिए sshd_config फ़ाइल में ये बदलाव करें:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### आंतरिक हैंडलर

**यह जानने के लिए निम्न पेज देखें** कि निर्दिष्ट scheme या protocol को **handle करने के लिए कौन-सा app ज़िम्मेदार है:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Network Processes की गणना

यह उन processes को खोजने के लिए उपयोगी है जो network data को manage कर रहे हैं:

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

यह कई macOS GUI tools के साथ "**बस काम करता है**"। कुछ applications की अतिरिक्त आवश्यकताएँ होती हैं, जैसे unique filenames, कोई खास extension, या उनके sandbox container (`~/Library/Containers/com.apple.Safari/Data`) से files पढ़ना।

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

### macOS Fuzzing के बारे में अधिक जानकारी

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X Incident Response: Scripting और Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Fuzz का ग्रीष्मकाल: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Mac Malware की कला, Volume I: Analysis](https://taomm.org/)
- [4] [No Starch Press - Mac Malware की कला: दुर्भावनापूर्ण Software का विश्लेषण करने की मार्गदर्शिका](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - इस blog post के sections में संग्रहीत जानकारी](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach का उपयोग करने वाले Apple Binaries की Debugging](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Techniques को निष्प्रभावी करना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode structured logs और `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log में private data दिखाना](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - fork के उदाहरण](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - dlsym और fork का उपयोग करने वाली Anti-debugging technique](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
