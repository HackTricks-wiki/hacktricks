# macOS Apps - निरीक्षण, debugging और Fuzzing

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

### Disarm (पुराना jtool2)

आप [**यहाँ से disarm डाउनलोड कर सकते हैं**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> ध्यान दें कि **`disarm`** compressed IM4P files (जैसे `kernelcache`) के साथ भी काम कर सकता है और केवल ज़रूरी हिस्से निकाल सकता है, या उन्हें निकाले बिना भी ज़रूरी हिस्से का विश्लेषण कर सकता है।

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) एक ऐसा tool है जो **.pkg** files (installers) का निरीक्षण करने और उन्हें install करने से पहले उनकी सामग्री देखने में उपयोगी है।\
इन installers में `preinstall` और `postinstall` bash scripts होते हैं, जिनका malware authors आमतौर पर **malware** को **persist** करने के लिए दुरुपयोग करते हैं।

### hdiutil

यह tool Apple disk image (`.dmg`) files को **mounts** करता है, ताकि कुछ भी run करने से पहले उनका निरीक्षण किया जा सके:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

इसे `/Volumes` में माउंट किया जाएगा

### Packed binaries

- High entropy की जाँच करें
- Strings की जाँच करें (अगर लगभग कोई समझ में आने वाली string नहीं है, तो binary packed है)
- macOS के लिए UPX packer `__XHDR` नाम का section बनाता है।

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए प्रोग्राम [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) में **compile** किए जाने पर अपनी class declarations को **बनाए रखते हैं**। ऐसी class declarations में ये नाम और प्रकार **शामिल होते हैं**:

- परिभाषित interfaces
- interface methods
- interface instance variables
- परिभाषित protocols

ध्यान दें कि binary को reverse करना अधिक कठिन बनाने के लिए इन नामों को obfuscate किया जा सकता है।

### Function calling

Objective-C का उपयोग करने वाली binary में जब कोई function call किया जाता है, तो compiled code उस function को call करने के बजाय **`objc_msgSend`** को call करता है। यह अंतिम function को call करेगा:

![Metadata - Function calling: जब Objective-C का उपयोग करने वाली binary में कोई function call किया जाता है, तो compiled code उस function को call करने के बजाय objc_msgSend को call करता है। यह...](<../../../images/image (305).png>)

इस function के लिए आवश्यक params हैं:

- पहला parameter (**self**) "एक pointer है, जो **उस class के instance की ओर point करता है जिसे message प्राप्त करना है**"। सरल शब्दों में, यह वह object है जिस पर method invoke किया जा रहा है। अगर method class method है, तो यह class object (पूरी class) का instance होगा; जबकि instance method के लिए, self class के instantiated instance को object के रूप में point करेगा।
- दूसरा parameter, (**op**), "उस method का selector है जो message को handle करता है"। सरल शब्दों में, यह बस **method का नाम** है।
- बाकी के parameters, method (op) के लिए आवश्यक कोई भी **values** होते हैं।

इस पेज पर देखें कि **ARM64 में `lldb` के साथ यह जानकारी आसानी से कैसे प्राप्त करें**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: वह object जिस पर method invoke किया जा रहा है** |
| **2nd argument**  | **rsi**                                                         | **op: method का नाम**                             |
| **3rd argument**  | **rdx**                                                         | **method का 1st argument**                         |
| **4th argument**  | **rcx**                                                         | **method का 2nd argument**                         |
| **5th argument**  | **r8**                                                          | **method का 3rd argument**                         |
| **6th argument**  | **r9**                                                          | **method का 4th argument**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **method का 5th+ argument**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) Objective-C binaries को class-dump करने वाला एक tool है। GitHub पर dylibs का उल्लेख है, लेकिन यह executables के साथ भी काम करता है।

```bash
./dynadump dump /path/to/bin
```

लेखन के समय, **वर्तमान में यही सबसे अच्छा काम करता है**।

#### सामान्य टूल्स

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ObjectiveC फ़ॉर्मेटेड code में classes, categories और protocols के declarations जनरेट करने वाला मूल tool है।

यह पुराना और unmaintained है, इसलिए शायद ठीक से काम न करे।

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) एक आधुनिक और cross-platform Objective-C class dump tool है। मौजूदा tools की तुलना में, iCDump Apple ecosystem से स्वतंत्र रूप से चल सकता है और Python bindings उपलब्ध कराता है।

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Static Swift analysis

Swift binaries में, Objective-C compatibility होने के कारण, कभी-कभी [class-dump](https://github.com/nygard/class-dump/) का उपयोग करके declarations निकाली जा सकती हैं, लेकिन हमेशा नहीं।

**`jtool -l`** या **`otool -l`** command lines से **`__swift5`** prefix से शुरू होने वाले कई sections ढूँढ़े जा सकते हैं:

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

आप इन section में **संग्रहीत जानकारी के बारे में अधिक जानकारी इस blog post में पा सकते हैं**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)।<sup>[[5]](#references)</sup>

इसके अलावा, **Swift binaries में symbols हो सकते हैं** (उदाहरण के लिए, libraries को symbols संग्रहीत करने की ज़रूरत होती है ताकि उनके functions को call किया जा सके)। **आमतौर पर symbols में function name और attributes की जानकारी खराब तरीके से लिखी होती है**, इसलिए वे बहुत उपयोगी हैं और ऐसे "**demanglers"** मौजूद हैं जो मूल name प्राप्त कर सकते हैं:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dynamic Analysis

> [!WARNING]
> **डिफ़ॉल्ट debugging चरण के रूप में SIP को अक्षम न करें।** `com.apple.security.get-task-allow` वाले Development builds को SIP सक्षम रहते हुए debug किया जा सकता है। LLDB आज़माने से पहले `codesign -d --entitlements :- /path/to/binary` से target जाँचें। केवल debugger entitlement होने से SIP-संरक्षित targets तक पहुँच नहीं मिलती।<sup>[[15]](#references)</sup>
>
> Hardened runtime वाला वितरित app आमतौर पर `get-task-allow` को शामिल नहीं करता और attachment को रोकता है। संभव हो तो developer द्वारा दिया गया debug build इस्तेमाल करें; किसी अस्थायी copy को फिर से sign करने से जाँचे जा रहे व्यवहार में बदलाव आ सकता है। अगर किसी संरक्षित target के लिए SIP अक्षम करना ज़रूरी हो, तो उस मशीन के बजाय एक अलग test machine या VM इस्तेमाल करें जिस पर आप निर्भर हैं।<sup>[[16]](#references)</sup>
>
> किसी अलग-थलग test environment में संरक्षित target के लिए पहले दिए गए निर्देशों में ये विकल्प शामिल थे:
>
> ध्यान दें कि binaries को debug करने के लिए SIP अक्षम होना चाहिए (`csrutil disable` या `csrutil enable --without debug`), या binaries को किसी अस्थायी folder में copy करके `codesign --remove-signature <binary-path>` से उनका signature हटाना चाहिए, या binary की debugging की अनुमति देनी चाहिए (आप [इस script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) का उपयोग कर सकते हैं)
>
> SIP के लिए यह कोई सामान्य आवश्यकता नहीं है: debug build को प्राथमिकता दें, और ध्यान रखें कि किसी signature को copy या बदलने से जाँचे जा रहे व्यवहार में बदलाव आ सकता है।

> [!WARNING]
> ध्यान दें कि macOS पर **system binaries को instrument करने** (जैसे `cloudconfigurationd`) के लिए **SIP अक्षम होना चाहिए** (केवल signature हटाने से काम नहीं चलेगा)।

### APIs

macOS कुछ दिलचस्प APIs उपलब्ध कराता है जो processes के बारे में जानकारी देते हैं:

- `proc_info`: यह मुख्य API है, जो हर process के बारे में बहुत-सी जानकारी देता है। दूसरे processes की जानकारी पाने के लिए root होना ज़रूरी है, लेकिन special entitlements या mach ports की ज़रूरत नहीं होती।
- `libsysmon.dylib`: XPC functions के ज़रिए process की जानकारी उपलब्ध कराता है, लेकिन callers के पास `com.apple.sysmond.client` entitlement होना चाहिए।

### Stackshot & microstackshots

**Stackshotting** एक ऐसी तकनीक है जिसका उपयोग processes की स्थिति कैप्चर करने के लिए किया जाता है, जिसमें चल रहे सभी threads के call stacks भी शामिल होते हैं। यह किसी खास समय पर debugging, performance analysis और system के व्यवहार को समझने के लिए विशेष रूप से उपयोगी है। iOS और macOS पर stackshotting, **`sample`** और **`spindump`** जैसे tools और तरीकों से किया जा सकता है।

### Sysdiagnose

यह tool (`/usr/bini/ysdiagnose`) मूल रूप से आपके computer से बहुत-सी जानकारी इकट्ठा करता है और `ps`, `zprint` जैसे दर्जनों अलग-अलग commands चलाता है...

इसे **root** के रूप में चलाना ज़रूरी है और daemon `/usr/libexec/sysdiagnosed` के पास `com.apple.system-task-ports` और `get-task-allow` जैसे बहुत दिलचस्प entitlements हैं।

इसकी plist `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` में मौजूद है, जो 3 MachServices घोषित करती है:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp में पुराने archives हटाता है
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C class के ज़रिए user mode interface। एक dict में तीन arguments दिए जा सकते हैं (`compress`, `display`, `run`)

### Unified Logs

macOS व्यापक logs बनाता है, जो किसी application के व्यवहार का विश्लेषण करते समय उपयोगी होते हैं।

कुछ log fields में user या device की पहचान बताने वाली जानकारी छिपाने के लिए `<private>` tag होता है। पुराने निर्देशों में कभी-कभी इन fields को दिखाने के लिए certificate install करने की बात होती है; मौजूदा debugging guidance में इसके बजाय स्पष्ट रूप से scoped configuration profile के साथ `Enable-Private-Data`, या per-application `OSLogPreferences` इस्तेमाल किए जाते हैं, और व्यवहार subsystem तथा macOS release के अनुसार अलग हो सकता है। पुराने certificate/profile से जुड़ी चर्चा references में रखी गई है। <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### बायाँ panel

Hopper के बाएँ panel में binary के symbols (**Labels**), procedures और functions की सूची (**Proc**) तथा strings (**Str**) देखी जा सकती हैं। इसमें सभी strings नहीं होतीं, बल्कि Mac-O file के कई हिस्सों (जैसे _cstring या `objc_methname`) में परिभाषित strings होती हैं।

#### बीच का panel

बीच के panel में **disassembled code** देखा जा सकता है। संबंधित icon पर click करके इसे **raw** disassembly, **graph**, **decompiled** या **binary** रूप में देखा जा सकता है:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

किसी code object पर right-click करने से आप उस object के **references to/from** देख सकते हैं या उसका नाम बदल सकते हैं (यह decompiled pseudocode में काम नहीं करता):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

इसके अलावा, **बीच के panel के निचले हिस्से में आप Python commands लिख सकते हैं**।

#### दायाँ panel

दाएँ panel में navigation history जैसी उपयोगी जानकारी दिखती है (जिससे पता चलता है कि आप मौजूदा स्थिति तक कैसे पहुँचे), **call graph**, जिसमें वे सभी **functions दिखते हैं जो इस function को call करते हैं** और वे सभी functions **जिन्हें यह function call करता है**, तथा **local variables** की जानकारी।

### dtrace

यह users को applications तक बेहद **low level** पर पहुँचने देता है और users को **programs trace** करने, यहाँ तक कि उनका execution flow बदलने का तरीका भी देता है। Dtrace **probes** का उपयोग करता है, जिन्हें **kernel में अलग-अलग जगहों पर रखा जाता है**, जैसे system calls की शुरुआत और अंत में।

DTrace हर system call के लिए probe बनाने हेतु **`dtrace_probe_create`** function का उपयोग करता है। ये probes हर system call के **entry और exit point** पर fire हो सकते हैं। DTrace के साथ interaction /dev/dtrace के ज़रिए होता है, जो केवल root user के लिए उपलब्ध है।<sup>[[1]](#references)</sup>

> [!TIP]
> SIP protection को पूरी तरह अक्षम किए बिना Dtrace सक्षम करने के लिए आप recovery mode में यह चला सकते हैं: `csrutil enable --without dtrace`
>
> आप उन binaries पर भी **`dtrace`** या **`dtruss`** चला सकते हैं **जिन्हें आपने compile किया है**।

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

probe name में चार भाग होते हैं: provider, module, function और name (`fbt:mach_kernel:ptrace:entry`)। अगर आप name के किसी भाग को निर्दिष्ट नहीं करते हैं, तो DTrace उस भाग को wildcard के रूप में लागू करेगा।

DTrace को probes activate करने और उनके fire होने पर किए जाने वाले actions निर्दिष्ट करने के लिए, हमें D language का उपयोग करना होगा।

अधिक विस्तृत स्पष्टीकरण और अतिरिक्त उदाहरण [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) में मिल सकते हैं।

#### उदाहरण

**उपलब्ध DTrace scripts** की सूची देखने के लिए `man -k dtrace` चलाएँ। उदाहरण: `sudo dtruss -n binary`

- इन लाइन में

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

`latency`, `sc_usage`, `fs_usage` और `trace` जैसे tools इसे internally इस्तेमाल करते हैं।

`kdebug` के साथ interface करने के लिए `kern.kdebug` namespace के ज़रिए `sysctl` का इस्तेमाल किया जाता है। इस्तेमाल किए जाने वाले MIBs `sys/sysctl.h` में मिल सकते हैं और इनके functions `bsd/kern/kdebug.c` में implemented हैं।

Custom client से kdebug के साथ interact करने के आम तौर पर ये steps होते हैं:

- KERN_KDSETREMOVE का इस्तेमाल करके मौजूदा settings हटाएँ
- KERN_KDSETBUF और KERN_KDSETUP का इस्तेमाल करके trace सेट करें
- Buffer entries की संख्या पाने के लिए KERN_KDGETBUF का इस्तेमाल करें
- KERN_KDPINDEX का इस्तेमाल करके trace से अपने client की जानकारी निकालें
- KERN_KDENABLE का इस्तेमाल करके tracing enable करें
- KERN_KDREADTR को call करके buffer पढ़ें
- हर thread को उसके process से match करने के लिए KERN_KDTHRMAP call करें।

यह जानकारी पाने के लिए Apple tool **`trace`** या custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** का इस्तेमाल किया जा सकता है।

**ध्यान दें कि Kdebug एक समय में केवल 1 ग्राहक के लिए उपलब्ध है।** इसलिए k-debug पर आधारित केवल एक tool ही एक समय में चलाया जा सकता है।

### ktrace

`ktrace_*` APIs `libktrace.dylib` से आते हैं, जो `Kdebug` के APIs को wrap करते हैं। इसके बाद, client `ktrace_session_create` और `ktrace_events_[single/class]` को call करके विशिष्ट codes पर callbacks सेट कर सकता है और फिर `ktrace_start` से इसे शुरू कर सकता है।

आप इसे **SIP enabled** होने पर भी इस्तेमाल कर सकते हैं।

आप `ktrace` utility को client के रूप में इस्तेमाल कर सकते हैं:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

या `tailspin`।

### kperf

इसका उपयोग kernel-level profiling के लिए किया जाता है और इसे `Kdebug` callouts की मदद से बनाया गया है।

मूल रूप से, global variable `kernel_debug_active` की जाँच की जाती है। इसके set होने पर, यह `Kdebug` code और कॉल करने वाले kernel frame के address के साथ `kperf_kdebug_handler` को call करता है। अगर `Kdebug` code चुने गए code में से किसी एक से मेल खाता है, तो उसे bitmap के रूप में configure किए गए "actions" मिलते हैं (विकल्पों के लिए `osfmk/kperf/action.h` देखें)।

Kperf में एक sysctl MIB table भी है: (root के रूप में) `sysctl kperf`। यह code `osfmk/kperf/kperfbsd.c` में मिल सकता है।

इसके अलावा, Kperf की कुछ functionality `kpc` में मौजूद है, जो machine performance counters की जानकारी देता है।

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) यह जाँचने के लिए बहुत उपयोगी tool है कि कोई process कौन-सी process-related actions कर रहा है (उदाहरण के लिए, यह monitor करना कि कोई process कौन-से नए processes बना रहा है)।

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) एक ऐसा tool है जो processes के बीच संबंध दिखाता है।\
आपको अपने Mac को इस तरह की command से monitor करना होगा: **`sudo eslogger fork exec rename create > cap.json`** (इसे launch करने वाले terminal को FDA की आवश्यकता है)। फिर आप सभी संबंध देखने के लिए इस tool में JSON load कर सकते हैं:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) file events, जैसे creation, modification और deletion, को monitor करता है।

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) एक GUI tool है, जिसका look and feel Windows users को Microsoft Sysinternal के _Procmon_ जैसा लग सकता है। यह tool विभिन्न event types की recording शुरू और बंद करने देता है, file, process, network जैसी categories के आधार पर इन events को filter करने देता है, और record किए गए events को JSON format में save करने की सुविधा देता है।

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) Xcode के Developer tools का हिस्सा है। इसका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है।

![Crescendo - Apple Instruments: Apple Instruments, Xcode के Developer tools का हिस्सा है। इसका उपयोग application performance monitor करने, memory leaks की पहचान करने और filesystem activity track करने के लिए किया जाता है](<../../../images/image (1138).png>)

### fs_usage

Processes द्वारा की जाने वाली actions को follow करने देता है:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) binary द्वारा इस्तेमाल की जाने वाली **libraries**, उसके द्वारा इस्तेमाल की जाने वाली **files** और **network** connections देखने के लिए उपयोगी है।\
यह binary processes को **virustotal** के विरुद्ध भी जाँचता है और binary के बारे में जानकारी दिखाता है।

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**इस blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) में आपको एक ऐसे **running daemon को debug** करने का उदाहरण मिलेगा जिसने SIP disabled होने पर भी debugging रोकने के लिए **`PT_DENY_ATTACH`** का उपयोग किया था।<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` एक Darwin-specific `ptrace(2)` request है, जिसकी value **31** (`0x1f`) है; अन्य arguments को अनदेखा किया जाता है। कोई process इसे सीधे, fork किए बिना, invoke करके बाद में होने वाली parent tracing को अस्वीकार कर सकता है।<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU की स्थिति और कॉल का क्रम

नतीजा इस बात पर निर्भर करता है कि कौन-सी `ptrace` request पहले XNU तक पहुँचती है:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB पहले attach करता है:** `debugserver`, `PT_ATTACHEXC` का उपयोग करता है; XNU इसे `PT_ATTACH` में बदलता है, `KAUTH_PROCESS_CANTRACE` authorization करता है और target पर `P_LTRACED` सेट करता है। इसके बाद आने वाला `PT_DENY_ATTACH` उस flag को देखता है और target को `W_EXITCODE(ENOTSUP, 0)` के साथ terminate कर देता है। LLDB आम तौर पर इसे status **45** (`0x2d`) के रूप में दिखाता है।
- **Target पहले deny करता है:** XNU `P_LNOATTACH` सेट करता है। बाद में होने वाला attach, process-tracing authorization द्वारा अस्वीकार कर दिया जाता है; attach error path को `P_LNOATTACH` दिखता है और वह attaching process को `SIGSEGV` भेजता है, जो LLDB में `debugserver` connection टूटने के रूप में दिख सकता है।

इन paths में अंतर पहचानने के लिए, launch या attach करने से पहले `debugserver` logging चालू करें और उसकी `ptrace` requests की जाँच करें:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 का static identification और bypass

एक non-obfuscated ARM64 Mach-O के लिए, imported `_ptrace` stub खोजें और call sites की जाँच करें। पहला integer argument `w0` में पास किया जाता है, इसलिए यह sequence anti-debug request को सीधे उजागर करता है। Import का न होना निर्णायक नहीं है, क्योंकि code `ptrace` को dynamically resolve कर सकता है। Imported `_sysctl` भी anti-debug checks का संकेत हो सकता है, हालाँकि इसे भी dynamically resolve किया जा सकता है।<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

दिखाए गए sample में, immediate को `0x1f` से `0x0` में patch करने से request `PT_TRACE_ME` में बदल जाती है और प्रोग्राम LLDB के तहत जारी रह पाता है। यह **केवल इस sample के लिए विशिष्ट bypass** है, कोई सामान्य no-op नहीं: request बदलने, call छोड़ने या successful return को force करने का निर्णय लेने से पहले caller के return-value checks और control flow का निरीक्षण करें।<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** **macOS** बाइनरी **डिबगिंग** के लिए **वास्तविक मानक टूल** है।

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

आप अपने home folder में **`.lldbinit`** नाम की फ़ाइल बनाकर, lldb का उपयोग करते समय intel flavour सेट कर सकते हैं। इसमें यह पंक्ति लिखें:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> lldb के अंदर, `process save-core` से किसी process का dump लें

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>विवरण</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Execution शुरू करें। यह तब तक जारी रहेगा जब तक कोई breakpoint hit न हो या process terminate न हो जाए।</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Execution शुरू करें और entry point पर रुकें।</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Debug किए जा रहे process का execution जारी रखें।</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>अगला instruction execute करें। यह command function calls को skip करती है।</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>अगला instruction execute करें। <code>nexti</code> command के विपरीत, यह command function calls के अंदर जाती है।</td></tr>
<tr><td><strong>finish (f)</strong></td><td>मौजूदा function (frame) के बाकी instructions execute करें, उससे return करें और रुक जाएँ।</td></tr>
<tr><td><strong>control + c</strong></td><td>Execution रोकें। यदि process चलाया (<code>r</code>) या जारी रखा (<code>c</code>) गया है, तो यह उसे वहीं रोक देता है जहाँ वह अभी execute हो रहा है।</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # main नाम से बुलाया गया कोई भी function</p>
<p><code>b &lt;binname&gt;`main</code> # Binary का main function</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # बताई गई binary का main function</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # कोई भी NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # उस library के सभी functions में break करें</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint सूची</p>
<p><code>br e/dis &lt;num&gt;</code> # Breakpoint enable/disable करें</p>
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
<p>Apple के ज़्यादातर Objective-C APIs या methods objects लौटाते हैं, इसलिए उन्हें “print object” (<code>po</code>) command से दिखाना चाहिए। यदि <code>po</code> से उपयोगी output न मिले, तो <code>x/b</code> का उपयोग करें।</p>
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
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # <code>x1</code> register में मौजूद तीन components वाले array का निरीक्षण करें</td></tr>
<tr><td><strong>image dump sections</strong></td><td>मौजूदा process memory का नक्शा print करें।</td></tr>
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

### डायनेमिक विश्लेषण-रोधी तरीके

#### VM पहचान

- **`sysctl hw.model`** command आम तौर पर physical hardware पर Mac model identifier लौटाता है और VM में कोई अलग value लौटा सकता है।<sup>[[3]](#references)</sup>
- **`hw.logicalcpu`** और **`hw.physicalcpu`** की values के साथ छेड़छाड़ करके कुछ malwares यह पता लगाने की कोशिश करते हैं कि वे VM में चल रहे हैं या नहीं।<sup>[[4]](#references)</sup>
- अगला stage unpack करने से पहले, VM की जाँच करते समय loader `sysctl` के ज़रिए `kern.hv_vmm_present` और `machdep.cpu.brand_string` को भी query कर सकता है। ये checks नीचे बताए गए debugger-attachment check के पूरक हैं, उसका विकल्प नहीं।<sup>[[20]](#references)</sup>
- कुछ malwares MAC address (00:50:56) के आधार पर यह भी **पता लगा सकते हैं** कि machine **VMware** पर आधारित है या नहीं।
- इस तरह के सरल code से यह भी पता लगाया जा सकता है कि **किसी process को debug किया जा रहा है या नहीं**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- यह `PT_DENY_ATTACH` flag के साथ `ptrace` system call भी invoke कर सकता है। इससे debugger को attach होकर tracing करने से रोका जाता है। इसके order-dependent XNU behavior, `debugserver` logging और ARM64 patching workflow के लिए [PT_DENY_ATTACH section](#page-title) देखें।<sup>[[7]](#references)[[12]](#references)</sup>
- यह **`PT_DENY_ATTACH`** flag के साथ **`ptrace`** system call भी invoke कर सकता है। इसके order-dependent XNU behavior, `debugserver` logging और ARM64 patching workflow के लिए [PT_DENY_ATTACH section](#page-title) देखें।<sup>[[7]](#references)[[12]](#references)</sup>
  - आप जाँच सकते हैं कि **`sysctl`** या **`ptrace`** function **import** हो रहा है या नहीं (लेकिन malware इसे dynamically import कर सकता है)
  - इस writeup में बताया गया है, “[Anti-Debug तकनीकों को विफल करना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Process # exited with **status = 45 (0x0000002d)** संदेश आम तौर पर इस बात का स्पष्ट संकेत होता है कि debug target **PT_DENY_ATTACH** का उपयोग कर रहा है_”
#### `fork()` process handoff

`fork()` call करके कोई process उस debugger से बच सकता है जो मूल PID से attached रहता है: यह startup के करीब `fork()` call करता है, parent को terminate करता है (`fork()` एक positive child PID लौटाता है) और protected logic केवल child में जारी रखता है (`fork()` `0` लौटाता है)। `dlsym(RTLD_DEFAULT, "fork")` से `fork` resolve करने पर direct `_fork` call site भी हट जाता है, लेकिन यह केवल anti-analysis बाधा है: symbol-name string और dynamic-resolution data flow फिर भी Mach-O binary में दिखाई देते हैं।<sup>[[13]](#references)[[14]](#references)</sup>

arm64 पर, fixed addresses के बजाय data flow को follow करके इस pattern का पता लगाएँ: `dlsym` के पहले दो arguments `x0` और `x1` में pass होते हैं, `RTLD_DEFAULT` `-2` के रूप में दिख सकता है (उदाहरण के लिए, `movn x0, #1`), और `adrp`/`add` pair आम तौर पर `"fork"` string का address बनाता है। `dlsym` stub पर `bl` के बाद, लौटे हुए pointer को `x0` से उसके null check और storage होते हुए बाद के indirect `blr` तक trace करें। फिर `w0` में `fork()` के result को follow करें: zero से child continuation चुना जाता है, जबकि positive और `-1` values से parent/error path चुना जाता है।<sup>[[13]](#references)[[14]](#references)</sup>

एक static bypass यह है कि indirect call को suppress करें और मौजूदा result check को child path लेने के लिए मजबूर करें। उदाहरण के लिए, यदि compiler ने नीचे दिखाया गया sequence बनाया है, तो `blr` और result store को `nop` से patch करें, synthetic zero result दें और comparison/branch logic को बनाए रखें। इसके बाद application child बनाए बिना, मूल PID के तहत जारी रहती है; instruction registers और branch targets का analyzed build के अनुसार समायोजन करना होगा।<sup>[[13]](#references)[[14]](#references)</sup>

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

- `kern.coredump` sysctl को 1 पर सेट किया गया हो (डिफ़ॉल्ट रूप से)
- यदि process suid/sgid न हो या `kern.sugid_coredump` 1 हो (डिफ़ॉल्ट रूप से 0)
- `AS_CORE` limit इस operation की अनुमति देता हो। `ulimit -c 0` को call करके core dumps का निर्माण रोकना और `ulimit -c unlimited` से उन्हें फिर से enable करना संभव है।

इन मामलों में core dumps `kern.corefile` sysctl के अनुसार generate होते हैं और आमतौर पर `/cores/core/.%P` में store किए जाते हैं।

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **crashing processes का विश्लेषण करता है और crash report को disk पर save करता है**। Crash report में ऐसी जानकारी होती है जो **developer को crash का कारण पता लगाने में मदद कर सकती है**।\
**Per-user launchd context में चल रहे** applications और अन्य processes के लिए, ReportCrash LaunchAgent के रूप में चलता है और crash reports को user की `~/Library/Logs/DiagnosticReports/` में save करता है।\
Daemons, **system launchd context में चल रहे** अन्य processes और अन्य privileged processes के लिए, ReportCrash LaunchDaemon के रूप में चलता है और crash reports को system की `/Library/Logs/DiagnosticReports` में save करता है।

यदि आपको चिंता है कि crash reports **Apple को भेजी जा रही हैं**, तो आप उन्हें disable कर सकते हैं। अन्यथा, crash reports यह **पता लगाने में उपयोगी हो सकती हैं कि server कैसे crash हुआ**।

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

**नीचे दिया गया पेज देखें** कि कैसे पता करें कि **निर्दिष्ट scheme या protocol को handle करने के लिए कौन-सा app ज़िम्मेदार है:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Network Processes की Enumeration

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

### Stateful Mach IPC fuzzing

Privileged daemons द्वारा उजागर की गई Mach services उपयोगी fuzz targets हैं, जब कोई unprivileged या sandboxed client send right प्राप्त कर सकता हो। Daemon की `MachServices` launchd entry से शुरुआत करें और message IDs को handlers से map करने के लिए [MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) का उपयोग करें। Bytes में बदलाव करने से पहले, किसी सामान्य client द्वारा service का उपयोग करते समय MIG server routine पर breakpoint लगाएँ और valid request messages को seed inputs के रूप में सहेजें। आवश्यक header fields, message sizes और descriptor layout को सुरक्षित रखें, ताकि mutations dispatch में तुरंत fail होने के बजाय handler तक पहुँचें।<sup>[[17]](#references)</sup>

कई handlers पिछली calls पर निर्भर होते हैं। Harness से service state initialize करवाएँ, फिर हर fuzz input को **operations plus arguments** के क्रम के रूप में लें: setup requests भेजें (जैसे open या create), लौटाए गए identifiers को बनाए रखें और बाद की requests में उनका उपयोग करें। इससे coverage feedback बार-बार uninitialized-object check तक पहुँचने के बजाय state transitions को explore कर सकता है।<sup>[[17]](#references)</sup>

Closed-source target के लिए, MIG dispatch routine को call करने वाले in-process harness को Jackalope/TinyInst से instrument किया जा सकता है। [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) इसका एक ठोस implementation है, अन्य services के लिए drop-in harness नहीं।<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**हर crash को वास्तविक IPC path से validate करें।** Direct-dispatch harness, Mach messages की kernel validation को छोड़ देता है और false positives पैदा कर सकता है, खासकर जब वह invalid out-of-line (OOL) memory या port descriptors देता हो। Harness में valid OOL backing memory allocate करें, फिर मूल service access वाले client से `mach_msg` के ज़रिए reduced testcase को दोबारा चलाएँ और पुष्टि करें कि daemon अब भी crash होता है।<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI tools के लिए काम करता है

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

यह कई macOS GUI tools के साथ "**बस काम करता है**"। कुछ applications की अतिरिक्त आवश्यकताएँ होती हैं, जैसे unique filenames, कोई खास extension, या अपने sandbox container (`~/Library/Containers/com.apple.Safari/Data`) से files पढ़ना।

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

- [1] [OS X घटना प्रतिक्रिया: Scripting और Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/)
- [4] [No Starch Press - The Art of Mac Malware: Malicious Software का विश्लेषण करने की मार्गदर्शिका](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - इस ब्लॉग पोस्ट में इन sections में संग्रहीत जानकारी](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Pt Deny Attach का उपयोग करने वाले Apple Binaries को Debug करना](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-Debug Techniques को निष्प्रभावी करना: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode structured logs और `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - macOS unified log में private data दिखाना](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` request definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `mach_process.c` में `ptrace` implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace internals: यह debugger attachment को कैसे रोकता है](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork examples](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - dlsym और fork का उपयोग करने वाली Anti-debugging technique](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Debugging tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - hardened third-party app को Debug करना](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - ध्वनि की बाधा तोड़ना, भाग I: Mach Messages के साथ CoreAudio को Fuzz करना](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - MacSync macOS stealer का नया संस्करण crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
