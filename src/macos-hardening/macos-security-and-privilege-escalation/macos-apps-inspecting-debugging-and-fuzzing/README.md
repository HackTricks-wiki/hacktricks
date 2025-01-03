# macOS ऐप्स - निरीक्षण, डिबगिंग और फज़िंग

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
### jtool2 & Disarm

आप [**यहां से disarm डाउनलोड कर सकते हैं**](https://newosxbook.com/tools/disarm.html)।
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
आप [**jtool2 यहाँ डाउनलोड कर सकते हैं**](http://www.newosxbook.com/tools/jtool.html) या इसे `brew` के साथ इंस्टॉल कर सकते हैं।
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool का उपयोग बंद कर दिया गया है disarm के पक्ष में**

### Codesign / ldid

> [!TIP] > **`Codesign`** **macOS** में पाया जा सकता है जबकि **`ldid`** **iOS** में पाया जा सकता है
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) एक उपकरण है जो **.pkg** फ़ाइलों (इंस्टॉलर) की जांच करने के लिए उपयोगी है और इसे स्थापित करने से पहले इसके अंदर क्या है, यह देखने के लिए।\
इन इंस्टॉलरों में `preinstall` और `postinstall` बैश स्क्रिप्ट होती हैं जिनका उपयोग आमतौर पर मैलवेयर लेखक **persist** **the** **malware** के लिए करते हैं।

### hdiutil

यह उपकरण Apple डिस्क इमेज (**.dmg**) फ़ाइलों को **mount** करने की अनुमति देता है ताकि उन्हें चलाने से पहले जांचा जा सके:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
यह `/Volumes` में माउंट किया जाएगा

### पैक्ड बाइनरी

- उच्च एंट्रॉपी के लिए जांचें
- स्ट्रिंग्स की जांच करें (यदि लगभग कोई समझने योग्य स्ट्रिंग नहीं है, तो पैक किया गया है)
- MacOS के लिए UPX पैकर एक सेक्शन बनाता है जिसे "\_\_XHDR" कहा जाता है

## स्थैतिक Objective-C विश्लेषण

### मेटाडेटा

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए प्रोग्राम **क्लास डिक्लेरेशन को बनाए रखते हैं** **जब** **कंपाइल** किया जाता है [Mach-O बाइनरी में](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)। ऐसे क्लास डिक्लेरेशन **में शामिल हैं**:

- परिभाषित इंटरफेस
- इंटरफेस विधियाँ
- इंटरफेस इंस्टेंस वेरिएबल्स
- परिभाषित प्रोटोकॉल

ध्यान दें कि ये नाम बाइनरी के रिवर्सिंग को अधिक कठिन बनाने के लिए ओबफस्केट किए जा सकते हैं।

### फ़ंक्शन कॉलिंग

जब एक बाइनरी में एक फ़ंक्शन को कॉल किया जाता है जो Objective-C का उपयोग करता है, तो कंपाइल किया गया कोड उस फ़ंक्शन को कॉल करने के बजाय **`objc_msgSend`** को कॉल करेगा। जो अंतिम फ़ंक्शन को कॉल करेगा:

![](<../../../images/image (305).png>)

इस फ़ंक्शन की अपेक्षित पैरामीटर हैं:

- पहला पैरामीटर (**self**) "एक पॉइंटर है जो **क्लास के इंस्टेंस की ओर इशारा करता है जो संदेश प्राप्त करने वाला है**"। या सरल शब्दों में, यह वह ऑब्जेक्ट है जिस पर विधि को लागू किया जा रहा है। यदि विधि एक क्लास विधि है, तो यह क्लास ऑब्जेक्ट का एक इंस्टेंस होगा (जैसे पूरा), जबकि एक इंस्टेंस विधि के लिए, self क्लास के एक इंस्टेंस के रूप में एक ऑब्जेक्ट की ओर इशारा करेगा।
- दूसरा पैरामीटर, (**op**), "विधि का चयनकर्ता है जो संदेश को संभालता है"। फिर से, सरल शब्दों में, यह बस **विधि का नाम है।**
- शेष पैरामीटर वे **मान हैं जो विधि द्वारा आवश्यक हैं** (op)।

देखें कि **`lldb` का उपयोग करके ARM64 में इस जानकारी को आसानी से कैसे प्राप्त करें** इस पृष्ठ पर:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **आर्गुमेंट**      | **रजिस्टर**                                                    | **(के लिए) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st आर्गुमेंट**  | **rdi**                                                         | **self: वह ऑब्जेक्ट जिस पर विधि को लागू किया जा रहा है** |
| **2nd आर्गुमेंट**  | **rsi**                                                         | **op: विधि का नाम**                             |
| **3rd आर्गुमेंट**  | **rdx**                                                         | **विधि के लिए 1st आर्गुमेंट**                         |
| **4th आर्गुमेंट**  | **rcx**                                                         | **विधि के लिए 2nd आर्गुमेंट**                         |
| **5th आर्गुमेंट**  | **r8**                                                          | **विधि के लिए 3rd आर्गुमेंट**                         |
| **6th आर्गुमेंट**  | **r9**                                                          | **विधि के लिए 4th आर्गुमेंट**                         |
| **7th+ आर्गुमेंट** | <p><strong>rsp+</strong><br><strong>(स्टैक पर)</strong></p> | **विधि के लिए 5th+ आर्गुमेंट**                        |

### ObjectiveC मेटाडेटा डंप करें

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) एक उपकरण है जो Objective-C बाइनरी को क्लास-डंप करता है। गिटहब डायलिब्स को निर्दिष्ट करता है लेकिन यह निष्पादन योग्य फ़ाइलों के साथ भी काम करता है।
```bash
./dynadump dump /path/to/bin
```
लेखन के समय, यह **वर्तमान में सबसे अच्छा काम करने वाला है**।

#### नियमित उपकरण
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) मूल उपकरण है जो ObjetiveC स्वरूपित कोड में वर्गों, श्रेणियों और प्रोटोकॉल के लिए घोषणाएँ उत्पन्न करता है।

यह पुराना और अनुपयुक्त है इसलिए यह शायद ठीक से काम नहीं करेगा।

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) एक आधुनिक और क्रॉस-प्लेटफ़ॉर्म Objective-C क्लास डंप है। मौजूदा उपकरणों की तुलना में, iCDump Apple पारिस्थितिकी तंत्र से स्वतंत्र रूप से चल सकता है और यह Python बाइंडिंग्स को उजागर करता है।
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analysis

Swift बाइनरी के साथ, चूंकि इसमें Objective-C संगतता है, कभी-कभी आप [class-dump](https://github.com/nygard/class-dump/) का उपयोग करके घोषणाएँ निकाल सकते हैं लेकिन हमेशा नहीं।

**`jtool -l`** या **`otool -l`** कमांड लाइनों के साथ यह संभव है कि आप कई सेक्शन पा सकें जो **`__swift5`** उपसर्ग से शुरू होते हैं:
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
आप इस [**ब्लॉग पोस्ट में इन अनुभागों में संग्रहीत जानकारी**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) के बारे में और जानकारी प्राप्त कर सकते हैं।

इसके अलावा, **Swift बाइनरी में प्रतीक हो सकते हैं** (उदाहरण के लिए पुस्तकालयों को प्रतीकों को संग्रहीत करने की आवश्यकता होती है ताकि उनके कार्यों को कॉल किया जा सके)। **प्रतीकों में आमतौर पर कार्य का नाम** और विशेषता के बारे में जानकारी होती है, इसलिए वे बहुत उपयोगी होते हैं और ऐसे "**डेमैंग्लर्स"** होते हैं जो मूल नाम प्राप्त कर सकते हैं:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## डायनामिक विश्लेषण

> [!WARNING]
> ध्यान दें कि बाइनरी को डिबग करने के लिए, **SIP को अक्षम करना आवश्यक है** (`csrutil disable` या `csrutil enable --without debug`) या बाइनरी को एक अस्थायी फ़ोल्डर में कॉपी करना और **हस्ताक्षर को हटाना** `codesign --remove-signature <binary-path>` या बाइनरी के डिबगिंग की अनुमति देना (आप [इस स्क्रिप्ट](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) का उपयोग कर सकते हैं)

> [!WARNING]
> ध्यान दें कि **सिस्टम बाइनरीज़ को इंस्ट्रूमेंट** करने के लिए, (जैसे `cloudconfigurationd`) macOS पर, **SIP को अक्षम करना आवश्यक है** (सिर्फ हस्ताक्षर हटाना काम नहीं करेगा)।

### APIs

macOS कुछ दिलचस्प APIs को उजागर करता है जो प्रक्रियाओं के बारे में जानकारी देते हैं:

- `proc_info`: यह मुख्य है जो प्रत्येक प्रक्रिया के बारे में बहुत सारी जानकारी देता है। आपको अन्य प्रक्रियाओं की जानकारी प्राप्त करने के लिए रूट होना आवश्यक है लेकिन आपको विशेष अधिकार या मच पोर्ट की आवश्यकता नहीं है।
- `libsysmon.dylib`: यह XPC द्वारा उजागर की गई कार्यों के माध्यम से प्रक्रियाओं के बारे में जानकारी प्राप्त करने की अनुमति देता है, हालाँकि, इसके लिए `com.apple.sysmond.client` का अधिकार होना आवश्यक है।

### स्टैकशॉट और माइक्रोस्टैकशॉट्स

**स्टैकशॉटिंग** एक तकनीक है जिसका उपयोग प्रक्रियाओं की स्थिति को कैप्चर करने के लिए किया जाता है, जिसमें सभी चल रहे थ्रेड्स के कॉल स्टैक शामिल होते हैं। यह विशेष रूप से डिबगिंग, प्रदर्शन विश्लेषण, और किसी विशेष समय पर सिस्टम के व्यवहार को समझने के लिए उपयोगी है। iOS और macOS पर, स्टैकशॉटिंग कई उपकरणों और विधियों का उपयोग करके किया जा सकता है जैसे कि उपकरण **`sample`** और **`spindump`**।

### Sysdiagnose

यह उपकरण (`/usr/bini/ysdiagnose`) मूल रूप से आपके कंप्यूटर से बहुत सारी जानकारी एकत्र करता है, जिसमें `ps`, `zprint` जैसे दर्जनों विभिन्न कमांड चलाना शामिल है...

इसे **रूट** के रूप में चलाना आवश्यक है और डेमन `/usr/libexec/sysdiagnosed` के पास बहुत दिलचस्प अधिकार हैं जैसे `com.apple.system-task-ports` और `get-task-allow`।

इसका plist `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` में स्थित है जो 3 MachServices की घोषणा करता है:

- `com.apple.sysdiagnose.CacheDelete`: /var/rmp में पुराने आर्काइव को हटाता है
- `com.apple.sysdiagnose.kernel.ipc`: विशेष पोर्ट 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C वर्ग के माध्यम से उपयोगकर्ता मोड इंटरफ़ेस। एक dict में तीन तर्क पास किए जा सकते हैं (`compress`, `display`, `run`)

### यूनिफाइड लॉग्स

MacOS बहुत सारे लॉग उत्पन्न करता है जो एक एप्लिकेशन चलाते समय **यह समझने में बहुत उपयोगी हो सकते हैं कि यह क्या कर रहा है**।

इसके अलावा, कुछ लॉग्स में `<private>` टैग होगा ताकि कुछ **उपयोगकर्ता** या **कंप्यूटर** **पहचान योग्य** जानकारी को **छिपाया** जा सके। हालाँकि, इस जानकारी को प्रकट करने के लिए **एक प्रमाणपत्र स्थापित करना संभव है**। [**यहाँ**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) से स्पष्टीकरण का पालन करें।

### हॉप्पर

#### बाईं पैनल

हॉप्पर के बाईं पैनल में बाइनरी के प्रतीक (**Labels**), प्रक्रियाओं और कार्यों की सूची (**Proc**) और स्ट्रिंग्स (**Str**) देखी जा सकती हैं। ये सभी स्ट्रिंग्स नहीं हैं बल्कि वे हैं जो Mac-O फ़ाइल के कई भागों में परिभाषित हैं (जैसे _cstring या_ `objc_methname`)।

#### मध्य पैनल

मध्य पैनल में आप **डिस्सेम्बल्ड कोड** देख सकते हैं। और आप इसे **कच्चे** डिस्सेम्बल, **ग्राफ** के रूप में, **डीकंपाइल** के रूप में और **बाइनरी** के रूप में संबंधित आइकन पर क्लिक करके देख सकते हैं:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

कोड ऑब्जेक्ट पर राइट-क्लिक करने पर आप **उस ऑब्जेक्ट के लिए संदर्भ** देख सकते हैं या यहां तक कि इसका नाम बदल सकते हैं (यह डी-कंपाइल किए गए प्सेडोकोड में काम नहीं करता):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

इसके अलावा, **मध्य नीचे आप पायथन कमांड लिख सकते हैं**।

#### दाईं पैनल

दाईं पैनल में आप दिलचस्प जानकारी देख सकते हैं जैसे **नेविगेशन इतिहास** (ताकि आप जान सकें कि आप वर्तमान स्थिति पर कैसे पहुंचे), **कॉल ग्राफ** जहां आप देख सकते हैं सभी **कार्य जो इस कार्य को कॉल करते हैं** और सभी कार्य जो **यह कार्य कॉल करता है**, और **स्थानीय चर** की जानकारी।

### डीट्रैस

यह उपयोगकर्ताओं को अनुप्रयोगों तक अत्यधिक **निम्न स्तर** पर पहुंच प्रदान करता है और उपयोगकर्ताओं को **कार्यक्रमों को ट्रेस** करने और यहां तक कि उनके निष्पादन प्रवाह को बदलने का एक तरीका प्रदान करता है। Dtrace **प्रोब्स** का उपयोग करता है जो **कर्नेल के चारों ओर रखे जाते हैं** और सिस्टम कॉल के प्रारंभ और अंत जैसे स्थानों पर होते हैं।

DTrace प्रत्येक सिस्टम कॉल के लिए एक प्रोब बनाने के लिए **`dtrace_probe_create`** फ़ंक्शन का उपयोग करता है। ये प्रोब्स प्रत्येक सिस्टम कॉल के **प्रवेश और निकास बिंदु** में फायर किए जा सकते हैं। DTrace के साथ इंटरैक्शन /dev/dtrace के माध्यम से होता है जो केवल रूट उपयोगकर्ता के लिए उपलब्ध है।

> [!TIP]
> Dtrace को पूरी तरह से SIP सुरक्षा को अक्षम किए बिना सक्षम करने के लिए आप रिकवरी मोड में निष्पादित कर सकते हैं: `csrutil enable --without dtrace`
>
> आप **`dtrace`** या **`dtruss`** बाइनरी भी कर सकते हैं जो **आपने संकलित की हैं**।

dtrace के उपलब्ध प्रोब्स को प्राप्त किया जा सकता है:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
प्रोब नाम चार भागों में बंटा होता है: प्रदाता, मॉड्यूल, फ़ंक्शन, और नाम (`fbt:mach_kernel:ptrace:entry`)। यदि आप नाम के कुछ भाग को निर्दिष्ट नहीं करते हैं, तो Dtrace उस भाग को वाइल्डकार्ड के रूप में लागू करेगा।

DTrace को प्रोब्स को सक्रिय करने और जब वे फायर होते हैं तो कौन से क्रियाएँ करनी हैं, यह निर्दिष्ट करने के लिए, हमें D भाषा का उपयोग करने की आवश्यकता होगी।

एक अधिक विस्तृत व्याख्या और अधिक उदाहरण [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) में पाया जा सकता है।

#### उदाहरण

`man -k dtrace` चलाएँ ताकि **DTrace स्क्रिप्ट उपलब्ध** की सूची मिल सके। उदाहरण: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- स्क्रिप्ट
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

यह एक कर्नेल ट्रेसिंग सुविधा है। दस्तावेज़ित कोड **`/usr/share/misc/trace.codes`
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
या `tailspin`।

### kperf

यह कर्नेल स्तर की प्रोफाइलिंग करने के लिए उपयोग किया जाता है और इसे `Kdebug` कॉलआउट्स का उपयोग करके बनाया गया है।

बुनियादी रूप से, वैश्विक चर `kernel_debug_active` की जांच की जाती है और यदि यह सेट है तो यह `kperf_kdebug_handler` को `Kdebug` कोड और कर्नेल फ्रेम के पते के साथ कॉल करता है। यदि `Kdebug` कोड में से एक चयनित के साथ मेल खाता है, तो इसे "क्रियाएँ" के रूप में एक बिटमैप के रूप में कॉन्फ़िगर किया जाता है (विकल्पों के लिए `osfmk/kperf/action.h` देखें)।

Kperf का एक sysctl MIB तालिका भी है: (रूट के रूप में) `sysctl kperf`। ये कोड `osfmk/kperf/kperfbsd.c` में पाए जा सकते हैं।

इसके अलावा, Kperfs की कार्यक्षमता का एक उपसमुच्चय `kpc` में स्थित है, जो मशीन प्रदर्शन काउंटर के बारे में जानकारी प्रदान करता है।

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) एक बहुत उपयोगी उपकरण है जो यह जांचने के लिए है कि एक प्रक्रिया कौन-कौन से क्रियाएँ कर रही है (उदाहरण के लिए, यह मॉनिटर करें कि एक प्रक्रिया कौन-कौन से नए प्रक्रियाएँ बना रही है)।

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) एक उपकरण है जो प्रक्रियाओं के बीच संबंधों को प्रिंट करता है।\
आपको अपने मैक को एक कमांड के साथ मॉनिटर करना होगा जैसे **`sudo eslogger fork exec rename create > cap.json`** (इसकी आवश्यकता के लिए टर्मिनल को FDA लॉन्च करना होगा)। और फिर आप इस उपकरण में json लोड कर सकते हैं ताकि सभी संबंधों को देख सकें:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) फ़ाइल घटनाओं (जैसे निर्माण, संशोधन, और विलोपन) की निगरानी करने की अनुमति देता है, जो ऐसी घटनाओं के बारे में विस्तृत जानकारी प्रदान करता है।

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) एक GUI उपकरण है जिसका रूप और अनुभव Windows उपयोगकर्ताओं को Microsoft Sysinternal के _Procmon_ से परिचित हो सकता है। यह उपकरण विभिन्न प्रकार की घटनाओं के रिकॉर्डिंग को शुरू और रोकने की अनुमति देता है, इन घटनाओं को फ़ाइल, प्रक्रिया, नेटवर्क आदि जैसी श्रेणियों द्वारा फ़िल्टर करने की अनुमति देता है, और json प्रारूप में रिकॉर्ड की गई घटनाओं को सहेजने की कार्यक्षमता प्रदान करता है।

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) Xcode के डेवलपर उपकरणों का हिस्सा हैं - जो अनुप्रयोग प्रदर्शन की निगरानी, मेमोरी लीक की पहचान और फ़ाइल सिस्टम गतिविधि को ट्रैक करने के लिए उपयोग किए जाते हैं।

![](<../../../images/image (1138).png>)

### fs_usage

यह प्रक्रियाओं द्वारा किए गए कार्यों का पालन करने की अनुमति देता है:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) एक बाइनरी द्वारा उपयोग की जाने वाली **लाइब्रेरीज़**, इसके द्वारा उपयोग किए जा रहे **फाइलों** और **नेटवर्क** कनेक्शनों को देखने के लिए उपयोगी है।\
यह बाइनरी प्रक्रियाओं की जांच **virustotal** के खिलाफ करता है और बाइनरी के बारे में जानकारी दिखाता है।

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

[**इस ब्लॉग पोस्ट**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) में आप एक उदाहरण पा सकते हैं कि कैसे **एक चल रहे डेमन** को **`PT_DENY_ATTACH`** का उपयोग करके डिबग किया जाए ताकि डिबगिंग को रोका जा सके, भले ही SIP अक्षम हो।

### lldb

**lldb** **macOS** बाइनरी **डिबगिंग** के लिए de **facto tool** है।
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
आप अपने होम फ़ोल्डर में **`.lldbinit`** नामक एक फ़ाइल बनाकर lldb का उपयोग करते समय intel स्वाद सेट कर सकते हैं, जिसमें निम्नलिखित पंक्ति हो:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> lldb के अंदर, `process save-core` के साथ एक प्रक्रिया को डंप करें

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) कमांड</strong></td><td><strong>विवरण</strong></td></tr><tr><td><strong>run (r)</strong></td><td>कार्यवाही शुरू करना, जो तब तक जारी रहेगा जब तक कि एक ब्रेकपॉइंट हिट न हो या प्रक्रिया समाप्त न हो जाए।</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>प्रवेश बिंदु पर रुकते हुए कार्यवाही शुरू करें</td></tr><tr><td><strong>continue (c)</strong></td><td>डीबग की गई प्रक्रिया की कार्यवाही जारी रखें।</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>अगली निर्देश को निष्पादित करें। यह कमांड फ़ंक्शन कॉल को छोड़ देगा।</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>अगली निर्देश को निष्पादित करें। अगले कमांड के विपरीत, यह कमांड फ़ंक्शन कॉल में कदम रखेगा।</td></tr><tr><td><strong>finish (f)</strong></td><td>वर्तमान फ़ंक्शन में शेष निर्देशों को निष्पादित करें (“फ्रेम”) लौटें और रुकें।</td></tr><tr><td><strong>control + c</strong></td><td>कार्यवाही को रोकें। यदि प्रक्रिया को चलाया गया है (r) या जारी रखा गया है (c), तो यह प्रक्रिया को रोक देगा ...जहाँ भी यह वर्तमान में निष्पादित हो रही है।</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #कोई भी फ़ंक्शन जिसे main कहा जाता है</p><p><code>b &#x3C;binname>`main</code> #बिन का मुख्य फ़ंक्शन</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #संकेतित बिन का मुख्य फ़ंक्शन</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #कोई भी NSFileManager विधि</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # उस पुस्तकालय के सभी फ़ंक्शनों में ब्रेक</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #ब्रेकपॉइंट सूची</p><p><code>br e/dis &#x3C;num></code> #ब्रेकपॉइंट सक्षम/अक्षम करें</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #ब्रेकपॉइंट कमांड की मदद प्राप्त करें</p><p>help memory write #मेमोरी में लिखने के लिए मदद प्राप्त करें</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>मेमोरी को एक नल-टर्मिनेटेड स्ट्रिंग के रूप में प्रदर्शित करें।</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>मेमोरी को असेंबली निर्देश के रूप में प्रदर्शित करें।</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>मेमोरी को बाइट के रूप में प्रदर्शित करें।</td></tr><tr><td><strong>print object (po)</strong></td><td><p>यह उस ऑब्जेक्ट को प्रिंट करेगा जिसका संदर्भ पैरामीटर द्वारा दिया गया है</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>ध्यान दें कि Apple के अधिकांश Objective-C APIs या विधियाँ ऑब्जेक्ट लौटाती हैं, और इसलिए उन्हें “print object” (po) कमांड के माध्यम से प्रदर्शित किया जाना चाहिए। यदि po अर्थपूर्ण आउटपुट नहीं देता है तो <code>x/b</code> का उपयोग करें</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #उस पते में AAAA लिखें<br>memory write -f s $rip+0x11f+7 "AAAA" #पते में AAAA लिखें</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #वर्तमान फ़ंक्शन का डिसास</p><p>dis -n &#x3C;funcname> #फ़ंक्शन का डिसास</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #फ़ंक्शन का डिसास<br>dis -c 6 #6 पंक्तियों का डिसास<br>dis -c 0x100003764 -e 0x100003768 #एक जोड़ से दूसरे तक<br>dis -p -c 4 #वर्तमान पते से डिसास करना शुरू करें</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #x1 रजिस्टर में 3 घटकों का ऐरे जांचें</td></tr><tr><td><strong>image dump sections</strong></td><td>वर्तमान प्रक्रिया की मेमोरी का मानचित्र प्रिंट करें</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #CoreNLP से सभी प्रतीकों के पते प्राप्त करें</td></tr></tbody></table>

> [!NOTE]
> जब **`objc_sendMsg`** फ़ंक्शन को कॉल किया जाता है, तो **rsi** रजिस्टर **विधि का नाम** एक नल-टर्मिनेटेड (“C”) स्ट्रिंग के रूप में रखता है। lldb के माध्यम से नाम प्रिंट करने के लिए करें:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### एंटी-डायनामिक एनालिसिस

#### VM पहचान

- कमांड **`sysctl hw.model`** "Mac" लौटाता है जब **होस्ट MacOS है** लेकिन जब यह एक VM है तो कुछ अलग लौटाता है।
- **`hw.logicalcpu`** और **`hw.physicalcpu`** के मानों के साथ खेलते हुए कुछ मैलवेयर यह पहचानने की कोशिश करते हैं कि क्या यह एक VM है।
- कुछ मैलवेयर यह भी **पहचान सकते हैं** कि मशीन **VMware** आधारित है या नहीं MAC पते (00:50:56) के आधार पर।
- यह भी संभव है कि **यदि एक प्रक्रिया को डीबग किया जा रहा है** तो इसे एक साधारण कोड के साथ जांचा जा सके जैसे:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //प्रक्रिया को डीबग किया जा रहा है }`
- यह **`ptrace`** सिस्टम कॉल को **`PT_DENY_ATTACH`** फ्लैग के साथ भी कॉल कर सकता है। यह **डीबग** करने वाले को अटैच और ट्रेस करने से रोकता है।
- आप जांच सकते हैं कि **`sysctl`** या **`ptrace`** फ़ंक्शन को **आयात** किया जा रहा है (लेकिन मैलवेयर इसे डायनामिक रूप से आयात कर सकता है)
- जैसा कि इस लेख में नोट किया गया है, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_संदेश प्रक्रिया # समाप्त हो गई **स्थिति = 45 (0x0000002d)** आमतौर पर यह एक संकेत है कि डीबग लक्ष्य **PT_DENY_ATTACH** का उपयोग कर रहा है_”

## कोर डंप

कोर डंप तब बनाए जाते हैं यदि:

- `kern.coredump` sysctl 1 पर सेट है (डिफ़ॉल्ट रूप से)
- यदि प्रक्रिया suid/sgid नहीं थी या `kern.sugid_coredump` 1 है (डिफ़ॉल्ट रूप से 0)
- `AS_CORE` सीमा ऑपरेशन की अनुमति देती है। कोड डंप निर्माण को दबाने के लिए `ulimit -c 0` कॉल करके और उन्हें फिर से सक्षम करने के लिए `ulimit -c unlimited` का उपयोग करना संभव है।

इन मामलों में कोर डंप `kern.corefile` sysctl के अनुसार उत्पन्न होते हैं और आमतौर पर `/cores/core/.%P` में संग्रहीत होते हैं।

## फज़िंग

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **क्रैश होने वाली प्रक्रियाओं का विश्लेषण करता है और डिस्क पर एक क्रैश रिपोर्ट सहेजता है**। एक क्रैश रिपोर्ट में ऐसी जानकारी होती है जो **डेवलपर को क्रैश के कारण का निदान करने में मदद कर सकती है**।\
उपयोगकर्ता के लॉन्चड संदर्भ में **चलने वाली अनुप्रयोगों और अन्य प्रक्रियाओं** के लिए, ReportCrash एक LaunchAgent के रूप में चलता है और उपयोगकर्ता के `~/Library/Logs/DiagnosticReports/` में क्रैश रिपोर्ट सहेजता है।\
डेमन्स, सिस्टम लॉन्चड संदर्भ में **चलने वाली अन्य प्रक्रियाओं** और अन्य विशेषाधिकार प्राप्त प्रक्रियाओं के लिए, ReportCrash एक LaunchDaemon के रूप में चलता है और सिस्टम के `/Library/Logs/DiagnosticReports` में क्रैश रिपोर्ट सहेजता है।

यदि आप क्रैश रिपोर्टों के बारे में चिंतित हैं **जो Apple को भेजी जा रही हैं** तो आप उन्हें अक्षम कर सकते हैं। यदि नहीं, तो क्रैश रिपोर्टें **यह पता लगाने में सहायक हो सकती हैं कि सर्वर कैसे क्रैश हुआ**।
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### नींद

MacOS में फज़िंग करते समय यह महत्वपूर्ण है कि मैक को सोने न दिया जाए:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH डिस्कनेक्ट

यदि आप SSH कनेक्शन के माध्यम से फज़िंग कर रहे हैं, तो यह सुनिश्चित करना महत्वपूर्ण है कि सत्र समाप्त न हो। इसलिए sshd_config फ़ाइल को बदलें:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**नीचे दिए गए पृष्ठ पर जाएं** यह जानने के लिए कि आप किस ऐप के लिए **निर्धारित स्कीम या प्रोटोकॉल को संभालने के लिए जिम्मेदार है:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

यह नेटवर्क डेटा का प्रबंधन करने वाले प्रक्रियाओं को खोजने के लिए दिलचस्प है:
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

CLI टूल्स के लिए काम करता है

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

यह "**बस काम करता है"** macOS GUI टूल्स के साथ। ध्यान दें कि कुछ macOS ऐप्स में कुछ विशिष्ट आवश्यकताएँ होती हैं जैसे अद्वितीय फ़ाइल नाम, सही एक्सटेंशन, फ़ाइलों को सैंडबॉक्स से पढ़ने की आवश्यकता (`~/Library/Containers/com.apple.Safari/Data`)...

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
### अधिक फज़िंग मैकोस जानकारी

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## संदर्भ

- [**OS X घटना प्रतिक्रिया: स्क्रिप्टिंग और विश्लेषण**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**Mac मैलवेयर की कला: दुर्भावनापूर्ण सॉफ़्टवेयर का विश्लेषण करने के लिए गाइड**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
