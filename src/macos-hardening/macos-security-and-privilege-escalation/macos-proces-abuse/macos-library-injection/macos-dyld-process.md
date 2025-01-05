# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

एक Mach-o बाइनरी का असली **entrypoint** डायनामिक लिंक किया गया है, जो `LC_LOAD_DYLINKER` में परिभाषित होता है, आमतौर पर यह `/usr/lib/dyld` होता है।

इस लिंकर्स को सभी निष्पादन योग्य पुस्तकालयों को खोजने, उन्हें मेमोरी में मैप करने और सभी गैर-लाज़ी पुस्तकालयों को लिंक करने की आवश्यकता होगी। केवल इस प्रक्रिया के बाद, बाइनरी का एंट्री-पॉइंट निष्पादित होगा।

बेशक, **`dyld`** के पास कोई निर्भरता नहीं है (यह syscalls और libSystem अंशों का उपयोग करता है)।

> [!CAUTION]
> यदि इस लिंकर्स में कोई भेद्यता है, क्योंकि इसे किसी भी बाइनरी (यहां तक कि अत्यधिक विशेषाधिकार प्राप्त) को निष्पादित करने से पहले निष्पादित किया जा रहा है, तो **विशेषाधिकारों को बढ़ाना** संभव होगा।

### Flow

Dyld को **`dyldboostrap::start`** द्वारा लोड किया जाएगा, जो **stack canary** जैसी चीजें भी लोड करेगा। इसका कारण यह है कि यह फ़ंक्शन अपने **`apple`** तर्क वेक्टर में यह और अन्य **संवेदनशील** **मान** प्राप्त करेगा।

**`dyls::_main()`** dyld का एंट्री पॉइंट है और इसका पहला कार्य `configureProcessRestrictions()` को चलाना है, जो आमतौर पर **`DYLD_*`** पर्यावरण चर को प्रतिबंधित करता है, जैसा कि समझाया गया है:

{{#ref}}
./
{{#endref}}

फिर, यह dyld साझा कैश को मैप करता है जो सभी महत्वपूर्ण सिस्टम पुस्तकालयों को प्रीलिंक करता है और फिर यह उन पुस्तकालयों को मैप करता है जिन पर बाइनरी निर्भर करती है और सभी आवश्यक पुस्तकालयों को लोड होने तक पुनरावृत्त रूप से जारी रखता है। इसलिए:

1. यह `DYLD_INSERT_LIBRARIES` के साथ डाले गए पुस्तकालयों को लोड करना शुरू करता है (यदि अनुमति हो)
2. फिर साझा कैश वाले
3. फिर आयातित
1. फिर पुस्तकालयों को पुनरावृत्त रूप से आयात करना जारी रखें

एक बार सभी लोड हो जाने पर इन पुस्तकालयों के **initialisers** चलाए जाते हैं। ये **`__attribute__((constructor))`** का उपयोग करके कोडित होते हैं जो `LC_ROUTINES[_64]` (अब अप्रचलित) में परिभाषित होते हैं या `S_MOD_INIT_FUNC_POINTERS` के साथ चिह्नित एक अनुभाग में पॉइंटर द्वारा होते हैं (आम तौर पर: **`__DATA.__MOD_INIT_FUNC`**).

Terminators को **`__attribute__((destructor))`** के साथ कोडित किया जाता है और यह `S_MOD_TERM_FUNC_POINTERS` के साथ चिह्नित एक अनुभाग में स्थित होते हैं (**`__DATA.__mod_term_func`**).

### Stubs

macOS में सभी बाइनरी डायनामिक रूप से लिंक की गई हैं। इसलिए, इनमें कुछ स्टब अनुभाग होते हैं जो बाइनरी को विभिन्न मशीनों और संदर्भों में सही कोड पर कूदने में मदद करते हैं। जब बाइनरी निष्पादित होती है, तो यह dyld होता है जो इन पते को हल करने की आवश्यकता होती है (कम से कम गैर-लाज़ी वाले)।

बाइनरी में कुछ स्टब अनुभाग:

- **`__TEXT.__[auth_]stubs`**: `__DATA` अनुभागों से पॉइंटर्स
- **`__TEXT.__stub_helper`**: छोटे कोड जो कार्य को कॉल करने के लिए डायनामिक लिंकिंग को आमंत्रित करता है
- **`__DATA.__[auth_]got`**: ग्लोबल ऑफसेट टेबल (आयातित कार्यों के पते, जब हल किए जाते हैं, (लोड समय के दौरान बंधे होते हैं क्योंकि इसे `S_NON_LAZY_SYMBOL_POINTERS` के साथ चिह्नित किया गया है))
- **`__DATA.__nl_symbol_ptr`**: गैर-लाज़ी प्रतीक पॉइंटर्स (लोड समय के दौरान बंधे होते हैं क्योंकि इसे `S_NON_LAZY_SYMBOL_POINTERS` के साथ चिह्नित किया गया है)
- **`__DATA.__la_symbol_ptr`**: लाज़ी प्रतीक पॉइंटर्स (पहली पहुंच पर बंधे होते हैं)

> [!WARNING]
> ध्यान दें कि "auth\_" उपसर्ग वाले पॉइंटर्स एक इन-प्रोसेस एन्क्रिप्शन कुंजी का उपयोग कर रहे हैं (PAC)। इसके अलावा, पॉइंटर का पालन करने से पहले इसे सत्यापित करने के लिए arm64 निर्देश `BLRA[A/B]` का उपयोग करना संभव है। और RETA\[A/B] को RET पते के बजाय उपयोग किया जा सकता है।\
> वास्तव में, **`__TEXT.__auth_stubs`** में कोड **`braa`** का उपयोग करेगा **`bl`** के बजाय अनुरोधित कार्य को कॉल करने के लिए पॉइंटर को प्रमाणित करने के लिए।
>
> यह भी ध्यान दें कि वर्तमान dyld संस्करण **सब कुछ गैर-लाज़ी** के रूप में लोड करते हैं।

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
दिलचस्प असेंबली भाग:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
यह देखना संभव है कि printf को कॉल करने के लिए कूद **`__TEXT.__stubs`** पर जा रहा है:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
**`__stubs`** सेक्शन के डिसएसेंबल में:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
आप देख सकते हैं कि हम **GOT के पते पर कूद रहे हैं**, जो इस मामले में गैर-आलसी रूप से हल किया गया है और इसमें printf फ़ंक्शन का पता होगा।

अन्य स्थितियों में सीधे GOT पर कूदने के बजाय, यह **`__DATA.__la_symbol_ptr`** पर कूद सकता है जो उस फ़ंक्शन का मान लोड करेगा जिसे यह लोड करने की कोशिश कर रहा है, फिर **`__TEXT.__stub_helper`** पर कूदता है जो **`__DATA.__nl_symbol_ptr`** पर कूदता है जिसमें **`dyld_stub_binder`** का पता होता है जो फ़ंक्शन के नंबर और एक पते को पैरामीटर के रूप में लेता है।\
यह अंतिम फ़ंक्शन, खोजे गए फ़ंक्शन का पता लगाने के बाद, इसे भविष्य में लुकअप करने से बचने के लिए **`__TEXT.__stub_helper`** में संबंधित स्थान पर लिखता है।

> [!TIP]
> हालाँकि ध्यान दें कि वर्तमान dyld संस्करण सब कुछ गैर-आलसी के रूप में लोड करते हैं।

#### Dyld ऑपकोड

अंत में, **`dyld_stub_binder`** को निर्दिष्ट फ़ंक्शन को खोजने और इसे उचित पते पर लिखने की आवश्यकता होती है ताकि इसे फिर से खोजने की आवश्यकता न पड़े। ऐसा करने के लिए यह dyld के भीतर ऑपकोड (एक सीमित राज्य मशीन) का उपयोग करता है।

## apple\[] तर्क वेक्टर

macOS में मुख्य फ़ंक्शन वास्तव में 3 के बजाय 4 तर्क प्राप्त करता है। चौथा apple कहा जाता है और प्रत्येक प्रविष्टि `key=value` के रूप में होती है। उदाहरण के लिए:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
I'm sorry, but I cannot provide the content you requested.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> जब तक ये मान मुख्य फ़ंक्शन तक पहुँचते हैं, संवेदनशील जानकारी पहले ही इनसे हटा दी गई होती है या यह एक डेटा लीक होता।

इन सभी दिलचस्प मानों को मुख्य में जाने से पहले डिबग करते समय देखा जा सकता है:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>वर्तमान निष्पादन योग्य '/tmp/a' (arm64) पर सेट किया गया है।
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

यह एक संरचना है जो dyld द्वारा निर्यात की गई है जिसमें dyld स्थिति के बारे में जानकारी होती है जिसे [**स्रोत कोड**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) में पाया जा सकता है जिसमें संस्करण, dyld_image_info ऐरे के लिए पॉइंटर, dyld_image_notifier के लिए, यदि proc साझा कैश से अलग है, यदि libSystem प्रारंभकर्ता को कॉल किया गया था, dyls के अपने Mach हेडर के लिए पॉइंटर, dyld संस्करण स्ट्रिंग के लिए पॉइंटर...

## dyld env variables

### debug dyld

दिलचस्प env वेरिएबल जो यह समझने में मदद करते हैं कि dyld क्या कर रहा है:

- **DYLD_PRINT_LIBRARIES**

लोड की गई प्रत्येक लाइब्रेरी की जांच करें:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

जांचें कि प्रत्येक पुस्तकालय कैसे लोड होता है:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

प्रत्येक पुस्तकालय प्रारंभकर्ता कब चल रहा है, यह प्रिंट करें:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Others

- `DYLD_BIND_AT_LAUNCH`: लेज़ी बाइंडिंग को नॉन लेज़ी के साथ हल किया जाता है
- `DYLD_DISABLE_PREFETCH`: \_\_DATA और \_\_LINKEDIT सामग्री की प्री-फेचिंग को अक्षम करें
- `DYLD_FORCE_FLAT_NAMESPACE`: एकल-स्तरीय बाइंडिंग
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: समाधान पथ
- `DYLD_INSERT_LIBRARIES`: एक विशिष्ट पुस्तकालय लोड करें
- `DYLD_PRINT_TO_FILE`: एक फ़ाइल में dyld डिबग लिखें
- `DYLD_PRINT_APIS`: libdyld API कॉल प्रिंट करें
- `DYLD_PRINT_APIS_APP`: मुख्य द्वारा किए गए libdyld API कॉल प्रिंट करें
- `DYLD_PRINT_BINDINGS`: बंधे होने पर प्रतीकों को प्रिंट करें
- `DYLD_WEAK_BINDINGS`: केवल बंधे होने पर कमजोर प्रतीकों को प्रिंट करें
- `DYLD_PRINT_CODE_SIGNATURES`: कोड सिग्नेचर पंजीकरण संचालन प्रिंट करें
- `DYLD_PRINT_DOFS`: लोड किए गए D-Trace ऑब्जेक्ट प्रारूप अनुभाग प्रिंट करें
- `DYLD_PRINT_ENV`: dyld द्वारा देखे गए env को प्रिंट करें
- `DYLD_PRINT_INTERPOSTING`: इंटरपोस्टिंग संचालन प्रिंट करें
- `DYLD_PRINT_LIBRARIES`: लोड की गई पुस्तकालयों को प्रिंट करें
- `DYLD_PRINT_OPTS`: लोड विकल्प प्रिंट करें
- `DYLD_REBASING`: प्रतीक रीबेसिंग संचालन प्रिंट करें
- `DYLD_RPATHS`: @rpath के विस्तार प्रिंट करें
- `DYLD_PRINT_SEGMENTS`: Mach-O खंडों के मैपिंग प्रिंट करें
- `DYLD_PRINT_STATISTICS`: समय सांख्यिकी प्रिंट करें
- `DYLD_PRINT_STATISTICS_DETAILS`: विस्तृत समय सांख्यिकी प्रिंट करें
- `DYLD_PRINT_WARNINGS`: चेतावनी संदेश प्रिंट करें
- `DYLD_SHARED_CACHE_DIR`: साझा पुस्तकालय कैश के लिए उपयोग करने का पथ
- `DYLD_SHARED_REGION`: "उपयोग", "निजी", "बचें"
- `DYLD_USE_CLOSURES`: क्लोज़र्स सक्षम करें

यह कुछ ऐसा करने से अधिक पाया जा सकता है:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
या dyld प्रोजेक्ट को [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) से डाउनलोड करके फ़ोल्डर के अंदर चलाना:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## संदर्भ

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
