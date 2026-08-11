# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Mach-o binary का वास्तविक **entrypoint** dynamic linker होता है, जिसे `LC_LOAD_DYLINKER` में परिभाषित किया जाता है और यह आमतौर पर `/usr/lib/dyld` होता है।<sup>[[3]](#references)</sup>

इस linker को सभी executable libraries को locate करना, उन्हें memory में map करना और सभी non-lazy libraries को link करना होता है। इस process के बाद ही binary का entry-point execute किया जाता है।

स्वाभाविक रूप से, **`dyld`** की कोई dependencies नहीं होतीं (यह syscalls और libSystem excerpts का उपयोग करता है)।

> [!CAUTION]
> यदि इस linker में कोई vulnerability हो, तो चूंकि इसे किसी भी binary (यहां तक कि अत्यधिक privileged binaries) के execute होने से पहले execute किया जाता है, इसलिए **escalate privileges** करना संभव हो सकता है।

### Flow

Dyld को **`dyldboostrap::start`** द्वारा load किया जाता है, जो **stack canary** जैसी चीजों को भी load करता है। ऐसा इसलिए है क्योंकि यह function अपने **`apple`** argument vector में इसे और अन्य **sensitive** **values** को प्राप्त करता है।<sup>[[1]](#references)</sup>

**`dyls::_main()`** dyld का entry point है और इसका पहला task `configureProcessRestrictions()` को run करना है, जो आमतौर पर **`DYLD_*`** environment variables को restrict करता है, जैसा कि यहां समझाया गया है:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

इसके बाद यह dyld shared cache को map करता है, जो सभी महत्वपूर्ण system libraries को prelink करता है। फिर यह उन libraries को map करता है जिन पर binary निर्भर करती है और recursively जारी रहता है, जब तक सभी आवश्यक libraries load न हो जाएं। इसलिए:

1. यह `DYLD_INSERT_LIBRARIES` के साथ inserted libraries को load करना शुरू करता है (यदि अनुमति हो)
2. फिर shared cache वाली libraries
3. फिर imported libraries
1. फिर libraries को recursively import करना जारी रखता है

जब सभी libraries load हो जाती हैं, तो उनके **initialisers** run किए जाते हैं। इन्हें `LC_ROUTINES[_64]` (अब deprecated) में परिभाषित **`__attribute__((constructor))`** का उपयोग करके या `S_MOD_INIT_FUNC_POINTERS` से flagged section में pointer द्वारा code किया जाता है (आमतौर पर: **`__DATA.__MOD_INIT_FUNC`**)।

Terminators को **`__attribute__((destructor))`** के साथ code किया जाता है और वे `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**) से flagged section में स्थित होते हैं।

### Stubs

macOS के सभी binaries dynamically linked होते हैं। इसलिए, उनमें कुछ stub sections होते हैं जो binary को अलग-अलग machines और contexts में सही code पर jump करने में सहायता करते हैं। Binary execute होने पर इन addresses को resolve करना dyld का कार्य होता है (कम से कम non-lazy addresses का)।

Binary में कुछ stub sections:

- **`__TEXT.__[auth_]stubs`**: `__DATA` sections से pointers
- **`__TEXT.__stub_helper`**: call किए जाने वाले function की जानकारी के साथ dynamic linking invoke करने वाला छोटा code
- **`__DATA.__[auth_]got`**: Global Offset Table (imported functions के addresses; resolve होने पर load time के दौरान bound किए जाते हैं, क्योंकि यह `S_NON_LAZY_SYMBOL_POINTERS` flag से marked है)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (load time के दौरान bound किए जाते हैं, क्योंकि यह `S_NON_LAZY_SYMBOL_POINTERS` flag से marked है)
- **`__DATA.__la_symbol_ptr`**: Lazy symbol pointers (पहली access पर bound किए जाते हैं)

> [!WARNING]
> ध्यान दें कि "auth\_" prefix वाले pointers उन्हें protect करने के लिए एक in-process encryption key (PAC) का उपयोग करते हैं। इसके अलावा, pointer को follow करने से पहले verify करने के लिए arm64 instruction `BLRA[A/B]` का उपयोग किया जा सकता है। RET address के स्थान पर RETA\[A/B] का भी उपयोग किया जा सकता है।\
> वास्तव में, **`__TEXT.__auth_stubs`** में code requested function को call करने के लिए pointer को authenticate करने हेतु **`braa`** का उपयोग करेगा, न कि **`bl`** का।
>
> यह भी ध्यान दें कि वर्तमान dyld versions हर चीज को **non-lazy** के रूप में load करते हैं।

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
दिलचस्प disassembly भाग:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
यह देखा जा सकता है कि printf को call करने के लिए jump **`__TEXT.__stubs`** पर जा रहा है:
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
**`__stubs`** section के disassemble में:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
आप देख सकते हैं कि हम **GOT के address पर jump कर रहे हैं**, जो इस मामले में non-lazy रूप से resolved है और इसमें printf function का address होगा।

अन्य स्थितियों में GOT पर सीधे jump करने के बजाय, यह **`__DATA.__la_symbol_ptr`** पर jump कर सकता है, जो उस function को दर्शाने वाली value load करेगा जिसे load करने का प्रयास किया जा रहा है। इसके बाद यह **`__TEXT.__stub_helper`** पर jump करेगा, जो **`__DATA.__nl_symbol_ptr`** पर jump करता है। इसमें **`dyld_stub_binder`** का address होता है, जो parameters के रूप में function number और एक address लेता है।\
यह अंतिम function, searched function का address ढूँढने के बाद, उसे **`__TEXT.__stub_helper`** में संबंधित location पर लिख देता है, ताकि भविष्य में lookups न करने पड़ें।

> [!TIP]
> हालांकि, ध्यान दें कि current dyld versions हर चीज़ को non-lazy रूप से load करते हैं।

#### Dyld opcodes

अंततः, **`dyld_stub_binder`** को indicated function ढूँढना और उसे उचित address पर लिखना होता है, ताकि उसे दोबारा search न करना पड़े। ऐसा करने के लिए यह dyld के भीतर opcodes (एक finite state machine) का उपयोग करता है।

## apple\[] argument vector

macOS में main function को वास्तव में 3 के बजाय 4 arguments मिलते हैं। चौथे को apple कहा जाता है और प्रत्येक entry `key=value` के रूप में होती है। उदाहरण के लिए:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Result:
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
> जब तक ये values main function तक पहुंचती हैं, तब तक उनमें से sensitive information पहले ही हटा दी गई होती है, अन्यथा यह data leak हो सकता है।

main में जाने से पहले debugging करके इन सभी interesting values को देखना संभव है:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00  ...o............

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

यह dyld द्वारा export की गई एक structure है, जिसमें dyld state से संबंधित information होती है। इसे [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) में पाया जा सकता है। इसमें version, dyld_image_info array का pointer, dyld_image_notifier का pointer, यह information कि proc shared cache से detached है या नहीं, libSystem initializer को call किया गया है या नहीं, dyld के अपने Mach header का pointer, dyld version string आदि जैसी information शामिल होती है।<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

यह समझने में मदद करने वाले interesting env variables कि dyld क्या कर रहा है:

- **DYLD_PRINT_LIBRARIES**

Load की जाने वाली प्रत्येक library को check करें:
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

जांचें कि प्रत्येक library कैसे load की जाती है:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: reusing existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
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

प्रत्येक library initializer के चलने पर print करें:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### अन्य

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings को non lazy bindings के साथ resolve किया जाता है
- `DYLD_DISABLE_PREFETCH`: \_\_DATA और \_\_LINKEDIT content की pre-fetching अक्षम करें
- `DYLD_FORCE_FLAT_NAMESPACE`: Single-level bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolution paths
- `DYLD_INSERT_LIBRARIES`: किसी specific library को load करें
- `DYLD_PRINT_TO_FILE`: dyld debug को किसी file में लिखें
- `DYLD_PRINT_APIS`: libdyld API calls print करें
- `DYLD_PRINT_APIS_APP`: main द्वारा की गई libdyld API calls print करें
- `DYLD_PRINT_BINDINGS`: Bind किए जाने पर symbols print करें
- `DYLD_WEAK_BINDINGS`: Bind किए जाने पर केवल weak symbols print करें
- `DYLD_PRINT_CODE_SIGNATURES`: Code signature registration operations print करें
- `DYLD_PRINT_DOFS`: Load किए जाने पर D-Trace object format sections print करें
- `DYLD_PRINT_ENV`: dyld द्वारा देखे गए env को print करें
- `DYLD_PRINT_INTERPOSTING`: Interposting operations print करें
- `DYLD_PRINT_LIBRARIES`: Load की गई libraries print करें
- `DYLD_PRINT_OPTS`: Load options print करें
- `DYLD_REBASING`: Symbol rebasing operations print करें
- `DYLD_RPATHS`: @rpath के expansions print करें
- `DYLD_PRINT_SEGMENTS`: Mach-O segments की mappings print करें
- `DYLD_PRINT_STATISTICS`: Timing statistics print करें
- `DYLD_PRINT_STATISTICS_DETAILS`: Detailed timing statistics print करें
- `DYLD_PRINT_WARNINGS`: Warning messages print करें
- `DYLD_SHARED_CACHE_DIR`: Shared library cache के लिए उपयोग किया जाने वाला path
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Closures enable करें

Something like का उपयोग करके और अधिक ढूंढना संभव है:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
या [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) से dyld project डाउनलोड करके फ़ोल्डर के अंदर चलाएँ:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (process startup path)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (process/security configuration)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (kernel side of `execve`, loading dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (`dyld_all_image_infos` structure)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
