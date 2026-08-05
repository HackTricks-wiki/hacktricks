# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## मूल जानकारी

Mac OS binaries आमतौर पर **universal binaries** के रूप में compiled होते हैं। एक **universal binary** एक ही file में **multiple architectures को support** कर सकता है।

ये binaries **Mach-O structure** का पालन करते हैं, जो मूल रूप से इनसे बना होता है:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

File को इस command से खोजें: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

Header में **magic** bytes के बाद file में **मौजूद archs की संख्या** (`nfat_arch`) होती है और प्रत्येक arch में एक `fat_arch` struct होगा।

इसे इस command से check करें:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

या [Mach-O View](https://sourceforge.net/projects/machoview/) tool का उपयोग करके:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

जैसा कि आप सोच सकते हैं, आमतौर पर 2 architectures के लिए compiled universal binary का **size**, केवल 1 arch के लिए compiled binary के **size से दोगुना** होता है।

> [!TIP]
> Malware या suspicious apps को triage करते समय, `file` द्वारा "best" architecture report किए जाने के बाद रुकें नहीं। एक universal binary प्रत्येक slice में अलग-अलग imports, load commands या compiler metadata छिपा सकता है। इसलिए पहले **सभी** slices को enumerate करें और फिर प्रत्येक का independently inspection करें:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recent macOS SDKs `<mach-o/utils.h>` में `macho_for_each_slice()` और `macho_best_slice()` जैसे helpers भी उपलब्ध कराते हैं। बाद वाला यह emulate करने के लिए उपयोगी है कि dyld/kernel क्या load करेगा, लेकिन scanners को हर slice पर iterate करना चाहिए ताकि arch-specific content छूट न जाए।<sup>[1]</sup>

## **Mach-O Header**

Header में file के बारे में basic information होती है, जैसे इसे Mach-O file के रूप में पहचानने के लिए magic bytes और target architecture की information। आप इसे यहां पा सकते हैं: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Mach-O फ़ाइल प्रकार

विभिन्न फ़ाइल प्रकार होते हैं, जिन्हें आप [**उदाहरण के लिए यहाँ source code में देख सकते हैं**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)। सबसे महत्वपूर्ण प्रकार ये हैं:

- `MH_OBJECT`: Relocatable object फ़ाइल (compilation के intermediate products, अभी executables नहीं)।
- `MH_EXECUTE`: Executable फ़ाइलें।
- `MH_FVMLIB`: Fixed VM library फ़ाइल।
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable फ़ाइल (अब XNU में supported नहीं है)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin फ़ाइलें"। gcc में -bundle का उपयोग करके generated और `NSBundle` या `dlopen` द्वारा explicitly loaded।
- `MH_DYSM`: Companion `.dSym` फ़ाइल (debugging के लिए symbols वाली फ़ाइल)।
- `MH_KEXT_BUNDLE`: Kernel Extensions।
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
या [Mach-O View](https://sourceforge.net/projects/machoview/) का उपयोग करके:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

source code libraries को load करने के लिए उपयोगी कई flags भी परिभाषित करता है:

- `MH_NOUNDEFS`: कोई undefined references नहीं (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references पहले से prebound हैं।
- `MH_SPLIT_SEGS`: File r/o और r/w segments में विभाजित है।
- `MH_WEAK_DEFINES`: Binary में weak defined symbols हैं
- `MH_BINDS_TO_WEAK`: Binary weak symbols का उपयोग करता है
- `MH_ALLOW_STACK_EXECUTION`: Stack को executable बनाता है
- `MH_NO_REEXPORTED_DYLIBS`: Library में LC_REEXPORT commands नहीं हैं
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables वाला एक section मौजूद है
- `MH_NO_HEAP_EXECUTION`: Heap/data pages के लिए execution नहीं है
- `MH_HAS_OBJC`: Binary में oBject-C sections हैं
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Shared library cache में मौजूद dylibs/frameworks पर उपयोग किया जाता है।

## **Mach-O Load commands**

**File का memory में layout** यहां निर्दिष्ट किया गया है। इसमें **symbol table का स्थान**, execution शुरू होने पर main thread का context और आवश्यक **shared libraries** का विवरण दिया गया है। Dynamic loader **(dyld)** को binary को memory में load करने की प्रक्रिया के बारे में instructions दिए जाते हैं।

यह उल्लिखित **`loader.h`** में परिभाषित **load_command** structure का उपयोग करता है:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
लगभग **50 अलग-अलग प्रकार के load commands** होते हैं, जिन्हें system अलग-अलग तरीके से handle करता है। सबसे common वाले हैं: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, और `LC_CODE_SIGNATURE`।

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> मूल रूप से, इस प्रकार का Load Command यह define करता है कि binary execute होने पर **Data section** में दिए गए **offsets** के अनुसार **\_\_TEXT** (executable code) और **\_\_DATA** (process के लिए data) **segments** को **कैसे load किया जाए**।

ये commands उन **segments को define** करते हैं जिन्हें process के execute होने पर उसकी **virtual memory space** में **map** किया जाता है।

**Segments** के **अलग-अलग प्रकार** होते हैं, जैसे **\_\_TEXT** segment, जिसमें program का executable code होता है, और **\_\_DATA** segment, जिसमें process द्वारा उपयोग किया जाने वाला data होता है। ये **segments Mach-O file के data section में स्थित होते हैं**।

**प्रत्येक segment** को आगे कई **sections** में **विभाजित** किया जा सकता है। **Load command structure** में संबंधित segment के भीतर मौजूद **इन sections के बारे में information** होती है।

Header में सबसे पहले आपको **segment header** मिलता है:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* segment name */
uint64_t	vmaddr;		/* memory address of this segment */
uint64_t	vmsize;		/* memory size of this segment */
uint64_t	fileoff;	/* file offset of this segment */
uint64_t	filesize;	/* amount to map from the file */
int32_t		maxprot;	/* maximum VM protection */
int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Segment header का example:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

यह header उन **sections की संख्या define करता है, जिनके headers इसके बाद दिखाई देते हैं**:
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
**section header** का उदाहरण:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

यदि आप **section offset** (0x37DC) को उस **offset** में जोड़ते हैं जहाँ **arch starts** होता है, इस मामले में `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line** से **headers information** प्राप्त करना भी संभव है:
```bash
otool -lv /bin/ls
```
इस cmd द्वारा load किए गए common segments:

- **`__PAGEZERO`:** यह kernel को **address zero** को **map** करने का निर्देश देता है, ताकि उसे **read**, **write** या **execute** न किया जा सके। Structure में maxprot और minprot variables को zero पर set किया जाता है, जो दर्शाता है कि **इस page पर कोई read-write-execute rights नहीं हैं**।
- यह allocation **NULL pointer dereference vulnerabilities को mitigate** करने के लिए महत्वपूर्ण है। ऐसा इसलिए है क्योंकि XNU एक hard page zero लागू करता है, जो सुनिश्चित करता है कि memory का पहला page (केवल पहला) inaccessible हो (i386 को छोड़कर)। एक binary छोटे \_\_PAGEZERO को craft करके यह requirement पूरी कर सकती है (`-pagezero_size` का उपयोग करके), ताकि पहले 4k को cover किया जा सके और बाकी 32bit memory user तथा kernel mode दोनों में accessible हो।
- **`__TEXT`**: इसमें **executable** **code** होता है, जिसमें **read** और **execute** permissions होती हैं (writable नहीं)**।** इस segment के common sections:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode या os logs के string constants
- `__stubs` और `__stubs_helper`: Dynamic library loading process के दौरान उपयोग किए जाते हैं
- `__unwind_info`: Stack unwind data।
- ध्यान दें कि यह पूरा content signed होता है, लेकिन executable के रूप में भी marked होता है (जिससे उन sections के exploitation के लिए अधिक options मिलते हैं जिन्हें आवश्यक रूप से इस privilege की जरूरत नहीं होती, जैसे string dedicated sections)।
- **`__DATA`**: इसमें ऐसा data होता है जो **readable** और **writable** है (executable नहीं)**।**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (load पर bind) symbol pointer
- `__la_symbol_ptr`: Lazy (use पर bind) symbol pointer
- `__const`: Read-only data होना चाहिए (वास्तव में नहीं)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (जो initialized हैं)
- `__bss`: Static variables (जो initialized नहीं हैं)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, आदि): Objective-C runtime द्वारा उपयोग की जाने वाली information
- **`__DATA_CONST`**: \_\_DATA.\_\_const के constant होने की guarantee नहीं है (write permissions), और न ही अन्य pointers तथा GOT की। यह section `mprotect` का उपयोग करके `__const`, कुछ initializers और GOT table (एक बार resolved होने के बाद) को **read only** बनाता है।
- **`__AUTH` / `__AUTH_CONST`**: Recent Apple Silicon binaries में common हैं। इन segments में वे pointers होते हैं जिन्हें load या use time पर authenticate किया जाना आवश्यक होता है (उदाहरण के लिए `__auth_got`)। यदि कोई rebinding, hook या import-patching trick केवल legacy `__got` / `__la_symbol_ptr` sections को check करती है, तो वह modern `arm64e` binaries में वास्तविक call sites को miss कर सकती है। इन sections के बारे में अधिक details के लिए [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।
- **`__LINKEDIT`**: इसमें linker (dyld) के लिए information होती है, जैसे symbol, string और relocation table entries। यह उन contents के लिए एक generic container है जो `__TEXT` या `__DATA` में नहीं होते और जिनका content अन्य load commands में describe किया जाता है।
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes और export info
- Functions starts: Functions के start addresses की table
- Data In Code: \_\_text में data islands
- SYmbol Table: Binary में symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: इसमें Objective-C runtime द्वारा उपयोग की जाने वाली information होती है। हालांकि यह information \_\_DATA segment में, विभिन्न \_\_objc\_\* sections के भीतर भी मिल सकती है।
- **`__RESTRICT`**: यह बिना content वाला एक segment है, जिसमें `__restrict` नाम का एक section होता है (यह भी empty है), जो सुनिश्चित करता है कि binary चलाते समय वह DYLD environmental variables को ignore करेगा।

जैसा कि code में देखा जा सकता है, **segments flags को भी support करते हैं** (हालांकि इनका बहुत अधिक उपयोग नहीं होता):

- `SG_HIGHVM`: Core only (उपयोग नहीं किया जाता)
- `SG_FVMLIB`: उपयोग नहीं किया जाता
- `SG_NORELOC`: Segment में कोई relocation नहीं है
- `SG_PROTECTED_VERSION_1`: Encryption। उदाहरण के लिए Finder द्वारा text `__TEXT` segment को encrypt करने के लिए उपयोग किया जाता है।

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** में **`entryoff attribute` में entrypoint होता है।** Load time पर, **dyld** इस value को binary के (in-memory) **base** में simply **add** करता है, फिर binary के code का execution शुरू करने के लिए इस instruction पर **jumps** करता है।

**`LC_UNIXTHREAD`** में वे values होती हैं जो main thread शुरू करते समय registers में होनी चाहिए। यह पहले ही deprecated हो चुका है, लेकिन **`dyld`** अभी भी इसका उपयोग करता है। इसके द्वारा set किए गए registers के **values** को यह command चलाकर देखा जा सकता है:
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


इसमें **Macho-O file के code signature** की जानकारी होती है। इसमें केवल एक **offset** होता है, जो **signature blob** की ओर **संकेत करता है**। यह आमतौर पर file के बिल्कुल अंत में होता है।\
हालांकि, आप इस section के बारे में कुछ जानकारी [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) और इस [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) में पा सकते हैं।<sup>[3][4]</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption के लिए support। हालांकि, यदि कोई attacker process को compromise करने में सफल हो जाता है, तो वह memory को unencrypted रूप में dump कर सकेगा।

### **`LC_LOAD_DYLINKER`**

इसमें **dynamic linker executable का path** होता है, जो shared libraries को process address space में map करता है। **value हमेशा `/usr/lib/dyld` पर set होती है**। यह ध्यान रखना महत्वपूर्ण है कि macOS में dylib mapping **user mode** में होती है, kernel mode में नहीं।

### **`LC_IDENT`**

यह obsolete है, लेकिन जब panic पर dumps generate करने के लिए configure किया जाता है, तो Mach-O core dump बनाया जाता है और kernel version को `LC_IDENT` command में set किया जाता है।

### **`LC_UUID`**

Random UUID। यह सीधे तौर पर किसी काम के लिए उपयोगी नहीं है, लेकिन XNU इसे बाकी process info के साथ cache करता है। इसका उपयोग crash reports में किया जा सकता है।

### **`LC_BUILD_VERSION`**

Modern binaries में आमतौर पर यह command मौजूद होती है, जो **target platform**, **minimum OS version**, **SDK version**, और वैकल्पिक रूप से उस slice को build करने के लिए उपयोग किए गए **tool versions** घोषित करती है। Offensive/reversing के दृष्टिकोण से, यह sample के build होने के तरीके को fingerprint करने और ऐसे अजीब universal binaries को तुरंत पहचानने के लिए बहुत उपयोगी है, जिनमें किसी एक slice को अलग SDK या deployment target के साथ compile किया गया हो। पुराने binaries में इसके बजाय अभी भी `LC_VERSION_MIN_*` का उपयोग किया जा सकता है।
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Process को execute करने से पहले dyld को environment variables indicate करने की अनुमति देता है। यह बहुत dangerous हो सकता है, क्योंकि इससे process के अंदर arbitrary code execute किया जा सकता है। इसलिए यह load command केवल `#define SUPPORT_LC_DYLD_ENVIRONMENT` के साथ build किए गए dyld में उपयोग किया जाता है और processing को केवल `DYLD_..._PATH` के रूप वाली variables तक सीमित करता है, जो load paths निर्दिष्ट करती हैं।

### **`LC_DYLD_EXPORTS_TRIE` और `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains अक्सर केवल पुराने `LC_DYLD_INFO[_ONLY]` opcodes पर निर्भर रहने के बजाय इन commands में export/bind/rebase metadata store करते हैं। दोनों `linkedit_data_command` entries हैं, जो **`__LINKEDIT`** के अंदर point करती हैं:

- **`LC_DYLD_EXPORTS_TRIE`**: Image द्वारा exported symbols वाली Compact trie।
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld द्वारा rebases और binds लागू करने के लिए उपयोग की जाने वाली per-segment fixup chains। Apple Silicon पर आपको कई modern authenticated pointer fixups भी यहीं मिलेंगे।

यह metadata imports/exports को reconstruct करते समय, यह समझने के लिए कि `@rpath`-loaded dependency किस तरह resolve हुई, या यह पता लगाने के लिए बहुत उपयोगी है कि modern `arm64e` target पर कोई hook/rebinding attempt क्यों विफल हुआ। **cache-only dylib paths** पर `dyld_info` का उपयोग भी किया जा सकता है, जो disk पर standalone files के रूप में मौजूद नहीं होते। यह modern macOS पर विशेष रूप से उपयोगी है, जहाँ कई system libraries केवल shared cache में रहती हैं।<sup>[2]</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

यह modern load command मुख्यतः **kernel collections / kernelcache-style filesets** का निरीक्षण करते समय प्रासंगिक होता है। किसी एक standalone image को दर्शाने के बजाय, बाहरी Mach-O एक container के रूप में कार्य करता है और प्रत्येक `LC_FILESET_ENTRY` अपने path-like **entry id**, VM address और file offset के साथ embedded Mach-O की ओर संकेत करता है। यदि आप modern macOS/iOS kernel components को reverse कर रहे हैं, तो यह command अक्सर top-level container और उस वास्तविक image के बीच bridge का काम करता है जिसे आप extract या disassemble करना चाहते हैं।
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
व्यावहारिक extraction workflows के लिए, [macOS kernel extensions और kernelcache के बारे में यह अन्य पेज देखें](../mac-os-architecture/macos-kernel-extensions.md)।

### **`LC_LOAD_DYLIB`**

यह load command एक **dynamic** **library** dependency का वर्णन करता है, जो **loader** (dyld) को उक्त **library को load और link** करने का निर्देश देता है। Mach-O binary के लिए आवश्यक **प्रत्येक library** के लिए एक `LC_LOAD_DYLIB` load command होता है।

- यह load command **`dylib_command`** प्रकार का structure है (जिसमें एक struct dylib होता है, जो वास्तविक dependent dynamic library का वर्णन करता है):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

आप यह जानकारी cli से भी प्राप्त कर सकते हैं:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
कुछ संभावित malware संबंधित libraries हैं:

- **DiskArbitration**: USB drives की निगरानी
- **AVFoundation:** audio और video capture करना
- **CoreWLAN**: Wifi scans।

> [!TIP]
> एक Mach-O binary में एक या **अधिक** **constructors** हो सकते हैं, जिन्हें **LC_MAIN** में निर्दिष्ट address से **पहले** **execute** किया जाएगा।\
> किसी भी constructors के offsets, **\_\_DATA_CONST** segment के **\_\_mod_init_func** section में रखे जाते हैं।

## **Mach-O Data**

File के केंद्र में data region होती है, जो load-commands region में परिभाषित कई segments से बनी होती है। **प्रत्येक segment के भीतर विभिन्न data sections रखे जा सकते हैं**, और प्रत्येक section में किसी type से संबंधित **code या data** होता है।

> [!TIP]
> Data मूल रूप से वह भाग है जिसमें **सभी information** होती है, जिसे load commands **LC_SEGMENTS_64** द्वारा load किया जाता है।

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

इसमें शामिल हैं:

- **Function table:** इसमें program functions की information होती है।
- **Symbol table**: इसमें binary द्वारा उपयोग किए गए external function की information होती है।
- इसमें internal function, variable names और अन्य चीज़ें भी शामिल हो सकती हैं।

इसे check करने के लिए आप [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool का उपयोग कर सकते हैं:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

या CLI से:
```bash
size -m /bin/ls
```
## Objective-C के सामान्य Sections

`__TEXT` segment (r-x) में:

- `__objc_classname`: Class names (strings)
- `__objc_methname`: Method names (strings)
- `__objc_methtype`: Method types (strings)

`__DATA` segment (rw-) में:

- `__objc_classlist`: सभी Objective-C classes के Pointers
- `__objc_nlclslist`: Non-Lazy Objective-C classes के Pointers
- `__objc_catlist`: Categories का Pointer
- `__objc_nlcatlist`: Non-Lazy Categories का Pointer
- `__objc_protolist`: Protocols की list
- `__objc_const`: Constant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O slices उतने सरल नहीं हैं, जितना आप सोच सकते हैं](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [अपने Entitlements को पढ़ना](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
