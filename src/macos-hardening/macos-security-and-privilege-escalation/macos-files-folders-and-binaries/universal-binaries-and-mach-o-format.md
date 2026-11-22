# macOS Universal binaries और Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

macOS **Mach-O** executable format का इस्तेमाल करता है। एक **universal**, या fat, binary में एक ही file में कई architecture-specific Mach-O slices होते हैं। Apple के open-source `fat.h` और `loader.h` headers इस पेज पर बताए गए structures और constants को define करते हैं। <sup>[[5]](#references)</sup>

एक Mach-O image इन हिस्सों से बनी होती है:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

इस file को खोजें: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header में **magic** bytes के बाद file में मौजूद **archs** की **संख्या** (`nfat_arch`) होती है और हर arch में एक `fat_arch` struct होता है।

इसे इस तरह जाँचें:

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

या [Mach-O View](https://sourceforge.net/projects/machoview/) tool का इस्तेमाल करके:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

जैसा कि आप सोच रहे होंगे, आम तौर पर 2 architectures के लिए compiled universal binary का आकार सिर्फ़ 1 arch के लिए compiled binary से **दोगुना** होता है।

> [!TIP]
> Malware या suspicious apps की triage करते समय, `file` द्वारा "best" architecture बताए जाने के बाद जाँच बंद न करें। Universal binary की हर slice में अलग-अलग imports, load commands या compiler metadata हो सकते हैं, इसलिए पहले **सभी** slices की सूची बनाएँ और फिर हर एक की स्वतंत्र रूप से जाँच करें:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

हाल के macOS SDKs में `<mach-o/utils.h>` के अंतर्गत `macho_for_each_slice()` और `macho_best_slice()` भी उपलब्ध हैं। Apple Silicon पर, macOS 15 से पहले `macho_best_slice()` किसी चलने योग्य third-party `arm64` binary के लिए गलत तरीके से `EBADARCH` लौटा सकता था; macOS 15 में API को ठीक किया गया। हर slice की सूची बनाने के लिए `macho_for_each_slice()` या `lipo -archs` का उपयोग करें; `best-slice` lookup विफल होने को इस बात का प्रमाण न मानें कि कोई slice चल नहीं सकता।<sup>[[1]](#references)[[7]](#references)</sup>

### slices के बीच code signatures की तुलना करें

Universal binary में हर architecture का अपना CodeDirectory और CDHash होता है। किसी signed executable या privileged helper का audit करते समय, **हर slice के signature** की जाँच करें। अलग CDHash होना सामान्य है; इसके बजाय signing identity, CodeDirectory flags और entitlements की तुलना करें।<sup>[[8]](#references)</sup>

CDHash से मेल खाने वाली policies में, एक hash केवल एक architecture-specific execution path की पहचान करता है। Apple slices की गणना करने और हर एक की जाँच के लिए `codesign --arch` का उपयोग करने की अनुशंसा करता है।<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

हस्ताक्षर संरचना और validation की जानकारी के लिए, [macOS Code Signing](../macos-security-protections/macos-code-signing.md) देखें।

## **Mach-O Header**

Header में फ़ाइल की बुनियादी जानकारी होती है, जैसे इसे Mach-O फ़ाइल के रूप में पहचानने वाले magic bytes और target architecture की जानकारी। आप इसे यहाँ ढूँढ़ सकते हैं: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

अलग-अलग फ़ाइल प्रकार होते हैं, इन्हें आप [**उदाहरण के लिए यहाँ source code में**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) परिभाषित पा सकते हैं। सबसे महत्वपूर्ण प्रकार हैं:

- `MH_OBJECT`: Relocatable object file (कंपाइलेशन के मध्यवर्ती उत्पाद, अभी executable नहीं)।
- `MH_EXECUTE`: Executable फ़ाइलें।
- `MH_FVMLIB`: Fixed VM library फ़ाइल।
- `MH_CORE`: कोड डंप
- `MH_PRELOAD`: Preloaded executable फ़ाइल (अब XNU में समर्थित नहीं)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin फ़ाइलें"। gcc में -bundle का उपयोग करके बनाई जाती हैं और `NSBundle` या `dlopen` द्वारा स्पष्ट रूप से लोड की जाती हैं।
- `MH_DSYM`: Companion `.dSYM` फ़ाइल (डिबगिंग के लिए symbols वाली फ़ाइल)।
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

सोर्स कोड में libraries लोड करने के लिए उपयोगी कई flags भी परिभाषित हैं:

- `MH_NOUNDEFS`: कोई undefined reference नहीं (पूरी तरह linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references पहले से bound हैं।
- `MH_SPLIT_SEGS`: File को r/o और r/w segments में विभाजित करता है।
- `MH_WEAK_DEFINES`: Binary में weak defined symbols हैं
- `MH_BINDS_TO_WEAK`: Binary weak symbols का उपयोग करता है
- `MH_ALLOW_STACK_EXECUTION`: Stack को executable बनाता है
- `MH_NO_REEXPORTED_DYLIBS`: Library में LC_REEXPORT commands नहीं हैं
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables वाला एक section मौजूद है
- `MH_NO_HEAP_EXECUTION`: Heap/data pages पर execution नहीं
- `MH_HAS_OBJC`: Binary में Objective-C sections हैं
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Shared library cache में मौजूद dylibs/frameworks पर उपयोग किया जाता है।

## **Mach-O Load commands**

यहाँ **memory में file का layout** निर्दिष्ट किया जाता है, जिसमें **symbol table का स्थान**, execution शुरू होने पर main thread का context और आवश्यक **shared libraries** शामिल हैं। Dynamic loader **(dyld)** को binary को memory में load करने की प्रक्रिया के निर्देश दिए जाते हैं।

इसमें उल्लिखित **`loader.h`** में परिभाषित **load_command** structure का उपयोग किया गया है:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

There are about **50 different types of load commands** जिन्हें system अलग-अलग तरीके से handle करता है। इनमें सबसे आम हैं: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, और `LC_CODE_SIGNATURE`।

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> मूल रूप से, इस प्रकार का Load Command यह तय करता है कि binary के execute होने पर **Data section में दिए गए offsets** के अनुसार **\_\_TEXT** (executable code) और **\_\_DATA** (process के लिए data) **segments** को कैसे load करना है।

ये commands उन **segments को define** करते हैं जिन्हें process के execute होने पर उसकी **virtual memory space** में **map** किया जाता है।

**अलग-अलग प्रकार** के segments होते हैं, जैसे **\_\_TEXT** segment, जिसमें program का executable code होता है, और **\_\_DATA** segment, जिसमें process द्वारा उपयोग किया जाने वाला data होता है। ये **segments, Mach-O file के data section में स्थित होते हैं**।

**हर segment** को आगे कई **sections** में **विभाजित** किया जा सकता है। **Load command structure** में संबंधित segment के **इन sections** के बारे में **जानकारी** होती है।

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

Segment header का उदाहरण:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

यह header उन **sections की संख्या बताता है जिनके headers इसके बाद आते हैं**:

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

अगर आप **section offset** (0x37DC) को उस **offset** में जोड़ते हैं जहाँ **arch starts** होता है, तो इस मामले में `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line** से **headers information** प्राप्त करना भी संभव है:

```bash
otool -lv /bin/ls
```

Common segments जो इस cmd द्वारा load किए जाते हैं:

- **`__PAGEZERO`:** यह kernel को **address zero को map** करने का निर्देश देता है, ताकि इसे **read, write या execute न किया जा सके**। Structure में maxprot और minprot variables को zero पर set किया जाता है, जो बताता है कि **इस page पर read-write-execute अधिकार नहीं हैं**।
  - यह allocation **NULL pointer dereference vulnerabilities को mitigate** करने के लिए महत्वपूर्ण है। ऐसा इसलिए है क्योंकि XNU एक hard page zero लागू करता है, जो memory के पहले page (केवल पहले page) को inaccessible बनाता है (i386 को छोड़कर)। एक binary छोटा \_\_PAGEZERO बनाकर (`-pagezero_size` का उपयोग करके) पहले 4k को cover कर सकती है और बाकी 32bit memory को user और kernel mode, दोनों में accessible रखकर इस requirement को पूरा कर सकती है।
- **`__TEXT`**: इसमें **read** और **execute** permissions वाला **executable code** होता है (writable नहीं)**।** इस segment के आम sections:
  - `__text`: Compiled binary code
  - `__const`: Constant data (read only)
  - `__[c/u/os_log]string`: C, Unicode या os logs के string constants
  - `__stubs` और `__stubs_helper`: Dynamic library loading process के दौरान काम आते हैं
  - `__unwind_info`: Stack unwind data।
  - ध्यान दें कि यह सारा content signed होता है, लेकिन executable के रूप में भी marked होता है। इससे उन sections के exploitation के लिए अधिक विकल्प मिलते हैं जिन्हें इस privilege की आवश्यकता नहीं होती, जैसे strings के लिए dedicated sections।
- **`__DATA`**: इसमें **readable** और **writable** data होता है (executable नहीं)**।**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Non lazy (load के समय bind होने वाला) symbol pointer
  - `__la_symbol_ptr`: Lazy (उपयोग के समय bind होने वाला) symbol pointer
  - `__const`: Read-only data होना चाहिए (वास्तव में ऐसा नहीं है)
  - `__cfstring`: CoreFoundation strings
  - `__data`: Global variables (जिन्हें initialize किया गया है)
  - `__bss`: Static variables (जिन्हें initialize नहीं किया गया है)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, आदि): Objective-C runtime द्वारा उपयोग की जाने वाली जानकारी
- **`__DATA_CONST`**: \_\_DATA.\_\_const के constant होने की गारंटी नहीं है (इस पर write permissions हो सकती हैं), और न ही अन्य pointers तथा GOT की। यह section `mprotect` का उपयोग करके `__const`, कुछ initializers और GOT table (resolve हो जाने के बाद) को **read only** बनाता है।
- **`__AUTH` / `__AUTH_CONST`**: हाल के Apple Silicon binaries में आम हैं। इन segments में ऐसे pointers होते हैं जिन्हें load या उपयोग के समय authenticate करना आवश्यक होता है (उदाहरण के लिए `__auth_got`)। यदि कोई rebinding, hook या import-patching trick केवल legacy `__got` / `__la_symbol_ptr` sections की जाँच करती है, तो वह modern `arm64e` binaries में असली call sites को miss कर सकती है। इन sections के बारे में अधिक जानकारी के लिए [यह page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।
- **`__LINKEDIT`**: इसमें linker (dyld) के लिए जानकारी होती है, जैसे symbol, string और relocation table entries। यह ऐसे content के लिए एक generic container है जो `__TEXT` या `__DATA` में नहीं होता; इसके content का वर्णन अन्य load commands में किया जाता है।
  - dyld जानकारी: Rebase, Non-lazy/lazy/weak binding opcodes और export info
  - Functions starts: Functions के start addresses की table
  - Data In Code: \_\_text में data islands
  - SYmbol Table: Binary में symbols
  - Indirect Symbol Table: Pointer/stub symbols
  - String Table
  - Code Signature
- **`__OBJC`**: इसमें Objective-C runtime द्वारा उपयोग की जाने वाली जानकारी होती है। हालाँकि, यह जानकारी \_\_DATA segment में, विभिन्न \_\_objc\_\* sections के भीतर भी मिल सकती है।
- **`__RESTRICT`**: ऐसा segment जिसमें कोई content नहीं होता और इसमें केवल एक section **`__restrict`** होता है (यह भी खाली होता है)। यह सुनिश्चित करता है कि binary चलाते समय DYLD environmental variables को ignore किया जाएगा।

जैसा कि code में देखा जा सकता है, **segments flags को भी support करते हैं** (हालाँकि इनका बहुत अधिक उपयोग नहीं होता):

- `SG_HIGHVM`: केवल Core के लिए (उपयोग नहीं होता)
- `SG_FVMLIB`: उपयोग नहीं होता
- `SG_NORELOC`: Segment में relocation नहीं है
- `SG_PROTECTED_VERSION_1`: Encryption। उदाहरण के लिए, Finder इसका उपयोग text `__TEXT` segment को encrypt करने के लिए करता है।

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** में **entryoff attribute में entrypoint होता है।** Load time पर, **dyld** इस value को binary के (memory में मौजूद) **base में जोड़ता है**, फिर binary के code का execution शुरू करने के लिए इस instruction पर **jump करता है**।

**`LC_UNIXTHREAD`** में वे values होती हैं जो main thread शुरू होने पर registers में होनी चाहिए। यह पहले ही deprecated हो चुका है, लेकिन **`dyld`** अब भी इसका उपयोग करता है। इससे set किए गए registers की values इस तरह देखी जा सकती हैं:

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


इसमें **Mach-O file के code signature** की जानकारी होती है। इसमें केवल एक **offset** होता है, जो **signature blob** की ओर **point** करता है। यह आमतौर पर file के बिल्कुल अंत में होता है।\
इस section के बारे में अधिक जानकारी [**इस blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) और [**इस gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) में मिल सकती है।<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption के लिए support। हालांकि, निश्चित रूप से, अगर कोई attacker process को compromise करने में कामयाब हो जाता है, तो वह memory को unencrypted dump कर सकता है।

### **`LC_LOAD_DYLINKER`**

इसमें **dynamic linker executable का path** होता है, जो shared libraries को process address space में map करता है। **यह value हमेशा `/usr/lib/dyld` पर set होती है**। यह ध्यान रखना महत्वपूर्ण है कि macOS में, dylib mapping **user mode** में होती है, kernel mode में नहीं।

### **`LC_IDENT`**

Obsolete है, लेकिन panic पर dumps generate करने के लिए configure किए जाने पर, Mach-O core dump बनाया जाता है और `LC_IDENT` command में kernel version set किया जाता है।

### **`LC_UUID`**

Random UUID। यह सीधे किसी काम के लिए उपयोगी नहीं है, लेकिन XNU इसे बाकी process info के साथ cache करता है। इसका उपयोग crash reports में किया जा सकता है।

### **`LC_BUILD_VERSION`**

आधुनिक binaries में आमतौर पर यह command होती है, जो **target platform**, **minimum OS version**, **SDK version**, और वैकल्पिक रूप से उस slice को build करने के लिए इस्तेमाल किए गए **tool versions** घोषित करती है। Offensive/reversing के नज़रिए से, यह पता लगाने में बहुत उपयोगी है कि कोई sample कैसे बनाया गया था और ऐसे अजीब universal binaries को जल्दी पहचानने में भी, जिनका एक slice किसी अलग SDK या deployment target के साथ compile किया गया हो। पुराने binaries में इसकी जगह अब भी `LC_VERSION_MIN_*` का उपयोग हो सकता है।

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

प्रोसेस execute होने से पहले dyld के लिए environment variables निर्दिष्ट करने की अनुमति देता है। यह काफी खतरनाक हो सकता है, क्योंकि इससे प्रोसेस के अंदर arbitrary code execute हो सकता है। इसलिए यह load command केवल `#define SUPPORT_LC_DYLD_ENVIRONMENT` के साथ build किए गए dyld में उपयोग होता है, और processing को आगे केवल `DYLD_..._PATH` के रूप वाले variables तक सीमित करता है, जो load paths निर्दिष्ट करते हैं।

### **`LC_DYLD_EXPORTS_TRIE` और `LC_DYLD_CHAINED_FIXUPS`**

हाल के toolchains अक्सर केवल पुराने `LC_DYLD_INFO[_ONLY]` opcodes पर निर्भर रहने के बजाय, इन commands में export/bind/rebase metadata store करते हैं। दोनों `linkedit_data_command` entries हैं, जो **`__LINKEDIT`** के भीतर के डेटा की ओर संकेत करती हैं:

- **`LC_DYLD_EXPORTS_TRIE`**: Image द्वारा export किए गए symbols वाली compact trie।
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld द्वारा rebases और binds लागू करने के लिए उपयोग की जाने वाली per-segment fixup chains। Apple Silicon पर आपको कई modern authenticated pointer fixups भी यहीं मिलेंगे।

यह metadata imports/exports को reconstruct करने, यह समझने कि `@rpath` से load हुई dependency किस तरह resolve हुई, या यह पता लगाने में बहुत उपयोगी है कि modern `arm64e` target पर hook/rebinding का प्रयास क्यों विफल हुआ। `dyld_info` का उपयोग उन **cache-only dylib paths** पर भी किया जा सकता है, जो disk पर standalone files के रूप में मौजूद नहीं हैं। यह modern macOS में बहुत उपयोगी है, जहाँ कई system libraries केवल shared cache में रहती हैं।<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

यह modern load command मुख्यतः **kernel collections / kernelcache-style filesets** की जाँच करते समय प्रासंगिक होता है। किसी एक standalone image को दर्शाने के बजाय, बाहरी Mach-O एक container की तरह काम करता है और हर `LC_FILESET_ENTRY` अपने path-जैसे **entry id**, VM address और file offset वाले embedded Mach-O की ओर संकेत करता है। अगर आप modern macOS/iOS kernel components को reverse कर रहे हैं, तो यह command अक्सर top-level container और उस वास्तविक image के बीच कड़ी का काम करता है जिसे आप extract या disassemble करना चाहते हैं।

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

व्यावहारिक extraction workflows के लिए, [macOS kernel extensions और kernelcache के बारे में यह दूसरा पेज देखें](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

यह load command एक **dynamic** **library** dependency का वर्णन करता है, जो **loader** (dyld) को **उस library को load और link करने का निर्देश देता है**। Mach-O binary को जिन libraries की ज़रूरत होती है, उनमें से **हर library के लिए** एक `LC_LOAD_DYLIB` load command होता है।

- यह load command **`dylib_command`** प्रकार का एक structure है (इसमें एक struct dylib होता है, जो वास्तविक dependent dynamic library का वर्णन करता है):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t संगतता संस्करण; / लाइब्रेरी का संगतता संस्करण नंबर /](<../../../images/image (486).png>)

आप यह जानकारी CLI से भी प्राप्त कर सकते हैं:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

कुछ संभावित malware-संबंधित libraries हैं:

- **DiskArbitration**: USB drives की निगरानी
- **AVFoundation:** Audio और video capture करना
- **CoreWLAN**: WiFi scans।

> [!TIP]
> एक Mach-O binary में एक या **अधिक** **constructors** हो सकते हैं, जो **LC_MAIN** में निर्दिष्ट address से **पहले** **execute** होंगे।\
> किसी भी constructor के offsets, **\_\_DATA_CONST** segment के **\_\_mod_init_func** section में रखे जाते हैं।

## **Mach-O Data**

File के केंद्र में data region होता है, जो load-commands region में परिभाषित कई segments से बना होता है। **हर segment में विभिन्न प्रकार के data sections हो सकते हैं**, और हर section में किसी खास type का **code या data** होता है।

> [!TIP]
> Data मूल रूप से वह हिस्सा है जिसमें load commands **LC_SEGMENTS_64** द्वारा load की गई सारी **जानकारी** होती है।

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

इसमें शामिल हैं:

- **Function table:** इसमें program functions की जानकारी होती है।
- **Symbol table**: इसमें binary द्वारा उपयोग किए गए external function की जानकारी होती है।
- इसमें internal function, variable names और अन्य चीजें भी हो सकती हैं।

इसे जाँचने के लिए आप [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool का उपयोग कर सकते हैं:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

या CLI से:

```bash
size -m /bin/ls
```

### Appended data और reverse-parsed overlays

एक loader, किसी named Mach-O section के बजाय appended data में configuration रख सकता है। इसके बाद reverse parser, trailer marker को आधार बनाता है, उससे ठीक पहले stored size को पढ़ता है, और उस value का उपयोग करके उससे पहले वाले blob को locate और decrypt करता है। एक देखे गए universal loader ने XOR-encrypted downloader URL के लिए इस layout का उपयोग किया था:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

किसी अपरिचित binary को reverse करते समय, पहचानने योग्य end markers के आसपास के bytes की जाँच करें और यह मानने से पहले कि strings या configuration किसी load-command section का हिस्सा हैं, size की हर backward calculation का पता लगाएँ। Marker और XOR key इस sample के लिए विशिष्ट हैं; दोबारा इस्तेमाल की जा सकने वाली तकनीक self-describing trailer है।

## Objective-C के सामान्य sections

`__TEXT` segment (r-x) में:

- `__objc_classname`: Class के नाम (strings)
- `__objc_methname`: Method के नाम (strings)
- `__objc_methtype`: Method के types (strings)

`__DATA` segment (rw-) में:

- `__objc_classlist`: सभी Objective-C classes के pointers
- `__objc_nlclslist`: Non-Lazy Objective-C classes के pointers
- `__objc_catlist`: Categories के pointers
- `__objc_nlcatlist`: Non-Lazy Categories के pointers
- `__objc_protolist`: Protocols की सूची
- `__objc_const`: Constant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

यह भी देखें: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O slices उतने सीधे-सादे नहीं हैं, जितना आप सोचते होंगे](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [अपने Entitlements पढ़ना](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` और `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS stealer का नया संस्करण crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
- [7] [The Art of Mac Malware, Volume 2 — Binaries का विश्लेषण](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Code Signing के भीतर: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Apps और binaries को अनुमति देना और अस्वीकार करना](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
