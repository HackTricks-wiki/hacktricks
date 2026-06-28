# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

The header has the **magic** bytes followed by the **number** of **archs** the file **contains** (`nfat_arch`) and each arch will have a `fat_arch` struct.

Check it with:

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

> [!TIP]
> When triaging malware or suspicious apps, don't stop after `file` reports the "best" architecture. A universal binary can hide different imports, load commands or compiler metadata in each slice, so enumerate **all** the slices first and then inspect them independently:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
हाल के macOS SDKs `<mach-o/utils.h>` में `macho_for_each_slice()` और `macho_best_slice()` जैसे helpers भी expose करते हैं। दूसरा dyld/kernel क्या load करेगा उसे emulate करने के लिए उपयोगी है, लेकिन scanners को फिर भी हर slice iterate करनी चाहिए ताकि arch-specific content miss न हो।

## **Mach-O Header**

header में file के बारे में basic information होती है, जैसे इसे Mach-O file के रूप में identify करने के लिए magic bytes और target architecture की information। आप इसे यहाँ पा सकते हैं: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Types

विभिन्न file types होते हैं, आप उन्हें [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) में परिभाषित पा सकते हैं। सबसे महत्वपूर्ण ये हैं:

- `MH_OBJECT`: Relocatable object file (compilation के intermediate products, अभी executables नहीं)।
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (XNU में अब समर्थित नहीं)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". gcc में -bundle का उपयोग करके generated और `NSBundle` या `dlopen` द्वारा explicitly loaded।
- `MH_DYSM`: Companion `.dSym` file (debugging के लिए symbols वाली file)।
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

सोर्स कोड में libraries लोड करने के लिए उपयोगी कई flags भी परिभाषित किए गए हैं:

- `MH_NOUNDEFS`: No undefined references (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: There is a section with thread local variables
- `MH_NO_HEAP_EXECUTION`: No execution for heap/data pages
- `MH_HAS_OBJC`: Binary has oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Load commands**

**memory में file का layout** यहां specify किया जाता है, जिसमें **symbol table का location**, execution start पर main thread का context, और required **shared libraries** शामिल हैं। binary को memory में load करने की process के लिए dynamic loader **(dyld)** को instructions दी जाती हैं।

यह **load_command** structure का use करता है, जो mentioned **`loader.h`** में defined है:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
लगभग **50 अलग-अलग प्रकार** के load commands होते हैं जिन्हें system अलग-अलग तरीके से handle करता है। सबसे common हैं: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, और `LC_CODE_SIGNATURE`।

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basically, इस प्रकार का Load Command **यह define करता है कि \_\_TEXT** (executable code) **और \_\_DATA** (process के लिए data) **segments को कैसे load करना है** binary execute होने पर **Data section में indicated offsets** के अनुसार।

ये commands **segments define** करते हैं जिन्हें process execute होने पर उसकी **virtual memory space** में **mapped** किया जाता है।

**Segments के different types** होते हैं, जैसे **\_\_TEXT** segment, जो program का executable code रखता है, और **\_\_DATA** segment, जिसमें process द्वारा इस्तेमाल किया जाने वाला data होता है। ये **segments Mach-O file के data section में located** होते हैं।

**हर segment** को आगे **multiple sections** में **divide** किया जा सकता है। **Load command structure** में उनके respective segment के अंदर **इन sections की information** होती है।

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
<strong>	uint32_t	nsects;		/* segment में sections की संख्या */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Segment header का example:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

यह header **उन sections की संख्या define करता है जिनके headers इसके बाद आते हैं**:
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

अगर आप **section offset** (0x37DC) + **offset** जोड़ते हैं जहां **arch starts** होता है, इस मामले में `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**command line** से **headers information** प्राप्त करना भी संभव है:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** यह kernel को **address zero** को **map** करने का निर्देश देता है ताकि इसे **read, write, या execute** न किया जा सके। structure में `maxprot` और `minprot` variables को zero पर set किया जाता है ताकि यह दिखाया जा सके कि इस page पर **कोई read-write-execute rights नहीं हैं**।
- यह allocation **NULL pointer dereference vulnerabilities** को **mitigate** करने के लिए important है। ऐसा इसलिए है क्योंकि XNU एक hard page zero enforce करता है, जो memory के पहले page (सिर्फ पहले) को inaccessible बनाता है (i386 को छोड़कर)। एक binary इस requirement को fulfill कर सकती है `-pagezero_size` का उपयोग करके एक छोटा \_\_PAGEZERO craft करके, जिससे पहले 4k को cover किया जा सके, और बाकी 32bit memory को user और kernel mode दोनों में accessible रखा जा सके।
- **`__TEXT`**: इसमें **executable** **code** होता है, जिसमें **read** और **execute** permissions होती हैं (writable नहीं)**.** इस segment की common sections:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Dynamic library loading process के दौरान involved
- `__unwind_info`: Stack unwind data.
- ध्यान दें कि यह सारा content signed होता है लेकिन executable के रूप में भी marked होता है (जिससे उन sections के exploitation के लिए और options मिलते हैं जिन्हें necessarily इस privilege की जरूरत नहीं होती, जैसे string dedicated sections)।
- **`__DATA`**: इसमें ऐसा data होता है जो **readable** और **writable** होता है (कोई executable नहीं)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Read-only data होना चाहिए (असल में नहीं)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (जो initialize की गई हैं)
- `__bss`: Static variables (जो initialize नहीं की गई हैं)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime द्वारा used information
- **`__DATA_CONST`**: \_\_DATA.\_\_const की constant होने की guarantee नहीं होती (write permissions), और न ही other pointers और GOT की। यह section `mprotect` का उपयोग करके `__const`, कुछ initializers और GOT table (once resolved) को **read only** बनाता है।
- **`__AUTH` / `__AUTH_CONST`**: Recent Apple Silicon binaries में common। ये segments ऐसे pointers रखते हैं जिन्हें load या use time पर authenticate करना होता है (उदाहरण के लिए `__auth_got`)। अगर rebinding, hook या import-patching trick सिर्फ legacy `__got` / `__la_symbol_ptr` sections को check करती है, तो modern `arm64e` binaries में वह real call sites miss कर सकती है। इन sections के बारे में अधिक details के लिए [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।
- **`__LINKEDIT`**: इसमें linker (dyld) के लिए information होती है, जैसे symbol, string, और relocation table entries। यह उन contents के लिए एक generic container है जो न तो `__TEXT` में होते हैं और न ही `__DATA` में, और इसका content अन्य load commands में described होता है।
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Functions के start addresses की table
- Data In Code: \_\_text में data islands
- SYmbol Table: Binary में symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: इसमें Objective-C runtime द्वारा used information होती है। हालांकि यह information \_\_DATA segment में भी मिल सकती है, various \_\_objc\_\* sections के भीतर।
- **`__RESTRICT`**: बिना content वाला segment, जिसमें केवल एक section होता है जिसका नाम **`__restrict`** है (वह भी खाली), जो सुनिश्चित करता है कि binary चलाते समय यह DYLD environmental variables को ignore करेगा।

जैसा code में देखा जा सकता था, **segments flags** भी support करते हैं (हालांकि इनका बहुत ज्यादा use नहीं होता):

- `SG_HIGHVM`: Core only (used नहीं)
- `SG_FVMLIB`: Used नहीं
- `SG_NORELOC`: Segment में relocation नहीं है
- `SG_PROTECTED_VERSION_1`: Encryption। उदाहरण के लिए Finder द्वारा text `__TEXT` segment को encrypt करने के लिए used।

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** में **entryoff attribute** में entrypoint होता है। Load time पर, **dyld** बस इस value को binary के (in-memory) **base** में **add** करता है, फिर binary के code execution को शुरू करने के लिए इस instruction पर **jump** करता है।

**`LC_UNIXTHREAD`** में वे values होती हैं जो main thread शुरू करते समय registers में होनी चाहिए। यह पहले ही deprecated हो चुका था लेकिन **`dyld`** अभी भी इसका use करता है। इसके द्वारा set किए गए registers की values इनसे देखना संभव है:
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


इसमें **Macho-O file** के **code signature** की जानकारी होती है। इसमें केवल एक **offset** होता है जो **signature blob** की ओर **point** करता है। यह आमतौर पर file के बिल्कुल अंत में होता है।\
हालांकि, आप इस section के बारे में कुछ जानकारी [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) और इस [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) में पा सकते हैं।

### **`LC_ENCRYPTION_INFO[_64]`**

binary encryption के लिए support। हालांकि, यदि कोई attacker process को compromise करने में सफल हो जाता है, तो वह memory को unencrypted dump कर सकेगा।

### **`LC_LOAD_DYLINKER`**

**dynamic linker executable** का **path** होता है जो shared libraries को process address space में map करता है। **value हमेशा `/usr/lib/dyld`** पर set होती है। यह ध्यान रखना महत्वपूर्ण है कि macOS में, dylib mapping **user mode** में होती है, kernel mode में नहीं।

### **`LC_IDENT`**

पुराना है, लेकिन जब panic पर dumps generate करने के लिए configured होता है, तो एक Mach-O core dump बनाया जाता है और kernel version को `LC_IDENT` command में set किया जाता है।

### **`LC_UUID`**

Random UUID। यह सीधे तौर पर किसी चीज़ के लिए useful नहीं है, लेकिन XNU इसे बाकी process info के साथ cache करता है। इसे crash reports में इस्तेमाल किया जा सकता है।

### **`LC_BUILD_VERSION`**

Modern binaries आमतौर पर यह command carry करते हैं ताकि **target platform**, **minimum OS version**, **SDK version**, और वैकल्पिक रूप से उस slice को build करने में इस्तेमाल किए गए **tool versions** declare किए जा सकें। offensive/reversing perspective से यह बहुत उपयोगी है sample कैसे build हुआ था यह fingerprint करने और जल्दी से ऐसे weird universal binaries spot करने के लिए जहाँ एक slice किसी अलग SDK या deployment target के साथ compile किया गया हो। पुराने binaries इसके बजाय `LC_VERSION_MIN_*` का उपयोग कर सकते हैं।
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

dyld को प्रोसेस execute होने से पहले environment variables indicate करने की अनुमति देता है। यह बहुत dangerous हो सकता है क्योंकि यह process के अंदर arbitrary code execute करने की अनुमति दे सकता है, इसलिए यह load command केवल dyld build में `#define SUPPORT_LC_DYLD_ENVIRONMENT` के साथ इस्तेमाल होता है और आगे केवल `DYLD_..._PATH` form वाली variables तक processing को restrict करता है, जो load paths specify करती हैं।

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains अक्सर export/bind/rebase metadata को पुराने `LC_DYLD_INFO[_ONLY]` opcodes पर only rely करने के बजाय इन commands में store करती हैं। दोनों `linkedit_data_command` entries हैं जो **`__LINKEDIT`** की ओर point करती हैं:

- **`LC_DYLD_EXPORTS_TRIE`**: Image द्वारा exported symbols के साथ compact trie।
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains जिनका उपयोग dyld rebases और binds apply करने के लिए करता है। Apple Silicon पर यही वह जगह भी है जहाँ आपको कई modern authenticated pointer fixups मिलेंगे।

यह metadata imports/exports reconstruct करते समय, यह समझने में कि `@rpath`-loaded dependency ने जिस तरह resolve किया वह क्यों किया, या यह पता लगाने में कि modern `arm64e` target पर hook/rebinding attempt क्यों fail हुआ, बहुत उपयोगी है। `dyld_info` को **cache-only dylib paths** के खिलाफ भी इस्तेमाल किया जा सकता है जो disk पर standalone files के रूप में मौजूद नहीं होते, जो modern macOS पर बहुत उपयोगी है जहाँ कई system libraries केवल shared cache में रहती हैं।
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

यह आधुनिक load command मुख्यतः **kernel collections / kernelcache-style filesets** का निरीक्षण करते समय प्रासंगिक होती है। एक single standalone image को represent करने के बजाय, outer Mach-O एक container की तरह काम करता है और हर `LC_FILESET_ENTRY` एक embedded Mach-O की ओर point करता है, जिसमें अपना path-like **entry id**, VM address और file offset होता है। अगर आप modern macOS/iOS kernel components को reverse कर रहे हैं, तो यह command अक्सर top-level container और उस actual image के बीच bridge होती है जिसे आप extract या disassemble करना चाहते हैं।
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

यह load command एक **dynamic** **library** dependency का वर्णन करता है, जो **loader** (dyld) को **उस library को load और link करने** का निर्देश देता है। Mach-O binary को जितनी libraries की आवश्यकता होती है, **हर library के लिए** एक `LC_LOAD_DYLIB` load command होता है।

- यह load command **`dylib_command`** type की एक structure है (जिसमें एक struct dylib होता है, जो actual dependent dynamic library का वर्णन करता है):
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

- **DiskArbitration**: USB drives की monitoring
- **AVFoundation:** audio और video capture
- **CoreWLAN**: Wifi scans.

> [!TIP]
> एक Mach-O binary में एक या **more** **constructors** हो सकते हैं, जो **LC_MAIN** में specified address से **before** **executed** होंगे।\
> किसी भी constructors के offsets **\_\_DATA_CONST** segment के **\_\_mod_init_func** section में रखे जाते हैं।

## **Mach-O Data**

File के core में data region होती है, जो load-commands region में defined कई segments से बनी होती है। **हर segment के भीतर कई तरह के data sections हो सकते हैं**, और हर section **उस type से संबंधित code या data** hold करता है।

> [!TIP]
> data मूल रूप से वह part है जिसमें वह सारी **information** होती है जो load commands **LC_SEGMENTS_64** द्वारा loaded की जाती है

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

इसमें शामिल है:

- **Function table:** जो program functions के बारे में information रखती है।
- **Symbol table**: जिसमें binary द्वारा used external function की information होती है
- इसमें internal function, variable names आदि भी हो सकते हैं।

इसे check करने के लिए आप [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool का use कर सकते हैं:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

या cli से:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

`__TEXT` segment (r-x) में:

- `__objc_classname`: Class names (strings)
- `__objc_methname`: Method names (strings)
- `__objc_methtype`: Method types (strings)

`__DATA` segment (rw-) में:

- `__objc_classlist`: सभी Objetive-C classes के pointers
- `__objc_nlclslist`: Non-Lazy Objective-C classes के pointers
- `__objc_catlist`: Categories के लिए Pointer
- `__objc_nlcatlist`: Non-Lazy Categories के लिए Pointer
- `__objc_protolist`: Protocols list
- `__objc_const`: Constant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
