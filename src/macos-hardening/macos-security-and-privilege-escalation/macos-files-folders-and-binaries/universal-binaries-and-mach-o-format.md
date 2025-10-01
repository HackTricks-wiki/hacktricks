# macOS यूनिवर्सल बायनरी और Mach-O फॉर्मेट

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Mac OS के बायनरी आमतौर पर **यूनिवर्सल बायनरी** के रूप में कम्पाइल होते हैं। एक **यूनिवर्सल बायनरी** एक ही फ़ाइल में **कई आर्किटेक्चर का समर्थन कर सकती है**।

ये बायनरी **Mach-O संरचना** का पालन करते हैं, जो मूल रूप से निम्न हिस्सों से मिलकर बनती है:

- हेडर
- लोड कमांड्स
- डेटा

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## फैट हेडर

फाइल खोजने के लिए उपयोग करें: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

हेडर में **magic** बाइट्स होती हैं, उसके बाद फ़ाइल में मौजूद **archs** की **संख्या** (`nfat_arch`) होती है और हर arch के लिए एक `fat_arch` struct होगा।

इसे जाँचें:

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

या [Mach-O View](https://sourceforge.net/projects/machoview/) टूल का उपयोग करके:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

जैसा कि आप सोच रहे होंगे, सामान्यतः 2 आर्किटेक्चर के लिए कम्पाइल की गई एक यूनिवर्सल बाइनरी एक ही आर्किटेक्चर के लिए कम्पाइल की गई बाइनरी के आकार को **दो गुना** कर देती है।

## **Mach-O Header**

हेडर फ़ाइल के बारे में बुनियादी जानकारी रखता है, जैसे कि उसे Mach-O फ़ाइल के रूप में पहचानने के लिए magic बाइट्स और लक्ष्य आर्किटेक्चर की जानकारी। आप इसे यहाँ पा सकते हैं: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

There are different file types, you can find them defined in the [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). The most important ones are:

- `MH_OBJECT`: रिलोकेटेबल ऑब्जेक्ट फ़ाइल (कम्पाइलिंग के मध्यवर्ती उत्पाद, अभी निष्पादन योग्य नहीं)।
- `MH_EXECUTE`: निष्पादन योग्य फ़ाइलें।
- `MH_FVMLIB`: Fixed VM लाइब्रेरी फ़ाइल।
- `MH_CORE`: कोड डंप्स
- `MH_PRELOAD`: प्रीलोडेड निष्पादन योग्य फ़ाइल (अब XNU में समर्थित नहीं)
- `MH_DYLIB`: डायनेमिक लाइब्रेरीज़
- `MH_DYLINKER`: डायनेमिक लिंकर
- `MH_BUNDLE`: "प्लगइन फ़ाइलें". Generated using -bundle in gcc and explicitly loaded by `NSBundle` or `dlopen`.
- `MH_DYSM`: Companion `.dSym` file (file with symbols for debugging).
- `MH_KEXT_BUNDLE`: कर्नल एक्सटेंशंस।
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O फ़्लैग्स**

स्रोत कोड कुछ फ़्लैग्स भी परिभाषित करता है जो लाइब्रेरीज़ लोड करने में उपयोगी होते हैं:

- `MH_NOUNDEFS`: कोई अपरिभाषित संदर्भ नहीं (पूर्ण रूप से लिंक्ड)
- `MH_DYLDLINK`: Dyld लिंकिंग
- `MH_PREBOUND`: डायनमिक संदर्भ प्रीबाउंड।
- `MH_SPLIT_SEGS`: फ़ाइल को r/o और r/w सेगमेंट में विभाजित करता है।
- `MH_WEAK_DEFINES`: बाइनरी में weak परिभाषित प्रतीक हैं
- `MH_BINDS_TO_WEAK`: बाइनरी weak symbols का उपयोग करती है
- `MH_ALLOW_STACK_EXECUTION`: स्टैक को executable बनाता है
- `MH_NO_REEXPORTED_DYLIBS`: लाइब्रेरी LC_REEXPORT कमांड्स के रूप में पुनः निर्यात नहीं होती
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: थ्रेड लोकल वेरिएबल्स वाला सेक्शन मौजूद है
- `MH_NO_HEAP_EXECUTION`: heap/data पृष्ठों पर execution नहीं
- `MH_HAS_OBJC`: बाइनरी में Objective-C सेक्शन हैं
- `MH_SIM_SUPPORT`: सिम्युलेटर सपोर्ट
- `MH_DYLIB_IN_CACHE`: shared library cache में dylibs/frameworks पर उपयोग होता है।

## **Mach-O लोड कमांड्स**

The **file's layout in memory** is specified here, detailing the **symbol table's location**, the context of the main thread at execution start, and the required **shared libraries**. Instructions are provided to the dynamic loader **(dyld)** on the binary's loading process into memory.

The uses the **load_command** structure, defined in the mentioned **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> मूलतः, इस प्रकार का Load Command यह परिभाषित करता है कि बाइनरी के execute होने पर **\_\_TEXT** (एक्जीक्यूटेबल कोड) और **\_\_DATA** (प्रोसेस के लिए डेटा) **segments** को Data सेक्शन में दिए गए **offsets** के अनुसार कैसे लोड किया जाए।

ये कमांड्स उन **segments को परिभाषित करते हैं** जो किसी प्रोसेस के execute होने पर उसके **वर्चुअल मेमोरी स्पेस** में **मैप** किए जाते हैं।

कई तरह के **segments** होते हैं, जैसे कि **\_\_TEXT** segment, जो किसी प्रोग्राम का executable code रखता है, और **\_\_DATA** segment, जो प्रोसेस द्वारा उपयोग किए जाने वाले डेटा को रखता है। ये **segments Mach-O फाइल के data section में स्थित** होते हैं।

**प्रत्येक segment** को और भी छोटे-छोटे **sections** में **बाँटा** जा सकता है। **लोड कमांड संरचना** संबंधित segment के भीतर इन **sections** के बारे में **जानकारी** रखती है।

हैडर में सबसे पहले आपको **segment header** मिलता है:

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

Example of segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

यह हेडर उन **sections की संख्या जिनके हैडर इसके बाद दिखाई देते हैं** को परिभाषित करता है:
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
उदाहरण: **सेक्शन हेडर**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

यदि आप **section offset** (0x37DC) में उस **offset** को जोड़ें जहाँ **arch** शुरू होता है — इस मामले में `0x18000` — तो `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

आप **command line** के जरिए **headers information** भी प्राप्त कर सकते हैं:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** यह kernel को निर्देश देता है कि वह **map** करे `address zero` को ताकि इसे **read से, write से, या execute से रोक दिया जाए**। संरचना में maxprot और minprot वेरिएबल्स को शून्य पर सेट किया जाता है ताकि सूचित हो कि इस पेज पर **कोई read-write-execute अधिकार नहीं हैं**।
- यह allocation महत्वपूर्ण है ताकि **NULL pointer dereference vulnerabilities** को mitigate किया जा सके। इसका कारण यह है कि XNU एक hard page zero लागू करता है जो सुनिश्चित करता है कि memory का पहला पेज (सिर्फ पहला) inaccessible हो (i386 को छोड़कर)। एक बाइनरी इस आवश्यकता को पूरा कर सकता है छोटे \_\_PAGEZERO का निर्माण करके ( `-pagezero_size` का उपयोग करके) जो पहले 4k को कवर करे और शेष 32bit memory को user और kernel मोड दोनों में accessible रखे।
- **`__TEXT`**: इसमें **executable** **code** होता है जिसमें **read** और **execute** permissions होते हैं (कोई writable नहीं)**.** इस सेगमेंट के सामान्य सेक्शन्स:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: डायनेमिक लाइब्रेरी लोडिंग प्रक्रिया के दौरान उपयोग होते हैं
- `__unwind_info`: स्टैक अनवाइंड डेटा।
- ध्यान दें कि यह सभी कंटेंट signed होते हैं पर साथ ही executable के रूप में चिह्नित भी होते हैं (जिससे उन सेक्शन्स का exploitation करने के और विकल्प बनते हैं जिनको जरूरी नहीं कि यह privilege चाहिए, जैसे string dedicated sections)।
- **`__DATA`**: इसमें डेटा होता है जो **readable** और **writable** होता है (कोई executable नहीं)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: पढ़ने योग्य होना चाहिए (वास्तव में नहीं)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime द्वारा उपयोग की जाने वाली जानकारी
- **`__DATA_CONST`**: \_\_DATA.\_\_const की constant होने की गारंटी नहीं होती (write permissions), न ही अन्य pointers और GOT की। यह सेक्शन `__const`, कुछ initializers और GOT टेबल (एक बार resolved होने पर) को `mprotect` का उपयोग करके **read only** बनाता है।
- **`__LINKEDIT`**: linker (dyld) के लिए जानकारी रखता है जैसे कि symbol, string, और relocation table entries। यह उन कंटेंट्स के लिए एक generic container है जो `__TEXT` या `__DATA` में नहीं हैं और इसकी सामग्री अन्य load commands में वर्णित है।
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime द्वारा उपयोग की जाने वाली जानकारी रखता है। हालांकि यह जानकारी \_\_DATA सेगमेंट में भी मिल सकती है, विभिन्न \_\_objc\_\* सेक्शन्स के भीतर।
- **`__RESTRICT`**: एक ऐसा सेगमेंट जिसका कोई कंटेंट नहीं होता और जिसमें एक अकेला सेक्शन होता है जिसका नाम **`__restrict`** (यह भी खाली) है, जो सुनिश्चित करता है कि बाइनरी चलने पर यह DYLD environmental variables को ignore करे।

जैसा कि कोड में देखा जा सकता है, **segments flags को भी सपोर्ट करते हैं** (हालाँकि इनका बहुत अधिक उपयोग नहीं होता):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: एन्क्रिप्शन। उदाहरण के लिए Finder द्वारा text `__TEXT` segment को एन्क्रिप्ट करने के लिए प्रयोग किया जाता है।

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** entryoff attribute में entrypoint रखता है। लोड समय पर, **dyld** बस इस मान को (in-memory) **base of the binary** में जोड़ देता है, फिर इस निर्देश पर **jump** करके बाइनरी के कोड के निष्पादन को शुरू करता है।

**`LC_UNIXTHREAD`** में वे मान होते हैं जो main thread शुरू करते समय registers में होने चाहिए। यह पहले से ही deprecated है लेकिन **`dyld`** अभी भी इसका उपयोग करता है। आप इसके द्वारा सेट किए गए registers के values को यह कमांड देखकर देख सकते हैं:
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


Contains information about the **code signature of the Mach-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

बाइनरी एन्क्रिप्शन के लिए समर्थन। हालांकि, ज़ाहिर है, अगर कोई attacker प्रक्रिया को compromise कर लेता है, तो वह मेमोरी को अनएन्क्रिप्टेड dump कर पाएगा।

### **`LC_LOAD_DYLINKER`**

यह उस **dynamic linker executable के path** को बताता है जो shared libraries को process address space में map करता है। **value हमेशा `/usr/lib/dyld` पर सेट रहती है**। यह ध्यान देने योग्य है कि macOS में, dylib mapping **user mode** में होता है, kernel mode में नहीं।

### **`LC_IDENT`**

अब प्रचलन में नहीं है, लेकिन जब panic पर dumps generate करने के लिए कॉन्फ़िगर किया जाता है, तो एक Mach-O core dump बनाया जाता है और kernel version `LC_IDENT` कमांड में सेट किया जाता है।

### **`LC_UUID`**

Random UUID। यह प्रत्यक्ष रूप से किसी भी चीज़ के लिए उपयोगी हो सकता है लेकिन XNU इसे बाकी process info के साथ cache करता है। इसे crash reports में इस्तेमाल किया जा सकता है।

### **`LC_DYLD_ENVIRONMENT`**

यह dyld को environment variables बताने की अनुमति देता है इससे पहले कि process execute हो। यह बहुत खतरनाक हो सकता है क्योंकि इससे process के अंदर arbitrary code execute होने की अनुमति मिल सकती है, इसलिए यह load command केवल dyld build में `#define SUPPORT_LC_DYLD_ENVIRONMENT` के साथ उपयोग किया जाता है और प्रोसेसिंग को केवल `DYLD_..._PATH` स्वरूप के variables तक सीमित करता है जो load paths निर्दिष्ट करते हैं।

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

- यह load command प्रकार **`dylib_command`** की एक संरचना है (जिसमें एक struct dylib होता है, जो वास्तविक dependent dynamic library का वर्णन करता है):
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
![](<../../../images/image (486).png>)

आप यह जानकारी cli से भी प्राप्त कर सकते हैं:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
कुछ संभावित malware संबंधित लाइब्रेरीज़ हैं:

- **DiskArbitration**: USB ड्राइव्स की निगरानी
- **AVFoundation:** ऑडियो और वीडियो कैप्चर करना
- **CoreWLAN**: Wi-Fi स्कैन।

> [!TIP]
> एक Mach-O बाइनरी में एक या अधिक **constructors** हो सकते हैं, जिन्हें **LC_MAIN** में निर्दिष्ट पते से पहले निष्पादित किया जाता है।\
> किसी भी constructors के offsets **\_\_mod_init_func** सेक्शन में रखे जाते हैं जो **\_\_DATA_CONST** सेगमेंट का हिस्सा है।

## **Mach-O डेटा**

फाइल के मूल में डेटा क्षेत्र होता है, जो load-commands क्षेत्र में परिभाषित कई सेगमेंट्स से बना होता है। **प्रत्येक सेगमेंट के भीतर विभिन्न डेटा सेक्शन्स हो सकते हैं**, और प्रत्येक सेक्शन किसी विशिष्ट प्रकार के लिए **code या data** रखता है।

> [!TIP]
> डेटा मूलतः वह भाग है जिसमें load commands **LC_SEGMENTS_64** द्वारा लोड की जाने वाली सभी जानकारी होती है।

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

यह शामिल करता है:

- **Function table:** जो प्रोग्राम के functions के बारे में जानकारी रखता है।
- **Symbol table**: जो बाइनरी द्वारा उपयोग की जाने वाली external functions के बारे में जानकारी रखता है।
- यह अंदरूनी function, variable नामों और अन्य चीज़ों को भी शामिल कर सकता है।

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C सामान्य अनुभाग

`__TEXT` सेगमेंट (r-x) में:

- `__objc_classname`: क्लास नाम (strings)
- `__objc_methname`: मेथड नाम (strings)
- `__objc_methtype`: मेथड प्रकार (strings)

`__DATA` सेगमेंट (rw-) में:

- `__objc_classlist`: सभी Objetive-C क्लासेस के पॉइंटर्स
- `__objc_nlclslist`: Non-Lazy Objetive-C क्लासेस के पॉइंटर्स
- `__objc_catlist`: Categories का पॉइंटर
- `__objc_nlcatlist`: Non-Lazy Categories का पॉइंटर
- `__objc_protolist`: प्रोटोकॉल्स सूची
- `__objc_const`: स्थिर डेटा
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
