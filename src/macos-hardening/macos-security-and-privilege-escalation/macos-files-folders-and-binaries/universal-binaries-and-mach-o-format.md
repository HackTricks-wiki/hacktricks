# macOS यूनिवर्सल बाइनरी और Mach-O प्रारूप

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Mac OS बाइनरी आमतौर पर **यूनिवर्सल बाइनरी** के रूप में संकलित होती हैं। एक **यूनिवर्सल बाइनरी** **एक ही फ़ाइल में कई आर्किटेक्चर का समर्थन कर सकती है**।

ये बाइनरी **Mach-O संरचना** का पालन करती हैं जो मूल रूप से निम्नलिखित से बनी होती है:

- हेडर
- लोड कमांड
- डेटा

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## फैट हेडर

फ़ाइल के लिए खोजें: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC या FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* उसके बाद आने वाले संरचनाओं की संख्या */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu निर्दिष्टकर्ता (int) */
cpu_subtype_t	cpusubtype;	/* मशीन निर्दिष्टकर्ता (int) */
uint32_t	offset;		/* इस ऑब्जेक्ट फ़ाइल के लिए फ़ाइल ऑफ़सेट */
uint32_t	size;		/* इस ऑब्जेक्ट फ़ाइल का आकार */
uint32_t	align;		/* 2 की शक्ति के रूप में संरेखण */
};
</code></pre>

हेडर में **जादुई** बाइट्स होते हैं जिनके बाद फ़ाइल में **आर्क्स** की **संख्या** होती है (`nfat_arch`) और प्रत्येक आर्क में एक `fat_arch` संरचना होगी।

इसे जांचें:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O यूनिवर्सल बाइनरी जिसमें 2 आर्किटेक्चर हैं: [x86_64:Mach-O 64-बिट निष्पादन योग्य x86_64] [arm64e:Mach-O 64-बिट निष्पादन योग्य arm64e]
/bin/ls (आर्किटेक्चर x86_64 के लिए):	Mach-O 64-बिट निष्पादन योग्य x86_64
/bin/ls (आर्किटेक्चर arm64e के लिए):	Mach-O 64-बिट निष्पादन योग्य arm64e

% otool -f -v /bin/ls
फैट हेडर्स
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>आर्किटेक्चर x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>आर्किटेक्चर arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

या [Mach-O View](https://sourceforge.net/projects/machoview/) उपकरण का उपयोग करके:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

जैसा कि आप सोच रहे होंगे, आमतौर पर 2 आर्किटेक्चर के लिए संकलित एक यूनिवर्सल बाइनरी **एक आर्क के लिए संकलित बाइनरी के आकार को दोगुना कर देती है**।

## **Mach-O हेडर**

हेडर फ़ाइल के बारे में बुनियादी जानकारी प्रदान करता है, जैसे इसे Mach-O फ़ाइल के रूप में पहचानने के लिए जादुई बाइट्स और लक्षित आर्किटेक्चर के बारे में जानकारी। आप इसे खोज सकते हैं: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

विभिन्न फ़ाइल प्रकार हैं, जिन्हें आप [**स्रोत कोड में उदाहरण के लिए यहाँ**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) पर परिभाषित कर सकते हैं। सबसे महत्वपूर्ण हैं:

- `MH_OBJECT`: पुनर्स्थापनीय ऑब्जेक्ट फ़ाइल (संकलन के मध्य उत्पाद, अभी निष्पादन योग्य नहीं)।
- `MH_EXECUTE`: निष्पादन योग्य फ़ाइलें।
- `MH_FVMLIB`: स्थिर VM पुस्तकालय फ़ाइल।
- `MH_CORE`: कोड डंप
- `MH_PRELOAD`: प्रीलोडेड निष्पादन योग्य फ़ाइल (XNU में अब समर्थित नहीं) 
- `MH_DYLIB`: गतिशील पुस्तकालय
- `MH_DYLINKER`: गतिशील लिंकर्स
- `MH_BUNDLE`: "प्लगइन फ़ाइलें"। gcc में -bundle का उपयोग करके उत्पन्न और `NSBundle` या `dlopen` द्वारा स्पष्ट रूप से लोड की गई।
- `MH_DYSM`: साथी `.dSym` फ़ाइल (डिबगिंग के लिए प्रतीकों के साथ फ़ाइल)।
- `MH_KEXT_BUNDLE`: कर्नेल एक्सटेंशन।
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
या [Mach-O View](https://sourceforge.net/projects/machoview/) का उपयोग करके:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O फ्लैग्स**

स्रोत कोड कई फ्लैग्स को परिभाषित करता है जो पुस्तकालयों को लोड करने के लिए उपयोगी होते हैं:

- `MH_NOUNDEFS`: कोई अपरिभाषित संदर्भ नहीं (पूर्ण रूप से लिंक किया गया)
- `MH_DYLDLINK`: Dyld लिंकिंग
- `MH_PREBOUND`: गतिशील संदर्भ पूर्व बंधित।
- `MH_SPLIT_SEGS`: फ़ाइल r/o और r/w खंडों में विभाजित होती है।
- `MH_WEAK_DEFINES`: बाइनरी में कमजोर परिभाषित प्रतीक हैं
- `MH_BINDS_TO_WEAK`: बाइनरी कमजोर प्रतीकों का उपयोग करती है
- `MH_ALLOW_STACK_EXECUTION`: स्टैक को निष्पादित करने योग्य बनाएं
- `MH_NO_REEXPORTED_DYLIBS`: पुस्तकालय LC_REEXPORT कमांड नहीं है
- `MH_PIE`: स्थिति स्वतंत्र निष्पादन योग्य
- `MH_HAS_TLV_DESCRIPTORS`: वहाँ एक अनुभाग है जिसमें थ्रेड स्थानीय चर हैं
- `MH_NO_HEAP_EXECUTION`: हीप/डेटा पृष्ठों के लिए कोई निष्पादन नहीं
- `MH_HAS_OBJC`: बाइनरी में oBject-C अनुभाग हैं
- `MH_SIM_SUPPORT`: सिम्युलेटर समर्थन
- `MH_DYLIB_IN_CACHE`: साझा पुस्तकालय कैश में dylibs/फ्रेमवर्क पर उपयोग किया गया।

## **Mach-O लोड कमांड्स**

**फाइल का लेआउट मेमोरी** में यहाँ निर्दिष्ट किया गया है, जिसमें **प्रतीक तालिका का स्थान**, निष्पादन प्रारंभ पर मुख्य थ्रेड का संदर्भ, और आवश्यक **साझा पुस्तकालयें** शामिल हैं। गतिशील लोडर **(dyld)** को बाइनरी के मेमोरी में लोडिंग प्रक्रिया के लिए निर्देश दिए जाते हैं।

यह **load_command** संरचना का उपयोग करता है, जिसे उल्लेखित **`loader.h`** में परिभाषित किया गया है:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> मूल रूप से, इस प्रकार के लोड कमांड **कैसे \_\_TEXT** (कार्यकारी कोड) **और \_\_DATA** (प्रक्रिया के लिए डेटा) **सेगमेंट को लोड करना है** यह परिभाषित करते हैं, **डेटा अनुभाग में निर्दिष्ट ऑफ़सेट के अनुसार** जब बाइनरी निष्पादित होती है।

ये कमांड **सेगमेंट को परिभाषित करते हैं** जो **प्रक्रिया के निष्पादन के समय** इसके **आभासी मेमोरी स्थान** में **मैप** होते हैं।

सेगमेंट के **विभिन्न प्रकार** होते हैं, जैसे कि **\_\_TEXT** सेगमेंट, जो एक प्रोग्राम के कार्यकारी कोड को रखता है, और **\_\_DATA** सेगमेंट, जो प्रक्रिया द्वारा उपयोग किए जाने वाले डेटा को शामिल करता है। ये **सेगमेंट Mach-O फ़ाइल के डेटा अनुभाग में स्थित होते हैं**।

**प्रत्येक सेगमेंट** को आगे **कई अनुभागों** में **विभाजित** किया जा सकता है। **लोड कमांड संरचना** में **इन अनुभागों** के बारे में **जानकारी** होती है जो संबंधित सेगमेंट के भीतर होती है।

हेडर में सबसे पहले आप **सेगमेंट हेडर** पाते हैं:

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

This header defines the **number of sections whose headers appear after** it:
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
उदाहरण **अनुभाग शीर्षक** का:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

यदि आप **अनुभाग ऑफसेट** (0x37DC) + **ऑफसेट** जहां **आर्क शुरू होता है**, इस मामले में `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

यह **कमांड लाइन** से **हेडर जानकारी** प्राप्त करना भी संभव है:
```bash
otool -lv /bin/ls
```
सामान्य खंड जो इस cmd द्वारा लोड होते हैं:

- **`__PAGEZERO`:** यह कर्नेल को **मैप** करने के लिए निर्देशित करता है **पता शून्य** ताकि इसे **पढ़ा, लिखा या निष्पादित** नहीं किया जा सके। संरचना में maxprot और minprot वेरिएबल को शून्य पर सेट किया गया है ताकि यह संकेत दिया जा सके कि इस पृष्ठ पर **कोई पढ़ने-लिखने-निष्पादन अधिकार नहीं हैं**।
- यह आवंटन **NULL पॉइंटर डेरिफरेंस कमजोरियों** को **कम करने** के लिए महत्वपूर्ण है। इसका कारण यह है कि XNU एक कठोर पृष्ठ शून्य को लागू करता है जो सुनिश्चित करता है कि मेमोरी का पहला पृष्ठ (केवल पहला) अनुपलब्ध है (i386 को छोड़कर)। एक बाइनरी इस आवश्यकताओं को पूरा कर सकती है एक छोटे \_\_PAGEZERO ( `-pagezero_size` का उपयोग करके) को तैयार करके जो पहले 4k को कवर करता है और शेष 32-बिट मेमोरी को उपयोगकर्ता और कर्नेल मोड दोनों में सुलभ बनाता है।
- **`__TEXT`**: इसमें **निष्पादन योग्य** **कोड** होता है जिसमें **पढ़ने** और **निष्पादन** की अनुमति होती है (कोई लिखने योग्य नहीं)**।** इस खंड के सामान्य अनुभाग:
- `__text`: संकलित बाइनरी कोड
- `__const`: स्थायी डेटा (केवल पढ़ने के लिए)
- `__[c/u/os_log]string`: C, यूनिकोड या os लॉग स्ट्रिंग स्थिरांक
- `__stubs` और `__stubs_helper`: गतिशील पुस्तकालय लोडिंग प्रक्रिया के दौरान शामिल होते हैं
- `__unwind_info`: स्टैक अनवाइंड डेटा।
- ध्यान दें कि इस सभी सामग्री पर हस्ताक्षर किया गया है लेकिन इसे निष्पादन योग्य के रूप में भी चिह्नित किया गया है (ऐसे अनुभागों के शोषण के लिए अधिक विकल्प बनाना जिन्हें इस विशेषाधिकार की आवश्यकता नहीं होती, जैसे स्ट्रिंग समर्पित अनुभाग)।
- **`__DATA`**: इसमें डेटा होता है जो **पढ़ने योग्य** और **लिखने योग्य** (कोई निष्पादन योग्य नहीं)**।**
- `__got:` वैश्विक ऑफसेट तालिका
- `__nl_symbol_ptr`: गैर आलसी (लोड पर बाइंड) प्रतीक पॉइंटर
- `__la_symbol_ptr`: आलसी (उपयोग पर बाइंड) प्रतीक पॉइंटर
- `__const`: इसे केवल पढ़ने योग्य डेटा होना चाहिए (वास्तव में नहीं)
- `__cfstring`: कोरफाउंडेशन स्ट्रिंग
- `__data`: वैश्विक वेरिएबल (जो प्रारंभिक किया गया है)
- `__bss`: स्थिर वेरिएबल (जो प्रारंभिक नहीं किया गया है)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, आदि): जानकारी जो ऑब्जेक्टिव-सी रनटाइम द्वारा उपयोग की जाती है
- **`__DATA_CONST`**: \_\_DATA.\_\_const को स्थायी होने की गारंटी नहीं है (लिखने की अनुमति), न ही अन्य पॉइंटर्स और GOT। यह अनुभाग `__const`, कुछ प्रारंभिककरणकर्ताओं और GOT तालिका (एक बार हल होने पर) को **केवल पढ़ने योग्य** बनाता है `mprotect` का उपयोग करके।
- **`__LINKEDIT`**: इसमें लिंकर्स (dyld) के लिए जानकारी होती है जैसे, प्रतीक, स्ट्रिंग, और पुनर्स्थापन तालिका प्रविष्टियाँ। यह `__TEXT` या `__DATA` में न होने वाली सामग्री के लिए एक सामान्य कंटेनर है और इसकी सामग्री अन्य लोड कमांड में वर्णित है।
- dyld जानकारी: रीबेस, गैर-आलसी/आलसी/कमजोर बाइंडिंग ऑपकोड और निर्यात जानकारी
- फ़ंक्शंस प्रारंभ: फ़ंक्शंस के प्रारंभ पते की तालिका
- कोड में डेटा: \_\_text में डेटा द्वीप
- प्रतीक तालिका: बाइनरी में प्रतीक
- अप्रत्यक्ष प्रतीक तालिका: पॉइंटर/स्टब प्रतीक
- स्ट्रिंग तालिका
- कोड सिग्नेचर
- **`__OBJC`**: इसमें ऑब्जेक्टिव-सी रनटाइम द्वारा उपयोग की जाने वाली जानकारी होती है। हालांकि यह जानकारी \_\_DATA खंड में भी पाई जा सकती है, विभिन्न \_\_objc\_\* अनुभागों के भीतर।
- **`__RESTRICT`**: एक ऐसा खंड जिसमें सामग्री नहीं होती है जिसमें एकल अनुभाग होता है जिसे **`__restrict`** (भी खाली) कहा जाता है जो सुनिश्चित करता है कि बाइनरी चलाते समय, यह DYLD पर्यावरणीय चर को अनदेखा करेगा।

जैसा कि कोड में देखा जा सकता है, **खंड भी फ़्लैग का समर्थन करते हैं** (हालांकि उनका बहुत अधिक उपयोग नहीं किया जाता):

- `SG_HIGHVM`: केवल कोर (उपयोग नहीं किया गया)
- `SG_FVMLIB`: उपयोग नहीं किया गया
- `SG_NORELOC`: खंड में कोई पुनर्स्थापन नहीं है
- `SG_PROTECTED_VERSION_1`: एन्क्रिप्शन। उदाहरण के लिए Finder द्वारा `__TEXT` खंड को एन्क्रिप्ट करने के लिए उपयोग किया जाता है।

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** में **entryoff विशेषता** में प्रवेश बिंदु होता है। लोड समय पर, **dyld** बस इस मान को (मेमोरी में) **बाइनरी के आधार** में **जोड़ता** है, फिर **इस निर्देश पर कूदता** है ताकि बाइनरी के कोड का निष्पादन शुरू हो सके।

**`LC_UNIXTHREAD`** में वे मान होते हैं जो रजिस्टर को मुख्य धागा शुरू करते समय होना चाहिए। इसे पहले ही अमान्य कर दिया गया था लेकिन **`dyld`** अभी भी इसका उपयोग करता है। इसके द्वारा सेट किए गए रजिस्टर के मानों को देखना संभव है:
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

यह **Macho-O फ़ाइल** के **कोड सिग्नेचर** के बारे में जानकारी रखता है। इसमें केवल एक **ऑफसेट** होता है जो **सिग्नेचर ब्लॉब** की ओर **संकेत** करता है। यह आमतौर पर फ़ाइल के अंत में होता है।\
हालांकि, आप इस अनुभाग के बारे में कुछ जानकारी [**इस ब्लॉग पोस्ट**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) और इस [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) में पा सकते हैं।

### **`LC_ENCRYPTION_INFO[_64]`**

बाइनरी एन्क्रिप्शन के लिए समर्थन। हालाँकि, यदि एक हमलावर प्रक्रिया को समझौता करने में सफल हो जाता है, तो वह बिना एन्क्रिप्टेड मेमोरी को डंप कर सकेगा।

### **`LC_LOAD_DYLINKER`**

यह **डायनामिक लिंकर्स निष्पादन योग्य** का **पथ** रखता है जो साझा पुस्तकालयों को प्रक्रिया के पते की जगह में मैप करता है। **मान हमेशा `/usr/lib/dyld` पर सेट होता है**। यह ध्यान रखना महत्वपूर्ण है कि macOS में, dylib मैपिंग **उपयोगकर्ता मोड** में होती है, न कि कर्नेल मोड में।

### **`LC_IDENT`**

पुराना लेकिन जब पैनिक पर डंप उत्पन्न करने के लिए कॉन्फ़िगर किया जाता है, तो एक Mach-O कोर डंप बनाया जाता है और कर्नेल संस्करण `LC_IDENT` कमांड में सेट होता है।

### **`LC_UUID`**

यादृच्छिक UUID। यह किसी भी चीज़ के लिए सीधे उपयोगी नहीं है लेकिन XNU इसे प्रक्रिया की बाकी जानकारी के साथ कैश करता है। इसका उपयोग क्रैश रिपोर्ट में किया जा सकता है।

### **`LC_DYLD_ENVIRONMENT`**

प्रक्रिया के निष्पादन से पहले dyld को पर्यावरण चर निर्दिष्ट करने की अनुमति देता है। यह बहुत खतरनाक हो सकता है क्योंकि यह प्रक्रिया के अंदर मनमाना कोड निष्पादित करने की अनुमति दे सकता है, इसलिए यह लोड कमांड केवल `#define SUPPORT_LC_DYLD_ENVIRONMENT` के साथ dyld निर्माण में उपयोग किया जाता है और केवल `DYLD_..._PATH` के रूप के चर को लोड पथ निर्दिष्ट करने के लिए आगे संसाधित करता है।

### **`LC_LOAD_DYLIB`**

यह लोड कमांड एक **डायनामिक** **लाइब्रेरी** निर्भरता का वर्णन करता है जो **लोडर** (dyld) को **कहा गया लाइब्रेरी लोड और लिंक करने** के लिए **निर्देश** देता है। Mach-O बाइनरी के लिए आवश्यक **प्रत्येक लाइब्रेरी** के लिए एक `LC_LOAD_DYLIB` लोड कमांड है।

- यह लोड कमांड **`dylib_command`** प्रकार की संरचना है (जिसमें एक स्ट्रक्चर dylib होता है, जो वास्तविक निर्भर डायनामिक लाइब्रेरी का वर्णन करता है):
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

आप इस जानकारी को cli से भी प्राप्त कर सकते हैं:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
कुछ संभावित मैलवेयर से संबंधित पुस्तकालय हैं:

- **DiskArbitration**: USB ड्राइव की निगरानी
- **AVFoundation:** ऑडियो और वीडियो कैप्चर
- **CoreWLAN**: वाईफाई स्कैन।

> [!NOTE]
> एक Mach-O बाइनरी में एक या **अधिक** **कंस्ट्रक्टर्स** हो सकते हैं, जिन्हें **LC_MAIN** में निर्दिष्ट पते से **पहले** **निष्पादित** किया जाएगा।\
> किसी भी कंस्ट्रक्टर के ऑफसेट **\_\_mod_init_func** सेक्शन में **\_\_DATA_CONST** सेगमेंट में रखे जाते हैं।

## **Mach-O डेटा**

फाइल के मूल में डेटा क्षेत्र है, जो लोड-कमांड क्षेत्र में परिभाषित कई सेगमेंट से बना है। **प्रत्येक सेगमेंट के भीतर विभिन्न प्रकार के डेटा सेक्शन हो सकते हैं**, प्रत्येक सेक्शन में एक प्रकार के लिए विशिष्ट **कोड या डेटा** होता है।

> [!TIP]
> डेटा मूल रूप से वह भाग है जिसमें सभी **जानकारी** होती है जो लोड कमांड **LC_SEGMENTS_64** द्वारा लोड की जाती है।

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

इसमें शामिल हैं:

- **फंक्शन टेबल:** जो प्रोग्राम फंक्शंस के बारे में जानकारी रखता है।
- **सिंबल टेबल**: जो बाइनरी द्वारा उपयोग किए जाने वाले बाहरी फंक्शन के बारे में जानकारी रखता है
- इसमें आंतरिक फंक्शन, वेरिएबल नाम भी हो सकते हैं और अधिक।

इसे जांचने के लिए आप [**Mach-O View**](https://sourceforge.net/projects/machoview/) टूल का उपयोग कर सकते हैं:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

या CLI से:
```bash
size -m /bin/ls
```
## Objetive-C सामान्य अनुभाग

In `__TEXT` segment (r-x):

- `__objc_classname`: क्लास नाम (स्ट्रिंग)
- `__objc_methname`: मेथड नाम (स्ट्रिंग)
- `__objc_methtype`: मेथड प्रकार (स्ट्रिंग)

In `__DATA` segment (rw-):

- `__objc_classlist`: सभी Objetive-C क्लासेस के लिए पॉइंटर्स
- `__objc_nlclslist`: नॉन-लेज़ी Objective-C क्लासेस के लिए पॉइंटर्स
- `__objc_catlist`: श्रेणियों के लिए पॉइंटर
- `__objc_nlcatlist`: नॉन-लेज़ी श्रेणियों के लिए पॉइंटर
- `__objc_protolist`: प्रोटोकॉल सूची
- `__objc_const`: स्थायी डेटा
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
