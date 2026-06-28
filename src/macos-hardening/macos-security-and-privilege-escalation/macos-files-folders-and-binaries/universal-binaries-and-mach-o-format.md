# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Бінарні файли Mac OS зазвичай компілюються як **universal binaries**. **Universal binary** може **підтримувати кілька архітектур в одному файлі**.

Ці бінарні файли слідують **Mach-O structure**, яка, по суті, складається з:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Шукайте файл за допомогою: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header має **magic** байти, за якими йде **number** **archs**, які файл **contains** (`nfat_arch`), і кожен arch матиме структуру `fat_arch`.

Перевірте це за допомогою:

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

або використовуючи інструмент [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Як ви можете думати, зазвичай universal binary, скомпільований для 2 архітектур, **подвоює розмір** того, що скомпільований лише для 1 arch.

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
Останні macOS SDKs також надають helpers, такі як `macho_for_each_slice()` і `macho_best_slice()` у `<mach-o/utils.h>`. Останній зручний, щоб emulювати те, що завантажили б dyld/kernel, але scanners усе одно мають ітеруватися по кожному slice, щоб не пропустити arch-specific content.

## **Mach-O Header**

The header містить базову інформацію про файл, таку як magic bytes для ідентифікації його як Mach-O file і інформацію про target architecture. Ви можете знайти його в: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Типи файлів Mach-O

Існують різні типи файлів, їх можна знайти, наприклад, визначеними в [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Найважливіші з них:

- `MH_OBJECT`: Переміщуваний object file (проміжні продукти компіляції, ще не executables).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Попередньо завантажений executable file (більше не підтримується в XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Генеруються за допомогою -bundle у gcc і явно завантажуються через `NSBundle` або `dlopen`.
- `MH_DYSM`: Супровідний `.dSym` file (file with symbols for debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Або використовуючи [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Вихідний код також визначає кілька прапорів, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: Файл розділяє сегменти r/o і r/w.
- `MH_WEAK_DEFINES`: Binary має weak визначені символи
- `MH_BINDS_TO_WEAK`: Binary використовує weak символи
- `MH_ALLOW_STACK_EXECUTION`: Зробити stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Бібліотека не має команд LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Є секція з thread local variables
- `MH_NO_HEAP_EXECUTION`: Немає execution для heap/data pages
- `MH_HAS_OBJC`: Binary має oBject-C секції
- `MH_SIM_SUPPORT`: Підтримка simulator
- `MH_DYLIB_IN_CACHE`: Використовується на dylibs/frameworks у shared library cache.

## **Mach-O Load commands**

**Розмітка файлу в пам'яті** тут визначається, із деталями про **розташування symbol table**, контекст main thread на початку виконання та необхідні **shared libraries**. Інструкції надаються dynamic loader **(dyld)** щодо процесу завантаження binary в пам'ять.

Використовується структура **load_command**, визначена в згаданому **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Існує близько **50 різних типів load commands**, які система обробляє по-різному. Найпоширеніші: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` і `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> По суті, цей тип Load Command визначає **як завантажувати сегменти \_\_TEXT** (виконуваний код) **і \_\_DATA** (дані для процесу) **відповідно до offset-ів, указаних у секції Data**, коли binary виконується.

Ці команди **визначають сегменти**, які **mapped** у **virtual memory space** процесу під час його виконання.

Існують **різні типи** сегментів, наприклад **\_\_TEXT** segment, який містить виконуваний код програми, і **\_\_DATA** segment, який містить дані, що використовуються процесом. Ці **segments located in the data section** файлу Mach-O.

**Кожен segment** може бути додатково **поділений** на кілька **sections**. **Структура load command** містить **інформацію** про **ці sections** у відповідному segment.

У header спочатку ви знаходите **segment header**:

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

Приклад segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Цей header визначає **кількість sections, заголовки яких ідуть після нього**:
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
Приклад **заголовка секції**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Якщо ви **додасте** **зсув секції** (0x37DC) + **зсув**, де **починається arch**, у цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **інформацію про заголовки** з **командного рядка** за допомогою:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Він вказує kernel **відобразити** **адресу zero** так, щоб її **не можна було читати, записувати або виконувати**. Змінні maxprot і minprot у структурі встановлюються в zero, щоб показати, що на цій сторінці **немає прав read-write-execute**.
- Це виділення важливе для **mitigate NULL pointer dereference vulnerabilities**. Це тому, що XNU enforce-ить hard page zero, який гарантує, що перша сторінка (лише перша) memory є inaccesible (крім i386). Binary could fulfil this requirements by crafting a small \_\_PAGEZERO (using the `-pagezero_size`) to cover the first 4k and having the rest of 32bit memory accessible in both user and kernel mode.
- **`__TEXT`**: Містить **executable** **code** з правами **read** і **execute** (без writable)**.** Common sections of this segment:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Зверніть увагу, що весь цей content signed, але також позначений як executable (створюючи більше options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
- **`__DATA`**: Містить data, яка є **readable** і **writable** (без executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const is not guaranteed to be constant (write permissions), nor are other pointers and the GOT. This section makes `__const`, some initializers and the GOT table (once resolved) **read only** using `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Common in recent Apple Silicon binaries. These segments hold pointers that must be authenticated at load or use time (for example `__auth_got`). If a rebinding, hook or import-patching trick only checks the legacy `__got` / `__la_symbol_ptr` sections, it may miss the real call sites in modern `arm64e` binaries. For more details on these sections check [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Містить information for the linker (dyld), таку як entries таблиці символів, string і relocation table. It' a generic container for contents that are neither in `__TEXT` or `__DATA` and its content is decribed in other load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Містить information used by the Objective-C runtime. Though this information might also be found in the \_\_DATA segment, within various in \_\_objc\_\* sections.
- **`__RESTRICT`**: Segment без content з єдиною section під назвою **`__restrict`** (також empty), яка забезпечує, що під час запуску binary він ігноруватиме DYLD environmental variables.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить entrypoint в атрибуті **entryoff.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

**`LC_UNIXTHREAD`** містить values, які register must have when starting the main thread. This was already deprecated but **`dyld`** still uses it. It's possible to see the vlaues of the registers set by this with:
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


Містить інформацію про **кодову сигнатуру файлу Macho-O**. Він містить лише **зсув**, який **вказує** на **signature blob**. Зазвичай це розташовано в самому кінці файлу.\
Однак ви можете знайти деяку інформацію про цей розділ у [**цьому blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) і в цих [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування binary. Однак, звісно, якщо attacker зможе скомпрометувати process, він зможе дампнути memory незашифрованою.

### **`LC_LOAD_DYLINKER`**

Містить **path до executable dynamic linker**, який мапить shared libraries в address space process. **Значення завжди встановлене в `/usr/lib/dyld`**. Важливо зазначити, що в macOS мапінг dylib відбувається в **user mode**, а не в kernel mode.

### **`LC_IDENT`**

Застарілий, але коли налаштовано на створення dumps під час panic, створюється Mach-O core dump і версія kernel встановлюється в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Сам по собі він не особливо корисний, але XNU кешує його разом з рештою process info. Його можна використовувати в crash reports.

### **`LC_BUILD_VERSION`**

Сучасні binaries зазвичай містять цю команду, щоб оголосити **target platform**, **minimum OS version**, **SDK version** і, за потреби, **tool versions**, використані для побудови цього slice. З точки зору offensive/reversing це дуже корисно для fingerprinting того, як було зібрано sample, і для швидкого виявлення дивних universal binaries, де один slice був скомпільований з іншим SDK або deployment target. Старіші binaries можуть натомість використовувати `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказувати змінні середовища для dyld перед запуском процесу. Це може бути дуже небезпечно, оскільки це може дозволити виконати довільний код всередині процесу, тому цей load command використовується лише в білді dyld з `#define SUPPORT_LC_DYLD_ENVIRONMENT` і додатково обмежує обробку лише змінними у форматі `DYLD_..._PATH`, що вказують load paths.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains frequently store export/bind/rebase metadata in these commands instead of relying only on the older `LC_DYLD_INFO[_ONLY]` opcodes. Both are `linkedit_data_command` entries that point into **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Compact trie with the symbols exported by the image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains used by dyld to apply rebases and binds. On Apple Silicon this is also where you will encounter many modern authenticated pointer fixups.

This metadata is very handy when reconstructing imports/exports, understanding why an `@rpath`-loaded dependency resolved the way it did, or figuring out why a hook/rebinding attempt failed on a modern `arm64e` target. `dyld_info` can also be used against **cache-only dylib paths** that do not exist as standalone files on disk, which is very handy on modern macOS where many system libraries live only in the shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Ця сучасна load command здебільшого актуальна під час аналізу **kernel collections / kernelcache-style filesets**. Замість того щоб представляти один окремий image, зовнішній Mach-O діє як контейнер, а кожен `LC_FILESET_ENTRY` вказує на вбудований Mach-O з власним path-like **entry id**, VM address і file offset. Якщо ви reverse modern macOS/iOS kernel components, ця команда часто є мостом між верхньорівневим контейнером і фактичним image, який ви хочете витягти або disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність від **динамічної** **бібліотеки**, яка **вказує** **loader** (dyld) **завантажити й зв’язати цю бібліотеку**. Існує команда завантаження `LC_LOAD_DYLIB` **для кожної бібліотеки**, яку вимагає Mach-O binary.

- Ця команда завантаження є структурою типу **`dylib_command`** (яка містить struct dylib, що описує фактичну залежну динамічну бібліотеку):
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

Ви також можете отримати цю інформацію з cli за допомогою:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Monitoring USB drives
- **AVFoundation:** Capture audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

In `__TEXT` segment (r-x):

- `__objc_classname`: Назви класів (рядки)
- `__objc_methname`: Назви методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

In `__DATA` segment (rw-):

- `__objc_classlist`: Вказівники на всі класи Objetive-C
- `__objc_nlclslist`: Вказівники на Non-Lazy Objective-C класи
- `__objc_catlist`: Вказівник на Categories
- `__objc_nlcatlist`: Вказівники на Non-Lazy Categories
- `__objc_protolist`: Список protocols
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
