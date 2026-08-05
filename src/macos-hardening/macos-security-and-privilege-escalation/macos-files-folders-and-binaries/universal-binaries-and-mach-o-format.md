# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Бінарні файли Mac OS зазвичай компілюються як **universal binaries**. **Universal binary** може **підтримувати кілька архітектур в одному файлі**.

Ці бінарні файли відповідають **структурі Mach-O**, яка в основному складається з:

- Заголовка
- Load Commands
- Даних

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Знайдіть файл за допомогою: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Заголовок містить **magic**-байти, за якими йде **кількість** **archs**, які **містить** файл (`nfat_arch`), і кожна arch матиме структуру `fat_arch`.

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

або за допомогою інструмента [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Як ви, можливо, здогадалися, universal binary, скомпільований для 2 архітектур, зазвичай **удвічі більший**, ніж binary, скомпільований лише для 1 arch.

> [!TIP]
> Під час triaging malware або підозрілих apps не зупиняйтеся після того, як `file` повідомить про «найкращу» архітектуру. Universal binary може приховувати різні imports, load commands або compiler metadata у кожному slice, тому спочатку перелічіть **всі** slices, а потім перевірте їх окремо:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Сучасні macOS SDK також надають такі helpers, як `macho_for_each_slice()` і `macho_best_slice()` у `<mach-o/utils.h>`. Останній зручний для емуляції того, що завантажив би dyld/kernel, але scanners все одно мають перебирати кожен slice, щоб не пропустити вміст, специфічний для певної arch.<sup>[[1]](#references)</sup>

## **Заголовок Mach-O**

Заголовок містить базову інформацію про файл, наприклад magic bytes для ідентифікації його як Mach-O-файлу та інформацію про цільову архітектуру. Знайти його можна за допомогою: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Існують різні типи файлів, їх можна знайти у [**вихідному коді, наприклад тут**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Найважливіші з них:

- `MH_OBJECT`: Relocatable object file (проміжні результати компіляції, ще не виконувані файли).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Файл бібліотеки Fixed VM.
- `MH_CORE`: Дампи коду.
- `MH_PRELOAD`: Попередньо завантажений виконуваний файл (більше не підтримується в XNU).
- `MH_DYLIB`: Dynamic Libraries.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "Файли плагінів". Створюються за допомогою -bundle у gcc і явно завантажуються через `NSBundle` або `dlopen`.
- `MH_DYSM`: Супровідний файл `.dSym` (файл із символами для налагодження).
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

Вихідний код також визначає кілька flags, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю скомпоновано)
- `MH_DYLDLINK`: Компонування через Dyld
- `MH_PREBOUND`: Динамічні посилання попередньо прив’язані.
- `MH_SPLIT_SEGS`: Файл розділяє сегменти r/o та r/w.
- `MH_WEAK_DEFINES`: Binary містить weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary використовує weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Зробити stack виконуваним
- `MH_NO_REEXPORTED_DYLIBS`: Library не містить команд LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Існує секція з thread local variables
- `MH_NO_HEAP_EXECUTION`: Виконання для heap/data pages заборонено
- `MH_HAS_OBJC`: Binary містить секції oBject-C
- `MH_SIM_SUPPORT`: Підтримка Simulator
- `MH_DYLIB_IN_CACHE`: Використовується для dylibs/frameworks у shared library cache.

## **Mach-O Load commands**

**Структура файлу в пам’яті** визначається тут і містить відомості про **розташування таблиці символів**, контекст головного потоку на початку виконання та необхідні **shared libraries**. Dynamic loader **(dyld)** отримує інструкції щодо процесу завантаження binary у пам’ять.

Він використовує структуру **load_command**, визначену у згаданому **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Існує близько **50 різних типів load commands**, які система обробляє по-різному. Найпоширеніші з них: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` і `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> По суті, цей тип Load Command визначає, **як завантажити сегменти \_\_TEXT** (виконуваний код) **і \_\_DATA** (дані для процесу) **відповідно до зміщень, зазначених у секції Data**, під час виконання binary.

Ці команди **визначають сегменти**, які **відображаються** у **віртуальний адресний простір** процесу під час його виконання.

Існують **різні типи** сегментів, зокрема сегмент **\_\_TEXT**, що містить виконуваний код програми, і сегмент **\_\_DATA**, що містить дані, які використовує процес. Ці **сегменти розташовані в секції даних** файлу Mach-O.

**Кожен сегмент** можна додатково **розділити** на кілька **секцій**. **Структура load command** містить **інформацію** про **ці секції** у відповідному сегменті.

Спочатку в заголовку розташований **заголовок сегмента**:

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

Приклад заголовка сегмента:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Цей заголовок визначає **кількість секцій, заголовки яких розташовані після нього**:
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

Якщо **додати** **зміщення секції** (0x37DC) до **зміщення**, де **починається arch**, у цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **інформацію про заголовки** з **командного рядка** за допомогою:
```bash
otool -lv /bin/ls
```
Поширені сегменти, завантажені цією командою:

- **`__PAGEZERO`:** Вказує kernel **відобразити** **адресу zero**, щоб її **не можна було читати, записувати або виконувати**. Змінні maxprot і minprot у структурі встановлюються в zero, щоб вказати, що на цій сторінці **немає прав на читання-запис-виконання**.
- Це виділення важливе для **зменшення впливу вразливостей розіменування NULL pointer**. Це пояснюється тим, що XNU застосовує hard page zero, який гарантує, що перша сторінка пам'яті (і лише перша) є недоступною (крім i386). Binary може виконати цю вимогу, створивши малий \_\_PAGEZERO (за допомогою `-pagezero_size`), щоб охопити перші 4k, а решту 32bit memory зробити доступною як у user, так і в kernel mode.
- **`__TEXT`**: Містить **executable** **code** із правами **read** і **execute** (без writable)**.** Поширені sections цього segment:
- `__text`: Скомпільований binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: Рядкові constants для C, Unicode або os logs
- `__stubs` і `__stubs_helper`: Задіяні під час процесу dynamic library loading
- `__unwind_info`: Дані для stack unwind.
- Зверніть увагу, що весь цей content підписаний, але також позначений як executable (що створює більше options для exploitation sections, яким не обов'язково потрібен цей privilege, наприклад sections, призначених для рядків).
- **`__DATA`**: Містить data, доступні для **read** і **write** (без executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Має містити read-only data (але це не зовсім так)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (які було initialized)
- `__bss`: Static variables (які не було initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist тощо): Information, яку використовує Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const не гарантовано є constant (має write permissions), як і інші pointers та GOT. Ця section робить `__const`, деякі initializers і GOT table (після resolved) **read only** за допомогою `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Поширені в новіших Apple Silicon binaries. Ці segments містять pointers, які мають бути authenticated під час load або use (наприклад `__auth_got`). Якщо rebinding, hook або import-patching trick перевіряє лише legacy sections `__got` / `__la_symbol_ptr`, він може пропустити реальні call sites у сучасних `arm64e` binaries. Докладніше про ці sections див. на [цій сторінці](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Містить information для linker (dyld), наприклад entries таблиць symbol, string і relocation. Це generic container для contents, які не належать до `__TEXT` або `__DATA`, а його content описується в інших load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes та export info
- Functions starts: Таблиця start addresses functions
- Data In Code: Data islands у \_\_text
- SYmbol Table: Symbols у binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Містить information, яку використовує Objective-C runtime. Водночас ця information також може міститися в segment \_\_DATA, у різних sections \_\_objc\_\*.
- **`__RESTRICT`**: Segment без content з однією section під назвою **`__restrict`** (також empty), яка гарантує, що під час запуску binary він ігноруватиме змінні середовища DYLD.

Як можна було побачити в code, **segments також підтримують flags** (хоча їх використовують не дуже часто):

- `SG_HIGHVM`: Лише Core (не використовується)
- `SG_FVMLIB`: Не використовується
- `SG_NORELOC`: Segment не має relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Використовується, наприклад, Finder для encryption text segment `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить entrypoint в **attribute entryoff.** Під час load **dyld** просто **додає** це value до (in-memory) **base binary**, а потім **переходить** до цієї instruction, щоб почати виконання code binary.

**`LC_UNIXTHREAD`** містить values, які register має мати під час запуску main thread. Цей механізм уже deprecated, але **`dyld`** досі його використовує. Переглянути vlaues registers, встановлені таким способом, можна за допомогою:
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


Містить інформацію про **code signature Mach-O-файлу**. Він містить лише **offset**, що **вказує** на **signature blob**. Зазвичай він розташований у самому кінці файлу.\
Однак деяку інформацію про цю секцію можна знайти в [**цьому дописі в блозі**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) і в цих [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування binary. Однак, звісно, якщо attacker зможе скомпрометувати процес, він зможе дампити пам’ять у незашифрованому вигляді.

### **`LC_LOAD_DYLINKER`**

Містить **path до executable dynamic linker**, який відображає shared libraries в адресний простір процесу. **Value завжди встановлено в `/usr/lib/dyld`**. Важливо зазначити, що в macOS mapping dylib відбувається в **user mode**, а не в kernel mode.

### **`LC_IDENT`**

Застарілий, але коли налаштовано **generate dumps on panic**, створюється Mach-O core dump, а версія kernel задається в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Сам по собі він безпосередньо ні для чого не корисний, але XNU кешує його разом з іншою інформацією про процес. Його можна використовувати у crash reports.

### **`LC_BUILD_VERSION`**

Сучасні binary зазвичай містять цю команду для оголошення **target platform**, **мінімальної версії OS**, **версії SDK** та, опційно, **версій tool**-ів, використаних для збірки цього slice. З погляду offensive/reversing це дуже корисно для fingerprinting способу збірки sample і швидкого виявлення дивних universal binary, де один slice було скомпільовано з іншим SDK або deployment target. Старіші binary можуть натомість використовувати `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказати змінні середовища для dyld перед виконанням процесу. Це може бути дуже небезпечно, оскільки дозволяє виконати довільний код усередині процесу, тому ця load command використовується лише у збірках dyld із `#define SUPPORT_LC_DYLD_ENVIRONMENT` і додатково обмежує обробку змінними форми `DYLD_..._PATH`, що вказують шляхи завантаження.

### **`LC_DYLD_EXPORTS_TRIE` і `LC_DYLD_CHAINED_FIXUPS`**

Сучасні toolchains часто зберігають метадані export/bind/rebase у цих командах замість того, щоб покладатися лише на старіші opcodes `LC_DYLD_INFO[_ONLY]`. Обидві є записами `linkedit_data_command`, що вказують у **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Компактне trie-дерево із symbols, експортованими image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Ланцюжки fixup для кожного сегмента, які dyld використовує для застосування rebases і binds. На Apple Silicon саме тут також можна зустріти багато сучасних authenticated pointer fixups.

Ці метадані дуже корисні під час відновлення imports/exports, розуміння того, чому dependency, завантажена через `@rpath`, була resolved саме так, або з'ясування причини, через яку hook/rebinding attempt не спрацювала на сучасній цілі `arm64e`. `dyld_info` також можна використовувати для **cache-only dylib paths**, які не існують як окремі файли на диску. Це особливо корисно в сучасній macOS, де багато системних бібліотек існують лише у shared cache.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Ця сучасна команда завантаження здебільшого актуальна під час аналізу **kernel collections / kernelcache-style filesets**. Замість представлення одного окремого образу зовнішній Mach-O виступає контейнером, а кожна `LC_FILESET_ENTRY` вказує на вбудований Mach-O із власним схожим на шлях **entry id**, VM-адресою та зміщенням у файлі. Якщо ви реверсите сучасні компоненти kernel macOS/iOS, ця команда часто є мостом між контейнером верхнього рівня та фактичним образом, який потрібно витягти або дизасемблювати.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Для практичних робочих процесів вилучення див. [цю іншу сторінку про розширення ядра macOS і kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність від **динамічної** **бібліотеки**, яка **вказує** **завантажувачу** (dyld) **завантажити та зв'язати цю бібліотеку**. Для **кожної бібліотеки**, необхідної Mach-O binary, існує команда завантаження `LC_LOAD_DYLIB`.

- Ця команда завантаження є структурою типу **`dylib_command`** (яка містить структуру dylib, що описує фактичну залежну динамічну бібліотеку):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / номер версії сумісності бібліотеки /](<../../../images/image (486).png>)

Цю інформацію також можна отримати з cli за допомогою:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Деякі потенційно пов’язані з malware бібліотеки:

- **DiskArbitration**: Моніторинг USB-накопичувачів
- **AVFoundation:** Захоплення аудіо та відео
- **CoreWLAN**: Сканування Wi-Fi.

> [!TIP]
> Mach-O binary може містити один або **більше** **конструкторів**, які будуть **виконані** **до** адреси, указаної в **LC_MAIN**.\
> Зміщення будь-яких конструкторів зберігаються в секції **\_\_mod_init_func** сегмента **\_\_DATA_CONST**.

## **Mach-O Data**

У центрі файлу розташована область даних, яка складається з кількох сегментів, визначених в області load commands. **У кожному сегменті може міститися різноманітний набір секцій даних**, причому кожна секція **містить код або дані**, специфічні для певного типу.

> [!TIP]
> По суті, data — це частина, що містить усю **інформацію**, завантажену load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Сюди входять:

- **Function table:** Містить інформацію про функції програми.
- **Symbol table**: Містить інформацію про зовнішні функції, які використовує binary.
- Також вона може містити імена внутрішніх функцій, змінних та інші дані.

Щоб перевірити це, можна скористатися інструментом [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або з cli:
```bash
size -m /bin/ls
```
## Загальні секції Objective-C

У сегменті `__TEXT` (r-x):

- `__objc_classname`: Назви класів (рядки)
- `__objc_methname`: Назви методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

У сегменті `__DATA` (rw-):

- `__objc_classlist`: Вказівники на всі класи Objective-C
- `__objc_nlclslist`: Вказівники на Non-Lazy класи Objective-C
- `__objc_catlist`: Вказівник на Categories
- `__objc_nlcatlist`: Вказівники на Non-Lazy Categories
- `__objc_protolist`: Список Protocols
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Посилання

- [1] [Слайси Mach-O не такі прості, як може здатися](https://objective-see.org/blog/blog_0x80.html)
- [2] [Сторінка довідника dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Читання власних Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
