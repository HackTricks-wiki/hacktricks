# macOS Універсальні бінарні файли та формат Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Бінарні файли Mac OS зазвичай компілюються як **універсальні бінарні файли**. **Універсальний бінарний файл** може **підтримувати кілька архітектур в одному файлі**.

Ці бінарні файли слідують структурі **Mach-O**, яка в основному складається з:

- Заголовок
- Команди завантаження
- Дані

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

Заголовок містить **magic**-байти, за якими йде **кількість** **архітектур**, які **містить** файл (`nfat_arch`), і для кожної архітектури існує структура `fat_arch`.

Перевірити це можна за допомогою:

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

Як ви, мабуть, здогадуєтеся, зазвичай універсальний бінарний файл, скомпільований для 2 архітектур, **подвоює розмір** порівняно з тим, що скомпільований лише для однієї архітектури.

## **Mach-O Header**

Заголовок містить базову інформацію про файл, таку як magic-байти для ідентифікації його як Mach-O файлу та інформацію про цільову архітектуру. Ви можете знайти його в: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Існують різні типи файлів, їх можна знайти визначеними в [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Найважливіші з них:

- `MH_OBJECT`: Relocatable object file (intermediate products of compilation, not executables yet).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Файл бібліотеки Fixed VM.
- `MH_CORE`: Дампи коду
- `MH_PRELOAD`: Попередньо завантажений виконуваний файл (більше не підтримується в XNU)
- `MH_DYLIB`: Динамічні бібліотеки
- `MH_DYLINKER`: Динамічний лінкер
- `MH_BUNDLE`: "Plugin files". Генеруються за допомогою -bundle в gcc і явно завантажуються через `NSBundle` або `dlopen`.
- `MH_DYSM`: Супутній `.dSym` файл (файл із символами для налагодження).
- `MH_KEXT_BUNDLE`: Розширення ядра.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Або використовуючи [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O прапори**

Исходний код також визначає кілька прапорів, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю зв'язаний)
- `MH_DYLDLINK`: Dyld лінкування
- `MH_PREBOUND`: Динамічні посилання попередньо зв'язані.
- `MH_SPLIT_SEGS`: Файл розділяє r/o та r/w сегменти.
- `MH_WEAK_DEFINES`: Бінарний файл має слабо визначені символи
- `MH_BINDS_TO_WEAK`: Бінарний файл використовує weak символи
- `MH_ALLOW_STACK_EXECUTION`: Дозволяє виконання коду на стеку
- `MH_NO_REEXPORTED_DYLIBS`: Бібліотека без команд LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Є секція з thread-local змінними
- `MH_NO_HEAP_EXECUTION`: Заборонено виконання на сторінках heap/даних
- `MH_HAS_OBJC`: Бінарний файл містить секції Objective-C
- `MH_SIM_SUPPORT`: Підтримка симулятора
- `MH_DYLIB_IN_CACHE`: Використовується для dylibs/frameworks у кеші спільних бібліотек.

## **Команди завантаження Mach-O**

Тут визначається розташування файлу в пам'яті, з детальним описом розташування таблиці символів, контексту головного потоку на початку виконання та необхідних спільних бібліотек. Надаються інструкції динамічному завантажувачу (dyld) щодо процесу завантаження бінарного файлу в пам'ять.

Використовується структура `load_command`, визначена у згаданому `loader.h`:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> По суті, цей тип Load Command визначає, **як завантажувати сегменти \_\_TEXT** (виконуваний код) **та \_\_DATA** (дані процесу) **відповідно до зсувів, вказаних у секції даних**, коли бінарник виконується.

Ці команди **визначають сегменти**, які **відображаються** в **віртуальній пам'яті процесу** під час його виконання.

Існують **різні типи** сегментів, наприклад сегмент **\_\_TEXT**, який містить виконуваний код програми, та сегмент **\_\_DATA**, який містить дані, що використовуються процесом. Ці **сегменти знаходяться в секції даних** файлу Mach-O.

**Кожен сегмент** може бути додатково **поділений** на кілька **секцій**. **Структура load command** містить **інформацію** про **ці секції** в межах відповідного сегменту.

У заголовку спочатку знаходиться **segment header**:

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

Цей заголовок визначає **кількість секцій**, заголовки яких з'являються після нього:
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
Приклад **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Якщо ви **додасте** **section offset** (0x37DC) до **offset**, де **arch starts** (у цьому випадку `0x18000`) --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **headers information** з **command line** за допомогою:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Він інструктує ядро **відобразити** адресу нуль так, щоб її **не можна було читати, записувати або виконувати**. Змінні maxprot і minprot у структурі встановлені в нуль, щоб вказати, що на цій сторінці **немає прав на читання-запис-виконання**.
- Це виділення важливе для **пом’якшення вразливостей через dereference NULL pointer**. Це тому, що XNU накладає жорстку сторінку нуля, яка забезпечує, що перша сторінка (тільки перша) пам’яті недоступна (за винятком i386). Бінарник може виконати цю вимогу, створивши невеликий \_\_PAGEZERO (використовуючи `-pagezero_size`) щоб покрити перші 4k і зробивши решту 32-бітної пам’яті доступною як у користувацькому, так і в ядровому режимі.
- **`__TEXT`**: Містить **виконуваний** **код** з правами **читання** та **виконання** (без запису)**.** Звичайні секції цього сегмента:
- `__text`: Скомпільований бінарний код
- `__const`: Константні дані (тільки для читання)
- `__[c/u/os_log]string`: C, Unicode або os log рядкові константи
- `__stubs` і `__stubs_helper`: Залучені під час динамічного завантаження бібліотек
- `__unwind_info`: Дані для розгортання стеку (stack unwind)
- Зауважте, що весь цей вміст підписаний, але також позначений як виконуваний (що створює більше опцій для експлуатації секцій, які фактично не потребують цього привілею, наприклад секції, присвячені рядкам).
- **`__DATA`**: Містить дані, які **можна читати** і **записувати** (без виконання)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Повинні бути даними лише для читання (насправді ні)
- `__cfstring`: CoreFoundation рядки
- `__data`: Глобальні змінні (які були ініціалізовані)
- `__bss`: Статичні змінні (які не були ініціалізовані)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Інформація, що використовується рантаймом Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const не гарантується як константа (має права на запис), так само як і інші покажчики та GOT. Цей сегмент робить `__const`, деякі ініціалізатори та таблицю GOT (після її розв’язання) **тільки для читання** за допомогою `mprotect`.
- **`__LINKEDIT`**: Містить інформацію для лінкера (dyld), таку як таблиці символів, рядків та записів релокацій. Це загальний контейнер для вмісту, який не входить до `__TEXT` або `__DATA`, і його вміст описується в інших load командах.
- dyld information: Rebase, опкоди non-lazy/lazy/weak binding та інформація про export
- Початки функцій: Таблиця адрес початку функцій
- Data In Code: Острови даних у \_\_text
- Таблиця символів: Символи у бінарному файлі
- Indirect Symbol Table: Показникові/заглушкові символи
- String Table
- Code Signature
- **`__OBJC`**: Містить інформацію, яку використовує рантайм Objective-C. Хоча ця інформація також може бути знайдена в сегменті \_\_DATA, у різних секціях \_\_objc\_\*.
- **`__RESTRICT`**: Сегмент без вмісту з єдиною секцією під назвою **`__restrict`** (також порожньою), який гарантує, що при виконанні бінарника він ігноруватиме DYLD змінні середовища.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Тільки ядро (не використовується)
- `SG_FVMLIB`: Не використовується
- `SG_NORELOC`: Сегмент не має релокацій
- `SG_PROTECTED_VERSION_1`: Шифрування. Використовується, наприклад, Finder для шифрування текстового сегмента `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить точку входу в атрибуті **entryoff.** Під час завантаження **`dyld`** просто **додає** це значення до (в пам’яті) **бази бінарника**, після чого **переходить** до цієї інструкції, щоб розпочати виконання коду бінарника.

**`LC_UNIXTHREAD`** містить значення, які повинні бути встановлені у регістрах при запуску головного потоку. Воно вже застаріле, але **`dyld`** все ще його використовує. Можна побачити значення регістрів, встановлені цим, за допомогою:
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


Містить інформацію про **code signature файлу Mach-O**. Воно містить лише **offset**, який **вказує** на **signature blob**. Зазвичай це розташовано в самому кінці файлу.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування бінарників. Проте, якщо зловмисникові вдасться скомпрометувати процес, він зможе дампнути пам'ять у незашифрованому вигляді.

### **`LC_LOAD_DYLINKER`**

Містить **шлях до виконуваного файлу dynamic linker**, який відображає shared libraries в адресний простір процесу. The **value is always set to `/usr/lib/dyld`**. Важливо зазначити, що в macOS відображення dylib відбувається в **user mode**, а не в kernel mode.

### **`LC_IDENT`**

Застарілий, але коли налаштовано генерацію дампів при panic, створюється Mach-O core dump і версія ядра встановлюється в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Прямого широкого застосування немає, але XNU кешує його разом з рештою інформації про процес. Може використовуватись у crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказати змінні оточення для dyld перед запуском процесу. Це може бути досить небезпечно, оскільки дозволяє виконати довільний код всередині процесу, тому ця load command використовується лише в збірках dyld з `#define SUPPORT_LC_DYLD_ENVIRONMENT` і додатково обмежує обробку лише змінними у формі `DYLD_..._PATH`, які задають шляхи завантаження.

### **`LC_LOAD_DYLIB`**

Ця load command описує залежність від **dynamic** **library**, яка **наказує** **loader** (dyld) **завантажити та зв'язати цю бібліотеку**. Існує команда `LC_LOAD_DYLIB` **для кожної бібліотеки**, яку вимагає Mach-O бінар.

- Ця load command — структура типу **`dylib_command`** (яка містить struct dylib, що описує власне залежну dynamic library):
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

Ви також можете отримати цю інформацію з cli за допомогою:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Деякі потенційні бібліотеки, пов'язані з malware:

- **DiskArbitration**: Моніторинг USB-накопичувачів
- **AVFoundation:** Захоплення аудіо та відео
- **CoreWLAN**: Сканування Wi‑Fi

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Дані**

У центрі файлу знаходиться область даних, яка складається з кількох сегментів, як визначено в області load-commands. **У кожному сегменті може міститися різноманіття секцій даних**, причому кожна секція **містить код або дані**, специфічні для певного типу.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Це включає:

- **Function table:** Яка містить інформацію про функції програми.
- **Symbol table**: Яка містить інформацію про зовнішні функції, що використовуються бінарним файлом
- Також може містити імена внутрішніх функцій, змінних та інше.

Щоб перевірити це, ви можете використати інструмент [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або з командного рядка:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

У `__TEXT` сегменті (r-x):

- `__objc_classname`: Імена класів (рядки)
- `__objc_methname`: Імена методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

У `__DATA` сегменті (rw-):

- `__objc_classlist`: Вказівники на всі Objetive-C класи
- `__objc_nlclslist`: Вказівники на Non-Lazy Objective-C класи
- `__objc_catlist`: Вказівник на Categories
- `__objc_nlcatlist`: Вказівник на Non-Lazy Categories
- `__objc_protolist`: Список протоколів
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
