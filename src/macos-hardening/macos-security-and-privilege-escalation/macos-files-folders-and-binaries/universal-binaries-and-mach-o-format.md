# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS бінарники зазвичай компілюються як **універсальні бінарники**. **Універсальний бінарник** може **підтримувати кілька архітектур в одному файлі**.

Ці бінарники слідують **Mach-O структурі**, яка в основному складається з:

- Заголовка
- Команд завантаження
- Даних

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Шукайте файл за допомогою: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC або FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* кількість структур, що слідують */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* специфікатор процесора (int) */
cpu_subtype_t	cpusubtype;	/* специфікатор машини (int) */
uint32_t	offset;		/* зсув файлу до цього об'єктного файлу */
uint32_t	size;		/* розмір цього об'єктного файлу */
uint32_t	align;		/* вирівнювання як ступінь 2 */
};
</code></pre>

Заголовок має **магічні** байти, за якими слідує **число** **архітектур**, які файл **містить** (`nfat_arch`), і кожна архітектура матиме структуру `fat_arch`.

Перевірте це за допомогою:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (для архітектури x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (для архітектури arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>архітектура x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>архітектура arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

або за допомогою інструменту [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Як ви, напевно, думаєте, зазвичай універсальний бінарник, скомпільований для 2 архітектур, **подвоює розмір** одного, скомпільованого лише для 1 архітектури.

## **Mach-O Header**

Заголовок містить основну інформацію про файл, таку як магічні байти для його ідентифікації як Mach-O файл та інформацію про цільову архітектуру. Ви можете знайти його за допомогою: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Є різні типи файлів, ви можете знайти їх визначення в [**джерельному коді, наприклад, тут**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Найважливіші з них:

- `MH_OBJECT`: Переміщуваний об'єктний файл (проміжні продукти компіляції, ще не виконувані).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Фіксований файл бібліотеки VM.
- `MH_CORE`: Знімки коду
- `MH_PRELOAD`: Попередньо завантажений виконуваний файл (більше не підтримується в XNU)
- `MH_DYLIB`: Динамічні бібліотеки
- `MH_DYLINKER`: Динамічний зв'язувач
- `MH_BUNDLE`: "Файли плагінів". Генеруються за допомогою -bundle в gcc і явно завантажуються за допомогою `NSBundle` або `dlopen`.
- `MH_DYSM`: Супутній файл `.dSym` (файл з символами для налагодження).
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

## **Mach-O Прапори**

Джерельний код також визначає кілька прапорів, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю зв'язано)
- `MH_DYLDLINK`: Зв'язування Dyld
- `MH_PREBOUND`: Динамічні посилання попередньо зв'язані.
- `MH_SPLIT_SEGS`: Файл розділяє сегменти r/o та r/w.
- `MH_WEAK_DEFINES`: Бінарний файл має слабко визначені символи
- `MH_BINDS_TO_WEAK`: Бінарний файл використовує слабкі символи
- `MH_ALLOW_STACK_EXECUTION`: Зробити стек виконуваним
- `MH_NO_REEXPORTED_DYLIBS`: Бібліотека не має команд LC_REEXPORT
- `MH_PIE`: Виконуваний файл, незалежний від позиції
- `MH_HAS_TLV_DESCRIPTORS`: Є секція з локальними змінними потоку
- `MH_NO_HEAP_EXECUTION`: Немає виконання для сторінок купи/даних
- `MH_HAS_OBJC`: Бінарний файл має секції oBject-C
- `MH_SIM_SUPPORT`: Підтримка емулятора
- `MH_DYLIB_IN_CACHE`: Використовується для dylibs/frameworks у кеші спільних бібліотек.

## **Команди завантаження Mach-O**

**Розташування файлу в пам'яті** вказується тут, детально описуючи **місцезнаходження таблиці символів**, контекст основного потоку на початку виконання та необхідні **спільні бібліотеки**. Інструкції надаються динамічному завантажувачу **(dyld)** щодо процесу завантаження бінарного файлу в пам'ять.

Використовується структура **load_command**, визначена в згаданому **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Є близько **50 різних типів команд завантаження**, які система обробляє по-різному. Найпоширеніші з них: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` та `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> В основному, цей тип команди завантаження визначає **як завантажити \_\_TEXT** (виконуваний код) **та \_\_DATA** (дані для процесу) **сегменти** відповідно до **зсувів, вказаних у секції даних** під час виконання бінарного файлу.

Ці команди **визначають сегменти**, які **відображаються** у **віртуальному адресному просторі** процесу під час його виконання.

Існують **різні типи** сегментів, такі як сегмент **\_\_TEXT**, який містить виконуваний код програми, та сегмент **\_\_DATA**, який містить дані, що використовуються процесом. Ці **сегменти розташовані в секції даних** файлу Mach-O.

**Кожен сегмент** може бути додатково **поділений** на кілька **секцій**. **Структура команди завантаження** містить **інформацію** про **ці секції** в межах відповідного сегмента.

У заголовку спочатку ви знайдете **заголовок сегмента**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* для 64-бітних архітектур */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* включає sizeof section_64 structs */
char		segname[16];	/* ім'я сегмента */
uint64_t	vmaddr;		/* адреса пам'яті цього сегмента */
uint64_t	vmsize;		/* розмір пам'яті цього сегмента */
uint64_t	fileoff;	/* зсув файлу цього сегмента */
uint64_t	filesize;	/* кількість для відображення з файлу */
int32_t		maxprot;	/* максимальний захист VM */
int32_t		initprot;	/* початковий захист VM */
<strong>	uint32_t	nsects;		/* кількість секцій у сегменті */
</strong>	uint32_t	flags;		/* прапори */
};
</code></pre>

Приклад заголовка сегмента:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Цей заголовок визначає **кількість секцій, заголовки яких з'являються після** нього:
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

Якщо ви **додасте** **зсув секції** (0x37DC) + **зсув**, де **архітектура починається**, в цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можливо отримати **інформацію про заголовки** з **командного рядка** за допомогою:
```bash
otool -lv /bin/ls
```
Загальні сегменти, завантажені цим cmd:

- **`__PAGEZERO`:** Він інструктує ядро **відобразити** **адресу нуль** так, щоб вона **не могла бути прочитана, записана або виконана**. Змінні maxprot і minprot у структурі встановлені в нуль, щоб вказати, що **немає прав на читання-запис-виконання на цій сторінці**.
- Це виділення важливе для **зменшення вразливостей, пов'язаних з розіменуванням нульових вказівників**. Це пов'язано з тим, що XNU забезпечує жорстку нульову сторінку, яка гарантує, що перша сторінка (тільки перша) пам'яті недоступна (за винятком i386). Бінарний файл може виконати ці вимоги, створивши невелику \_\_PAGEZERO (використовуючи `-pagezero_size`), щоб покрити перші 4k, а решта 32-бітної пам'яті була доступна як в режимі користувача, так і в режимі ядра.
- **`__TEXT`**: Містить **виконуваний** **код** з **правами на читання** та **виконання** (без запису)**.** Загальні секції цього сегмента:
- `__text`: Скомпільований бінарний код
- `__const`: Константні дані (тільки для читання)
- `__[c/u/os_log]string`: Константи рядків C, Unicode або os logs
- `__stubs` та `__stubs_helper`: Бере участь у процесі завантаження динамічної бібліотеки
- `__unwind_info`: Дані про розгортання стеку.
- Зверніть увагу, що весь цей вміст підписаний, але також позначений як виконуваний (створюючи більше можливостей для експлуатації секцій, які не обов'язково потребують цього привілею, як секції, присвячені рядкам).
- **`__DATA`**: Містить дані, які є **читабельними** та **записуваними** (без виконуваних)**.**
- `__got:` Глобальна таблиця зсувів
- `__nl_symbol_ptr`: Неледачний (прив'язка при завантаженні) вказівник символу
- `__la_symbol_ptr`: Ледачий (прив'язка при використанні) вказівник символу
- `__const`: Має бути даними тільки для читання (насправді не так)
- `__cfstring`: Рядки CoreFoundation
- `__data`: Глобальні змінні (які були ініціалізовані)
- `__bss`: Статичні змінні (які не були ініціалізовані)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist тощо): Інформація, що використовується середовищем виконання Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const не гарантує, що є константним (права на запис), так само як і інші вказівники та GOT. Цей розділ робить `__const`, деякі ініціалізатори та таблицю GOT (після розв'язання) **тільки для читання** за допомогою `mprotect`.
- **`__LINKEDIT`**: Містить інформацію для компоновщика (dyld), таку як символи, рядки та записи таблиці переміщення. Це загальний контейнер для вмісту, який не знаходиться в `__TEXT` або `__DATA`, а його вміст описується в інших командах завантаження.
- Інформація dyld: Переміщення, неледачні/ледачі/слабкі коди прив'язки та інформація про експорт
- Початок функцій: Таблиця початкових адрес функцій
- Дані в коді: Острівці даних у \_\_text
- Таблиця символів: Символи в бінарному файлі
- Таблиця непрямих символів: Вказівники/стаб символів
- Таблиця рядків
- Код підпису
- **`__OBJC`**: Містить інформацію, що використовується середовищем виконання Objective-C. Хоча ця інформація також може бути знайдена в сегменті \_\_DATA, в різних секціях \_\_objc\_\*.
- **`__RESTRICT`**: Сегмент без вмісту з єдиною секцією, що називається **`__restrict`** (також порожня), яка забезпечує, що при виконанні бінарного файлу він ігноруватиме змінні середовища DYLD.

Як було видно в коді, **сегменти також підтримують прапорці** (хоча вони не використовуються дуже часто):

- `SG_HIGHVM`: Тільки ядро (не використовується)
- `SG_FVMLIB`: Не використовується
- `SG_NORELOC`: Сегмент не має переміщення
- `SG_PROTECTED_VERSION_1`: Шифрування. Використовується, наприклад, Finder для шифрування тексту сегмента `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить точку входу в **атрибуті entryoff.** Під час завантаження **dyld** просто **додає** це значення до (в пам'яті) **бази бінарного файлу**, а потім **переходить** до цієї інструкції, щоб почати виконання коду бінарного файлу.

**`LC_UNIXTHREAD`** містить значення, які повинні мати регістри при запуску основного потоку. Це вже застаріло, але **`dyld`** все ще використовує це. Можна побачити значення регістрів, встановлені цим:
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

Містить інформацію про **код підпису файлу Macho-O**. Він містить лише **зсув**, який **вказує** на **блоб підпису**. Це зазвичай знаходиться в самому кінці файлу.\
Однак ви можете знайти деяку інформацію про цей розділ у [**цьому блозі**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) та у [**цих гістах**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування бінарних файлів. Однак, звичайно, якщо зловмисник зможе скомпрометувати процес, він зможе скинути пам'ять у незашифрованому вигляді.

### **`LC_LOAD_DYLINKER`**

Містить **шлях до виконуваного файлу динамічного зв'язувача**, який відображає спільні бібліотеки в адресному просторі процесу. **Значення завжди встановлюється на `/usr/lib/dyld`**. Важливо зазначити, що в macOS, відображення dylib відбувається в **режимі користувача**, а не в режимі ядра.

### **`LC_IDENT`**

Застарілий, але коли налаштований для генерації дампів при паніці, створюється дамп ядра Mach-O, і версія ядра встановлюється в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Він корисний для чого завгодно, але XNU кешує його разом з рештою інформації про процес. Його можна використовувати в звітах про збої.

### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказати змінні середовища для dyld перед виконанням процесу. Це може бути дуже небезпечно, оскільки може дозволити виконувати довільний код всередині процесу, тому ця команда завантаження використовується лише в dyld, зібраному з `#define SUPPORT_LC_DYLD_ENVIRONMENT`, і додатково обмежує обробку лише змінними у формі `DYLD_..._PATH`, що вказують шляхи завантаження.

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність **динамічної** **бібліотеки**, яка **інструктує** **завантажувач** (dyld) **завантажити та зв'язати цю бібліотеку**. Існує команда завантаження `LC_LOAD_DYLIB` **для кожної бібліотеки**, яка потрібна бінарному файлу Mach-O.

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
![](<../../../images/image (486).png>)

Ви також можете отримати цю інформацію з командного рядка за допомогою:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Деякі потенційні бібліотеки, пов'язані з шкідливим ПЗ:

- **DiskArbitration**: Моніторинг USB-накопичувачів
- **AVFoundation:** Захоплення аудіо та відео
- **CoreWLAN**: Сканування Wifi.

> [!NOTE]
> Mach-O бінарний файл може містити один або **більше** **конструкторів**, які будуть **виконані** **перед** адресою, вказаною в **LC_MAIN**.\
> Зсуви будь-яких конструкторів зберігаються в секції **\_\_mod_init_func** сегмента **\_\_DATA_CONST**.

## **Дані Mach-O**

В основі файлу лежить регіон даних, який складається з кількох сегментів, як визначено в регіоні команд завантаження. **Різноманітні секції даних можуть бути розміщені в кожному сегменті**, при цьому кожна секція **містить код або дані**, специфічні для певного типу.

> [!TIP]
> Дані в основному є частиною, що містить всю **інформацію**, яка завантажується командами завантаження **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Це включає:

- **Таблиця функцій:** Яка містить інформацію про функції програми.
- **Таблиця символів**: Яка містить інформацію про зовнішні функції, що використовуються бінарним файлом
- Вона також може містити внутрішні функції, імена змінних та інше.

Щоб перевірити це, ви можете використовувати інструмент [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або з командного рядка:
```bash
size -m /bin/ls
```
## Objetive-C Загальні Розділи

В `__TEXT` сегменті (r-x):

- `__objc_classname`: Імена класів (рядки)
- `__objc_methname`: Імена методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

В `__DATA` сегменті (rw-):

- `__objc_classlist`: Вказівники на всі класи Objective-C
- `__objc_nlclslist`: Вказівники на не-ліниві класи Objective-C
- `__objc_catlist`: Вказівник на категорії
- `__objc_nlcatlist`: Вказівник на не-ліниві категорії
- `__objc_protolist`: Список протоколів
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
