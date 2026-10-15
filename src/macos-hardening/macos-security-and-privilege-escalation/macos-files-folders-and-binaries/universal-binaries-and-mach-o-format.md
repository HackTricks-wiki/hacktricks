# Універсальні бінарні файли macOS і формат Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

У macOS використовується формат виконуваних файлів **Mach-O**. **Універсальний**, або fat, бінарний файл містить кілька зрізів Mach-O, кожен для окремої архітектури. Структури й константи, описані на цій сторінці, визначені у заголовках Apple з відкритим кодом `fat.h` і `loader.h`. <sup>[[5]](#references)</sup>

Образ Mach-O складається з:

- Заголовка
- Команд завантаження
- Даних

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat-заголовок

Знайдіть файл командою: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Заголовок містить байти **magic**, за якими йде **кількість** архітектур, що **містить** файл (`nfat_arch`); для кожної архітектури буде структура `fat_arch`.

Перевірте командою:

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

Як ви, мабуть, здогадалися, універсальний бінарний файл, скомпільований для 2 архітектур, зазвичай **удвічі більший** за файл, скомпільований лише для однієї архітектури.

> [!TIP]
> Під час первинного аналізу malware чи підозрілих програм не зупиняйтеся після того, як `file` визначить «найкращу» архітектуру. Універсальний бінарний файл може містити різні імпорти, команди завантаження або метадані компілятора в кожному зрізі, тож спочатку перелічіть **усі** зрізи, а потім перевірте їх окремо:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

У новіших macOS SDK також доступні допоміжні функції, як-от `macho_for_each_slice()` і `macho_best_slice()` з `<mach-o/utils.h>`. Остання зручна для відтворення того, що завантажив би dyld/kernel, але сканерам усе одно слід перебирати кожен slice, щоб не пропустити вміст, специфічний для певної архітектури.<sup>[[1]](#references)</sup>

## **Заголовок Mach-O**

Заголовок містить основну інформацію про файл, зокрема magic bytes для ідентифікації файлу як Mach-O та інформацію про цільову архітектуру. Його можна знайти за допомогою: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Існують різні типи файлів; їх можна знайти, наприклад, у [**вихідному коді тут**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Найважливіші з них:

- `MH_OBJECT`: Переміщуваний об’єктний файл (проміжний результат компіляції, ще не виконуваний файл).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Файл бібліотеки з фіксованою VM.
- `MH_CORE`: Дампи коду.
- `MH_PRELOAD`: Попередньо завантажений виконуваний файл (більше не підтримується в XNU).
- `MH_DYLIB`: Динамічні бібліотеки.
- `MH_DYLINKER`: Динамічний компонувальник.
- `MH_BUNDLE`: «Файли плагінів». Створюються за допомогою `-bundle` у gcc і явно завантажуються через `NSBundle` або `dlopen`.
- `MH_DYSM`: Супровідний файл `.dSym` (файл із символами для налагодження).
- `MH_KEXT_BUNDLE`: Розширення ядра.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Або за допомогою [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Прапорці Mach-O**

У вихідному коді також визначено кілька прапорців, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю скомпоновано)
- `MH_DYLDLINK`: Компонування Dyld
- `MH_PREBOUND`: Динамічні посилання попередньо зв’язані.
- `MH_SPLIT_SEGS`: Файл розділяє сегменти лише для читання та читання/запису.
- `MH_WEAK_DEFINES`: Бінарний файл має слабко визначені символи
- `MH_BINDS_TO_WEAK`: Бінарний файл використовує слабкі символи
- `MH_ALLOW_STACK_EXECUTION`: Зробити стек виконуваним
- `MH_NO_REEXPORTED_DYLIBS`: Бібліотека не має команд LC_REEXPORT
- `MH_PIE`: Незалежний від розташування виконуваний файл
- `MH_HAS_TLV_DESCRIPTORS`: Є секція зі змінними локального сховища потоків
- `MH_NO_HEAP_EXECUTION`: Заборонити виконання сторінок купи/даних
- `MH_HAS_OBJC`: Бінарний файл має секції oBject-C
- `MH_SIM_SUPPORT`: Підтримка симулятора
- `MH_DYLIB_IN_CACHE`: Використовується для dylib/framework у кеші спільних бібліотек.

## **Команди завантаження Mach-O**

Тут визначено **розташування файлу в пам’яті**, зокрема **місце розташування таблиці символів**, контекст головного потоку на початку виконання та необхідні **спільні бібліотеки**. Динамічному завантажувачу **(dyld)** надаються інструкції щодо завантаження бінарного файлу в пам’ять.

Тут використовується структура **load_command**, визначена у згаданому файлі **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Існує близько **50 різних типів команд завантаження**, які система обробляє по-різному. Найпоширеніші з них: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` і `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> По суті, цей тип команди завантаження визначає, **як завантажувати сегменти \_\_TEXT** (виконуваний код) **і \_\_DATA** (дані для процесу) **відповідно до зміщень, указаних у секції Data**, під час виконання бінарного файла.

Ці команди **визначають сегменти**, які **відображаються** у **віртуальну пам’ять** процесу під час його виконання.

Є **різні типи** сегментів, зокрема сегмент **\_\_TEXT**, який містить виконуваний код програми, і сегмент **\_\_DATA**, що містить дані, які використовує процес. Ці **сегменти розташовані в секції даних** файла Mach-O.

**Кожен сегмент** можна додатково **розділити** на кілька **секцій**. **Структура команди завантаження** містить **інформацію** про **ці секції** у відповідному сегменті.

Спочатку в заголовку міститься **заголовок сегмента**:

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

Якщо **додати** **зміщення секції** (0x37DC) до **зміщення**, з якого **починається архітектура**, у цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **інформацію про заголовки** за допомогою **командного рядка**:

```bash
otool -lv /bin/ls
```

Common segments, які завантажує ця команда:

- **`__PAGEZERO`:** Вказує ядру **відобразити** **нульову адресу** так, щоб її **не можна було читати, записувати в неї чи виконувати код**. Змінні maxprot і minprot у структурі встановлюються в нуль, щоб позначити, що **для цієї сторінки немає прав на читання, запис чи виконання**.
  - Це виділення важливе для **пом’якшення вразливостей розіменування NULL-вказівника**. XNU примусово захищає нульову сторінку, забезпечуючи недоступність першої сторінки пам’яті (лише першої; виняток — i386). Бінарний файл може виконати цю вимогу, створивши невелику \_\_PAGEZERO (за допомогою `-pagezero_size`), яка охоплює перші 4k, і залишивши решту 32-бітної пам’яті доступною в режимах користувача та ядра.
- **`__TEXT`**: Містить виконуваний **код** із правами на **читання** та **виконання** (без права запису)**.** Типові секції цього сегмента:
  - `__text`: скомпільований бінарний код
  - `__const`: константні дані (лише для читання)
  - `__[c/u/os_log]string`: рядкові константи C, Unicode або журналів os
  - `__stubs` і `__stubs_helper`: беруть участь у процесі завантаження динамічних бібліотек
  - `__unwind_info`: дані для розмотування стека.
  - Зверніть увагу, що весь цей вміст підписаний, але також позначений як виконуваний (що створює додаткові можливості для експлуатації секцій, яким цей привілей не обов’язково потрібен, як-от секцій, призначених для рядків).
- **`__DATA`**: Містить дані, доступні для **читання** та **запису** (без права виконання)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: покажчик на неледачо зв’язуваний символ (зв’язується під час завантаження)
  - `__la_symbol_ptr`: покажчик на ледачо зв’язуваний символ (зв’язується під час використання)
  - `__const`: має містити дані лише для читання (насправді це не гарантовано)
  - `__cfstring`: рядки CoreFoundation
  - `__data`: глобальні змінні (ініціалізовані)
  - `__bss`: статичні змінні (неініціалізовані)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist тощо): інформація, яку використовує середовище виконання Objective-C
- **`__DATA_CONST`**: Незмінність \_\_DATA.\_\_const не гарантована (є права на запис), як і незмінність інших покажчиків та GOT. Цей сегмент за допомогою `mprotect` робить `__const`, деякі ініціалізатори та таблицю GOT (після розв’язання символів) **доступними лише для читання**.
- **`__AUTH` / `__AUTH_CONST`**: Типові сегменти в нових бінарних файлах Apple Silicon. Вони містять покажчики, які мають пройти автентифікацію під час завантаження або використання (наприклад, `__auth_got`). Якщо rebinding, hook або import-patching прийом перевіряє лише застарілі секції `__got` / `__la_symbol_ptr`, він може не виявити фактичні точки виклику в сучасних бінарних файлах `arm64e`. Докладніше про ці секції див. на [цій сторінці](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Містить інформацію для лінкера (dyld), зокрема записи таблиць символів, рядків і релокацій. Це універсальний контейнер для вмісту, який не належить до `__TEXT` чи `__DATA`; його вміст описується в інших командах завантаження.
  - Інформація dyld: опкоди rebase, неледачого/ледачого/слабкого зв’язування та дані експорту
  - Початки функцій: таблиця початкових адрес функцій
  - Data In Code: ділянки даних у \_\_text
  - Таблиця символів: символи в бінарному файлі
  - Таблиця непрямих символів: символи покажчиків/stub
  - Таблиця рядків
  - Підпис коду
- **`__OBJC`**: Містить інформацію, яку використовує середовище виконання Objective-C. Хоча цю інформацію також можна знайти в сегменті \_\_DATA, у різних секціях \_\_objc\_\*.
- **`__RESTRICT`**: Сегмент без вмісту, з єдиною секцією **`__restrict`** (також порожньою), що забезпечує ігнорування змінних середовища DYLD під час запуску бінарного файлу.

Як видно з коду, **сегменти також підтримують прапорці** (хоча їх використовують нечасто):

- `SG_HIGHVM`: лише ядро (не використовується)
- `SG_FVMLIB`: не використовується
- `SG_NORELOC`: сегмент не має релокацій
- `SG_PROTECTED_VERSION_1`: шифрування. Наприклад, використовується Finder для шифрування сегмента `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить точку входу в **атрибуті entryoff.** Під час завантаження **dyld** просто **додає** це значення до (розташованої в пам’яті) **базової адреси бінарного файлу**, а потім **переходить** до цієї інструкції, щоб почати виконання коду бінарного файлу.

**`LC_UNIXTHREAD`** містить значення, які мають бути встановлені в регістрах під час запуску головного потоку. Цей механізм уже застарів, але **`dyld`** досі його використовує. Переглянути значення, встановлені в регістрах за допомогою цього механізму, можна так:

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


Містить інформацію про **підпис коду Mach-O-файлу**. Він містить лише **зміщення**, яке **вказує** на **блок підпису**. Зазвичай він розташований у самому кінці файлу.\
Докладніше про цей розділ можна дізнатися в [**цьому дописі в блозі**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) і [**цьому gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування бінарних файлів. Однак, звісно, якщо зловмиснику вдасться скомпрометувати процес, він зможе дампити незашифровану пам’ять.

### **`LC_LOAD_DYLINKER`**

Містить **шлях до виконуваного файлу динамічного лінкера**, який відображає спільні бібліотеки в адресний простір процесу. **Значення завжди дорівнює `/usr/lib/dyld`**. Важливо зазначити, що в macOS відображення dylib відбувається в **режимі користувача**, а не в режимі ядра.

### **`LC_IDENT`**

Застаріла команда, але якщо налаштовано створення дампів під час panic, створюється дамп ядра Mach-O, а версія ядра задається в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Сам по собі він не має особливої користі, але XNU кешує його разом з іншою інформацією про процес. Його можна використовувати у звітах про збої.

### **`LC_BUILD_VERSION`**

Сучасні бінарні файли зазвичай містять цю команду, щоб указати **цільову платформу**, **мінімальну версію ОС**, **версію SDK** і, за бажанням, **версії інструментів**, використаних для збирання цього slice. З погляду offensive/reversing це дуже корисно для визначення способу збирання зразка та швидкого виявлення підозрілих universal binaries, у яких один slice скомпільовано з іншим SDK або з іншою цільовою версією ОС. У старіших бінарних файлах натомість може використовуватися `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказувати змінні середовища для dyld перед виконанням процесу. Це може бути дуже небезпечно, оскільки дає змогу виконувати довільний код у процесі, тому ця команда завантаження використовується лише в збірках dyld із `#define SUPPORT_LC_DYLD_ENVIRONMENT` і додатково обмежує обробку лише змінними формату `DYLD_..._PATH`, що задають шляхи завантаження.

### **`LC_DYLD_EXPORTS_TRIE` і `LC_DYLD_CHAINED_FIXUPS`**

У сучасних toolchain-ах метадані експорту, прив’язки та перебазування часто зберігаються в цих командах, а не лише в старих опкодах `LC_DYLD_INFO[_ONLY]`. Обидві є записами `linkedit_data_command`, що вказують на дані в **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: компактне дерево зі символами, експортованими образом.
- **`LC_DYLD_CHAINED_FIXUPS`**: ланцюжки виправлень для кожного сегмента, які dyld використовує для застосування перебазувань і прив’язок. На Apple Silicon тут також можна знайти багато сучасних виправлень автентифікованих вказівників.

Ці метадані дуже корисні для відновлення імпортів/експортів, розуміння того, чому залежність, завантажена через `@rpath`, була розв’язана саме так, або з’ясування, чому спроба hook/rebinding не вдалася на сучасній цілі `arm64e`. `dyld_info` також можна використовувати зі шляхами dylib, наявними лише в кеші, які не існують як окремі файли на диску. Це особливо корисно в сучасній macOS, де багато системних бібліотек містяться лише в shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ця сучасна команда завантаження здебільшого важлива під час аналізу **наборів файлів kernel collections / kernelcache**. Замість представлення одного окремого образу зовнішній Mach-O слугує контейнером, а кожен `LC_FILESET_ENTRY` вказує на вбудований Mach-O із власним схожим на шлях **ідентифікатором запису**, VM-адресою та файловим зсувом. Якщо ви досліджуєте сучасні компоненти ядра macOS/iOS, ця команда часто є сполучною ланкою між контейнером верхнього рівня та власне образом, який потрібно видобути або дизасемблювати.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

For practical extraction workflows, check [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність від **dynamic** **library**, яка **вказує** **loader** (dyld) **завантажити та зв’язати зазначену бібліотеку**. У Mach-O binary є команда завантаження `LC_LOAD_DYLIB` **для кожної бібліотеки**, від якої він залежить.

- Ця команда завантаження є структурою типу **`dylib_command`** (яка містить структуру dylib, що описує фактичну залежну dynamic library):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t версія сумісності; / номер версії сумісності бібліотеки /](<../../../images/image (486).png>)

Цю інформацію також можна отримати в CLI за допомогою:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Деякі бібліотеки, потенційно пов’язані зі шкідливим ПЗ:

- **DiskArbitration**: Моніторинг USB-накопичувачів
- **AVFoundation:** Захоплення аудіо та відео
- **CoreWLAN**: Сканування Wi-Fi.

> [!TIP]
> Бінарний файл Mach-O може містити один або **більше** **конструкторів**, які **виконуються** **до** адреси, зазначеної в **LC_MAIN**.\
> Зміщення будь-яких конструкторів зберігаються в секції **\_\_mod_init_func** сегмента **\_\_DATA_CONST**.

## **Дані Mach-O**

У центрі файла розташована область даних, що складається з кількох сегментів, визначених в області команд завантаження. **У кожному сегменті можуть міститися різноманітні секції даних**, кожна з яких **містить код або дані**, специфічні для певного типу.

> [!TIP]
> Дані — це, по суті, частина, що містить усю **інформацію**, яку завантажують команди завантаження **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

До неї належать:

- **Таблиця функцій:** містить інформацію про функції програми.
- **Таблиця символів**: містить інформацію про зовнішні функції, які використовує бінарний файл.
- Вона також може містити назви внутрішніх функцій і змінних тощо.

Для перевірки можна скористатися інструментом [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або з CLI:

```bash
size -m /bin/ls
```

### Додані дані та оверлеї зі зворотним розбором

Завантажувач може зберігати конфігурацію в доданих даних, а не в іменованій секції Mach-O. Тоді зворотний парсер орієнтується на маркер у кінці файла, зчитує розмір, збережений безпосередньо перед ним, і використовує це значення, щоб знайти та розшифрувати попередній блок даних. В одному дослідженому універсальному завантажувачі така структура використовувалася для URL завантажувача, зашифрованого XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Під час реверсингу незнайомого бінарного файла перевіряйте байти навколо впізнаваних кінцевих маркерів і простежуйте кожне обчислення розміру у зворотному напрямку, перш ніж припускати, що рядки чи конфігурація обов’язково належать до секції load command. Маркер і XOR-ключ залежать від конкретного зразка; повторно використовуваний прийом — це самодокументований трейлер.

## Поширені секції Objective-C

У сегменті `__TEXT` (r-x):

- `__objc_classname`: Назви класів (рядки)
- `__objc_methname`: Назви методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

У сегменті `__DATA` (rw-):

- `__objc_classlist`: Вказівники на всі класи Objective-C
- `__objc_nlclslist`: Вказівники на класи Objective-C, що не є Lazy
- `__objc_catlist`: Вказівник на категорії
- `__objc_nlcatlist`: Вказівники на категорії, що не є Lazy
- `__objc_protolist`: Список протоколів
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Див. також: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Зрізи Mach-O не такі прості, як може здатися](https://objective-see.org/blog/blog_0x80.html)
- [2] [Сторінка man dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Читання власних entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Відкритий вихідний код Apple — Mach-O `fat.h` і `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Нова версія викрадача даних MacSync для macOS націлена на криптоентузіастів і розробників](https://securelist.com/macsync-new-version/121383/)
