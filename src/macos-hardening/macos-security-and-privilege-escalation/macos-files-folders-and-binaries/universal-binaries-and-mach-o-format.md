# Універсальні бінарні файли macOS і формат Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

macOS використовує формат виконуваних файлів **Mach-O**. **Універсальний**, або fat, бінарний файл містить кілька Mach-O-слайсів, кожен для окремої архітектури, в одному файлі. Структури й константи, описані на цій сторінці, визначено у відкритих заголовкових файлах Apple `fat.h` і `loader.h`. <sup>[[5]](#references)</sup>

Образ Mach-O складається з:

- Заголовка
- Команд завантаження
- Даних

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Заголовок Fat

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

Заголовок містить байти **magic**, за якими йде **кількість** **архітектур**, що **містяться у файлі** (`nfat_arch`); кожна архітектура матиме структуру `fat_arch`.

Перевірте це командою:

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

Як ви, мабуть, уже здогадалися, універсальний бінарний файл, скомпільований для 2 архітектур, зазвичай **удвічі більший** за файл, скомпільований лише для 1 архітектури.

> [!TIP]
> Під час аналізу malware або підозрілих програм не зупиняйтеся на архітектурі, яку `file` визначає як «найкращу». Універсальний бінарний файл може приховувати різні імпорти, команди завантаження або метадані компілятора в кожному слайсі, тому спершу перелічіть **усі** слайси, а потім аналізуйте їх окремо:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

У новіших версіях macOS SDK також є допоміжні функції, як-от `macho_for_each_slice()` і `macho_best_slice()` у `<mach-o/utils.h>`. Остання стане в пригоді, щоб відтворити поведінку dyld/kernel під час завантаження, але сканерам усе одно слід перебирати всі слайси, щоб не пропустити вміст, специфічний для певної архітектури.<sup>[[1]](#references)</sup>

## **Заголовок Mach-O**

Заголовок містить основну інформацію про файл, як-от магічні байти для ідентифікації файлу Mach-O та відомості про цільову архітектуру. Його можна знайти так: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

- `MH_OBJECT`: Об’єктний файл із можливістю переміщення (проміжний результат компіляції, ще не виконуваний файл).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Файл бібліотеки з фіксованою віртуальною пам’яттю.
- `MH_CORE`: Дампи коду.
- `MH_PRELOAD`: Попередньо завантажуваний виконуваний файл (більше не підтримується в XNU).
- `MH_DYLIB`: Динамічні бібліотеки.
- `MH_DYLINKER`: Динамічний компонувальник.
- `MH_BUNDLE`: «Файли плагінів». Створюються за допомогою параметра `-bundle` у gcc і явно завантажуються через `NSBundle` або `dlopen`.
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

## **Mach-O Flags**

У вихідному коді також визначено кілька прапорців, корисних для завантаження бібліотек:

- `MH_NOUNDEFS`: Немає невизначених посилань (повністю компоновано)
- `MH_DYLDLINK`: Компонування Dyld
- `MH_PREBOUND`: Динамічні посилання попередньо прив’язані.
- `MH_SPLIT_SEGS`: Файл розділяє сегменти лише для читання та для читання й запису.
- `MH_WEAK_DEFINES`: Бінарний файл містить слабко визначені символи
- `MH_BINDS_TO_WEAK`: Бінарний файл використовує слабкі символи
- `MH_ALLOW_STACK_EXECUTION`: Зробити стек виконуваним
- `MH_NO_REEXPORTED_DYLIBS`: Бібліотека не містить команд LC_REEXPORT
- `MH_PIE`: Незалежний від розташування виконуваний файл
- `MH_HAS_TLV_DESCRIPTORS`: Є секція з локальними змінними потоку
- `MH_NO_HEAP_EXECUTION`: Заборонити виконання сторінок купи/даних
- `MH_HAS_OBJC`: Бінарний файл містить секції Objective-C
- `MH_SIM_SUPPORT`: Підтримка симулятора
- `MH_DYLIB_IN_CACHE`: Використовується для dylib/framework у кеші спільних бібліотек.

## **Mach-O Load commands**

**Розташування файлу в пам’яті** визначається тут; також вказано **місце розташування таблиці символів**, контекст основного потоку на початку виконання та необхідні **спільні бібліотеки**. Динамічному завантажувачу **(dyld)** надаються інструкції щодо процесу завантаження бінарного файлу в пам’ять.

У ньому використовується структура **load_command**, визначена у згаданому файлі **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

У системі обробляється приблизно **50 різних типів команд завантаження**. Найпоширеніші з них: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` і `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Загалом, цей тип Load Command визначає, **як завантажувати сегменти \_\_TEXT** (виконуваний код) **і \_\_DATA** (дані процесу) **відповідно до зсувів, указаних у секції даних**, коли виконується бінарний файл.

Ці команди **визначають сегменти**, які **відображаються** у **просторі віртуальної пам’яті** процесу під час його виконання.

Існують **різні типи** сегментів, зокрема сегмент **\_\_TEXT**, який містить виконуваний код програми, і сегмент **\_\_DATA**, який містить дані, що використовуються процесом. Ці **сегменти розташовані в секції даних** файлу Mach-O.

**Кожен сегмент** можна додатково **розділити** на кілька **секцій**. **Структура команди завантаження** містить **інформацію** про **ці секції** у відповідному сегменті.

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

Якщо **додати** **зміщення секції** (0x37DC) до **зміщення**, з якого починається **arch**, у цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **інформацію про заголовки** з **командного рядка** за допомогою:

```bash
otool -lv /bin/ls
```

Загальні сегменти, завантажувані цією командою:

- **`__PAGEZERO`:** Вказує ядру **відобразити** **нульову адресу** так, щоб її **не можна було читати, записувати в неї чи виконувати код із неї**. Змінним maxprot і minprot у структурі присвоюється нульове значення, що вказує на **відсутність прав на читання, запис і виконання для цієї сторінки**.
  - Це виділення пам’яті важливе для **зменшення ризику вразливостей, спричинених розіменуванням NULL-вказівника**. XNU примусово захищає нульову сторінку, роблячи першу сторінку пам’яті (лише першу) недоступною (за винятком i386). Бінарний файл міг задовольнити цю вимогу, створивши невеликий \_\_PAGEZERO (за допомогою `-pagezero_size`), який охоплює перші 4k, залишивши решту 32-бітної пам’яті доступною і в режимі користувача, і в режимі ядра.
- **`__TEXT`**: Містить **виконуваний** **код** із правами на **читання** та **виконання** (без запису)**.** Поширені секції цього сегмента:
  - `__text`: Скомпільований бінарний код
  - `__const`: Константні дані (лише для читання)
  - `__[c/u/os_log]string`: Рядкові константи C, Unicode або журналів os
  - `__stubs` і `__stubs_helper`: Задіяні під час завантаження динамічної бібліотеки
  - `__unwind_info`: Дані для розмотування стека.
  - Зауважте, що весь цей вміст підписаний, але також позначений як виконуваний (це створює більше можливостей для експлуатації секцій, яким цей привілей не обов’язково потрібен, наприклад секцій, призначених для рядків).
- **`__DATA`**: Містить дані, доступні для **читання** та **запису** (але не для виконання)**.**
  - `__got:` Таблиця глобальних зсувів
  - `__nl_symbol_ptr`: Вказівник на символ без лінивого зв’язування (зв’язується під час завантаження)
  - `__la_symbol_ptr`: Вказівник на символ із лінивим зв’язуванням (зв’язується під час використання)
  - `__const`: Має містити дані лише для читання (насправді це не гарантовано)
  - `__cfstring`: Рядки CoreFoundation
  - `__data`: Глобальні змінні (ініціалізовані)
  - `__bss`: Статичні змінні (неініціалізовані)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist тощо): Інформація, яку використовує середовище виконання Objective-C
- **`__DATA_CONST`**: Для \_\_DATA.\_\_const не гарантовано, що дані будуть константними (секція має права на запис); це також стосується інших вказівників і GOT. Цей сегмент робить `__const`, деякі ініціалізатори та таблицю GOT (після розв’язання) **доступними лише для читання** за допомогою `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Часто трапляються в новіших бінарних файлах Apple Silicon. Ці сегменти містять вказівники, які потрібно автентифікувати під час завантаження або використання (наприклад, `__auth_got`). Якщо rebinding, hook або прийом із патчингом імпортів перевіряє лише застарілі секції `__got` / `__la_symbol_ptr`, він може не виявити фактичні точки виклику в сучасних бінарних файлах `arm64e`. Докладніше про ці секції див. [на цій сторінці](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Містить інформацію для лінкера (dyld), зокрема записи таблиць символів, рядків і релокацій. Це універсальний контейнер для вмісту, який не належить до `__TEXT` або `__DATA`; його вміст описується в інших командах завантаження.
  - Інформація dyld: Опкоди rebase, non-lazy/lazy/weak binding та інформація про експорт
  - Початки функцій: Таблиця початкових адрес функцій
  - Data In Code: Острівці даних у \_\_text
  - Таблиця символів: Символи в бінарному файлі
  - Таблиця непрямих символів: Символи вказівників/stub
  - Таблиця рядків
  - Підпис коду
- **`__OBJC`**: Містить інформацію, яку використовує середовище виконання Objective-C. Водночас ця інформація може також міститися в сегменті \_\_DATA, у різних секціях \_\_objc\_\*.
- **`__RESTRICT`**: Сегмент без вмісту, який містить одну секцію **`__restrict`** (також порожню). Вона забезпечує ігнорування змінних середовища DYLD під час запуску бінарного файлу.

Як видно з коду, **сегменти також підтримують прапорці** (хоча їх використовують нечасто):

- `SG_HIGHVM`: Лише для Core (не використовується)
- `SG_FVMLIB`: Не використовується
- `SG_NORELOC`: Сегмент не має релокацій
- `SG_PROTECTED_VERSION_1`: Шифрування. Наприклад, Finder використовує його для шифрування текстового сегмента `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить точку входу в атрибуті **entryoff**. Під час завантаження **dyld** просто **додає** це значення до (розташованої в пам’яті) **базової адреси бінарного файлу**, а потім **переходить** до цієї інструкції, щоб почати виконання коду бінарного файлу.

**`LC_UNIXTHREAD`** містить значення, які мають бути встановлені в регістрах під час запуску головного потоку. Цей механізм уже застарів, але **`dyld`** досі його використовує. Значення регістрів, установлені таким чином, можна переглянути за допомогою:

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


Містить інформацію про **підпис коду файлу Macho-O**. Він містить лише **зміщення**, яке **вказує** на **блок підпису**. Зазвичай він розташований у самому кінці файлу.\
Докладніше про цей розділ можна дізнатися в [**цій публікації в блозі**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) і [**цьому gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування бінарних файлів. Однак, звісно, якщо зловмиснику вдасться скомпрометувати процес, він зможе зняти дамп незашифрованої пам’яті.

### **`LC_LOAD_DYLINKER`**

Містить **шлях до виконуваного файлу динамічного компонувальника**, який завантажує спільні бібліотеки в адресний простір процесу. **Значення завжди дорівнює `/usr/lib/dyld`**. Важливо зазначити, що в macOS завантаження dylib відбувається в **режимі користувача**, а не в режимі ядра.

### **`LC_IDENT`**

Застаріла команда. Проте, якщо налаштовано створення дампів у разі panic, створюється дамп ядра Mach-O, а версія ядра вказується в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Сам по собі він не має прямої користі, але XNU кешує його разом з іншою інформацією про процес. Його можна використовувати у звітах про аварійне завершення роботи.

### **`LC_BUILD_VERSION`**

Сучасні бінарні файли зазвичай містять цю команду, щоб указати **цільову платформу**, **мінімальну версію ОС**, **версію SDK** і, за потреби, **версії інструментів**, використаних для створення цього зрізу. З погляду offensive/reversing це дуже корисно для визначення способу збирання зразка та швидкого виявлення дивних universal binaries, у яких один зріз скомпільовано з іншим SDK або для іншої цільової версії ОС. У старіших бінарних файлах замість цього може використовуватися `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказати змінні середовища для dyld до запуску процесу. Це може бути дуже небезпечно, оскільки дає змогу виконувати довільний код у процесі, тому цю команду завантаження використовують лише у збірках dyld із `#define SUPPORT_LC_DYLD_ENVIRONMENT`; крім того, обробка обмежена змінними у форматі `DYLD_..._PATH`, що визначають шляхи завантаження.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

У сучасних toolchain метадані експорту, прив’язування та переміщення часто зберігаються в цих командах, а не лише в старіших опкодах `LC_DYLD_INFO[_ONLY]`. Обидві є записами `linkedit_data_command`, що вказують на дані в **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: компактне trie з символами, які експортує образ.
- **`LC_DYLD_CHAINED_FIXUPS`**: ланцюжки fixup для кожного сегмента, які dyld використовує для застосування переміщень і прив’язувань. В Apple Silicon тут також можна знайти багато сучасних fixup автентифікованих вказівників.

Ці метадані дуже корисні для відновлення імпортів/експортів, розуміння того, чому залежність, завантажена через `@rpath`, розв’язалася саме так, або з’ясування, чому спроба перехоплення/rebinding не вдалася на сучасній цілі `arm64e`. `dyld_info` також можна використовувати з **шляхами до dylib, наявних лише в кеші**, які не існують як окремі файли на диску. Це дуже зручно в сучасній macOS, де багато системних бібліотек містяться лише в спільному кеші.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ця сучасна команда завантаження переважно має значення під час аналізу **kernel collections / файлів у стилі kernelcache**. Замість того щоб представляти одне автономне зображення, зовнішній Mach-O виступає контейнером, а кожен `LC_FILESET_ENTRY` вказує на вбудований Mach-O з власним схожим на шлях **ідентифікатором entry**, VM-адресою та файловим зміщенням. Якщо ви реверсите сучасні компоненти ядра macOS/iOS, ця команда часто слугує сполучною ланкою між контейнером верхнього рівня та потрібним для вилучення чи дизасемблювання образом.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Для практичних сценаріїв вилучення див. [цю іншу сторінку про розширення ядра macOS і kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність від **динамічної** **бібліотеки** та **вказує** **завантажувачу** (dyld) **завантажити й зв’язати цю бібліотеку**. У бінарному файлі Mach-O є команда завантаження `LC_LOAD_DYLIB` **для кожної бібліотеки**, від якої він залежить.

- Ця команда завантаження має тип структури **`dylib_command`** (яка містить структуру dylib з описом фактичної залежної динамічної бібліотеки):

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

Цю інформацію також можна отримати з CLI за допомогою:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Some потенційно пов’язані з malware бібліотеки:

- **DiskArbitration**: Моніторинг USB-накопичувачів
- **AVFoundation:** Захоплення аудіо та відео
- **CoreWLAN**: Сканування Wi-Fi.

> [!TIP]
> Бінарний файл Mach-O може містити один або **кілька** **конструкторів**, які **виконуються** **до** адреси, зазначеної в **LC_MAIN**.\
> Зміщення будь-яких конструкторів зберігаються в секції **\_\_mod_init_func** сегмента **\_\_DATA_CONST**.

## **Дані Mach-O**

У центрі файлу міститься область даних, що складається з кількох сегментів, визначених у області load commands. **У кожному сегменті може міститися багато різних секцій даних**, кожна з яких **містить код або дані**, характерні для певного типу.

> [!TIP]
> Дані — це, по суті, частина, що містить усю **інформацію**, яку завантажують load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Сюди входять:

- **Таблиця функцій:** містить інформацію про функції програми.
- **Таблиця символів**: містить інформацію про зовнішні функції, які використовує бінарний файл.
- Вона також може містити назви внутрішніх функцій і змінних тощо.

Для перевірки можна скористатися інструментом [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або з CLI:

```bash
size -m /bin/ls
```

### Додані дані та оверлеї, розібрані у зворотному порядку

Завантажувач може зберігати конфігурацію в доданих даних, а не в іменованій секції Mach-O. Тоді парсер, що виконує зворотний розбір, знаходить маркер-трейлер, зчитує розмір, збережений безпосередньо перед ним, і використовує це значення, щоб знайти та розшифрувати blob, розташований перед ним. В одному зі спостережуваних універсальних завантажувачів така структура використовувалася для URL завантажувача, зашифрованого за допомогою XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Під час реверсингу незнайомого бінарного файлу перевіряйте байти навколо впізнаваних кінцевих маркерів і простежуйте кожне обчислення розміру у зворотному напрямку, перш ніж припускати, що рядки або конфігурація мають належати до секції load-command. Маркер і XOR-ключ залежать від конкретного зразка; повторно використовуваний прийом — це трейлер із самодостатнім описом.

## Поширені секції Objective-C

У сегменті `__TEXT` (r-x):

- `__objc_classname`: Назви класів (рядки)
- `__objc_methname`: Назви методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

У сегменті `__DATA` (rw-):

- `__objc_classlist`: Вказівники на всі класи Objective-C
- `__objc_nlclslist`: Вказівники на класи Objective-C, що не є лінивими
- `__objc_catlist`: Вказівник на категорії
- `__objc_nlcatlist`: Вказівники на категорії, що не є лінивими
- `__objc_protolist`: Список протоколів
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Зрізи Mach-O не такі прості, як може здатися](https://objective-see.org/blog/blog_0x80.html)
- [2] [Сторінка довідки dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Як прочитати власні entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Відкритий код Apple — Mach-O `fat.h` і `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Нова версія macOS-стілера MacSync націлена на ентузіастів криптовалют і розробників](https://securelist.com/macsync-new-version/121383/)
