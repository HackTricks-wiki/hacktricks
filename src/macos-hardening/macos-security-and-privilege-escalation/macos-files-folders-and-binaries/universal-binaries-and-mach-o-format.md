# Універсальні бінарні файли macOS і формат Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

У macOS використовується формат виконуваних файлів **Mach-O**. **Універсальний**, або fat, бінарний файл містить кілька Mach-O-слайсів, специфічних для різних архітектур, в одному файлі. У заголовках Apple з відкритим кодом `fat.h` і `loader.h` визначено структури й константи, описані на цій сторінці. <sup>[[5]](#references)</sup>

Образ Mach-O складається з:

- Заголовка
- Команд завантаження
- Даних

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat-заголовок

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

Заголовок містить **magic**-байти, за якими йде **кількість** **архітектур**, що **містяться** у файлі (`nfat_arch`); для кожної архітектури буде структура `fat_arch`.

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

Як ви, мабуть, уже здогадалися, універсальний бінарний файл, скомпільований для 2 архітектур, зазвичай **удвічі більший**, ніж файл, скомпільований лише для 1 архітектури.

> [!TIP]
> Під час первинного аналізу malware або підозрілих застосунків не зупиняйтеся після того, як `file` повідомить про «найкращу» архітектуру. Універсальний бінарний файл може містити різні імпорти, команди завантаження або метадані компілятора в кожному слайсі, тож спочатку перелічіть **усі** слайси, а потім перевірте їх окремо:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

У новіших SDK macOS також доступні `macho_for_each_slice()` і `macho_best_slice()` у `<mach-o/utils.h>`. На Apple Silicon до macOS 15 `macho_best_slice()` міг помилково повертати `EBADARCH` для виконуваного стороннього бінарного файла `arm64`; у macOS 15 API виправили. Використовуйте `macho_for_each_slice()` або `lipo -archs`, щоб перелічити всі зрізи, а не вважайте невдалий пошук найкращого зрізу доказом того, що жоден зріз не може виконуватися.<sup>[[1]](#references)[[7]](#references)</sup>

### Порівняння підписів коду між зрізами

Кожна архітектура в universal binary має власні CodeDirectory і CDHash. Під час аудиту підписаного виконуваного файла або привілейованого допоміжного компонента перевіряйте **підпис кожного зрізу**. Відмінність CDHash — це нормально; натомість порівнюйте ідентичність підписувача, прапорці CodeDirectory та entitlements.<sup>[[8]](#references)</sup>

У політиках, що зіставляють CDHash, один хеш ідентифікує лише один шлях виконання, специфічний для архітектури. Apple рекомендує перелічувати зрізи й використовувати `codesign --arch`, щоб перевірити кожен із них.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Для структури підпису та деталей перевірки див. [підписування коду в macOS](../macos-security-protections/macos-code-signing.md).

## **Заголовок Mach-O**

Заголовок містить основну інформацію про файл, зокрема magic bytes для визначення того, що це файл Mach-O, і відомості про цільову архітектуру. Його можна знайти за допомогою: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

- `MH_OBJECT`: Переміщуваний об'єктний файл (проміжний результат компіляції, ще не виконуваний файл).
- `MH_EXECUTE`: Виконувані файли.
- `MH_FVMLIB`: Файл бібліотеки з фіксованою VM.
- `MH_CORE`: Дампи коду
- `MH_PRELOAD`: Попередньо завантажений виконуваний файл (більше не підтримується в XNU)
- `MH_DYLIB`: Динамічні бібліотеки
- `MH_DYLINKER`: Динамічний компонувальник
- `MH_BUNDLE`: «Файли плагінів». Створюються за допомогою `-bundle` у gcc і явно завантажуються через `NSBundle` або `dlopen`.
- `MH_DSYM`: Супровідний файл `.dSYM` (файл із символами для налагодження).
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

- `MH_NOUNDEFS`: немає невизначених посилань (повністю скомпоновано)
- `MH_DYLDLINK`: компонування Dyld
- `MH_PREBOUND`: динамічні посилання попередньо прив’язані.
- `MH_SPLIT_SEGS`: файл розділяє сегменти лише для читання та читання/запису.
- `MH_WEAK_DEFINES`: бінарний файл містить слабко визначені символи
- `MH_BINDS_TO_WEAK`: бінарний файл використовує слабкі символи
- `MH_ALLOW_STACK_EXECUTION`: зробити стек виконуваним
- `MH_NO_REEXPORTED_DYLIBS`: бібліотека не має команд LC_REEXPORT
- `MH_PIE`: виконуваний файл із незалежним розташуванням
- `MH_HAS_TLV_DESCRIPTORS`: є секція зі змінними локального сховища потоків
- `MH_NO_HEAP_EXECUTION`: заборонити виконання для сторінок купи/даних
- `MH_HAS_OBJC`: бінарний файл містить секції Object-C
- `MH_SIM_SUPPORT`: підтримка симулятора
- `MH_DYLIB_IN_CACHE`: використовується для dylibs/frameworks у кеші спільних бібліотек.

## **Команди завантаження Mach-O**

**Розташування файлу в пам’яті** визначається тут; також вказуються **розташування таблиці символів**, контекст головного потоку на початку виконання та необхідні **спільні бібліотеки**. Динамічному завантажувачу **(dyld)** надаються інструкції щодо завантаження бінарного файлу в пам’ять.

Використовується структура **load_command**, визначена в згаданому файлі **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Існує близько **50 різних типів команд завантаження**, які система обробляє по-різному. Найпоширеніші з них: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` і `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> По суті, цей тип команди завантаження визначає, **як завантажувати сегменти \_\_TEXT** (виконуваний код) **і \_\_DATA** (дані процесу) **відповідно до зміщень, указаних у секції Data**, під час запуску бінарного файлу.

Ці команди **визначають сегменти**, які під час запуску процесу **відображаються** у його **просторі віртуальної пам’яті**.

Існують **різні типи** сегментів, наприклад сегмент **\_\_TEXT**, у якому міститься виконуваний код програми, і сегмент **\_\_DATA**, що містить дані, які використовує процес. Ці **сегменти розташовані в секції даних** файлу Mach-O.

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

Якщо **додати** **зміщення секції** (0x37DC) до **зміщення**, де починається **архітектура**, у цьому випадку `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Також можна отримати **інформацію про заголовки** за допомогою **командного рядка**:

```bash
otool -lv /bin/ls
```

Загальні сегменти, що завантажуються цією командою:

- **`__PAGEZERO`:** Він вказує ядру **відобразити** **нульову адресу** так, щоб її **не можна було читати, записувати в неї або виконувати код із неї**. Змінні maxprot і minprot у структурі встановлюються в нуль, щоб указати, що **ця сторінка не має прав на читання, запис і виконання**.
  - Це виділення важливе для **пом’якшення вразливостей розіменування NULL-вказівника**. XNU забезпечує наявність захищеної нульової сторінки, завдяки чому перша сторінка пам’яті (лише перша) стає недоступною (за винятком i386). Бінарний файл може відповідати цим вимогам, створивши невелику \_\_PAGEZERO (за допомогою `-pagezero_size`), яка покриває перші 4k, і зробивши решту 32-бітної пам’яті доступною як у користувацькому, так і в режимі ядра.
- **`__TEXT`**: Містить **виконуваний** **код** із дозволами на **читання** та **виконання** (без дозволу на запис)**.** Типові секції цього сегмента:
  - `__text`: Скомпільований бінарний код
  - `__const`: Константні дані (лише для читання)
  - `__[c/u/os_log]string`: Рядкові константи C, Unicode або журналів os
  - `__stubs` і `__stubs_helper`: Використовуються під час завантаження динамічних бібліотек
  - `__unwind_info`: Дані для розмотування стека.
  - Зауважте, що весь цей вміст підписаний, але також позначений як виконуваний (що створює більше можливостей для експлуатації секцій, яким цей дозвіл не обов’язково потрібен, як-от секцій, призначених для рядків).
- **`__DATA`**: Містить дані, доступні для **читання** та **запису** (без дозволу на виконання)**.**
  - `__got:` Таблиця глобальних зміщень
  - `__nl_symbol_ptr`: Вказівник на символ із не відкладеним зв’язуванням (зв’язування під час завантаження)
  - `__la_symbol_ptr`: Вказівник на символ із відкладеним зв’язуванням (зв’язування під час використання)
  - `__const`: Має містити дані лише для читання (насправді це не гарантовано)
  - `__cfstring`: Рядки CoreFoundation
  - `__data`: Глобальні змінні (які було ініціалізовано)
  - `__bss`: Статичні змінні (які не було ініціалізовано)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist тощо): Інформація, яку використовує Objective-C runtime
- **`__DATA_CONST`**: Для \_\_DATA.\_\_const не гарантовано, що дані будуть константними (дозволи на запис), як і для інших вказівників та GOT. Цей сегмент робить `__const`, деякі ініціалізатори та таблицю GOT (після розв’язання) **доступними лише для читання** за допомогою `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Поширені в новіших бінарних файлах Apple Silicon. Ці сегменти містять вказівники, які потрібно автентифікувати під час завантаження або використання (наприклад, `__auth_got`). Якщо rebinding, hook або метод підміни імпортів перевіряє лише застарілі секції `__got` / `__la_symbol_ptr`, він може не виявити фактичні місця викликів у сучасних бінарних файлах `arm64e`. Докладніше про ці секції див. [на цій сторінці](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Містить інформацію для лінкера (dyld), як-от записи таблиць символів, рядків і релокацій. Це універсальний контейнер для вмісту, якого немає в `__TEXT` чи `__DATA`; його вміст описано в інших командах завантаження.
  - Інформація dyld: Rebase, опкоди зв’язування для non-lazy/lazy/weak і інформація про експорт
  - Початки функцій: Таблиця початкових адрес функцій
  - Дані в коді: Острови даних у \_\_text
  - Таблиця символів: Символи в бінарному файлі
  - Таблиця непрямих символів: Символи вказівників/stub
  - Таблиця рядків
  - Підпис коду
- **`__OBJC`**: Містить інформацію, яку використовує Objective-C runtime. Однак ця інформація також може міститися в сегменті \_\_DATA, у різних секціях \_\_objc\_\*.
- **`__RESTRICT`**: Сегмент без вмісту, який має одну секцію **`__restrict`** (також порожню). Вона гарантує, що під час запуску бінарного файлу змінні середовища DYLD ігноруватимуться.

Як видно з коду, **сегменти також підтримують прапорці** (хоча їх використовують нечасто):

- `SG_HIGHVM`: Лише для Core (не використовується)
- `SG_FVMLIB`: Не використовується
- `SG_NORELOC`: Сегмент не має релокацій
- `SG_PROTECTED_VERSION_1`: Шифрування. Наприклад, Finder використовує його для шифрування текстового сегмента `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** містить точку входу в атрибуті **entryoff**. Під час завантаження **dyld** просто **додає** це значення до (розташованої в пам’яті) **базової адреси бінарного файлу**, а потім **переходить** до цієї інструкції, щоб розпочати виконання коду бінарного файлу.

**`LC_UNIXTHREAD`** містить значення, які мають бути встановлені в регістрах під час запуску головного потоку. Цей механізм уже застарів, але **`dyld`** досі його використовує. Переглянути встановлені таким чином значення регістрів можна за допомогою:

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


Містить інформацію про **підпис коду файлу Mach-O**. Містить лише **зміщення**, що **вказує** на **блок підпису**. Зазвичай він розташований у самому кінці файлу.\
Додаткову інформацію про цей розділ можна знайти в [**цьому дописі в блозі**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) і [**цьому gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Підтримка шифрування бінарних файлів. Однак, звісно, якщо зловмисникові вдасться скомпрометувати процес, він зможе зняти дамп пам’яті без шифрування.

### **`LC_LOAD_DYLINKER`**

Містить **шлях до виконуваного файлу динамічного компонувальника**, який завантажує спільні бібліотеки в адресний простір процесу. **Значенням завжди є `/usr/lib/dyld`**. Важливо зазначити, що в macOS завантаження dylib відбувається в **режимі користувача**, а не в режимі ядра.

### **`LC_IDENT`**

Застаріла команда, але якщо налаштовано створення дампів під час паніки, створюється дамп ядра Mach-O, а версія ядра задається в команді `LC_IDENT`.

### **`LC_UUID`**

Випадковий UUID. Сам по собі він не надто корисний, але XNU кешує його разом з іншою інформацією про процес. Його можна використовувати у звітах про аварійне завершення роботи.

### **`LC_BUILD_VERSION`**

Сучасні бінарні файли зазвичай містять цю команду, яка визначає **цільову платформу**, **мінімальну версію ОС**, **версію SDK** і, за потреби, **версії інструментів**, використаних для збирання цього зрізу. З погляду наступальних методів і реверсингу це дуже корисно для визначення того, як було зібрано зразок, а також для швидкого виявлення підозрілих універсальних бінарних файлів, у яких один зріз скомпільовано з іншим SDK або цільовою версією ОС. У старіших бінарних файлах замість цього може використовуватися `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Дозволяє вказати змінні середовища для dyld до виконання процесу. Це може бути дуже небезпечно, оскільки дає змогу виконувати довільний код у процесі, тому ця load command використовується лише в збірках dyld із `#define SUPPORT_LC_DYLD_ENVIRONMENT`, а її обробку додатково обмежено змінними виду `DYLD_..._PATH`, які задають шляхи завантаження.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

У новіших toolchain метадані export/bind/rebase часто зберігаються в цих командах, а не лише в старіших opcodes `LC_DYLD_INFO[_ONLY]`. Обидві є записами `linkedit_data_command`, що вказують на дані в **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: компактне trie-дерево із символами, які експортує образ.
- **`LC_DYLD_CHAINED_FIXUPS`**: ланцюжки fixup для кожного сегмента, які dyld використовує для застосування rebases і binds. На Apple Silicon саме тут також трапляється багато сучасних fixup для автентифікованих вказівників.

Ці метадані дуже корисні для відновлення imports/exports, розуміння того, чому залежність, завантажена через `@rpath`, була знайдена саме так, або з’ясування, чому hook/rebinding не спрацював на сучасній цілі `arm64e`. `dyld_info` також можна використовувати для шляхів до dylib, наявних лише в кеші, які не існують як окремі файли на диску. Це особливо корисно в сучасній macOS, де багато системних бібліотек містяться лише в shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ця сучасна команда завантаження має значення переважно під час аналізу **kernel collections / файлів у стилі kernelcache**. Замість того щоб представляти окремий самостійний образ, зовнішній Mach-O слугує контейнером, а кожен `LC_FILESET_ENTRY` вказує на вбудований Mach-O з власним схожим на шлях **ідентифікатором запису**, VM-адресою та файловим зсувом. Під час реверсингу сучасних компонентів ядра macOS/iOS ця команда часто є містком між контейнером верхнього рівня та потрібним образом, який ви хочете витягти або дизасемблювати.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Для практичних робочих процесів вилучення див. [цю іншу сторінку про розширення ядра macOS і kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Ця команда завантаження описує залежність від **динамічної** **бібліотеки**, яка **вказує** **завантажувачу** (dyld) **завантажити та зв’язати цю бібліотеку**. У бінарному файлі Mach-O є команда завантаження `LC_LOAD_DYLIB` **для кожної бібліотеки**, яка йому потрібна.

- Ця команда завантаження є структурою типу **`dylib_command`** (яка містить структуру dylib з описом фактичної динамічної бібліотеки, від якої залежить бінарний файл):

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

Також цю інформацію можна отримати з CLI за допомогою:

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
> Бінарний файл Mach-O може містити один або **кілька** **конструкторів**, які **виконуються** **до** адреси, вказаної в **LC_MAIN**.\
> Зміщення будь-яких конструкторів зберігаються в секції **\_\_mod_init_func** сегмента **\_\_DATA_CONST**.

## **Дані Mach-O**

У центрі файла розташована область даних, що складається з кількох сегментів, визначених в області load commands. **Кожен сегмент може містити різноманітні секції даних**, кожна з яких **містить код або дані**, специфічні для певного типу.

> [!TIP]
> По суті, дані — це частина, що містить усю **інформацію**, яка завантажується load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Сюди належать:

- **Таблиця функцій:** Містить інформацію про функції програми.
- **Таблиця символів**: Містить інформацію про зовнішні функції, які використовує бінарний файл.
- Також вона може містити назви внутрішніх функцій, змінних тощо.

Щоб перевірити її, можна скористатися інструментом [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Або через CLI:

```bash
size -m /bin/ls
```

### Додавані дані та оверлеї зі зворотним розбором

Завантажувач може зберігати конфігурацію в доданих даних, а не в іменованій секції Mach-O. Тоді парсер зі зворотним розбором прив’язується до маркера в кінці файла, зчитує розмір, записаний безпосередньо перед ним, і використовує це значення, щоб знайти та розшифрувати попередній blob. В одному виявленому universal loader така структура використовувалася для URL downloader’а, зашифрованого XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Під час зворотного аналізу незнайомого бінарного файла перевіряйте байти навколо впізнаваних кінцевих маркерів і простежуйте кожне обчислення розміру у зворотному напрямку, перш ніж припускати, що рядки чи конфігурація мають належати до секції load-command. Маркер і XOR-ключ залежать від зразка; повторно використовуваний прийом — це самодокументований трейлер.

## Поширені секції Objective-C

У сегменті `__TEXT` (r-x):

- `__objc_classname`: Назви класів (рядки)
- `__objc_methname`: Назви методів (рядки)
- `__objc_methtype`: Типи методів (рядки)

У сегменті `__DATA` (rw-):

- `__objc_classlist`: Вказівники на всі класи Objective-C
- `__objc_nlclslist`: Вказівники на класи Objective-C без лінивого завантаження
- `__objc_catlist`: Вказівник на категорії
- `__objc_nlcatlist`: Вказівники на категорії без лінивого завантаження
- `__objc_protolist`: Список протоколів
- `__objc_const`: Константні дані
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Див. також: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Слайси Mach-O не такі прості, як може здатися](https://objective-see.org/blog/blog_0x80.html)
- [2] [Сторінка man dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Читаємо власні entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Відкритий вихідний код Apple — Mach-O `fat.h` і `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Нова версія macOS-стілера MacSync націлена на криптоентузіастів і розробників](https://securelist.com/macsync-new-version/121383/)
- [7] [Мистецтво шкідливого ПЗ для Mac, том 2 — аналіз бінарних файлів](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Усередині підписування коду: хеші](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Дозвіл і заборона програм і бінарних файлів](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
