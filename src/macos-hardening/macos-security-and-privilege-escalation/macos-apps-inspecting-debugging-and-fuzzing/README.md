# macOS Apps - Інспектування, налагодження та Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Статичний аналіз

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (старий jtool2)

Ви можете [**завантажити disarm звідси**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Зверніть увагу, що **`disarm`** також може працювати зі стиснутими файлами IM4P (наприклад, `kernelcache`) і витягувати лише потрібні частини або навіть аналізувати потрібну частину без її витягування.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** можна знайти в **macOS**, а **`ldid`** — в **iOS**

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) — це корисний інструмент для перевірки файлів **.pkg** (інсталяторів) і перегляду їхнього вмісту перед встановленням.\
Ці інсталятори містять bash-скрипти `preinstall` і `postinstall`, якими автори malware зазвичай зловживають, щоб **persist** **the** **malware**.

### hdiutil

Цей інструмент монтує файли образів дисків Apple (`.dmg`), щоб їх можна було перевірити до запуску будь-чого:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Він буде змонтований у `/Volumes`

### Упаковані бінарні файли

- Перевірте ентропію
- Перевірте рядки (якщо майже немає зрозумілих рядків, бінарний файл упакований)
- Пакувальник UPX для macOS створює секцію під назвою `__XHDR`.

## Статичний аналіз Objective-C

### Метадані

> [!CAUTION]
> Зверніть увагу, що програми, написані на Objective-C, **зберігають** оголошення класів **після** **компіляції** у [бінарні файли Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Ці оголошення класів **містять** назви й типи таких елементів:

- Визначені інтерфейси
- Методи інтерфейсів
- Змінні екземплярів інтерфейсів
- Визначені протоколи

Зверніть увагу, що ці назви можуть бути обфусковані, щоб ускладнити реверс-інжиніринг бінарного файлу.

### Виклик функцій

Коли викликається функція у бінарному файлі, що використовує Objective-C, скомпільований код не викликає цю функцію напряму, а натомість викликає **`objc_msgSend`**. Саме вона викличе потрібну функцію:

![Метадані — виклик функцій: коли викликається функція у бінарному файлі, що використовує Objective-C, скомпільований код не викликає цю функцію напряму, а натомість викликає objc msgSend . Саме вона викличе...](<../../../images/image (305).png>)

Функція приймає такі параметри:

- Перший параметр (**self**) — це «вказівник на **екземпляр класу, який має отримати повідомлення**». Простіше кажучи, це об’єкт, для якого викликається метод. Якщо метод є методом класу, цей параметр вказуватиме на екземпляр об’єкта класу (як цілого), а для методу екземпляра `self` вказуватиме на створений екземпляр класу як об’єкт.
- Другий параметр (**op**) — це «селектор методу, який обробляє повідомлення». Простіше кажучи, це просто **назва методу**.
- Решта параметрів — це **значення, потрібні методу** (op).

Дізнайтеся, як легко **отримати цю інформацію за допомогою `lldb` на ARM64** на цій сторінці:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Аргумент**       | **Регістр**                                                    | **(для) objc_msgSend**                                  |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1-й аргумент**   | **rdi**                                                        | **self: об’єкт, для якого викликається метод**         |
| **2-й аргумент**   | **rsi**                                                        | **op: назва методу**                                   |
| **3-й аргумент**   | **rdx**                                                        | **1-й аргумент методу**                                |
| **4-й аргумент**   | **rcx**                                                        | **2-й аргумент методу**                                |
| **5-й аргумент**   | **r8**                                                         | **3-й аргумент методу**                                |
| **6-й аргумент**   | **r9**                                                         | **4-й аргумент методу**                                |
| **7-й і наступні аргументи** | <p><strong>rsp+</strong><br><strong>(у стеку)</strong></p> | **5-й і наступні аргументи методу**                    |

### Вивантаження метаданих ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) — це інструмент для class-dump бінарних файлів Objective-C. У GitHub зазначено dylibs, але інструмент також працює з виконуваними файлами.

```bash
./dynadump dump /path/to/bin
```

На момент написання це **працює найкраще**.

#### Звичайні інструменти

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) — це оригінальний інструмент для генерації оголошень класів, категорій і протоколів у форматованому коді Objective-C.

Він застарілий і більше не підтримується, тож, імовірно, працюватиме некоректно.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) — це сучасний кросплатформний інструмент для дампу класів Objective-C. На відміну від наявних інструментів, iCDump може працювати незалежно від екосистеми Apple і надає прив’язки до Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Статичний аналіз Swift

У бінарних файлах Swift, завдяки сумісності з Objective-C, іноді можна отримати оголошення за допомогою [class-dump](https://github.com/nygard/class-dump/), але не завжди.

За допомогою команд **`jtool -l`** або **`otool -l`** можна знайти кілька секцій із префіксом **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Додаткову інформацію про [**інформацію, що зберігається в цих секціях, можна знайти в цій публікації в блозі**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Крім того, **Swift-бінарні файли можуть містити symbols** (наприклад, бібліотеки мають зберігати symbols, щоб можна було викликати їхні функції). **Symbols зазвичай містять інформацію про назву функції** та атрибути у нечитабельному вигляді, тому вони дуже корисні. Існують «**demanglers**», які можуть відновити оригінальну назву:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Динамічний аналіз

> [!WARNING]
> **Не вимикайте SIP як стандартний крок налагодження.** Збірки для розробки з `com.apple.security.get-task-allow` можна налагоджувати з увімкненим SIP. Перевірте ціль командою `codesign -d --entitlements :- /path/to/binary`, перш ніж запускати LLDB. Самого права debugger недостатньо для доступу до цілей, захищених SIP.<sup>[[15]](#references)</sup>
>
> У розповсюджуваних застосунках із hardened runtime зазвичай немає `get-task-allow`, а під’єднання до них заблоковано. Якщо можливо, використовуйте надану розробником debug-збірку; повторне підписування окремої копії може змінити поведінку, яку ви досліджуєте. Якщо для роботи із захищеною ціллю потрібно вимкнути SIP, використовуйте окрему тестову машину або VM, а не машину, на яку покладаєтеся.<sup>[[16]](#references)</sup>
>
> У попередніх рекомендаціях для захищеної цілі в ізольованому тестовому середовищі перелічувалися такі альтернативи:
>
> Зверніть увагу: щоб налагоджувати бінарні файли, SIP потрібно вимкнути (`csrutil disable` або `csrutil enable --without debug`), або скопіювати бінарні файли в тимчасову папку й видалити підпис за допомогою `codesign --remove-signature <binary-path>`, або дозволити налагодження бінарного файла (можна скористатися [цим скриптом](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Це не загальна вимога SIP: віддавайте перевагу debug-збірці й пам’ятайте, що копіювання або зміна підпису може змінити поведінку, яку ви досліджуєте.

> [!WARNING]
> Зверніть увагу: щоб **інструментувати системні бінарні файли** (наприклад, `cloudconfigurationd`) у macOS, **SIP потрібно вимкнути** (простого видалення підпису недостатньо).

### API

macOS надає кілька цікавих API, які дають інформацію про процеси:

- `proc_info`: Основний API, що надає багато інформації про кожен процес. Щоб отримати інформацію про інші процеси, потрібні права root, але спеціальні entitlements або mach-порти не потрібні.
- `libsysmon.dylib`: Надає інформацію про процеси через функції XPC, але для викликів потрібен entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** — це техніка знімання стану процесів, зокрема стеків викликів усіх запущених потоків. Вона особливо корисна для налагодження, аналізу продуктивності та розуміння поведінки системи в певний момент часу. В iOS і macOS stackshotting можна виконувати за допомогою кількох інструментів і методів, зокрема **`sample`** і **`spindump`**.

### Sysdiagnose

Цей інструмент (`/usr/bini/ysdiagnose`) збирає багато інформації з вашого комп’ютера, виконуючи десятки різних команд, як-от `ps`, `zprint`...

Його потрібно запускати з правами **root**, а демон `/usr/libexec/sysdiagnosed` має дуже цікаві entitlements, зокрема `com.apple.system-task-ports` і `get-task-allow`.

Його plist розташований за адресою `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` і визначає 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: видаляє старі архіви у /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: спеціальний порт 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: інтерфейс користувацького режиму через клас Obj-C `Libsysdiagnose`. У dict можна передати три аргументи (`compress`, `display`, `run`)

### Unified Logs

macOS створює докладні журнали, корисні для аналізу поведінки застосунку.

Деякі поля журналу містять тег `<private>`, щоб приховати інформацію, яка може ідентифікувати користувача або пристрій. У старіших інструкціях іноді описується встановлення сертифіката для відображення цих полів; сучасні рекомендації з налагодження натомість передбачають використання профілю конфігурації з явно визначеною областю дії та `Enable-Private-Data` або параметрів `OSLogPreferences` для окремого застосунку. Поведінка може різнитися залежно від підсистеми й версії macOS. Обговорення старішого сертифіката/профілю залишено в посиланнях. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Ліва панель

На лівій панелі Hopper можна переглянути символи (**Labels**) бінарного файла, список процедур і функцій (**Proc**) та рядки (**Str**). Це не всі рядки, а лише ті, що визначені в кількох частинах файла Mac-O (наприклад, _cstring або `objc_methname`).

#### Центральна панель

На центральній панелі можна переглянути **дизасембльований код**. Його можна переглянути як **raw**-дизасемблювання, **граф**, **декомпільований** код або **бінарні дані**, натиснувши відповідну піктограму:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Якщо клацнути правою кнопкою миші на об’єкті коду, можна переглянути **посилання на цей об’єкт і з нього** або навіть змінити його назву (це не працює для декомпільованого псевдокоду):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Крім того, **у нижній частині центральної панелі можна вводити команди Python**.

#### Права панель

На правій панелі можна переглянути цікаву інформацію, зокрема **історію навігації** (щоб знати, як ви дійшли до поточного місця), **граф викликів**, де показано всі **функції, що викликають цю функцію**, і всі функції, **які викликає ця функція**, а також інформацію про **локальні змінні**.

### dtrace

Він надає користувачам доступ до застосунків на надзвичайно **низькому рівні** та дає змогу **трасувати** **програми** й навіть змінювати потік їх виконання. Dtrace використовує **probes**, розміщені **в різних місцях ядра**, зокрема на початку й наприкінці системних викликів.

DTrace використовує функцію **`dtrace_probe_create`**, щоб створити probe для кожного системного виклику. Ці probes можуть спрацьовувати **в точках входу й виходу кожного системного виклику**. Взаємодія з DTrace відбувається через /dev/dtrace, доступний лише користувачу root.<sup>[[1]](#references)</sup>

> [!TIP]
> Щоб увімкнути Dtrace, не вимикаючи повністю захист SIP, можна виконати в режимі відновлення: `csrutil enable --without dtrace`
>
> Також можна виконувати **`dtrace`** або **`dtruss`** для бінарних файлів, **які ви скомпілювали**.

Доступні probes dtrace можна отримати командою:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Ім’я probe складається з чотирьох частин: provider, module, function та name (`fbt:mach_kernel:ptrace:entry`). Якщо не вказати якусь частину імені, DTrace використовуватиме для неї wildcard.

Щоб налаштувати DTrace на активацію probe та вказати, які дії виконувати під час їх спрацювання, нам потрібно використовувати мову D.

Детальніше пояснення та більше прикладів наведено в [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Приклади

Запустіть `man -k dtrace`, щоб переглянути **доступні скрипти DTrace**. Приклад: `sudo dtruss -n binary`

- У рядку

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

Це засіб трасування ядра. Документовані коди можна знайти у **`/usr/share/misc/trace.codes`**.

Такі інструменти, як `latency`, `sc_usage`, `fs_usage` і `trace`, використовують його внутрішньо.

Для взаємодії з `kdebug` використовується `sysctl` у просторі імен `kern.kdebug`; потрібні MIB можна знайти в `sys/sysctl.h`, а їхні функції реалізовано в `bsd/kern/kdebug.c`.

Зазвичай для взаємодії з kdebug за допомогою власного клієнта виконують такі кроки:

- Видалити наявні налаштування за допомогою KERN_KDSETREMOVE
- Налаштувати трасування за допомогою KERN_KDSETBUF і KERN_KDSETUP
- Використати KERN_KDGETBUF, щоб отримати кількість записів у буфері
- Отримати власний клієнт із трасування за допомогою KERN_KDPINDEX
- Увімкнути трасування за допомогою KERN_KDENABLE
- Зчитати буфер, викликавши KERN_KDREADTR
- Щоб зіставити кожен потік із його процесом, викликати KERN_KDTHRMAP.

Щоб отримати цю інформацію, можна скористатися інструментом Apple **`trace`** або власним інструментом [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.

**Зверніть увагу: одночасно Kdebug доступний лише одному користувачеві.** Тому одночасно можна запускати лише один інструмент, що використовує k-debug.

### ktrace

API `ktrace_*` походять із `libktrace.dylib`, яка обгортає API Kdebug. Тоді клієнт може просто викликати `ktrace_session_create` і `ktrace_events_[single/class]`, щоб задати зворотні виклики для певних кодів, а потім запустити трасування за допомогою `ktrace_start`.

Цей інструмент можна використовувати навіть із **увімкненим SIP**.

Як клієнт можна використовувати утиліту `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Or `tailspin`.

### kperf

Цей інструмент використовується для профілювання на рівні ядра та побудований на основі викликів `Kdebug`.

Загалом перевіряється глобальна змінна `kernel_debug_active`, і якщо вона встановлена, викликається `kperf_kdebug_handler` із кодом `Kdebug` та адресою кадру ядра, який виконує виклик. Якщо код `Kdebug` збігається з одним із вибраних, застосовуються налаштовані «дії», представлені у вигляді bitmap (перегляньте доступні параметри в `osfmk/kperf/action.h`).

У Kperf також є таблиця sysctl MIB: (від root) `sysctl kperf`. Цей код можна знайти в `osfmk/kperf/kperfbsd.c`.

Крім того, частина функціональності Kperf міститься в `kpc`, який надає інформацію про лічильники продуктивності машини.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) — дуже корисний інструмент для перевірки дій, пов’язаних із процесами (наприклад, моніторингу нових процесів, які створює певний процес).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) — це інструмент для відображення зв’язків між процесами.\
Потрібно відстежувати свій Mac за допомогою команди на кшталт **`sudo eslogger fork exec rename create > cap.json`** (терміналу, з якого запускається команда, потрібен FDA). Потім можна завантажити json у цей інструмент, щоб переглянути всі зв’язки:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) відстежує файлові події, як-от створення, зміну та видалення файлів.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) — це GUI-інструмент, який нагадує _Procmon_ від Microsoft Sysinternals, знайомий користувачам Windows. Цей інструмент дає змогу починати й зупиняти запис різних типів подій, фільтрувати їх за категоріями, як-от файли, процеси, мережа тощо, а також зберігати записані події у форматі json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) входить до Developer tools у Xcode. Цей інструмент використовується для моніторингу продуктивності програм, виявлення витоків пам’яті та відстеження активності файлової системи.

![Crescendo - Apple Instruments: Apple Instruments входить до Developer tools у Xcode. Цей інструмент використовується для моніторингу продуктивності програм, виявлення витоків пам’яті та відстеження активності файлової системи](<../../../images/image (1138).png>)

### fs_usage

Дає змогу відстежувати дії, які виконують процеси:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) корисний для перегляду **бібліотек**, які використовує бінарний файл, **файлів**, із якими він працює, та **мережевих** з’єднань.\
Він також перевіряє процеси бінарних файлів за допомогою **virustotal** і показує інформацію про бінарний файл.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

У [**цій публікації блогу**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) наведено приклад того, як **налагодити запущений daemon**, який використовував **`PT_DENY_ATTACH`**, щоб заборонити налагодження, навіть якщо SIP було вимкнено.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` — це специфічний для Darwin запит `ptrace(2)` зі значенням **31** (`0x1f`); інші аргументи ігноруються. Процес може викликати його безпосередньо, без fork, щоб заборонити подальше трасування батьківським процесом.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Стан XNU та порядок викликів

Результат залежить від того, який запит `ptrace` першим надходить до XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB під’єднується першим:** `debugserver` використовує `PT_ATTACHEXC`; XNU перетворює його на `PT_ATTACH`, виконує авторизацію `KAUTH_PROCESS_CANTRACE` і встановлює `P_LTRACED` для цільового процесу. Подальший `PT_DENY_ATTACH` бачить цей прапорець і завершує цільовий процес із кодом `W_EXITCODE(ENOTSUP, 0)`, який LLDB зазвичай показує як статус **45** (`0x2d`).
- **Цільовий процес забороняє під’єднання першим:** XNU встановлює `P_LNOATTACH`. Пізніше під’єднання відхиляється під час авторизації трасування процесу; шлях обробки помилки під’єднання бачить `P_LNOATTACH` і надсилає `SIGSEGV` процесу, що намагається під’єднатися. У LLDB це може відображатися як втрачений зв’язок із `debugserver`.

Щоб розрізнити ці шляхи, увімкніть журналювання `debugserver` перед запуском або під’єднанням і перевірте його запити `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Статична ідентифікація та обхід ARM64

Для незаплутаного ARM64 Mach-O знайдіть імпортований stub `_ptrace` і перевірте місця виклику. Перший цілочисельний аргумент передається в `w0`, тому ця послідовність безпосередньо показує anti-debug запит. Відсутність імпорту не є остаточним доказом, оскільки код може динамічно знаходити `ptrace`. Імпортований `_sysctl` також може вказувати на anti-debug перевірки, хоча його теж можуть знаходити динамічно.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

У продемонстрованому прикладі зміна імедіатного операнда з `0x1f` на `0x0` змінює запит на `PT_TRACE_ME` і дає програмі змогу продовжити роботу під LLDB. Це **bypass, специфічний для цього прикладу**, а не універсальний no-op: перш ніж вирішувати, чи змінювати запит, пропускати виклик або примусово повертати успішний результат, перевірте перевірки значення, що повертається, і потік виконання у викликувачі.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** — **де-факто інструмент** для **налагодження** двійкових файлів у **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Ви можете встановити режим Intel під час використання lldb, створивши у своїй домашній теці файл **`.lldbinit`** із таким рядком:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Усередині lldb скиньте процес за допомогою `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Команда</strong></td><td><strong>Опис</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Запустити виконання. Воно триватиме, доки не спрацює breakpoint або процес не завершиться.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Запустити виконання й зупинитися на точці входу.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Продовжити виконання процесу, який налагоджується.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Виконати наступну інструкцію. Ця команда пропускає виклики функцій.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Виконати наступну інструкцію. На відміну від команди <code>nexti</code>, ця команда заходить у виклики функцій.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Виконати решту інструкцій поточної функції (frame), повернутися й зупинитися.</td></tr>
<tr><td><strong>control + c</strong></td><td>Призупинити виконання. Якщо процес запущено (<code>r</code>) або виконання продовжено (<code>c</code>), ця команда зупиняє його в поточному місці виконання.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Будь-яка функція з назвою main</p>
<p><code>b &lt;binname&gt;`main</code> # Функція main цього бінарного файла</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Функція main указаного бінарного файла</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Будь-який метод NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Зупинятися в усіх функціях цієї бібліотеки</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Список breakpoint</p>
<p><code>br e/dis &lt;num&gt;</code> # Увімкнути/вимкнути breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Довідка щодо команди breakpoint</p>
<p><code>help memory write</code> # Довідка щодо запису в пам’ять</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Показати пам’ять як рядок із нульовим завершенням.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Показати пам’ять як інструкцію асемблера.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Показати пам’ять як байт.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Виводить об’єкт, на який посилається параметр.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Більшість Apple Objective-C API або методів повертають об’єкти, тому їх слід виводити командою «print object» (<code>po</code>). Якщо <code>po</code> не виводить нічого змістовного, використовуйте <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Записати AAAA за цією адресою<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Записати AAAA за цією адресою
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Дизасемблювати поточну функцію</p>
<p><code>dis -n &lt;funcname&gt;</code> # Дизасемблювати функцію</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Дизасемблювати функцію<br>
<code>dis -c 6</code> # Дизасемблювати шість рядків<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Дизасемблювати від однієї адреси до іншої<br>
<code>dis -p -c 4</code> # Почати дизасемблювання з поточної адреси</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Переглянути масив із трьох компонентів у регістрі <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Вивести карту пам’яті поточного процесу.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Отримати адресу кожного символу з CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Під час виклику функції **`objc_sendMsg`** у регістрі **rsi** міститься **назва методу** як рядок із нульовим завершенням («C»-рядок). Щоб вивести назву через lldb, виконайте:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Протидія динамічному аналізу

#### Виявлення VM

- Команда **`sysctl hw.model`** зазвичай повертає ідентифікатор моделі Mac на фізичному обладнанні, а у VM може повертати інше значення.<sup>[[3]](#references)</sup>
- Змінюючи значення **`hw.logicalcpu`** і **`hw.physicalcpu`**, деякі malware намагаються виявити VM.<sup>[[4]](#references)</sup>
- Перед розпакуванням наступного етапу loader також може перевіряти наявність VM, запитуючи `kern.hv_vmm_present` і `machdep.cpu.brand_string` через `sysctl`. Ці перевірки доповнюють, а не замінюють описану нижче перевірку на підключений debugger.<sup>[[20]](#references)</sup>
- Деякі malware також можуть **виявити**, що машина працює на **VMware**, за MAC-адресою (00:50:56).
- Також можна **перевірити, чи налагоджується процес**, за допомогою простого коду, наприклад:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Також може викликатися системний виклик `ptrace` із прапорцем `PT_DENY_ATTACH`. Це забороняє debugger підключатися й трасувати процес. Див. [розділ PT_DENY_ATTACH](#page-title), де описано залежну від порядку викликів поведінку XNU, логування `debugserver` і workflow патчингу ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
- Також може викликатися системний виклик **`ptrace`** із прапорцем **`PT_DENY_ATTACH`**. Див. [розділ PT_DENY_ATTACH](#page-title), де описано залежну від порядку викликів поведінку XNU, логування `debugserver` і workflow патчингу ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
  - Можна перевірити, чи імпортуються функції **`sysctl`** або **`ptrace`** (але malware може імпортувати їх динамічно).
  - Як зазначено в цьому матеріалі, «[Подолання методів анти-debug: варіанти macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)»:<sup>[[7]](#references)</sup>\
    «_Повідомлення Process # exited with **status = 45 (0x0000002d)** зазвичай є очевидною ознакою того, що ціль налагодження використовує **PT_DENY_ATTACH**_»

#### Передавання процесу через `fork()`

Процес може обійти debugger, який залишається підключеним до початкового PID: на початку роботи він викликає `fork()`, завершує батьківський процес (`fork()` повертає додатний PID дочірнього процесу) і продовжує захищену логіку лише в дочірньому процесі (`fork()` повертає `0`). Розв’язання `fork` через `dlsym(RTLD_DEFAULT, "fork")` також усуває пряме місце виклику `_fork`, але це лише перешкода для аналізу: рядок із назвою символу й потік даних динамічного розв’язання залишаються видимими в Mach-O бінарному файлі.<sup>[[13]](#references)[[14]](#references)</sup>

На arm64 виявляйте цей шаблон, відстежуючи потік даних, а не фіксовані адреси: перші два аргументи `dlsym` передаються в `x0` і `x1`, `RTLD_DEFAULT` може мати значення `-2` (наприклад, `movn x0, #1`), а пара `adrp`/`add` зазвичай формує адресу рядка `"fork"`. Після `bl` до stub `dlsym` відстежте вказівник, повернутий у `x0`, під час перевірки на нуль і збереження до подальшого непрямого виклику `blr`. Потім відстежте результат `fork()` у `w0`: нуль спрямовує виконання дочірнім шляхом, а додатні значення та `-1` — шляхом батьківського процесу або обробки помилки.<sup>[[13]](#references)[[14]](#references)</sup>

Статичний спосіб обходу — пропустити непрямий виклик і змусити наявну перевірку результату обрати дочірній шлях. Наприклад, якщо компілятор згенерував наведену нижче послідовність, пропатчіть `blr` і збереження результату на `nop`, задайте синтетичний нульовий результат і залиште логіку порівняння/переходу. Тоді застосунок продовжить роботу з початковим PID, не створюючи дочірнього процесу; регістри інструкцій і цілі переходів потрібно адаптувати до аналізованої збірки.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Дампи ядра

Дампи ядра створюються, якщо:

- sysctl `kern.coredump` встановлено в 1 (за замовчуванням)
- Процес не мав прапорців suid/sgid або `kern.sugid_coredump` встановлено в 1 (за замовчуванням — 0)
- Ліміт `AS_CORE` дозволяє цю операцію. Створення дампів ядра можна вимкнути викликом `ulimit -c 0` і знову ввімкнути за допомогою `ulimit -c unlimited`.

У таких випадках дампи ядра генеруються відповідно до sysctl `kern.corefile` і зазвичай зберігаються в `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **аналізує процеси, що аварійно завершилися, і зберігає звіт про збій на диску**. Звіт про збій містить інформацію, яка може **допомогти розробнику діагностувати** причину збою.\
Для застосунків та інших процесів, **що працюють у контексті launchd користувача**, ReportCrash працює як LaunchAgent і зберігає звіти про збої в `~/Library/Logs/DiagnosticReports/` користувача.\
Для демонів, інших процесів, **що працюють у системному контексті launchd**, та інших привілейованих процесів ReportCrash працює як LaunchDaemon і зберігає звіти про збої в `/Library/Logs/DiagnosticReports` системи.

Якщо вас турбує, що звіти про збої **надсилаються до Apple**, їх можна вимкнути. Інакше звіти про збої можуть допомогти **з’ясувати, через що сервер аварійно завершив роботу**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Сон

Під час fuzzing у macOS не давайте Mac переходити в режим сну:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Відключення SSH

Якщо ви виконуєте fuzzing через SSH-з’єднання, важливо переконатися, що сеанс не буде перервано. Тож змініть файл sshd_config:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Внутрішні обробники

**Перегляньте цю сторінку**, щоб дізнатися, як визначити, яка програма **обробляє вказану схему або протокол:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Перелік мережевих процесів

Це цікаво, щоб знайти процеси, які керують мережевими даними:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Або використайте `netstat` чи `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Фаззинг Mach IPC зі збереженням стану

Служби Mach, доступні через привілейовані демони, — корисні цілі для фаззингу, якщо непривілейований клієнт або клієнт у sandbox може отримати право надсилання. Почніть із запису служби в `MachServices` у launchd і скористайтеся [процесом аналізу MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md), щоб зіставити ідентифікатори повідомлень з обробниками. Перш ніж змінювати байти, встановіть точку зупинки на серверній процедурі MIG, поки звичайний клієнт взаємодіє зі службою, і збережіть коректні запити як початкові вхідні дані. Зберігайте обов'язкові поля заголовка, розміри повідомлень і структуру дескрипторів, щоб мутації доходили до обробника, а не одразу відхилялися під час диспетчеризації.<sup>[[17]](#references)</sup>

Багато обробників залежать від попередніх викликів. Налаштуйте в harness ініціалізацію стану служби, а потім обробляйте кожен вхідний набір даних як послідовність **операцій і аргументів**: надсилайте запити для налаштування (наприклад, open або create), зберігайте отримані ідентифікатори та використовуйте їх у наступних запитах. Це дає змогу зворотному зв'язку про покриття досліджувати переходи станів, а не раз у раз натрапляти на перевірку неініціалізованого об'єкта.<sup>[[17]](#references)</sup>

Для цілі із закритим вихідним кодом внутрішньопроцесний harness, який викликає процедуру диспетчеризації MIG, можна інструментувати за допомогою Jackalope/TinyInst. [Harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) — це конкретна реалізація, а не готовий harness для інших служб.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Перевіряйте кожне аварійне завершення через реальний шлях IPC.** Harness із прямою диспетчеризацією пропускає перевірку повідомлень Mach ядром і може давати хибнопозитивні результати, особливо якщо передає некоректну пам'ять out-of-line (OOL) або дескриптори портів. Виділяйте в harness коректну пам'ять для OOL, а потім повторно відтворіть зменшений тестовий випадок через `mach_msg` від клієнта з початковим доступом до служби й переконайтеся, що демон усе ще аварійно завершується.<sup>[[17]](#references)</sup>

### Фаззери

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Працює з CLI-інструментами

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

З багатьма GUI-інструментами macOS він "**просто працює**". Для деяких програм є додаткові вимоги: наприклад, унікальні назви файлів, певне розширення або читання файлів із контейнера sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Ось кілька прикладів:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Більше інформації про fuzzing у macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Реагування на інциденти в OS X: скриптинг та аналіз](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Джеремі Браун — Літо fuzzing: MacOS — село AppSec на DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Мистецтво зловмисного ПЗ для Mac, том I: аналіз](https://taomm.org/)
- [4] [No Starch Press — Мистецтво зловмисного ПЗ для Mac: посібник з аналізу шкідливого програмного забезпечення](https://nostarch.com/art-mac-malware)
- [5] [knight.sc — інформація, збережена в цих розділах допису блогу](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc — налагодження бінарних файлів Apple, що використовують Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com — як обійти техніки протидії налагодженню: варіанти macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Форуми розробників Apple — структуровані журнали Xcode та `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User — відображення приватних даних в уніфікованому журналі macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Визначення запитів Apple XNU у `ptrace.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Реалізація Apple XNU `ptrace` у `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society — внутрішня будова ptrace: як вона запобігає підключенню налагоджувача](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples — приклади fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society — техніка протидії налагодженню з використанням dlsym і fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple — entitlement для інструментів налагодження](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Форуми розробників Apple — налагодження захищеного стороннього застосунку](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero — подолання звукового бар’єра, частина I: fuzzing CoreAudio за допомогою Mach-повідомлень](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero — harness для CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero — fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist — нова версія викрадача для macOS MacSync націлилася на криптоентузіастів і розробників](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
