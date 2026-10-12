# Застосунки macOS — інспектування, налагодження та Fuzzing

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

### Disarm (old jtool2)

Ви можете [**завантажити disarm тут**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Зверніть увагу, що **`disarm`** також може працювати зі стисненими файлами IM4P (наприклад, `kernelcache`) і витягувати лише потрібні частини або навіть аналізувати потрібну частину без її витягування.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) — це інструмент для перевірки файлів **.pkg** (інсталяторів) і перегляду їхнього вмісту перед встановленням.\
У цих інсталяторів є bash-скрипти `preinstall` і `postinstall`, якими автори шкідливого ПЗ зазвичай зловживають, щоб **забезпечити стійкість** **цього** **шкідливого ПЗ**.

### hdiutil

Цей інструмент **монтує** файли образів дисків Apple (`.dmg`), щоб їх можна було перевірити до запуску будь-чого:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Буде змонтовано в `/Volumes`

### Упаковані бінарні файли

- Перевірте ентропію
- Перевірте рядки (якщо майже немає зрозумілих рядків, файл упакований)
- Пакувальник UPX для macOS створює секцію `__XHDR`.

## Статичний аналіз Objective-C

### Метадані

> [!CAUTION]
> Зверніть увагу, що програми, написані на Objective-C, **зберігають** оголошення класів **після** **компіляції** у [бінарні файли Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Такі оголошення класів **містять** назви й типи:

- Визначених інтерфейсів
- Методів інтерфейсів
- Змінних екземплярів інтерфейсів
- Визначених протоколів

Зверніть увагу, що ці назви можуть бути обфусковані, щоб ускладнити реверс-інжиніринг бінарного файлу.

### Виклик функцій

Коли викликається функція в бінарному файлі, що використовує Objective-C, скомпільований код замість прямого виклику цієї функції викликає **`objc_msgSend`**. Саме вона викликає кінцеву функцію:

![Метадані — виклик функцій: коли викликається функція в бінарному файлі, що використовує Objective-C, скомпільований код замість прямого виклику цієї функції викликає objc msgSend . Саме вона...](<../../../images/image (305).png>)

Функція очікує такі параметри:

- Перший параметр (**self**) — це «вказівник на **екземпляр класу, який має отримати повідомлення**». Простіше кажучи, це об’єкт, для якого викликається метод. Якщо метод є методом класу, це буде екземпляр об’єкта класу (як цілого), а для методу екземпляра `self` вказуватиме на створений екземпляр класу як об’єкт.
- Другий параметр (**op**) — це «селектор методу, який обробляє повідомлення». Простіше кажучи, це просто **назва методу**.
- Решта параметрів — це **значення, потрібні методу** (`op`).

Дивіться, як **легко отримати цю інформацію за допомогою `lldb` в ARM64** на цій сторінці:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Аргумент**      | **Регістр**                                                    | **(для) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1-й аргумент**  | **rdi**                                                         | **self: об’єкт, для якого викликається метод** |
| **2-й аргумент**  | **rsi**                                                         | **op: назва методу**                             |
| **3-й аргумент**  | **rdx**                                                         | **1-й аргумент методу**                         |
| **4-й аргумент**  | **rcx**                                                         | **2-й аргумент методу**                         |
| **5-й аргумент**  | **r8**                                                          | **3-й аргумент методу**                         |
| **6-й аргумент**  | **r9**                                                          | **4-й аргумент методу**                         |
| **7-й і наступні аргументи** | <p><strong>rsp+</strong><br><strong>(у стеку)</strong></p> | **5-й і наступні аргументи методу**                        |

### Дамп метаданих Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) — це інструмент для отримання дампу класів із бінарних файлів Objective-C. У GitHub-репозиторії зазначено, що він призначений для dylibs, але він також працює з виконуваними файлами.

```bash
./dynadump dump /path/to/bin
```

На момент написання це **найкраще працює**.

#### Звичайні інструменти

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) — це оригінальний інструмент для генерації оголошень класів, категорій і протоколів у коді Objective-C.

Він застарілий і більше не підтримується, тому, імовірно, працюватиме некоректно.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) — це сучасний кросплатформний інструмент для дампу класів Objective-C. На відміну від наявних інструментів, iCDump може працювати незалежно від екосистеми Apple і надає прив’язки до Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Статичний аналіз Swift

Оскільки бінарні файли Swift сумісні з Objective-C, іноді можна отримати оголошення за допомогою [class-dump](https://github.com/nygard/class-dump/), але не завжди.

За допомогою команд **`jtool -l`** або **`otool -l`** можна знайти кілька секцій, назви яких починаються з префікса **`__swift5`**:

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

Додаткову інформацію про [**інформацію, що зберігається в цих секціях, можна знайти в цій публікації блогу**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Крім того, **бінарні файли Swift можуть містити symbols** (наприклад, бібліотеки мають зберігати symbols, щоб можна було викликати їхні функції). **Symbols зазвичай містять інформацію про назву функції** та її атрибути у нечитабельному вигляді, тож вони дуже корисні. Існують «**demanglers**», які можуть відновити початкову назву:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Динамічний аналіз

> [!WARNING]
> Зверніть увагу: для налагодження бінарних файлів потрібно **вимкнути SIP** (`csrutil disable` або `csrutil enable --without debug`), або скопіювати бінарні файли до тимчасової теки й **видалити підпис** командою `codesign --remove-signature <binary-path>`, або дозволити налагодження бінарного файлу (можна скористатися [цим скриптом](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Зверніть увагу: щоб **інструментувати системні бінарні файли** (наприклад, `cloudconfigurationd`) у macOS, **SIP має бути вимкнено** (простого видалення підпису недостатньо).

### API

macOS надає кілька цікавих API, які надають інформацію про процеси:

- `proc_info`: Основний API, що надає багато інформації про кожен процес. Щоб отримати інформацію про інші процеси, потрібні права root, але спеціальні entitlements або mach-порти не потрібні.
- `libsysmon.dylib`: Надає інформацію про процеси через функції XPC, але викликачам потрібен entitlement `com.apple.sysmond.client`.

### Stackshot і microstackshots

**Stackshotting** — це техніка для знімання стану процесів, зокрема стеків викликів усіх запущених потоків. Це особливо корисно для налагодження, аналізу продуктивності та розуміння поведінки системи в певний момент часу. В iOS і macOS stackshotting можна виконувати за допомогою кількох інструментів і методів, зокрема інструментів **`sample`** і **`spindump`**.

### Sysdiagnose

Цей інструмент (`/usr/bini/ysdiagnose`) збирає багато інформації з комп’ютера, виконуючи десятки різних команд, наприклад `ps`, `zprint`...

Його потрібно запускати від імені **root**, а демон `/usr/libexec/sysdiagnosed` має дуже цікаві entitlements, зокрема `com.apple.system-task-ports` і `get-task-allow`.

Його plist розташований за адресою `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` і визначає 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: видаляє старі архіви з /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: спеціальний порт 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: інтерфейс користувацького режиму через клас Obj-C `Libsysdiagnose`. Можна передати три аргументи у dict (`compress`, `display`, `run`)

### Уніфіковані журнали

macOS створює докладні журнали, корисні для аналізу поведінки програм.

Деякі поля журналу містять тег `<private>`, щоб приховати інформацію, яка дає змогу ідентифікувати користувача або пристрій. У старіших інструкціях іноді описувалося встановлення сертифіката для показу цих полів; у сучасних рекомендаціях із налагодження натомість використовують конфігураційний профіль із явно заданою областю дії та параметром `Enable-Private-Data` або `OSLogPreferences` для окремих програм. Поведінка може залежати від підсистеми та версії macOS. Обговорення старіших сертифікатів і профілів збережено в посиланнях. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Ліва панель

На лівій панелі Hopper можна переглянути символи бінарного файлу (**Labels**), список процедур і функцій (**Proc**) та рядки (**Str**). Тут показано не всі рядки, а лише визначені в кількох частинах файлу Mac-O (наприклад, _cstring або `objc_methname`).

#### Середня панель

У середній панелі можна переглянути **дизасембльований код**. Його можна відобразити як **звичайний дизасембльований код**, **граф**, **декомпільований код** або **бінарний код**, натиснувши відповідну піктограму:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Клацнувши правою кнопкою миші на об’єкті коду, можна переглянути **посилання на цей об’єкт і з нього** або навіть змінити його назву (це не працює для декомпільованого псевдокоду):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Крім того, **у нижній частині середньої панелі можна вводити команди Python**.

#### Права панель

На правій панелі можна переглянути корисну інформацію, як-от **історію навігації** (щоб знати, як ви перейшли до поточного місця), **граф викликів**, який показує всі **функції, що викликають цю функцію**, і всі функції, **які викликає ця функція**, а також інформацію про **локальні змінні**.

### dtrace

Надає користувачам доступ до програм на надзвичайно **низькому рівні** та дає змогу **трасувати** **програми** й навіть змінювати їхній потік виконання. Dtrace використовує **проби**, розміщені **в різних місцях ядра**, зокрема на початку та в кінці системних викликів.

DTrace використовує функцію **`dtrace_probe_create`**, щоб створити пробу для кожного системного виклику. Ці проби можуть спрацьовувати в **точках входу та виходу кожного системного виклику**. Взаємодія з DTrace відбувається через /dev/dtrace, доступний лише користувачеві root.<sup>[[1]](#references)</sup>

> [!TIP]
> Щоб увімкнути Dtrace, не вимикаючи повністю захист SIP, можна виконати в режимі відновлення: `csrutil enable --without dtrace`
>
> Також можна використовувати **`dtrace`** або **`dtruss`** для бінарних файлів, які **ви скомпілювали**.

Список доступних проб dtrace можна отримати так:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Ім’я probe складається з чотирьох частин: provider, module, function і name (`fbt:mach_kernel:ptrace:entry`). Якщо не вказати якусь частину імені, DTrace застосує до неї wildcard.

Щоб налаштувати DTrace на активацію probe і вказати, які дії виконувати під час їх спрацювання, потрібно використовувати мову D.

Докладніше пояснення та додаткові приклади наведено тут: [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Приклади

Виконайте `man -k dtrace`, щоб переглянути **доступні скрипти DTrace**. Приклад: `sudo dtruss -n binary`

- У рядку

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- скрипт

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

Такі інструменти, як `latency`, `sc_usage`, `fs_usage` і `trace`, використовують його всередині.

Для взаємодії з `kdebug` використовується `sysctl` у просторі імен `kern.kdebug`, а потрібні MIB можна знайти в `sys/sysctl.h`; функції реалізовано в `bsd/kern/kdebug.c`.

Зазвичай для взаємодії з kdebug за допомогою власного клієнта потрібно виконати такі кроки:

- Видалити наявні налаштування за допомогою KERN_KDSETREMOVE
- Налаштувати трасування за допомогою KERN_KDSETBUF і KERN_KDSETUP
- Використати KERN_KDGETBUF, щоб отримати кількість записів у буфері
- Отримати власний клієнт із трасування за допомогою KERN_KDPINDEX
- Увімкнути трасування за допомогою KERN_KDENABLE
- Прочитати буфер, викликавши KERN_KDREADTR
- Щоб зіставити кожен потік із його процесом, викликати KERN_KDTHRMAP.

Щоб отримати цю інформацію, можна скористатися інструментом Apple **`trace`** або спеціальним інструментом [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Зверніть увагу: одночасно Kdebug доступний лише одному користувачу.** Тому одночасно може працювати лише один інструмент, що використовує k-debug.

### ktrace

API `ktrace_*` походять із `libktrace.dylib`, яка обгортає API Kdebug. Клієнту достатньо викликати `ktrace_session_create` і `ktrace_events_[single/class]`, щоб призначити callback-функції для певних кодів, а потім запустити трасування за допомогою `ktrace_start`.

Цей спосіб можна використовувати, навіть коли **SIP активовано**.

Як клієнт можна використовувати утиліту `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Або `tailspin`.

### kperf

Цей інструмент використовується для профілювання на рівні ядра та побудований на основі викликів `Kdebug`.

Загалом перевіряється глобальна змінна `kernel_debug_active`, і якщо вона встановлена, викликається `kperf_kdebug_handler` із кодом `Kdebug` та адресою кадру ядра, що виконує виклик. Якщо код `Kdebug` збігається з одним із вибраних, застосовуються налаштовані «дії», представлені у вигляді бітової маски (див. доступні параметри у `osfmk/kperf/action.h`).

У Kperf також є таблиця MIB для sysctl: (від root) `sysctl kperf`. Відповідний код можна знайти в `osfmk/kperf/kperfbsd.c`.

Крім того, частина функціональності Kperf міститься в `kpc`, який надає інформацію про лічильники продуктивності машини.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) — дуже корисний інструмент для перевірки дій, пов’язаних із процесами (наприклад, для моніторингу нових процесів, які створює певний процес).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) — інструмент для відображення зв’язків між процесами.\
Потрібно моніторити свій Mac за допомогою команди на кшталт **`sudo eslogger fork exec rename create > cap.json`** (терміналу, з якого її запущено, потрібен FDA). Потім можна завантажити JSON у цей інструмент і переглянути всі зв’язки:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) моніторить файлові події, як-от створення, змінення та видалення файлів.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) — інструмент із графічним інтерфейсом, схожий на Microsoft Sysinternals _Procmon_, знайомий користувачам Windows. Він дає змогу починати й зупиняти запис різних типів подій, фільтрувати їх за категоріями (наприклад, файлова система, процеси, мережа тощо) та зберігати записані події у форматі JSON.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) входить до складу інструментів розробника Xcode і використовується для моніторингу продуктивності програм, виявлення memory leaks і відстеження активності файлової системи.

![Crescendo — Apple Instruments: Apple Instruments входить до складу інструментів розробника Xcode і використовується для моніторингу продуктивності програм, виявлення memory leaks і відстеження активності файлової системи](<../../../images/image (1138).png>)

### fs_usage

Дає змогу відстежувати дії, які виконують процеси:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) корисний для перегляду **бібліотек**, які використовує бінарний файл, **файлів**, з якими він працює, і **мережевих** з’єднань.\
Він також перевіряє процеси бінарних файлів за допомогою **virustotal** і показує інформацію про бінарний файл.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

У [**цій публікації в блозі**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) наведено приклад того, як **налагодити запущений демон**, який використовував **`PT_DENY_ATTACH`**, щоб перешкодити налагодженню, навіть якщо SIP було вимкнено.<sup>[[6]](#references)</sup>

### lldb

**lldb** — це фактичний інструмент для **налагодження** бінарних файлів **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Ви можете встановити синтаксис Intel під час використання lldb, створивши файл **`.lldbinit`** у домашній теці з таким рядком:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Усередині lldb збережіть дамп процесу за допомогою `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Опис</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Запустити виконання; воно триватиме, доки не буде досягнуто breakpoint або процес не завершиться.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Запустити виконання та зупинитися на точці входу.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Продовжити виконання процесу, який налагоджується.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Виконати наступну інструкцію. Ця команда пропускає виклики функцій.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Виконати наступну інструкцію. На відміну від команди <code>nexti</code>, ця команда заходить у виклики функцій.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Виконати решту інструкцій у поточній функції (frame), повернутися та зупинитися.</td></tr>
<tr><td><strong>control + c</strong></td><td>Призупинити виконання. Якщо процес запущено (<code>r</code>) або продовжено (<code>c</code>), ця команда зупинить його в поточному місці виконання.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Відобразити пам’ять як рядок із нульовим завершенням.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Відобразити пам’ять як асемблерну інструкцію.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Відобразити пам’ять як байт.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Виводить об’єкт, на який посилається параметр.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
Більшість API або методів Apple Objective-C повертають об’єкти, тому їх слід виводити командою «print object» (<code>po</code>). Якщо <code>po</code> не дає змістовного результату, використовуйте <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Вивести карту пам’яті поточного процесу.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Під час виклику функції **`objc_sendMsg`** регістр **rsi** містить **назву методу** як рядок із нульовим завершенням («C»). Щоб вивести назву через lldb, виконайте:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Захист від динамічного аналізу

#### Виявлення VM

- Команда **`sysctl hw.model`** зазвичай повертає ідентифікатор моделі Mac на фізичному обладнанні, але у VM може повернути інше значення.<sup>[[3]](#references)</sup>
- Змінюючи значення **`hw.logicalcpu`** та **`hw.physicalcpu`**, деякі malware намагаються виявити VM.<sup>[[4]](#references)</sup>
- Деякі malware також можуть **виявити**, що машина працює на **VMware**, за MAC-адресою (00:50:56).
- Також можна **визначити, чи налагоджується процес**, за допомогою простого коду, наприклад:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Також malware може викликати системний виклик **`ptrace`** із прапорцем **`PT_DENY_ATTACH`**. Це **не дозволяє** налагоджува**чу** приєднатися до процесу й трасувати його.
  - Можна перевірити, чи імпортується функція **`sysctl`** або **`ptrace`** (але malware може імпортувати її динамічно)
  - Як зазначено в цьому writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Повідомлення Process # exited with **status = 45 (0x0000002d)** зазвичай є очевидною ознакою того, що ціль налагодження використовує **PT_DENY_ATTACH**_”

#### Передавання керування процесу `fork()`

Процес може ухилитися від налагоджувача, який залишається приєднаним до початкового PID: для цього він викликає `fork()` на початку роботи, завершує батьківський процес (`fork()` повертає додатний PID дочірнього процесу) і продовжує захищену логіку лише в дочірньому процесі (`fork()` повертає `0`). Розв’язання `fork` за допомогою `dlsym(RTLD_DEFAULT, "fork")` також прибирає пряме місце виклику `_fork`, однак це лише перешкода для аналізу: рядок із назвою символу й потік даних динамічного розв’язання залишаються видимими у Mach-O бінарному файлі.<sup>[[10]](#references)[[11]](#references)</sup>

В arm64 виявляйте цей шаблон, відстежуючи потік даних, а не фіксовані адреси: перші два аргументи `dlsym` передаються в `x0` і `x1`, `RTLD_DEFAULT` може відображатися як `-2` (наприклад, `movn x0, #1`), а адреса рядка `"fork"` часто формується парою `adrp`/`add`. Після `bl` до stub `dlsym` відстежте повернений вказівник від `x0` через його перевірку на null і збереження до подальшого непрямого виклику `blr`. Потім простежте результат `fork()` у `w0`: нуль спрямовує виконання до продовження дочірнього процесу, тоді як додатні значення й `-1` спрямовують його до шляху батьківського процесу або обробки помилки.<sup>[[10]](#references)[[11]](#references)</sup>

Статичний обхід полягає в тому, щоб придушити непрямий виклик і змусити наявну перевірку результату перейти шляхом дочірнього процесу. Наприклад, якщо компілятор згенерував наведену нижче послідовність, замініть `blr` і збереження результату на `nop`, задайте штучний результат `0` і залиште логіку порівняння та переходу. Тоді застосунок продовжить виконання з початковим PID, не створюючи дочірнього процесу; регістри інструкцій і цілі переходів потрібно адаптувати до аналізованої збірки.<sup>[[10]](#references)[[11]](#references)</sup>

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

- sysctl `kern.coredump` встановлено на 1 (за замовчуванням)
- Процес не мав прапорців suid/sgid або `kern.sugid_coredump` встановлено на 1 (за замовчуванням — 0)
- Ліміт `AS_CORE` дозволяє цю операцію. Створення дампів можна вимкнути командою `ulimit -c 0`, а повторно ввімкнути командою `ulimit -c unlimited`.

У таких випадках дампи ядра створюються відповідно до значення sysctl `kern.corefile` і зазвичай зберігаються в `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **аналізує процеси, що аварійно завершилися, і зберігає звіт про збій на диску**. Звіт про збій містить інформацію, яка може **допомогти розробнику діагностувати** причину збою.\
Для програм та інших процесів, **що працюють у контексті per-user launchd**, ReportCrash запускається як LaunchAgent і зберігає звіти про збої в `~/Library/Logs/DiagnosticReports/` користувача.\
Для демонів, інших процесів, **що працюють у контексті system launchd**, та інших привілейованих процесів ReportCrash запускається як LaunchDaemon і зберігає звіти про збої в `/Library/Logs/DiagnosticReports` системи.

Якщо ви хвилюєтеся, що звіти про збої **надсилатимуться Apple**, їх можна вимкнути. Якщо ні, звіти про збої можуть допомогти **з’ясувати, чому сервер аварійно завершив роботу**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Сон

Під час fuzzing на macOS забороніть Mac переходити в режим сну:

- systemsetup -setsleep Never
- pmset, Системні параметри
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Розрив SSH-з’єднання

Якщо ви виконуєте fuzzing через SSH-з’єднання, важливо переконатися, що сеанс не перерветься. Для цього змініть файл sshd_config:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Внутрішні обробники

**Перегляньте цю сторінку**, щоб дізнатися, як визначити, яка програма відповідає за **обробку вказаної схеми або протоколу:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Перелік мережевих процесів

Це може бути корисно для пошуку процесів, які обробляють мережеві дані:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Або скористайтеся `netstat` або `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Працює з інструментами CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Він «**просто працює**» з багатьма інструментами GUI для macOS. Деякі програми мають додаткові вимоги, наприклад унікальні імена файлів, певне розширення або читання файлів із контейнера sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Деякі приклади:

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

### Додаткова інформація про fuzzing у macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Реагування на інциденти OS X: написання скриптів та аналіз](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown — Літо fuzzing: macOS — DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Мистецтво шкідливого ПЗ для Mac, том I: аналіз](https://taomm.org/)
- [4] [No Starch Press — Мистецтво шкідливого ПЗ для Mac: посібник з аналізу шкідливого програмного забезпечення](https://nostarch.com/art-mac-malware)
- [5] [knight.sc — інформація, що зберігається в цих секціях у цій публікації блогу](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc — налагодження бінарних файлів Apple, які використовують Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com — подолання методів anti-debug: варіанти macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums — структуровані журнали Xcode та `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User — відображення приватних даних в уніфікованому журналі macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples — приклади fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society — техніка anti-debugging із використанням dlsym і fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
