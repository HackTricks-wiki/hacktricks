# macOS-застосунки - Inspecting, debugging і Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Статичний аналіз

### otool і objdump і nm
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

You can [**download disarm from here**](https://newosxbook.com/tools/disarm.html).

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
> **`Codesign`** можна знайти в **macOS**, тоді як **`ldid`** можна знайти в **iOS**
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
Ці інсталятори містять bash-скрипти `preinstall` і `postinstall`, якими автори malware зазвичай зловживають, щоб забезпечити **персистентність** **malware**.

### hdiutil

Цей інструмент дає змогу **монтувати** образи дисків Apple (**.dmg**), щоб перевірити їх перед запуском будь-чого:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Його буде змонтовано в `/Volumes`

### Упаковані бінарні файли

- Перевірте високу ентропію
- Перевірте рядки (якщо зрозумілих рядків майже немає, файл упакований)
- Packer UPX для MacOS створює секцію під назвою "\_\_XHDR"

## Статичний аналіз Objective-C

### Метадані

> [!CAUTION]
> Зверніть увагу, що програми, написані на Objective-C, **зберігають** оголошення своїх класів **під час** **компіляції** у [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Такі оголошення класів **містять** назви й типи:

- Визначених інтерфейсів
- Методи інтерфейсів
- Змінні екземплярів інтерфейсів
- Визначених протоколів

Зверніть увагу, що ці назви можуть бути обфусковані, щоб ускладнити reverse engineering бінарного файлу.

### Виклик функцій

Коли у бінарному файлі, який використовує Objective-C, викликається функція, скомпільований код замість безпосереднього виклику цієї функції викликає **`objc_msgSend`**. Вона викликає кінцеву функцію:

![Метадані - Виклик функцій: коли у бінарному файлі, який використовує Objective-C, викликається функція, скомпільований код замість безпосереднього виклику цієї функції викликає objc msgSend. Яка потім викликає...](<../../../images/image (305).png>)

Параметри, які очікує ця функція:

- Перший параметр (**self**) — це "вказівник, який вказує на **екземпляр класу, що має отримати повідомлення**". Простіше кажучи, це об'єкт, для якого викликається метод. Якщо метод є методом класу, це буде екземпляр об'єкта класу (в цілому), тоді як для методу екземпляра self вказуватиме на створений екземпляр класу як об'єкт.
- Другий параметр (**op**) — це "селектор методу, який обробляє повідомлення". Знову ж таки, простіше кажучи, це просто **назва методу.**
- Решта параметрів — це будь-які **значення, необхідні методу** (op).

Дивіться, як легко **отримати цю інформацію за допомогою `lldb` в ARM64** на цій сторінці:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Аргумент**      | **Регістр**                                                    | **(для) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1-й аргумент**  | **rdi**                                                         | **self: об'єкт, для якого викликається метод** |
| **2-й аргумент**  | **rsi**                                                         | **op: назва методу**                             |
| **3-й аргумент**  | **rdx**                                                         | **1-й аргумент методу**                         |
| **4-й аргумент**  | **rcx**                                                         | **2-й аргумент методу**                         |
| **5-й аргумент**  | **r8**                                                          | **3-й аргумент методу**                         |
| **6-й аргумент**  | **r9**                                                          | **4-й аргумент методу**                         |
| **7-й+ аргумент** | <p><strong>rsp+</strong><br><strong>(у стеку)</strong></p> | **5-й+ аргумент методу**                        |

### Дамп метаданих ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) — це tool для class-dump бінарних файлів Objective-C. У github зазначено dylibs, але цей tool також працює з executables.
```bash
./dynadump dump /path/to/bin
```
На момент написання це **наразі працює найкраще**.

#### Звичайні інструменти
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) — це оригінальний інструмент для генерації декларацій класів, категорій і протоколів у форматованому коді Objective-C.

Він застарілий і більше не підтримується, тому, ймовірно, працюватиме некоректно.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) — це сучасний кросплатформний інструмент для class dump у Objective-C. Порівняно з наявними інструментами, iCDump може працювати незалежно від екосистеми Apple і надає прив'язки Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Статичний аналіз Swift

Для бінарних файлів Swift, оскільки існує сумісність з Objective-C, іноді можна витягти оголошення за допомогою [class-dump](https://github.com/nygard/class-dump/), але не завжди.

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
Подальшу інформацію про [**інформацію, що зберігається в цьому розділі, можна знайти в цьому дописі блогу**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Крім того, **Swift binaries можуть містити symbols** (наприклад, libraries потрібно зберігати symbols, щоб можна було викликати їхні functions). **Symbols зазвичай містять інформацію про назву function** та атрибути у некоректному для читання вигляді, тому вони дуже корисні, а існують "**demanglers"**, які можуть отримати оригінальну назву:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Динамічний аналіз

> [!WARNING]
> Зверніть увагу, що для debug бінарних файлів **SIP потрібно вимкнути** (`csrutil disable` або `csrutil enable --without debug`), або скопіювати бінарні файли до тимчасової папки та **видалити підпис** за допомогою `codesign --remove-signature <binary-path>`, або дозволити debug бінарного файлу (можна використати [цей скрипт](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Зверніть увагу, що для **інструментування системних бінарних файлів** (наприклад, `cloudconfigurationd`) у macOS **SIP потрібно вимкнути** (простого видалення підпису буде недостатньо).

### APIs

macOS надає кілька цікавих APIs, які повертають інформацію про процеси:

- `proc_info`: Основний API, який надає багато інформації про кожен процес. Для отримання інформації про інші процеси потрібні права root, але не потрібні спеціальні entitlements або mach ports.
- `libsysmon.dylib`: Дозволяє отримувати інформацію про процеси через exposed-функції XPC, однак потрібен entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** — це техніка захоплення стану процесів, включно зі стеками викликів усіх запущених потоків. Вона особливо корисна для debug, аналізу продуктивності та розуміння поведінки системи в певний момент часу. В iOS і macOS stackshotting можна виконувати за допомогою різних інструментів і методів, зокрема **`sample`** та **`spindump`**.

### Sysdiagnose

Цей інструмент (`/usr/bini/ysdiagnose`) фактично збирає багато інформації з комп’ютера, виконуючи десятки різних команд, таких як `ps`, `zprint`...

Його потрібно запускати від імені **root**, а daemon `/usr/libexec/sysdiagnosed` має дуже цікаві entitlements, зокрема `com.apple.system-task-ports` і `get-task-allow`.

Його plist розташований у `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` і оголошує 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Видаляє старі архіви з /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Спеціальний порт 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Інтерфейс user mode через Obj-C клас `Libsysdiagnose`. Можна передати три аргументи в dict (`compress`, `display`, `run`)

### Unified Logs

MacOS генерує багато logs, які можуть бути дуже корисними під час запуску застосунку, щоб зрозуміти, **що саме він робить**.

Крім того, деякі logs містять тег `<private>`, щоб **приховати** певну **ідентифікаційну** інформацію про **користувача** або **комп’ютер**. Однак можна **встановити сертифікат, щоб розкрити цю інформацію**. Скористайтеся поясненнями [**тут**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Ліва панель

На лівій панелі Hopper можна побачити symbols (**Labels**) бінарного файлу, список процедур і функцій (**Proc**) та strings (**Str**). Це не всі strings, а лише ті, що визначені в кількох частинах файлу Mac-O (наприклад, _cstring або `objc_methname`).

#### Центральна панель

На центральній панелі можна побачити **dissasembled code**. Його можна переглядати як **raw** disassemble, **graph**, **decompiled** або **binary**, натискаючи відповідну іконку:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Клацнувши правою кнопкою миші на об’єкті коду, можна переглянути **references to/from that object** або навіть змінити його назву (це не працює в decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Крім того, **внизу центральної панелі можна вводити команди python**.

#### Права панель

На правій панелі можна переглянути цікаву інформацію, зокрема **історію навігації** (щоб знати, як ви дійшли до поточного стану), **граф викликів**, де видно всі **функції, які викликають цю функцію**, і всі функції, **які викликає ця функція**, а також інформацію про **локальні змінні**.

### dtrace

Це дозволяє користувачам отримувати доступ до застосунків на надзвичайно **низькому рівні**, а також надає можливість **трасувати** **програми** і навіть змінювати потік їхнього виконання. Dtrace використовує **probes**, які **розміщені по всьому kernel**, у таких місцях, як початок і кінець системних викликів.

DTrace використовує функцію **`dtrace_probe_create`** для створення probe для кожного системного виклику. Ці probes можуть спрацьовувати в **точці входу та виходу кожного системного виклику**. Взаємодія з DTrace відбувається через /dev/dtrace, який доступний лише користувачу root.

> [!TIP]
> Щоб увімкнути Dtrace без повного вимкнення захисту SIP, можна виконати в recovery mode: `csrutil enable --without dtrace`
>
> Також можна використовувати бінарні файли **`dtrace`** або **`dtruss`**, які **ви скомпілювали**.

Доступні probes dtrace можна отримати за допомогою:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Назва probe складається з чотирьох частин: provider, module, function і name (`fbt:mach_kernel:ptrace:entry`). Якщо не вказати деякі частини назви, Dtrace застосує до них wildcard.

Щоб налаштувати DTrace на активацію probe і вказати, які дії виконувати під час їх спрацювання, нам потрібно використовувати мову D.

Докладніше пояснення та більше прикладів можна знайти в [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Приклади

Виконайте `man -k dtrace`, щоб переглянути **доступні DTrace scripts**. Приклад: `sudo dtruss -n binary`

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

Для взаємодії з `kdebug` використовується `sysctl` через простір імен `kern.kdebug`, а MIB, які потрібно використовувати, можна знайти в `sys/sysctl.h`; відповідні функції реалізовано в `bsd/kern/kdebug.c`.

Для взаємодії з kdebug за допомогою custom client зазвичай виконуються такі кроки:

- Видалити наявні налаштування за допомогою KERN_KDSETREMOVE
- Налаштувати trace за допомогою KERN_KDSETBUF і KERN_KDSETUP
- Використати KERN_KDGETBUF, щоб отримати кількість записів у buffer
- Виключити власний client із trace за допомогою KERN_KDPINDEX
- Увімкнути tracing за допомогою KERN_KDENABLE
- Прочитати buffer, викликавши KERN_KDREADTR
- Щоб зіставити кожен thread із його process, викликати KERN_KDTHRMAP.

Щоб отримати цю інформацію, можна використати Apple tool **`trace`** або custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Зверніть увагу, що Kdebug доступний лише для 1 користувача одночасно.** Тому одночасно можна виконувати лише один інструмент, що використовує k-debug.

### ktrace

API `ktrace_*` походять із `libktrace.dylib`, яка обгортає API `Kdebug`. Тоді client може просто викликати `ktrace_session_create` і `ktrace_events_[single/class]`, щоб налаштувати callbacks для певних кодів, а потім запустити його за допомогою `ktrace_start`.

Це можна використовувати навіть із **активованим SIP**

Як clients можна використовувати utility `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Це використовується для профілювання на рівні ядра та побудовано на основі callouts `Kdebug`.

Зазвичай перевіряється глобальна змінна `kernel_debug_active`, і якщо її встановлено, викликається `kperf_kdebug_handler` із кодом `Kdebug` та адресою kernel frame, який здійснює виклик. Якщо код `Kdebug` відповідає одному з вибраних, отримуються налаштовані "actions" у вигляді bitmap (перегляньте `osfmk/kperf/action.h`, щоб дізнатися про доступні опції).

Kperf також має таблицю sysctl MIB: (від імені root) `sysctl kperf`. Цей код можна знайти в `osfmk/kperf/kperfbsd.c`.

Крім того, підмножина функціональності Kperf міститься в `kpc`, який надає інформацію про лічильники продуктивності машини.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) — дуже корисний інструмент для перевірки дій, пов’язаних із процесами, які виконує процес (наприклад, для моніторингу того, які нові процеси створює процес).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) — інструмент, який виводить зв’язки між процесами.\
Потрібно моніторити ваш Mac за допомогою команди на кшталт **`sudo eslogger fork exec rename create > cap.json`** (терміналу, з якого запускається ця команда, потрібен FDA). Після цього можна завантажити json у цей інструмент, щоб переглянути всі зв’язки:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) дає змогу моніторити події, пов’язані з файлами (наприклад, створення, зміни та видалення), надаючи детальну інформацію про такі події.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) — GUI-інструмент із виглядом і поведінкою, знайомими користувачам Windows з Microsoft Sysinternal’s _Procmon_. Цей інструмент дає змогу запускати й зупиняти запис різних типів подій, фільтрувати ці події за категоріями, такими як file, process, network тощо, а також зберігати записані події у форматі json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) є частиною Developer tools Xcode — вони використовуються для моніторингу продуктивності застосунків, виявлення memory leaks і відстеження активності файлової системи.

![Crescendo - Apple Instruments: Apple Instruments є частиною Developer tools Xcode — вони використовуються для моніторингу продуктивності застосунків, виявлення memory leaks і відстеження активності файлової системи](<../../../images/image (1138).png>)

### fs_usage

Дає змогу відстежувати дії, які виконують процеси:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) корисний для перегляду **бібліотек**, які використовує бінарний файл, **файлів**, які він використовує, і **мережевих** з'єднань.\
Він також перевіряє процеси бінарного файлу через **virustotal** і показує інформацію про бінарний файл.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

У [**цьому дописі блогу**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) наведено приклад того, як **налагоджувати запущений daemon**, який використовував **`PT_DENY_ATTACH`**, щоб запобігти налагодженню, навіть якщо SIP було вимкнено.

### lldb

**lldb** — це de facto інструмент для **налагодження** бінарних файлів **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Ви можете встановити Intel-синтаксис під час використання lldb, створивши файл **`.lldbinit`** у домашній папці з таким рядком:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Усередині lldb створіть дамп процесу за допомогою `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Команда</strong></td><td><strong>Опис</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Початок виконання, яке триватиме безперервно, доки не буде досягнуто breakpoint або процес не завершиться.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Початок виконання із зупинкою в точці входу</td></tr><tr><td><strong>continue (c)</strong></td><td>Продовжити виконання debug-процесу.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Виконати наступну інструкцію. Ця команда пропустить виклики функцій.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Виконати наступну інструкцію. На відміну від команди nexti, ця команда увійде у виклики функцій.</td></tr><tr><td><strong>finish (f)</strong></td><td>Виконати решту інструкцій поточної функції (“frame”), повернутися та зупинитися.</td></tr><tr><td><strong>control + c</strong></td><td>Призупинити виконання. Якщо процес було запущено (r) або продовжено (c), це призведе до його зупинки ...де б він зараз не виконувався.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Будь-яка функція з назвою main</p><p><code>b <binname>`main</code> #Головна функція бінарного файлу</p><p><code>b set -n main --shlib <lib_name></code> #Головна функція вказаного бінарного файлу</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Будь-який метод NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break у всіх функціях цієї бібліотеки</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Список breakpoint</p><p><code>br e/dis <num></code> #Увімкнути/вимкнути breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Отримати довідку щодо команди breakpoint</p><p>help memory write #Отримати довідку щодо запису в пам’ять</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Відобразити пам’ять як рядок із завершенням нульовим символом.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Відобразити пам’ять як інструкцію асемблера.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Відобразити пам’ять як байт.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Це виведе об’єкт, на який посилається параметр</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Зверніть увагу, що більшість Objective-C API або методів Apple повертають об’єкти, тому їх слід відображати за допомогою команди “print object” (po). Якщо po не виводить змістовний результат, використовуйте <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Записати AAAA за цією адресою<br>memory write -f s $rip+0x11f+7 "AAAA" #Записати AAAA за цією адресою</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Дизасемблювати поточну функцію</p><p>dis -n <funcname> #Дизасемблювати функцію</p><p>dis -n <funcname> -b <basename> #Дизасемблювати функцію<br>dis -c 6 #Дизасемблювати 6 рядків<br>dis -c 0x100003764 -e 0x100003768 # Від однієї адреси до іншої<br>dis -p -c 4 # Почати дизасемблювання з поточної адреси</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Перевірити масив із 3 компонентів у регістрі x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Вивести карту пам’яті поточного процесу</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Отримати адреси всіх символів із CoreNLP</td></tr></tbody></table>

> [!TIP]
> Під час виклику функції **`objc_sendMsg`** регістр **rsi** містить **назву методу** як рядок із завершенням нульовим (“C”) символом. Щоб вивести назву через lldb, виконайте:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Команда **`sysctl hw.model`** повертає "Mac", коли **host є MacOS**, але повертає інше значення у VM.
- Змінюючи значення **`hw.logicalcpu`** і **`hw.physicalcpu`**, деякі malware намагаються визначити, чи працюють вони у VM.
- Деякі malware також можуть **визначити**, що машина працює на **VMware**, на основі MAC-адреси (00:50:56).
- Також можна визначити, **чи debug-иться процес**, за допомогою простого коду:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Також можна викликати системний виклик **`ptrace`** із прапорцем **`PT_DENY_ATTACH`**. Це **перешкоджає debugger-у під’єднатися до процесу та трасувати його**.
- Можна перевірити, **чи імпортуються** функції **`sysctl`** або **`ptrace`** (але malware може імпортувати їх динамічно)
- Як зазначено в цьому writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Повідомлення Process # exited with **status = 45 (0x0000002d)** зазвичай є очевидною ознакою того, що debug target використовує **`PT_DENY_ATTACH`**_”

## Core Dumps

Core dumps створюються, якщо:

- sysctl `kern.coredump` встановлено в 1 (за замовчуванням)
- Процес не був suid/sgid або `kern.sugid_coredump` дорівнює 1 (за замовчуванням — 0)
- Ліміт `AS_CORE` дозволяє цю операцію. Створення core dumps можна вимкнути за допомогою `ulimit -c 0` і знову ввімкнути за допомогою `ulimit -c unlimited`.

У таких випадках core dumps створюється відповідно до sysctl `kern.corefile` і зазвичай зберігається в `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **аналізує процеси, що аварійно завершилися, і зберігає crash report на диску**. Crash report містить інформацію, яка може **допомогти developer-у діагностувати** причину збою.\
Для застосунків та інших процесів, **що працюють у per-user context launchd**, ReportCrash працює як LaunchAgent і зберігає crash reports у `~/Library/Logs/DiagnosticReports/` користувача.\
Для daemon-ів, інших процесів, **що працюють у system context launchd**, та інших привілейованих процесів ReportCrash працює як LaunchDaemon і зберігає crash reports у системному `/Library/Logs/DiagnosticReports`

Якщо ви занепокоєні тим, що crash reports **надсилаються до Apple**, їх можна вимкнути. В іншому разі crash reports можуть бути корисними, щоб **визначити, через що впав server**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Сон

Під час fuzzing на MacOS важливо не дозволяти Mac переходити в режим сну:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Розрив SSH-з'єднання

Якщо ви виконуєте fuzzing через SSH-з'єднання, важливо переконатися, що сесія не буде розірвана. Тому змініть файл sshd_config так:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Внутрішні обробники

**Перегляньте наведену нижче сторінку**, щоб дізнатися, як визначити, який застосунок відповідає за **обробку вказаної схеми або протоколу:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Перелік мережевих процесів

Це корисно для пошуку процесів, які керують мережевими даними:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Або використайте `netstat` або `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Працює з CLI-інструментами

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**"Просто працює"** з GUI-інструментами macOS. Зверніть увагу, що деякі програми macOS мають специфічні вимоги, як-от унікальні імена файлів, правильне розширення, необхідність читати файли з sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Додаткова інформація про Fuzzing MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Посилання

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
