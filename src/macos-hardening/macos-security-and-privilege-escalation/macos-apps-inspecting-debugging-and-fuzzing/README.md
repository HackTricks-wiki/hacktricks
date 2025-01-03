# macOS Apps - Інспекція, налагодження та Fuzzing

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
### jtool2 & Disarm

Ви можете [**завантажити disarm звідси**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Ви можете [**завантажити jtool2 тут**](http://www.newosxbook.com/tools/jtool.html) або встановити його за допомогою `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool застарілий на користь disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** можна знайти в **macOS**, а **`ldid`** можна знайти в **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) - це інструмент, корисний для перевірки **.pkg** файлів (інсталяторів) і перегляду їх вмісту перед установкою.\
Ці інсталятори мають `preinstall` та `postinstall` bash-скрипти, які автори шкідливого ПЗ зазвичай зловживають для **постійності** **шкідливого** **ПЗ**.

### hdiutil

Цей інструмент дозволяє **монтувати** образи дисків Apple (**.dmg**) для їх перевірки перед запуском чого-небудь:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Він буде змонтований у `/Volumes`

### Упаковані бінарні файли

- Перевірте на високу ентропію
- Перевірте рядки (якщо майже немає зрозумілого рядка, упаковано)
- Упаковщик UPX для MacOS генерує секцію під назвою "\_\_XHDR"

## Статичний аналіз Objective-C

### Метадані

> [!CAUTION]
> Зверніть увагу, що програми, написані на Objective-C, **зберігають** свої оголошення класів **під час** **компіляції** в [Mach-O бінарні файли](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Такі оголошення класів **включають** ім'я та тип:

- Визначені інтерфейси
- Методи інтерфейсу
- Змінні екземпляра інтерфейсу
- Визначені протоколи

Зверніть увагу, що ці імена можуть бути обфусцировані, щоб ускладнити реверсування бінарного файлу.

### Виклик функцій

Коли функція викликається в бінарному файлі, що використовує Objective-C, скомпільований код замість виклику цієї функції викликатиме **`objc_msgSend`**. Яка буде викликати фінальну функцію:

![](<../../../images/image (305).png>)

Параметри, які очікує ця функція:

- Перший параметр (**self**) - "вказівник, який вказує на **екземпляр класу, що має отримати повідомлення**". А простіше кажучи, це об'єкт, на якому викликається метод. Якщо метод є класовим методом, це буде екземпляр об'єкта класу (в цілому), тоді як для методу екземпляра self вказуватиме на створений екземпляр класу як об'єкт.
- Другий параметр (**op**) - "селектор методу, який обробляє повідомлення". Знову ж таки, простіше кажучи, це просто **ім'я методу.**
- Залишкові параметри - це будь-які **значення, які потрібні методу** (op).

Дивіться, як **легко отримати цю інформацію за допомогою `lldb` в ARM64** на цій сторінці:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Аргумент**      | **Реєстр**                                                    | **(для) objc_msgSend**                                 |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------------------ |
| **1-й аргумент**  | **rdi**                                                       | **self: об'єкт, на якому викликається метод**         |
| **2-й аргумент**  | **rsi**                                                       | **op: ім'я методу**                                   |
| **3-й аргумент**  | **rdx**                                                       | **1-й аргумент для методу**                           |
| **4-й аргумент**  | **rcx**                                                       | **2-й аргумент для методу**                           |
| **5-й аргумент**  | **r8**                                                        | **3-й аргумент для методу**                           |
| **6-й аргумент**  | **r9**                                                        | **4-й аргумент для методу**                           |
| **7-й+ аргумент** | <p><strong>rsp+</strong><br><strong>(в стеку)</strong></p> | **5-й+ аргумент для методу**                          |

### Вивантаження метаданих ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) - це інструмент для класового вивантаження Objective-C бінарних файлів. Github вказує на dylibs, але це також працює з виконуваними файлами.
```bash
./dynadump dump /path/to/bin
```
На момент написання, це **в даний час найкраще працює**.

#### Звичайні інструменти
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) - це оригінальний інструмент для генерації декларацій для класів, категорій та протоколів у форматованому коді ObjectiveC.

Він старий і не підтримується, тому, ймовірно, не буде працювати належним чином.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) - це сучасний крос-платформений дамп класів Objective-C. У порівнянні з існуючими інструментами, iCDump може працювати незалежно від екосистеми Apple і надає прив'язки до Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Статичний аналіз Swift

З бінарними файлами Swift, оскільки є сумісність з Objective-C, іноді ви можете витягти декларації за допомогою [class-dump](https://github.com/nygard/class-dump/), але не завжди.

За допомогою команд **`jtool -l`** або **`otool -l`** можна знайти кілька секцій, які починаються з префікса **`__swift5`**:
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
Ви можете знайти додаткову інформацію про [**інформацію, збережену в цьому розділі, у цьому блозі**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Більше того, **Swift бінарники можуть мати символи** (наприклад, бібліотеки повинні зберігати символи, щоб їх функції могли бути викликані). **Символи зазвичай містять інформацію про назву функції** та атрибути в неохайному вигляді, тому вони дуже корисні, і існують "**деманглери"**, які можуть отримати оригінальну назву:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Динамічний аналіз

> [!WARNING]
> Зверніть увагу, що для налагодження бінарних файлів **SIP потрібно вимкнути** (`csrutil disable` або `csrutil enable --without debug`) або скопіювати бінарні файли в тимчасову папку та **видалити підпис** за допомогою `codesign --remove-signature <binary-path>` або дозволити налагодження бінарного файлу (ви можете використовувати [цей скрипт](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Зверніть увагу, що для **інструментування системних бінарних файлів**, (таких як `cloudconfigurationd`) на macOS, **SIP має бути вимкнено** (просто видалення підпису не спрацює).

### APIs

macOS надає деякі цікаві API, які надають інформацію про процеси:

- `proc_info`: Це основний API, який надає багато інформації про кожен процес. Вам потрібно бути root, щоб отримати інформацію про інші процеси, але спеціальні права або порти mach не потрібні.
- `libsysmon.dylib`: Дозволяє отримувати інформацію про процеси через функції, що надаються XPC, однак потрібно мати право `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** - це техніка, що використовується для захоплення стану процесів, включаючи стек викликів усіх запущених потоків. Це особливо корисно для налагодження, аналізу продуктивності та розуміння поведінки системи в конкретний момент часу. На iOS та macOS stackshotting можна виконувати за допомогою кількох інструментів і методів, таких як інструменти **`sample`** та **`spindump`**.

### Sysdiagnose

Цей інструмент (`/usr/bini/ysdiagnose`) в основному збирає багато інформації з вашого комп'ютера, виконуючи десятки різних команд, таких як `ps`, `zprint`...

Його потрібно запускати як **root**, а демон `/usr/libexec/sysdiagnosed` має дуже цікаві права, такі як `com.apple.system-task-ports` та `get-task-allow`.

Його plist розташований у `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, який оголошує 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Видаляє старі архіви в /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Спеціальний порт 23 (ядро)
- `com.apple.sysdiagnose.service.xpc`: Інтерфейс режиму користувача через клас `Libsysdiagnose` Obj-C. Три аргументи в словнику можуть бути передані (`compress`, `display`, `run`)

### Уніфіковані журнали

MacOS генерує багато журналів, які можуть бути дуже корисними при запуску програми, намагаючись зрозуміти **що вона робить**.

Більше того, є деякі журнали, які міститимуть тег `<private>`, щоб **сховати** деяку **інформацію**, що **ідентифікує** **користувача** або **комп'ютер**. Однак, можливо, **встановити сертифікат для розкриття цієї інформації**. Слідуйте поясненням з [**тут**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Ліва панель

На лівій панелі Hopper можна побачити символи (**Labels**) бінарного файлу, список процедур і функцій (**Proc**) та рядки (**Str**). Це не всі рядки, а лише ті, що визначені в кількох частинах файлу Mac-O (як _cstring або_ `objc_methname`).

#### Середня панель

На середній панелі ви можете бачити **дизасембльований код**. І ви можете бачити його у **сирому** дизасемблюванні, як **граф**, як **декодований** і як **бінарний**, натискаючи на відповідну іконку:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Клацнувши правою кнопкою миші на об'єкті коду, ви можете побачити **посилання на/з цього об'єкта** або навіть змінити його назву (це не працює в декодованому псевдокоді):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Більше того, в **нижній частині середньої панелі ви можете писати команди python**.

#### Права панель

На правій панелі ви можете побачити цікаву інформацію, таку як **історія навігації** (щоб ви знали, як ви потрапили в поточну ситуацію), **граф викликів**, де ви можете бачити всі **функції, які викликають цю функцію** та всі функції, які **викликає ця функція**, а також інформацію про **локальні змінні**.

### dtrace

Цей інструмент дозволяє користувачам отримувати доступ до додатків на надзвичайно **низькому рівні** і надає спосіб для користувачів **відстежувати** **програми** і навіть змінювати їх виконання. Dtrace використовує **пробники**, які **розміщені по всьому ядру** і знаходяться в таких місцях, як початок і кінець системних викликів.

DTrace використовує функцію **`dtrace_probe_create`** для створення пробника для кожного системного виклику. Ці пробники можуть бути активовані в **точках входу та виходу кожного системного виклику**. Взаємодія з DTrace відбувається через /dev/dtrace, який доступний лише для користувача root.

> [!TIP]
> Щоб увімкнути Dtrace, не вимикаючи повністю захист SIP, ви можете виконати в режимі відновлення: `csrutil enable --without dtrace`
>
> Ви також можете **`dtrace`** або **`dtruss`** бінарні файли, які **ви скомпілювали**.

Доступні пробники dtrace можна отримати за допомогою:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Назва зонда складається з чотирьох частин: постачальник, модуль, функція та ім'я (`fbt:mach_kernel:ptrace:entry`). Якщо ви не вкажете якусь частину назви, Dtrace застосує цю частину як шаблон.

Щоб налаштувати DTrace для активації зондів і вказати, які дії виконувати, коли вони спрацьовують, нам потрібно буде використовувати мову D.

Більш детальне пояснення та більше прикладів можна знайти в [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Приклади

Запустіть `man -k dtrace`, щоб перерахувати **доступні скрипти DTrace**. Приклад: `sudo dtruss -n binary`
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

Це засіб трасування ядра. Документовані коди можна знайти в **`/usr/share/misc/trace.codes`**.

Інструменти, такі як `latency`, `sc_usage`, `fs_usage` та `trace`, використовують його внутрішньо.

Для взаємодії з `kdebug` використовується `sysctl` через простір імен `kern.kdebug`, а MIB, які можна використовувати, можна знайти в `sys/sysctl.h`, де реалізовані функції в `bsd/kern/kdebug.c`.

Щоб взаємодіяти з kdebug за допомогою власного клієнта, зазвичай виконуються такі кроки:

- Видалити існуючі налаштування з KERN_KDSETREMOVE
- Встановити трасування з KERN_KDSETBUF та KERN_KDSETUP
- Використовувати KERN_KDGETBUF для отримання кількості записів буфера
- Отримати власного клієнта з трасування за допомогою KERN_KDPINDEX
- Увімкнути трасування з KERN_KDENABLE
- Прочитати буфер, викликавши KERN_KDREADTR
- Щоб зіставити кожен потік з його процесом, викликати KERN_KDTHRMAP.

Щоб отримати цю інформацію, можна використовувати інструмент Apple **`trace`** або власний інструмент [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Зверніть увагу, що Kdebug доступний лише для 1 клієнта одночасно.** Тому лише один інструмент на базі k-debug може бути виконаний одночасно.

### ktrace

API `ktrace_*` походять з `libktrace.dylib`, які обгортують ті, що з `Kdebug`. Тоді клієнт може просто викликати `ktrace_session_create` та `ktrace_events_[single/class]`, щоб встановити зворотні виклики для конкретних кодів, а потім запустити його з `ktrace_start`.

Ви можете використовувати це навіть з **активованим SIP**

Ви можете використовувати утиліту `ktrace` як клієнт:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Або `tailspin`.

### kperf

Це використовується для профілювання на рівні ядра і побудоване за допомогою викликів `Kdebug`.

В основному, перевіряється глобальна змінна `kernel_debug_active`, і якщо вона встановлена, викликається `kperf_kdebug_handler` з кодом `Kdebug` та адресою кадру ядра, що викликає. Якщо код `Kdebug` відповідає одному з вибраних, отримуються "дії", налаштовані як бітова карта (перевірте `osfmk/kperf/action.h` для варіантів).

Kperf також має таблицю MIB sysctl: (як root) `sysctl kperf`. Ці коди можна знайти в `osfmk/kperf/kperfbsd.c`.

Більше того, підмножина функціональності Kperf знаходиться в `kpc`, яка надає інформацію про лічильники продуктивності машини.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) є дуже корисним інструментом для перевірки дій, пов'язаних з процесами, які виконує процес (наприклад, моніторинг нових процесів, які створює процес).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) є інструментом для виведення відносин між процесами.\
Вам потрібно моніторити ваш Mac за допомогою команди **`sudo eslogger fork exec rename create > cap.json`** (термінал, що запускає це, вимагає FDA). А потім ви можете завантажити json в цей інструмент, щоб переглянути всі відносини:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) дозволяє моніторити події файлів (такі як створення, модифікації та видалення), надаючи детальну інформацію про такі події.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) є GUI-інструментом з виглядом і відчуттям, які можуть бути знайомі користувачам Windows з _Procmon_ від Microsoft Sysinternal. Цей інструмент дозволяє записувати різні типи подій, які можна почати і зупинити, дозволяє фільтрувати ці події за категоріями, такими як файл, процес, мережа тощо, і надає функціональність для збереження записаних подій у форматі json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) є частиною інструментів розробника Xcode – використовується для моніторингу продуктивності додатків, виявлення витоків пам'яті та відстеження активності файлової системи.

![](<../../../images/image (1138).png>)

### fs_usage

Дозволяє відстежувати дії, виконувані процесами:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) корисний для перегляду **бібліотек**, які використовуються бінарним файлом, **файлів**, які він використовує, та **мережевих** з'єднань.\
Він також перевіряє бінарні процеси на **virustotal** і показує інформацію про бінарний файл.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

У [**цьому блозі**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) ви можете знайти приклад того, як **налагоджувати працюючий демон**, який використовував **`PT_DENY_ATTACH`** для запобігання налагодженню, навіть якщо SIP був вимкнений.

### lldb

**lldb** є де **факто інструментом** для **налагодження** бінарних файлів **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Ви можете встановити смак intel, використовуючи lldb, створивши файл **`.lldbinit`** у вашій домашній папці з наступним рядком:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Всередині lldb, скиньте процес за допомогою `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Команда</strong></td><td><strong>Опис</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Початок виконання, яке триватиме безперервно, поки не буде досягнуто точки зупинки або процес не завершиться.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Почати виконання, зупиняючись на точці входу</td></tr><tr><td><strong>continue (c)</strong></td><td>Продовжити виконання налагоджуваного процесу.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Виконати наступну інструкцію. Ця команда пропустить виклики функцій.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Виконати наступну інструкцію. На відміну від команди nexti, ця команда зайде всередину викликів функцій.</td></tr><tr><td><strong>finish (f)</strong></td><td>Виконати решту інструкцій у поточній функції (“frame”), повернутися та зупинитися.</td></tr><tr><td><strong>control + c</strong></td><td>Призупинити виконання. Якщо процес був запущений (r) або продовжений (c), це призведе до зупинки процесу ...де б він не виконувався в даний момент.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Будь-яка функція, названа main</p><p><code>b &#x3C;binname>`main</code> #Головна функція бінарного файлу</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Головна функція вказаного бінарного файлу</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Будь-який метод NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Зупинка в усіх функціях цієї бібліотеки</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Список точок зупинки</p><p><code>br e/dis &#x3C;num></code> #Увімкнути/Вимкнути точку зупинки</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Отримати допомогу з команди точки зупинки</p><p>help memory write #Отримати допомогу для запису в пам'ять</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">формат</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Відобразити пам'ять як рядок з нульовим закінченням.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Відобразити пам'ять як інструкцію асемблера.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Відобразити пам'ять як байт.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Це надрукує об'єкт, на який посилається параметр</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Зверніть увагу, що більшість API або методів Objective-C від Apple повертають об'єкти, і тому їх слід відображати за допомогою команди “print object” (po). Якщо po не дає змістовного виходу, використовуйте <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Записати AAAA за цією адресою<br>memory write -f s $rip+0x11f+7 "AAAA" #Записати AAAA за адресою</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Дизасемблювати поточну функцію</p><p>dis -n &#x3C;funcname> #Дизасемблювати функцію</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Дизасемблювати функцію<br>dis -c 6 #Дизасемблювати 6 рядків<br>dis -c 0x100003764 -e 0x100003768 # Від однієї адреси до іншої<br>dis -p -c 4 # Почати з поточної адреси дизасемблювання</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Перевірити масив з 3 компонентів у регістрі x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Друк карти пам'яті поточного процесу</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Отримати адресу всіх символів з CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Коли викликається функція **`objc_sendMsg`**, регістр **rsi** містить **назву методу** як рядок з нульовим закінченням (“C”). Щоб надрукувати назву через lldb, виконайте:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Анти-динамічний аналіз

#### Виявлення VM

- Команда **`sysctl hw.model`** повертає "Mac", коли **хост є MacOS**, але щось інше, коли це VM.
- Граючи з значеннями **`hw.logicalcpu`** та **`hw.physicalcpu`**, деякі шкідливі програми намагаються виявити, чи це VM.
- Деякі шкідливі програми також можуть **виявити**, чи машина є **VMware** на основі MAC-адреси (00:50:56).
- Також можливо дізнатися, **чи процес налагоджується** за допомогою простого коду, такого як:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //процес налагоджується }`
- Це також може викликати системний виклик **`ptrace`** з прапором **`PT_DENY_ATTACH`**. Це **запобігає** прикріпленню та трасуванню налагоджувача.
- Ви можете перевірити, чи функція **`sysctl`** або **`ptrace`** імпортується (але шкідливе ПЗ може імпортувати її динамічно)
- Як зазначено в цьому звіті, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Повідомлення Process # exited with **status = 45 (0x0000002d)** зазвичай є явною ознакою того, що ціль налагодження використовує **PT_DENY_ATTACH**_”

## Ядрові дампи

Ядрові дампи створюються, якщо:

- `kern.coredump` sysctl встановлено на 1 (за замовчуванням)
- Якщо процес не був suid/sgid або `kern.sugid_coredump` дорівнює 1 (за замовчуванням 0)
- Ліміт `AS_CORE` дозволяє операцію. Можна подавити створення дампів, викликавши `ulimit -c 0` і знову увімкнути їх за допомогою `ulimit -c unlimited`.

У цих випадках ядрові дампи генеруються відповідно до `kern.corefile` sysctl і зазвичай зберігаються в `/cores/core/.%P`.

## Фаззинг

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **аналізує процеси, що зазнали краху, і зберігає звіт про крах на диск**. Звіт про крах містить інформацію, яка може **допомогти розробнику діагностувати** причину краху.\
Для додатків та інших процесів **в контексті запуску per-user**, ReportCrash працює як LaunchAgent і зберігає звіти про крах у `~/Library/Logs/DiagnosticReports/` користувача.\
Для демонів, інших процесів **в контексті запуску системи** та інших привілейованих процесів, ReportCrash працює як LaunchDaemon і зберігає звіти про крах у `/Library/Logs/DiagnosticReports` системи.

Якщо ви стурбовані тим, що звіти про крах **надсилаються Apple**, ви можете їх вимкнути. Якщо ні, звіти про крах можуть бути корисними для **з'ясування, як сервер зазнав краху**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Сон

Під час фуззингу в MacOS важливо не дозволяти Mac засинати:

- systemsetup -setsleep Never
- pmset, Системні налаштування
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Відключення SSH

Якщо ви фуззите через SSH-з'єднання, важливо переконатися, що сесія не закриється. Тому змініть файл sshd_config на:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Внутрішні обробники

**Перегляньте наступну сторінку**, щоб дізнатися, як ви можете знайти, який додаток відповідає за **обробку вказаної схеми або протоколу:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Перерахування мережевих процесів

Це цікаво для знаходження процесів, які керують мережевими даними:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Або використовуйте `netstat` або `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Працює для CLI інструментів

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Він "**просто працює"** з macOS GUI інструментами. Зверніть увагу, що деякі macOS додатки мають специфічні вимоги, такі як унікальні імена файлів, правильне розширення, необхідність читати файли з пісочниці (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Більше інформації про Fuzzing MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Посилання

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
