# Дамп пам’яті macOS

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти пам’яті

### Swap-файли

Swap-файли, наприклад `/private/var/vm/swapfile0`, слугують **кешами, коли фізична пам’ять заповнена**. Коли у фізичній пам’яті більше немає місця, її дані переміщуються до swap-файлу, а потім за потреби повертаються до фізичної пам’яті. Може бути присутньо кілька swap-файлів із назвами на кшталт swapfile0, swapfile1 тощо.

### Hibernate Image

Файл `/private/var/vm/sleepimage` має важливе значення під час **режиму hibernation**. **Дані з пам’яті зберігаються в цьому файлі, коли OS X переходить у режим hibernation**. Після пробудження комп’ютера система отримує дані пам’яті з цього файлу, що дає користувачу змогу продовжити роботу з того місця, де він її залишив.

Варто зазначити, що в сучасних системах MacOS цей файл зазвичай зашифрований з міркувань безпеки, що ускладнює відновлення даних.

- Щоб перевірити, чи ввімкнено шифрування sleepimage, можна виконати команду `sysctl vm.swapusage`. Вона покаже, чи зашифрований файл.

### Логи Memory Pressure

Ще одним важливим файлом, пов’язаним із пам’яттю в системах MacOS, є **лог memory pressure**. Ці логи розташовані в `/var/log` і містять детальну інформацію про використання пам’яті системою та події memory pressure. Вони можуть бути особливо корисними для діагностики проблем, пов’язаних із пам’яттю, або для розуміння того, як система керує пам’яттю з часом.

## Дамп пам’яті за допомогою osxpmem

Щоб виконати дамп пам’яті на комп’ютері MacOS, можна використати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Примітка**: Зараз це здебільшого **застарілий workflow**. `osxpmem` залежить від завантаження kernel extension, проєкт [Rekall](https://github.com/google/rekall) заархівований, його останній реліз датується **2017 роком**, а опублікований binary призначений для **Intel Mac**. У сучасних релізах macOS, особливо на **Apple Silicon**, отримання повного образу RAM на основі kext зазвичай блокується сучасними обмеженнями kernel extension, SIP і вимогами до platform signing. На практиці в сучасних системах частіше доводиться виконувати **дамп, обмежений певним процесом**, а не створювати образ усієї RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви зіткнулися з цією помилкою: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` її можна виправити так:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можна виправити, **дозволивши завантаження kext** у розділі "Безпека та конфіденційність --> Загальні", просто **дозвольте** це.

Також можна використати цей **oneliner**, щоб завантажити застосунок, завантажити kext і зробити dump пам'яті:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Дамп пам’яті активного процесу за допомогою LLDB

Для **сучасних версій macOS** найпрактичнішим підходом зазвичай є дамп пам’яті **певного процесу**, а не спроба створити образ усієї фізичної пам’яті.

LLDB може зберегти Mach-O core-файл із активної цілі:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
За замовчуванням це зазвичай створює **skinny core**. Щоб змусити LLDB включити всю пам’ять процесу, відображену в адресний простір:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Корисні команди для подальших дій перед dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Цього зазвичай достатньо, якщо мета полягає у відновленні:

- Розшифрованих конфігураційних blob-ів
- Токенів, cookies або облікових даних у пам’яті
- Секретів у відкритому вигляді, захищених лише під час зберігання
- Розшифрованих сторінок Mach-O після unpacking / JIT / runtime patching

Якщо ціль захищена **hardened runtime** або `taskgated` забороняє підключення, зазвичай потрібна одна з таких умов:

- Ціль містить **`get-task-allow`**
- Ваш debugger підписаний із відповідним **debugger entitlement**
- Ви є **root**, а ціль є стороннім процесом без hardened runtime

Докладніше про отримання task port і можливості, які він надає:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Швидкі перевірки перед підключенням

Перш ніж витрачати час на LLDB/Frida, швидко перевірте, чи ціль справді можна **dump-ити**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Операційно це зазвичай означає:

- Сторонній app із **`get-task-allow`** часто можна безпосередньо dump-ити за допомогою LLDB, і отриманий dump може розкрити захищені TCC дані, до яких app уже отримав доступ.<sup>[1]</sup>
- **hardened** target без `get-task-allow` зазвичай відхиляє attach, навіть із правами `root`, якщо ви не контролюєте відповідні debugger entitlements / policy path.
- Unhardened процеси сторонніх розробників і далі є найпростішим місцем для використання `lldb`, `vmmap`, Frida або власних readers на основі `task_for_pid`/`vm_read`.

### Пошук dumpable вкладених helpers

Останні дослідження notarized macOS apps постійно виявляють **`get-task-allow` у вкладених helpers**, а не в основному GUI binary. Якщо app верхнього рівня виглядає hardened, перед тим як здаватися, перелічіть його **XPC services**, **login items**, **helper tools** і bundled CLIs:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Вкладений executable із `get-task-allow` часто є найпростішим місцем для підключення через `lldb`, створення дампа core або вилучення пам’яті за допомогою власного клієнта `task_for_pid`, навіть якщо основний застосунок краще захищений.

## Вибіркові дампи за допомогою Frida або userland readers

Коли повний core містить забагато зайвих даних, часто швидше створити дамп лише **цікавих доступних для читання діапазонів**. Frida особливо корисна, оскільки добре підходить для **цільового вилучення** після отримання можливості підключитися до процесу.

Приклад підходу:

1. Перерахувати доступні для читання/запису діапазони
2. Відфільтрувати їх за module, heap, stack або anonymous memory
3. Створити дамп лише регіонів, що містять потенційні рядки, ключі, protobufs, plist/XML blobs або decrypted code/data

Мінімальний приклад Frida для створення дампа всіх доступних для читання anonymous ranges:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Це корисно, коли потрібно уникнути гігантських core-файлів і зібрати лише:

- Фрагменти App heap, що містять секрети
- Anonymous-регіони, створені custom packer-ами або loader-ами
- JIT / unpacked code-сторінки після зміни protection

Якщо target продовжує **виділяти / звільняти** пам'ять під час dump, для нестабільних діапазонів надавайте перевагу примітиву Frida **`readVolatile()`** замість **`readByteArray()`**. Він повільніший, але запобігає аварійному завершенню target, якщо сторінка стане недоступною посеред читання. Для більших acquisitions також може бути зручніше передавати chunks назад через `send(..., data)` і стискати їх на стороні controller, замість створення тисяч малих файлів усередині target.

Також існують старіші userland-інструменти, як-от [`readmem`](https://github.com/gdbinit/readmem), але вони переважно корисні як **source references** для dumping у стилі `task_for_pid`/`vm_read` і недостатньо добре підтримуються для сучасних workflow на Apple Silicon.

## Знімки Heap / VM у форматі `.memgraph`

Якщо вас переважно цікавлять **об'єкти heap**, **provenance allocation** або snapshot, який можна перемістити на іншу машину, `.memgraph` часто практичніший за гігантський Mach-O core. Інструментарій `leaks` може створити його з live process:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Потім проведіть його офлайн-тріаж за допомогою стандартних інструментів Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` — головна причина зберігати знімок `-fullContent`, оскільки мітки, що описують вміст пам’яті, відсутні в мінімальному `.memgraph`.

Це особливо корисно, коли:

- Вам потрібен **менший знімок, яким можна ділитися**, замість повного core
- Було ввімкнено `MallocStackLogging`, і вам потрібні **backtrace виділення пам’яті**
- Ви вже знаєте **цікаву адресу в heap** і хочете виконати pivot за допомогою `malloc_history`
- Вам потрібен швидкий **розбір VM/heap**, перш ніж вирішувати, чи вартий повний dump супутнього шуму

### Тріаж differential memgraph

Якщо ви контролюєте спосіб запуску target, увімкніть **історичне логування allocation** до запуску, щоб подальші snapshots зберігали корисні backtrace операцій alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Потім зробіть знімки стану до та після цікавої дії й порівняйте їх офлайн:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Це практичний спосіб ізолювати **об’єкти після автентифікації**, **великі буфери `CFData`** або **анонімні області VM**, які з’являються лише після етапу розшифрування, розпакування чи отримання секрету.

## Цілі з активним використанням Swift: `swift-inspect`

Для застосунків, які зберігають цінні дані всередині **об’єктів runtime Swift**, `swift-inspect` може бути хорошим доповненням до LLDB або Frida. Замість того щоб спочатку дампити все, можна запитувати конкретні структури runtime Swift у live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Це зручно для виявлення:

- Великих Swift-масивів, що буферизують цікаві дані
- Виділень пам'яті для metadata, які розкривають типи, завантажені під час виконання
- Стану Swift concurrency (`Task`, зв'язки між actor і thread) перед виконанням більш цільового dump

Щоб виконати подальший runtime triage на рівні об'єктів, коли ви вже можете перевіряти процес, дивіться [окрему сторінку про об'єкти в пам'яті](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Короткі нотатки щодо triage

- `sysctl vm.swapusage` і надалі є швидким способом перевірити **використання swap** і те, чи **зашифрований** swap.
- `sleepimage` залишається актуальним переважно для сценаріїв **hibernate/safe sleep**, але сучасні системи зазвичай його захищають, тому його слід розглядати як **джерело артефактів для перевірки**, а не як надійний шлях отримання даних.
- У нових версіях macOS **dump на рівні процесу** зазвичай реалістичніший за **повне створення образу фізичної пам'яті**, якщо ви не контролюєте boot policy, стан SIP і завантаження kext.

## Посилання

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
