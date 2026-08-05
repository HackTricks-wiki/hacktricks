# Зняття дампа пам'яті в macOS

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти пам'яті

### Файли підкачки

Файли підкачки, такі як `/private/var/vm/swapfile0`, працюють як **кеші, коли фізична пам'ять заповнена**. Коли у фізичній пам'яті більше немає вільного місця, її дані переміщуються до файлу підкачки, а потім за потреби повертаються у фізичну пам'ять. Може бути присутньо кілька файлів підкачки з назвами на кшталт swapfile0, swapfile1 тощо.

### Образ гібернації

Файл `/private/var/vm/sleepimage` відіграє важливу роль під час **режиму гібернації**. **Дані з пам'яті зберігаються в цьому файлі, коли OS X переходить у режим гібернації**. Після пробудження комп'ютера система отримує дані пам'яті з цього файлу, дозволяючи користувачу продовжити роботу з того місця, де він її залишив.

Варто зазначити, що в сучасних системах MacOS цей файл зазвичай зашифрований з міркувань безпеки, що ускладнює відновлення даних.

- Щоб перевірити, чи ввімкнено шифрування для sleepimage, можна виконати команду `sysctl vm.swapusage`. Вона покаже, чи зашифрований файл.

### Журнали навантаження на пам'ять

Іншим важливим файлом, пов'язаним із пам'яттю в системах MacOS, є **журнал навантаження на пам'ять**. Ці журнали розташовані в `/var/log` і містять детальну інформацію про використання пам'яті системою та події, пов'язані з навантаженням на неї. Вони можуть бути особливо корисними для діагностики проблем із пам'яттю або розуміння того, як система керує пам'яттю з часом.

## Зняття дампа пам'яті за допомогою osxpmem

Щоб зняти дамп пам'яті на комп'ютері MacOS, можна використати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Примітка**: Наразі це здебільшого **застарілий workflow**. `osxpmem` залежить від завантаження kernel extension, проєкт [Rekall](https://github.com/google/rekall) заархівований, останній реліз датований **2017 роком**, а опублікований binary призначений для **Intel Mac**. У сучасних релізах macOS, особливо на **Apple Silicon**, отримання повного образу RAM на основі kext зазвичай блокується сучасними обмеженнями kernel extension, SIP і вимогами до platform signing. На практиці в сучасних системах частіше доводиться виконувати **dump, обмежений окремим процесом**, замість створення образу всієї RAM.
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
**Інші помилки** можна виправити, **дозволивши завантаження kext** у розділі "Security & Privacy --> General", просто **дозвольте** це.

Також можна використати цей **oneliner**, щоб завантажити application, завантажити kext і виконати memory dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Дамп пам’яті запущеного процесу за допомогою LLDB

Для **сучасних версій macOS** зазвичай найпрактичніше створити дамп пам’яті **конкретного процесу**, а не намагатися створити образ усієї фізичної пам’яті.

LLDB може зберегти Mach-O core file із запущеного target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
За замовчуванням це зазвичай створює **skinny core**. Щоб змусити LLDB включити всю відображену пам’ять процесу:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Корисні команди для подальших дій перед створенням дампа:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Зазвичай цього достатньо, якщо мета полягає у відновленні:

- Розшифрованих конфігураційних blob'ів
- Токенів, cookie або облікових даних у пам'яті
- Секретів у відкритому вигляді, які захищені лише під час зберігання
- Розшифрованих сторінок Mach-O після unpacking / JIT / runtime patching

Якщо ціль захищена **hardened runtime** або `taskgated` відхиляє attach, зазвичай потрібна одна з таких умов:

- Ціль має **`get-task-allow`**
- Ваш debugger підписаний із відповідним **debugger entitlement**
- Ви є **root**, а ціль є стороннім процесом без hardened runtime

Додаткову інформацію про отримання task port і можливості його використання наведено тут:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Швидкі перевірки перед attach

Перш ніж витрачати час на LLDB/Frida, швидко перевірте, чи ціль справді можна **dump'ити**:
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

- Сторонній застосунок, постачений з **`get-task-allow`**, часто можна безпосередньо dump-ити за допомогою LLDB, і отриманий dump може розкрити захищені TCC дані, до яких застосунок уже отримував доступ.<sup>[[1]](#references)</sup>
- **hardened** target без `get-task-allow` зазвичай відхилятиме спроби attach, навіть якщо вони виконуються від імені `root`, якщо ви не контролюєте відповідні debugger entitlements / policy path.
- Процеси сторонніх застосунків без hardening усе ще є найпростішим місцем для використання `lldb`, `vmmap`, Frida або власних readers на основі `task_for_pid`/`vm_read`.

### Пошук dumpable вкладених helpers

Останні дослідження notarized macOS застосунків знову й знову виявляють **`get-task-allow` у вкладених helpers**, а не в основному GUI binary. Коли застосунок верхнього рівня виглядає hardened, перед тим як зупинятися, перелічіть його **XPC services**, **login items**, **helper tools** і вбудовані CLI:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Вкладений виконуваний файл із `get-task-allow` часто є найпростішим місцем для підключення через `lldb`, створення core dump або вилучення пам’яті за допомогою власного клієнта `task_for_pid`, навіть якщо основний застосунок краще захищений.

## Вибіркові dumps за допомогою Frida або userland readers

Коли повний core dump містить забагато зайвих даних, часто швидше створити dump лише **цікавих доступних для читання діапазонів**. Frida особливо корисна, оскільки добре підходить для **цільового вилучення** після отримання можливості підключитися до процесу.

Приклад підходу:

1. Перерахувати доступні для читання/запису діапазони
2. Відфільтрувати їх за module, heap, stack або anonymous memory
3. Створити dump лише регіонів, що містять потенційні рядки, ключі, protobufs, plist/XML blobs або розшифрований code/data

Мінімальний приклад Frida для створення dump усіх доступних для читання anonymous ranges:
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
Це корисно, коли потрібно уникнути величезних core-файлів і зібрати лише:

- Фрагменти heap застосунку, що містять секрети
- Anonymous-регіони, створені custom packers або loaders
- Сторінки JIT / unpacked code після зміни permissions

Якщо target продовжує **виділяти / звільняти пам’ять** під час dump, для нестабільних діапазонів надавайте перевагу primitive **`readVolatile()`** у Frida замість **`readByteArray()`**. Він працює повільніше, але не завершує роботу target, якщо сторінка стає недоступною посередині читання. Для більших acquisitions також може бути зручніше передавати chunks назад через `send(..., data)` і стискати їх на стороні controller, замість створення тисяч маленьких файлів усередині target.

Також існують старіші userland tools, як-от [`readmem`](https://github.com/gdbinit/readmem), але вони переважно корисні як **source references** для dump у стилі прямого використання `task_for_pid`/`vm_read` і погано підтримуються для сучасних workflows на Apple Silicon.

## Heap / VM snapshots за допомогою `.memgraph`

Якщо вас переважно цікавлять **heap objects**, **allocation provenance** або snapshot, який можна перенести на іншу машину, `.memgraph` часто практичніший за величезний Mach-O core. Tooling `leaks` може створити його з live process:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Потім проведіть його первинний аналіз офлайн за допомогою стандартних інструментів Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` є основною причиною зберігати capture із `-fullContent`, оскільки labels, що описують вміст пам’яті, відсутні в мінімальному `.memgraph`.

Це особливо корисно, коли:

- Вам потрібен **менший snapshot, яким можна поділитися**, замість повного core
- Було увімкнено `MallocStackLogging`, і вам потрібні **allocation backtraces**
- Ви вже знаєте **цікаву heap-адресу** й хочете виконати pivot за допомогою `malloc_history`
- Вам потрібен швидкий **розподіл VM/heap**, перш ніж вирішувати, чи вартий повний dump створюваного шуму

### Differential memgraph triage

Якщо ви контролюєте спосіб запуску target, увімкніть **historical allocation logging** до запуску, щоб подальші snapshots зберігали корисні alloc/free backtraces:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Потім зробіть знімки стану до та після цікавої операції й порівняйте їх offline:
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
Це практичний спосіб ізолювати **об’єкти після автентифікації**, **великі буфери `CFData`** або **анонімні області VM**, які з’являються лише після етапу розшифрування, розпакування чи отримання секретів.

## Цілі з активним використанням Swift: `swift-inspect`

Для застосунків, які зберігають цінні дані всередині **об’єктів runtime Swift**, `swift-inspect` може бути корисним доповненням до LLDB або Frida. Замість того щоб спочатку дампити все, можна запитувати конкретні структури runtime Swift із запущеного процесу:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Це зручно для виявлення:

- Великих Swift-масивів, що буферизують цікаві дані
- Виділень пам’яті для metadata, які розкривають типи, завантажені під час runtime
- Стану Swift concurrency (`Task`, зв’язки між actor і thread) перед виконанням більш цілеспрямованого dump

Для детальнішого runtime triage на рівні об’єктів, коли ви вже можете перевіряти процес, перегляньте [окрему сторінку про об’єкти в пам’яті](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Короткі нотатки щодо triage

- `sysctl vm.swapusage` і надалі є швидким способом перевірити **використання swap** і те, чи **зашифрований** swap.
- `sleepimage` залишається актуальним переважно для сценаріїв **hibernate/safe sleep**, але сучасні системи зазвичай захищають його, тому його слід розглядати як **джерело артефактів для перевірки**, а не як надійний шлях отримання даних.
- У нових версіях macOS **dumping на рівні процесу** зазвичай реалістичніший за **створення повного образу фізичної пам’яті**, якщо ви не контролюєте boot policy, стан SIP і завантаження kext.

## References

- [1] [Дозволяти чи не дозволяти get-task-allow: аналіз безпеки macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [man-сторінка leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
