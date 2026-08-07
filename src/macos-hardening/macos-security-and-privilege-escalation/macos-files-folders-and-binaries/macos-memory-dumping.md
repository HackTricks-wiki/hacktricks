# Дамп пам'яті macOS

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти пам'яті

### Файли підкачки

Файли підкачки, такі як `/private/var/vm/swapfile0`, слугують **кешами, коли фізична пам'ять заповнена**. Коли у фізичній пам'яті більше немає місця, її дані переносяться до файлу підкачки, а потім за потреби повертаються до фізичної пам'яті. Може бути присутньо кілька файлів підкачки з назвами на кшталт swapfile0, swapfile1 тощо.

### Образ гібернації

Файл, розташований за адресою `/private/var/vm/sleepimage`, відіграє важливу роль під час **режиму гібернації**. **Дані з пам'яті зберігаються в цьому файлі, коли OS X переходить у режим гібернації**. Після пробудження комп'ютера система отримує дані пам'яті з цього файлу, що дає користувачу змогу продовжити роботу з того місця, де він зупинився.

Варто зазначити, що в сучасних системах MacOS цей файл зазвичай зашифрований із міркувань безпеки, що ускладнює відновлення даних.

- Щоб перевірити, чи ввімкнено шифрування sleepimage, можна виконати команду `sysctl vm.swapusage`. Вона покаже, чи зашифрований файл.

### Журнали навантаження на пам'ять

Ще одним важливим файлом, пов'язаним із пам'яттю в системах MacOS, є **журнал навантаження на пам'ять**. Ці журнали розташовані в `/var/log` і містять детальну інформацію про використання пам'яті системою та події, пов'язані з навантаженням на пам'ять. Вони можуть бути особливо корисними для діагностики проблем, пов'язаних із пам'яттю, або для розуміння того, як система керує пам'яттю з часом.

## Дамп пам'яті за допомогою osxpmem

Щоб створити дамп пам'яті на комп'ютері MacOS, можна використати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Примітка**: Зараз це здебільшого **застарілий workflow**. `osxpmem` залежить від завантаження kernel extension, проєкт [Rekall](https://github.com/google/rekall) заархівований, його останній реліз датовано **2017** роком, а опублікований binary призначений для **Intel Mac**. У сучасних версіях macOS, особливо на **Apple Silicon**, отримання повного дампа RAM на основі kext зазвичай блокується сучасними обмеженнями для kernel extension, SIP і вимогами до platform signing. На практиці в сучасних системах частіше доводиться створювати **process-scoped dump**, а не образ усієї RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви бачите цю помилку: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` її можна виправити так:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можна виправити, **дозволивши завантаження kext** у розділі "Security & Privacy --> General", просто **дозвольте** це.

Також можна використати цей **oneliner**, щоб завантажити застосунок, завантажити kext і виконати дамп пам’яті:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Дамп пам’яті запущеного процесу за допомогою LLDB

Для **новіших версій macOS** зазвичай найпрактичніше створити дамп пам’яті **певного процесу**, а не намагатися створити образ усієї фізичної пам’яті.

LLDB може зберегти Mach-O core file із запущеної цілі:
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

- Розшифрованих конфігураційних blob-ів
- Токенів, cookies або облікових даних у пам’яті
- Секретів у plaintext, які захищені лише під час зберігання
- Розшифрованих сторінок Mach-O після unpacking / JIT / runtime patching

Якщо ціль захищена **hardened runtime** або `taskgated` забороняє attach, зазвичай потрібна одна з таких умов:

- Ціль містить **`get-task-allow`**
- Ваш debugger підписаний із відповідним **debugger entitlement**
- Ви є **root**, а ціль є стороннім процесом без hardened runtime

Додаткову інформацію про отримання task port і можливості його використання наведено тут:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Швидкі перевірки перед attach

Перш ніж витрачати час на LLDB/Frida, швидко перевірте, чи ціль реально можна **дампити**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
З операційного погляду це зазвичай означає:

- Сторонній застосунок із **`get-task-allow`** часто можна безпосередньо дампити за допомогою LLDB, і отриманий дамп може містити дані, захищені TCC, до яких застосунок уже отримав доступ.<sup>[[1]](#references)</sup>
- **Захищена** ціль без `get-task-allow` зазвичай відхилятиме attach навіть для `root`, якщо ви не контролюєте відповідні entitlements налагоджувача або policy path.
- Незахищені процеси сторонніх розробників і далі є найпростішим місцем для використання `lldb`, `vmmap`, Frida або власних читачів на основі `task_for_pid`/`vm_read`.

### Пошук dumpable вкладених helper'ів

Нові дослідження notarized macOS-застосунків і надалі виявляють **`get-task-allow`** у вкладених helper'ах, а не в основному GUI-бінарнику. Якщо застосунок верхнього рівня виглядає захищеним, перед тим як припиняти пошук, перевірте його **XPC services**, **login items**, **helper tools** і CLI, що входять до комплекту:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Вкладений виконуваний файл із `get-task-allow` часто є найпростішим місцем для підключення через `lldb`, створення core dump або вилучення пам'яті за допомогою власного клієнта `task_for_pid`, навіть якщо основний застосунок має кращий захист.

## Вибіркові dumps за допомогою Frida або userland readers

Коли повний core dump містить забагато зайвих даних, часто швидше dump-нути лише **цікаві доступні для читання діапазони**. Frida особливо корисна, оскільки добре підходить для **цільового вилучення** після отримання можливості підключитися до процесу.

Приклад підходу:

1. Перерахувати доступні для читання/запису діапазони
2. Відфільтрувати їх за module, heap, stack або anonymous memory
3. Dump-нути лише регіони, що містять потенційні рядки, ключі, protobufs, plist/XML blobs або розшифрований code/data

Мінімальний приклад Frida для dump усіх доступних для читання anonymous ranges:
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

- Фрагменти heap застосунку, що містять секрети
- Анонімні області, створені custom packers або loaders
- Сторінки JIT / unpacked code після зміни захистів

Якщо ціль продовжує **виділяти / звільняти пам’ять** під час створення дампа, для нестабільних діапазонів надавайте перевагу примітиву Frida **`readVolatile()`**, а не **`readByteArray()`**. Він повільніший, але не завершує роботу цільового процесу, якщо сторінка стає недоступною посеред читання. Для більших операцій також може бути зручніше передавати фрагменти потоком назад за допомогою `send(..., data)` і стискати їх на стороні контролера, замість створення тисяч малих файлів усередині цільового процесу.

Також існують старіші userland-інструменти, як-от [`readmem`](https://github.com/gdbinit/readmem), але вони переважно корисні як **посилання на вихідний код** для дампінгу в стилі прямого використання `task_for_pid`/`vm_read` і погано підтримуються в сучасних робочих процесах на Apple Silicon.

## Знімки Heap / VM у форматі `.memgraph`

Якщо вас переважно цікавлять **об’єкти heap**, **походження алокацій** або знімок, який можна перемістити на іншу машину, `.memgraph` часто практичніший за гігантський Mach-O core. Інструменти `leaks` можуть створити його з процесу, що працює:<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Потім проведіть його offline-тріаж за допомогою стандартних інструментів Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` — основна причина зберігати знімок `-fullContent`, оскільки мітки, що описують вміст пам'яті, відсутні в мінімальному `.memgraph`.

Це особливо корисно, коли:

- Вам потрібен **менший знімок, яким можна поділитися**, замість повного core dump
- `MallocStackLogging` було ввімкнено, і вам потрібні **backtrace виділень пам'яті**
- Ви вже знаєте **цікаву адресу в heap** і хочете перейти до аналізу за допомогою `malloc_history`
- Вам потрібен швидкий **аналіз VM/heap** перед рішенням, чи вартий повний dump супутнього шуму

### Диференційований triage memgraph

Якщо ви контролюєте спосіб запуску target, увімкніть **історичне логування виділень пам'яті** до запуску, щоб подальші snapshots зберігали корисні backtrace операцій alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Потім зробіть знімки стану навколо цікавої дії та порівняйте їх offline:
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

Для застосунків, які зберігають цінні дані всередині **об’єктів runtime Swift**, `swift-inspect` може бути хорошим доповненням до LLDB або Frida. Замість того щоб спочатку дампити все, можна запитувати конкретні структури runtime Swift із живого процесу:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Це зручно для ідентифікації:

- Великих масивів Swift, що буферизують цікаві дані
- Виділень метаданих, які розкривають типи, завантажені під час виконання
- Стану Swift concurrency (`Task`, зв’язки actor і thread) перед виконанням більш цілеспрямованого dump

Щоб виконати подальший runtime triage на рівні об’єктів, коли ви вже можете інспектувати процес, перегляньте [окрему сторінку про об’єкти в пам’яті](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Нотатки для швидкого triage

- `sysctl vm.swapusage` досі є швидким способом перевірити **використання swap** і те, чи **зашифрований** swap.
- `sleepimage` залишається актуальним переважно для сценаріїв **hibernate/safe sleep**, але сучасні системи зазвичай захищають його, тому його слід розглядати як **джерело артефактів для перевірки**, а не як надійний шлях отримання даних.
- У нових версіях macOS **dump на рівні процесу** зазвичай реалістичніший за **повне створення образу фізичної пам’яті**, якщо ви не контролюєте політику завантаження, стан SIP і завантаження kext.

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
