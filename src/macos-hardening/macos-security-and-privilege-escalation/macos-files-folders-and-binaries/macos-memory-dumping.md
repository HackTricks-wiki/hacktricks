# Дамп пам’яті macOS

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти пам’яті

### Swap Files

Swap files, такі як `/private/var/vm/swapfile0`, слугують **кешами, коли фізична пам’ять заповнена**. Коли у фізичній пам’яті більше немає місця, її дані переносяться у swap file, а потім за потреби повертаються назад у фізичну пам’ять. Може бути кілька swap files з назвами на кшталт swapfile0, swapfile1 тощо.

### Hibernate Image

Файл, розташований за шляхом `/private/var/vm/sleepimage`, є критично важливим під час **режиму гібернації**. **Дані з пам’яті зберігаються в цьому файлі, коли OS X переходить у hibernation**. Після пробудження комп’ютера система отримує дані пам’яті з цього файлу, дозволяючи користувачу продовжити з того місця, де він зупинився.

Варто зазначити, що на сучасних системах MacOS цей файл зазвичай зашифрований з міркувань безпеки, що ускладнює відновлення.

- Щоб перевірити, чи ввімкнено шифрування для sleepimage, можна виконати команду `sysctl vm.swapusage`. Вона покаже, чи зашифровано файл.

### Memory Pressure Logs

Ще один важливий файл, пов’язаний із пам’яттю, у системах MacOS — це **memory pressure log**. Ці логи розташовані в `/var/log` і містять детальну інформацію про використання пам’яті системою та події memory pressure. Вони можуть бути особливо корисними для діагностики проблем, пов’язаних із пам’яттю, або для розуміння того, як система керує пам’яттю з часом.

## Dumping memory with osxpmem

Щоб зробити dump пам’яті на машині MacOS, ви можете використати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Це переважно **legacy workflow**. `osxpmem` залежить від завантаження kernel extension, проєкт [Rekall](https://github.com/google/rekall) archived, останній release — з **2017**, а опублікований binary орієнтований на **Intel Macs**. На поточних релізах macOS, особливо на **Apple Silicon**, повне отримання RAM через kext зазвичай блокується сучасними обмеженнями kernel extension, SIP і вимогами до platform-signing. На практиці на сучасних системах ви частіше робитимете **process-scoped dump** замість whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви бачите цю помилку: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Ви можете виправити це, зробивши:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можна виправити, **дозволивши завантаження kext** у "Security & Privacy --> General", просто **дозвольте** це.

Ви також можете використати цей **oneliner**, щоб завантажити застосунок, завантажити kext і виконати dump пам’яті:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Живий дамп процесу за допомогою LLDB

Для **новіших версій macOS** найпрактичніший підхід зазвичай — знімати пам’ять **конкретного процесу**, замість того щоб намагатися зобразити всю фізичну пам’ять.

LLDB може зберегти Mach-O core file з живої цілі:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
За замовчуванням це зазвичай створює **skinny core**. Щоб примусити LLDB включити всю відображену пам’ять процесу:
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
Зазвичай цього достатньо, коли мета — отримати:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

Якщо ціль захищена **hardened runtime**, або якщо `taskgated` забороняє attach, зазвичай потрібна одна з цих умов:

- Ціль має **`get-task-allow`**
- Ваш debugger підписаний із правильним **debugger entitlement**
- Ви є **root**, а ціль — не hardened сторонній process

Для додаткової інформації про отримання task port і про те, що з ним можна робити:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Перед тим як витрачати час на LLDB/Frida, швидко перевірте, чи є ціль реально **dumpable**:
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

- Сторонній app, зібраний з **`get-task-allow`**, часто можна напряму дампити за допомогою LLDB, і отриманий дамп може розкрити TCC-protected дані, до яких app уже отримав доступ.
- **hardened** target без `get-task-allow` зазвичай відхилятиме attach-і, навіть від `root`, якщо ви не контролюєте відповідні debugger entitlements / policy path.
- Unhardened сторонні процеси все ще є найпростішим місцем, де можна використовувати `lldb`, `vmmap`, Frida або кастомні читачі `task_for_pid`/`vm_read`.

## Selective dumps with Frida or userland readers

Коли повний core занадто noisy, дамп лише **interesting readable ranges** часто є швидшим. Frida особливо корисна, бо добре працює для **targeted extraction**, щойно ви можете attach-нутися до процесу.

Приклад підходу:

1. Перелічити readable/writable ranges
2. Відфільтрувати за module, heap, stack або anonymous memory
3. Дампити лише ті regions, що містять candidate strings, keys, protobufs, plist/XML blobs або decrypted code/data

Мінімальний приклад Frida для дампу всіх readable anonymous ranges:
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
Це корисно, коли ви хочете уникнути гігантських core files і зібрати лише:

- App heap chunks, що містять secrets
- Anonymous regions, створені custom packers або loaders
- JIT / unpacked code pages після зміни protections

Старіші userland tools, такі як [`readmem`](https://github.com/gdbinit/readmem), також існують, але вони переважно корисні як **source references** для прямого `task_for_pid`/`vm_read`-style dumping і погано підтримуються для сучасних Apple Silicon workflows.

## Heap / VM snapshots with `.memgraph`

Якщо вас головним чином цікавлять **heap objects**, **allocation provenance** або snapshot, який можна перенести на іншу машину, `.memgraph` часто практичніший за гігантський Mach-O core. Інструменти `leaks` можуть згенерувати його з живого процесу:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Потім виконайте triage офлайн за допомогою стандартних Apple tooling:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` — це основна причина зберігати `-fullContent` capture, оскільки мітки, що описують вміст пам’яті, відсутні в minimal `.memgraph`.

Це особливо корисно, коли:

- Вам потрібен **менший, зручний для поширення snapshot** замість повного core
- `MallocStackLogging` було увімкнено і вам потрібні **allocation backtraces**
- Ви вже знаєте **цікаву адресу heap** і хочете перейти до неї з `malloc_history`
- Вам потрібен швидкий **VM/heap breakdown** перед тим, як вирішити, чи вартий full dump зайвого шуму

## Swift-heavy targets: `swift-inspect`

Для applications, які зберігають high-value data всередині **Swift runtime objects**, `swift-inspect` може бути хорошим доповненням до LLDB або Frida. Замість того щоб спочатку дампити все, ви можете запитувати конкретні Swift runtime structures з live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Це зручно для виявлення:

- Large Swift arrays, що буферизують цікаві дані
- Metadata allocations, які показують types, завантажені під час runtime
- Swift concurrency state (`Task`, actor, thread relationships) перед виконанням більш цільового dump

Для більш детального object-level runtime triage, коли ви вже можете інспектувати process, дивіться [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` усе ще є швидким способом перевірити **swap usage** і те, чи є swap **encrypted**.
- `sleepimage` і далі має значення переважно для сценаріїв **hibernate/safe sleep**, але сучасні системи зазвичай захищають його, тож його слід розглядати як **artifact source to check**, а не як надійний шлях acquisition.
- У recent macOS releases, **process-level dumping** загалом реалістичніший за **full physical memory imaging**, якщо тільки ви не контролюєте boot policy, SIP state і kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
