# Дамп пам'яті macOS

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти пам'яті

### Файли підкачки

Файли підкачки, такі як `/private/var/vm/swapfile0`, служать як **кеші, коли фізична пам'ять заповнена**. Коли в фізичній пам'яті немає вільного місця, її дані переміщуються у файл підкачки та за потреби повертаються назад у фізичну пам'ять. Може бути кілька файлів підкачки з іменами на кшталт swapfile0, swapfile1 тощо.

### Файл гібернації

Файл, що знаходиться за шляхом `/private/var/vm/sleepimage`, має ключове значення в режимі **hibernation mode**. **Дані з пам'яті зберігаються у цьому файлі, коли OS X переходить у гібернацію**. Після пробудження система відновлює дані пам'яті з цього файлу, що дозволяє користувачу продовжити роботу з того місця, де він зупинився.

Варто зазначити, що на сучасних системах MacOS цей файл зазвичай шифрується з міркувань безпеки, що ускладнює відновлення.

- Щоб перевірити, чи ввімкнено шифрування для sleepimage, можна виконати команду `sysctl vm.swapusage`. Це покаже, чи файл зашифровано.

### Логи навантаження пам'яті

Іншим важливим файлом, пов'язаним з пам'яттю в системах MacOS, є **memory pressure log**. Ці логи розташовані в `/var/log` і містять детальну інформацію про використання пам'яті системою та події тиску пам'яті. Вони можуть бути особливо корисні для діагностики проблем, пов'язаних із пам'яттю, або для розуміння того, як система керує пам'яттю з часом.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Примітка**: Це здебільшого **застарілий робочий процес** зараз. `osxpmem` залежить від завантаження kernel extension, проект [Rekall](https://github.com/google/rekall) архівовано, останній реліз датовано **2017** роком, а опублікований бінарник орієнтований на **Intel Macs**. У поточних випусках macOS, особливо на **Apple Silicon**, kext-based повне отримання RAM зазвичай блокується сучасними обмеженнями для kernel-extension, SIP та вимогами platform-signing. На практиці на сучасних системах частіше доводиться робити **дамп, обмежений процесом** замість знімку всієї оперативної пам'яті.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви бачите цю помилку: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Ви можете виправити це, виконавши:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можна виправити, **дозволивши завантаження kext** у "Security & Privacy --> General", просто **дозвольте** це.

Ви також можете використати цей **oneliner** щоб завантажити додаток, завантажити kext і dump the memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Зняття дампу живого процесу за допомогою LLDB

Для **нових версій macOS**, найпрактичнішим підходом зазвичай є збереження пам'яті **конкретного процесу** замість спроби створити образ усієї фізичної пам'яті.

LLDB може зберегти Mach-O core file з живої цілі:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
За замовчуванням це зазвичай створює **skinny core**. Щоб змусити LLDB включити всю відображену пам'ять процесу:
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
Цього зазвичай достатньо, коли метою є відновлення:

- Розшифрованих конфігураційних блобів
- Токенів, cookies або облікових даних, що знаходяться в пам'яті
- Текстових секретів, які захищені лише на диску
- Розшифрованих сторінок Mach-O після unpacking / JIT / runtime patching

Якщо ціль захищена **hardened runtime**, або якщо `taskgated` відмовляє в приєднанні, зазвичай потрібна одна з цих умов:

- Ціль має **`get-task-allow`**
- Ваш debugger підписаний з відповідним **debugger entitlement**
- Ви — **root**, і ціль — сторонній процес без hardened runtime

Для додаткової інформації про отримання task port та що з ним можна зробити:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selective dumps with Frida or userland readers

Коли повний core дає занадто багато шуму, дамп лише **цікавих читабельних ділянок** часто буває швидшим. Frida особливо корисна, бо добре підходить для **targeted extraction**, як тільки ви можете приєднатися до процесу.

Приклад підходу:

1. Перелічити readable/writable ділянки
2. Відфільтрувати за модулем, heap, stack або анонімною пам'яттю
3. Дампувати лише регіони, що містять кандидатні рядки, ключі, protobufs, plist/XML блоаби або розшифрований код/дані

Мінімальний приклад Frida для дампу всіх читабельних анонімних ділянок:
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
Це корисно, коли ви хочете уникнути величезних core-файлів і зібрати лише:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Older userland tools such as [`readmem`](https://github.com/gdbinit/readmem) also exist, but they are mainly useful as **source references** for direct `task_for_pid`/`vm_read` style dumping and are not well-maintained for modern Apple Silicon workflows.

## Короткі нотатки для тріажу

- `sysctl vm.swapusage` is still a quick way to check **swap usage** and whether swap is **encrypted**.
- `sleepimage` remains relevant mainly for **hibernate/safe sleep** scenarios, but modern systems commonly protect it, so it should be treated as an **artifact source to check**, not as a reliable acquisition path.
- On recent macOS releases, **process-level dumping** is generally more realistic than **full physical memory imaging** unless you control boot policy, SIP state, and kext loading.

## Посилання

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
