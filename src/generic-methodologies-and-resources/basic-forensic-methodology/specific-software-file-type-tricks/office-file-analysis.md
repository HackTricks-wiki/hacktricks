# Аналіз Office файлів

{{#include ../../../banners/hacktricks-training.md}}


Для додаткової інформації див. [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Нижче — короткий підсумок:

Microsoft створила багато форматів офісних документів, дві основні групи — **OLE formats** (наприклад RTF, DOC, XLS, PPT) та **Office Open XML (OOXML) formats** (наприклад DOCX, XLSX, PPTX). Ці формати можуть містити macros, що робить їх цілями для phishing та malware. OOXML файли побудовані як zip-контейнери, які можна розпакувати для перегляду структури файлів і папок та вмісту XML-файлів.

Щоб дослідити структуру OOXML-файлів, наведено команду для розпакування документа та приклад вихідної структури. Описані техніки приховування даних у таких файлах свідчать про постійну еволюцію методів приховування інформації в CTF-викликах.

Для аналізу **oletools** та **OfficeDissector** пропонують комплексні набори інструментів для перевірки як OLE, так і OOXML документів. Ці інструменти допомагають виявляти та аналізувати вбудовані macros, які часто слугують векторами доставки malware, зазвичай завантажуючи та виконуючи додаткові шкідливі payloads. Аналіз VBA macros можна проводити без Microsoft Office, використовуючи Libre Office, який дозволяє налагоджувати з breakpoints та watch variables.

Встановлення та використання **oletools** є простим: наведені команди для встановлення через pip та витягання macros з документів. Автоматичне виконання macros запускається функціями, такими як `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Експлуатація OLE Compound File: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, naïvely editing the compressed bytes won’t persist: your changes are either reverted or the file is rejected. To ensure byte-accurate control over what the deserializer sees you must:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Редагувати Global\Latest з дотриманням gzip/ECC дисципліни

- Розберіть `Global/Latest`: збережіть заголовок, розпакуйте (gunzip) payload, змініть байти, потім знову стисніть (gzip) з використанням сумісних з Revit параметрів deflate.
- Збережіть zero-padding і перерахуйте ECC trailer, щоб нові байти були прийняті Revit.
- Якщо потрібне детерміноване відтворення byte-for-byte, створіть мінімальну обгортку навколо Revit’s DLLs для виклику його gzip/gunzip шляхів та ECC computation (як показано в дослідженні), або повторно використайте будь-який доступний helper, що відтворює ці семантики.

3) Перебудувати OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Примітки:

- CompoundFileTool записує storages/streams у файлову систему з екрануванням символів, недопустимих в іменах NTFS; шлях потоку, який вам потрібен, — це саме `Global/Latest` у дереві виводу.
- Під час проведення масових атак через ecosystem plugins, які отримують RFAs з cloud storage, переконайтеся, що ваш патчений RFA спочатку проходить локальні перевірки цілісності Revit (gzip/ECC correct), перш ніж намагатися виконати ін’єкцію по мережі.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Десеріалізатор Revit читає 16-бітний індекс класу та конструює об'єкт. Певні типи не є поліморфними й позбавлені vtables; зловживання обробкою деструкторів призводить до type confusion, коли рушій виконує непряму виклик через вказівник під контролем атакуючого.
- Вибір `AString` (індекс класу `0x1F`) поміщує вказівник на heap, контрольований атакуючим, у зсув об'єкта 0. Під час циклу деструкторів Revit фактично виконує:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об'єктів у serialized graph так, щоб кожна ітерація destructor loop виконувала по одному gadget («weird machine»), і забезпечте stack pivot у звичний x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:

- CompoundFileTool (OSS) щоб розпакувати/перебудувати OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap з TTD, щоб зберегти сліди компактними.
- Локальний проксі (наприклад, Fiddler) може імітувати доставку через ланцюжок постачання, замінюючи RFAs у трафіку плагіна для тестування.

## Джерела

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
