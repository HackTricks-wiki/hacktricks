# Аналіз Office-файлів

{{#include ../../../banners/hacktricks-training.md}}


Для додаткової інформації див. [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише підсумок:

Microsoft створила багато форматів офісних документів; основні дві групи — **OLE formats** (наприклад RTF, DOC, XLS, PPT) та **Office Open XML (OOXML) formats** (наприклад DOCX, XLSX, PPTX). Ці формати можуть містити macros, через що вони стають цілями для phishing і malware. OOXML-файли мають структуру zip-контейнера, що дозволяє проаналізувати їх розпакуванням і переглянути ієрархію файлів і папок та вміст XML-файлів.

Щоб дослідити структуру OOXML-файлів, надається команда для розпакування документа та приклад виведеної структури. Задокументовано техніки приховування даних у цих файлах, що свідчить про постійну еволюцію методів приховування даних у CTF-завданнях.

Для аналізу **oletools** і **OfficeDissector** пропонують повні набори інструментів для дослідження як OLE, так і OOXML-документів. Ці інструменти допомагають виявляти та аналізувати вбудовані macros, які часто слугують векторами доставки malware — зазвичай вони завантажують і виконують додаткові шкідливі payloads. Аналіз VBA macros можна проводити без Microsoft Office, використовуючи Libre Office, який дозволяє відлагоджувати з breakpoint-ами та watch variables.

Встановлення та використання **oletools** просте: наведено команди для інсталяції через pip та для витягання macros з документів. Автоматичне виконання macros тригериться функціями на кшталт `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

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
2) Редагувати Global\Latest з дисципліною gzip/ECC

- Розберіть `Global/Latest`: збережіть header, виконайте gunzip payload, змініть байти, потім виконайте gzip назад, використовуючи параметри deflate сумісні з Revit.
- Збережіть zero-padding і перераховуйте ECC trailer, щоб нові байти були прийняті Revit.
- Якщо вам потрібне детерміноване побайтове відтворення, створіть мінімальний wrapper навколо Revit’s DLLs для виклику його шляхів gzip/gunzip та обчислення ECC (як показано в дослідженні), або повторно використайте будь-який доступний helper, що відтворює ці семантики.

3) Перебудуйте OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об'єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала по одному gadget (“weird machine”), і організуйте stack pivot у звичайний x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:

- CompoundFileTool (OSS) для розгортання/відновлення OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD — для reverse/taint; вимкніть page heap у TTD, щоб зменшити розмір трейсів.
- Локальний proxy (наприклад, Fiddler) може симулювати доставку в supply-chain шляхом підміни RFAs у трафіку плагіна для тестування.

## Посилання

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
