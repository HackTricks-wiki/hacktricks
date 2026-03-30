# Аналіз Office-файлів

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft створила багато форматів офісних документів, два основні типи — **OLE formats** (наприклад RTF, DOC, XLS, PPT) та **Office Open XML (OOXML) formats** (наприклад DOCX, XLSX, PPTX). Ці формати можуть містити макроси, через що вони стають мішенню для фішингу та malware. Файли OOXML мають структуру zip-контейнера, що дозволяє їх розпаковувати й переглядати ієрархію файлів і папок та вміст XML-файлів.

Щоб дослідити структуру файлів OOXML, наведено команду для розпаковки документа та приклад вихідної структури. Документовано техніки приховування даних у цих файлах, що свідчить про постійну еволюцію способів приховування даних у CTF-завданнях.

Для аналізу **oletools** та **OfficeDissector** пропонують повний набір інструментів для дослідження як OLE, так і OOXML документів. Ці інструменти допомагають виявляти й аналізувати вбудовані макроси, які часто виступають векторами доставки malware, зазвичай завантажуючи й виконуючи додаткові шкідливі payloads. Аналіз VBA-макросів можна проводити без Microsoft Office, використовуючи Libre Office, який дозволяє відлагоджувати з breakpoints та watch variables.

Встановлення та використання **oletools** прості: наведені команди для інсталяції через pip та вилучення макросів з документів. Автоматичне виконання макросів запускають функції на кшталт `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – повторний розрахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Серіалізована модель знаходиться під storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ключова структура `Global\Latest` (спостерігалася у Revit 2025):

- Заголовок
- GZIP-стиснений payload (фактичний серіалізований граф об’єктів)
- Заповнення нулями
- Трейлер коду виправлення помилок (Error-Correcting Code, ECC)

Revit автоматично відновлює невеликі порушення у стрімі, використовуючи трейлер ECC, і відкидає стріми, які не відповідають ECC. Тому наївне редагування стиснених байтів не збережеться: ваші зміни або відкотяться, або файл буде відкинутий. Щоб забезпечити побайтовий контроль над тим, що бачить десеріалізатор, ви повинні:

- Повторно стиснути за допомогою сумісної з Revit реалізації gzip (щоб стиснені байти, які Revit генерує/приймає, відповідали очікуваним).
- Повторно обчислити трейлер ECC по заповненому стріму, щоб Revit прийняв змінений стрім без автоматичного відновлення.

Практичний робочий процес для patching/fuzzing вмісту RFA:

1) Розгорніть OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Відредагуйте Global\Latest із дисципліною gzip/ECC

- Розберіть `Global/Latest`: збережіть заголовок, розпакуйте payload за допомогою gunzip, змініть байти, потім знову запакуйте gzip, використовуючи Revit-compatible deflate parameters.
- Збережіть zero-padding і перерахуйте ECC trailer, щоб Revit прийняв нові байти.
- Якщо вам потрібна детермінована побайтова відтворюваність, створіть мінімальний wrapper навколо Revit’s DLLs, щоб викликати його gzip/gunzip paths і ECC computation (як показано в дослідженні), або повторно використайте будь-який доступний helper, що відтворює ці семантики.

3) Перебудуйте OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Примітки:

- CompoundFileTool записує storages/streams у файлову систему з ескейпінгом для символів, недопустимих у NTFS-іменах; шлях потоку, який вам потрібен, точно відповідає `Global/Latest` у дереві виводу.
- Під час проведення масових атак через ecosystem plugins, які витягують RFA з cloud storage, переконайтеся, що ваш патчений RFA локально проходить перевірки цілісності Revit (gzip/ECC correct) перед тим, як намагатися network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer читає 16-bit class index і конструює об'єкт. Certain types are non‑polymorphic і не мають vtables; abusing destructor handling призводить до type confusion, де engine виконує indirect call через attacker-controlled pointer.
- Вибір `AString` (class index `0x1F`) розміщує attacker-controlled heap pointer на object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об'єктів у серіалізованому графі так, щоб кожна ітерація циклу деструктора виконувала один gadget («weird machine»), і організуйте stack pivot у звичайний x64 ROP chain.

Див. деталі побудови Windows x64 pivot/gadget тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

а загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:

- CompoundFileTool (OSS) — для розпакування/перебудови OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap при використанні TTD, щоб зробити сліди компактними.
- Локальний проксі (наприклад, Fiddler) може імітувати supply-chain delivery, підміняючи RFAs у plugin traffic для тестування.

## Посилання

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
