# Аналіз файлів Office

{{#include ../../../banners/hacktricks-training.md}}


Для отримання додаткової інформації перегляньте [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий підсумок:<sup>[[4]](#references)</sup>

Microsoft створила багато форматів документів Office. Основними типами є **OLE formats** (як-от RTF, DOC, XLS, PPT) і **Office Open XML (OOXML) formats** (наприклад, DOCX, XLSX, PPTX). Ці формати можуть містити макроси, що робить їх цілями для phishing і malware. Файли OOXML структуровані як zip-контейнери, тому їх можна досліджувати за допомогою розпакування, отримуючи ієрархію файлів і папок та вміст XML-файлів.

Для дослідження структур файлів OOXML наведено команду для розпакування документа та структуру отриманого результату. Задокументовано техніки приховування даних у цих файлах, що свідчить про постійні інновації у concealment даних у CTF challenges.

Для аналізу **oletools** і **OfficeDissector** пропонують комплексні набори інструментів для перевірки документів OLE і OOXML. Ці інструменти допомагають виявляти й аналізувати вбудовані макроси, які часто використовуються як vectors для доставки malware, зазвичай завантажуючи та виконуючи додаткові malicious payloads. Аналіз VBA-макросів можна проводити без Microsoft Office за допомогою Libre Office, який дає змогу виконувати debugging із breakpoints і watch variables.

Встановлення та використання **oletools** є простими: наведено команди для встановлення через pip і вилучення макросів із документів. Автоматичне виконання макросів запускається такими функціями, як `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Експлуатація OLE Compound File: Autodesk Revit RFA — перерахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (також відомий як CFBF). Серіалізована модель міститься в storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Основна структура `Global\Latest` (спостерігалася в Revit 2025):

- Заголовок
- Стиснений за допомогою GZIP payload (фактичний серіалізований граф об'єктів)
- Нульове заповнення
- Трейлер Error-Correcting Code (ECC)

Revit автоматично виправляє невеликі зміни у stream за допомогою трейлера ECC і відхиляє stream, який не відповідає ECC. Тому наївне редагування стиснених байтів не зберігається: зміни або скасовуються, або файл відхиляється. Щоб забезпечити побайтний контроль над тим, що побачить deserializer, потрібно:

- Повторно стиснути дані за допомогою сумісної з Revit реалізації gzip, щоб стиснені байти, які створює/приймає Revit, відповідали очікуваним.
- Перерахувати трейлер ECC для stream із padding, щоб Revit прийняв змінений stream і не виконав автоматичне виправлення.

Практичний workflow для patching/fuzzing вмісту RFA:<sup>[[1]](#references)</sup>

1) Розгорнути OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Редагування Global\Latest із дотриманням правил gzip/ECC

- Декомпонуйте `Global/Latest`: збережіть заголовок, розпакуйте payload за допомогою gunzip, змініть байти, а потім знову запакуйте за допомогою deflate-параметрів, сумісних із Revit.
- Збережіть нульове заповнення та повторно обчисліть трейлер ECC, щоб Revit прийняв нові байти.
- Якщо потрібне детерміноване відтворення байт у байт, створіть мінімальну обгортку навколо DLL Revit для виклику його шляхів gzip/gunzip та обчислення ECC (як продемонстровано в дослідженні) або повторно використайте доступний helper, який відтворює цю семантику.

3) Повторно зібрати складений документ OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Примітки:<sup>[[1]](#references)</sup>

- CompoundFileTool записує storages/streams у файлову систему з екрануванням символів, недійсних у назвах NTFS; потрібний вам шлях до stream — це саме `Global/Latest` у вихідному дереві.
- Під час доставки масових атак через ecosystem plugins, які отримують RFA з cloud storage, переконайтеся, що ваш пропатчений RFA спочатку локально проходить перевірки цілісності Revit (gzip/ECC коректні), перш ніж намагатися виконати мережеву ін'єкцію.

Інсайт щодо exploitation (щоб визначити, які байти розмістити в gzip payload):<sup>[[1]](#references)</sup>

- Deserializer Revit зчитує 16-бітний class index і створює object. Певні типи є non-polymorphic і не мають vtables; зловживання обробкою destructor спричиняє type confusion, за якого engine виконує непрямий виклик через pointer, контрольований атакувальником.
- Вибір `AString` (class index `0x1F`) розміщує heap pointer, контрольований атакувальником, за offset 0 object. Під час циклу destructor Revit фактично виконує:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об’єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала один gadget («weird machine»), і організуйте stack pivot у звичайний x64 ROP chain.

Докладні відомості про Windows x64 pivot/gadget building наведено тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

а загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) для розгортання/перебудови складених OLE-файлів: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap у TTD, щоб зберігати компактні trace.
- Локальний proxy (наприклад, Fiddler) може імітувати supply-chain delivery, підміняючи RFA у plugin traffic під час тестування.

## References

- [1] [Створення повного RCE exploit на основі crash під час парсингу файлів Autodesk Revit RFA (блог ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Посібник з Forensics CTF](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
