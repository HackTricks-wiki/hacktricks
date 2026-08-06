# Аналіз файлів Office

{{#include ../../../banners/hacktricks-training.md}}


Додаткову інформацію наведено за посиланням [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий підсумок:<sup>[[4]](#references)</sup>

Microsoft створила багато форматів документів Office, серед яких основними типами є **OLE formats** (наприклад, RTF, DOC, XLS, PPT) і **Office Open XML (OOXML) formats** (зокрема DOCX, XLSX, PPTX). Ці формати можуть містити macros, що робить їх цілями для phishing і malware. Файли OOXML структуровані як zip-контейнери, тому їх можна перевірити, розпакувавши, щоб побачити ієрархію файлів і папок та вміст XML-файлів.

Щоб дослідити структуру файлів OOXML, наведено команду для розпакування документа та структуру отриманого виводу. Методи приховування даних у цих файлах уже задокументовані, що свідчить про постійний розвиток способів приховування даних у CTF challenges.

Для аналізу **oletools** і **OfficeDissector** надають комплексні набори інструментів для перевірки документів OLE та OOXML. Ці інструменти допомагають виявляти й аналізувати embedded macros, які часто використовуються як vectors для доставки malware і зазвичай завантажують та виконують додаткові malicious payloads. Аналіз VBA macros можна виконувати без Microsoft Office за допомогою Libre Office, який дає змогу здійснювати debugging із breakpoints і watch variables.

Встановлення та використання **oletools** є простими: наведено команди для встановлення через pip і вилучення macros із документів. Автоматичне виконання macros запускається такими функціями, як `AutoOpen`, `AutoExec` або `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Експлуатація OLE Compound File: Autodesk Revit RFA – перерахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (також CFBF). Серіалізована модель міститься у storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ключова структура `Global\Latest` (спостерігалася в Revit 2025):

- Заголовок
- GZIP-стиснене корисне навантаження (фактичний серіалізований граф об’єктів)
- Нульове заповнення
- Трейлер Error-Correcting Code (ECC)

Revit автоматично виправляє невеликі зміни у stream за допомогою трейлера ECC і відхиляє stream, які не відповідають ECC. Тому наївне редагування стиснених байтів не зберігатиметься: зміни або скасовуються, або файл відхиляється. Щоб отримати побайтово точний контроль над тим, що побачить десеріалізатор, необхідно:

- Повторно стиснути дані за допомогою сумісної з Revit реалізації gzip (щоб стиснені байти, які Revit створює/приймає, відповідали очікуваним).
- Перерахувати трейлер ECC для доповненого stream, щоб Revit прийняв змінений stream без автоматичного виправлення.

Практичний workflow для patching/fuzzing вмісту RFA:<sup>[[1]](#references)</sup>

1) Розгорнути OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Редагування Global\Latest із дотриманням правил gzip/ECC

- Декомпонуйте `Global/Latest`: збережіть заголовок, розпакуйте payload через gunzip, змініть bytes, потім знову запакуйте через gzip із параметрами deflate, сумісними з Revit.
- Збережіть zero-padding і повторно обчисліть трейлер ECC, щоб Revit прийняв нові bytes.
- Якщо потрібне детерміноване відтворення байт-в-байт, створіть мінімальну обгортку навколо DLL Revit для виклику його шляхів gzip/gunzip та обчислення ECC (як продемонстровано в дослідженні) або повторно використайте доступний helper, який відтворює цю семантику.

3) Повторно зібрати складений OLE-документ
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Примітки:<sup>[[1]](#references)</sup>

- CompoundFileTool записує storages/streams у файлову систему з екрануванням символів, недійсних у назвах NTFS; потрібний шлях до stream у вихідному дереві — саме `Global/Latest`.
- Під час доставки mass attacks через ecosystem plugins, які отримують RFA із cloud storage, переконайтеся, що ваш пропатчений RFA спочатку локально проходить перевірки цілісності Revit (gzip/ECC коректні), перш ніж намагатися виконувати network injection.

Інсайт щодо exploitation (щоб визначити, які bytes розмістити в gzip payload):<sup>[[1]](#references)</sup>

- Десеріалізатор Revit зчитує 16-бітний class index і створює object. Певні типи є non-polymorphic і не мають vtables; abuse обробки destructor спричиняє type confusion, через який engine виконує непрямий виклик через pointer, контрольований attacker.
- Вибір `AString` (class index `0x1F`) розміщує контрольований attacker heap pointer за offset 0 object. Під час циклу destructor Revit фактично виконує:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об’єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала один gadget (“weird machine”), і організуйте stack pivot до звичайного x64 ROP chain.

Докладні відомості про Windows x64 pivot/gadget building наведено тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

а загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) для розгортання/перебудови OLE compound files: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap за допомогою TTD, щоб зберегти трасування компактними.
- Локальний proxy (наприклад, Fiddler) може імітувати supply-chain delivery, підміняючи RFA у plugin traffic для тестування.

## Посилання

- [1] [Створення повноцінного RCE exploit на основі crash під час парсингу Autodesk Revit RFA (блог ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Документація OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
