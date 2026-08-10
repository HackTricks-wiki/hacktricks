# Аналіз файлів Office

Додаткову інформацію наведено на [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий огляд:<sup>[[4]](#references)</sup>

Документи Microsoft Office зазвичай представлені у legacy-форматах, таких як RTF і DOC, XLS та PPT на основі OLE/CFBF, або в новіших форматах **Office Open XML (OOXML)**, таких як DOCX, XLSX і PPTX. Документи Office можуть містити активний вміст, зокрема macros, що робить їх поширеними засобами phishing і розповсюдження malware. Файли OOXML є ZIP-контейнерами, і їхню ієрархію файлів та XML-вміст можна переглянути, розпакувавши їх.<sup>[[3]](#references)[[4]](#references)</sup>

Щоб дослідити структуру файлів OOXML, наведено команду для розпакування документа та структуру отриманих даних. Методи приховування даних у цих файлах задокументовані, що свідчить про постійні інновації у приховуванні даних у CTF challenges.<sup>[[4]](#references)</sup>

Для аналізу **oletools** і **OfficeDissector** пропонують комплексні набори інструментів для дослідження документів OLE та OOXML. Ці інструменти допомагають виявляти й аналізувати вбудовані macros, які часто використовуються як vectors для доставки malware, зазвичай завантажуючи та виконуючи додаткові malicious payloads. Аналіз VBA macros можна проводити без Microsoft Office за допомогою Libre Office, який дає змогу виконувати debugging із breakpoints і watch variables.<sup>[[4]](#references)</sup>

Встановлення та використання **oletools** є простими: наведено команди для встановлення через pip і вилучення macros із документів. У Word автоматичні macros включають `AutoExec` і `AutoOpen`, тоді як `Document_Open` є процедурою open-event.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Експлуатація OLE Compound File: Autodesk Revit RFA – перерахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (також відомий як CFBF). Серіалізована модель знаходиться у storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ключова структура `Global\Latest` (спостерігалася у Revit 2025):

- Заголовок
- GZIP-стиснений payload (фактичний серіалізований граф об’єктів)
- Нульове доповнення
- Трейлер Error-Correcting Code (ECC)

Revit автоматично виправляє невеликі зміни у stream за допомогою трейлера ECC і відхиляє stream, який не відповідає ECC. Тому наївне редагування стиснених байтів не зберігається: зміни або скасовуються, або файл відхиляється. Щоб забезпечити побайтний контроль над тим, що бачить deserializer, потрібно:<sup>[[1]](#references)</sup>

- Повторно стиснути дані за допомогою сумісної з Revit реалізації gzip (щоб стиснені байти, які створює/приймає Revit, відповідали очікуваним).
- Перерахувати трейлер ECC для доповненого stream, щоб Revit прийняв змінений stream і не виконав автоматичне виправлення.

Практичний workflow для patching/fuzzing вмісту RFA:<sup>[[1]](#references)</sup>

1) Розгорнути OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Редагування `Global\Latest` із дотриманням правил gzip/ECC

- Декомпонуйте `Global/Latest`: збережіть заголовок, розпакуйте payload через gunzip, змініть байти, а потім знову запакуйте через gzip, використовуючи параметри deflate, сумісні з Revit.
- Збережіть нульове заповнення та перерахувати trailer ECC, щоб Revit прийняв нові байти.
- Якщо потрібне детерміноване відтворення байт у байт, створіть мінімальну обгортку навколо DLL Revit для виклику його шляхів gzip/gunzip і обчислення ECC, як продемонстровано в дослідженні, або повторно використайте доступний helper, що відтворює цю семантику.

3) Перебудуйте складений OLE-документ.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Нотатки:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool записує сховища/потоки у файлову систему, екрануючи символи, недійсні в іменах NTFS; потрібний шлях до потоку в дереві виводу — саме `Global/Latest`.
- Під час масових атак через ecosystem plugins, які отримують RFA з cloud storage, спочатку переконайтеся локально, що ваш пропатчений RFA проходить перевірки цілісності Revit (gzip/ECC коректні), і лише потім намагайтеся виконувати network injection.

Інсайт щодо експлуатації (щоб визначити, які байти розмістити в gzip payload):<sup>[[1]](#references)</sup>

- Десеріалізатор Revit зчитує 16-бітний class index і створює об’єкт. Певні типи є non‑polymorphic і не мають vtables; зловживання обробкою деструктора спричиняє type confusion, унаслідок чого engine виконує непрямий виклик через pointer, контрольований атакувальником.
- Вибір `AString` (class index `0x1F`) розміщує контрольований атакувальником heap pointer за зміщенням 0 об’єкта. Під час циклу деструктора Revit фактично виконує:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об’єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала один gadget (“weird machine”), і організуйте stack pivot у звичайний x64 ROP chain.

Деталі побудови Windows x64 pivot/gadget наведено тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

а загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) для розгортання/перебудови OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap за допомогою TTD, щоб зберегти компактність трасувань.
- Локальний proxy (наприклад, Fiddler) може імітувати supply-chain delivery, замінюючи RFA у plugin traffic під час тестування.

## References

- [1] [Створення повного RCE exploit на основі crash під час парсингу Autodesk Revit RFA File (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Посібник з Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Документація olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Подія Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
