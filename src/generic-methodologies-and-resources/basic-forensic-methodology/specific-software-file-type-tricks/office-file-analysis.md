# Аналіз файлів Office

{{#include ../../../banners/hacktricks-training.md}}

Докладніше див. [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Тут наведено лише короткий огляд:<sup>[[4]](#references)</sup>

Документи Microsoft Office часто трапляються у застарілих форматах, як-от RTF і DOC, XLS та PPT на основі OLE/CFBF, або в новіших форматах **Office Open XML (OOXML)**, як-от DOCX, XLSX і PPTX. Документи Office можуть містити активний вміст, наприклад макроси, що робить їх поширеними засобами фішингу та розповсюдження malware. Файли OOXML — це ZIP-контейнери, ієрархію файлів і вміст XML яких можна переглянути, розпакувавши їх.<sup>[[3]](#references)[[4]](#references)</sup>

Щоб дослідити структуру файлів OOXML, наведено команду для розпакування документа та структуру отриманих файлів. Методи приховування даних у таких файлах уже задокументовані, що свідчить про постійне вдосконалення способів приховування даних у CTF-завданнях.<sup>[[4]](#references)</sup>

Для аналізу **oletools** і **OfficeDissector** пропонують комплексні набори інструментів для дослідження документів OLE та OOXML. Ці інструменти допомагають виявляти й аналізувати вбудовані макроси, які часто слугують засобом доставки malware, зазвичай завантажуючи та запускаючи додаткові шкідливі payload-и. Аналізувати макроси VBA можна без Microsoft Office за допомогою LibreOffice, який підтримує налагодження з точками зупинки та змінними для спостереження.<sup>[[4]](#references)</sup>

Встановити й використовувати **oletools** просто: наведено команди для встановлення через pip і вилучення макросів із документів. У Word автоматичні макроси мають назви `AutoExec` і `AutoOpen`, а `Document_Open` — це процедура події відкриття документа.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Для документів Office, зашифрованих паролем, див. [офлайн-процес відновлення на основі граматики](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Експлуатація OLE Compound File: Autodesk Revit RFA — перерахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (також відомий як CFBF). Серіалізована модель міститься в storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Структура `Global\Latest` (спостерігалася в Revit 2025):

- Заголовок
- Стиснені за допомогою GZIP дані (фактичний серіалізований граф об’єктів)
- Заповнення нулями
- Трейлер коду виправлення помилок (ECC)

Revit автоматично виправляє незначні зміни потоку за допомогою трейлера ECC і відхиляє потоки, що не відповідають ECC. Тому просте редагування стиснених байтів не збереже зміни: вони або будуть скасовані, або файл буде відхилено. Щоб забезпечити точний побайтовий контроль над тим, що бачить десеріалізатор, потрібно:<sup>[[1]](#references)</sup>

- Повторно стиснути дані за допомогою сумісної з Revit реалізації gzip (щоб стиснені байти, які створює/приймає Revit, відповідали очікуваним).
- Перерахувати трейлер ECC для потоку з доповненням, щоб Revit прийняв змінений потік без автоматичного виправлення.

Практичний процес виправлення/fuzzing вмісту RFA:<sup>[[1]](#references)</sup>

1) Розгорніть складений документ OLE.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Редагуйте Global\Latest, дотримуючись вимог gzip/ECC

- Розберіть `Global/Latest`: збережіть заголовок, розпакуйте payload за допомогою gunzip, змініть байти, а потім знову запакуйте за допомогою параметрів deflate, сумісних із Revit.
- Збережіть нульове доповнення та перерахункуйте трейлер ECC, щоб Revit прийняв нові байти.
- Якщо вам потрібне детерміноване відтворення байт у байт, створіть мінімальну оболонку навколо DLL Revit, щоб викликати його шляхи gzip/gunzip і обчислення ECC (як продемонстровано в дослідженні), або повторно використайте наявний допоміжний інструмент, який відтворює цю семантику.

3) Перебудуйте складений документ OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool записує storages/streams у файлову систему, екрануючи символи, неприпустимі в іменах NTFS; потрібний шлях до stream у вихідному дереві — саме `Global/Latest`.
- Під час доставки масових атак через плагіни екосистеми, які завантажують RFA з хмарного сховища, спершу переконайтеся, що виправлений RFA локально проходить перевірки цілісності Revit (gzip/ECC коректні), і лише після цього намагайтеся виконати мережеве впровадження.

Інсайт щодо експлуатації (щоб визначити, які байти розмістити в gzip payload):<sup>[[1]](#references)</sup>

- Десеріалізатор Revit зчитує 16-бітний індекс класу та створює об’єкт. Деякі типи не є поліморфними й не мають vtable; зловживання обробкою деструкторів спричиняє type confusion, унаслідок якого рушій виконує непрямий виклик через контрольований зловмисником вказівник.
- Вибір `AString` (індекс класу `0x1F`) розміщує контрольований зловмисником вказівник на heap за зміщенням 0 в об’єкті. Під час циклу деструктора Revit фактично виконує:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Розмістіть кілька таких об’єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала один gadget («weird machine»), і організуйте pivot стека до звичайного x64 ROP chain.

Докладніше про побудову pivot/gadget для Windows x64 дивіться тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

Загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) для розпакування/повторного створення складених файлів OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD для реверс-аналізу/taint-аналізу; вимкніть page heap у TTD, щоб журнали трасування були компактними.
- Локальний proxy (наприклад, Fiddler) може симулювати доставку через ланцюг постачання, підміняючи RFA у трафіку плагіна під час тестування.

## References

- [1] [Створення повноцінного RCE-експлойта на основі збою під час обробки файлу Autodesk Revit RFA (блог ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Документація про складений файл OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Польовий посібник із Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Документація olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Автоматичні макроси (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Подія Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
