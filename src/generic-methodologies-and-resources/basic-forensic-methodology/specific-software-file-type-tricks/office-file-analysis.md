# Аналіз файлів Office

{{#include ../../../banners/hacktricks-training.md}}

Додаткову інформацію дивіться на [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий підсумок:<sup>[[4]](#references)</sup>

Документи Microsoft Office зазвичай мають застарілі формати, такі як RTF і засновані на OLE/CFBF DOC, XLS та PPT, або новіші формати **Office Open XML (OOXML)**, такі як DOCX, XLSX і PPTX. Документи Office можуть містити активний вміст, наприклад макроси, що робить їх поширеними носіями фішингу та malware. Файли OOXML є ZIP-контейнерами, і їхню ієрархію файлів та XML-вміст можна переглянути, розпакувавши їх.<sup>[[3]](#references)[[4]](#references)</sup>

Для дослідження структур файлів OOXML наведено команду для розпакування документа та вихідну структуру. Методи приховування даних у цих файлах були задокументовані, що свідчить про постійні інновації у приховуванні даних у CTF-завданнях.<sup>[[4]](#references)</sup>

Для аналізу **oletools** і **OfficeDissector** пропонують комплексні набори інструментів для дослідження документів OLE та OOXML. Ці інструменти допомагають виявляти й аналізувати вбудовані макроси, які часто використовуються як вектори доставки malware, зазвичай завантажуючи та виконуючи додаткові шкідливі payloads. Аналіз VBA-макросів можна проводити без Microsoft Office за допомогою Libre Office, який дає змогу налагоджувати код із використанням breakpoint-ів і watch-змінних.<sup>[[4]](#references)</sup>

Встановлення та використання **oletools** є простим: наведено команди для встановлення через pip і вилучення макросів із документів. У Word автоматичні макроси включають `AutoExec` і `AutoOpen`, тоді як `Document_Open` є процедурою події відкриття документа.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Для Office-документів, зашифрованих паролем, дивіться [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Експлуатація OLE Compound File: Autodesk Revit RFA — перерахунок ECC і контрольований gzip

Моделі Revit RFA зберігаються як [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (також CFBF). Серіалізована модель міститься у storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ключова структура `Global\Latest` (спостерігалася в Revit 2025):

- Заголовок
- Стиснене за допомогою GZIP корисне навантаження (фактичний серіалізований граф об'єктів)
- Нульове заповнення
- Трейлер Error-Correcting Code (ECC)

Revit автоматично виправляє невеликі зміни у stream за допомогою трейлера ECC і відхиляє stream, які не відповідають ECC. Тому наївне редагування стиснених байтів не зберігається: зміни або скасовуються, або файл відхиляється. Щоб забезпечити побайтний контроль над тим, що бачить десеріалізатор, потрібно:<sup>[[1]](#references)</sup>

- Повторно стиснути дані за допомогою сумісної з Revit реалізації gzip (щоб стиснені байти, які створює/приймає Revit, відповідали очікуваним).
- Перерахувати трейлер ECC для доповненого stream, щоб Revit прийняв змінений stream без автоматичного виправлення.

Практичний workflow для patching/fuzzing вмісту RFA:<sup>[[1]](#references)</sup>

1) Розгорнути OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Редагування `Global\Latest` із дотриманням правил gzip/ECC

- Декомпонуйте `Global/Latest`: збережіть заголовок, розпакуйте payload за допомогою gunzip, змініть байти, а потім знову запакуйте за допомогою параметрів deflate, сумісних із Revit.
- Збережіть нульове доповнення та повторно обчисліть трейлер ECC, щоб Revit прийняв нові байти.
- Якщо потрібне детерміноване відтворення байт у байт, створіть мінімальну обгортку навколо DLL Revit для виклику його шляхів gzip/gunzip і обчислення ECC (як продемонстровано в дослідженні) або повторно використайте доступний helper, що відтворює цю семантику.

3) Повторно побудуйте складений документ OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool записує storages/streams у filesystem, екрануючи символи, недійсні в іменах NTFS; потрібний вам шлях до stream у вихідному дереві — це саме `Global/Latest`.
- Під час доставки mass attacks через ecosystem plugins, які отримують RFA з cloud storage, переконайтеся, що ваш patched RFA спочатку локально проходить перевірки цілісності Revit (gzip/ECC коректні), перш ніж намагатися виконувати network injection.

Exploitation insight (щоб визначити, які bytes розмістити в gzip payload):<sup>[[1]](#references)</sup>

- Десеріалізатор Revit зчитує 16-бітний class index і створює object. Деякі типи є non-polymorphic і не мають vtables; зловживання обробкою destructor спричиняє type confusion, за якого engine виконує indirect call через pointer, контрольований attacker.
- Вибір `AString` (class index `0x1F`) розміщує контрольований attacker heap pointer за offset 0 object. Під час циклу destructor Revit фактично виконує:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Розмістіть кілька таких об’єктів у серіалізованому графі, щоб кожна ітерація циклу деструктора виконувала один gadget (“weird machine”), і організуйте stack pivot у звичайний x64 ROP chain.

Деталі створення Windows x64 pivot/gadget наведено тут:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

а загальні рекомендації щодо ROP — тут:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Інструменти:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) для розгортання/відновлення складених OLE-файлів: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD для reverse/taint; вимкніть page heap за допомогою TTD, щоб зберегти компактність трас.
- Локальний proxy (наприклад, Fiddler) може імітувати supply-chain delivery, підміняючи RFA у plugin traffic для тестування.

## References

- [1] [Створення повного RCE exploit після crash під час аналізу RFA-файлів Autodesk Revit (блог ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Складений OLE-файл (CFBF): документація](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Польовий посібник Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Документація olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Подія Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
