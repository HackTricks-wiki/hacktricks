# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**Для отримання додаткової інформації дивіться:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Формат PDF відомий своєю складністю та потенціалом для приховування даних, що робить його центром уваги для CTF forensic викликів. Він поєднує елементи простого тексту з бінарними об'єктами, які можуть бути стиснуті або зашифровані, і може включати скрипти на мовах, таких як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна звернутися до [вступних матеріалів](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Дідьє Стефенса, або використовувати інструменти, такі як текстовий редактор або PDF-редактор, наприклад, Origami.

Для глибшого дослідження або маніпуляції з PDF доступні інструменти, такі як [qpdf](https://github.com/qpdf/qpdf) та [Origami](https://github.com/mobmewireless/origami-pdf). Сховані дані в PDF можуть бути приховані в:

- Невидимих шарах
- Форматі метаданих XMP від Adobe
- Інкрементальних генераціях
- Тексті того ж кольору, що й фон
- Тексті за зображеннями або накладеними зображеннями
- Непоказаних коментарях

Для кастомного аналізу PDF можна використовувати бібліотеки Python, такі як [PeepDF](https://github.com/jesparza/peepdf), щоб створити індивідуальні скрипти парсингу. Крім того, потенціал PDF для зберігання прихованих даних настільки великий, що ресурси, такі як посібник НСА з ризиків PDF та контрзаходів, хоча більше не розміщений за своєю первісною адресою, все ще пропонують цінні відомості. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) та колекція [триків формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Анжелі Альберті можуть надати додаткову інформацію з цієї теми.

## Загальні шкідливі конструкції

Зловмисники часто зловживають певними об'єктами PDF та діями, які автоматично виконуються при відкритті документа або взаємодії з ним. Ключові слова, за якими варто полювати:

* **/OpenAction, /AA** – автоматичні дії, що виконуються при відкритті або за певними подіями.
* **/JS, /JavaScript** – вбудований JavaScript (часто обфусцований або розділений між об'єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – запуск зовнішніх процесів / URL.
* **/RichMedia, /Flash, /3D** – мультимедійні об'єкти, які можуть приховувати навантаження.
* **/EmbeddedFile /Filespec** – вкладення файлів (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – потоки об'єктів або форми, які часто зловживають для приховування shell-коду.
* **Інкрементальні оновлення** – кілька %%EOF маркерів або дуже великий **/Prev** зсув можуть вказувати на дані, додані після підписання, щоб обійти AV.

Коли будь-які з попередніх токенів з'являються разом з підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF заслуговує на глибший аналіз.

---

## Статичний аналіз cheat-sheet
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Додаткові корисні проекти (активно підтримуються 2023-2025):
* **pdfcpu** – бібліотека/CLI на Go, здатна *lint*, *decrypt*, *extract*, *compress* та *sanitize* PDF-файли.
* **pdf-inspector** – візуалізатор на базі браузера, який відображає об'єктний граф і потоки.
* **PyMuPDF (fitz)** – скриптовий Python-двигун, який може безпечно відображати сторінки у зображення, щоб активувати вбудований JS у захищеному пісочниці.

---

## Останні техніки атак (2023-2025)

* **MalDoc у PDF polyglot (2023)** – JPCERT/CC спостерігали, як загрози додають документ Word на основі MHT з VBA макросами після фінального **%%EOF**, створюючи файл, який є одночасно дійсним PDF і дійсним DOC. AV-движки, які аналізують лише PDF-слой, пропускають макрос. Статичні PDF-ключові слова чисті, але `file` все ще виводить `%PDF`. Слід вважати будь-який PDF, який також містить рядок `<w:WordDocument>`, дуже підозрілим.
* **Тіньові інкрементальні оновлення (2024)** – противники зловживають функцією інкрементального оновлення, щоб вставити другий **/Catalog** з шкідливим `/OpenAction`, зберігаючи при цьому добрий перший варіант підписаним. Інструменти, які перевіряють лише першу таблицю xref, обходяться.
* **Ланцюг UAF парсингу шрифтів – CVE-2024-30284 (Acrobat/Reader)** – вразлива функція **CoolType.dll** може бути досягнута з вбудованих шрифтів CIDType2, що дозволяє віддалене виконання коду з привілеями користувача після відкриття підготовленого документа. Виправлено в APSB24-29, травень 2024.

---

## Шаблон швидкого правила YARA
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Захисні поради

1. **Швидке виправлення** – тримайте Acrobat/Reader на останньому постійному треку; більшість RCE ланцюгів, спостережуваних у природі, використовують n-день вразливості, виправлені місяцями раніше.
2. **Видалення активного контенту на шлюзі** – використовуйте `pdfcpu sanitize` або `qpdf --qdf --remove-unreferenced`, щоб видалити JavaScript, вбудовані файли та дії запуску з вхідних PDF.
3. **Дезактивація контенту та реконструкція (CDR)** – конвертуйте PDF у зображення (або PDF/A) на пісочниці, щоб зберегти візуальну точність, відкидаючи активні об'єкти.
4. **Блокування рідко використовуваних функцій** – корпоративні налаштування “Покращена безпека” в Reader дозволяють відключати JavaScript, мультимедіа та 3D рендеринг.
5. **Освіта користувачів** – соціальна інженерія (підроблені рахунки та резюме) залишається початковим вектором; навчайте співробітників пересилати підозрілі вкладення до IR.

## Посилання

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (серпень 2023)
* Adobe – Оновлення безпеки для Acrobat і Reader (APSB24-29, травень 2024)


{{#include ../../../banners/hacktricks-training.md}}
