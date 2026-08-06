# Аналіз PDF-файлів

{{#include ../../../banners/hacktricks-training.md}}

**Докладнішу інформацію дивіться:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Формат PDF відомий своєю складністю та можливістю приховувати дані, що робить його важливим об'єктом у forensic challenges для CTF. Він поєднує елементи звичайного тексту з бінарними об'єктами, які можуть бути стиснуті або зашифровані, а також може містити скрипти такими мовами, як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна звернутися до [вступних матеріалів](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didier Stevens або використовувати такі інструменти, як текстовий редактор чи спеціалізований редактор PDF, наприклад Origami.

Для поглибленого дослідження або маніпуляцій із PDF доступні такі інструменти, як [qpdf](https://github.com/qpdf/qpdf) та [Origami](https://github.com/mobmewireless/origami-pdf). Приховані дані в PDF можуть міститися:

- У невидимих шарах
- У форматі XMP metadata від Adobe
- У інкрементальних поколіннях
- У тексті, що має такий самий колір, як і фон
- У тексті за зображеннями або в зображеннях, що перекривають одне одного
- У коментарях, які не відображаються

Для спеціалізованого аналізу PDF можна використовувати Python-бібліотеки, наприклад [PeepDF](https://github.com/jesparza/peepdf), щоб створювати власні parsing scripts. Крім того, потенціал PDF для зберігання прихованих даних настільки великий, що навіть ресурси на кшталт посібника NSA щодо ризиків PDF і контрзаходів, хоча він більше не розміщений у своєму початковому місці, досі містять цінну інформацію. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) та збірка [трюків формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Ange Albertini допоможуть дізнатися більше про цю тему.<sup>[[4]](#references)[[5]](#references)</sup>

## Поширені шкідливі конструкції

Зловмисники часто зловживають певними об'єктами та діями PDF, які автоматично виконуються під час відкриття документа або взаємодії з ним. Варто шукати такі ключові слова:

* **/OpenAction, /AA** – автоматичні дії, що виконуються під час відкриття або певних подій.
* **/JS, /JavaScript** – вбудований JavaScript (часто обфускований або розділений між кількома об'єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – засоби запуску зовнішніх процесів / URL.
* **/RichMedia, /Flash, /3D** – мультимедійні об'єкти, які можуть приховувати payloads.
* **/EmbeddedFile /Filespec** – файлові вкладення (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – object streams або форми, якими часто зловживають для приховування shell-code.
* **Інкрементальні оновлення** – кілька маркерів %%EOF або дуже велике зміщення **/Prev** можуть вказувати на дані, додані після підписання, щоб обійти AV.

Якщо будь-які з наведених токенів зустрічаються разом із підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF заслуговує на глибший аналіз.

---

## Шпаргалка зі статичного аналізу
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
Додаткові корисні проєкти (активно підтримуються у 2023–2025 роках):
* **pdfcpu** – Go-бібліотека/CLI, здатна виконувати *lint*, *decrypt*, *extract*, *compress* і *sanitize* PDF-файлів.
* **pdf-inspector** – візуалізатор у браузері, який відображає граф об’єктів і streams.
* **PyMuPDF (fitz)** – скриптовий Python-рушій, який може безпечно рендерити сторінки в зображення, щоб детонувати вбудований JS у hardened sandbox.

---

## Новітні attack techniques (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC спостерігала, як threat actors додають Word-документ на основі MHT із VBA-макросами після останнього **%%EOF**, створюючи файл, який є одночасно коректним PDF і коректним DOC. AV-рушії, що аналізують лише PDF-шар, пропускають макрос. Статичні PDF-ключові слова не викликають підозр, але `file` усе ще виводить `%PDF`. Вважайте будь-який PDF, який також містить рядок `<w:WordDocument>`, highly suspicious.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries зловживають функцією incremental update, щоб вставити другий **/Catalog** зі шкідливим `/OpenAction`, зберігаючи першу benign revision підписаною. Інструменти, які перевіряють лише першу xref table, можна обійти.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – вразливу функцію **CoolType.dll** можна викликати через вбудовані шрифти CIDType2, що дає змогу виконати remote code з привілеями користувача після відкриття crafted document. Виправлено в APSB24-29 у травні 2024 року.<sup>[[3]](#references)</sup>

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

1. **Швидко встановлюйте патчі** – тримайте Acrobat/Reader на актуальній Continuous track; у більшості RCE-ланцюжків, зафіксованих у wild, використовуються n-day vulnerabilities, виправлені місяцями раніше.
2. **Видаляйте active content на gateway** – використовуйте `pdfcpu sanitize` або `qpdf --qdf --remove-unreferenced`, щоб видаляти JavaScript, embedded files і launch actions із вхідних PDF.
3. **Content Disarm & Reconstruction (CDR)** – конвертуйте PDF у зображення (або PDF/A) на sandbox host, щоб зберегти візуальну точність і водночас видалити active objects.
4. **Блокуйте рідко використовувані функції** – корпоративні налаштування “Enhanced Security” у Reader дають змогу вимкнути JavaScript, multimedia та 3D rendering.
5. **Навчайте користувачів** – social engineering (приманки з рахунками та резюме) залишається початковим вектором; навчіть співробітників пересилати підозрілі вкладення до IR.

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
