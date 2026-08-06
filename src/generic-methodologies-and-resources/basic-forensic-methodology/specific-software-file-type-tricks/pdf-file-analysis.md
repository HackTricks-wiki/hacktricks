# Аналіз PDF-файлів

{{#include ../../../banners/hacktricks-training.md}}

**Докладнішу інформацію дивіться:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Формат PDF відомий своєю складністю та можливістю приховувати дані, що робить його важливим об'єктом CTF forensic challenges. Він поєднує елементи звичайного тексту з бінарними об'єктами, які можуть бути стиснутими або зашифрованими, а також може містити скрипти такими мовами, як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна звернутися до [вступних матеріалів](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didier Stevens або скористатися такими інструментами, як текстовий редактор чи спеціалізований редактор PDF, наприклад Origami.

Для детального дослідження або модифікації PDF доступні такі інструменти, як [qpdf](https://github.com/qpdf/qpdf) і [Origami](https://github.com/mobmewireless/origami-pdf). Приховані дані в PDF можуть міститися в:

- Невидимих шарах
- Форматі XMP metadata від Adobe
- Incremental generations
- Тексті, колір якого збігається з кольором фону
- Тексті за зображеннями або зображеннях, що накладаються одне на одне
- Коментарях, які не відображаються

Для спеціалізованого аналізу PDF можна використовувати Python-бібліотеки, як-от [PeepDF](https://github.com/jesparza/peepdf), щоб створювати власні parsing scripts. Крім того, потенціал PDF для приховування даних настільки великий, що навіть такі ресурси, як посібник NSA щодо ризиків PDF і контрзаходів, хоча він більше не розміщений за оригінальним посиланням, досі містять цінну інформацію. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) і збірка [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Ange Albertini можуть бути корисними для подальшого ознайомлення з темою.

## Поширені шкідливі конструкції

Зловмисники часто зловживають певними PDF-об'єктами та діями, які автоматично виконуються під час відкриття документа або взаємодії з ним. Варто шукати такі ключові слова:

* **/OpenAction, /AA** – автоматичні дії, що виконуються під час відкриття або настання певних подій.
* **/JS, /JavaScript** – вбудований JavaScript (часто обфускований або розділений між об'єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – засоби запуску зовнішніх процесів / URL.
* **/RichMedia, /Flash, /3D** – мультимедійні об'єкти, у яких можуть приховуватися payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – object streams або forms, які часто використовують для приховування shell-code.
* **Incremental updates** – кілька маркерів %%EOF або дуже велике значення зміщення **/Prev** можуть вказувати на дані, додані після підписання для обходу AV.

Якщо будь-які з наведених вище токенів зустрічаються разом із підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF потребує глибшого аналізу.

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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – Go-бібліотека/CLI, здатна виконувати *lint*, *decrypt*, *extract*, *compress* і *sanitize* PDF-файлів.
* **pdf-inspector** – візуалізатор на основі браузера, який відображає граф об'єктів і streams.
* **PyMuPDF (fitz)** – скриптовий Python-рушій, що може безпечно рендерити сторінки в зображення для детонації вбудованого JS у hardened sandbox.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC виявила threat actors, які додавали MHT-based Word document з VBA macros після фінального **%%EOF**, створюючи файл, що одночасно є коректним PDF і коректним DOC. AV engines, які аналізують лише PDF layer, пропускають macro. Static PDF keywords не виявляються, але `file` все одно виводить `%PDF`. Вважайте будь-який PDF, який також містить string `<w:WordDocument>`, highly suspicious.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries зловживають функцією incremental update, щоб вставити другий **/Catalog** зі шкідливим `/OpenAction`, залишаючи benign first revision підписаною. Tools, які перевіряють лише першу xref table, обходяться.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – уразлива функція **CoolType.dll** може бути викликана через embedded CIDType2 fonts, що дає змогу виконати remote code execution із привілеями користувача після відкриття crafted document. Виправлено в APSB24-29 у травні 2024 року.<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **Швидко встановлюйте патчі** – підтримуйте Acrobat/Reader на найновішій гілці Continuous; більшість ланцюжків RCE, зафіксованих у wild, використовують n-day вразливості, виправлені кілька місяців тому.
2. **Видаляйте активний контент на шлюзі** – використовуйте `pdfcpu sanitize` або `qpdf --qdf --remove-unreferenced`, щоб видаляти JavaScript, вбудовані файли та launch actions із вхідних PDF.
3. **Content Disarm & Reconstruction (CDR)** – конвертуйте PDF у зображення (або PDF/A) на sandbox-хості, щоб зберегти візуальну точність і водночас відкинути активні об'єкти.
4. **Блокуйте рідко використовувані функції** – корпоративні налаштування “Enhanced Security” у Reader дають змогу вимкнути JavaScript, мультимедіа та 3D-рендеринг.
5. **Навчайте користувачів** – social engineering (приманки з рахунками та резюме) залишається початковим вектором; навчіть співробітників пересилати підозрілі вкладення до IR.

## References

- [1] [Польовий довідник Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – обхід виявлення шляхом вбудовування шкідливого файлу Word у PDF-файл](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Бюлетень безпеки Adobe – доступне оновлення безпеки для Adobe Acrobat і Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
