# Аналіз PDF-файлів

**Докладнішу інформацію дивіться тут:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Формат PDF відомий своєю складністю та потенціалом для приховування даних, що робить його важливим об’єктом forensic-досліджень у CTF. Він поєднує елементи звичайного тексту з бінарними об’єктами, які можуть бути стиснутими або зашифрованими, а також може містити скрипти такими мовами, як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна ознайомитися з [вступними матеріалами](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didier Stevens або використовувати такі інструменти, як текстовий редактор чи спеціалізований редактор PDF, наприклад Origami.

Для детального дослідження або модифікації PDF доступні такі інструменти, як [qpdf](https://github.com/qpdf/qpdf) і [Origami](https://github.com/mobmewireless/origami-pdf). Приховані дані в PDF можуть міститися в:

- Невидимих шарах
- Форматі XMP metadata від Adobe
- Інкрементальних поколіннях
- Тексті, колір якого збігається з кольором фону
- Тексті, розташованому за зображеннями, або зображеннях, що перекривають одне одного
- Коментарях, які не відображаються

Для спеціального аналізу PDF можна використовувати Python-бібліотеки, наприклад [PeepDF](https://github.com/jesparza/peepdf), щоб створювати власні скрипти парсингу. Крім того, потенціал PDF для приховування даних настільки великий, що такі ресурси, як посібник NSA щодо ризиків PDF і контрзаходів, хоча він більше не розміщений за початковою адресою, досі містять цінну інформацію. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) і збірка [трюків формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Ange Albertini можуть стати додатковими джерелами для вивчення цієї теми.<sup>[[4]](#references)[[5]](#references)</sup>

## Поширені шкідливі конструкції

Зловмисники часто зловживають певними об’єктами та діями PDF, які автоматично виконуються під час відкриття документа або взаємодії з ним. Варто шукати такі ключові слова:

* **/OpenAction, /AA** – автоматичні дії, що виконуються під час відкриття або певних подій.
* **/JS, /JavaScript** – вбудований JavaScript (часто обфускований або розділений між об’єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – засоби запуску зовнішніх процесів або URL.
* **/RichMedia, /Flash, /3D** – мультимедійні об’єкти, у яких можуть приховуватися payload.
* **/EmbeddedFile /Filespec** – вкладення файлів (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – потоки об’єктів або форми, якими часто зловживають для приховування shell-code.
* **Інкрементальні оновлення** – кілька маркерів %%EOF або дуже велике зміщення **/Prev** можуть вказувати на дані, додані після підписання для обходу AV.

Якщо будь-які з наведених вище токенів зустрічаються разом із підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF потребує глибшого аналізу.

---

## Шпаргалка зі статичного аналізу

У наведених нижче прикладах використовуються задокументовані інтерфейси командного рядка `pdf-parser.py`, qpdf і pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
* **pdfcpu** – Go-бібліотека/CLI, здатна перевіряти, розшифровувати, витягувати, оптимізувати та обробляти PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – візуалізатор на основі браузера, який відображає граф об’єктів і потоки.
* **PyMuPDF** – скриптові Python-прив’язки для перевірки PDF і рендерингу сторінок у растрові зображення. Вважайте parser/renderer attack surface для untrusted-файлів і запускайте його у відповідно ізольованому середовищі аналізу.<sup>[[8]](#references)</sup>

---

## Новітні attack techniques (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC повідомила про техніку, яка додає до PDF MHT-файл, створений Word, із VBA-макросами, зберігаючи PDF magic і водночас забезпечуючи відкриття у Word. Інструменти аналізу, sandbox або antivirus, орієнтовані лише на PDF, можуть пропустити макрос, оскільки malicious behavior виникає під час відкриття у Word; шукайте маркер `<w:WordDocument>` разом з іншими MHT-індикаторами.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers можуть розмістити прихований вміст у PDF до його підписання, а потім додати incremental update, який змінює посилання на catalog або object, щоб viewers відображали прихований вміст, тоді як оригінальний signature залишається чинним. Техніка може обійти viewers, які класифікують такі оновлення як harmless.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe оцінює цю critical vulnerability як use-after-free, що може призвести до arbitrary code execution; APSB24-29 було опубліковано 14 травня 2024 року.<sup>[[3]](#references)</sup>

---

## Швидкий шаблон правила YARA
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

1. **Швидко встановлюйте патчі** – підтримуйте Acrobat/Reader на найновішому Continuous track; більшість RCE-ланцюжків, що спостерігалися у wild, використовують n-day вразливості, виправлені за кілька місяців до цього.
2. **Видаляйте активний вміст на шлюзі** – використовуйте спеціалізований санітайзер або продукт CDR із контрольованою політикою, який явно видаляє JavaScript, вбудовані файли, launch actions, форми та мультимедіа. `qpdf --qdf` спрощує перевірку об'єктів PDF, тоді як pdfcpu надає функції валідації та маніпуляції; жодна з цих команд сама по собі не доводить, що активний вміст було видалено.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – конвертуйте PDF у зображення (або PDF/A) на sandbox-хості, щоб зберегти візуальну точність і водночас видалити активні об'єкти.
4. **Блокуйте рідко використовувані функції** – корпоративні налаштування “Enhanced Security” у Reader дають змогу вимкнути JavaScript, мультимедіа та 3D-рендеринг.
5. **Навчання користувачів** – соціальна інженерія (приманки з рахунками та резюме) залишається початковим вектором; навчайте співробітників пересилати підозрілі вкладення до IR.

## References

- [1] [Посібник з Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Обхід виявлення шляхом вбудовування шкідливого Word-файлу у PDF-файл](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Бюлетень безпеки Adobe – Доступне оновлення безпеки для Adobe Acrobat і Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - трюки формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: приховування та заміна вмісту в підписаних PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Посібник з PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Параметри командного рядка qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
