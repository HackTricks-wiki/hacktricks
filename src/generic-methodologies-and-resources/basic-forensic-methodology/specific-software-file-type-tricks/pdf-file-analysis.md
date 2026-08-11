# Аналіз PDF-файлів

{{#include ../../../banners/hacktricks-training.md}}

**Докладнішу інформацію дивіться:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Формат PDF відомий своєю складністю та потенціалом для приховування даних, що робить його важливим об’єктом у forensic challenges CTF. Він поєднує елементи звичайного тексту з бінарними об’єктами, які можуть бути стиснутими або зашифрованими, а також може містити скрипти такими мовами, як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна ознайомитися з [вступними матеріалами](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didier Stevens або використовувати такі інструменти, як текстовий редактор чи спеціалізований редактор PDF, наприклад Origami.

Для детального дослідження або обробки PDF доступні такі інструменти, як [qpdf](https://github.com/qpdf/qpdf) та [Origami](https://github.com/mobmewireless/origami-pdf). Приховані дані в PDF можуть бути заховані в:

- Невидимих шарах
- Форматі XMP metadata від Adobe
- Інкрементальних поколіннях
- Тексті такого самого кольору, як і фон
- Тексті за зображеннями або зображеннях, що накладаються одне на одне
- Коментарях, які не відображаються

Для спеціального аналізу PDF можна використовувати Python-бібліотеки, наприклад [PeepDF](https://github.com/jesparza/peepdf), щоб створювати власні parsing scripts. Крім того, потенціал PDF для зберігання прихованих даних настільки великий, що навіть посібник NSA щодо ризиків PDF і countermeasures, хоча він більше не розміщений у своєму початковому місці, досі містить цінну інформацію. [Копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) та добірка [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Ange Albertini можуть бути корисними для подальшого вивчення цієї теми.<sup>[[4]](#references)[[5]](#references)</sup>

## Поширені шкідливі конструкції

Attackers часто зловживають певними PDF-об’єктами та діями, які автоматично виконуються під час відкриття документа або взаємодії з ним. Варто шукати такі ключові слова:

* **/OpenAction, /AA** – automatic actions, що виконуються під час відкриття або за певних подій.
* **/JS, /JavaScript** – вбудований JavaScript (часто obfuscated або розділений між кількома об’єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – засоби запуску зовнішніх процесів або URL.
* **/RichMedia, /Flash, /3D** – мультимедійні об’єкти, які можуть приховувати payloads.
* **/EmbeddedFile /Filespec** – файлові вкладення (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – object streams або форми, якими часто зловживають для приховування shell-code.
* **Incremental updates** – кілька маркерів %%EOF або дуже велике значення зміщення **/Prev** можуть вказувати на дані, додані після підписання для обходу AV.

Якщо будь-які з наведених вище токенів зустрічаються разом із підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF потребує глибшого аналізу.

---

## Пам’ятка зі static analysis

У наведених нижче прикладах використовуються задокументовані інтерфейси командного рядка `pdf-parser.py`, qpdf та pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
* **pdfcpu** – бібліотека/CLI на Go, здатні перевіряти, розшифровувати, витягувати, оптимізувати та обробляти PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – візуалізатор на основі браузера, який відтворює граф об’єктів і потоки.
* **PyMuPDF** – скриптові Python bindings для перевірки PDF і рендерингу сторінок у растрові зображення. Розглядайте parser/renderer як attack surface для файлів, яким не слід довіряти, і запускайте його у відповідно ізольованому середовищі аналізу.<sup>[[8]](#references)</sup>

---

## Останні attack techniques (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC повідомила про техніку, яка додає до PDF створений у Word MHT-файл із VBA-макросами, зберігаючи PDF magic і водночас забезпечуючи відкриття у Word. Інструменти аналізу лише PDF, sandboxes або antivirus можуть не виявити макрос, оскільки шкідлива поведінка виникає під час відкриття у Word; шукайте маркер `<w:WordDocument>` разом з іншими індикаторами MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers можуть розмістити прихований вміст у PDF до його підписання, а потім додати incremental update, який змінює посилання на catalog або object, щоб viewers відображали прихований вміст, тоді як оригінальний підпис залишається дійсним. Техніка може обходити viewers, які класифікують такі оновлення як нешкідливі.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe оцінює цю критичну вразливість як use-after-free, що може призвести до довільного виконання коду; APSB24-29 було опубліковано 14 травня 2024 року.<sup>[[3]](#references)</sup>

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

## Поради щодо захисту

1. **Швидко встановлюйте патчі** – підтримуйте Acrobat/Reader на найновішій гілці Continuous; більшість RCE-ланцюжків, виявлених у wild, використовують n-day vulnerabilities, виправлені кілька місяців тому.
2. **Видаляйте active content на шлюзі** – використовуйте спеціалізований sanitizer або CDR-продукт із керуванням політиками, який явно видаляє JavaScript, вбудовані файли, launch actions, форми та мультимедіа. `qpdf --qdf` спрощує перевірку об'єктів PDF, тоді як pdfcpu надає функції валідації та маніпуляцій; жодна з цих команд сама по собі не доводить, що active content було видалено.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – конвертуйте PDF у зображення (або PDF/A) на sandbox-хості, щоб зберегти візуальну точність і водночас відкинути активні об'єкти.
4. **Блокуйте рідко використовувані функції** – корпоративні налаштування “Enhanced Security” у Reader дають змогу вимкнути JavaScript, мультимедіа та 3D-рендеринг.
5. **Навчайте користувачів** – social engineering (приманки у вигляді рахунків і резюме) залишається початковим вектором; навчіть працівників пересилати підозрілі вкладення до IR.

## References

- [1] [Польовий довідник Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – обхід виявлення через вбудовування шкідливого Word-файлу у PDF-файл](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Бюлетень безпеки Adobe – доступне оновлення безпеки для Adobe Acrobat і Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - трюки формату PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: приховування та заміна вмісту в підписаних PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Посібник PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Параметри командного рядка qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
