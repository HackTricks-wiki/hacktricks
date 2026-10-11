# Аналіз PDF-файлів

{{#include ../../../banners/hacktricks-training.md}}

**Докладніше див.:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Формат PDF відомий своєю складністю та здатністю приховувати дані, тому він часто стає об’єктом завдань із форензики на CTF. У ньому поєднуються текстові елементи та бінарні об’єкти, які можуть бути стиснутими або зашифрованими, а також можуть міститися скрипти такими мовами, як JavaScript або Flash. Щоб зрозуміти структуру PDF, можна ознайомитися з [вступними матеріалами](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Дідьє Стівенса або скористатися текстовим редактором чи спеціалізованим редактором PDF, наприклад Origami.

Для глибокого аналізу PDF або маніпуляцій із ним доступні такі інструменти, як [qpdf](https://github.com/qpdf/qpdf) і [Origami](https://github.com/mobmewireless/origami-pdf). У PDF приховані дані можуть міститися в:

- Невидимих шарах
- Форматі метаданих XMP від Adobe
- Інкрементальних поколіннях
- Тексті того самого кольору, що й тло
- Тексті за зображеннями або зображеннях, що накладаються одне на одне
- Коментарях, які не відображаються

Для спеціального аналізу PDF можна використовувати бібліотеки Python, як-от [PeepDF](https://github.com/jesparza/peepdf), щоб створювати власні скрипти для парсингу. Крім того, можливості PDF для приховування даних настільки широкі, що навіть посібник NSA про ризики PDF і контрзаходи, який більше не розміщено за початковою адресою, досі містить цінні відомості. З додатковими матеріалами можна ознайомитися в [копії посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) та збірці [хитрощів із форматом PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) від Анжа Альбертіні.<sup>[[4]](#references)[[5]](#references)</sup>

## Поширені шкідливі конструкції

Зловмисники часто використовують певні об’єкти та дії PDF, які виконуються автоматично під час відкриття документа або взаємодії з ним. Варто шукати такі ключові слова:

* **/OpenAction, /AA** – автоматичні дії, що виконуються під час відкриття або за певних подій.
* **/JS, /JavaScript** – вбудований JavaScript (часто обфускований або розділений між об’єктами).
* **/Launch, /SubmitForm, /URI, /GoToE** – засоби запуску зовнішніх процесів або URL-адрес.
* **/RichMedia, /Flash, /3D** – мультимедійні об’єкти, у яких можуть приховуватися payload-и.
* **/EmbeddedFile /Filespec** – вкладені файли (EXE, DLL, OLE тощо).
* **/ObjStm, /XFA, /AcroForm** – потоки об’єктів або форми, які часто використовують для приховування shell-code.
* **Інкрементальні оновлення** – кілька маркерів %%EOF або дуже велике зміщення **/Prev** можуть вказувати на дані, додані після підписання, щоб обійти AV.

Якщо будь-які з наведених вище токенів трапляються разом із підозрілими рядками (powershell, cmd.exe, calc.exe, base64 тощо), PDF потребує глибшого аналізу.

---

## Шпаргалка зі статичного аналізу

У прикладах нижче використовуються задокументовані інтерфейси командного рядка `pdf-parser.py`, qpdf і pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Пікселізація зображення всередині PDF не видаляє пікселі, що лежать під ним. Якщо в документі, який можна прочитати, таким способом, схоже, приховано облікові дані, витягніть вбудоване зображення для авторизованого офлайн-аналізу; результат залежить від зображення та наявності відповідного еталона, а відновлення візуального вмісту не гарантоване. Відновлений пароль усе одно потрібно окремо перевірити для облікового запису, чиї привілеї мають значення. Не включайте витягування PDF чи відновлення зображень до стандартного сканування хостів.

Інші корисні проєкти (активно підтримуються у 2023–2025 роках):
* **pdfcpu** – бібліотека/CLI на Go для перевірки, розшифрування, витягування, оптимізації та обробки PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – браузерний візуалізатор, який відображає граф об’єктів і потоки.
* **PyMuPDF** – прив’язки Python зі скриптовим керуванням для перевірки PDF і рендерингу сторінок у растрові зображення. Вважайте парсер/рендерер поверхнею атаки, пов’язаною з недовіреними файлами, і запускайте його у відповідно ізольованому середовищі аналізу.<sup>[[8]](#references)</sup>

---

## Новітні методи атак (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC повідомила про метод, за якого створений у Word файл MHT із макросами VBA додається до PDF, зберігаючи сигнатуру PDF і водночас відкриваючись у Word. Інструменти аналізу лише PDF, пісочниці чи антивірус можуть не виявити макрос, оскільки шкідлива поведінка проявляється під час відкриття у Word; шукайте маркер `<w:WordDocument>` разом з іншими ознаками MHT.<sup>[[2]](#references)</sup>
* **Атаки Shadow на підписані PDF** – зловмисники можуть розмістити в PDF прихований вміст до його підписання, а потім додати інкрементальне оновлення, яке змінює посилання на каталог або об’єкти, щоб переглядачі показували прихований вміст, тоді як початковий підпис залишається чинним. Метод може обходити переглядачі, які класифікують такі оновлення як нешкідливі.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe оцінює цю критичну вразливість як use-after-free, що може призвести до довільного виконання коду; APSB24-29 опубліковано 14 травня 2024 року.<sup>[[3]](#references)</sup>

---

## Шаблон простого правила YARA

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

## Поради із захисту

1. **Швидко встановлюйте оновлення** – використовуйте найновішу Continuous-версію Acrobat/Reader; більшість ланцюжків RCE, виявлених у дикій природі, використовують n-day вразливості, виправлені кілька місяців тому.
2. **Видаляйте активний вміст на шлюзі** – використовуйте спеціалізований санітайзер із керуванням політиками або продукт CDR, який явно видаляє JavaScript, вбудовані файли, дії запуску, форми та мультимедіа. `qpdf --qdf` полегшує перевірку об’єктів PDF, а pdfcpu надає функції перевірки та обробки; жодна з цих команд сама по собі не є доказом видалення активного вмісту.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – перетворюйте PDF на зображення (або PDF/A) на хості sandbox, щоб зберегти візуальну точність, відкинувши активні об’єкти.
4. **Блокуйте функції, що рідко використовуються** – налаштування “Enhanced Security” у Reader для підприємств дають змогу вимкнути JavaScript, мультимедіа та 3D-візуалізацію.
5. **Навчайте користувачів** – social engineering (приманки у вигляді рахунків і резюме) залишається початковим вектором; навчіть співробітників пересилати підозрілі вкладення до IR.

## References

- [1] [Довідник з форензики для CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – обхід виявлення шляхом вбудовування шкідливого файла Word у PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Бюлетень безпеки Adobe – доступне оновлення безпеки для Adobe Acrobat і Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu — копія посібника](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs — хитрощі з форматом PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Атаки Shadow: приховування та заміна вмісту в підписаних PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Посібник PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Параметри командного рядка qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
