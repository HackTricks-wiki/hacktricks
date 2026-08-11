# Трюки з PNG

{{#include ../../../banners/hacktricks-training.md}}

**PNG-файли** дуже поширені в **CTFs**, **реагуванні на інциденти** та **стадіюванні шкідливого ПЗ**, оскільки вони є **безвтратними**, **на основі чанків**, і багато інструментів охоче відображають їх, навіть якщо вони містять **додаткові метадані**, **дописані payloads** або **частково пошкоджені чанки**.

Розглядайте PNG як **контейнер**, а не лише як зображення.

## Швидкий первинний аналіз

Почніть із перевірок на рівні контейнера, перш ніж переходити до LSB stego. Щоб ознайомитися з робочим процесом для бітових площин/LSB, перегляньте [спеціальну сторінку про stego зображень](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Корисні речі, на які варто звернути увагу:

- **Неочікувані допоміжні chunks**, такі як `tEXt`, `zTXt`, `iTXt`, `eXIf` або `iCCP`
- **Помилки CRC** або некоректні довжини chunks
- **Додаткові дані після `IEND`**
- **Кілька маркерів `IEND`** або фрагменти `IDAT`, які можна відновити, після формального завершення файлу
- Файл, який є коректним PNG **і водночас під час carving виглядає як ZIP/PDF/script**

Пам’ятайте, що мінімальна коректна структура зазвичай така:

- `IHDR` (має бути першим)
- `IDAT` (один або більше послідовних chunks)
- `IEND` (має бути останнім)

## Дані після `IEND`

Одним із найпоказовіших артефактів PNG є **дані, додані після фінального chunk `IEND`**. Багато декодерів їх ігнорують, що робить їх корисними для:

- **Простого stego / прихованих payloads**
- **PNG polyglots**
- **Malware staging**
- **Відновлення старіших даних зображення** після роботи баггі-редакторів

Швидке виявлення:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Якщо потрібно вирізати все після останнього `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Також спробуйте безпосередньо застосувати загальні парсери архівів до PNG або витягнутого трейлера:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Відновлення обрізаних/заретушованих скриншотів у стилі Acropalypse

Дуже практичний сучасний PNG-форензичний прийом — перевірити, чи редактор скриншотів **перезаписав** PNG, не **обрізавши** спочатку старий файл. У таких випадках байти з **попереднього зображення** можуть залишитися після `IEND`, а іноді додаткові дані `IDAT` можна частково відновити.

Це стало широко відомо завдяки **aCropalypse** (Google Pixel Markup) і пов’язаній із ним проблемі **Windows Snipping Tool**.<sup>[[3]](#references)</sup> На практиці, якщо "обрізаний" або "заретушований" PNG усе ще містить старі кінцеві дані, можна відновити частину оригінального скриншота.<sup>[[1]](#references)</sup>

Практичний робочий процес:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ознаки, які вагомо виправдовують глибший аналіз:

- `pngcheck` повідомляє про **додаткові дані після `IEND`**
- Ви знаходите **більше одного `IEND`**
- Ви знаходите **додаткові чанки `IDAT`** після уявного кінця зображення
- Скріншот було створено на пристрої або в редакторі, які, як відомо, зазнавали впливу

Якщо це сталося, перед тим як вважати редагування надійним, обробіть файл за допомогою **aCropalypse recovery tool**.

## Зловживання чанками, яке має практичне значення

Найцікавішими PNG-чанками для розслідувань зазвичай є не очевидні чанки зображення, а чанки, які можуть містити **текст**, **метадані** або **байти payload**:

- `tEXt` / `zTXt` / `iTXt` – текстові метадані та стиснений текст
- `eXIf` – EXIF-дані всередині PNG
- `iCCP` – вбудований ICC-профіль
- `PLTE` – дані палітри в індексованих зображеннях, але також корисні у сценаріях приховування payload.<sup>[[2]](#references)</sup>

Виведіть їх за допомогою:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Для persistence offensive payloads усередині PNG chunks (наприклад, tricks із **PLTE**, **IDAT** або **tEXt**, які зберігаються після деяких PHP image transformations), перегляньте докладніші upload-focused нотатки тут:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Відновлення пошкоджених PNG

Для перевірки цілісності та визначення точної пошкодженої ділянки **pngcheck** залишається одним із найкращих інструментів для першої перевірки:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Якщо файл пошкоджено, а не навмисно створено як malicious, **PCRT** може бути корисним у CTF і лабораторній роботі для виправлення поширених проблем, таких як неправильні заголовки, некоректні значення IHDR, проблеми з CRC або неправильно сформовані структури chunks.

Якщо ваша мета — **санітизувати** PNG, який містить підозрілі trailer data, зберігши видиме зображення, ExifTool може явно видалити trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Для конфіденційних доказів завжди працюйте з **копією** та зберігайте хеші оригіналу перед спробою відновлення.

## References

- [1] [Експлуатація aCropalypse: відновлення обрізаних PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Постійні PHP payloads у PNG: як вставити PHP-код у зображення — і зберегти його там](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
