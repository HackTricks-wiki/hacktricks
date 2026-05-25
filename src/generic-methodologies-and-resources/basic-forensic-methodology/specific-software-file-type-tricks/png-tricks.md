# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** дуже поширені в **CTFs**, **incident response**, and **malware staging** because they are **lossless**, **chunk-based**, and many tools will happily render them even when they contain **extra metadata**, **appended payloads**, or **partially corrupted chunks**.

Treat a PNG as a **container**, not just as an image.

## Quick triage

Start with container-level checks before jumping into LSB stego. For the bit-plane/LSB workflow, check [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Корисні речі, на які варто звернути увагу:

- **Unexpected ancillary chunks** такі як `tEXt`, `zTXt`, `iTXt`, `eXIf` або `iCCP`
- **CRC errors** або некоректні довжини chunk
- **Додаткові дані після `IEND`**
- **Кілька маркерів `IEND`** або відновлювані фрагменти `IDAT` після формального кінця файла
- Файл, який є валідним PNG **і** також виглядає як ZIP/PDF/script при carving

Пам’ятайте, що мінімальна валідна структура зазвичай така:

- `IHDR` (має бути першим)
- `IDAT` (один або кілька послідовних chunk)
- `IEND` (має бути останнім)

## Trailing data after `IEND`

Одним із найінформативніших PNG artefacts є **дані, додані після фінального chunk `IEND`**. Багато декодерів їх ігнорують, що робить це корисним для:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** з buggy editors

Швидке виявлення:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Якщо ви хочете вирізати все після фінального `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Також спробуйте generic archive parsers напряму проти PNG або carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Відновлення cropped/redacted screenshots у стилі Acropalypse

Дуже практичний нещодавній PNG forensic trick — перевіряти, чи screenshot editor **перезаписав** PNG без **truncating** старого файлу спочатку. У таких випадках bytes з **previous image** можуть залишатися після `IEND`, а інколи додаткові `IDAT` дані можна частково відновити.

Це стало широко відомо завдяки **aCropalypse** (Google Pixel Markup) і пов’язаній проблемі **Windows Snipping Tool**. На практиці, якщо "cropped" або "redacted" PNG все ще містить старі trailing data, ви можете відновити частину original screenshot.

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ознаки, які сильно виправдовують глибший аналіз:

- `pngcheck` повідомляє про **додаткові дані після `IEND`**
- Ви знаходите **більше ніж один `IEND`**
- Ви знаходите **додаткові `IDAT` chunks** після видимого кінця зображення
- Скріншот походить із пристрою/редактора, про який відомо, що він був уражений

Якщо це стається, пропустіть файл через **aCropalypse recovery tool** перед тим, як вважати редагування надійним.

## Chunk abuse that matters in practice

Найцікавіші PNG chunks для розслідувань зазвичай не очевидні image ones, а chunks, які можуть містити **text**, **metadata** або **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata and compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, but also useful in payload-smuggling scenarios

Витягніть їх за допомогою:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Для offensive payload persistence всередині PNG chunks (наприклад **PLTE**, **IDAT** або **tEXt** tricks, що переживають деякі PHP image transformations), дивіться більш детальні upload-focused notes тут:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Для перевірки integrity і знаходження точної пошкодженої ділянки, **pngcheck** залишається одним із найкращих first tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Якщо file пошкоджений, а не intentionally malicious, **PCRT** може бути корисним у CTFs і lab work для виправлення common issues, таких як bad headers, wrong IHDR values, CRC problems або malformed chunk layouts.

Якщо ваша мета — **sanitize** PNG, що містить suspicious trailer data, зберігши visible image, ExifTool може explicitly remove the trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Для чутливих доказів завжди працюй із **копією** та зберігай hashes оригіналу перед спробами відновлення.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
