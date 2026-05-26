# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** дуже поширені в **CTFs**, **incident response** і **malware staging**, тому що вони **lossless**, **chunk-based**, і багато tools без проблем відображатимуть їх навіть тоді, коли вони містять **extra metadata**, **appended payloads** або **partially corrupted chunks**.

Сприймайте PNG як **container**, а не просто як image.

## Quick triage

Починайте з перевірок на рівні container перед тим, як переходити до LSB stego. Для bit-plane/LSB workflow дивіться [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Корисні речі, на які варто звернути увагу:

- **Unexpected ancillary chunks** такі як `tEXt`, `zTXt`, `iTXt`, `eXIf`, або `iCCP`
- **CRC errors** або malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** або recoverable `IDAT` fragments після formal end of the file
- Файл, який є valid PNG **і** також схожий на ZIP/PDF/script when carved

Пам’ятайте, що мінімальна valid structure зазвичай така:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

Один із PNG artefacts з найвищим signal — це **data appended after the final `IEND` chunk**. Багато decoders ігнорують його, що робить його корисним для:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** з buggy editors

Quick detection:
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
Також спробуйте generic archive parsers безпосередньо проти PNG або carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Відновлення в стилі Acropalypse зі cropped/redacted screenshots

Дуже практичний недавній PNG forensic trick — перевірити, чи screenshot editor **перезаписав** PNG без попереднього **truncating** старого файлу. У таких випадках байти з **previous image** можуть залишатися після `IEND`, а інколи додаткові `IDAT` дані можна частково відновити.

Це стало широко відомо завдяки **aCropalypse** (Google Pixel Markup) і пов’язаній проблемі **Windows Snipping Tool**. На практиці, якщо "cropped" або "redacted" PNG усе ще містить старі trailing data, ви можете відновити частину оригінального screenshot.

Практичний workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ознаки, що сильно виправдовують глибший аналіз:

- `pngcheck` повідомляє про **додаткові дані після `IEND`**
- Ви знаходите **більше ніж один `IEND`**
- Ви знаходите **зайві `IDAT` chunks** після очевидного кінця зображення
- Знімок екрана був зроблений на пристрої/в editor, про який відомо, що він був affected

Якщо це сталося, пропустіть файл через **aCropalypse recovery tool** перед тим, як вважати redaction надійним.

## Chunk abuse that matters in practice

Найцікавіші PNG chunks для investigations зазвичай не очевидні image ones, а chunks, які можуть містити **text**, **metadata** або **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata and compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, but also useful in payload-smuggling scenarios

Вивантажте їх за допомогою:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), check the more detailed upload-focused notes here:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

For checking integrity and locating the exact broken area, **pngcheck** remains one of the best first tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

If the file is damaged rather than intentionally malicious, **PCRT** can be useful in CTFs and lab work for fixing common issues such as bad headers, wrong IHDR values, CRC problems, or malformed chunk layouts.

If your goal is to **sanitize** a PNG that contains suspicious trailer data while preserving the visible image, ExifTool can explicitly remove the trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Для чутливих доказів завжди працюйте з **копією** і зберігайте хеші оригіналу перед будь-якими спробами відновлення.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
