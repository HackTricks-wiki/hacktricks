# Трюки з PNG

{{#include ../../../banners/hacktricks-training.md}}

**Файли PNG** дуже поширені в **CTF**, **реагуванні на інциденти** та **підготовці malware**, оскільки вони є **безвтратними**, **основаними на чанках**, і багато інструментів без проблем відображають їх, навіть якщо вони містять **додаткові метадані**, **дописані payload-и** або **частково пошкоджені чанки**.

Розглядайте PNG як **контейнер**, а не просто як зображення.

## Швидке первинне дослідження

Перш ніж переходити до LSB stego, почніть із перевірок на рівні контейнера. Щоб ознайомитися з робочим процесом для бітових площин/LSB, перегляньте [спеціальну сторінку про stego у зображеннях](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Корисні речі, на які варто звернути увагу:

- **Неочікувані ancillary chunks**, такі як `tEXt`, `zTXt`, `iTXt`, `eXIf` або `iCCP`
- **CRC errors** або некоректні довжини chunks
- **Додаткові дані після `IEND`**
- **Кілька маркерів `IEND`** або відновлювані фрагменти `IDAT` після формального завершення файлу
- Файл, який є валідним PNG **і** водночас під час carving виглядає як ZIP/PDF/script

Пам’ятайте, що мінімальна валідна структура зазвичай має такий вигляд:

- `IHDR` (має бути першим)
- `IDAT` (один або більше послідовних chunks)
- `IEND` (має бути останнім)

## Trailing data after `IEND`

Одним із найпомітніших PNG артефактів є **дані, додані після фінального chunk `IEND`**. Багато декодерів їх ігнорують, що робить це корисним для:

- **Simple stego / прихованих payloads**
- **PNG polyglots**
- **Malware staging**
- **Відновлення старих даних зображення** після роботи помилкових редакторів

Швидке виявлення:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Якщо потрібно витягти все після останнього `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Також спробуйте безпосередньо застосувати універсальні парсери архівів до PNG або витягнутого трейлера:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style відновлення обрізаних/замаскованих скриншотів

Дуже практичний нещодавній PNG forensic trick — перевірити, чи редактор скриншотів **перезаписав** PNG, не **обрізавши** спочатку старий файл. У таких випадках байти з **попереднього зображення** можуть залишитися після `IEND`, а іноді додаткові дані `IDAT` можна частково відновити.

Це стало добре відомо завдяки **aCropalypse** (Google Pixel Markup) і пов’язаній із ним проблемі **Windows Snipping Tool**. На практиці, якщо "обрізаний" або "замаскований" PNG усе ще містить старі кінцеві дані, може бути можливо відновити частину оригінального скриншота.<sup>[[1]](#references)</sup>

Практичний workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Ознаки, які переконливо виправдовують глибший аналіз:

- `pngcheck` повідомляє про **додаткові дані після `IEND`**
- Ви знаходите **більше одного `IEND`**
- Ви знаходите **додаткові блоки `IDAT`** після очевидного завершення зображення
- Знімок екрана було створено на пристрої або в редакторі, які, як відомо, зазнавали впливу

Якщо це сталося, перед тим як вважати редагування надійним, обробіть файл за допомогою **aCropalypse recovery tool**.

## Зловживання блоками, яке має практичне значення

Найцікавішими PNG-блоками під час розслідувань зазвичай є не очевидні блоки зображення, а блоки, які можуть містити **текст**, **метадані** або **байти payload**:

- `tEXt` / `zTXt` / `iTXt` – текстові метадані та стиснений текст
- `eXIf` – дані EXIF усередині PNG
- `iCCP` – вбудований профіль ICC
- `PLTE` – дані палітри в індексованих зображеннях, але також корисні у сценаріях приховування payload<sup>[[2]](#references)</sup>

Витягніть їх за допомогою:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Для offensive payload persistence всередині PNG chunks (наприклад, tricks із **PLTE**, **IDAT** або **tEXt**, які зберігаються після деяких PHP image transformations) перегляньте докладніші upload-focused notes тут<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Відновлення пошкоджених PNG

Для перевірки цілісності та визначення точної пошкодженої області **pngcheck** залишається одним із найкращих перших інструментів:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Якщо файл пошкоджений, а не навмисно зловмисний, **PCRT** може бути корисним у CTF і лабораторній роботі для виправлення поширених проблем, таких як неправильні заголовки, хибні значення IHDR, проблеми CRC або некоректна структура chunks.

Якщо ваша мета — **санітизувати** PNG, що містить підозрілі trailer data, зберігши видиме зображення, ExifTool може явно видалити trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Для чутливих доказів завжди працюйте з **копією** та зберігайте хеші оригіналу перед спробою відновлення.

## Посилання

- [1] [Експлуатація aCropalypse: відновлення обрізаних PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Постійні PHP payloads у PNG: як вставити PHP-код у зображення — і зберегти його там](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
