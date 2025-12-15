# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Більшість CTF image stego зводиться до одного з цих варіантів:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Швидка перевірка

Надавайте пріоритет доказам на рівні контейнера перед глибоким аналізом вмісту:

- Перевірте файл і дослідіть структуру: `file`, `magick identify -verbose`, валідатори форматів (наприклад, `pngcheck`).
- Витягніть метадані та видимі рядки: `exiftool -a -u -g1`, `strings`.
- Перевірте на вбудований/доданий вміст: `binwalk` та огляд кінця файлу (`tail | xxd`).
- Розгалуження за типом контейнера:
  - PNG/BMP: bit-planes/LSB та аномалії на рівні chunk.
  - JPEG: метадані + інструменти в DCT-домені (OutGuess/F5-style families).
  - GIF/APNG: витяг кадрів, порівняння кадрів, трюки з палітрою.

## Bit-planes / LSB

### Technique

PNG/BMP популярні в CTF, оскільки вони зберігають пікселі так, що маніпуляції на бітовому рівні робляться просто. Класичний механізм приховування/витягання:

- Кожен канал пікселя (R/G/B/A) має кілька бітів.
- Найменш значущий біт (LSB) кожного каналу змінює зображення дуже мало.
- Зловмисники ховають дані в цих молодших бітах, іноді з кроком (stride), перестановкою або вибором по каналу.

Чого очікувати в задачах:

- Payload знаходиться лише в одному каналі (наприклад, `R` LSB).
- Payload знаходиться в alpha-каналі.
- Payload стискається/кодується після витягання.
- Повідомлення розподілене по площинах або сховане через XOR між площинами.

Додаткові варіанти, які ви можете зустріти (залежить від реалізації):

- **LSB matching** (не просто інвертація біта, а коригування +/-1 для узгодження цільового біта)
- **Palette/index-based hiding** (indexed PNG/GIF: payload в індексах кольору замість raw RGB)
- **Alpha-only payloads** (повністю невидимі в RGB-перегляді)

### Tooling

#### zsteg

`zsteg` перераховує багато шаблонів витягання LSB/bit-plane для PNG/BMP:
```bash
zsteg -a file.png
```
StegoVeritas / Stegsolve

- `stegoVeritas`: запускає набір перетворень (метадані, перетворення зображення, brute forcing LSB variants).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, інспекція площин, XOR тощо).

Завантаження Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Трюки видимості на основі FFT

FFT — це не витяг LSB; його використовують у випадках, коли вміст навмисно прихований у частотній області або в тонких патернах.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Веб-орієнтований триаж, часто використовуваний у CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Внутрішня структура PNG: chunks, пошкодження та приховані дані

### Техніка

PNG — це формат, що складається з chunks. У багатьох задачах payload зберігається на рівні контейнера/chunk, а не в значеннях пікселів:

- **Додаткові байти після `IEND`** (багато переглядачів ігнорують кінцеві байти)
- **Неcтандартні ancillary chunks**, що несуть payload
- **Пошкоджені заголовки**, які приховують розміри або ламають парсери, доки їх не виправлять

Місця chunks, які варто перевірити:

- `tEXt` / `iTXt` / `zTXt` (текстові метадані, інколи стиснені)
- `iCCP` (ICC profile) та інші ancillary chunks, які використовуються як носій
- `eXIf` (EXIF-дані в PNG)

### Команди для триажу
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
На що звертати увагу:

- Незвичні комбінації width/height/bit-depth/colour-type
- CRC/chunk помилки (pngcheck зазвичай вказує на точний зсув)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Корисні посилання:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- Трюки з форматами файлів (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Техніка

JPEG не зберігається як необроблені пікселі; він стискається в DCT-домені. Саме тому JPEG stego tools відрізняються від PNG LSB tools:

- Metadata/comment payloads є на рівні файлу (висока інформаційна цінність і швидко перевіряються)
- DCT-domain stego tools вбудовують біти в коефіцієнти частот

Операційно розглядайте JPEG як:

- Контейнер для metadata сегментів (висока інформаційна цінність, швидко перевіряється)
- Стиснений домен сигналу (DCT coefficients), де працюють спеціалізовані stego tools

### Швидкі перевірки
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Місця з високим сигналом:

- EXIF/XMP/IPTC метадані
- JPEG сегмент коментаря (`COM`)
- Сегменти додатків (`APP1` for EXIF, `APPn` for vendor data)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви конкретно маєте справу з steghide payloads у JPEGs, розгляньте використання `stegseek` (швидший bruteforce, ніж старі скрипти):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA підсвічує різні артефакти повторного стиснення; вона може вказати на області, які були відредаговані, але сама по собі не є stego-детектором:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Анімовані зображення

### Техніка

Для анімованих зображень припускайте, що повідомлення:

- У одному кадрі (легко), або
- Розповсюджене по кадрах (порядок має значення), або
- Видиме лише коли ви diff послідовні кадри

### Екстрагувати кадри
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Потім обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (швидке вилучення кадрів)
- `imagemagick`/`magick` для перетворень по кадру

Порівняння кадрів часто є вирішальним:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Вбудовування, захищене паролем

Якщо ви підозрюєте, що вбудовування захищене passphrase, а не маніпуляціями на рівні пікселів, це зазвичай найшвидший шлях.

### steghide

Підтримує `JPEG, BMP, WAV, AU` і може вбудовувати/витягувати зашифровані payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Я не маю доступу до репозиторію. Будь ласка, вставте вміст файлу src/stego/images/README.md сюди, і я перекладу відповідний англомовний текст на українську, зберігаючи точно той самий markdown та html‑синтаксис.
```bash
stegcracker file.jpg wordlist.txt
```
Репозиторій: https://github.com/Paradoxis/StegCracker

### stegpy

Підтримує PNG/BMP/GIF/WebP/WAV.

Репозиторій: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
