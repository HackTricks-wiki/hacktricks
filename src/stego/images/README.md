# Стеганографія зображень

{{#include ../../banners/hacktricks-training.md}}

Більшість CTF-стеганографії зображень зводиться до однієї з цих категорій:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Швидка діагностика

Надавайте пріоритет доказам на рівні контейнера перед глибоким аналізом вмісту:

- Перевірте файл і проінспектуйте структуру: `file`, `magick identify -verbose`, форматні валідатори (наприклад, `pngcheck`).
- Витягніть метадані та видимі рядки: `exiftool -a -u -g1`, `strings`.
- Перевірте на вбудований/доданий в кінець вміст: `binwalk` та інспекція кінця файлу (`tail | xxd`).
- Розгалужуйте підхід за типом контейнера:
- PNG/BMP: bit-planes/LSB та аномалії на рівні чанків.
- JPEG: метадані + інструменти DCT-domain (OutGuess/F5-style families).
- GIF/APNG: витягнення кадрів, віднімання кадрів, трюки з палітрою.

## Bit-planes / LSB

### Техніка

PNG/BMP популярні в CTF, бо вони зберігають пікселі так, що **маніпулювання на бітовому рівні** стає простим. Класичний механізм схову/витягання:

- Кожен канал пікселя (R/G/B/A) має кілька бітів.
- **найменш значущий біт** (LSB) кожного каналу майже не змінює зображення.
- Зловмисники ховають дані в цих молодших бітах, іноді з кроком (stride), перестановкою або вибором по каналу.

Чого очікувати в задачах:

- Payload знаходиться тільки в одному каналі (наприклад, `R` LSB).
- Payload знаходиться в alpha-каналі.
- Payload стискається/кодується після витягання.
- Повідомлення розподілене між площинами або приховане через XOR між площинами.

Інші варіанти, що можуть зустрітися (залежить від реалізації):

- **LSB matching** (не просто інвертування біта, а корекції +/-1, щоб відповідати цільовому біту)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Інструменти

#### zsteg

`zsteg` перелічує багато шаблонів вилучення LSB/bit-plane для PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: запускає набір трансформацій (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, перевірка площин, XOR тощо).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT — це не витяг LSB; його використовують у випадках, коли вміст навмисно прихований у частотній області або в тонких візерунках.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Метод

PNG — це формат із чанками. У багатьох задачах payload зберігається на рівні контейнера/чанку, а не в значеннях пікселів:

- **Зайві байти після `IEND`** (багато переглядачів ігнорують кінцеві байти)
- **Нестандартні допоміжні чанки**, які несуть payload
- **Пошкоджені заголовки**, що приховують розміри або ламають парсери, поки їх не виправлено

Ключові місця чанків для перевірки:

- `tEXt` / `iTXt` / `zTXt` (текстові метадані, іноді стиснуті)
- `iCCP` (ICC profile) та інші допоміжні чанки, які використовуються як носій
- `eXIf` (EXIF-дані у PNG)

### Команди триажу
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
На що звертати увагу:

- Незвичні комбінації width/height/bit-depth/colour-type
- CRC/chunk помилки (pngcheck зазвичай вказує на точний зсув)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд чанків:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Корисні посилання:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- Трюки з форматом файлів (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools та обмеження ELA

### Техніка

JPEG не зберігається як raw pixels; він стискається в DCT domain. Ось чому JPEG stego tools відрізняються від PNG LSB tools:

- Metadata/comment payloads — file-level (high-signal і швидко переглядаються)
- DCT-domain stego tools вбудовують біти у частотні коефіцієнти

З операційної точки зору, розглядайте JPEG як:

- Контейнер для metadata segments (high-signal, швидко переглядаються)
- Стиснений сигнальний домен (DCT coefficients), де працюють спеціалізовані stego tools

### Швидкі перевірки
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Місця з високою ймовірністю прихованих даних:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- APP-сегменти (`APP1` for EXIF, `APPn` for vendor data)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви маєте справу зі steghide payloads у JPEGs, розгляньте використання `stegseek` (швидший bruteforce ніж старі скрипти):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA підкреслює різні артефакти повторної компресії; це може вказати на області, які були відредаговані, але саме по собі не є stego-детектором:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Анімовані зображення

### Техніка

Для анімованих зображень припускайте, що повідомлення знаходиться:

- У одному кадрі (легко), або
- Розподілене по кадрах (важлива послідовність), або
- Видно лише при виконанні diff між послідовними кадрами

### Витяг кадрів
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Потім обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (швидке витягання кадрів)
- `imagemagick`/`magick` для перетворення кожного кадру

Frame differencing часто буває вирішальним:
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
I don't have access to the repo. Please paste the contents of src/stego/images/README.md (or the specific "StegCracker" section) you want translated to Ukrainian.
```bash
stegcracker file.jpg wordlist.txt
```
Репозиторій: https://github.com/Paradoxis/StegCracker

### stegpy

Підтримує PNG/BMP/GIF/WebP/WAV.

Репозиторій: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
