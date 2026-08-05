# Стеганографія зображень

{{#include ../../banners/hacktricks-training.md}}

Більшість CTF із image stego зводиться до однієї з таких категорій:

- LSB/bit-planes (PNG/BMP)
- Payloads у metadata/comments
- Незвичні PNG chunks / відновлення пошкоджень
- Інструменти JPEG DCT-domain (OutGuess тощо)
- Frame-based (GIF/APNG)

## Швидке сортування

Перед глибоким аналізом вмісту визначте докази на рівні контейнера:

- Перевірте файл та дослідіть його структуру: `file`, `magick identify -verbose`, format validators (наприклад, `pngcheck`).
- Витягніть metadata та видимі strings: `exiftool -a -u -g1`, `strings`.
- Перевірте наявність embedded/appended content: `binwalk` та дані в кінці файлу (`tail | xxd`).
- Визначте тип контейнера:
- PNG/BMP: bit-planes/LSB та аномалії на рівні chunks.
- JPEG: metadata + DCT-domain tooling (сімейства на кшталт OutGuess/F5).
- GIF/APNG: витягування frames, порівняння frames, tricks із palette.

## Bit-planes / LSB

### Technique

PNG/BMP популярні в CTF, оскільки зберігають pixels у форматі, що спрощує **bit-level manipulation**. Класичний механізм приховування/витягування такий:

- Кожен pixel channel (R/G/B/A) має кілька bits.
- **Least significant bit** (LSB) кожного channel майже не змінює вигляд зображення.
- Attackers приховують дані в цих low-order bits, іноді використовуючи stride, permutation або вибір окремого channel.

Чого очікувати в challenges:

- Payload знаходиться лише в одному channel (наприклад, `R` LSB).
- Payload знаходиться в alpha channel.
- Payload після витягування є compressed/encoded.
- Message розподілено між planes або приховано за допомогою XOR між planes.

Додаткові сімейства, які можуть трапитися (залежно від implementation):

- **LSB matching** (не просто flipping bit, а коригування +/-1 для відповідності target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload у color indices, а не в raw RGB)
- **Alpha-only payloads** (повністю невидимі в RGB view)

### Tooling

#### zsteg

`zsteg` перебирає багато patterns для LSB/bit-plane extraction у PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: запускає набір transforms (метадані, image transforms, brute forcing варіантів LSB).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, перевірка площин, XOR тощо).

Завантаження Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Трюки для виявлення на основі FFT

FFT — це не LSB extraction; його використовують у випадках, коли вміст навмисно приховано у frequency space або малопомітних патернах.

- Демо EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage часто використовується в CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Внутрішня структура PNG: chunks, corruption і приховані дані

### Technique

PNG — це chunked format. У багатьох challenge payload зберігається на рівні container/chunk, а не в значеннях пікселів:

- **Додаткові байти після `IEND`** (багато переглядачів ігнорують trailing bytes)
- **Нестандартні ancillary chunks**, що містять payload
- **Пошкоджені заголовки**, які приховують dimensions або порушують роботу парсерів, доки їх не буде виправлено

High-signal місця в chunks, які варто перевірити:

- `tEXt` / `iTXt` / `zTXt` (текстові metadata, іноді стиснені)
- `iCCP` (ICC profile) та інші ancillary chunks, що використовуються як carrier
- `eXIf` (EXIF data у PNG)

### Команди для triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Що шукати:

- Дивні комбінації ширини/висоти/глибини кольору/типу кольору
- Помилки CRC/chunk (`pngcheck` зазвичай вказує точне зміщення)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Корисні посилання:

- Специфікація PNG (структура, chunks): https://www.w3.org/TR/PNG/
- Прийоми роботи з форматами файлів (нестандартні випадки PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools та обмеження ELA

### Техніка

JPEG зберігається не як необроблені пікселі; він стискається в DCT domain. Саме тому JPEG stego tools відрізняються від PNG LSB tools:

- Payloads у metadata/comments належать до рівня файлу (висока інформативність і швидка перевірка)
- DCT-domain stego tools вбудовують біти у frequency coefficients

На практиці розглядайте JPEG як:

- Контейнер для metadata segments (висока інформативність, швидка перевірка)
- Стиснений signal domain (DCT coefficients), у якому працюють спеціалізовані stego tools

### Швидкі перевірки
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Місця з високою інформативністю:

- метадані EXIF/XMP/IPTC
- сегмент коментаря JPEG (`COM`)
- сегменти застосунків (`APP1` для EXIF, `APPn` для даних vendor-а)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви спеціально працюєте зі steghide payloads у JPEG, розгляньте використання `stegseek` (швидший bruteforce, ніж у старих скриптах):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA виділяє різні артефакти повторного стиснення; це може вказати на області, які редагувалися, але сам по собі це не stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Анімовані зображення

### Техніка

Для анімованих зображень припускайте, що повідомлення:

- міститься в одному кадрі (просто), або
- розподілене між кадрами (порядок має значення), або
- видиме лише під час порівняння послідовних кадрів

### Витягування кадрів
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Тоді обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, ізоляція каналів.

Альтернативні інструменти:

- `gifsicle --explode anim.gif` (швидке вилучення кадрів)
- `imagemagick`/`magick` для перетворень окремих кадрів

Порівняння кадрів часто є вирішальним:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Кодування кількістю пікселів в APNG

- Виявлення контейнерів APNG: `exiftool -a -G1 file.png | grep -i animation` або `file`.
- Витягування кадрів без зміни таймінгу: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Відновлення payloads, закодованих кількістю пікселів у кожному кадрі:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Анімовані задачі можуть кодувати кожен байт як кількість певного кольору в кожному кадрі; об’єднання цих кількостей відновлює повідомлення.<sup>[[1]](#references)</sup>

## Вбудовування, захищене паролем

Якщо ви підозрюєте, що вбудовування захищене парольною фразою, а не маніпуляціями на рівні пікселів, це зазвичай найшвидший шлях.

### steghide

Підтримує `JPEG, BMP, WAV, AU` і може вбудовувати/витягувати зашифровані payload-и.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Репозиторій: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Репозиторій: https://github.com/Paradoxis/StegCracker

### stegpy

Підтримує PNG/BMP/GIF/WebP/WAV.

Репозиторій: https://github.com/dhsdshdhk/stegpy

## Посилання

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
