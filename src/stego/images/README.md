# Стеганографія зображень

{{#include ../../banners/hacktricks-training.md}}

Більшість CTF із image stego зводиться до однієї з таких категорій:

- LSB/bit-planes (PNG/BMP)
- Payloads у metadata/comments
- Дивні PNG chunks / відновлення пошкоджень
- Інструменти для JPEG DCT-domain (OutGuess тощо)
- Frame-based (GIF/APNG)

## Швидке первинне сортування

Пріоритезуйте evidence на рівні контейнера перед глибоким аналізом вмісту:

- Перевірте файл та дослідіть структуру: `file`, `magick identify -verbose`, format validators (наприклад, `pngcheck`).
- Витягніть metadata та видимі strings: `exiftool -a -u -g1`, `strings`.
- Перевірте наявність embedded/appended content: `binwalk` та перевірка кінця файлу (`tail | xxd`).
- Оберіть напрямок залежно від контейнера:
- PNG/BMP: bit-planes/LSB та аномалії на рівні chunks.
- JPEG: metadata + DCT-domain tooling (сімейства OutGuess/F5-style).
- GIF/APNG: витягування frames, порівняння frames, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP популярні в CTF, оскільки зберігають pixels у форматі, який спрощує **маніпуляції на рівні бітів**. Класичний механізм приховування/витягування:

- Кожен pixel channel (R/G/B/A) має кілька бітів.
- **Найменш значущий біт** (LSB) кожного channel майже не змінює зображення.
- Attackers приховують data у цих low-order bits, іноді використовуючи stride, permutation або вибір окремого channel.

Чого очікувати в challenges:

- Payload міститься лише в одному channel (наприклад, `R` LSB).
- Payload міститься в alpha channel.
- Payload після extraction стиснений/закодований.
- Message розподілено між planes або приховано за допомогою XOR між planes.

Додаткові сімейства, з якими можна зустрітися (залежно від implementation):

- **LSB matching** (не лише зміна біта, а й коригування +/-1 для відповідності target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload у color indices, а не в raw RGB)
- **Alpha-only payloads** (повністю невидимі в RGB view)

### Tooling

#### zsteg

`zsteg` перебирає багато patterns для extraction LSB/bit-plane у PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: запускає набір перетворень (метадані, перетворення зображень, brute forcing варіантів LSB).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, перевірка площин, XOR тощо).

Завантаження Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Трюки для виявлення на основі FFT

FFT не є вилученням LSB; він використовується у випадках, коли вміст навмисно приховано у частотному просторі або в малопомітних шаблонах.

- Демонстрація EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage часто використовується в CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Внутрішня будова PNG: chunks, пошкодження та приховані дані

### Техніка

PNG є форматом на основі chunks. У багатьох challenge payload зберігається на рівні контейнера/chunk, а не в значеннях пікселів:

- **Додаткові bytes після `IEND`** (багато переглядачів ігнорують bytes у кінці)
- **Нестандартні ancillary chunks**, що містять payload
- **Пошкоджені headers**, які приховують dimensions або порушують роботу parsers, доки їх не буде виправлено

Високосигнальні місця в chunks, які слід перевірити:

- `tEXt` / `iTXt` / `zTXt` (текстові metadata, іноді стиснуті)
- `iCCP` (ICC profile) та інші ancillary chunks, що використовуються як carrier
- `eXIf` (EXIF data у PNG)

### Команди для первинного аналізу
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
На що звертати увагу:

- Незвичні комбінації ширини/висоти/розрядності/типу кольору
- Помилки CRC/chunk (pngcheck зазвичай вказує точне зміщення)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Корисні посилання:

- Специфікація PNG (структура, chunks): https://www.w3.org/TR/PNG/
- Трюки з форматами файлів (нестандартні випадки PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, інструменти DCT-domain і обмеження ELA

### Методика

JPEG не зберігається як необроблені пікселі; його стиснуто в DCT-domain. Саме тому stego tools для JPEG відрізняються від LSB tools для PNG:

- Payloads metadata/comment належать до рівня файлу (високий сигнал і швидка перевірка)
- Stego tools у DCT-domain вбудовують біти у frequency coefficients

З практичної точки зору розглядайте JPEG як:

- Контейнер для metadata segments (високий сигнал, швидка перевірка)
- Стиснений signal domain (DCT coefficients), у якому працюють спеціалізовані stego tools

### Швидкі перевірки
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Високосигнальні місця:

- EXIF/XMP/IPTC metadata
- Сегмент коментаря JPEG (`COM`)
- Сегменти застосунків (`APP1` для EXIF, `APPn` для даних vendor)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви спеціально працюєте зі steghide payloads у JPEG, розгляньте використання `stegseek` (швидший bruteforce, ніж у старих скриптів):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA виділяє різні артефакти повторного стиснення; це може вказати на області, які редагувалися, але сам по собі цей метод не є stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Анімовані зображення

### Методика

Для анімованих зображень припускайте, що повідомлення:

- Міститься в одному кадрі (просто), або
- Розподілене між кадрами (порядок має значення), або
- Видиме лише під час порівняння послідовних кадрів

### Витягування кадрів
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Потім обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, ізоляція каналів.

Альтернативні інструменти:

- `gifsicle --explode anim.gif` (швидке вилучення кадрів)
- `imagemagick`/`magick` для перетворень окремих кадрів

Порівняння кадрів часто є вирішальним:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Кодування кількістю пікселів APNG

- Виявлення контейнерів APNG: `exiftool -a -G1 file.png | grep -i animation` або `file`.
- Витягування кадрів без зміни таймінгу: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Відновлення payload, закодованих як кількість пікселів у кожному кадрі:
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
Анімовані challenges можуть кодувати кожен байт як кількість пікселів певного кольору в кожному кадрі; об'єднання цих кількостей відновлює повідомлення.<sup>[[1]](#references)</sup>

## Вбудовування, захищене паролем

Якщо ви підозрюєте, що вбудовування захищене passphrase, а не маніпуляціями на рівні пікселів, це зазвичай найшвидший шлях.

### steghide

Підтримує `JPEG, BMP, WAV, AU` і може вбудовувати/видобувати зашифровані payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Репозиторій: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Підтримує PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Посилання

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
