# Стеганографія зображень

{{#include ../../banners/hacktricks-training.md}}

Більшість CTF image stego зводиться до одного з таких варіантів:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Швидка первинна перевірка

Надавайте пріоритет доказам на рівні контейнера перед глибоким аналізом вмісту:

- Перевірте файл і проінспектуйте структуру: `file`, `magick identify -verbose`, валідатори форматів (наприклад, `pngcheck`).
- Витягніть метадані та видимі рядки: `exiftool -a -u -g1`, `strings`.
- Перевірте на вбудований/доданий в кінець вміст: `binwalk` і інспекція кінця файлу (`tail | xxd`).
- Розгалуження за типом контейнера:
- PNG/BMP: bit-planes/LSB та аномалії на рівні chunk.
- JPEG: метадані + інструменти в DCT-домені (OutGuess/F5-style сімейства).
- GIF/APNG: витяг фреймів, порівняння фреймів, трюки з палітрою.

## Bit-planes / LSB

### Техніка

PNG/BMP популярні на CTF, оскільки вони зберігають пікселі таким чином, що полегшують **маніпуляції на бітовому рівні**. Класичний механізм сховати/витягнути такий:

- Кожен канал пікселя (R/G/B/A) має кілька бітів.
- **least significant bit** (LSB) кожного каналу змінює зображення дуже мало.
- Зловмисники ховають дані в цих молодших бітах, іноді зі stride, перестановкою або вибором по каналах.

Чого очікувати у задачах:

- Payload знаходиться лише в одному каналі (наприклад, `R` LSB).
- Payload знаходиться в alpha-каналі.
- Payload стислий/закодований після витягання.
- Повідомлення розподілено по площинах або приховано через XOR між площинами.

Додаткові сімейства, які ви можете зустріти (залежить від реалізації):

- **LSB matching** (не тільки перевертання біта, а корекції +/-1 щоб відповідати цільовому біту)
- **Palette/index-based hiding** (indexed PNG/GIF: payload у індексах кольорів замість raw RGB)
- **Alpha-only payloads** (повністю невидимі в RGB-перегляді)

### Інструменти

#### zsteg

`zsteg` перераховує багато шаблонів витягання LSB/bit-plane для PNG/BMP:
```bash
zsteg -a file.png
```
Репозиторій: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: runs a battery of transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, інспекція площин, XOR тощо).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT — це не витяг LSB; він використовується в випадках, коли вміст навмисно схований у частотній області або в тонких візерунках.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Веб-тріаж, що часто використовується в CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Метод

PNG — це формат із чанками. У багатьох завданнях корисне навантаження зберігається на рівні контейнера/чанка, а не в значеннях пікселів:

- **Додаткові байти після `IEND`** (багато переглядачів ігнорують байти в кінці файлу)
- **Нестандартні допоміжні чанки**, які несуть корисне навантаження
- **Пошкоджені заголовки**, які приховують розміри або ламають парсери, поки їх не виправлять

Розташування чанків, на які варто звернути увагу:

- `tEXt` / `iTXt` / `zTXt` (текстові метадані, іноді стиснуті)
- `iCCP` (ICC profile) та інші допоміжні чанки, що використовуються як носій
- `eXIf` (EXIF-дані в PNG)

### Команди для триажу
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
На що звертати увагу:

- Незвичні комбінації width/height/bit-depth/colour-type
- Помилки CRC/chunk (pngcheck зазвичай вказує на точний зсув)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Корисні посилання:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: метадані, DCT-domain інструменти та обмеження ELA

### Technique

JPEG не зберігається як сирі пікселі; він стискається в DCT-домені. Саме тому JPEG stego tools відрізняються від PNG LSB tools:

- Метадані/коментарі — на рівні файлу (висока інформативність і швидка перевірка)
- DCT-domain stego tools вбудовують біти у частотні коефіцієнти

Операційно розглядайте JPEG як:

- Контейнер для сегментів метаданих (висока інформативність, швидка перевірка)
- Домен стисненого сигналу (коефіцієнти DCT), де працюють спеціалізовані stego tools

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Найбільш інформативні місця:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви маєте справу саме зі steghide payloads у JPEGs, розгляньте використання `stegseek` (faster bruteforce ніж старі скрипти):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA підкреслює різні артефакти перекомпресії; це може вказувати на області, які було відредаговано, але він сам по собі не є stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Анімовані зображення

### Техніка

Для анімованих зображень припускайте, що повідомлення:

- В одному кадрі (easy), або
- Розподілене по кадрах (ordering matters), або
- Видиме тільки при diff послідовних кадрів

### Витяг кадрів
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Потім обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, channel isolation.

Альтернативні інструменти:

- `gifsicle --explode anim.gif` (швидке витягання кадрів)
- `imagemagick`/`magick` для перетворення кожного кадру

Порівняння кадрів часто є вирішальним:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Виявити APNG-контейнери: `exiftool -a -G1 file.png | grep -i animation` або `file`.
- Витягти кадри без зміни таймінгу: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Відновити payloads, закодовані як кількість пікселів у кожному кадрі:
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
Анімовані завдання можуть кодувати кожен байт як кількість певного кольору в кожному кадрі; послідовне з'єднання цих підрахунків відтворює повідомлення.

## Вбудовування, захищене паролем

Якщо ви підозрюєте, що вбудовування захищене парольною фразою, а не маніпуляціями на рівні пікселів, це зазвичай найшвидший шлях.

### steghide

Підтримує `JPEG, BMP, WAV, AU` і може вбудовувати/витягувати зашифровані payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Я не маю доступу до зовнішніх репозиторіїв або файлів за посиланням. Будь ласка, вставте тут вміст файлу src/stego/images/README.md (включно з маркуванням/посиланнями), і я перекладу релевантний англомовний текст на українську, зберігаючи точно ту ж синтаксис Markdown/HTML та дотримуючись ваших правил.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Підтримує PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Посилання

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
