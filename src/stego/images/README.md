# Стеганографія зображень

{{#include ../../banners/hacktricks-training.md}}

Стеганографія зображень у більшості CTF зводиться до одного з таких варіантів:

- LSB/бітові площини (PNG/BMP)
- Payload у метаданих/коментарях
- Аномалії PNG-chunk’ів / відновлення пошкоджених файлів
- Інструменти для JPEG у DCT-домені (OutGuess тощо)
- Робота з кадрами (GIF/APNG)

## Первинний аналіз

Спершу перевірте докази на рівні контейнера, а вже потім переходьте до глибокого аналізу вмісту. Дивіться [загальний workflow для стеганографії](../workflow/) щодо ідентифікації файлів і вилучення даних перед специфічними для зображень перевірками.

- Перевірте файл і дослідіть його структуру: `file`, `magick identify -verbose`, валідатори форматів (наприклад, `pngcheck`).
- Витягніть метадані та видимі рядки: `exiftool -a -u -g1`, `strings`.
- Перевірте наявність вбудованого або дописаного вмісту: `binwalk` і кінець файлу (`tail | xxd`).
- Виберіть напрям аналізу за контейнером:
  - PNG/BMP: бітові площини/LSB та аномалії на рівні chunk’ів.
  - JPEG: метадані та інструменти для DCT-домену (сімейства OutGuess/F5).
  - GIF/APNG: вилучення кадрів, порівняння кадрів, трюки з палітрою.

## Бітові площини / LSB

### Методика

PNG/BMP популярні в CTF, оскільки зберігають пікселі так, що їх легко **маніпулювати на рівні бітів**. Класичний механізм приховування/вилучення даних такий:

- Кожен канал пікселя (R/G/B/A) має кілька бітів.
- **Найменш значущий біт** (LSB) кожного каналу майже не змінює зображення.
- Зловмисники приховують дані в молодших бітах, іноді використовуючи крок, перестановку або вибір окремих каналів.

Що можна очікувати в завданнях:

- Payload міститься лише в одному каналі (наприклад, у LSB каналу `R`).
- Payload міститься в альфа-каналі.
- Після вилучення payload стиснений/закодований.
- Повідомлення розподілене між площинами або приховане за допомогою XOR між площинами.

Додаткові варіанти, які можуть трапитися (залежно від реалізації):

- **LSB matching** (не просто інвертування біта, а коригування на +/-1 для відповідності цільовому біту)
- **Приховування на основі палітри/індексів** (індексовані PNG/GIF: payload міститься в індексах кольорів, а не в необроблених RGB-значеннях)
- **Payload лише в альфа-каналі** (повністю невидимий у RGB-поданні)

### Індекси палітри з індексованими кольорами

В індексованому PNG або GIF для кожного пікселя зберігається **індекс** палітри, а не RGB-трійка. Два індекси можуть відповідати одному видимому кольору, тож перетворення в RGB перед аналізом може стерти приховану відмінність. Перевірте палітру на дублікати або майже однакові елементи, а потім створіть бінарну маску пікселів для кожного підозрілого індексу. Такий підхід допоміг виявити прихований текст і зміни QR-кодів у нещодавніх завданнях із GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Для однокадрового індексованого PNG (або **першого кадру** GIF) збережіть режим Pillow `P` і змініть `target` на цікавий індекс, указаний скриптом. Під час вибору індексів перевірте прозорість (`tRNS` або індекс прозорості GIF), а також RGB.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Для анімованих GIF переглядайте кадри окремо. Pillow зазвичай перетворює пізніші кадри на RGB/RGBA під час компонування; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` зберігає режим `P`, лише поки палітра не змінюється. Якщо кадр має локальну палітру або його вже було скомпоновано, переглядайте вихідні дані кадру з індексами, а не трактуйте пікселі, перетворені на RGB, як індекси.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Інструменти

#### zsteg

`zsteg` перебирає багато шаблонів вилучення LSB/бітових площин для PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: запускає набір перетворень (метадані, перетворення зображень, brute force варіантів LSB).
- `stegsolve`: ручні візуальні фільтри (ізоляція каналів, перегляд площин, XOR тощо).

Завантажити Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Трюки для виявлення за допомогою FFT

FFT — це не витягування LSB; цей метод використовують, коли вміст навмисно приховано в частотному просторі або малопомітних візерунках.

- Демонстрація EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Вебінструменти для первинного аналізу, які часто використовують у CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Внутрішня структура PNG: чанки, пошкодження та приховані дані

### Техніка

PNG має чанковий формат. У багатьох завданнях payload зберігається на рівні контейнера/чанків, а не в значеннях пікселів:

- **Додаткові байти після `IEND`** (багато переглядачів ігнорують кінцеві байти)
- **Нестандартні допоміжні чанки**, що містять payload; див. [обхід чанків PNG і процес карвінгу](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Пошкоджені заголовки**, які приховують розміри або порушують роботу парсерів, доки їх не виправити

Важливі місця в чанках для перевірки:

- `tEXt` / `iTXt` / `zTXt` (текстові метадані, іноді стиснені)
- `iCCP` (профіль ICC) та інші допоміжні чанки, що використовуються як носій
- `eXIf` (дані EXIF у PNG)

### Байти фільтра рядків сканування PNG як носій

PNG зберігає один байт типу фільтра (0–4) перед кожним рядком сканування в декомпресованому потоці `IDAT`. Це не значення пікселів; декодовані пікселі RGB не зберігають початковий вибір фільтрів, а повторне кодування може його змінити. Кодувальник може цілком законно змінювати фільтри, але навмисні шаблони можуть кодувати коротке повідомлення; у нещодавньому завданні значення фільтрів 1–4 використовувалися як двобітові символи. Перевіряйте **оригінальний файл** і об’єднайте дані всіх `IDAT` перед декомпресією. Для наведеного нижче випадку — неінтерлейсного зображення RGB/RGBA із глибиною 8 біт — крок дорівнює ширині, помноженій на кількість каналів; для зображень Adam7 потрібна ширина рядка сканування для кожного проходу.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Перелік байтів фільтра рядків сканування PNG без повторного кодування</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Запустіть команду `python3 filters.py suspect.png`. Перевірте, чи відповідає правдоподібному відображенню символів саме послідовність фільтрів, а не декодовані пікселі. Вибір відображення залежить від конкретного завдання; сама лише варіативність не є доказом стеганографії.<sup>[[3]](#references)[[7]](#references)</sup>

### Команди первинного аналізу

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

На що звернути увагу:

- Дивні комбінації ширини/висоти/глибини кольору/типу кольору
- Помилки CRC/чанків (pngcheck зазвичай указує точне зміщення)
- Попередження про додаткові дані після `IEND`

Якщо потрібен детальніший перегляд чанків:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Корисні посилання:

- Специфікація PNG (структура, чанки): https://www.w3.org/TR/PNG/
- Трюки з форматами файлів (особливі випадки PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: метадані, інструменти для DCT-домену та обмеження ELA

### Техніка

JPEG зберігається не як необроблені пікселі, а стискається в DCT-домені. Тому інструменти для стеганографії JPEG відрізняються від інструментів PNG LSB:

- Payloads метаданих і коментарів зберігаються на рівні файла (їх легко виявити та швидко перевірити)
- Інструменти стеганографії для DCT-домену вбудовують біти в частотні коефіцієнти

На практиці розглядайте JPEG як:

- Контейнер для сегментів метаданих (їх легко виявити та швидко перевірити)
- Стиснений сигнальний домен (коефіцієнти DCT), у якому працюють спеціалізовані інструменти стеганографії

### Швидкі перевірки

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Місця з високим сигналом:

- Метадані EXIF/XMP/IPTC
- Сегмент коментаря JPEG (`COM`)
- Сегменти застосунків (`APP1` для EXIF, `APPn` для даних виробника)

### Поширені інструменти

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Якщо ви маєте справу саме з payload у JPEG, створеними за допомогою steghide, спробуйте `stegseek` (швидший bruteforce, ніж у старіших скриптів):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA виявляє різні артефакти повторного стиснення; це може вказати на ділянки, які редагували, але сам по собі цей метод не виявляє stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Анімовані зображення

### Методика

Для анімованих зображень припускайте, що повідомлення:

- Міститься в одному кадрі (легкий випадок), або
- Розподілене між кадрами (порядок важливий), або
- Видиме лише під час diff послідовних кадрів

### Вилучення кадрів

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Далі обробляйте кадри як звичайні PNG: `zsteg`, `pngcheck`, ізоляція каналів.

Альтернативні інструменти:

- `gifsicle --explode anim.gif` (швидке вилучення кадрів)
- `imagemagick`/`magick` для перетворення окремих кадрів

Порівняння кадрів часто має вирішальне значення:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Кодування кількістю пікселів в APNG

- Виявлення контейнерів APNG: `exiftool -a -G1 file.png | grep -i animation` або `file`.
- Витягування кадрів без зміни таймінгу: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Відновлення корисного навантаження, закодованого кількістю пікселів у кожному кадрі:

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

Анімовані завдання можуть кодувати кожен байт як кількість пікселів певного кольору в кожному кадрі; об’єднання цих кількостей відновлює повідомлення.<sup>[[1]](#references)</sup>

## Вбудовування із захистом паролем

Якщо ви підозрюєте, що вбудовування захищене парольною фразою, а не виконане на рівні пікселів, зазвичай це найшвидший шлях.

### steghide

Підтримує `JPEG, BMP, WAV, AU` і може вбудовувати та витягувати зашифровані payload-и.

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





## References

- [1] [Flagvent 2025 (Medium) — pink, Список бажань Санти, Різдвяні метадані, Захоплений шум](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Звіт HackVent 2024 — Twisted Colors](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Специфікація Portable Network Graphics (PNG), третє видання](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Глибоко під водою є щось](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Формати файлів зображень Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Специфікація GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — звіт CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
