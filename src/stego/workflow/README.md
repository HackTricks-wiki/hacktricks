# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Більшість задач зі Stego швидше розв'язуються завдяки систематичному первинному аналізу, ніж випадковим використанням інструментів.

## Основний процес

### Чекліст швидкого первинного аналізу

Мета — ефективно відповісти на два запитання:

1. Який справжній контейнер/формат?
2. Чи міститься payload у метаданих, дописаних байтах, embedded files або на рівні вмісту Stego?

#### 1) Визначте контейнер
```bash
file target
ls -lah target
```
Якщо `file` і розширення не збігаються, довіряйте `file`. Розглядайте поширені формати як контейнери, коли це доречно (наприклад, документи OOXML є ZIP-файлами).

#### 2) Шукайте метадані та очевидні рядки
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Спробуйте кілька кодувань:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Перевірка доданих даних / вбудованих файлів
```bash
binwalk target
binwalk -e target
```
Якщо extraction не вдається, але signatures виявлено, вручну виріжте offsets за допомогою `dd` і повторно запустіть `file` для вирізаної області.

#### 4) Якщо це image

- Перевірте аномалії: `magick identify -verbose file`
- Якщо це PNG/BMP, перелічіть bit-planes/LSB: `zsteg -a file.png`
- Перевірте структуру PNG: `pngcheck -v file.png`
- Використовуйте visual filters (Stegsolve / StegoVeritas), коли вміст може розкриватися через channel/plane transforms

#### 5) Якщо це audio

- Спочатку побудуйте spectrogram (Sonic Visualiser)
- Декодуйте/перевірте streams: `ffmpeg -v info -i file -f null -`
- Якщо audio нагадує структуровані tones, перевірте DTMF decoding

### Основні інструменти

Вони виявляють найпоширеніші випадки на рівні container: payloads у metadata, appended bytes і embedded files, замасковані розширенням.<sup>[[1]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Репозиторій: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Контейнери, додані дані та polyglot-трюки

У багатьох steganography challenges після коректного файлу містяться додаткові байти або embedded archives, замасковані розширенням.

#### Додані payload-и

Багато форматів ігнорують кінцеві байти. ZIP/PDF/script можна додати до image/audio container.

Швидкі перевірки:
```bash
binwalk file
tail -c 200 file | xxd
```
Якщо вам відомий offset, виконайте carving за допомогою `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Магічні байти

Коли `file` не може визначити тип файлу, шукайте магічні байти за допомогою `xxd` і порівнюйте їх із відомими сигнатурами:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на zip:
```bash
7z l file
unzip -l file
```
### Дивацтва, суміжні зі stego

Швидкі посилання на шаблони, які часто трапляються поруч зі stego (QR із binary, braille тощо).

#### QR codes із binary

Якщо довжина blob є повним квадратом, це можуть бути необроблені пікселі для зображення/QR.
```python
import math
math.isqrt(2500)  # 50
```
Помічник для перетворення двійкового коду на зображення:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Шрифт Брайля

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Посилання

- [1] [DominicBreuker/stego-toolkit - Docker image with the most popular steganography tools bundled together](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
