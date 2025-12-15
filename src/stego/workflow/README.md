# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Більшість stego проблем вирішуються швидше системним тріажем, ніж спробами випадкових інструментів.

## Основний процес

### Швидкий чекліст тріажу

Мета — ефективно відповісти на два запитання:

1. Який реальний контейнер/формат?
2. Чи payload міститься в metadata, appended bytes, embedded files, або content-level stego?

#### 1) Визначити контейнер
```bash
file target
ls -lah target
```
Якщо `file` і розширення не збігаються, довіряйте `file`. Обробляйте поширені формати як контейнери, коли це доречно (наприклад, OOXML документи — ZIP-файли).

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
#### 3) Перевірте на наявність доданих даних / вбудованих файлів
```bash
binwalk target
binwalk -e target
```
Якщо вилучення не вдається, але виявлено сигнатури, вручну виріжте офсети за допомогою `dd` і повторно запустіть `file` на вирізаному фрагменті.

#### 4) Якщо зображення

- Перевірте аномалії: `magick identify -verbose file`
- Якщо PNG/BMP, перерахувати bit-planes/LSB: `zsteg -a file.png`
- Перевірити структуру PNG: `pngcheck -v file.png`
- Використовуйте візуальні фільтри (Stegsolve / StegoVeritas), коли контент може проявитися внаслідок перетворень каналу/площини

#### 5) Якщо аудіо

- Спочатку спектрограма (Sonic Visualiser)
- Декодувати/перевірити потоки: `ffmpeg -v info -i file -f null -`
- Якщо аудіо нагадує структуровані тони, перевірте декодування DTMF

### Основні інструменти

Вони покривають найчастіші випадки на рівні контейнера: metadata payloads, appended bytes, and embedded files disguised by extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### файл / рядки
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

Багато steganography задач — це додаткові байти після валідного файлу або вбудовані архіви, замасковані під інше розширення.

#### Appended payloads

Багато форматів ігнорують trailing bytes. A ZIP/PDF/script can be appended to an image/audio container.

Швидкі перевірки:
```bash
binwalk file
tail -c 200 file | xxd
```
Якщо ви знаєте offset, виконайте carve за допомогою `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Коли `file` плутається, шукайте magic bytes за допомогою `xxd` і порівнюйте з відомими сигнатурами:
```bash
xxd -g 1 -l 32 file
```
#### Zip у маскуванні

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на zip:
```bash
7z l file
unzip -l file
```
### Поблизу stego: дивності

Швидкі посилання на патерни, які регулярно з'являються поруч зі stego (QR-from-binary, braille тощо).

#### QR codes from binary

Якщо довжина blob є точним квадратом, це може бути сирі пікселі для зображення/QR.
```python
import math
math.isqrt(2500)  # 50
```
Помічник для перетворення бінарних даних у зображення:

- https://www.dcode.fr/binary-image

#### Брайль

- https://www.branah.com/braille-translator

## Довідкові списки

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
