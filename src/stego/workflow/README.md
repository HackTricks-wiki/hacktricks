# Stego Робочий процес

{{#include ../../banners/hacktricks-training.md}}

Більшість stego-проблем вирішується швидше систематичною тріажною перевіркою, а не спробами випадкових інструментів.

## Основний потік

### Швидкий чекліст триажу

Мета — ефективно відповісти на два питання:

1. Який це реальний контейнер/формат?
2. Чи знаходиться payload у metadata, appended bytes, embedded files, або content-level stego?

#### 1) Визначити контейнер
```bash
file target
ls -lah target
```
Якщо `file` і розширення не збігаються, довіряйте `file`. Розглядайте поширені формати як контейнери, коли це доречно (наприклад, OOXML документи — це файли ZIP).

#### 2) Шукайте метадані та очевидні strings
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
#### 3) Перевірте наявність доданих даних / вкладених файлів
```bash
binwalk target
binwalk -e target
```
Якщо вилучення не вдається, але виявлені сигнатури, вручну виріжте офсети за допомогою `dd` і повторно запустіть `file` на вирізаному регіоні.

#### 4) Якщо зображення

- Перевірте аномалії: `magick identify -verbose file`
- Якщо PNG/BMP, перераховуйте біт-плани/LSB: `zsteg -a file.png`
- Перевірте структуру PNG: `pngcheck -v file.png`
- Використовуйте візуальні фільтри (Stegsolve / StegoVeritas), коли вміст може бути виявлений перетвореннями каналів/площин

#### 5) Якщо аудіо

- Спочатку спектрограма (Sonic Visualiser)
- Декодуйте/перегляньте потоки: `ffmpeg -v info -i file -f null -`
- Якщо аудіо нагадує структуровані тони, спробуйте декодування DTMF

### Основні інструменти

Вони охоплюють найпоширеніші випадки на рівні контейнера: метадані, додані байти та вкладені файли, замасковані під інші розширення.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to external repos. Please paste the contents of src/stego/workflow/README.md here (or the parts you want translated), and I will translate the English text to Ukrainian following your rules.
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
### Контейнери, додані дані та polyglot трюки

Багато steganography завдань — це додаткові байти після валідного файлу або вкладені архіви, замасковані під інше розширення.

#### Додані payloads

Багато форматів ігнорують кінцеві байти. До контейнера зображення/аудіо можна додати ZIP/PDF/script.

Швидкі перевірки:
```bash
binwalk file
tail -c 200 file | xxd
```
Якщо ви знаєте offset, carve за допомогою `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Коли `file` не може визначити тип, шукайте magic bytes за допомогою `xxd` і порівнюйте з відомими сигнатурами:
```bash
xxd -g 1 -l 32 file
```
#### Zip під прикриттям

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на zip:
```bash
7z l file
unzip -l file
```
### Дивності поруч зі stego

Швидкі посилання на патерни, які регулярно з'являються поруч зі stego (QR-from-binary, braille тощо).

#### QR codes from binary

Якщо довжина blob є повним квадратом, це може бути сирі пікселі для image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Інструмент для перетворення бінарних даних у зображення:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Брайль

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Списки ресурсів

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
