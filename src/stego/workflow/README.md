# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Більшість stego-задач розв'язуються швидше завдяки систематичному triage, ніж спробам використовувати випадкові інструменти.

## Основний процес

### Чекліст швидкого triage

Мета — ефективно відповісти на два запитання:

1. Який справжній container/format?
2. Чи міститься payload у metadata, дописаних байтах, embedded files або content-level stego?

#### 1) Визначте container
```bash
file target
ls -lah target
```
Якщо `file` і розширення не збігаються, перевірте сигнатуру замість того, щоб довіряти суфіксу. `file` також використовує евристичний аналіз, і його можна ввести в оману пошкодженими або поліглотними вхідними даними. За потреби розглядайте поширені формати як контейнери (наприклад, документи OOXML є ZIP-пакетами).<sup>[[2]](#references)</sup>

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
Якщо видобування не вдається, але сигнатури виявлено, вручну виріжте offsets за допомогою `dd` і повторно запустіть `file` для вирізаної області.

#### 4) Якщо це зображення

- Перевірте аномалії: `magick identify -verbose file`
- Якщо це PNG/BMP, перелічіть bit-planes/LSB: `zsteg -a file.png`
- Перевірте структуру PNG: `pngcheck -v file.png`
- Використовуйте візуальні фільтри (Stegsolve / StegoVeritas), якщо вміст може розкриватися після перетворень каналів/площин

#### 5) Якщо це аудіо

- Спочатку побудуйте spectrogram (Sonic Visualiser)
- Декодуйте/перевірте потоки: `ffmpeg -v info -i file -f null -`
- Якщо аудіо нагадує структуровані тони, перевірте DTMF decoding

### Основні інструменти

Вони виявляють поширені випадки на рівні контейнера: payload у метаданих, дописані байти та embedded files, замасковані розширенням.<sup>[[1]](#references)[[3]](#references)</sup>

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
Репозиторій проєкту: `korczis/foremost`.<sup>[[4]](#references)</sup>

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
### Контейнери, додані дані та polyglot tricks

Багато завдань зі стеганографії містять додаткові байти після коректного файлу або вбудовані архіви, замасковані розширенням.

#### Додані payloads

Багато форматів ігнорують кінцеві байти. ZIP/PDF/script можна додати до контейнера зображення/аудіо.

Швидкі перевірки:
```bash
binwalk file
tail -c 200 file | xxd
```
Якщо ви знаєте зміщення, виконайте carving за допомогою `dd`:
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

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на формат zip:
```bash
7z l file
unzip -l file
```
### Дивності поруч зі stego

Швидкі посилання на шаблони, які регулярно трапляються поруч зі stego (QR із binary, braille тощо).

#### QR-коди з binary

Якщо довжина blob є повним квадратом, це можуть бути raw pixels для зображення/QR.
```python
import math
math.isqrt(2500)  # 50
```
Помічник для перетворення двійкового коду на зображення:

- Помічник dCode для перетворення двійкового коду на зображення.<sup>[[5]](#references)</sup>

#### Брайль

- Перекладач Брайля Branah.<sup>[[6]](#references)</sup>

Для ширших добірок утиліт для стеганографії та ресурсів, присвячених окремим технікам, див. bundled stego-toolkit і curated list від 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker-образ із найпопулярнішими інструментами стеганографії в одному комплекті](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston та ін. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Двійкове зображення](https://www.dcode.fr/binary-image)
- [6] [Branah — Перекладач Брайля](https://www.branah.com/braille-translator)
- [7] [0xRick — Ресурси зі стеганографії](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
