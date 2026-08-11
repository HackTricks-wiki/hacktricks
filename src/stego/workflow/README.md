# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Більшість завдань зі stego розв’язуються швидше завдяки систематичному triage, ніж шляхом випадкового використання інструментів.

## Основний процес

### Контрольний список швидкого triage

Мета — ефективно відповісти на два запитання:

1. Який справжній контейнер/формат?
2. Чи міститься payload у metadata, дописаних байтах, вбудованих файлах або на рівні вмісту stego?

#### 1) Визначте контейнер
```bash
file target
ls -lah target
```
Якщо `file` і розширення не збігаються, перевірте сигнатуру замість того, щоб довіряти суфіксу. `file` також працює за евристичними правилами, і його можна ввести в оману пошкодженими або polyglot-вхідними даними. За потреби розглядайте поширені формати як контейнери (наприклад, документи OOXML є ZIP-пакетами).<sup>[[2]](#references)</sup>

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
#### 3) Перевірка на додані дані / вбудовані файли
```bash
binwalk target
binwalk -e target
```
Якщо extraction не вдається, але сигнатури повідомляються, вручну витягніть offsets за допомогою `dd` і повторно запустіть `file` для витягнутої області.

#### 4) Якщо це зображення

- Перевірте аномалії: `magick identify -verbose file`
- Якщо це PNG/BMP, перелічіть bit-planes/LSB: `zsteg -a file.png`
- Перевірте структуру PNG: `pngcheck -v file.png`
- Використовуйте візуальні фільтри (Stegsolve / StegoVeritas), якщо вміст може розкриватися завдяки перетворенням каналів/площин

#### 5) Якщо це аудіо

- Спочатку побудуйте spectrogram (Sonic Visualiser)
- Декодуйте/перевірте streams: `ffmpeg -v info -i file -f null -`
- Якщо аудіо нагадує структуровані тони, перевірте DTMF decoding

### Основні інструменти

Вони виявляють поширені випадки на рівні контейнера: payloads у metadata, додані bytes і embedded files, замасковані розширенням.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Репозиторій: https://github.com/ReFirmLabs/binwalk

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
### Контейнери, додані дані та поліглотні прийоми

Багато задач зі стеганографії містять додаткові байти після коректного файлу або вбудовані архіви, замасковані розширенням.

#### Додані payload

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

Коли `file` не може визначити тип, шукайте магічні байти за допомогою `xxd` і порівнюйте їх із відомими сигнатурами:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на zip:
```bash
7z l file
unzip -l file
```
### Дивні випадки, пов’язані зі stego

Швидкі посилання на шаблони, які регулярно трапляються поруч зі stego (QR-from-binary, шрифт Брайля тощо).

#### QR codes from binary

Якщо довжина blob є повним квадратом, це можуть бути необроблені пікселі для зображення/QR.
```python
import math
math.isqrt(2500)  # 50
```
Помічник для перетворення двійкового коду на зображення:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Брайль

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image with the most popular steganography tools bundled together](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Двійкове зображення](https://www.dcode.fr/binary-image)
- [6] [Branah — Перекладач Брайля](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
