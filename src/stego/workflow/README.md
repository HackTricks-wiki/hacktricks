# Робочий процес стеганографії

{{#include ../../banners/hacktricks-training.md}}

Більшість завдань зі стеганографії швидше розв’язуються завдяки систематичному первинному аналізу, ніж випадковому підбору інструментів.

## Основний процес

### Контрольний список для швидкого первинного аналізу

Мета — швидко відповісти на два запитання:

1. Який справжній контейнер/формат?
2. Де міститься payload: у метаданих, дописаних байтах, вбудованих файлах чи у вмісті?

#### 1) Визначте контейнер

```bash
file target
ls -lah target
```

Якщо `file` і розширення не збігаються, перевірте сигнатуру, а не довіряйте суфіксу. `file` також використовує евристики, і його можуть ввести в оману некоректні або поліглотні дані. За потреби розглядайте поширені формати як контейнери (наприклад, документи OOXML є ZIP-пакетами).<sup>[[2]](#references)</sup>

#### 2) Пошук метаданих і очевидних рядків

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

#### 3) Перевірте дописані дані / вбудовані файли

```bash
binwalk target
binwalk -e target
```

Якщо витягування не вдається, але виявлено сигнатури, вручну виріжте ділянки за зміщеннями за допомогою `dd` і повторно запустіть `file` для вирізаної ділянки.

#### 4) Якщо це зображення

- Перевірте аномалії: `magick identify -verbose file`
- Якщо це PNG/BMP, переберіть bit-plane/LSB: `zsteg -a file.png`
- Перевірте структуру PNG: `pngcheck -v file.png`
- Використовуйте візуальні фільтри (Stegsolve / StegoVeritas), якщо вміст може стати видимим після перетворення каналів/площин

#### 5) Якщо це аудіо

- Спершу побудуйте спектрограму (Sonic Visualiser)
- Декодуйте/перевірте потоки: `ffmpeg -v info -i file -f null -`
- Якщо аудіо нагадує структуровані тони, перевірте декодування DTMF

### Основні інструменти

Вони виявляють поширені випадки на рівні контейнера: корисні дані в метаданих, додані байти та вбудовані файли, замасковані розширенням.<sup>[[1]](#references)[[3]](#references)</sup>

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

### Контейнери, дописані дані та поліглотні трюки

У багатьох завданнях зі стеганографії є зайві байти після коректного файла або вбудовані архіви, замасковані розширенням.

#### Дописані дані

Багато форматів ігнорують кінцеві байти. До контейнера зображення/аудіо можна дописати ZIP/PDF/скрипт.

Швидкі перевірки:

```bash
binwalk file
tail -c 200 file | xxd
```

Якщо відомий зсув, виріжте дані за допомогою dd:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Магічні байти

Якщо `file` не може визначити тип файлу, знайдіть магічні байти за допомогою `xxd` і порівняйте їх із відомими сигнатурами:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Спробуйте `7z` і `unzip`, навіть якщо розширення не вказує на ZIP:

```bash
7z l file
unzip -l file
```

### Незвичні випадки поруч зі stego

Швидкі посилання на шаблони, які часто трапляються поруч зі stego (QR-коди з двійкових даних, шрифт Брайля тощо).

#### QR-коди з двійкових даних

Якщо довжина блоба є повним квадратом, він може містити необроблені пікселі зображення або QR-коду.

```python
import math
math.isqrt(2500)  # 50
```

Помічник перетворення двійкового коду на зображення:

- Помічник dCode для перетворення двійкового коду на зображення.<sup>[[5]](#references)</sup>

#### Шрифт Брайля

- Перекладач шрифту Брайля Branah.<sup>[[6]](#references)</sup>

Щоб ознайомитися з ширшими добірками утиліт для стеганографії та ресурсів для конкретних технік, перегляньте stego-toolkit і добірку 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit — Docker-образ із найпопулярнішими інструментами стеганографії](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston та ін. — специфікація ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — зображення з двійкового коду](https://www.dcode.fr/binary-image)
- [6] [Branah — перекладач шрифту Брайля](https://www.branah.com/braille-translator)
- [7] [0xRick — ресурси зі стеганографії](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
