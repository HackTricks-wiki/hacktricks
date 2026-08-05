# Стеганографія аудіо

{{#include ../../banners/hacktricks-training.md}}

Поширені шаблони:

- Повідомлення на спектрограмі
- Вбудовування LSB у WAV
- Кодування DTMF / тональних сигналів набору номера
- Payload у метаданих

## Швидке первинне оцінювання

Перед використанням спеціалізованих інструментів:

- Перевірте відомості про codec/container і аномалії:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний контент або тональну структуру, на ранньому етапі перегляньте спектрограму.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Стеганографія спектрограм

### Техніка

Spectrogram stego приховує дані, формуючи розподіл енергії в часі/частоті так, щоб вони ставали видимими лише на часово-частотному графіку (часто нечутні або сприймаються як шум).

### Sonic Visualiser

Основний інструмент для аналізу спектрограм:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Альтернативи

- Audacity (перегляд спектрограми, фільтри): https://www.audacityteam.org/
- `sox` може генерувати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Декодування FSK / модемного сигналу

Аудіосигнал із частотною маніпуляцією часто виглядає як чергування одиночних тонів на спектрограмі.<sup>[[1]](#references)</sup> Отримавши приблизні значення центральної частоти/зсуву та швидкості передачі в бодах, переберіть варіанти за допомогою `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` автоматично налаштовує підсилення та визначає тони mark/space; змініть `--rx-invert` або `--samplerate`, якщо вихідні дані спотворені.

## WAV LSB

### Техніка

Для нестисненого PCM (WAV) кожен семпл є цілим числом. Зміна молодших бітів дуже незначно змінює форму сигналу, тому зловмисники можуть приховувати:

- 1 біт на семпл (або більше)
- Дані, перемежовані між каналами
- Дані з використанням кроку/перестановки

Інші сімейства методів приховування в аудіо, з якими ви можете зіткнутися:

- Кодування фази
- Приховування за допомогою еха
- Вбудовування методом spread-spectrum
- Бічні канали на рівні кодека (залежить від формату та інструментів)

### WavSteg

Джерело: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / тональні сигнали набору

### Методика

DTMF кодує символи як пари фіксованих частот (клавіатура телефону). Якщо аудіо нагадує тональні сигнали клавіатури або регулярні двочастотні звукові сигнали, спочатку перевірте декодування DTMF.

Онлайн-декодери:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Посилання

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
