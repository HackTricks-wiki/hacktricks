# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Поширені шаблони:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Швидкий триаж

Перед використанням спеціалізованих інструментів:

- Перевірте деталі кодека/контейнера та аномалії:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, на ранньому етапі перегляньте спектрограму.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Техніка

Spectrogram stego приховує дані, формуючи енергію в часі/частоті так, щоб вони ставали видимими лише на часово-частотному графіку (часто нечутні або сприймаються як шум).

### Sonic Visualiser

Основний інструмент для огляду спектрограм:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Альтернативи

- Audacity (перегляд спектрограми, фільтри): https://www.audacityteam.org/
- `sox` може генерувати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Техніка

Для несжатого PCM (WAV) кожен зразок — ціле число. Зміна молодших бітів дуже незначно змінює форму хвилі, тому атакувальники можуть сховати:

- 1 біт на зразок (або більше)
- Переплетено між каналами
- З кроком/перестановкою

Інші методи приховування аудіо, які ви можете зустріти:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Джерело: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / тони набору номера

### Техніка

DTMF кодує символи як пари фіксованих частот (клавіатура телефону). Якщо аудіо нагадує тони клавіатури або регулярні двочастотні сигнали, перевірте декодування DTMF на ранньому етапі.

Онлайн-декодери:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
