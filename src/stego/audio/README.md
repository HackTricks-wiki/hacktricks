# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Поширені шаблони:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Швидка перевірка

Перед використанням спеціалізованих інструментів:

- Підтвердьте відомості про codec/container та наявність аномалій:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, заздалегідь перегляньте spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Техніка

Spectrogram stego приховує дані, модулюючи енергію по часу й частоті так, щоб вони ставали видимими лише на часово-частотному графіку (часто нечутні або сприймаються як шум).

### Sonic Visualiser

Основний інструмент для аналізу спектрограм:

- https://www.sonicvisualiser.org/

### Альтернативи

- Audacity (перегляд спектрограми, фільтри): https://www.audacityteam.org/
- `sox` може генерувати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Техніка

Для нестисненого PCM (WAV) кожен семпл — це ціле число. Зміна молодших бітів дуже незначно змінює форму хвилі, тому зловмисники можуть приховувати:

- 1 біт на семпл (або більше)
- Переплітаються між каналами
- З кроком/перестановкою

Інші методи приховування в аудіо, які ви можете зустріти:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (залежно від формату та інструменту)

### WavSteg

Джерело: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / тональні сигнали набору

### Техніка

DTMF кодує символи парами фіксованих частот (телефонна клавіатура). Якщо аудіо нагадує сигнали клавіатури або регулярні двочастотні гудки, перевірте DTMF-декодування якомога раніше.

Онлайн-декодери:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
