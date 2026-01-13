# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Поширені патерни:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Швидка перевірка

Перед використанням спеціалізованих інструментів:

- Підтвердіть деталі codec/container та аномалії:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, завчасно перегляньте spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Техніка

Spectrogram stego приховує дані шляхом формування енергії в часі/частоті, так що вони стають видимими лише на часово-частотному графіку (часто нечутні або сприймаються як шум).

### Sonic Visualiser

Основний інструмент для огляду спектрограми:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Альтернативи

- Audacity (відображення спектрограми, фільтри): https://www.audacityteam.org/
- `sox` може генерувати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio часто виглядає як почергові однотонні сигнали на спектрограмі. Після того, як у вас є приблизна оцінка центру/зсуву та baud, brute force з `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` автопідсилює та автоматично визначає mark/space тони; відкоригуйте `--rx-invert` або `--samplerate`, якщо вихід спотворений.

## WAV LSB

### Техніка

Для непакованого PCM (WAV) кожний семпл — це ціле число. Зміна молодших бітів дуже незначно змінює форму хвилі, тому зловмисники можуть приховувати:

- 1 біт на семпл (або більше)
- чергуються між каналами
- із кроком/перестановкою

Інші підходи приховування аудіо, які ви можете зустріти:

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

## DTMF / dial tones

### Техніка

DTMF кодує символи як пари фіксованих частот (клавіатура телефону). Якщо аудіо нагадує тон набору або регулярні двочастотні сигнали, протестуйте декодування DTMF на ранньому етапі.

Онлайн декодери:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Посилання

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
