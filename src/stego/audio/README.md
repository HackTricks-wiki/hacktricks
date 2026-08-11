# Стеганографія в аудіо

{{#include ../../banners/hacktricks-training.md}}

Поширені методи:

- Повідомлення на спектрограмі
- Вбудовування LSB у WAV
- Кодування DTMF / тональних сигналів набору номера
- Payloads у метаданих

## Швидке первинне дослідження

Перед використанням спеціалізованих інструментів:

- Перевірте дані про codec/container та аномалії:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, спочатку дослідіть спектрограму.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Стеганографія за допомогою спектрограми

### Technique

Spectrogram stego приховує дані, формуючи розподіл енергії в часі/частоті, щоб вони ставали видимими на графіку час-частота, тоді як аудіо може звучати як тони або шум.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Основний інструмент для перегляду спектрограм:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (режим перегляду спектрограми та фільтри).<sup>[[6]](#references)</sup>
- `sox` може створювати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Аудіо з frequency-shift keying часто виглядає як чергування одиночних тонів на spectrogram. Отримавши приблизну оцінку центральної частоти/зсуву та baud, виконайте brute force за допомогою `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` підтримує Bell та інші FSK-режими, а також власні частоти mark/space; перегляньте його опції, а не припускайте, що кожен запис можна автоматично визначити. Спробуйте `--rx-invert`, явний baud-режим або `--samplerate <Hz>`, якщо результат є нерозбірливим.<sup>[[4]](#references)</sup>

## WAV LSB

### Методика

Для нестисненого PCM (WAV) кожен семпл є цілим числом. Зміна молодших бітів дуже незначно змінює форму хвилі, тому зловмисники можуть приховувати:

- 1 біт на семпл (або більше)
- Чергуючи між каналами
- За допомогою кроку/перестановки

Інші способи приховування в аудіо, з якими ви можете зіткнутися:

- Кодування фази
- Приховування за допомогою ехо
- Вбудовування методом spread-spectrum
- Канали на стороні codec (залежні від формату та інструмента)

### WavSteg

У наведених нижче командах використовується WavSteg із toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Офіційний репозиторій і релізи DeepSound.<sup>[[7]](#references)</sup>

## DTMF / сигнали набору

### Техніка

DTMF представляє кожен сигнал клавіатури за допомогою однієї частоти з низької групи та однієї частоти з високої групи. Якщо аудіо нагадує сигнали клавіатури або регулярні двочастотні гудки, спочатку перевірте декодування DTMF.<sup>[[5]](#references)</sup>

Онлайн-декодери:

- Браузерний інструмент `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, декодер аудіофайлів, що працює офлайн.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — рожевий, список бажань Санти, різдвяні метадані, захоплений шум](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — документація](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — FSK-модем командного рядка](https://github.com/kamalmostafa/minimodem)
- [5] [Рекомендація ITU-T Q.23 — технічні характеристики телефонних апаратів із кнопковим набором](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — офіційний репозиторій і релізи](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
