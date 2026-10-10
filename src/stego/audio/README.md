# Стеганографія в аудіо

{{#include ../../banners/hacktricks-training.md}}

Поширені шаблони:

- Повідомлення у спектрограмі
- Вбудовування LSB у WAV
- Кодування DTMF / сигналами набору номера
- Payloads у метаданих

## Швидкий тріаж

Перш ніж використовувати спеціалізовані інструменти:

- Перевірте деталі кодека/контейнера та аномалії:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, спочатку перегляньте спектрограму.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Стеганографія у спектрограмі

### Методика

Стеганографія у спектрограмі приховує дані, формуючи розподіл енергії в часі та частоті так, щоб вони ставали видимими на часово-частотному графіку, тоді як аудіо може звучати як тони або шум.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Основний інструмент для перегляду спектрограм:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Альтернативи

- Audacity (перегляд спектрограми та фільтри).<sup>[[6]](#references)</sup>
- `sox` може створювати спектрограми з командного рядка:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / декодування модема

Аудіо з частотною маніпуляцією часто виглядає як чергування окремих тонів на спектрограмі. Коли ви приблизно визначите центральну частоту/зсув і швидкість передавання символів, переберіть варіанти за допомогою `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` підтримує Bell та інші режими FSK, а також власні частоти mark/space; перегляньте його параметри, а не припускайте, що будь-який запис можна автоматично визначити. Якщо результат спотворений, спробуйте `--rx-invert`, явно вкажіть режим baud або задайте `--samplerate <Hz>`.<sup>[[4]](#references)</sup>

## WAV LSB

### Техніка

Для нестисненого PCM (WAV) кожен семпл є цілим числом. Зміна молодших бітів лише незначно змінює форму хвилі, тож зловмисники можуть приховувати дані:

- 1 біт на семпл (або більше)
- Чергуючи канали
- Використовуючи крок/перестановку

Інші методи приховування в аудіо, з якими можна зіткнутися:

- Кодування фази
- Приховування за допомогою ехо
- Вбудовування методом розширеного спектра
- Побічні канали кодека (залежно від формату й інструмента)

### WavSteg

У наведених нижче командах використовується WavSteg із набору інструментів `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Офіційний репозиторій і релізи DeepSound.<sup>[[7]](#references)</sup>

## DTMF / тональні сигнали набору номера

### Техніка

DTMF кодує кожен сигнал клавіатури за допомогою однієї частоти з нижньої групи та однієї з верхньої. Якщо аудіо нагадує сигнали клавіатури або регулярні двочастотні гудки, спершу спробуйте декодувати DTMF.<sup>[[5]](#references)</sup>

Онлайн-декодери:

- Браузерний інструмент `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, офлайн-декодер аудіофайлів.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — рожевий, список бажань Санти, різдвяні метадані, захоплений шум](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — документація](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — командний FSK-модем](https://github.com/kamalmostafa/minimodem)
- [5] [Рекомендація ITU-T Q.23 — технічні характеристики телефонних апаратів із кнопковим набором](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — офіційний репозиторій і релізи](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
