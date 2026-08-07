# Аудіостеганографія

{{#include ../../banners/hacktricks-training.md}}

Поширені шаблони:

- Повідомлення на спектрограмі
- Вбудовування LSB у WAV
- Кодування DTMF / тональних сигналів набору номера
- Payloads у метаданих

## Швидке первинне дослідження

Перед використанням спеціалізованих інструментів:

- Перевірте відомості про codec/container та аномалії:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Якщо аудіо містить шумоподібний вміст або тональну структуру, якомога раніше перегляньте спектрограму.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Стеганографія за допомогою спектрограми

### Technique

Spectrogram stego приховує дані, формуючи розподіл енергії в часі/частоті, завдяки чому вони стають видимими лише на графіку час-частота (часто нечутні або сприймаються як шум).

### Sonic Visualiser

Основний інструмент для перегляду спектрограм:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (перегляд спектрограми, фільтри): https://www.audacityteam.org/
- `sox` може генерувати спектрограми з CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / декодування модему

Аудіо з частотною маніпуляцією часто виглядає як чергування одиночних тонів на спектрограмі. Отримавши приблизні значення центральної частоти, зсуву та швидкості передавання в бодах, виконайте перебір за допомогою `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` автоматично налаштовує підсилення та визначає тони mark/space; налаштуйте `--rx-invert` або `--samplerate`, якщо вихідні дані спотворені.

## WAV LSB

### Методика

Для нестисненого PCM (WAV) кожен семпл є цілим числом. Зміна молодших бітів дуже незначно змінює форму хвилі, тому зловмисники можуть приховувати:

- 1 біт на семпл (або більше)
- Дані, перемежовані між каналами
- Дані з використанням кроку/перестановки

Інші родини методів приховування в аудіо, з якими ви можете зіткнутися:

- Кодування фази
- Приховування за допомогою еха
- Вбудовування з розширеним спектром
- Бічні канали на рівні кодека (залежно від формату та інструментів)

### WavSteg

Джерело: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / тональні сигнали набору

### Методика

DTMF кодує символи як пари фіксованих частот (клавіатура телефону). Якщо аудіо нагадує тональні сигнали клавіатури або регулярні двочастотні звукові сигнали, на ранньому етапі перевірте декодування DTMF.

Онлайн-декодери:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [1] [Flagvent 2025 (Medium) — рожевий, список бажань Санти, різдвяні метадані, захоплений шум](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
