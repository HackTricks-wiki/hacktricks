# Стеганографія тексту

{{#include ../../banners/hacktricks-training.md}}

Шукайте:

- Unicode homoglyphs
- Zero-width characters
- Шаблони пробілів (пробіли проти табуляцій)

## Практичний підхід

Якщо звичайний текст поводиться неочікувано, перевірте codepoints і обережно виконайте нормалізацію (не знищуйте докази).

### Техніка

Text stego часто використовує символи, які відображаються однаково (або невидимі):

- Homoglyphs: різні Unicode codepoints, які виглядають однаково (латинська `a` проти кириличної `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Кодування пробілами: пробіли проти табуляцій, кінцеві пробіли, шаблони довжини рядків<sup>[[1]](#references)</sup>

Додаткові випадки з високою інформативністю:

- Bidirectional override/control characters (можуть візуально змінювати порядок тексту)
- Variation selectors і combining characters, що використовуються як covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Перевірка codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Канали CSS `unicode-range`

Правила `@font-face` можуть кодувати байти в записах `unicode-range: U+..`. Витягніть кодові точки, об'єднайте шістнадцяткові значення та декодуйте:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Якщо діапазони містять кілька байтів в одному оголошенні, спочатку розділіть їх за комами та нормалізуйте (`tr ',+' '\n'`). Python спрощує аналіз і виведення байтів, якщо форматування є непослідовним.<sup>[[1]](#references)</sup>

## Посилання

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
