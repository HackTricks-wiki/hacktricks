# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Шукайте:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Практичний шлях

Якщо plain text поводиться несподівано, перевірте codepoints і нормалізуйте уважно (не знищуйте доказів).

### Техніка

Text stego часто використовує символи, які відображаються однаково (або невидимо):

- Homoglyphs: різні Unicode codepoints, які виглядають однаково (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Додаткові високосигнальні випадки:

- Bidirectional override/control characters (можуть візуально змінювати порядок тексту)
- Variation selectors and combining characters, які використовуються як прихований канал

### Інструменти декодування

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
## CSS `unicode-range` канали

`@font-face` правила можуть кодувати байти в записах `unicode-range: U+..`. Витягніть кодові точки, об'єднайте hex і декодуйте:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Якщо діапазони містять кілька bytes у кожному оголошенні, спочатку розділіть за комами й нормалізуйте (`tr ',+' '\n'`). Python полегшує розбір і виведення bytes, якщо форматування непослідовне.

## Посилання

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
