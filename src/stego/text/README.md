# Стеганографія в тексті

{{#include ../../banners/hacktricks-training.md}}

## Практичний підхід

Якщо звичайний текст поводиться неочікувано, збережіть оригінальні докази, перевірте його codepoints і нормалізуйте лише копію.

### Техніка

Стеганографія в тексті часто використовує символи, які відображаються однаково або невидимі:

- Homoglyphs: різні Unicode codepoints, які виглядають схожими (наприклад, латинська `a` і кирилична `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners і zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: пробіли та табуляції, шаблони кінцевих пробілів і навмисні шаблони довжини рядків<sup>[[3]](#references)[[4]](#references)</sup>

Додаткові випадки з високою інформативністю:

- Bidirectional controls, які можуть візуально змінювати порядок тексту<sup>[[1]](#references)</sup>
- Variation selectors і combining characters, які можуть містити прихований стан, залишаючи видимий текст майже незміненим<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

Правила `@font-face` можна використовувати для кодування байтів у записах `unicode-range: U+..`. Витягніть кодові точки, об'єднайте шістнадцяткові значення та декодуйте їх:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Якщо діапазони містять кілька значень в одному оголошенні, спочатку розділіть їх за комами та нормалізуйте (`tr ',+' '\n'`). Python може аналізувати та виводити байти, коли форматування є непослідовним.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Міркування щодо безпеки Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Стеганографія Unicode за допомогою символів нульової ширини та гомогліфів](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Список бажань Санти](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Посібник Debian: стеганографія пробілів за допомогою `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
