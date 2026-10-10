# Стеганографія в тексті

{{#include ../../banners/hacktricks-training.md}}

## Практичний підхід

Якщо звичайний текст поводиться неочікувано, збережіть оригінальні дані, перевірте його кодові точки й нормалізуйте лише копію.

### Техніка

Стеганографія в тексті часто спирається на символи, які виглядають однаково або невидимі:

- Гомогліфи: різні кодові точки Unicode, які виглядають схоже (наприклад, латинська `a` і кирилична `а`)<sup>[[1]](#references)</sup>
- Символи нульової ширини: символи з’єднання, нез’єднання та пробіли нульової ширини<sup>[[2]](#references)</sup>
- Кодування пробілами: пробіли замість табуляцій, шаблони кінцевих пробілів і навмисні шаблони довжини рядків<sup>[[3]](#references)[[4]](#references)</sup>

Додаткові випадки з високою ймовірністю прихованого вмісту:

- Керівні символи двонапрямного тексту, які можуть візуально змінювати порядок тексту<sup>[[1]](#references)</sup>
- Варіаційні селектори та комбінувальні символи, які можуть містити прихований стан, майже не змінюючи видимий текст<sup>[[1]](#references)</sup>

### Допоміжні засоби декодування

- [Кодувальник/декодувальник гомогліфів Unicode та символів нульової ширини](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Перевірка кодових точок

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

Правила `@font-face` можна використати для кодування байтів у записах `unicode-range: U+..`. Витягніть кодові точки, об’єднайте шістнадцяткові значення та декодуйте їх:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Якщо діапазони містять кілька значень в одному оголошенні, спочатку розділіть їх за комами й нормалізуйте (`tr ',+' '\n'`). Python може зчитати й вивести байти, якщо форматування непослідовне.<sup>[[3]](#references)</sup>

## References

- [1] [Технічний звіт Unicode № 36: міркування щодо безпеки Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: стеганографія Unicode із символами нульової ширини та гомогліфами](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — список бажань Санти](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Посібник Debian: стеганографія пробільними символами за допомогою `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
