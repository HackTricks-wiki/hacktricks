# Steganografia tekstowa

{{#include ../../banners/hacktricks-training.md}}

Szukaj:

- Homoglifów Unicode
- Znaków o zerowej szerokości
- Wzorców białych znaków (spacje vs tabulatory)

## Praktyczna ścieżka

Jeśli zwykły tekst zachowuje się nieoczekiwanie, sprawdź codepointy i ostrożnie go normalizuj (nie niszcz dowodów).

### Technika

Stego tekstowe często opiera się na znakach, które wyglądają identycznie (lub są niewidoczne):

- Homoglifach: różnych codepointach Unicode, które wyglądają tak samo (łacińskie `a` vs cyrylickie `а`)
- Znakach o zerowej szerokości: joinery, non-joinery, spacje o zerowej szerokości
- Kodowaniu białymi znakami: spacjach vs tabulatorach, końcowych spacjach, wzorcach długości wierszy<sup>[[1]](#references)</sup>

Dodatkowe przypadki o wysokiej wartości sygnału:

- Znakach sterujących/nadpisujących kierunek dwukierunkowy (mogą wizualnie zmieniać kolejność tekstu)
- Selektorach wariantów i znakach łączących używanych jako covert channel

### Pomocniki do dekodowania

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Sprawdzanie codepointów
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Kanały `unicode-range` CSS

Reguły `@font-face` mogą kodować bajty we wpisach `unicode-range: U+..`. Wyodrębnij punkty kodowe, połącz wartości szesnastkowe i zdekoduj:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Jeśli zakresy zawierają wiele bajtów w jednej deklaracji, najpierw podziel je po przecinkach i znormalizuj (`tr ',+' '\n'`). Python ułatwia analizowanie i generowanie bajtów, gdy formatowanie jest niespójne.

## Referencje

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
