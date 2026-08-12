# Steganografia tekstu

{{#include ../../banners/hacktricks-training.md}}

## Ścieżka praktyczna

Jeśli zwykły tekst zachowuje się nieoczekiwanie, zachowaj oryginalne dowody, sprawdź jego punkty kodowe i normalizuj tylko kopię.

### Technika

Steganografia tekstu często wykorzystuje znaki, które wyglądają identycznie lub są niewidoczne:

- Homoglify: różne punkty kodowe Unicode, które wyglądają podobnie (na przykład łacińskie `a` i cyrylickie `а`)<sup>[[1]](#references)</sup>
- Znaki o zerowej szerokości: joinery, non-joinery i spacje o zerowej szerokości<sup>[[2]](#references)</sup>
- Kodowanie białymi znakami: spacje i tabulatory, wzorce końcowych spacji oraz celowe wzorce długości wierszy<sup>[[3]](#references)[[4]](#references)</sup>

Dodatkowe przypadki o wysokiej wartości sygnału:

- Znaki sterujące dwukierunkowością, które mogą wizualnie zmieniać kolejność tekstu<sup>[[1]](#references)</sup>
- Selektory wariantów i znaki łączące, które mogą przenosić ukryty stan, pozostawiając widoczny tekst niemal niezmieniony<sup>[[1]](#references)</sup>

### Pomocniki dekodowania

- [Koder/dekoder homoglifów Unicode i znaków o zerowej szerokości](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Sprawdzanie punktów kodowych
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Kanały `unicode-range` w CSS

Reguły `@font-face` mogą być wykorzystywane do kodowania bajtów we wpisach `unicode-range: U+..`. Wyodrębnij codepointy, połącz wartości szesnastkowe i zdekoduj je:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Jeśli zakresy zawierają wiele wartości w jednej deklaracji, najpierw podziel je po przecinkach i znormalizuj (`tr ',+' '\n'`). Python może przeanalizować i wygenerować bajty, gdy formatowanie jest niespójne.<sup>[[3]](#references)</sup>

## References

- [1] [Raport techniczny Unicode #36: Uwagi dotyczące bezpieczeństwa Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganografia Unicode z użyciem znaków o zerowej szerokości i homoglifów](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista życzeń Świętego Mikołaja](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Podręcznik Debiana: steganografia białych znaków za pomocą `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
