# Text-Steganographie

{{#include ../../banners/hacktricks-training.md}}

Achte auf:

- Unicode-Homoglyphen
- Zero-width characters
- Whitespace-Muster (spaces vs tabs)

## Praktischer Weg

Wenn Klartext sich unerwartet verhält, untersuche die Codepoints und normalisiere sorgfältig (Beweise nicht zerstören).

### Technik

Text-Stego beruht häufig auf Zeichen, die identisch (oder unsichtbar) dargestellt werden:

- Homoglyphen: verschiedene Unicode-Codepoints, die gleich aussehen (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace-Codierungen: spaces vs tabs, trailing spaces, Zeilenlängenmuster

Weitere aussagekräftige Fälle:

- Bidirektionale override/control characters (können Text visuell umordnen)
- Variationsselektoren und kombinierende Zeichen, die als verdeckter Kanal verwendet werden

### Hilfen zum Dekodieren

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Codepoints inspizieren
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` Kanäle

`@font-face` rules können Bytes in `unicode-range: U+..` Einträgen kodieren. Extrahiere die Codepunkte, füge die Hexwerte zusammen und dekodiere:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Wenn Bereiche mehrere Bytes pro Deklaration enthalten, zuerst an Kommas aufteilen und normalisieren (`tr ',+' '\n'`). Python macht es einfach, Bytes zu parsen und auszugeben, wenn die Formatierung inkonsistent ist.

## Referenzen

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
