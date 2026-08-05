# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Achte auf:

- Unicode-Homoglyphen
- Zero-width-Zeichen
- Whitespace-Muster (Leerzeichen vs. Tabs)

## Praktischer Ansatz

Wenn sich Klartext unerwartet verhält, überprüfe die Codepoints und normalisiere vorsichtig (zerstöre keine Beweise).

### Technik

Text stego basiert häufig auf Zeichen, die identisch (oder unsichtbar) dargestellt werden:

- Homoglyphen: unterschiedliche Unicode-Codepoints, die gleich aussehen (lateinisches `a` vs. kyrillisches `а`)
- Zero-width-Zeichen: Joiner, Non-Joiner und Zero-width-Spaces
- Whitespace-Encodings: Leerzeichen vs. Tabs, nachgestellte Leerzeichen, Muster bei der Zeilenlänge<sup>[[1]](#references)</sup>

Weitere Fälle mit hoher Aussagekraft:

- Bidirektionale Override-/Steuerzeichen (können Text visuell neu anordnen)
- Variation Selectors und Combining Characters, die als Covert Channel verwendet werden

### Decode-Hilfsmittel

- Unicode-Homoglyph-/Zero-width-Playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Codepoints überprüfen
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS-`unicode-range`-Kanäle

`@font-face`-Regeln können Bytes in `unicode-range: U+..`-Einträgen codieren. Extrahiere die Codepoints, verkette die Hexadezimalwerte und dekodiere sie:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Wenn Bereiche mehrere Bytes pro Deklaration enthalten, trenne zuerst an Kommas und normalisiere (`tr ',+' '\n'`). Python macht es einfach, Bytes zu parsen und auszugeben, wenn die Formatierung inkonsistent ist.

## Referenzen

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
