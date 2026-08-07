# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Suche nach:

- Unicode-Homoglyphen
- Zero-width characters
- Whitespace-Mustern (Leerzeichen vs. Tabs)

## Praktischer Ansatz

Wenn sich Klartext unerwartet verhält, überprüfe die Codepoints und normalisiere vorsichtig (zerstöre keine Beweise).

### Technique

Text-Stego beruht häufig auf Zeichen, die identisch (oder unsichtbar) dargestellt werden:

- Homoglyphen: unterschiedliche Unicode-Codepoints, die gleich aussehen (lateinisches `a` vs. kyrillisches `а`)
- Zero-width characters: Joiner, Non-Joiner und Zero-width spaces
- Whitespace encodings: Leerzeichen vs. Tabs, nachgestellte Leerzeichen, Muster der Zeilenlänge<sup>[[1]](#references)</sup>

Weitere Fälle mit hoher Aussagekraft:

- Bidirectional override/control characters (können Text visuell neu anordnen)
- Variation selectors und combining characters, die als covert channel verwendet werden

### Decode helpers

- Unicode-Homoglyphen/Zero-width-playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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

`@font-face`-Regeln können Bytes in `unicode-range: U+..`-Einträgen kodieren. Extrahiere die Codepoints, füge das Hex zusammen und dekodiere:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Wenn ranges mehrere Bytes pro Deklaration enthalten, teile sie zuerst an Kommas auf und normalisiere sie (`tr ',+' '\n'`). Python macht es einfach, Bytes zu parsen und auszugeben, wenn die Formatierung inkonsistent ist.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
