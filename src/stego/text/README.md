# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Cerca:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Percorso pratico

Se il plain text si comporta in modo inaspettato, ispeziona i codepoints e normalizza con attenzione (non distruggere le prove).

### Tecnica

Text stego si basa frequentemente su caratteri che appaiono identici (o invisibili):

- Homoglyphs: diversi codepoint Unicode che appaiono uguali (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Casi aggiuntivi ad alto segnale:

- Bidirectional override/control characters (possono riordinare visivamente il testo)
- Variation selectors and combining characters used as a covert channel

### Strumenti di decodifica

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Ispeziona codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canali `unicode-range` di CSS

`@font-face` rules can encode bytes in `unicode-range: U+..` entries. Le regole `@font-face` possono codificare byte nelle voci `unicode-range: U+..`. Estrai i codepoint, concatena gli esadecimali e decodifica:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se gli intervalli contengono più byte per dichiarazione, separa prima sulle virgole e normalizza (`tr ',+' '\n'`). Python rende semplice analizzare ed emettere byte se il formato è inconsistente.

## Riferimenti

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
