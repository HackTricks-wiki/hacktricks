# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Buscar:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Ruta práctica

Si el texto plano se comporta de forma inesperada, inspecciona los codepoints y normaliza con cuidado (no destruyas la evidencia).

### Técnica

Text stego frecuentemente se basa en caracteres que se representan idénticamente (o de forma invisible):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Casos adicionales de alto interés:

- Bidirectional override/control characters (pueden reordenar visualmente el texto)
- Variation selectors and combining characters usados como un canal encubierto

### Herramientas para decodificar

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspeccionar codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canales CSS `unicode-range`

Las reglas `@font-face` pueden codificar bytes en entradas `unicode-range: U+..`. Extrae los codepoints, concatena el hex y decodifica:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si los rangos contienen múltiples bytes por declaración, primero sepáralos por comas y normalízalos (`tr ',+' '\n'`). Python facilita analizar y emitir bytes si el formato es inconsistente.

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
