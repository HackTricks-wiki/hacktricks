# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Buscar:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Ruta práctica

Si plain text se comporta de forma inesperada, inspecciona los codepoints y normaliza con cuidado (no destruyas evidencia).

### Técnica

Text stego frecuentemente se basa en caracteres que se muestran idénticamente (o son invisibles):

- Homoglyphs: diferentes Unicode codepoints que parecen iguales (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Casos adicionales de alta señal:

- Bidirectional override/control characters (pueden reordenar visualmente el texto)
- Variation selectors and combining characters usados como canal encubierto

### Herramientas de decodificación

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
{{#include ../../banners/hacktricks-training.md}}
