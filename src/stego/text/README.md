# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Procure por:

- Unicode homoglyphs
- Zero-width characters
- Padrões de whitespace (spaces vs tabs)

## Caminho prático

Se plain text se comportar inesperadamente, inspecione codepoints e normalize cuidadosamente (não destrua evidências).

### Técnica

Text stego frequentemente depende de caracteres que são renderizados de forma idêntica (ou invisível):

- Homoglyphs: diferentes Unicode codepoints que parecem iguais (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, padrões de comprimento de linha

Casos adicionais de alto sinal:

- Bidirectional override/control characters (podem reordenar visualmente o texto)
- Variation selectors and combining characters usados como um covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspecionar codepoints
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
