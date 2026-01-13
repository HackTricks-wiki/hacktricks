# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Procure por:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Caminho prático

Se plain text se comportar de forma inesperada, inspecione codepoints e normalize cuidadosamente (não destrua evidências).

### Técnica

Text stego frequentemente depende de caracteres que são renderizados de forma idêntica (ou invisíveis):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Casos adicionais de alto sinal:

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Ajuda para decodificação

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
## CSS `unicode-range` canais

Regras `@font-face` podem codificar bytes em entradas `unicode-range: U+..`. Extraia os pontos de código, concatene os valores hexadecimais e decodifique:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se os intervalos contiverem múltiplos bytes por declaração, separe por vírgulas primeiro e normalize (`tr ',+' '\n'`). Python facilita analisar e emitir bytes se a formatação for inconsistente.

## Referências

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
