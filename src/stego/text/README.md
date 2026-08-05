# Esteganografia de Texto

{{#include ../../banners/hacktricks-training.md}}

Procure por:

- Homoglyphs Unicode
- Caracteres de largura zero
- Padrões de whitespace (espaços vs tabs)

## Caminho prático

Se o texto simples se comportar de forma inesperada, inspecione os codepoints e normalize-o cuidadosamente (não destrua as evidências).

### Técnica

A esteganografia de texto frequentemente depende de caracteres que são renderizados de forma idêntica (ou invisível):

- Homoglyphs: diferentes codepoints Unicode que parecem iguais (`a` latino vs `а` cirílico)
- Caracteres de largura zero: joiners, non-joiners e espaços de largura zero
- Codificações de whitespace: espaços vs tabs, espaços no final e padrões de comprimento de linha<sup>[[1]](#references)</sup>

Casos adicionais de alto sinal:

- Caracteres de controle/override bidirecionais (podem reordenar visualmente o texto)
- Selectors de variação e caracteres combinantes usados como um canal encoberto

### Auxiliares de decodificação

- Ambiente de testes de Homoglyphs Unicode/caracteres de largura zero: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspecione os codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canais `unicode-range` do CSS

As regras `@font-face` podem codificar bytes em entradas `unicode-range: U+..`. Extraia os codepoints, concatene o hexadecimal e decodifique:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se os intervalos contiverem vários bytes por declaração, divida primeiro nas vírgulas e normalize (`tr ',+' '\n'`). O Python facilita a análise e a emissão de bytes quando a formatação é inconsistente.

## Referências

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
