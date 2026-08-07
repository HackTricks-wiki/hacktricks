# Esteganografia de Texto

{{#include ../../banners/hacktricks-training.md}}

Procure por:

- Homoglyphs Unicode
- Caracteres de largura zero
- Padrões de espaços em branco (espaços vs tabs)

## Abordagem prática

Se o texto simples se comportar de forma inesperada, inspecione os codepoints e normalize cuidadosamente (não destrua as evidências).

### Técnica

A esteganografia em texto frequentemente depende de caracteres que são renderizados de forma idêntica (ou invisível):

- Homoglyphs: diferentes codepoints Unicode que parecem iguais (`a` latino vs `а` cirílico)
- Caracteres de largura zero: joiners, non-joiners e espaços de largura zero
- Codificações por espaços em branco: espaços vs tabs, espaços no final das linhas e padrões de comprimento de linha<sup>[[1]](#references)</sup>

Casos adicionais de alto sinal:

- Caracteres de controle/sobrescrita bidirecional (podem reordenar visualmente o texto)
- Seletores de variação e caracteres combinantes usados como um canal secreto

### Auxiliares de decodificação

- Playground de homoglyphs Unicode/caracteres de largura zero: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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
## Canais `unicode-range` de CSS

As regras `@font-face` podem codificar bytes em entradas `unicode-range: U+..`. Extraia os codepoints, concatene os valores hexadecimais e decodifique:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se os ranges contiverem múltiplos bytes por declaração, divida primeiro nas vírgulas e normalize (`tr ',+' '\n'`). Python facilita a análise e a emissão de bytes quando a formatação é inconsistente.<sup>[[1]](#references)</sup>

## Referências

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
