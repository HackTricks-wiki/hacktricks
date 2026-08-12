# Esteganografia de Texto

{{#include ../../banners/hacktricks-training.md}}

## Caminho prático

Se o texto simples se comportar de forma inesperada, preserve a evidência original, inspecione seus codepoints e normalize apenas uma cópia.

### Técnica

A esteganografia de texto frequentemente depende de caracteres que são renderizados de forma idêntica ou invisível:

- Homoglyphs: diferentes codepoints Unicode que parecem iguais (por exemplo, o `a` latino e o `а` cirílico)<sup>[[1]](#references)</sup>
- Caracteres de largura zero: joiners, non-joiners e espaços de largura zero<sup>[[2]](#references)</sup>
- Codificações de whitespace: espaços versus tabulações, padrões de espaços à direita e padrões deliberados de comprimento de linha<sup>[[3]](#references)[[4]](#references)</sup>

Casos adicionais de alto sinal:

- Controles bidirecionais, que podem reordenar visualmente o texto<sup>[[1]](#references)</sup>
- Seletores de variação e caracteres combinantes, que podem carregar um estado oculto enquanto deixam o texto visível praticamente inalterado<sup>[[1]](#references)</sup>

### Auxiliares de decodificação

- [Codificador/decodificador de homoglyphs Unicode e caracteres de largura zero](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

As regras `@font-face` podem ser abusadas para codificar bytes em entradas `unicode-range: U+..`. Extraia os codepoints, concatene os valores hexadecimais e decodifique-os:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se os intervalos contiverem vários valores por declaração, divida primeiro pelas vírgulas e normalize (`tr ',+' '\n'`). O Python pode analisar e emitir os bytes quando a formatação é inconsistente.<sup>[[3]](#references)</sup>

## References

- [1] [Relatório Técnico Unicode #36: Considerações de Segurança do Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganography Unicode com Caracteres de Largura Zero e Homoglyphs](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista de Desejos do Papai Noel](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manual do Debian: stegsnow whitespace steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
