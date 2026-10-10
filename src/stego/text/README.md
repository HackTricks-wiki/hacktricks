# Esteganografia de texto

{{#include ../../banners/hacktricks-training.md}}

## Caminho prático

Se o texto simples se comportar de forma inesperada, preserve as evidências originais, inspecione seus pontos de código e normalize apenas uma cópia.

### Técnica

A esteganografia de texto frequentemente se baseia em caracteres que são renderizados de forma idêntica ou invisível:

- Homoglifos: pontos de código Unicode diferentes que parecem iguais (por exemplo, `a` latino e `а` cirílico)<sup>[[1]](#references)</sup>
- Caracteres de largura zero: juntadores, não juntadores e espaços de largura zero<sup>[[2]](#references)</sup>
- Codificações de espaços em branco: espaços versus tabulações, padrões de espaços finais e padrões deliberados de comprimento de linha<sup>[[3]](#references)[[4]](#references)</sup>

Casos adicionais de alto sinal:

- Controles bidirecionais, que podem reordenar visualmente o texto<sup>[[1]](#references)</sup>
- Seletores de variação e caracteres combinantes, que podem carregar estado oculto enquanto mantêm o texto visível quase inalterado<sup>[[1]](#references)</sup>

### Auxiliares de decodificação

- [Codificador/decodificador de homoglifos Unicode e caracteres de largura zero](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Inspecionar pontos de código

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

As regras `@font-face` podem ser abusadas para codificar bytes em entradas `unicode-range: U+..`. Extraia os codepoints, concatene os valores hexadecimais e decodifique-os:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Se os intervalos contiverem vários valores por declaração, divida primeiro pelas vírgulas e normalize (`tr ',+' '\n'`). Python pode analisar e emitir os bytes quando a formatação for inconsistente.<sup>[[3]](#references)</sup>

## References

- [1] [Relatório Técnico Unicode nº 36: Considerações de segurança do Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Esteganografia Unicode com caracteres de largura zero e homoglifos](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista de desejos do Papai Noel](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manual do Debian: esteganografia de espaços em branco com `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
