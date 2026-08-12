# Esteganografía de texto

{{#include ../../banners/hacktricks-training.md}}

## Ruta práctica

Si el texto plano se comporta de forma inesperada, conserva la evidencia original, inspecciona sus codepoints y normaliza únicamente una copia.

### Técnica

La esteganografía de texto suele basarse en caracteres que se representan de forma idéntica o invisible:

- Homoglyphs: diferentes codepoints de Unicode que parecen iguales (por ejemplo, la `a` latina y la `а` cirílica)<sup>[[1]](#references)</sup>
- Caracteres de ancho cero: joiners, non-joiners y espacios de ancho cero<sup>[[2]](#references)</sup>
- Codificaciones de espacios en blanco: espacios frente a tabulaciones, patrones de espacios finales y patrones deliberados de longitud de línea<sup>[[3]](#references)[[4]](#references)</sup>

Casos adicionales de alta señal:

- Controles bidireccionales, que pueden reordenar visualmente el texto<sup>[[1]](#references)</sup>
- Selectores de variación y caracteres combinantes, que pueden transportar un estado oculto mientras dejan el texto visible prácticamente sin cambios<sup>[[1]](#references)</sup>

### Helpers de decodificación

- [Codificador/decodificador de homoglyphs de Unicode y caracteres de ancho cero](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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
## Canales de `unicode-range` de CSS

Las reglas `@font-face` pueden abusarse para codificar bytes en entradas `unicode-range: U+..`. Extrae los codepoints, concatena los valores hexadecimales y decodifícalos:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si los rangos contienen varios valores por declaración, sepáralos primero por comas y normalízalos (`tr ',+' '\n'`). Python puede analizar y emitir los bytes cuando el formato es inconsistente.<sup>[[3]](#references)</sup>

## References

- [1] [Informe técnico Unicode n.º 36: Consideraciones de seguridad de Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganografía Unicode con caracteres de ancho cero y homoglifos](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — La lista de deseos de Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manual de Debian: esteganografía de espacios en blanco con `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
