# Esteganografía de texto

{{#include ../../banners/hacktricks-training.md}}

## Ruta práctica

Si el texto sin formato se comporta de forma inesperada, conserva la evidencia original, inspecciona sus puntos de código y normaliza solo una copia.

### Técnica

La esteganografía de texto suele basarse en caracteres que se representan de forma idéntica o invisible:

- Homoglifos: distintos puntos de código Unicode que se parecen (por ejemplo, la `a` latina y la `а` cirílica)<sup>[[1]](#references)</sup>
- Caracteres de ancho cero: unidores, separadores y espacios de ancho cero<sup>[[2]](#references)</sup>
- Codificaciones de espacios en blanco: espacios frente a tabulaciones, patrones de espacios finales y patrones deliberados de longitud de línea<sup>[[3]](#references)[[4]](#references)</sup>

Otros casos de alta relevancia:

- Controles bidireccionales, que pueden reordenar visualmente el texto<sup>[[1]](#references)</sup>
- Selectores de variación y caracteres combinantes, que pueden contener información oculta mientras mantienen el texto visible prácticamente sin cambios<sup>[[1]](#references)</sup>

### Herramientas de decodificación

- [Codificador/decodificador de homoglifos Unicode y caracteres de ancho cero](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Inspeccionar puntos de código

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## Canales de CSS `unicode-range`

Las reglas `@font-face` se pueden usar para codificar bytes en las entradas `unicode-range: U+..`. Extrae los puntos de código, concatena los valores hexadecimales y decodifícalos:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Si los rangos contienen varios valores por declaración, primero sepáralos por comas y normalízalos (`tr ',+' '\n'`). Python puede analizar y emitir los bytes cuando el formato es inconsistente.<sup>[[3]](#references)</sup>

## References

- [1] [Informe técnico Unicode n.º 36: Consideraciones de seguridad de Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Esteganografía Unicode con caracteres de ancho cero y homoglifos](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista de deseos de Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manual de Debian: esteganografía de espacios en blanco con `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
