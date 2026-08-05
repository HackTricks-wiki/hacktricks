# Esteganografía de texto

{{#include ../../banners/hacktricks-training.md}}

Busca:

- Homoglifos Unicode
- Caracteres de ancho cero
- Patrones de espacios en blanco (espacios frente a tabulaciones)

## Ruta práctica

Si el texto sin formato se comporta de forma inesperada, inspecciona los puntos de código y normaliza con cuidado (no destruyas las evidencias).

### Técnica

El stego de texto suele depender de caracteres que se representan de forma idéntica (o invisible):

- Homoglifos: distintos puntos de código Unicode que parecen iguales (la `a` latina frente a la `а` cirílica)
- Caracteres de ancho cero: unificadores, no unificadores y espacios de ancho cero
- Codificaciones mediante espacios en blanco: espacios frente a tabulaciones, espacios finales y patrones de longitud de línea<sup>[[1]](#references)</sup>

Casos adicionales de alta señal:

- Caracteres de control/sobrescritura bidireccionales (pueden reordenar visualmente el texto)
- Selectores de variación y caracteres combinados utilizados como canal encubierto

### Ayudas para decodificar

- Entorno de pruebas de homoglifos Unicode y caracteres de ancho cero: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspecciona los puntos de código
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canales `unicode-range` de CSS

Las reglas `@font-face` pueden codificar bytes en entradas `unicode-range: U+..`. Extrae los codepoints, concatena el hexadecimal y decodifica:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si los rangos contienen varios bytes por declaración, sepáralos primero por comas y normalízalos (`tr ',+' '\n'`). Python facilita el análisis y la emisión de bytes cuando el formato es inconsistente.

## Referencias

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
