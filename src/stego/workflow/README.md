# Flujo de trabajo de Stego

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas de stego se resuelven más rápido mediante una clasificación sistemática que probando herramientas al azar.

## Flujo principal

### Lista de comprobación de clasificación rápida

El objetivo es responder eficientemente a dos preguntas:

1. ¿Cuál es el contenedor/formato real?
2. ¿Está el payload en los metadatos, en bytes añadidos, en archivos incrustados o en stego a nivel de contenido?

#### 1) Identificar el contenedor
```bash
file target
ls -lah target
```
Si `file` y la extensión no coinciden, investiga la firma en lugar de confiar en el sufijo. `file` también es heurístico y puede confundirse con entradas malformadas o polyglot. Trata los formatos comunes como contenedores cuando corresponda (por ejemplo, los documentos OOXML son paquetes ZIP).<sup>[[2]](#references)</sup>

#### 2) Busca metadatos y cadenas obvias
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Prueba múltiples codificaciones:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Comprobar si hay datos añadidos / archivos incrustados
```bash
binwalk target
binwalk -e target
```
Si la extracción falla, pero se reportan firmas, extrae manualmente los offsets con `dd` y vuelve a ejecutar `file` en la región extraída.

#### 4) Si es una imagen

- Inspecciona anomalías: `magick identify -verbose file`
- Si es PNG/BMP, enumera los bit-planes/LSB: `zsteg -a file.png`
- Valida la estructura PNG: `pngcheck -v file.png`
- Usa filtros visuales (Stegsolve / StegoVeritas) cuando el contenido pueda revelarse mediante transformaciones de canales/planos

#### 5) Si es audio

- Primero, genera un espectrograma (Sonic Visualiser)
- Decodifica/inspecciona los streams: `ffmpeg -v info -i file -f null -`
- Si el audio se parece a tonos estructurados, prueba la decodificación DTMF

### Herramientas básicas

Estas detectan casos frecuentes a nivel de contenedor: payloads en metadatos, bytes añadidos y archivos incrustados disfrazados mediante su extensión.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Repositorio del proyecto: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### archivo / cadenas
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contenedores, datos añadidos y trucos de poliglotas

Muchos desafíos de esteganografía consisten en bytes adicionales después de un archivo válido o en archivos comprimidos incrustados cuyo formato se disimula mediante la extensión.

#### Payloads añadidos

Muchos formatos ignoran los bytes finales. Se puede añadir un ZIP/PDF/script a un contenedor de imagen/audio.

Comprobaciones rápidas:
```bash
binwalk file
tail -c 200 file | xxd
```
Si conoces un offset, haz carving con `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Cuando `file` se confunda, busca magic bytes con `xxd` y compáralos con firmas conocidas:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prueba `7z` y `unzip` aunque la extensión no indique que es un zip:
```bash
7z l file
unzip -l file
```
### Rarezas cercanas a stego

Enlaces rápidos para patrones que aparecen habitualmente junto a stego (QR a partir de binario, braille, etc.).

#### Códigos QR a partir de binario

Si la longitud de un blob es un cuadrado perfecto, puede tratarse de píxeles sin procesar para una imagen/QR.
```python
import math
math.isqrt(2500)  # 50
```
Ayudante de binario a imagen:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Traductor de Braille de Branah.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Imagen Docker con las herramientas de esteganografía más populares incluidas](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenciones de empaquetado abierto de ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Imagen binaria](https://www.dcode.fr/binary-image)
- [6] [Branah — Traductor de Braille](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
