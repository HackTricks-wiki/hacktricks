# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas de stego se resuelven más rápido mediante un triage sistemático que probando herramientas al azar.

## Flujo principal

### Lista de verificación rápida de triage

El objetivo es responder dos preguntas de forma eficiente:

1. ¿Cuál es el contenedor/formato real?
2. ¿Está la payload en metadata, bytes añadidos, archivos embebidos, o stego a nivel de contenido?

#### 1) Identificar el contenedor
```bash
file target
ls -lah target
```
Si `file` y la extensión no coinciden, confía en `file`. Trata los formatos comunes como contenedores cuando corresponda (p. ej., los documentos OOXML son archivos ZIP).

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
#### 3) Comprobar datos añadidos / archivos incrustados
```bash
binwalk target
binwalk -e target
```
Si la extracción falla pero se reportan firmas, realiza carving de offsets manualmente con `dd` y vuelve a ejecutar `file` en la región extraída.

#### 4) Si es imagen

- Inspecciona anomalías: `magick identify -verbose file`
- Si PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Valida la estructura PNG: `pngcheck -v file.png`
- Usa filtros visuales (Stegsolve / StegoVeritas) cuando el contenido pueda revelarse mediante transformaciones de canal/plano

#### 5) Si es audio

- Primero, espectrograma (Sonic Visualiser)
- Decodifica/inspecciona flujos: `ffmpeg -v info -i file -f null -`
- Si el audio se asemeja a tonos estructurados, prueba la decodificación DTMF

### Herramientas básicas

Estas detectan los casos a nivel de contenedor de alta frecuencia: metadatos payloads, bytes añadidos y archivos embebidos disfrazados por la extensión.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
No has proporcionado el contenido de src/stego/workflow/README.md. Pega aquí el texto (o la sección) que quieres que traduzca y lo traduciré al español manteniendo exactamente la misma sintaxis Markdown/HTML y respetando las reglas que indicaste (no traducir código, nombres de técnicas, plataformas, enlaces, rutas ni tags). ¿Quieres que traduzca todo el archivo o solo la sección "Foremost"?
```bash
foremost -i file
```
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
### Contenedores, datos añadidos y polyglot tricks

Muchos desafíos de steganografía consisten en bytes adicionales después de un archivo válido, o en archivos incrustados disfrazados por la extensión.

#### Appended payloads

Muchos formatos ignoran los bytes finales. Un ZIP/PDF/script puede ser añadido a un contenedor de imagen/audio.

Comprobaciones rápidas:
```bash
binwalk file
tail -c 200 file | xxd
```
Si conoces un offset, carve con `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Cuando `file` se confunde, busca magic bytes con `xxd` y compáralos con firmas conocidas:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prueba `7z` y `unzip` incluso si la extensión no dice zip:
```bash
7z l file
unzip -l file
```
### Anomalías cercanas a stego

Enlaces rápidos para patrones que aparecen con regularidad junto a stego (QR-from-binary, braille, etc).

#### Códigos QR a partir de binary
```python
import math
math.isqrt(2500)  # 50
```
Herramienta de binario a imagen:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Listas de referencia

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
