# Flujo de trabajo de Stego

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas de stego se resuelven más rápido mediante un triaje sistemático que probando herramientas al azar.

## Flujo principal

### Lista de verificación rápida de triaje

El objetivo es responder dos preguntas de forma eficiente:

1. ¿Cuál es el contenedor/formato real?
2. ¿Está la payload en metadata, appended bytes, embedded files, o content-level stego?

#### 1) Identificar el container
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
Si la extracción falla pero se detectan firmas, extrae manualmente a partir de offsets con `dd` y vuelve a ejecutar `file` en la región extraída.

#### 4) Si es imagen

- Inspeccionar anomalías: `magick identify -verbose file`
- Si PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Validar la estructura PNG: `pngcheck -v file.png`
- Usa filtros visuales (Stegsolve / StegoVeritas) cuando el contenido pueda revelarse mediante transformaciones de canal/plano

#### 5) Si es audio

- Primero, espectrograma (Sonic Visualiser)
- Decodificar/inspeccionar streams: `ffmpeg -v info -i file -f null -`
- Si el audio se asemeja a tonos estructurados, prueba la decodificación DTMF

### Herramientas básicas

Estas detectan los casos frecuentes a nivel de contenedor: metadata, payloads, bytes añadidos y archivos embebidos disfrazados por la extensión.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
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
### Contenedores, datos añadidos y trucos polyglot

Muchos retos de steganography son bytes extra después de un archivo válido, o archivos embebidos disfrazados por la extensión.

#### Payloads añadidos

Muchos formatos ignoran los bytes finales. A ZIP/PDF/script puede ser añadido al final de un contenedor de imagen/audio.

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
#### Bytes mágicos

Cuando `file` está confundido, busca bytes mágicos con `xxd` y compáralos con firmas conocidas:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prueba `7z` y `unzip` incluso si la extensión no indica zip:
```bash
7z l file
unzip -l file
```
### Rarezas cerca de stego

Enlaces rápidos para patrones que aparecen con regularidad junto a stego (QR-from-binary, braille, etc).

#### QR codes from binary

Si la longitud de un blob es un cuadrado perfecto, puede tratarse de píxeles en bruto para una imagen/QR.
```python
import math
math.isqrt(2500)  # 50
```
Conversor de binario a imagen:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Listas de referencia

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
