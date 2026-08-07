# Workflow de Stego

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los problemas de stego se resuelven más rápido mediante un triage sistemático que probando herramientas al azar.

## Flujo principal

### Checklist de triage rápido

El objetivo es responder eficientemente a dos preguntas:

1. ¿Cuál es el contenedor/formato real?
2. ¿El payload está en los metadatos, en bytes añadidos, en archivos incrustados o en stego a nivel de contenido?

#### 1) Identificar el contenedor
```bash
file target
ls -lah target
```
Si `file` y la extensión no coinciden, confía en `file`. Trata los formatos comunes como contenedores cuando corresponda (por ejemplo, los documentos OOXML son archivos ZIP).

#### 2) Busca metadatos y cadenas evidentes
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
#### 3) Comprobar datos anexados / archivos incrustados
```bash
binwalk target
binwalk -e target
```
Si la extracción falla pero se reportan firmas, extrae manualmente los offsets con `dd` y vuelve a ejecutar `file` en la región extraída.

#### 4) Si es una imagen

- Inspecciona las anomalías: `magick identify -verbose file`
- Si es PNG/BMP, enumera los bit-planes/LSB: `zsteg -a file.png`
- Valida la estructura PNG: `pngcheck -v file.png`
- Usa filtros visuales (Stegsolve / StegoVeritas) cuando el contenido pueda revelarse mediante transformaciones de canales/planos

#### 5) Si es audio

- Primero, obtén el espectrograma (Sonic Visualiser)
- Decodifica/inspecciona los streams: `ffmpeg -v info -i file -f null -`
- Si el audio se parece a tonos estructurados, prueba la decodificación DTMF

### Herramientas básicas

Estas detectan los casos más frecuentes a nivel de contenedor: payloads en metadatos, bytes añadidos y archivos incrustados ocultos mediante la extensión.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### archivo / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contenedores, datos anexados y trucos polyglot

Muchos desafíos de esteganografía consisten en bytes adicionales después de un archivo válido o en archives incrustados ocultos mediante la extensión.

#### Payloads anexados

Muchos formatos ignoran los bytes finales. Un ZIP/PDF/script puede anexarse a un contenedor de imagen/audio.

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

Prueba `7z` y `unzip` aunque la extensión no indique que sea zip:
```bash
7z l file
unzip -l file
```
### Rarezas cercanas a stego

Enlaces rápidos para patrones que aparecen regularmente junto a stego (QR desde binario, braille, etc.).

#### QR codes desde binario

Si la longitud de un blob es un cuadrado perfecto, puede tratarse de píxeles sin procesar para una imagen/QR.
```python
import math
math.isqrt(2500)  # 50
```
Ayuda de binary-to-image:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referencias

- [1] [DominicBreuker/stego-toolkit - Docker image con las herramientas de steganography más populares incluidas](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
