# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los CTF image stego se reducen a una de estas categorías:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioriza la evidencia a nivel de contenedor antes del análisis profundo del contenido:

- Valida el archivo e inspecciona la estructura: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extrae metadata y cadenas visibles: `exiftool -a -u -g1`, `strings`.
- Comprueba contenido embebido/adjunto: `binwalk` e inspección del final de archivo (`tail | xxd`).
- Según el contenedor:
- PNG/BMP: bit-planes/LSB y anomalías a nivel de chunks.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: extracción de frames, diferencias entre frames, trucos de paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP son populares en los CTFs porque almacenan píxeles de una forma que facilita la **manipulación a nivel de bits**. El mecanismo clásico de ocultar/extraer es:

- Cada canal de píxel (R/G/B/A) tiene múltiples bits.
- El **bit menos significativo** (LSB) de cada canal cambia la imagen muy poco.
- Los atacantes ocultan datos en esos bits de orden bajo, a veces con un stride, permutación o elección por canal.

Qué esperar en los desafíos:

- El payload está en un solo canal (p. ej., `R` LSB).
- El payload está en el canal alpha.
- El payload está comprimido/codificado después de la extracción.
- El mensaje está distribuido entre planos o oculto mediante XOR entre planos.

Familias adicionales que puede encontrar (dependiente de la implementación):

- **LSB matching** (no solo voltear el bit, sino ajustes de +/-1 para igualar el bit objetivo)
- **Palette/index-based hiding** (indexed PNG/GIF: payload en índices de color en lugar de RGB crudo)
- **Alpha-only payloads** (completamente invisibles en la vista RGB)

### Tooling

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transformaciones (metadatos, transformaciones de imagen, fuerza bruta contra variantes LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT no es extracción LSB; se usa para casos donde el contenido está deliberadamente oculto en el espacio de frecuencia o en patrones sutiles.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage web frecuentemente usado en CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Estructura interna de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato por chunks. En muchos retos el payload se almacena a nivel del contenedor/chunk en lugar de en los valores de píxel:

- **Bytes extra después de `IEND`** (muchos visores ignoran los bytes finales)
- **Chunks auxiliares no estándar** que contienen payloads
- **Cabeceras corruptas** que ocultan dimensiones o rompen parsers hasta que se corrigen

Ubicaciones de chunks de alta señal para revisar:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks auxiliares usados como portador
- `eXIf` (datos EXIF en PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Qué buscar:

- Combinaciones extrañas de width/height/bit-depth/colour-type
- Errores CRC/chunk (pngcheck suele indicar el offset exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista de chunks más detallada:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referencias útiles:

- Especificación de PNG (estructura, chunks): https://www.w3.org/TR/PNG/
- Trucos de formato de archivo (PNG/JPEG/GIF casos límite): https://github.com/corkami/docs

## JPEG: metadatos, herramientas DCT-domain y limitaciones de ELA

### Técnica

JPEG no se almacena como píxeles en bruto; se comprime en el dominio DCT. Por eso las herramientas stego para JPEG difieren de las herramientas LSB para PNG:

- Los payloads en metadatos/comentarios son a nivel de archivo (alta señal y rápidos de inspeccionar)
- Las herramientas stego en el dominio DCT insertan bits en los coeficientes de frecuencia

Operativamente, trata JPEG como:

- Un contenedor para segmentos de metadatos (alta señal, rápidos de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) donde operan herramientas stego especializadas

### Comprobaciones rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Ubicaciones de alta señal:

- EXIF/XMP/IPTC metadatos
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te encuentras específicamente con payloads de steghide en JPEGs, considera usar `stegseek` (bruteforce más rápido que scripts más antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA resalta diferentes artefactos de recompresión; puede señalarte regiones que fueron editadas, pero no es un stego detector por sí mismo:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imágenes animadas

### Técnica

Para imágenes animadas, asume que el mensaje está:

- En un solo fotograma (fácil), o
- Distribuido a lo largo de fotogramas (el orden importa), o
- Solo visible cuando hagas diff entre fotogramas consecutivos

### Extraer fotogramas
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Luego trate los fotogramas como PNGs normales: `zsteg`, `pngcheck`, aislamiento de canales.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de fotogramas)
- `imagemagick`/`magick` para transformaciones por fotograma

La diferencia entre fotogramas suele ser decisiva:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Embedding protegido por contraseña

Si sospechas que el embedding está protegido por una passphrase en lugar de manipulación a nivel de píxel, este suele ser el camino más rápido.

### steghide

Soporta `JPEG, BMP, WAV, AU` y puede embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
No tengo acceso directo al contenido del archivo. Por favor, pega aquí el contenido de src/stego/images/README.md (o la sección "StegCracker") que quieres que traduzca al español.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Admite PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
