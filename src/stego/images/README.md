# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los stego de imágenes en CTF se reducen a una de estas categorías:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Evaluación rápida

Prioriza la evidencia a nivel de contenedor antes del análisis profundo del contenido:

- Valida el archivo e inspecciona la estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae metadata y visible strings: `exiftool -a -u -g1`, `strings`.
- Verifica contenido embebido/adjunto: `binwalk` e inspección del final de archivo (`tail | xxd`).
- Divide según el contenedor:
  - PNG/BMP: bit-planes/LSB y anomalías a nivel de chunk.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: extracción de frames, frame differencing, trucos de paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP son populares en CTFs porque almacenan píxeles de una manera que facilita la **manipulación a nivel de bit**. El mecanismo clásico de ocultar/extraer es:

- Cada canal de píxel (`R`/`G`/`B`/`A`) tiene múltiples bits.
- El **bit menos significativo** (LSB) de cada canal cambia la imagen muy poco.
- Los atacantes ocultan datos en esos bits de menor peso, a veces con un stride, permutación o elección por canal.

Qué esperar en los retos:

- El payload está en un solo canal (por ejemplo, `R` LSB).
- El payload está en el canal alpha.
- El payload está comprimido/codificado después de la extracción.
- El mensaje está distribuido a través de planos o escondido mediante XOR entre planos.

Familias adicionales que puedes encontrar (dependen de la implementación):

- **LSB matching** (no solo invertir el bit, sino ajustes de +/-1 para coincidir con el bit objetivo)
- **Palette/index-based hiding** (indexed PNG/GIF: payload en índices de color en lugar de raw RGB)
- **Alpha-only payloads** (completamente invisibles en la vista RGB)

### Herramientas

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transformaciones (metadatos, transformaciones de imagen, brute forcing de variantes LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canal, inspección de planos, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG is a chunked format. In many challenges the payload is stored at the container/chunk level rather than in pixel values:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** that hide dimensions or break parsers until fixed

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Qué buscar:

- Combinaciones extrañas de width/height/bit-depth/colour-type
- CRC/chunk errors (pngcheck suele señalar el offset exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista de chunks más profunda:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referencias útiles:

- Especificación PNG (estructura, segmentos): https://www.w3.org/TR/PNG/
- Trucos de formato de archivo (PNG/JPEG/GIF casos límite): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Técnica

JPEG no se almacena como pixeles crudos; está comprimido en el DCT domain. Por eso JPEG stego tools difieren de PNG LSB tools:

- Metadata/comment payloads son a nivel de archivo (high-signal y rápido de inspeccionar)
- DCT-domain stego tools incrustan bits en los coeficientes de frecuencia

Operativamente, trate JPEG como:

- Un contenedor para segmentos de metadata (high-signal, rápido de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) donde operan stego tools especializadas

### Comprobaciones rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Ubicaciones de alta señal:

- metadatos EXIF/XMP/IPTC
- Segmento de comentario JPEG (`COM`)
- Segmentos de aplicación (`APP1` for EXIF, `APPn` for vendor data)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te enfrentas específicamente a payloads de steghide en JPEGs, considera usar `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA destaca diferentes artefactos de recompresión; puede señalarte regiones que fueron editadas, pero no es un detector de stego por sí mismo:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Imágenes animadas

### Técnica

Para imágenes animadas, asume que el mensaje está:

- En un solo fotograma (fácil), o
- Distribuido a través de fotogramas (el orden importa), o
- Solo visible cuando haces diff entre fotogramas consecutivos

### Extraer fotogramas
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Luego trata frames como PNGs normales: `zsteg`, `pngcheck`, channel isolation.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de frames)
- `imagemagick`/`magick` para transformaciones por frame

Frame differencing suele ser decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Incrustación protegida por contraseña

Si sospechas que la incrustación está protegida por una passphrase en lugar de una manipulación a nivel de píxeles, normalmente este es el camino más rápido.

### steghide

Soporta `JPEG, BMP, WAV, AU` y puede embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
No tengo acceso directo al repositorio. Por favor pega aquí el contenido de src/stego/images/README.md que quieres que traduzca.
```bash
stegcracker file.jpg wordlist.txt
```
Repositorio: https://github.com/Paradoxis/StegCracker

### stegpy

Soporta PNG/BMP/GIF/WebP/WAV.

Repositorio: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
