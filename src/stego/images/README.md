# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La mayoría del image stego en CTF se reduce a una de estas categorías:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage rápido

Prioriza la evidencia a nivel de contenedor antes del análisis profundo del contenido:

- Valida el archivo e inspecciona la estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae metadata y cadenas visibles: `exiftool -a -u -g1`, `strings`.
- Busca contenido embebido/añadido: `binwalk` e inspección del final de archivo (`tail | xxd`).
- Ramifica según el contenedor:
- PNG/BMP: bit-planes/LSB y anomalías a nivel de chunk.
- JPEG: metadata + herramientas en dominio DCT (OutGuess/F5-style families).
- GIF/APNG: extracción de frames, diferencia de frames, trucos con la paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP son populares en CTFs porque almacenan píxeles de una manera que facilita la **manipulación a nivel de bit**. El mecanismo clásico para ocultar/extraer es:

- Cada canal de píxel (R/G/B/A) tiene múltiples bits.
- El **least significant bit** (LSB) de cada canal cambia muy poco la imagen.
- Los atacantes ocultan datos en esos bits de menor orden, a veces con un stride, permutación o elección por canal.

Qué esperar en los retos:

- El payload está solo en un canal (p. ej., `R` LSB).
- El payload está en el canal alpha.
- El payload está comprimido/codificado tras la extracción.
- El mensaje está distribuido entre planos o escondido mediante XOR entre planos.

Familias adicionales que puedes encontrar (dependen de la implementación):

- **LSB matching** (no solo invertir el bit, sino ajustes de +/-1 para coincidir con el bit objetivo)
- **Palette/index-based hiding** (indexed PNG/GIF: payload en índices de color en lugar de RGB crudo)
- **Alpha-only payloads** (completamente invisible en la vista RGB)

### Tooling

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
Repositorio: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transformaciones (metadatos, transformaciones de imagen, fuerza bruta de variantes LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc).

Descarga de Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT no es extracción LSB; se usa para casos donde el contenido está deliberadamente oculto en el espacio de frecuencias o en patrones sutiles.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage web frecuentemente usado en CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internos de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato por chunks. En muchos retos el payload se almacena a nivel de contenedor/chunk en lugar de en los valores de píxel:

- **Bytes extra después de `IEND`** (muchos visores ignoran los bytes al final)
- **Chunks ancilares no estándar** que contienen payloads
- **Cabeceras corruptas** que ocultan dimensiones o rompen parsers hasta que se corrigen

Ubicaciones de chunks de alta señal para revisar:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks ancilares usados como portador
- `eXIf` (datos EXIF en PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Qué buscar:

- Combinaciones extrañas de width/height/bit-depth/colour-type
- Errores CRC/chunk (pngcheck normalmente señala el offset exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista más profunda de los chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referencias útiles:

- Especificación PNG (estructura, chunks): https://www.w3.org/TR/PNG/
- Trucos de formatos de archivo (casos límite PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadatos, herramientas en el dominio DCT y limitaciones de ELA

### Técnica

JPEG no se almacena como píxeles sin procesar; está comprimido en el dominio DCT. Por eso las herramientas stego para JPEG difieren de las herramientas LSB para PNG:

- Los payloads de metadata/comentario están a nivel de archivo (alta señal y rápidos de inspeccionar)
- Las herramientas stego en el dominio DCT incrustan bits en los coeficientes de frecuencia

Operativamente, trata JPEG como:

- Un contenedor para segmentos de metadata (alta señal, rápidos de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) donde operan herramientas stego especializadas

### Comprobaciones rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Ubicaciones de alta señal:

- Metadatos EXIF/XMP/IPTC
- Segmento de comentario JPEG (`COM`)
- Segmentos de aplicación (`APP1` para EXIF, `APPn` para datos del proveedor)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te enfrentas específicamente a payloads de steghide en JPEGs, considera usar `stegseek` (bruteforce más rápido que scripts antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA resalta diferentes artefactos de recompresión; puede señalarte regiones que fueron editadas, pero no es un stego detector por sí mismo:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imágenes animadas

### Técnica

Para imágenes animadas, asume que el mensaje está:

- En un solo fotograma (fácil), o
- Repartido a lo largo de fotogramas (el orden importa), o
- Solo visible cuando haces diff entre fotogramas consecutivos

### Extraer fotogramas
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Luego trata los fotogramas como PNG normales: `zsteg`, `pngcheck`, aislamiento de canales.

Alternative tooling:

- `gifsicle --explode anim.gif` (extracción rápida de fotogramas)
- `imagemagick`/`magick` para transformaciones por fotograma

Las diferencias entre fotogramas suelen ser decisivas:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG codificación por conteo de píxeles

- Detectar contenedores APNG: `exiftool -a -G1 file.png | grep -i animation` o `file`.
- Extraer fotogramas sin re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recuperar payloads codificados como conteos de píxeles por fotograma:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Los retos animados pueden codificar cada byte como la cantidad de un color específico en cada fotograma; concatenar esas cantidades reconstruye el mensaje.

## Incrustación protegida por contraseña

Si sospechas que la incrustación está protegida por una passphrase en lugar de manipulación a nivel de píxel, esta suele ser la vía más rápida.

### steghide

Soporta `JPEG, BMP, WAV, AU` y puede embed/extract payloads cifrados.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
No tengo acceso directo al contenido del archivo en ese repo. Por favor pega aquí el contenido de src/stego/images/README.md (o proporciona la sección que quieres traducir). Traduciré todo el texto relevante al español manteniendo intactos los tags, links, paths y código según tus instrucciones.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Soporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referencias

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
