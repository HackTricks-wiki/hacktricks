# Esteganografía de imágenes

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los casos de image stego en CTF se reducen a una de estas categorías:

- LSB/bit-planes (PNG/BMP)
- Payloads en metadatos/comentarios
- Anomalías en chunks de PNG / reparación de corrupción
- Herramientas de dominio DCT de JPEG (OutGuess, etc.)
- Basados en frames (GIF/APNG)

## Triage rápido

Prioriza la evidencia a nivel del contenedor antes del análisis profundo del contenido:

- Valida el archivo e inspecciona su estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae metadatos y strings visibles: `exiftool -a -u -g1`, `strings`.
- Comprueba si hay contenido incrustado o añadido: `binwalk` e inspección del final del archivo (`tail | xxd`).
- Divide el análisis según el contenedor:
- PNG/BMP: bit-planes/LSB y anomalías a nivel de chunks.
- JPEG: metadatos + herramientas de dominio DCT (familias similares a OutGuess/F5).
- GIF/APNG: extracción de frames, diferenciación entre frames y trucos con paletas.

## Bit-planes / LSB

### Técnica

PNG/BMP son populares en CTF porque almacenan los píxeles de una forma que facilita la **manipulación a nivel de bits**. El mecanismo clásico para ocultar/extraer datos es:

- Cada canal de píxel (R/G/B/A) tiene múltiples bits.
- El **bit menos significativo** (LSB) de cada canal modifica muy poco la imagen.
- Los atacantes ocultan datos en esos bits de orden inferior, a veces usando un stride, una permutación o una selección por canal.

Qué puedes esperar en los challenges:

- El payload está en un solo canal (p. ej., el LSB de `R`).
- El payload está en el canal alpha.
- El payload está comprimido/codificado después de la extracción.
- El mensaje está distribuido entre varios planos u oculto mediante XOR entre planos.

Familias adicionales que puedes encontrar (dependen de la implementación):

- **LSB matching** (no solo invierte el bit, sino que realiza ajustes de +/-1 para hacer coincidir el bit objetivo)
- **Ocultación basada en paleta/índices** (PNG/GIF indexados: el payload está en los índices de color en lugar de los valores RGB sin procesar)
- **Payload exclusivo en alpha** (completamente invisible en la vista RGB)

### Herramientas

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transforms (metadatos, transforms de imagen, fuerza bruta de variantes LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc.).

Descarga de Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucos de visibilidad basados en FFT

FFT no es extracción LSB; se utiliza cuando el contenido está oculto deliberadamente en el dominio de la frecuencia o en patrones sutiles.

- Demo de EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage basado en la web que se utiliza habitualmente en CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato basado en chunks. En muchos challenges, el payload se almacena en el nivel del contenedor/chunk, en lugar de en los valores de los píxeles:

- **Bytes adicionales después de `IEND`** (muchos visores ignoran los bytes finales)
- **Chunks ancillary no estándar** que contienen payloads
- **Headers corruptos** que ocultan las dimensiones o hacen que los parsers fallen hasta que se corrigen

Ubicaciones de chunks con alta probabilidad que conviene revisar:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks ancillary utilizados como carrier
- `eXIf` (datos EXIF en PNG)

### Comandos de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Qué buscar:

- Combinaciones inusuales de width/height/profundidad de bits/colour-type
- Errores de CRC/chunk (`pngcheck` suele señalar el offset exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista más detallada de los chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referencias útiles:

- Especificación de PNG (estructura, chunks): https://www.w3.org/TR/PNG/
- Trucos de formatos de archivo (casos límite de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, herramientas del dominio DCT y limitaciones de ELA

### Técnica

JPEG no se almacena como píxeles sin procesar; se comprime en el dominio DCT. Por eso las herramientas de stego para JPEG difieren de las herramientas LSB para PNG:

- Los payloads de metadata/comentarios están a nivel de archivo (alta señal y rápidos de inspeccionar)
- Las herramientas de stego del dominio DCT incrustan bits en coeficientes de frecuencia

Operativamente, trata JPEG como:

- Un contenedor para segmentos de metadata (alta señal y rápidos de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) donde operan herramientas de stego especializadas

### Comprobaciones rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Ubicaciones con mayor señal:

- Metadatos EXIF/XMP/IPTC
- Segmento de comentarios JPEG (`COM`)
- Segmentos de aplicación (`APP1` para EXIF, `APPn` para datos del proveedor)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te enfrentas específicamente a payloads de steghide en JPEGs, considera usar `stegseek` (bruteforce más rápido que los scripts antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Análisis del nivel de error

ELA resalta distintos artefactos de recomprensión; puede señalarte las regiones que fueron editadas, pero no es un detector de stego por sí mismo:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imágenes animadas

### Técnica

Para imágenes animadas, asume que el mensaje está:

- En un solo frame (fácil), o
- Distribuido entre varios frames (el orden importa), o
- Solo es visible al hacer diff entre frames consecutivos

### Extraer frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Luego trata los frames como PNG normales: `zsteg`, `pngcheck`, aislamiento de canales.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de frames)
- `imagemagick`/`magick` para transformaciones por frame

La diferenciación entre frames suele ser decisiva:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Codificación por conteo de píxeles en APNG

- Detecta contenedores APNG: `exiftool -a -G1 file.png | grep -i animation` o `file`.
- Extrae los frames sin volver a sincronizarlos: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera los payloads codificados como conteos de píxeles por frame:
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
Los challenges animados pueden codificar cada byte como el recuento de un color específico en cada frame; concatenar los recuentos reconstruye el mensaje.<sup>[[1]](#references)</sup>

## Embedding protegido por contraseña

Si sospechas que el embedding está protegido por una passphrase en lugar de utilizar manipulación a nivel de píxel, esta suele ser la vía más rápida.

### steghide

Admite `JPEG, BMP, WAV, AU` y puede incrustar/extraer payloads cifrados.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Soporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referencias

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
