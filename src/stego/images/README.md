# Esteganografía de imágenes

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los image stego en CTF se reducen a una de estas categorías:

- LSB/bit-planes (PNG/BMP)
- Payloads en metadatos/comentarios
- Anomalías en chunks de PNG / reparación de corrupción
- Herramientas para el dominio DCT de JPEG (OutGuess, etc.)
- Basados en frames (GIF/APNG)

## Triage rápido

Prioriza la evidencia a nivel del contenedor antes del análisis profundo del contenido:

- Valida el archivo e inspecciona su estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae metadatos y strings visibles: `exiftool -a -u -g1`, `strings`.
- Comprueba si hay contenido incrustado o añadido: `binwalk` e inspección del final del archivo (`tail | xxd`).
- Decide según el contenedor:
- PNG/BMP: bit-planes/LSB y anomalías a nivel de chunks.
- JPEG: metadatos + herramientas para el dominio DCT (familias del estilo OutGuess/F5).
- GIF/APNG: extracción de frames, diferenciación entre frames y trucos con la paleta.

## Bit-planes / LSB

### Técnica

PNG/BMP son populares en CTF porque almacenan los píxeles de una forma que facilita la **manipulación a nivel de bits**. El mecanismo clásico para ocultar/extraer es:

- Cada canal de píxel (R/G/B/A) tiene varios bits.
- El **bit menos significativo** (LSB) de cada canal cambia muy poco la imagen.
- Los atacantes ocultan datos en esos bits de orden inferior, a veces usando un stride, una permutación o una selección por canal.

Qué puedes esperar en los challenges:

- El payload está en un solo canal (p. ej., el LSB de `R`).
- El payload está en el canal alpha.
- El payload está comprimido/codificado después de la extracción.
- El mensaje está distribuido entre varios planos u oculto mediante XOR entre planos.

Familias adicionales que puedes encontrar (dependen de la implementación):

- **LSB matching** (no solo invierte el bit, sino que realiza ajustes de +/-1 para coincidir con el bit objetivo)
- **Ocultación basada en paleta/índice** (PNG/GIF indexados: el payload está en los índices de color en lugar de los valores RGB sin procesar)
- **Payload solo en alpha** (completamente invisible en la vista RGB)

### Herramientas

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/bit-plane para PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transformaciones (metadatos, transformaciones de imagen y fuerza bruta de variantes de LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc.).

Descarga de Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucos de visibilidad basados en FFT

FFT no es extracción de LSB; se utiliza cuando el contenido está oculto deliberadamente en el dominio de la frecuencia o en patrones sutiles.

- Demo de EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage basado en la web utilizado habitualmente en CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato basado en chunks. En muchos desafíos, el payload se almacena en el nivel del contenedor/chunk, en lugar de hacerlo en los valores de píxel:

- **Bytes adicionales después de `IEND`** (muchos visores ignoran los bytes finales)
- **Chunks auxiliares no estándar** que contienen payloads
- **Cabeceras corruptas** que ocultan las dimensiones o interrumpen los parsers hasta que se corrigen

Ubicaciones de chunks con alta probabilidad de contener datos que conviene revisar:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks auxiliares utilizados como portadores
- `eXIf` (datos EXIF en PNG)

### Comandos de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Qué buscar:

- Combinaciones extrañas de ancho/alto/profundidad de bits/tipo de color
- Errores de CRC/chunk (pngcheck normalmente indica el offset exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista más detallada de los chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Referencias útiles:

- Especificación de PNG (estructura, chunks): https://www.w3.org/TR/PNG/
- Trucos de formatos de archivo (casos límite de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadatos, herramientas del dominio DCT y limitaciones de ELA

### Técnica

JPEG no se almacena como píxeles sin procesar; se comprime en el dominio DCT. Por eso las herramientas de stego para JPEG difieren de las herramientas LSB para PNG:

- Los payloads de metadatos/comentarios están a nivel de archivo (señal de alto valor y rápidos de inspeccionar)
- Las herramientas de stego del dominio DCT incrustan bits en coeficientes de frecuencia

Operativamente, trata JPEG como:

- Un contenedor para segmentos de metadatos (señal de alto valor, rápidos de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) donde operan herramientas de stego especializadas

### Comprobaciones rápidas
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Ubicaciones de alta relevancia:

- Metadatos EXIF/XMP/IPTC
- Segmento de comentarios JPEG (`COM`)
- Segmentos de aplicación (`APP1` para EXIF, `APPn` para datos del proveedor)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te enfrentas específicamente a payloads de steghide en archivos JPEG, considera usar `stegseek` (fuerza bruta más rápida que los scripts antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Análisis de nivel de error

ELA resalta distintos artefactos de recomprensión; puede señalarte regiones que fueron editadas, pero no es un detector de stego por sí mismo:

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
Entonces trata los fotogramas como PNG normales: `zsteg`, `pngcheck`, aislamiento de canales.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de fotogramas)
- `imagemagick`/`magick` para transformaciones por fotograma

La diferenciación entre fotogramas suele ser decisiva:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Codificación APNG mediante recuento de píxeles

- Detecta contenedores APNG: `exiftool -a -G1 file.png | grep -i animation` o `file`.
- Extrae los fotogramas sin cambiar la temporización: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera las cargas útiles codificadas como recuentos de píxeles por fotograma:
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
Los challenges animados pueden codificar cada byte como la cantidad de un color específico en cada frame; al concatenar las cantidades se reconstruye el mensaje.<sup>[[1]](#references)</sup>

## Incrustación protegida por contraseña

Si sospechas que la incrustación está protegida por una passphrase en lugar de manipulación a nivel de píxel, esta suele ser la ruta más rápida.

### steghide

Admite `JPEG, BMP, WAV, AU` y puede incrustar/extraer cargas útiles cifradas.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
### stegpy

Compatible con PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referencias

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
