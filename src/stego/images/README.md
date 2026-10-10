# Esteganografía en imágenes

{{#include ../../banners/hacktricks-training.md}}

La mayoría de los retos CTF de esteganografía en imágenes se reducen a uno de estos grupos:

- LSB/planos de bits (PNG/BMP)
- Payloads en metadatos/comentarios
- Rarezas en chunks PNG / reparación de corrupción
- Herramientas de dominio DCT de JPEG (OutGuess, etc.)
- Basados en fotogramas (GIF/APNG)

## Análisis rápido

Prioriza las evidencias a nivel de contenedor antes de analizar el contenido en profundidad:

- Valida el archivo e inspecciona su estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae los metadatos y las cadenas visibles: `exiftool -a -u -g1`, `strings`.
- Comprueba si hay contenido incrustado o añadido: `binwalk` e inspección del final del archivo (`tail | xxd`).
- Elige la ruta según el contenedor:
  - PNG/BMP: planos de bits/LSB y anomalías a nivel de chunk.
  - JPEG: metadatos y herramientas de dominio DCT (familias de estilo OutGuess/F5).
  - GIF/APNG: extracción de fotogramas, diferencias entre fotogramas y trucos con paletas.

## Planos de bits / LSB

### Técnica

PNG/BMP son populares en CTF porque almacenan los píxeles de una forma que facilita la **manipulación a nivel de bits**. El mecanismo clásico para ocultar/extraer datos es:

- Cada canal de píxel (R/G/B/A) tiene varios bits.
- El **bit menos significativo** (LSB) de cada canal cambia muy poco la imagen.
- Los atacantes ocultan datos en esos bits de orden bajo, a veces con un stride, una permutación o una selección por canal.

Qué esperar en los retos:

- El payload está en un solo canal (p. ej., LSB de `R`).
- El payload está en el canal alfa.
- El payload se comprime/codifica después de extraerlo.
- El mensaje está distribuido entre planos o se oculta mediante XOR entre planos.

Otras familias que puedes encontrar (según la implementación):

- **LSB matching** (no se limita a cambiar el bit, sino que aplica ajustes de +/-1 para que coincida con el bit objetivo)
- **Ocultación basada en paletas/índices** (PNG/GIF indexados: el payload está en los índices de color, no en los valores RGB sin procesar)
- **Payloads solo en el canal alfa** (completamente invisibles en la vista RGB)

### Herramientas

#### zsteg

`zsteg` enumera muchos patrones de extracción LSB/planos de bits para PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una batería de transformaciones (metadatos, transformaciones de imagen, fuerza bruta de variantes LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc.).

Descarga de Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucos de visibilidad basados en FFT

FFT no es extracción LSB; se usa cuando el contenido está oculto deliberadamente en el espacio de frecuencias o en patrones sutiles.

- Demo de EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Herramientas web de análisis inicial que se usan a menudo en CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato basado en chunks. En muchos desafíos, el payload se almacena a nivel del contenedor/chunk en lugar de en los valores de píxel:

- **Bytes adicionales después de `IEND`** (muchos visores ignoran los bytes finales)
- **Chunks auxiliares no estándar** que contienen payloads
- **Cabeceras corruptas** que ocultan las dimensiones o impiden el funcionamiento de los parsers hasta que se reparan

Ubicaciones de chunks con alta probabilidad de contener datos:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks auxiliares usados como portadores
- `eXIf` (datos EXIF en PNG)

### Comandos de análisis inicial

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Qué buscar:

- Combinaciones extrañas de ancho/alto/profundidad de bits/tipo de color
- Errores de CRC/chunk (pngcheck suele indicar el desplazamiento exacto)
- Advertencias sobre datos adicionales después de `IEND`

Si necesitas una vista más detallada de los chunks:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Referencias útiles:

- Especificación de PNG (estructura, chunks): https://www.w3.org/TR/PNG/
- Trucos de formatos de archivo (casos límite de PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadatos, herramientas en el dominio DCT y limitaciones de ELA

### Técnica

JPEG no se almacena como píxeles sin procesar, sino que se comprime en el dominio DCT. Por eso las herramientas de esteganografía para JPEG son distintas de las herramientas LSB para PNG:

- Las cargas útiles en metadatos y comentarios están a nivel de archivo (fáciles de detectar y de inspeccionar rápidamente)
- Las herramientas de esteganografía en el dominio DCT incrustan bits en los coeficientes de frecuencia

En la práctica, trata JPEG como:

- Un contenedor de segmentos de metadatos (fáciles de detectar y de inspeccionar rápidamente)
- Un dominio de señal comprimida (coeficientes DCT) en el que operan herramientas de esteganografía especializadas

### Comprobaciones rápidas

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Ubicaciones con alta señal:

- Metadatos EXIF/XMP/IPTC
- Segmento de comentario JPEG (`COM`)
- Segmentos de aplicación (`APP1` para EXIF, `APPn` para datos del proveedor)

### Herramientas comunes

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si te encuentras específicamente con payloads de steghide en archivos JPEG, considera usar `stegseek` (fuerza bruta más rápida que los scripts antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA resalta distintos artefactos de recompresión; puede señalar regiones que se editaron, pero no es un detector de stego por sí solo:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imágenes animadas

### Técnica

Para las imágenes animadas, asume que el mensaje está:

- En un solo fotograma (fácil), o
- Repartido entre varios fotogramas (el orden importa), o
- Solo es visible al comparar fotogramas consecutivos

### Extraer fotogramas

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Luego trata los fotogramas como PNG normales: `zsteg`, `pngcheck`, aislamiento de canales.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de fotogramas)
- `imagemagick`/`magick` para transformaciones por fotograma

La comparación de diferencias entre fotogramas suele ser decisiva:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codificación mediante recuento de píxeles en APNG

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

Los retos animados pueden codificar cada byte como el recuento de un color específico en cada fotograma; al concatenar los recuentos se reconstruye el mensaje.<sup>[[1]](#references)</sup>

## Inserción protegida por contraseña

Si sospechas que la inserción está protegida por una frase de contraseña y no se basa en la manipulación a nivel de píxel, esta suele ser la vía más rápida.

### steghide

Admite `JPEG, BMP, WAV, AU` y permite insertar o extraer payloads cifrados.

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

Compatible con PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — rosa, Lista de deseos de Santa, Metadatos navideños, Ruido capturado](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
