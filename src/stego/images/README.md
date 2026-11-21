# Esteganografía de imágenes

{{#include ../../banners/hacktricks-training.md}}

La esteganografía de imágenes en CTF suele reducirse a una de estas categorías:

- LSB/planos de bits (PNG/BMP)
- Payloads en metadatos/comentarios
- Rarezas/corrupciones de chunks PNG
- Herramientas de dominio DCT de JPEG (OutGuess, etc.)
- Basada en fotogramas (GIF/APNG)

## Triage rápido

Prioriza la evidencia a nivel de contenedor antes de analizar el contenido en profundidad. Consulta el [flujo de trabajo general de estego](../workflow/) para identificar archivos y extraer datos antes de realizar pruebas específicas para imágenes.

- Valida el archivo e inspecciona su estructura: `file`, `magick identify -verbose`, validadores de formato (p. ej., `pngcheck`).
- Extrae metadatos y cadenas visibles: `exiftool -a -u -g1`, `strings`.
- Busca contenido incrustado o añadido: `binwalk` e inspecciona el final del archivo (`tail | xxd`).
- Elige según el contenedor:
  - PNG/BMP: planos de bits/LSB y anomalías a nivel de chunk.
  - JPEG: metadatos y herramientas de dominio DCT (familias como OutGuess/F5).
  - GIF/APNG: extracción de fotogramas, diferencias entre fotogramas y trucos con paletas.

## Planos de bits / LSB

### Técnica

PNG/BMP son populares en CTF porque almacenan los píxeles de una forma que facilita la **manipulación a nivel de bits**. El mecanismo clásico para ocultar/extraer datos es:

- Cada canal de píxel (R/G/B/A) tiene varios bits.
- El **bit menos significativo** (LSB) de cada canal apenas modifica la imagen.
- Los atacantes ocultan datos en esos bits de orden bajo, a veces con un paso, una permutación o una selección por canal.

Qué puedes encontrar en los desafíos:

- El payload está en un solo canal (p. ej., el LSB de `R`).
- El payload está en el canal alfa.
- El payload se comprime/codifica tras extraerlo.
- El mensaje se distribuye entre planos o se oculta mediante XOR entre planos.

Otras familias que puedes encontrar (según la implementación):

- **LSB matching** (no solo se invierte el bit, sino que se ajusta +/-1 para que coincida con el bit objetivo)
- **Ocultación basada en paleta/índice** (PNG/GIF indexados: el payload está en los índices de color, no en valores RGB sin procesar)
- **Payloads solo en el canal alfa** (completamente invisibles en la vista RGB)

### Índices de paleta de color indexado

Un PNG o GIF indexado almacena un **índice** de paleta por píxel, no una tripleta RGB. Dos índices pueden corresponder al mismo color visible, por lo que convertir la imagen a RGB antes de analizarla puede borrar la distinción oculta. Inspecciona las entradas duplicadas o casi duplicadas de la paleta y luego representa una máscara binaria de los píxeles que usan cada índice sospechoso. Esto ha permitido revelar texto oculto y cambios de código QR en desafíos recientes de GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Para un PNG indexado de un solo fotograma (o el **primer fotograma** de un GIF), conserva el modo `P` de Pillow y cambia `target` por un índice interesante que indique el script. Al elegir índices, comprueba la transparencia (`tRNS` o el índice de transparencia del GIF) además de RGB.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Para los GIF animados, inspecciona los fotogramas por separado. Pillow normalmente convierte los fotogramas posteriores a RGB/RGBA al componerlos; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` mantiene el modo `P` solo mientras la paleta no cambie. Si un fotograma tiene una paleta local o ya se ha compuesto, inspecciona sus datos originales de fotograma indexados en lugar de tratar los píxeles convertidos a RGB como índices.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Herramientas

#### zsteg

`zsteg` enumera numerosos patrones de extracción LSB/bit-plane para PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ejecuta una serie de transformaciones (metadatos, transformaciones de imagen, fuerza bruta de variantes de LSB).
- `stegsolve`: filtros visuales manuales (aislamiento de canales, inspección de planos, XOR, etc.).

Descarga de Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucos de visibilidad basados en FFT

FFT no es extracción de LSB; se usa en casos en los que el contenido se oculta deliberadamente en el espacio de frecuencias o en patrones sutiles.

- Demo de EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Herramientas web de análisis inicial que suelen usarse en CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Estructura interna de PNG: chunks, corrupción y datos ocultos

### Técnica

PNG es un formato basado en chunks. En muchos desafíos, la carga útil se almacena en el contenedor o en los chunks, en lugar de en los valores de píxel:

- **Bytes adicionales después de `IEND`** (muchos visores ignoran los bytes finales)
- **Chunks auxiliares no estándar** que contienen cargas útiles; consulta el [recorrido de chunks PNG y el flujo de trabajo de extracción](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Cabeceras corruptas** que ocultan las dimensiones o impiden el funcionamiento de los analizadores hasta que se reparan

Ubicaciones de chunks con alta probabilidad de contener datos que conviene revisar:

- `tEXt` / `iTXt` / `zTXt` (metadatos de texto, a veces comprimidos)
- `iCCP` (perfil ICC) y otros chunks auxiliares usados como portadores
- `eXIf` (datos EXIF en PNG)

### Bytes de filtro de las scanlines de PNG como portador

PNG almacena un byte de tipo de filtro (0–4) antes de cada scanline en el flujo `IDAT` descomprimido. Estos bytes no son valores de píxel; los píxeles RGB decodificados no conservan las opciones de filtro originales, y la recodificación puede modificarlas. Un codificador puede variar los filtros legítimamente, pero los patrones deliberados pueden codificar un mensaje corto; un desafío reciente usó los valores de filtro 1–4 como símbolos de dos bits. Inspecciona el **archivo original** y concatena todos los datos `IDAT` antes de descomprimirlos. Para el siguiente caso, que no está entrelazado y usa RGB/RGBA de 8 bits, el stride es el ancho multiplicado por el número de canales; las imágenes Adam7 requieren anchos de scanline específicos para cada pasada.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Listar los bytes de filtro de las scanlines PNG sin recodificar</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Ejecútalo con `python3 filters.py suspect.png`. Comprueba si la secuencia de filtros, en lugar de los píxeles decodificados, sigue una asignación de símbolos plausible. La asignación elegida depende del desafío; la variación por sí sola no demuestra que haya esteganografía.<sup>[[3]](#references)[[7]](#references)</sup>

### Comandos de triaje

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Qué buscar:

- Combinaciones inusuales de ancho/alto/profundidad de bits/tipo de color
- Errores de CRC/chunks (pngcheck suele señalar el desplazamiento exacto)
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

JPEG no se almacena como píxeles sin procesar; se comprime en el dominio DCT. Por eso, las herramientas de stego para JPEG son distintas de las herramientas LSB para PNG:

- Las cargas útiles de metadatos y comentarios están a nivel de archivo (alta señal y rápidas de inspeccionar)
- Las herramientas de stego del dominio DCT incrustan bits en coeficientes de frecuencia

En la práctica, trata JPEG como:

- Un contenedor de segmentos de metadatos (alta señal y rápidos de inspeccionar)
- Un dominio de señal comprimida (coeficientes DCT) en el que operan herramientas de stego especializadas

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

Si te enfrentas específicamente a payloads de steghide en archivos JPEG, considera usar `stegseek` (bruteforce más rápido que con scripts antiguos):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA resalta distintos artefactos de recompresión; puede indicarte las regiones que se editaron, pero no es un detector de stego por sí solo:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Imágenes animadas

### Técnica

Para imágenes animadas, asume que el mensaje está:

- En un único fotograma (fácil), o
- Distribuido entre varios fotogramas (el orden importa), o
- Visible solo al comparar fotogramas consecutivos

### Extraer fotogramas

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Después trata los fotogramas como PNG normales: `zsteg`, `pngcheck` y aislamiento de canales.

Herramientas alternativas:

- `gifsicle --explode anim.gif` (extracción rápida de fotogramas)
- `imagemagick`/`magick` para transformaciones por fotograma

La comparación de diferencias entre fotogramas suele ser decisiva:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codificación mediante recuento de píxeles en APNG

- Detecta contenedores APNG: `exiftool -a -G1 file.png | grep -i animation` o `file`.
- Extrae los fotogramas sin cambiar los tiempos: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

## Inserción protegida con contraseña

Si sospechas que la inserción está protegida por una frase de contraseña en lugar de implicar una manipulación a nivel de píxel, esta suele ser la vía más rápida.

### steghide

Admite `JPEG, BMP, WAV, AU` y puede insertar o extraer cargas útiles cifradas.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repositorio: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Admite PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, La lista de deseos de Santa, Metadatos navideños, Ruido capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Write-up de HackVent 2024 — Colores retorcidos](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Especificación de Portable Network Graphics (PNG), tercera edición](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — En las profundidades hay algo en el agua](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Formatos de archivo de imagen de Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Especificación GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protocolo Afterimage — write-up de CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
