# Análisis de glifos SVG/Font y desofuscación de Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Esta página documenta técnicas prácticas para recuperar texto de lectores web que envían secuencias de glifos posicionadas junto con definiciones de glifos vectoriales por request (rutas SVG), y que aleatorizan los IDs de los glifos en cada request para impedir el scraping. La idea principal es ignorar los IDs numéricos de los glifos, específicos de cada request, y crear una huella de las formas visuales mediante raster hashing; después, asignar las formas a caracteres usando SSIM frente a un atlas de referencia de fuentes. El workflow se generaliza más allá de Kindle Cloud Reader a cualquier viewer con protecciones similares.<sup>[[1]](#references)</sup>

Advertencia: Utiliza estas técnicas únicamente para realizar copias de seguridad de contenido que poseas legítimamente y cumpliendo las leyes y condiciones aplicables.

## Adquisición (ejemplo: Kindle Cloud Reader)

Endpoint observado:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiales necesarios por sesión:
- Cookies de la sesión del navegador (login normal de Amazon)
- Rendering token de una llamada a la API startReading
- Token de sesión ADP adicional utilizado por el renderer

Comportamiento:
- Cada request, cuando se envía con headers y cookies equivalentes a los del navegador, devuelve un archivo TAR limitado a 5 páginas.
- Para un libro largo necesitarás muchos batches; cada batch utiliza un mapping aleatorio diferente de los IDs de los glifos.

Contenido típico del TAR:
- page_data_0_4.json — text runs posicionados como secuencias de IDs de glifos (no Unicode)
- glyphs.json — definiciones de rutas SVG por request para cada glifo y fontFamily
- toc.json — tabla de contenidos
- metadata.json — metadatos del libro
- location_map.json — mappings de posición lógica→visual

Estructura de ejemplo de un page run:
```json
{
"type": "TextRun",
"glyphs": [24, 25, 74, 123, 91],
"rect": {"left": 100, "top": 200, "right": 850, "bottom": 220},
"fontStyle": "italic",
"fontWeight": 700,
"fontSize": 12.5
}
```
Ejemplo de entrada de glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notas sobre trucos de rutas anti-scraping:
- Las rutas pueden incluir pequeños movimientos relativos (p. ej., `m3,1 m1,6 m-4,-7`) que confunden a muchos parsers de vectores y métodos ingenuos de muestreo de rutas.
- Renderiza siempre las rutas completas rellenas con un motor SVG robusto (p. ej., CairoSVG) en lugar de realizar diferencias entre comandos/coordenadas.

## Por qué falla la decodificación ingenua

- Sustitución de glifos aleatorizada por solicitud: la asignación de ID de glifo→carácter cambia en cada lote; los ID no tienen significado global.<sup>[[1]](#references)</sup>
- La comparación directa de coordenadas SVG es frágil: las formas idénticas pueden diferir en sus coordenadas numéricas o en la codificación de comandos en cada solicitud.
- El OCR sobre glifos aislados funciona mal (≈50%), confunde la puntuación y los glifos visualmente similares, e ignora las ligaduras.

## Pipeline de trabajo: normalización y mapeo de glifos independiente de la solicitud

1) Rasterizar los glifos SVG de cada solicitud
- Construye un documento SVG mínimo por glifo con el `path` proporcionado y renderízalo en un canvas de tamaño fijo (p. ej., 512×512) usando CairoSVG o un motor equivalente que gestione secuencias de rutas complejas.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderiza negro relleno sobre blanco; evita los trazos para eliminar artefactos dependientes del renderizador y del antialiasing.

2) Hash perceptual para identificar elementos entre solicitudes
- Calcula un hash perceptual (p. ej., pHash mediante `imagehash.phash`) de cada imagen de glifo.<sup>[[3]](#references)</sup>
- Trata el hash como un ID estable: la misma forma visual en distintas solicitudes se reduce al mismo hash perceptual, anulando los ID aleatorizados.

3) Generación de un atlas de fuentes de referencia
- Descarga las fuentes TTF/OTF objetivo (p. ej., Bookerly normal/italic/bold/bold-italic).
- Renderiza candidatos para A–Z, a–z, 0–9, puntuación, marcas especiales (guiones em/en, comillas) y ligaduras explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantén atlas separados para cada variante de fuente (normal/italic/bold/bold-italic).
- Usa un text shaper adecuado (HarfBuzz) si quieres fidelidad a nivel de glifo para las ligaduras; la rasterización simple mediante Pillow ImageFont puede ser suficiente si renderizas directamente las cadenas de ligaduras y el motor de shaping las resuelve.

4) Comparación de similitud visual con SSIM
- Para cada imagen de glifo desconocida, calcula SSIM (Structural Similarity Index) frente a todas las imágenes candidatas de todos los atlas de variantes de fuente.<sup>[[4]](#references)</sup>
- Asigna la cadena de caracteres de la coincidencia con mayor puntuación. SSIM absorbe mejor que las comparaciones exactas de píxeles las pequeñas diferencias de antialiasing, escala y coordenadas.

5) Gestión de casos especiales y reconstrucción
- Cuando un glifo se corresponda con una ligadura (de varios caracteres), expándelo durante la decodificación.
- Usa rectángulos de ejecución (superior/izquierdo/derecho/inferior) para inferir saltos de párrafo (deltas Y), alineación (patrones X), estilo y tamaños.
- Serializa a HTML/EPUB conservando `fontStyle`, `fontWeight`, `fontSize` y los enlaces internos.

### Consejos de implementación

- Normaliza todas las imágenes al mismo tamaño y escala de grises antes de calcular el hash y SSIM.
- Usa una caché basada en el hash perceptual para evitar recalcular SSIM para glifos repetidos entre lotes.
- Usa un tamaño de rasterización de alta calidad (p. ej., 256–512 px) para mejorar la discriminación; reduce la escala según sea necesario antes de SSIM para acelerar el procesamiento.
- Si usas Pillow para renderizar candidatos TTF, establece el mismo tamaño de canvas y centra el glifo; añade margen para evitar recortar ascendentes y descendentes.

<details>
<summary>Python: normalización y matching de glifos de extremo a extremo (hash de rasterización + SSIM)</summary>
```python
# pip install cairosvg pillow imagehash scikit-image uharfbuzz freetype-py
import io, json, tarfile, base64, math
from PIL import Image, ImageOps, ImageDraw, ImageFont
import imagehash
from skimage.metrics import structural_similarity as ssim
import cairosvg

CANVAS = (512, 512)
BGCOLOR = 255  # white
FGCOLOR = 0    # black

# --- SVG -> raster ---
def rasterize_svg_path(path_d: str, canvas=CANVAS) -> Image.Image:
# Build a minimal SVG document; rely on CAIRO for correct path handling
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{canvas[0]}" height="{canvas[1]}" viewBox="0 0 2048 2048">
<rect width="100%" height="100%" fill="white"/>
<path d="{path_d}" fill="black" fill-rule="nonzero"/>
</svg>'''
png_bytes = cairosvg.svg2png(bytestring=svg.encode('utf-8'))
img = Image.open(io.BytesIO(png_bytes)).convert('L')
return img

# --- Perceptual hash ---
def phash_img(img: Image.Image) -> str:
# Normalize to grayscale and fixed size
img = ImageOps.grayscale(img).resize((128, 128), Image.LANCZOS)
return str(imagehash.phash(img))

# --- Reference atlas from TTF ---
def render_char(candidate: str, ttf_path: str, canvas=CANVAS, size=420) -> Image.Image:
# Render centered text on same canvas to approximate glyph shapes
font = ImageFont.truetype(ttf_path, size=size)
img = Image.new('L', canvas, color=BGCOLOR)
draw = ImageDraw.Draw(img)
w, h = draw.textbbox((0,0), candidate, font=font)[2:]
dx = (canvas[0]-w)//2
dy = (canvas[1]-h)//2
draw.text((dx, dy), candidate, fill=FGCOLOR, font=font)
return img

# --- Build atlases for variants ---
FONT_VARIANTS = {
'normal':   '/path/to/Bookerly-Regular.ttf',
'italic':   '/path/to/Bookerly-Italic.ttf',
'bold':     '/path/to/Bookerly-Bold.ttf',
'bolditalic':'/path/to/Bookerly-BoldItalic.ttf',
}
CANDIDATES = [
*[chr(c) for c in range(0x20, 0x7F)],  # basic ASCII
'–', '—', '“', '”', '‘', '’', '•',      # common punctuation
'ff','fi','fl','ffi','ffl'              # ligatures
]

def build_atlases():
atlases = {}  # variant -> list[(char, img)]
for variant, ttf in FONT_VARIANTS.items():
out = []
for ch in CANDIDATES:
img = render_char(ch, ttf)
out.append((ch, img))
atlases[variant] = out
return atlases

# --- SSIM match ---

def best_match(img: Image.Image, atlases) -> tuple[str, float, str]:
# Returns (char, score, variant)
img_n = ImageOps.grayscale(img).resize((128,128), Image.LANCZOS)
img_n = ImageOps.autocontrast(img_n)
best = ('', -1.0, '')
import numpy as np
candA = np.array(img_n)
for variant, entries in atlases.items():
for ch, ref in entries:
ref_n = ImageOps.grayscale(ref).resize((128,128), Image.LANCZOS)
ref_n = ImageOps.autocontrast(ref_n)
candB = np.array(ref_n)
score = ssim(candA, candB)
if score > best[1]:
best = (ch, score, variant)
return best

# --- Putting it together for one TAR batch ---

def process_tar(tar_path: str, cache: dict, atlases) -> list[dict]:
# cache: perceptual-hash -> mapping {char, score, variant}
out_runs = []
with tarfile.open(tar_path, 'r:*') as tf:
glyphs = json.load(tf.extractfile('glyphs.json'))
# page_data_0_4.json may differ in name; list members to find it
pd_name = next(m.name for m in tf.getmembers() if m.name.startswith('page_data_'))
page_data = json.load(tf.extractfile(pd_name))

# 1. Rasterize + hash all glyphs for this batch
id2hash = {}
for gid, meta in glyphs.items():
img = rasterize_svg_path(meta['path'])
h = phash_img(img)
id2hash[int(gid)] = (h, img)

# 2. Ensure all hashes are resolved to characters in cache
for h, img in {v[0]: v[1] for v in id2hash.values()}.items():
if h not in cache:
ch, score, variant = best_match(img, atlases)
cache[h] = { 'char': ch, 'score': float(score), 'variant': variant }

# 3. Decode text runs
for run in page_data:
if run.get('type') != 'TextRun':
continue
decoded = []
for gid in run['glyphs']:
h, _ = id2hash[gid]
decoded.append(cache[h]['char'])
run_out = {
'text': ''.join(decoded),
'rect': run.get('rect'),
'fontStyle': run.get('fontStyle'),
'fontWeight': run.get('fontWeight'),
'fontSize': run.get('fontSize'),
}
out_runs.append(run_out)
return out_runs

# Usage sketch:
# atlases = build_atlases()
# cache = {}
# for tar in sorted(glob('batches/*.tar')):
#     runs = process_tar(tar, cache, atlases)
#     # accumulate runs for layout reconstruction → EPUB/HTML
```
</details>

## Heurísticas de reconstrucción de Layout/EPUB

- Saltos de párrafo: Si la coordenada Y superior del siguiente run supera la línea base de la línea anterior por un umbral (relativo al tamaño de la fuente), comienza un párrafo nuevo.<sup>[[1]](#references)</sup>
- Alineación: Agrupa por una coordenada X izquierda similar los párrafos alineados a la izquierda; detecta las líneas centradas mediante márgenes simétricos; detecta la alineación a la derecha mediante los bordes derechos.
- Estilo: Conserva la cursiva/negrita mediante `fontStyle`/`fontWeight`; varía las clases CSS según intervalos de `fontSize` para aproximar encabezados y cuerpo de texto.
- Enlaces: Si los runs incluyen metadatos de enlaces (por ejemplo, `positionId`), genera anchors e hrefs internos.

## Mitigación de los trucos anti-scraping basados en paths SVG

- Usa paths rellenos con `fill-rule: nonzero` y un renderer adecuado (CairoSVG, resvg). No dependas de la normalización de tokens de path.<sup>[[1]](#references)</sup>
- Evita el renderizado de strokes; céntrate en sólidos rellenos para evitar artefactos de líneas finas causados por microdesplazamientos relativos.
- Mantén un `viewBox` estable por renderizado para que las formas idénticas se rastericen de manera consistente entre batches.

## Notas de rendimiento

- En la práctica, los libros convergen en unos pocos cientos de glyphs únicos (por ejemplo, ~361, incluidas las ligaduras). Almacena en caché los resultados de SSIM mediante un hash perceptual.<sup>[[1]](#references)</sup>
- Después del descubrimiento inicial, los batches posteriores reutilizan principalmente hashes conocidos; la decodificación pasa a estar limitada por la E/S.
- Un SSIM medio de ≈0.95 es una señal sólida; considera marcar para revisión manual las coincidencias con puntuaciones bajas.

## Generalización a otros viewers

Cualquier sistema que:<sup>[[1]](#references)</sup>
- Devuelva runs de glyphs posicionados con IDs numéricos específicos del request
- Envíe glyphs vectoriales por request (paths SVG o subset fonts)
- Limite el número de páginas por request para evitar la exportación masiva

…puede gestionarse con la misma normalización:
- Rasterizar las formas por request → hash perceptual → ID de forma
- Atlas de glyphs/ligaduras candidatos por variante de fuente
- SSIM (o una métrica perceptual similar) para asignar caracteres
- Reconstruir el layout a partir de los rectángulos/estilos de los runs

## Ejemplo mínimo de adquisición (esquema)

Usa las DevTools de tu navegador para capturar los headers, cookies y tokens exactos que utiliza el reader al solicitar `/renderer/render`. Después, replícalos desde un script o curl.<sup>[[1]](#references)</sup> Esquema del ejemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajusta la parametrización (ASIN del libro, ventana de páginas, viewport) para adaptarla a las solicitudes del lector. Espera un límite máximo de 5 páginas por solicitud.

## Resultados alcanzables

- Colapsar más de 100 alfabetos aleatorizados en un único espacio de glifos mediante hashing perceptual<sup>[[1]](#references)</sup>
- Mapeo del 100 % de los glifos únicos con un SSIM medio de ~0.95 cuando los atlas incluyen ligaduras y variantes
- EPUB/HTML reconstruido visualmente indistinguible del original

## Referencias

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
