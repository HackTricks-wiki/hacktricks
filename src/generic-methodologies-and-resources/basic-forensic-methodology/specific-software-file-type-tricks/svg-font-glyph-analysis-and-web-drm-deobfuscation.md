# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

This page documents practical techniques to recover text from web readers that ship positioned glyph runs plus per-request vector glyph definitions (SVG paths), and that randomize glyph IDs per request to prevent scraping. The core idea is to ignore request-scoped numeric glyph IDs and fingerprint the visual shapes via raster hashing, then map shapes to characters with SSIM against a reference font atlas. The workflow generalizes beyond Kindle Cloud Reader to any viewer with similar protections.

Warning: Only use these techniques to back up content you legitimately own and in compliance with applicable laws and terms.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:
- Browser session cookies (normal Amazon login)
- Rendering token from a startReading API call
- Additional ADP session token used by the renderer

Behavior:
- Each request, when sent with browser-equivalent headers and cookies, returns a TAR archive limited to 5 pages.
- For a long book you will need many batches; each batch uses a different randomized mapping of glyph IDs.

Typical TAR contents:
- page_data_0_4.json — positioned text runs as sequences of glyph IDs (not Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

Example page run structure:
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
Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete paths with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

## Por qué falla la decodificación ingenua

- Sustitución aleatoria de glifos por solicitud: glyph ID→character mapping cambia cada lote; los IDs no tienen significado a nivel global.
- La comparación directa de coordenadas SVG es frágil: formas idénticas pueden diferir en coordenadas numéricas o en la codificación de comandos por solicitud.
- OCR on isolated glyphs performs poorly (≈50%), confunde puntuación y glifos similares, e ignora ligaduras.

## Flujo de trabajo: normalización y mapeo de glifos independiente de la solicitud

1) Rasterizar los glifos SVG por solicitud
- Construye un documento SVG mínimo por glifo con el `path` provisto y renderízalo en un lienzo fijo (por ejemplo, 512×512) usando CairoSVG u otro motor equivalente que gestione secuencias de path complejas.
- Renderiza relleno negro sobre blanco; evita strokes para eliminar artefactos dependientes del renderer y del AA.

2) Hash perceptual para identidad entre solicitudes
- Calcula un hash perceptual (por ejemplo, pHash vía `imagehash.phash`) de cada imagen de glifo.
- Trata el hash como un ID estable: la misma forma visual entre solicitudes colapsa al mismo hash perceptual, derrotando los IDs aleatorizados.

3) Generación de atlas de fuentes de referencia
- Descarga las fuentes TTF/OTF objetivo (por ejemplo, Bookerly normal/italic/bold/bold-italic).
- Renderiza candidatos para A–Z, a–z, 0–9, puntuación, marcas especiales (em/en dashes, quotes), y ligaduras explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantén atlas separados por variante de fuente (normal/italic/bold/bold-italic).
- Usa un proper text shaper (HarfBuzz) si quieres fidelidad a nivel de glifo para ligaduras; una rasterización simple vía Pillow ImageFont puede ser suficiente si renderizas las cadenas de ligadura directamente y el motor de shaping las resuelve.

4) Emparejamiento por similitud visual con SSIM
- Para cada imagen de glifo desconocido, calcula SSIM (Structural Similarity Index) frente a todas las imágenes candidatas en todos los atlas de variantes de fuente.
- Asigna la cadena de caracteres de la coincidencia con mejor puntuación. SSIM absorbe pequeñas diferencias de antialiasing, escala y coordenadas mejor que comparaciones exactas por píxel.

5) Manejo de bordes y reconstrucción
- Cuando un glifo mapea a una ligadura (multi-char), expándela durante la decodificación.
- Usa run rectangles (top/left/right/bottom) para inferir saltos de párrafo (deltas en Y), alineación (patrones en X), estilo y tamaños.
- Serializa a HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize`, y enlaces internos.

### Consejos de implementación

- Normaliza todas las imágenes al mismo tamaño y escala de grises antes del hashing y SSIM.
- Cachea por hash perceptual para evitar recalcular SSIM en glifos repetidos entre lotes.
- Usa un tamaño de raster de alta calidad (por ejemplo, 256–512 px) para mejor discriminación; reduce la escala según sea necesario antes de SSIM para acelerar.
- Si usas Pillow para renderizar candidatos TTF, ajusta el mismo tamaño de lienzo y centra el glifo; añade padding para evitar recortar ascendentes/descendentes.

<details>
<summary>Python: end-to-end glyph normalization and matching (raster hash + SSIM)</summary>
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

## Heurísticas de reconstrucción de diseño/EPUB

- Saltos de párrafo: Si el Y superior del siguiente run excede la línea base de la línea anterior por un umbral (relativo al tamaño de fuente), inicia un nuevo párrafo.
- Alineación: Agrupa por X izquierdo similar para párrafos alineados a la izquierda; detecta líneas centradas por márgenes simétricos; detecta alineación a la derecha por los bordes derechos.
- Estilado: Conserva cursiva/negrita mediante `fontStyle`/`fontWeight`; varía clases CSS por rangos de `fontSize` para aproximar encabezados vs cuerpo.
- Enlaces: Si los runs incluyen metadata de enlace (p.ej., `positionId`), emite anclas y hrefs internos.

## Mitigación de trucos anti-scraping de paths SVG

- Usa paths rellenados con `fill-rule: nonzero` y un renderer adecuado (CairoSVG, resvg). No confíes en la normalización de tokens de path.
- Evita el stroke rendering; céntrate en sólidos rellenados para evitar artefactos de líneas finas causados por micro-movimientos relativos.
- Mantén un viewBox estable por render para que formas idénticas rastericen consistentemente entre lotes.

## Notas de rendimiento

- En la práctica, los libros convergen a unos pocos cientos de glifos únicos (p.ej., ~361 incluyendo ligaduras). Cachea los resultados SSIM por hash perceptual.
- Tras el descubrimiento inicial, los lotes futuros reutilizan mayoritariamente hashes conocidos; la decodificación se vuelve limitada por I/O.
- Un SSIM medio ≈0.95 es una señal fuerte; considera marcar coincidencias con puntuaciones bajas para revisión manual.

## Generalización a otros visores

Cualquier sistema que:
- Devuelva runs de glifos posicionados con IDs numéricos con alcance por solicitud
- Entregue glifos vectoriales por solicitud (SVG paths o subset fonts)
- Limite páginas por solicitud para evitar exportación masiva

…puede manejarse con la misma normalización:
- Rasterizar formas por solicitud → hash perceptual → ID de forma
- Atlas de glifos/ligaduras candidatos por variante de fuente
- SSIM (u otra métrica perceptual similar) para asignar caracteres
- Reconstruir el layout a partir de rectángulos/estilos de runs

## Ejemplo mínimo de adquisición (esbozo)

Usa las DevTools de tu navegador para capturar las cabeceras, cookies y tokens exactos que usa el lector al solicitar `/renderer/render`. Luego replica eso desde un script o curl. Esquema de ejemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajusta la parametrización (book ASIN, page window, viewport) para coincidir con las solicitudes del lector. Espera un límite de 5 páginas por solicitud.

## Resultados alcanzables

- Colapsar 100+ alfabetos aleatorizados a un único espacio de glifos mediante perceptual hashing
- Mapeo al 100% de glifos únicos con SSIM promedio ~0.95 cuando los atlas incluyen ligaduras y variantes
- EPUB/HTML reconstruido visualmente indistinguible del original

## Referencias

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
