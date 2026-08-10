# Análisis de glifos SVG/fuente y deobfuscation de Web DRM (hashing raster + SSIM)

Esta página documenta técnicas prácticas para recuperar texto de lectores web que envían secuencias de glifos posicionadas junto con definiciones de glifos vectoriales por solicitud (rutas SVG), y que randomizan los IDs de los glifos en cada solicitud para evitar el scraping. La idea principal es ignorar los IDs numéricos de glifos específicos de cada solicitud e identificar las formas visuales mediante hashing raster, para después asociar las formas con caracteres usando SSIM frente a un atlas de fuente de referencia. El mismo enfoque puede generalizarse a visores con protecciones similares.<sup>[[1]](#references)</sup>

Advertencia: Utiliza estas técnicas únicamente para realizar copias de seguridad de contenido que poseas legítimamente y de conformidad con las leyes y los términos aplicables.

## Adquisición (ejemplo: Kindle Cloud Reader)

Endpoint observado:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiales necesarios por sesión:<sup>[[1]](#references)</sup>
- Cookies de sesión del navegador (inicio de sesión normal en Amazon)
- Token de renderizado procedente de una llamada a la API startReading
- Token de sesión ADP adicional utilizado por el renderer

Comportamiento:<sup>[[1]](#references)</sup>
- Cada solicitud, cuando se envía con headers y cookies equivalentes a los del navegador, devuelve un archivo TAR limitado a 5 páginas.
- Para un libro largo necesitarás muchos lotes; cada lote utiliza un mapping randomizado diferente de los IDs de los glifos.

Contenido típico del TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — secuencias de texto posicionadas como secuencias de IDs de glifos (no Unicode)
- glyphs.json — definiciones de rutas SVG por solicitud para cada glifo y fontFamily
- toc.json — tabla de contenidos
- metadata.json — metadatos del libro
- location_map.json — mappings de posición lógica→visual

Estructura de ejemplo de una secuencia de página:<sup>[[1]](#references)</sup>
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
Ejemplo de entrada de glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notas sobre trucos de rutas anti-scraping:<sup>[[1]](#references)</sup>
- Las rutas pueden incluir pequeños movimientos relativos (p. ej., `m3,1 m1,6 m-4,-7`) que confunden a muchos parsers de vectores y al muestreo ingenuo de rutas.
- Renderiza siempre las rutas completas rellenas con un motor SVG robusto (p. ej., CairoSVG) en lugar de realizar diferencias entre comandos/coordenadas.

## Por qué falla la decodificación ingenua

- Sustitución de glifos aleatoria por solicitud: la asignación de ID de glifo→carácter cambia en cada lote; los ID no tienen significado global.<sup>[[1]](#references)</sup>
- La comparación directa de coordenadas SVG es frágil: las formas idénticas pueden diferir en las coordenadas numéricas o en la codificación de comandos en cada solicitud.<sup>[[1]](#references)</sup>
- El OCR en glifos aislados funciona mal (≈50%), confunde la puntuación y los glifos parecidos, e ignora las ligaduras.<sup>[[1]](#references)</sup>

## Pipeline de trabajo: normalización y mapeo de glifos independientes de la solicitud

1) Rasterizar los glifos SVG por solicitud
- Construye un documento SVG mínimo por glifo con la `path` proporcionada y renderízalo en un lienzo fijo (p. ej., 512×512) usando CairoSVG o un motor equivalente que gestione secuencias de rutas complejas.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderiza negro relleno sobre blanco; evita los trazos para eliminar artefactos dependientes del motor de renderizado y del antialiasing.

2) Hashing perceptual para la identidad entre solicitudes
- Calcula un hash perceptual (p. ej., pHash mediante `imagehash.phash`) de cada imagen de glifo.<sup>[[3]](#references)</sup>
- Trata el hash como un ID estable: la misma forma visual en distintas solicitudes se reduce al mismo hash perceptual, neutralizando los ID aleatorios.

3) Generación de un atlas de fuentes de referencia
- Descarga las fuentes TTF/OTF objetivo (p. ej., Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Renderiza candidatos para A–Z, a–z, 0–9, puntuación, marcas especiales (guiones em/en, comillas) y ligaduras explícitas: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantén atlas separados para cada variante de fuente (normal/italic/bold/bold-italic).
- Usa un text shaper adecuado (HarfBuzz) si quieres fidelidad a nivel de glifo para las ligaduras; una rasterización simple mediante Pillow ImageFont puede ser suficiente si renderizas directamente las cadenas de ligaduras y el motor de shaping las resuelve.

4) Coincidencia por similitud visual con SSIM
- Para cada imagen de glifo desconocida, calcula SSIM (Structural Similarity Index) frente a todas las imágenes candidatas de todos los atlas de variantes de fuente.<sup>[[4]](#references)</sup>
- Asigna la cadena de caracteres de la coincidencia con la puntuación más alta. SSIM absorbe mejor que las comparaciones exactas de píxeles las pequeñas diferencias de antialiasing, escala y coordenadas.<sup>[[1]](#references)[[4]](#references)</sup>

5) Gestión de casos límite y reconstrucción
- Cuando un glifo se corresponda con una ligadura (varios caracteres), expándelo durante la decodificación.<sup>[[1]](#references)</sup>
- Usa rectángulos de ejecución (superior/izquierdo/derecho/inferior) para inferir saltos de párrafo (deltas Y), alineación (patrones X), estilo y tamaños.<sup>[[1]](#references)</sup>
- Serializa a HTML/EPUB conservando `fontStyle`, `fontWeight`, `fontSize` y los enlaces internos.<sup>[[1]](#references)</sup>

### Consejos de implementación

- Normaliza todas las imágenes al mismo tamaño y escala de grises antes de aplicar hashing y SSIM.
- Usa una caché basada en el hash perceptual para evitar recalcular SSIM para glifos repetidos entre lotes.
- Usa un tamaño de rasterización de alta calidad (p. ej., 256–512 px) para mejorar la discriminación; reduce la escala según sea necesario antes de SSIM para acelerarlo.
- Si usas Pillow para renderizar candidatos TTF, establece el mismo tamaño de lienzo y centra el glifo; añade margen para evitar recortar ascendentes y descendentes.

<details>
<summary>Python: normalización y coincidencia de glifos de extremo a extremo (hash de rasterización + SSIM)</summary>
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

El informe de origen utilizó la geometría de los runs, los campos de estilo y los metadatos de enlaces para preservar el formato del documento reconstruido.<sup>[[1]](#references)</sup>

- Saltos de párrafo: Si la coordenada Y superior del siguiente run supera la línea base de la línea anterior por un umbral (relativo al tamaño de la fuente), iniciar un nuevo párrafo.<sup>[[1]](#references)</sup>
- Alineación: Agrupar por una coordenada X izquierda similar los párrafos alineados a la izquierda; detectar líneas centradas mediante márgenes simétricos; detectar líneas alineadas a la derecha mediante sus bordes derechos.
- Estilo: Preservar la cursiva/negrita mediante `fontStyle`/`fontWeight`; variar las clases CSS según grupos de `fontSize` para aproximar títulos y cuerpo de texto.
- Enlaces: Si los runs incluyen metadatos de enlaces (por ejemplo, `positionId`), emitir anchors y hrefs internos.

## Mitigación de los trucos anti-scraping de rutas SVG

- Usar rutas rellenas con `fill-rule: nonzero` y un renderer apropiado (CairoSVG, resvg). No depender de la normalización de tokens de ruta.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Evitar el renderizado de strokes; centrarse en sólidos rellenos para evitar artefactos de líneas finas causados por microdesplazamientos relativos.
- Mantener un `viewBox` estable por renderizado para que las formas idénticas se rastericen de manera consistente entre lotes.

## Notas de rendimiento

- En la práctica, los libros convergen en unos pocos cientos de glyphs únicos (por ejemplo, ~361 incluyendo ligaduras). Almacenar en caché los resultados de SSIM mediante un hash perceptual.<sup>[[1]](#references)</sup>
- Después del descubrimiento inicial, los lotes posteriores reutilizan principalmente hashes conocidos; la decodificación pasa a estar limitada por la E/S.
- El informe citado observó un SSIM medio de aproximadamente 0.95; marcar las coincidencias con puntuaciones bajas para revisión manual.<sup>[[1]](#references)</sup>

## Generalización a otros viewers

El flujo de trabajo de Kindle sugiere que viewers similares podrían admitir la misma normalización cuando:<sup>[[1]](#references)</sup>
- devuelven runs de glyphs posicionados con IDs numéricos asociados a la solicitud
- envían glyphs vectoriales por solicitud (rutas SVG o subset fonts)
- limitan el número de páginas por solicitud

…pueden procesarse con la misma normalización:
- Rasterizar las formas por solicitud → hash perceptual → ID de forma
- Atlas de glyphs/ligaduras candidatos por variante de fuente
- SSIM (o una métrica perceptual similar) para asignar caracteres
- Reconstruir el Layout a partir de rectángulos/estilos de los runs

## Ejemplo mínimo de adquisición (esquema)

Usa las DevTools de tu navegador para capturar los headers, cookies y tokens exactos que utiliza el reader al solicitar `/renderer/render`. Después, replícalos desde un script o curl.<sup>[[1]](#references)</sup> Esquema de ejemplo:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajusta la parametrización (ASIN del libro, ventana de páginas y viewport) para adaptarla a las solicitudes del lector. Espera un límite de 5 páginas por solicitud.<sup>[[1]](#references)</sup>

## Resultados alcanzables

- Reduce más de 100 alfabetos aleatorizados a un único espacio de glifos mediante perceptual hashing.<sup>[[1]](#references)</sup>
- En la prueba citada de 920 páginas, se emparejaron 361 glifos únicos (100 %) con un SSIM medio de 0.9527.<sup>[[1]](#references)</sup>
- El informe original describe el EPUB reconstruido como prácticamente indistinguible del original.<sup>[[1]](#references)</sup>

## References

- [1] [Cómo revertí la ofuscación web de Kindle de Amazon porque su app era terrible (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – Renderizador de SVG a PNG](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Índice de similitud estructural (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Propiedades de relleno](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – Biblioteca de renderizado SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
