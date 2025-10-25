# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina documenta tecniche pratiche per recuperare testo da web reader che inviano positioned glyph runs più definizioni vettoriali di glyph per richiesta (SVG paths), e che randomizzano gli ID dei glyph per richiesta per impedire lo scraping. L'idea core è ignorare gli ID numerici dei glyph limitati alla singola richiesta e fingerprintare le forme visive tramite raster hashing, quindi mappare le forme ai caratteri con SSIM confrontandole con un font atlas di riferimento. Il workflow si generalizza oltre Kindle Cloud Reader a qualsiasi viewer con protezioni simili.

Warning: Usa queste tecniche solo per effettuare il backup di contenuti che possiedi legittimamente e in conformità con le leggi e i termini applicabili.

## Acquisizione (esempio: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiale richiesto per sessione:
- Cookie della sessione del browser (normal Amazon login)
- Rendering token da una startReading API call
- Token di sessione ADP aggiuntivo usato dal renderer

Comportamento:
- Ogni richiesta, quando inviata con header e cookie equivalenti al browser, restituisce un archivio TAR limitato a 5 pagine.
- Per un libro lungo serviranno molti batch; ogni batch usa una diversa mappatura randomizzata di glyph IDs.

Contenuti tipici del TAR:
- page_data_0_4.json — run di testo posizionato come sequenze di glyph IDs (non Unicode)
- glyphs.json — definizioni per richiesta di SVG paths per ogni glyph e fontFamily
- toc.json — indice (table of contents)
- metadata.json — metadati del libro
- location_map.json — mappature posizione logica→visuale

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
Esempio di voce in glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete paths with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

## Why naïve decoding fails

- Per-request randomized glyph substitution: glyph ID→character mapping changes every batch; IDs are meaningless globally.
- Direct SVG coordinate comparison is brittle: identical shapes may differ in numeric coordinates or command encoding per request.
- OCR on isolated glyphs performs poorly (≈50%), confuses punctuation and look-alike glyphs, and ignores ligatures.

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- Build a minimal SVG document per glyph with the provided `path` and render to a fixed canvas (e.g., 512×512) using CairoSVG or an equivalent engine that handles tricky path sequences.
- Render filled black on white; avoid strokes to eliminate renderer- and AA-dependent artifacts.

2) Perceptual hashing for cross-request identity
- Compute a perceptual hash (e.g., pHash via `imagehash.phash`) of each glyph image.
- Treat the hash as a stable ID: the same visual shape across requests collapses to the same perceptual hash, defeating randomized IDs.

3) Reference font atlas generation
- Download the target TTF/OTF fonts (e.g., Bookerly normal/italic/bold/bold-italic).
- Render candidates for A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), and explicit ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Keep separate atlases per font variant (normal/italic/bold/bold-italic).
- Use a proper text shaper (HarfBuzz) if you want glyph-level fidelity for ligatures; simple rasterization via Pillow ImageFont can be sufficient if you render the ligature strings directly and the shaping engine resolves them.

4) Visual similarity matching with SSIM
- For each unknown glyph image, compute SSIM (Structural Similarity Index) against all candidate images across all font variant atlases.
- Assign the character string of the best-scoring match. SSIM absorbs small antialiasing, scale, and coordinate differences better than pixel-exact comparisons.

5) Edge handling and reconstruction
- When a glyph maps to a ligature (multi-char), expand it during decoding.
- Use run rectangles (top/left/right/bottom) to infer paragraph breaks (Y deltas), alignment (X patterns), style, and sizes.
- Serialize to HTML/EPUB preserving `fontStyle`, `fontWeight`, `fontSize`, and internal links.

### Implementation tips

- Normalize all images to the same size and grayscale before hashing and SSIM.
- Cache by perceptual hash to avoid recomputing SSIM for repeated glyphs across batches.
- Use a high-quality raster size (e.g., 256–512 px) for better discrimination; downscale as needed before SSIM to accelerate.
- If using Pillow to render TTF candidates, set the same canvas size and center the glyph; pad to avoid clipping ascenders/descenders.

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

## Layout/EPUB: euristiche di ricostruzione

- Paragraph breaks: Se il top Y della run successiva supera la baseline della riga precedente di una soglia (relativa alla dimensione del font), inizia un nuovo paragrafo.
- Alignment: Raggruppa per valori simili di X sinistro per paragrafi allineati a sinistra; rileva righe centrate tramite margini simmetrici; rileva l'allineamento a destra dagli edge di destra.
- Styling: Preserva corsivo/grassetto via `fontStyle`/`fontWeight`; varia le classi CSS in base a bucket di `fontSize` per approssimare headings vs body.
- Links: Se le run includono metadata di link (es., `positionId`), emetti anchor e href interni.

## Mitigazione dei trucchi anti-scraping dei path SVG

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Evita il rendering dello stroke; concentrati su filled solids per aggirare artefatti hairline causati da micro spostamenti relativi.
- Mantieni un viewBox stabile per render in modo che shape identiche rasterizzino consistentemente tra i batch.

## Note sulle prestazioni

- In pratica, i libri convergono su poche centinaia di glifi unici (es., ~361 includendo legature). Cache i risultati SSIM tramite hash percettivo.
- Dopo la scoperta iniziale, i batch successivi riutilizzano prevalentemente hash noti; la decodifica diventa vincolata dall'I/O.
- SSIM medio ≈0.95 è un segnale forte; valuta di segnalare le corrispondenze con punteggi bassi per revisione manuale.

## Generalizzazione ad altri visualizzatori

Qualsiasi sistema che:
- Restituisca run di glifi posizionati con ID numerici legati alla richiesta
- Fornisca glifi vettoriali per richiesta (SVG paths o subset fonts)
- Limiti le pagine per richiesta per prevenire esportazioni massive

…può essere gestito con la stessa normalizzazione:
- Rasterizza le forme per richiesta → hash percettivo → shape ID
- Atlante di glifi/legature candidate per variante di font
- SSIM (o metrica percettiva simile) per assegnare caratteri
- Ricostruire il layout da rettangoli e stili delle run

## Esempio minimo di acquisizione (bozza)

Usa i DevTools del tuo browser per catturare gli header, cookie e token esatti usati dal lettore quando richiede `/renderer/render`. Poi replica quelli da uno script o curl. Schema d'esempio:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Adatta la parametrizzazione (book ASIN, page window, viewport) per soddisfare le richieste del lettore. Previsto un limite di 5 pagine per richiesta.

## Results achievable

- Ridurre oltre 100 alfabeti randomizzati a un unico spazio di glyph tramite perceptual hashing
- Mappatura al 100% dei glyph unici con SSIM medio ~0.95 quando gli atlanti includono ligature e varianti
- EPUB/HTML ricostruito visivamente indistinguibile dall'originale

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
