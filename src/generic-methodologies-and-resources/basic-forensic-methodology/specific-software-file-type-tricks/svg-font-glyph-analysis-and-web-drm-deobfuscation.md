# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie blad dokumenteer praktiese tegnieke om teks te herstel vanaf web readers wat gepositioneerde glyph-runs stuur plus per-request vektor-glyph-definisies (SVG paths), en wat glyph IDs per versoek randomiseer om scraping te voorkom. Die kernidee is om versoek-geskoppe numeriese glyph IDs te ignoreer en die visuele vorms te fingerprint via raster hashing, en dan vorms na karakters te map met SSIM teen 'n verwysings font atlas. Die workflow generaliseer buite Kindle Cloud Reader na enige viewer met soortgelyke beskerming.

Waarskuwing: Gebruik hierdie tegnieke slegs om inhoud wat jy wettiglik besit te rugsteun en in ooreenstemming met toepaslike wette en bepalings.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vereiste materiale per sessie:
- Browser session cookies (normale Amazon login)
- Rendering token vanaf 'startReading' API-aanroep
- Addisionele ADP session token wat deur die renderer gebruik word

Gedrag:
- Elke versoek, wanneer dit gestuur word met browser-equivalent headers en cookies, lewer 'n TAR-argief beperk tot 5 bladsye.
- Vir 'n lang boek sal jy baie batches nodig hê; elke batch gebruik 'n ander gerandomiseerde mapping van glyph IDs.

Tipiese TAR-inhoud:
- page_data_0_4.json — gepositioneerde tekst runs as sequences of glyph IDs (not Unicode)
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
Voorbeeld glyphs.json inskrywing:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete `path` elements with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

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
<summary>Python: end-tot-end glyph-normalisering en ooreenstemming (raster-hash + SSIM)</summary>
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

## Layout/EPUB reconstruction heuristics

- Paragraafbreuke: As die volgende run se boonste Y die vorige reël se basislyn met 'n drempel (relatief tot lettergrootte) oorskry, begin 'n nuwe paragraaf.
- Uitlijning: Groepeer volgens soortgelyke linker X vir links-uitgelykte paragrawe; herken gesentreerde reëls aan simmetriese marge; herken regs-uitgelykte reëls aan regterkante.
- Styling: Behou kursief/vet via `fontStyle`/`fontWeight`; varieer CSS classes deur `fontSize`-emmers om opskrifte teenoor liggaamstekst te benader.
- Skakels: As runs skakel-metadata bevat (bv. `positionId`), genereer anchors en interne hrefs.

## Mitigating SVG anti-scraping path tricks

- Gebruik gevulde paths met `fill-rule: nonzero` en 'n ordentlike renderer (CairoSVG, resvg). Moet nie staatmaak op path token normalisering nie.
- Vermy stroke-rendering; fokus op gevulde soliede vorms om haarfyn-artefakte wat deur mikro-relatiewe beweegings veroorsaak word, te omseil.
- Behou 'n stabiele viewBox per render sodat identiese vorms konsekwent oor groepe gerasteriseer word.

## Performance notes

- In die praktyk konvergeer boeke na 'n paar honderd unieke glyphs (bv. ~361 insluitend ligatures). Kas SSIM-resultate op grond van 'n perceptual hash.
- Na die aanvanklike ontdekking hergebruik toekomstige groepe meestal bekende hashes; dekodering word I/O-bound.
- Gemiddelde SSIM ≈0.95 is 'n sterk sein; oorweeg om laaggescoreerde treffers vir handmatige hersiening te vlag.

## Generalization to other viewers

Enige stelsel wat:
- Retourneer gepositioneerde glyph-runs met aanvraag-geskepte numeriese IDs
- Lewer per-aanvraag vektor-glyphs (SVG paths of subset fonts)
- Beperk bladsye per aanvraag om massale uitvoer te voorkom

…kan met dieselfde normalisering hanteer word:
- Rasteriseer per-aanvraag vorms → perceptual hash → shape ID
- Atlas van kandidaat-glyphs/ligatures per font-variant
- SSIM (of 'n soortgelyke perceptuele metriek) om karakters toe te ken
- Herbou uitleg vanaf run-rechthoeke/style

## Minimal acquisition example (sketch)

Gebruik jou blaaier se DevTools om die presiese headers, cookies en tokens vas te vang wat deur die reader gebruik word wanneer `/renderer/render` aangevra word. Repliseer dit dan met 'n script of curl. Voorbeeld-oorsig:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Pas parameterisering (book ASIN, page window, viewport) aan om by die leser se versoeke te pas. Verwag 'n limiet van 5 bladsye per versoek.

## Bereikbare resultate

- Verminder 100+ gerandomiseerde alfabete tot 'n enkele glyfspasie via perceptual hashing
- 100% kartering van unieke glywe met 'n gemiddelde SSIM ~0.95 wanneer atlasse ligatures en variante insluit
- Herboude EPUB/HTML visueel ononderskeibaar van die oorspronklike

## Verwysings

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
