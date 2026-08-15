# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unaandika mbinu za vitendo za kurejesha maandishi kutoka kwa web readers wanaosafirisha glyph runs zilizowekwa pamoja na vector glyph definitions kwa kila request (SVG paths), na wanaobadilisha glyph IDs kwa kila request ili kuzuia scraping. Wazo kuu ni kupuuza numeric glyph IDs zinazohusishwa na request na kutambua maumbo ya kuona kupitia raster hashing, kisha kuhusisha maumbo hayo na herufi kwa kutumia SSIM dhidi ya reference font atlas. Mbinu hii inaweza pia kutumika kwa viewers wenye ulinzi unaofanana.<sup>[[1]](#references)</sup>

Onyo: Tumia mbinu hizi pekee kuhifadhi nakala za maudhui unayomiliki kihalali na kwa kuzingatia sheria na masharti yanayotumika.

## Acquisition (example: Kindle Cloud Reader)

Endpoint iliyozingatiwa:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vifaa vinavyohitajika kwa kila session:<sup>[[1]](#references)</sup>
- Browser session cookies (Amazon login ya kawaida)
- Rendering token kutoka kwa startReading API call
- ADP session token ya ziada inayotumiwa na renderer

Tabia:<sup>[[1]](#references)</sup>
- Kila request, inapotumwa ikiwa na headers na cookies zinazolingana na browser, hurudisha TAR archive yenye ukomo wa pages 5.
- Kwa kitabu kirefu utahitaji batches nyingi; kila batch hutumia mapping tofauti iliyobadilishwa bila mpangilio ya glyph IDs.

Maudhui ya kawaida ya TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positioned text runs kama mfululizo wa glyph IDs (si Unicode)
- glyphs.json — SVG path definitions kwa kila glyph na fontFamily kwa kila request
- toc.json — table of contents
- metadata.json — metadata ya kitabu
- location_map.json — mappings za logical→visual positions

Mfumo wa mfano wa page run:<sup>[[1]](#references)</sup>
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
Mfano wa ingizo la glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Vidokezo kuhusu mbinu za paths za anti-scraping:<sup>[[1]](#references)</sup>
- Paths zinaweza kujumuisha miondoko midogo ya relative (kwa mfano, `m3,1 m1,6 m-4,-7`) inayochanganya vector parsers nyingi na path sampling rahisi.
- Daima render filled complete paths kwa kutumia SVG engine imara (kwa mfano, CairoSVG) badala ya kufanya command/coordinate differencing.

## Kwa nini decoding rahisi hushindwa

- Per-request randomized glyph substitution: mapping ya glyph ID→character hubadilika kila batch; IDs hazina maana kwa ujumla.<sup>[[1]](#references)</sup>
- Ulinganishaji wa moja kwa moja wa SVG coordinates si thabiti: shapes zinazofanana zinaweza kutofautiana katika numeric coordinates au command encoding kwa kila request.<sup>[[1]](#references)</sup>
- OCR kwenye glyphs zilizotengwa hufanya kazi vibaya (≈50%), huchanganya punctuation na glyphs zinazofanana, na hupuuza ligatures.<sup>[[1]](#references)</sup>

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- Unda minimal SVG document kwa kila glyph ukitumia `path` iliyotolewa na u-render kwenye fixed canvas (kwa mfano, 512×512) ukitumia CairoSVG au engine inayolingana inayoshughulikia tricky path sequences.<sup>[[1]](#references)[[2]](#references)</sup>
- Render filled black on white; epuka strokes ili kuondoa artifacts zinazotegemea renderer na AA.

2) Perceptual hashing for cross-request identity
- Kokotoa perceptual hash (kwa mfano, pHash kupitia `imagehash.phash`) ya kila glyph image.<sup>[[3]](#references)</sup>
- Chukulia hash kama stable ID: shape ileile ya kimaonekano katika requests mbalimbali itaunganishwa kuwa perceptual hash ileile, hivyo kushinda randomized IDs.

3) Reference font atlas generation
- Pakua target TTF/OTF fonts (kwa mfano, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Render candidates za A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), na explicit ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Weka atlases tofauti kwa kila font variant (normal/italic/bold/bold-italic).
- Tumia proper text shaper (HarfBuzz) ikiwa unataka glyph-level fidelity kwa ligatures; simple rasterization kupitia Pillow ImageFont inaweza kutosha ikiwa uta-render ligature strings moja kwa moja na shaping engine ikazitatua.

4) Visual similarity matching with SSIM
- Kwa kila unknown glyph image, kokotoa SSIM (Structural Similarity Index) dhidi ya candidate images zote katika font variant atlases zote.<sup>[[4]](#references)</sup>
- Assign character string ya match yenye score bora zaidi. SSIM hufidia tofauti ndogo za antialiasing, scale, na coordinates vizuri zaidi kuliko pixel-exact comparisons.<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge handling and reconstruction
- Glyph inapomapishwa kuwa ligature (multi-char), expand wakati wa decoding.<sup>[[1]](#references)</sup>
- Tumia run rectangles (top/left/right/bottom) kukadiria paragraph breaks (Y deltas), alignment (X patterns), style, na sizes.<sup>[[1]](#references)</sup>
- Serialize hadi HTML/EPUB ukihifadhi `fontStyle`, `fontWeight`, `fontSize`, na internal links.<sup>[[1]](#references)</sup>

### Implementation tips

- Normalize images zote ziwe na size na grayscale sawa kabla ya hashing na SSIM.
- Cache kwa perceptual hash ili kuepuka kukokotoa upya SSIM kwa repeated glyphs katika batches mbalimbali.
- Tumia high-quality raster size (kwa mfano, 256–512 px) kwa discrimination bora; downscale inapohitajika kabla ya SSIM ili kuharakisha.
- Ikiwa unatumia Pillow ku-render TTF candidates, weka canvas size sawa na u-center glyph; ongeza padding ili kuepuka kukata ascenders/descenders.

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

## Heuristics za uundaji upya wa Layout/EPUB

Ripoti chanzo ilitumia jiometri ya runs, sehemu za style, na metadata ya links ili kuhifadhi formatting ya document iliyoundwa upya.<sup>[[1]](#references)</sup>

- Kuvunja paragraphs: Ikiwa Y ya juu ya run inayofuata inazidi baseline ya line iliyotangulia kwa threshold (ikilinganishwa na font size), anza paragraph mpya.<sup>[[1]](#references)</sup>
- Alignment: Panga kwa left X inayofanana kwa paragraphs zilizo left-aligned; tambua lines zilizocentered kwa margins zenye ulinganifu; tambua zilizo right-aligned kwa edges za kulia.
- Styling: Hifadhi italic/bold kupitia `fontStyle`/`fontWeight`; badilisha CSS classes kulingana na buckets za `fontSize` ili kukadiria headings dhidi ya body.
- Links: Ikiwa runs zina metadata ya link (kwa mfano, `positionId`), toa anchors na internal hrefs.

## Kupunguza mbinu za SVG anti-scraping za paths

- Tumia paths zilizojaa zenye `fill-rule: nonzero` na renderer sahihi (CairoSVG, resvg). Usitumie path token normalization.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Epuka stroke rendering; lenga solids zilizojaa ili kuepuka hairline artifacts zinazosababishwa na micro relative moves.
- Dumisha viewBox thabiti kwa kila render ili shapes zinazofanana zirasterize kwa uthabiti katika batches.

## Maelezo ya performance

- Kwa vitendo, books hukusanyika kuwa glyphs za kipekee mia chache (kwa mfano, ~361 ikijumuisha ligatures). Cache matokeo ya SSIM kwa perceptual hash.<sup>[[1]](#references)</sup>
- Baada ya discovery ya awali, batches zijazo hutumia tena hashes zinazojulikana kwa kiasi kikubwa; decoding huwa I/O-bound.
- Ripoti iliyotajwa iliona SSIM ya wastani ya takriban 0.95; weka alama kwenye matches zenye score ya chini kwa manual review.<sup>[[1]](#references)</sup>

## Generalization kwa viewers wengine

Kindle workflow inapendekeza kwamba viewers wanaofanana wanaweza kufaa kwa normalization hiyo hiyo wanapokuwa:<sup>[[1]](#references)</sup>
- wanarudisha glyph runs zilizo na positions zenye numeric IDs zinazohusishwa na request
- wanatuma vector glyphs za kila request (SVG paths au subset fonts)
- wanapunguza idadi ya pages kwa request

…zinaweza kushughulikiwa kwa normalization hiyo hiyo:
- Rasterize shapes za kila request → perceptual hash → shape ID
- Atlas ya candidate glyphs/ligatures kwa kila font variant
- SSIM (au perceptual metric inayofanana) kwa ajili ya kugawa characters
- Unda upya layout kutoka kwa rectangles/styles za runs

## Mfano mdogo wa acquisition (sketch)

Tumia DevTools za browser yako kunasa headers, cookies na tokens halisi zinazotumiwa na reader wakati wa kuomba `/renderer/render`. Kisha zirudie kutoka kwenye script au curl.<sup>[[1]](#references)</sup> Muhtasari wa mfano:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Rekebisha parameterization (book ASIN, page window, viewport) ili ilingane na maombi ya msomaji. Tarajia kikomo cha kurasa 5 kwa kila request.<sup>[[1]](#references)</sup>

## Matokeo yanayoweza kupatikana

- Punguza alphabets 100+ zilizowekwa randomized hadi glyph space moja kwa kutumia perceptual hashing.<sup>[[1]](#references)</sup>
- Katika jaribio lililotajwa la kurasa 920, glyphs 361 za kipekee zililinganishwa (100%) kwa SSIM ya wastani ya 0.9527.<sup>[[1]](#references)</sup>
- Ripoti ya chanzo inaeleza EPUB iliyojengwa upya kuwa karibu kutotofautiana na ya awali.<sup>[[1]](#references)</sup>

## References

- [1] [Jinsi Nilivyogeuza Amazon's Kindle Web Obfuscation Kwa Sababu App Yao Ilikuwa Mbaya (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderer ya SVG hadi PNG](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Sifa za fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – library ya SVG rendering](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
