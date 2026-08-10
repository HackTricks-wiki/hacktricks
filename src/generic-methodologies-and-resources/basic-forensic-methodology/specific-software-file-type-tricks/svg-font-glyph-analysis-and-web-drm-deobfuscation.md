# Uchambuzi wa SVG/Font Glyph na Web DRM Deobfuscation (Raster Hashing + SSIM)

Ukurasa huu unaeleza mbinu za vitendo za kurejesha maandishi kutoka kwa web readers wanaotuma glyph runs zilizo na nafasi pamoja na ufafanuzi wa vector glyph kwa kila ombi (SVG paths), na wanaobadilisha glyph IDs kwa kila ombi ili kuzuia scraping. Wazo kuu ni kupuuza numeric glyph IDs zinazohusishwa na ombi na kutambua maumbo ya kuona kupitia raster hashing, kisha kuhusisha maumbo hayo na herufi kwa kutumia SSIM dhidi ya reference font atlas. Mbinu hii inaweza pia kutumika kwa viewers wenye ulinzi unaofanana.<sup>[[1]](#references)</sup>

Onyo: Tumia mbinu hizi tu kuhifadhi nakala za maudhui unayomiliki kihalali na kwa kuzingatia sheria na masharti yanayotumika.

## Upataji (mfano: Kindle Cloud Reader)

Endpoint iliyozingatiwa:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vifaa vinavyohitajika kwa kila session:<sup>[[1]](#references)</sup>
- Browser session cookies (Amazon login ya kawaida)
- Rendering token kutoka kwa startReading API call
- Additional ADP session token inayotumiwa na renderer

Tabia:<sup>[[1]](#references)</sup>
- Kila ombi, linapotumwa pamoja na headers na cookies zinazolingana na browser, hurudisha TAR archive yenye ukomo wa kurasa 5.
- Kwa kitabu kirefu utahitaji batches nyingi; kila batch hutumia mapping tofauti ya glyph IDs zilizorandomishwa.

Maudhui ya kawaida ya TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — text runs zilizo na nafasi kama mfululizo wa glyph IDs (si Unicode)
- glyphs.json — SVG path definitions za kila glyph na fontFamily kwa kila ombi
- toc.json — jedwali la yaliyomo
- metadata.json — metadata ya kitabu
- location_map.json — mappings za logical→visual positions

Muundo wa mfano wa page run:<sup>[[1]](#references)</sup>
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
Maelezo kuhusu mbinu za path za anti-scraping:<sup>[[1]](#references)</sup>
- Paths zinaweza kujumuisha miondoko midogo ya relative (kwa mfano, `m3,1 m1,6 m-4,-7`) inayochanganya vector parsers nyingi na path sampling rahisi.
- Daima render paths zilizojazwa na kukamilika kwa kutumia SVG engine thabiti (kwa mfano, CairoSVG) badala ya kufanya utofautishaji wa command/coordinate.

## Kwa nini decoding rahisi hushindwa

- Ubadilishaji wa glyph kwa kila request kwa mpangilio wa random: mapping ya glyph ID→character hubadilika kila batch; IDs hazina maana kwa ujumla.<sup>[[1]](#references)</sup>
- Ulinganishaji wa moja kwa moja wa SVG coordinates si thabiti: shapes zinazofanana zinaweza kutofautiana katika numeric coordinates au command encoding kwa kila request.<sup>[[1]](#references)</sup>
- OCR kwenye glyph zilizotengwa hufanya kazi vibaya (≈50%), huchanganya punctuation na glyph zinazofanana, na hupuuza ligatures.<sup>[[1]](#references)</sup>

## Pipeline inayofanya kazi: glyph normalization na mapping isiyohusishwa na request

1) Rasterize SVG glyphs za kila request
- Tengeneza SVG document ndogo kwa kila glyph ikiwa na `path` iliyotolewa, kisha render kwenye canvas yenye ukubwa maalum (kwa mfano, 512×512) kwa kutumia CairoSVG au engine inayolingana inayoshughulikia path sequences tata.<sup>[[1]](#references)[[2]](#references)</sup>
- Render nyeusi iliyojazwa kwenye background nyeupe; epuka strokes ili kuondoa artifacts zinazotegemea renderer na AA.

2) Perceptual hashing kwa utambulisho kati ya requests
- Kokotoa perceptual hash (kwa mfano, pHash kupitia `imagehash.phash`) ya kila glyph image.<sup>[[3]](#references)</sup>
- Chukulia hash kama ID thabiti: shape ileile ya kuona katika requests tofauti itaunganishwa kuwa perceptual hash ileile, hivyo kushinda IDs za random.

3) Kutengeneza reference font atlas
- Download target TTF/OTF fonts (kwa mfano, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Render candidates za A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), na ligatures zilizoainishwa wazi: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Weka atlases tofauti kwa kila font variant (normal/italic/bold/bold-italic).
- Tumia text shaper sahihi (HarfBuzz) ikiwa unataka glyph-level fidelity kwa ligatures; rasterization rahisi kupitia Pillow ImageFont inaweza kutosha ikiwa unarender strings za ligature moja kwa moja na shaping engine ikazitatua.

4) Visual similarity matching kwa kutumia SSIM
- Kwa kila unknown glyph image, kokotoa SSIM (Structural Similarity Index) dhidi ya candidate images zote katika font variant atlases zote.<sup>[[4]](#references)</sup>
- Assign character string ya match yenye score bora zaidi. SSIM humeza tofauti ndogo za antialiasing, scale, na coordinates vizuri kuliko ulinganishaji wa pixel-exact.<sup>[[1]](#references)[[4]](#references)</sup>

5) Kushughulikia edges na reconstruction
- Glyph inapomap kwenye ligature (multi-char), expand wakati wa decoding.<sup>[[1]](#references)</sup>
- Tumia run rectangles (top/left/right/bottom) kukadiria paragraph breaks (Y deltas), alignment (X patterns), style, na sizes.<sup>[[1]](#references)</sup>
- Serialize hadi HTML/EPUB huku ukihifadhi `fontStyle`, `fontWeight`, `fontSize`, na internal links.<sup>[[1]](#references)</sup>

### Vidokezo vya implementation

- Normalize images zote ziwe na size na grayscale sawa kabla ya hashing na SSIM.
- Cache kwa kutumia perceptual hash ili kuepuka kurudia kukokotoa SSIM kwa glyphs zinazorudiwa katika batches tofauti.
- Tumia raster size yenye quality ya juu (kwa mfano, 256–512 px) kwa discrimination bora; downscale inapohitajika kabla ya SSIM ili kuharakisha.
- Ikiwa unatumia Pillow kurender TTF candidates, weka canvas size ileile na u-center glyph; ongeza padding ili kuepuka kukata ascenders/descenders.

<details>
<summary>Python: end-to-end glyph normalization na matching (raster hash + SSIM)</summary>
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

## Heuristics za layout/EPUB reconstruction

Source report ilitumia run geometry, style fields, na link metadata kuhifadhi formatting ya document iliyoreconstructiwa.<sup>[[1]](#references)</sup>

- Paragraph breaks: Ikiwa top Y ya run inayofuata inazidi baseline ya mstari uliotangulia kwa threshold (ikilinganishwa na font size), anza paragraph mpya.<sup>[[1]](#references)</sup>
- Alignment: Panga kwa left X zinazofanana kwa paragraphs zilizopangiliwa kushoto; tambua mistari iliyowekwa katikati kwa margins zenye usawa; tambua iliyopangiliwa kulia kwa edges za kulia.
- Styling: Hifadhi italic/bold kupitia `fontStyle`/`fontWeight`; badilisha CSS classes kulingana na fontSize buckets ili kukadiria headings dhidi ya body.
- Links: Ikiwa runs zina link metadata (k.m., `positionId`), toa anchors na internal hrefs.

## Kupunguza mbinu za SVG anti-scraping za path

- Tumia filled paths zilizo na `fill-rule: nonzero` na renderer sahihi (CairoSVG, resvg). Usitegemee path token normalization.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Epuka stroke rendering; lenga filled solids ili kuepuka hairline artifacts zinazosababishwa na micro relative moves.
- Dumisha viewBox thabiti kwa kila render ili shapes zinazofanana zirasterize kwa uthabiti katika batches mbalimbali.

## Vidokezo vya performance

- Kwa matumizi ya kawaida, vitabu hujumuika hadi kuwa na glyphs mia chache za kipekee (k.m., ~361 ikijumuisha ligatures). Cache SSIM results kwa perceptual hash.<sup>[[1]](#references)</sup>
- Baada ya discovery ya awali, batches zijazo hutumia tena hashes zinazojulikana; decoding huwa I/O-bound.
- Report iliyotajwa iliona wastani wa SSIM wa takriban 0.95; weka alama kwa matches zenye score ya chini ili zikaguliwe manually.<sup>[[1]](#references)</sup>

## Generalization kwa viewers wengine

Kindle workflow inaonyesha kwamba viewers wengine wanaofanana wanaweza kufaa kwa normalization hiyo hiyo wanapokuwa:<sup>[[1]](#references)</sup>
- wanarudisha positioned glyph runs zenye numeric IDs zinazohusishwa na request
- wanatuma vector glyphs kwa kila request (SVG paths au subset fonts)
- wanaweka kikomo cha pages kwa kila request

…zinaweza kushughulikiwa kwa normalization hiyo hiyo:
- Rasterize shapes za kila request → perceptual hash → shape ID
- Atlas ya candidate glyphs/ligatures kwa kila font variant
- SSIM (au perceptual metric inayofanana) ili kugawa characters
- Reconstruct layout kutoka kwa run rectangles/styles

## Minimal acquisition example (sketch)

Tumia DevTools ya browser yako kunasa headers, cookies na tokens halisi zinazotumiwa na reader wakati wa kuomba `/renderer/render`. Kisha zirudie kupitia script au curl.<sup>[[1]](#references)</sup> Muhtasari wa mfano:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Rekebisha parameterization (book ASIN, page window, viewport) ili kuendana na maombi ya msomaji. Tarajia kikomo cha kurasa 5 kwa kila request.<sup>[[1]](#references)</sup>

## Matokeo yanayoweza kufikiwa

- Punguza alphabets 100+ zilizobadilishwa kwa nasibu kuwa glyph space moja kwa kutumia perceptual hashing.<sup>[[1]](#references)</sup>
- Katika jaribio lililotajwa la kurasa 920, glyphs 361 za kipekee zililinganishwa (100%) kwa SSIM ya wastani ya 0.9527.<sup>[[1]](#references)</sup>
- Ripoti chanzo inaeleza EPUB iliyoundwa upya kuwa karibu kutotofautishwa na ya awali.<sup>[[1]](#references)</sup>

## References

- [1] [Jinsi Nilivyobadili Amazon's Kindle Web Obfuscation Kwa Sababu App Yao Ilikuwa Mbaya (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
