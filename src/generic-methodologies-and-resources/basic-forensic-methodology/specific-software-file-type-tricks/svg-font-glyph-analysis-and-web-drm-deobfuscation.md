# Uchambuzi wa SVG/Font Glyph & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unaandika mbinu za kiutendaji za kurejesha maandishi kutoka kwa web readers wanaotuma glyph runs zilizowekwa katika nafasi pamoja na vector glyph definitions za kila request (SVG paths), na wanaobadilisha glyph IDs kwa kila request ili kuzuia scraping. Wazo kuu ni kupuuza numeric glyph IDs zinazohusiana na request husika na kutambua alama za kuona kwa kutumia raster hashing, kisha kuhusisha alama hizo na characters kwa kutumia SSIM dhidi ya reference font atlas. Mbinu hiyo hiyo inaweza kutumika kwa viewers wenye ulinzi unaofanana.<sup>[[1]](#references)</sup>

Onyo: Tumia mbinu hizi pekee kuhifadhi nakala za maudhui unayomiliki kihalali na kwa kufuata sheria pamoja na masharti yanayotumika.

## Upatikanaji (mfano: Kindle Cloud Reader)

Endpoint iliyobainishwa:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vifaa vinavyohitajika kwa kila session:<sup>[[1]](#references)</sup>
- Browser session cookies (Amazon login ya kawaida)
- Rendering token kutoka kwa startReading API call
- ADP session token ya ziada inayotumiwa na renderer

Tabia:<sup>[[1]](#references)</sup>
- Kila request, inapotumwa ikiwa na headers na cookies zinazolingana na browser, hurejesha TAR archive yenye kikomo cha pages 5.
- Kwa kitabu kirefu utahitaji batches nyingi; kila batch hutumia mapping tofauti iliyobadilishwa kwa nasibu ya glyph IDs.

Yaliyomo kwa kawaida kwenye TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positioned text runs kama mfululizo wa glyph IDs (si Unicode)
- glyphs.json — per-request SVG path definitions kwa kila glyph na fontFamily
- toc.json — table of contents
- metadata.json — book metadata
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
- Paths zinaweza kujumuisha mikusanyo midogo ya relative moves (kwa mfano, `m3,1 m1,6 m-4,-7`) inayochanganya vector parsers nyingi na path sampling rahisi.
- Daima render paths zilizojazwa na zilizokamilika kwa kutumia SVG engine imara (kwa mfano, CairoSVG) badala ya kufanya utofautishaji wa commands/coordinates.

## Kwa nini decoding rahisi hushindwa

- Per-request randomized glyph substitution: mapping ya glyph ID→character hubadilika kila batch; IDs hazina maana kwa ujumla.<sup>[[1]](#references)</sup>
- Ulinganishaji wa coordinates za SVG moja kwa moja hauna uthabiti: shapes zinazofanana zinaweza kutofautiana katika numeric coordinates au command encoding kwa kila request.<sup>[[1]](#references)</sup>
- OCR kwenye glyphs zilizotengwa hufanya kazi vibaya (≈50%), huchanganya punctuation na glyphs zinazofanana, na hupuuza ligatures.<sup>[[1]](#references)</sup>

## Pipeline inayofanya kazi: glyph normalization na mapping isiyofungamana na request

1) Rasterize per-request SVG glyphs
- Tengeneza SVG document ndogo kwa kila glyph kwa kutumia `path` iliyotolewa na render kwenye canvas yenye ukubwa usiobadilika (kwa mfano, 512×512) ukitumia CairoSVG au engine inayolingana inayoshughulikia path sequences tata.<sup>[[1]](#references)[[2]](#references)</sup>
- Render ikiwa imejazwa kwa rangi nyeusi kwenye background nyeupe; epuka strokes ili kuondoa artifacts zinazotegemea renderer na AA.

2) Perceptual hashing kwa utambulisho wa cross-request
- Kadiria perceptual hash (kwa mfano, pHash kupitia `imagehash.phash`) ya kila glyph image.<sup>[[3]](#references)</sup>
- Chukulia hash kama ID thabiti: shape ileile ya kuonekana katika requests mbalimbali itaunganishwa kuwa perceptual hash ileile, hivyo kushinda randomized IDs.

3) Utengenezaji wa reference font atlas
- Pakua fonts za TTF/OTF zinazolengwa (kwa mfano, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Render candidates za A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), na ligatures zilizoainishwa wazi: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Weka atlases tofauti kwa kila font variant (normal/italic/bold/bold-italic).
- Tumia text shaper sahihi (HarfBuzz) ikiwa unataka glyph-level fidelity kwa ligatures; rasterization rahisi kupitia Pillow ImageFont inaweza kutosha ikiwa unarender strings za ligature moja kwa moja na shaping engine ikazitatua.

4) Visual similarity matching kwa kutumia SSIM
- Kwa kila unknown glyph image, kadiria SSIM (Structural Similarity Index) dhidi ya candidate images zote katika font variant atlases zote.<sup>[[4]](#references)</sup>
- Weka character string ya match yenye score bora. SSIM inachukua vizuri tofauti ndogo za antialiasing, scale, na coordinates kuliko comparisons zinazohitaji pixels zifanane kabisa.<sup>[[1]](#references)[[4]](#references)</sup>

5) Kushughulikia edges na reconstruction
- Glyph inapomappingiwa kuwa ligature (multi-char), expand wakati wa decoding.<sup>[[1]](#references)</sup>
- Tumia run rectangles (top/left/right/bottom) kukadiria paragraph breaks (Y deltas), alignment (X patterns), style, na sizes.<sup>[[1]](#references)</sup>
- Serialize kuwa HTML/EPUB huku ukihifadhi `fontStyle`, `fontWeight`, `fontSize`, na internal links.<sup>[[1]](#references)</sup>

### Vidokezo vya utekelezaji

- Normalize images zote ziwe na size na grayscale sawa kabla ya hashing na SSIM.
- Cache kwa kutumia perceptual hash ili kuepuka kukokotoa upya SSIM kwa glyphs zinazorudiwa katika batches mbalimbali.
- Tumia raster size yenye quality ya juu (kwa mfano, 256–512 px) kwa discrimination bora; downscale inapohitajika kabla ya SSIM ili kuharakisha.
- Ikiwa unatumia Pillow kurender TTF candidates, weka canvas size ileile na center glyph; ongeza padding ili kuepuka kukata ascenders/descenders.

<details>
<summary>Python: glyph normalization na matching kutoka mwanzo hadi mwisho (raster hash + SSIM)</summary>
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

Ripoti ya chanzo ilitumia jiometri ya runs, sehemu za style, na metadata ya links ili kuhifadhi formatting ya document iliyoundwa upya.<sup>[[1]](#references)</sup>

- Mapumziko ya paragraph: Ikiwa Y ya juu ya run inayofuata inazidi baseline ya mstari uliotangulia kwa kiwango fulani (ikilinganishwa na ukubwa wa font), anza paragraph mpya.<sup>[[1]](#references)</sup>
- Alignment: Panga kwa X ya kushoto inayofanana kwa paragraphs zilizo-left-aligned; tambua mistari iliyowekwa katikati kwa margins zenye usawa; tambua iliyo-right-aligned kwa edges za kulia.
- Styling: Hifadhi italic/bold kupitia `fontStyle`/`fontWeight`; badilisha CSS classes kulingana na vikundi vya `fontSize` ili kukadiria headings dhidi ya body.
- Links: Ikiwa runs zina metadata ya link (kwa mfano, `positionId`), toa anchors na hrefs za ndani.

## Kupunguza mbinu za SVG za anti-scraping za path

- Tumia paths zilizojazwa zenye `fill-rule: nonzero` na renderer inayofaa (CairoSVG, resvg). Usitumie path token normalization.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Epuka stroke rendering; lenga solids zilizojazwa ili kuepuka hairline artifacts zinazosababishwa na relative moves ndogo sana.
- Dumisha viewBox thabiti kwa kila render ili shapes zinazofanana zirasterize kwa uthabiti katika batches mbalimbali.

## Maelezo ya performance

- Kwa vitendo, books hujikusanya kuwa glyphs chache za kipekee (kwa mfano, ~361 pamoja na ligatures). Cache matokeo ya SSIM kwa kutumia perceptual hash.<sup>[[1]](#references)</sup>
- Baada ya discovery ya awali, batches zinazofuata hutumia tena hashes zinazojulikana kwa kiasi kikubwa; decoding huwa I/O-bound.
- Ripoti ya d iliona SSIM ya wastani ya takriban 0.95; weka alama kwa matches zenye alama ndogo kwa ajili ya manual review.<sup>[[1]](#references)</sup>

## Generalization kwa viewers wengine

Workflow ya Kindle inaonyesha kuwa viewers wanaofanana wanaweza kufaa kwa normalization hiyo hiyo ikiwa:<sup>[[1]](#references)</sup>
- wanarudisha positioned glyph runs zenye numeric IDs zinazohusishwa na request
- wanatuma vector glyphs za kila request (SVG paths au subset fonts)
- wanaweka kikomo cha pages kwa kila request

…zinaweza kushughulikiwa kwa normalization hiyo hiyo:
- Rasterize shapes za kila request → perceptual hash → shape ID
- Atlas ya candidate glyphs/ligatures kwa kila font variant
- SSIM (au perceptual metric inayofanana) ya kugawa characters
- Unda upya layout kutokana na rectangles/styles za runs

## Mfano mdogo wa acquisition (sketch)

Tumia DevTools za browser yako kunasa headers, cookies na tokens halisi zinazotumiwa na reader wakati wa kuomba `/renderer/render`. Kisha zirudie kupitia script au curl.<sup>[[1]](#references)</sup> Muhtasari wa mfano:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Rekebisha uwekaji wa parameter (book ASIN, page window, viewport) ili ulingane na maombi ya msomaji. Tarajia kikomo cha kurasa 5 kwa kila ombi.<sup>[[1]](#references)</sup>

## Matokeo yanayoweza kufikiwa

- Kunja alphabets 100+ zilizowekwa random kuwa glyph space moja kupitia perceptual hashing.<sup>[[1]](#references)</sup>
- Katika jaribio la d lenye kurasa 920, glyphs 361 za kipekee zililinganishwa (100%) kwa wastani wa SSIM wa 0.9527.<sup>[[1]](#references)</sup>
- Ripoti ya chanzo inaeleza kuwa EPUB iliyoundwa upya ilikuwa karibu kutotofautika na ya awali.<sup>[[1]](#references)</sup>

## References

- [1] [Jinsi Nilivyoreverse Amazon's Kindle Web Obfuscation Kwa Sababu App Yao Ilikuwa Mbaya (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – Renderer ya SVG hadi PNG](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Sifa za fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – Maktaba ya SVG rendering](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
