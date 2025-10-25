# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea mbinu za vitendo za kupata tena maandishi kutoka kwa web readers ambazo hutuma positioned glyph runs pamoja na per-request vector glyph definitions (SVG paths), na ambazo zinafanya randomize glyph IDs kwa kila ombi ili kuzuia scraping. Wazo kuu ni kupuuza request-scoped numeric glyph IDs na kuchora saini ya maumbo ya kuona kupitia raster hashing, kisha kutoka maumbo hadi herufi kwa SSIM dhidi ya font atlas ya marejeleo. Mchakato unaweza kutumika zaidi ya Kindle Cloud Reader kwa viewer yoyote yenye ulinzi kama huo.

Onyo: Tumia mbinu hizi tu kuhifadhi nakala ya maudhui unayomiliki kwa njia halali na kwa kufuata sheria na vigezo vinavyotumika.

## Acquisition (example: Kindle Cloud Reader)

Endpoint iliyogunduliwa:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vitu vinavyohitajika kwa kila kikao:
- Cookies za kikao cha browser (login ya kawaida ya Amazon)
- Rendering token kutoka kwa startReading API call
- Token ya ziada ya ADP ya kikao inayotumiwa na renderer

Tabia:
- Kila ombi, linapotumwa kwa headers na cookies sawa na zile za browser, hurudisha archive ya TAR iliyopunguzwa kwa kurasa 5.
- Kwa kitabu refu utahitaji batches nyingi; kila batch inatumia ramani tofauti iliyoratibiwa kwa nasibu ya glyph IDs.

Yaliyomo kawaida kwenye TAR:
- page_data_0_4.json — positioned text runs kama mfululizo wa glyph IDs (si Unicode)
- glyphs.json — per-request SVG path definitions kwa kila glyph na fontFamily
- toc.json — table of contents
- metadata.json — metadata ya kitabu
- location_map.json — logical→visual position mappings

Mfano wa muundo wa run za ukurasa:
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
Mfano wa kipengee cha glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes on anti-scraping path tricks:
- Paths may include micro relative moves (e.g., `m3,1 m1,6 m-4,-7`) that confuse many vector parsers and naïve path sampling.
- Always render filled complete paths with a robust SVG engine (e.g., CairoSVG) instead of doing command/coordinate differencing.

## Kwa nini decoding rahisi inashindwa

- Per-request randomized glyph substitution: mapping ya glyph ID→character hubadilika kila batch; IDs hazina maana kwa ujumla.
- Direct SVG coordinate comparison is brittle: maumbo sawa yanaweza kutofautiana kwa numeric coordinates au command encoding kwa kila ombi.
- OCR on isolated glyphs performs poorly (≈50%), inachanganya punctuation na glyphs zinazofanana, na inadharau ligatures.

## Kifurushi cha kazi: glyph normalization na mapping isiyoshikamana na ombi

1) Rasterize per-request SVG glyphs
- Tengeneza hati ndogo ya SVG kwa kila glyph ukiweka `path` iliyotolewa na render kwa canvas thabiti (mf., 512×512) ukitumia CairoSVG au engine sawa inayoshughulikia sequences ngumu za path.
- Render kwa kujazwa nyeusi juu ya nyeupe; epuka strokes ili kuondoa artifacts zinazoegemea renderer na AA.

2) Perceptual hashing for cross-request identity
- Hesabu perceptual hash (mf., pHash via `imagehash.phash`) ya kila picha ya glyph.
- Tumia hash kama ID thabiti: maumbo yale yale ya kuona kati ya maombi yatakuwa na perceptual hash ile ile, kuvunja randomized IDs.

3) Reference font atlas generation
- Pakua fonti za lengo TTF/OTF (mf., Bookerly normal/italic/bold/bold-italic).
- Render wagombea kwa A–Z, a–z, 0–9, punctuation, alama maalum (em/en dashes, quotes), na ligatures waziwazi: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Weka atlasi tofauti kwa kila variant ya fonti (normal/italic/bold/bold-italic).
- Tumia text shaper sahihi (HarfBuzz) ikiwa unataka fidelity ya glyph kwa ligatures; rasterization rahisi kwa kutumia Pillow ImageFont inaweza kutosha ikiwa uterender strings za ligature moja kwa moja na engine ya shaping inazitambua.

4) Visual similarity matching with SSIM
- Kwa kila picha ya glyph isiyojulikana, hesabu SSIM (Structural Similarity Index) dhidi ya picha zote za wagombea katika atlasi zote za variant ya fonti.
- Panga mfululizo wa herufi wa mechi yenye alama bora. SSIM huvumilia tofauti ndogo za antialiasing, skali, na coordinate vizuri zaidi kuliko ulinganifu wa moja kwa moja wa pikseli.

5) Edge handling and reconstruction
- Wakati glyph inarudi kwa ligature (multi-char), iupanue wakati wa decoding.
- Tumia run rectangles (top/left/right/bottom) kubaini mapumziko ya aya (Y deltas), alignment (mfumo za X), style, na sizes.
- Serialize kwa HTML/EPUB ukihifadhi `fontStyle`, `fontWeight`, `fontSize`, na internal links.

### Vidokezo vya utekelezaji

- Normalize picha zote kwa ukubwa ule ule na grayscale kabla ya hashing na SSIM.
- Cache kwa perceptual hash ili kuepuka kuhesabu tena SSIM kwa glyphs zinazojirudia kati ya batches.
- Tumia raster size yenye ubora mkubwa (mf., 256–512 px) kwa utofauti bora; downscale kama inavyohitajika kabla ya SSIM ili kuharakisha.
- Ikiwa unatumia Pillow ku-render wagombea wa TTF, weka canvas size ile ile na weka glyph katikati; ongeza padding ili kuepuka kukatwa kwa ascenders/descenders.

<details>
<summary>Python: ufanyaji wa normalization na matching wa glyph kutoka mwanzo hadi mwisho (raster hash + SSIM)</summary>
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

## Kanuni za ujenzi upya za Layout/EPUB

- Mapumziko ya aya: Ikiwa Y ya juu ya mfululizo unaofuata inazidi mstari wa msingi wa mstari uliopita kwa kikomo (kwa ulinganifu na ukubwa wa fonti), anza aya mpya.
- Ulinganifu: Panganya kwa X ya kushoto yenye ufanano kwa aya zilizo pangiliwa kushoto; tambua mistari iliyowekwa katikati kwa mipaka sawa; tambua zile zilizo pangiliwa kulia kwa kingo za kulia.
- Mtindo: Hifadhi italic/bold kupitia `fontStyle`/`fontWeight`; badilisha madaraja ya CSS kwa kutumia `fontSize` vikundi ili kukisia vichwa dhidi ya mwili wa maandishi.
- Viunganisho: Ikiwa mfululizo una metadata ya kiunganisho (mfano, `positionId`), tengeneza anchors na href za ndani.

## Kupunguza mbinu za anti-scraping za SVG path

- Tumia path zilizojazwa na `fill-rule: nonzero` na renderer sahihi (CairoSVG, resvg). Usitegemee path token normalization.
- Epuka rendering ya stroke; zingatia solids zilizojazwa ili kuepuka artefakti nyembamba zinazotokana na harakati ndogo za uhusiano.
- Hakikisha viewBox thabiti kwa kila render ili maumbo sawa yazorasterize kwa usawa across batches.

## Vidokezo vya utendaji

- Kivitendo, vitabu hujishinikiza hadi glyphs chache za kipekee (kwa mfano, ~361 ikiwa ni pamoja na ligatures). Hifadhi matokeo ya SSIM kwa perceptual hash.
- Baada ya ugunduzi wa awali, batches zijazo kwa ujumla hutumia tena hashi zilizojulikana; decoding inakuwa bound kwa I/O.
- SSIM ya wastani ≈0.95 ni ishara yenye nguvu; fikiria kuweka alama mechi zenye alama ndogo kwa ukaguzi wa mkono.

## Uenezi kwa viewers wengine

Mfumo wowote ambao:
- Inarudisha positioned glyph runs zenye request-scoped numeric IDs
- Inapeleka per-request vector glyphs (SVG paths au subset fonts)
- Inazuia pages kwa ombi ili kuzuia bulk export

…inaweza kushughulikiwa na normalization ile ile:
- Rasterize maumbo kwa kila ombi → perceptual hash → shape ID
- Atlas ya glyphs/ligatures wanaofaa kwa kila variant ya font
- SSIM (au kipimo cha perceptual kinachofanana) kutumika kugawa characters
- Jenga upya layout kutoka kwa mstatili/mitindo ya run

## Mfano wa upokeaji wa chini (sketch)

Tumia DevTools ya browser yako ili kunasa headers halisi, cookies na tokens zinazotumika na reader wakati wa kuomba `/renderer/render`. Kisha rudia hizo kutoka script au curl. Muhtasari wa mfano:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Rekebisha uparametrishaji (book ASIN, page window, viewport) ili kuendana na maombi ya msomaji. Anta kikomo cha 5 kurasa kwa kila ombi.

## Matokeo yanayoweza kupatikana

- Punguza alfabeti 100+ zilizopangwa kwa nasibu hadi nafasi moja ya glyph kwa kutumia perceptual hashing
- Ramani ya 100% ya glyphs za kipekee kwa SSIM ya wastani ~0.95 wakati atlases zinajumuisha ligatures na variants
- EPUB/HTML iliyojengwa upya haionekani tofauti na asili

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
