# SVG/Font Glyph Analysis और Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

यह पेज उन web readers से text recover करने की practical techniques का documentation है, जो positioned glyph runs और प्रत्येक request के लिए vector glyph definitions (SVG paths) भेजते हैं, और scraping रोकने के लिए हर request पर glyph IDs को randomize करते हैं। मुख्य विचार request-scoped numeric glyph IDs को अनदेखा करना और raster hashing के माध्यम से visual shapes की fingerprint बनाना है, फिर reference font atlas के विरुद्ध SSIM का उपयोग करके shapes को characters से map करना है। यही approach समान protections वाले viewers पर भी लागू हो सकती है।<sup>[[1]](#references)</sup>

Warning: इन techniques का उपयोग केवल उस content का backup लेने के लिए करें जिसका स्वामित्व आपके पास है, और लागू laws तथा terms का पालन करते हुए करें।

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:<sup>[[1]](#references)</sup>
- Browser session cookies (normal Amazon login)
- startReading API call से rendering token
- renderer द्वारा उपयोग किया जाने वाला additional ADP session token

Behavior:<sup>[[1]](#references)</sup>
- प्रत्येक request, जब browser-equivalent headers और cookies के साथ भेजी जाती है, तो अधिकतम 5 pages तक सीमित TAR archive लौटाती है।
- किसी लंबी book के लिए आपको कई batches की आवश्यकता होगी; प्रत्येक batch glyph IDs की अलग randomized mapping का उपयोग करता है।

Typical TAR contents:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positioned text runs, जो glyph IDs के sequences के रूप में होते हैं (Unicode नहीं)
- glyphs.json — प्रत्येक glyph और fontFamily के लिए per-request SVG path definitions
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

Example page run structure:<sup>[[1]](#references)</sup>
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
उदाहरण glyphs.json entry:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
anti-scraping path tricks पर Notes:<sup>[[1]](#references)</sup>
- Paths में micro relative moves शामिल हो सकते हैं (जैसे, `m3,1 m1,6 m-4,-7`), जो कई vector parsers और naïve path sampling को भ्रमित करते हैं।
- Command/coordinate differencing करने के बजाय, हमेशा भरे हुए complete paths को एक robust SVG engine (जैसे, CairoSVG) से render करें।

## naïve decoding क्यों विफल होता है

- Per-request randomized glyph substitution: glyph ID→character mapping हर batch में बदलती है; IDs globally meaningless होते हैं।<sup>[[1]](#references)</sup>
- Direct SVG coordinate comparison brittle है: प्रत्येक request में समान shapes के numeric coordinates या command encoding अलग हो सकते हैं।<sup>[[1]](#references)</sup>
- Isolated glyphs पर OCR खराब प्रदर्शन करता है (≈50%), punctuation और look-alike glyphs को भ्रमित करता है, और ligatures को अनदेखा करता है।<sup>[[1]](#references)</sup>

## Working pipeline: request-agnostic glyph normalization और mapping

1) Per-request SVG glyphs को rasterize करें
- प्रत्येक glyph के लिए दिए गए `path` के साथ एक minimal SVG document बनाएं और CairoSVG या किसी equivalent engine का उपयोग करके fixed canvas (जैसे, 512×512) पर render करें, जो tricky path sequences को handle करता हो।<sup>[[1]](#references)[[2]](#references)</sup>
- White पर filled black में render करें; renderer- और AA-dependent artifacts को हटाने के लिए strokes से बचें।

2) Cross-request identity के लिए perceptual hashing
- प्रत्येक glyph image का perceptual hash (जैसे, `imagehash.phash` के माध्यम से pHash) compute करें।<sup>[[3]](#references)</sup>
- Hash को stable ID मानें: अलग-अलग requests में समान visual shape एक ही perceptual hash में बदल जाती है, जिससे randomized IDs निष्प्रभावी हो जाते हैं।

3) Reference font atlas generation
- Target TTF/OTF fonts (जैसे, Bookerly normal/italic/bold/bold-italic) download करें।<sup>[[1]](#references)</sup>
- A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes), और explicit ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl` के लिए candidates render करें।
- प्रत्येक font variant (normal/italic/bold/bold-italic) के लिए अलग atlases रखें।
- यदि ligatures के लिए glyph-level fidelity चाहिए, तो proper text shaper (HarfBuzz) का उपयोग करें; यदि आप ligature strings को सीधे render करते हैं और shaping engine उन्हें resolve करता है, तो Pillow ImageFont के माध्यम से simple rasterization पर्याप्त हो सकती है।

4) SSIM के साथ Visual similarity matching
- प्रत्येक unknown glyph image के लिए, सभी font variant atlases में मौजूद सभी candidate images के विरुद्ध SSIM (Structural Similarity Index) compute करें।<sup>[[4]](#references)</sup>
- Best-scoring match की character string assign करें। SSIM pixel-exact comparisons की तुलना में छोटे antialiasing, scale और coordinate differences को बेहतर ढंग से absorb करता है।<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge handling और reconstruction
- जब कोई glyph किसी ligature (multi-char) से map हो, तो decoding के दौरान उसे expand करें।<sup>[[1]](#references)</sup>
- Paragraph breaks (Y deltas), alignment (X patterns), style और sizes का अनुमान लगाने के लिए run rectangles (top/left/right/bottom) का उपयोग करें।<sup>[[1]](#references)</sup>
- `fontStyle`, `fontWeight`, `fontSize` और internal links को preserve करते हुए HTML/EPUB में serialize करें।<sup>[[1]](#references)</sup>

### Implementation tips

- Hashing और SSIM से पहले सभी images को समान size और grayscale में normalize करें।
- Batches में repeated glyphs के लिए SSIM को दोबारा compute करने से बचने हेतु perceptual hash के आधार पर cache करें।
- बेहतर discrimination के लिए high-quality raster size (जैसे, 256–512 px) का उपयोग करें; SSIM को तेज करने के लिए आवश्यकता अनुसार downscale करें।
- यदि TTF candidates render करने के लिए Pillow का उपयोग कर रहे हैं, तो समान canvas size सेट करें और glyph को center में रखें; ascenders/descenders की clipping से बचने के लिए padding दें।

<details>
<summary>Python: end-to-end glyph normalization और matching (raster hash + SSIM)</summary>
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

Source report ने reconstructed document की formatting बनाए रखने के लिए run geometry, style fields और link metadata का उपयोग किया।<sup>[[1]](#references)</sup>

- Paragraph breaks: यदि अगले run का top Y, पिछले line के baseline से (font size के सापेक्ष) निर्धारित threshold से अधिक हो, तो नया paragraph शुरू करें।<sup>[[1]](#references)</sup>
- Alignment: left-aligned paragraphs के लिए समान left X के आधार पर group करें; symmetric margins से centered lines का पता लगाएँ; right edges से right-aligned lines का पता लगाएँ।
- Styling: `fontStyle`/`fontWeight` के माध्यम से italic/bold बनाए रखें; headings और body का अनुमान लगाने के लिए `fontSize` buckets के अनुसार CSS classes बदलें।
- Links: यदि runs में link metadata (जैसे `positionId`) शामिल हो, तो anchors और internal hrefs emit करें।

## SVG anti-scraping path tricks को कम करना

- `fill-rule: nonzero` वाले filled paths और proper renderer (CairoSVG, resvg) का उपयोग करें। Path token normalization पर निर्भर न रहें।<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Stroke rendering से बचें; micro relative moves के कारण होने वाले hairline artifacts को दरकिनार करने के लिए filled solids पर ध्यान दें।
- प्रत्येक render के लिए stable viewBox रखें, ताकि identical shapes batches के बीच consistent रूप से rasterize हों।

## Performance notes

- व्यवहार में, books कुछ सौ unique glyphs तक सीमित हो जाती हैं (जैसे ligatures सहित लगभग 361)। Perceptual hash के आधार पर SSIM results को cache करें।<sup>[[1]](#references)</sup>
- Initial discovery के बाद, future batches मुख्यतः ज्ञात hashes का फिर से उपयोग करते हैं; decoding I/O-bound हो जाता है।
- Cited report में लगभग 0.95 का average SSIM देखा गया; low-scoring matches को manual review के लिए flag करें।<sup>[[1]](#references)</sup>

## Generalization to other viewers

Kindle workflow से संकेत मिलता है कि समान viewers में भी यही normalization लागू की जा सकती है, यदि वे:<sup>[[1]](#references)</sup>
- request-scoped numeric IDs वाले positioned glyph runs return करें
- per-request vector glyphs (SVG paths या subset fonts) ship करें
- प्रत्येक request में pages की संख्या सीमित रखें

…तो उन्हें इसी normalization से handle किया जा सकता है:
- Per-request shapes को rasterize करें → perceptual hash → shape ID
- प्रत्येक font variant के लिए candidate glyphs/ligatures का atlas
- Characters assign करने के लिए SSIM (या समान perceptual metric)
- run rectangles/styles से layout reconstruct करें

## Minimal acquisition example (sketch)

Reader द्वारा `/renderer/render` request करते समय उपयोग किए गए exact headers, cookies और tokens capture करने के लिए अपने browser के DevTools का उपयोग करें। फिर उन्हें किसी script या curl से replicate करें।<sup>[[1]](#references)</sup> Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Reader की requests के अनुसार parameterization (book ASIN, page window, viewport) को समायोजित करें। प्रति request अधिकतम 5 pages की सीमा की अपेक्षा रखें।<sup>[[1]](#references)</sup>

## प्राप्त किए जा सकने वाले परिणाम

- Perceptual hashing के माध्यम से 100+ randomized alphabets को एकल glyph space में समेटें।<sup>[[1]](#references)</sup>
- उद्धृत 920-page test में, 361 unique glyphs का मिलान (100%) हुआ, जिसका औसत SSIM 0.9527 था।<sup>[[1]](#references)</sup>
- Source report के अनुसार reconstructed EPUB मूल से लगभग indistinguishable था।<sup>[[1]](#references)</sup>

## References

- [1] [मैंने Amazon के Kindle Web Obfuscation को reverse किया क्योंकि उनका App बेकार था (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG से PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill properties](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
