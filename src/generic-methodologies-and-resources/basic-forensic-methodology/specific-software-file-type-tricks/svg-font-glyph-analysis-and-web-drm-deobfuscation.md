# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

यह पेज उन व्यावहारिक तकनीकों का विवरण देता है जिनसे वेब रीडर्स से टेक्स्ट रिकवर किया जा सके, जो positioned glyph runs और प्रति-रिक्वेस्ट vector glyph definitions (SVG paths) भेजते हैं, और scraping रोकने के लिए glyph IDs को प्रति-रिक्वेस्ट randomize करते हैं। मूल विचार यह है कि request-scoped numeric glyph IDs को अनदेखा करके visual shapes का fingerprint raster hashing के माध्यम से लें, और फिर reference font atlas के खिलाफ SSIM का उपयोग करके shapes को characters से map करें। यह workflow Kindle Cloud Reader से परे किसी भी viewer पर लागू होता है जिनमें समान protections हों।

चेतावनी: इन तकनीकों का उपयोग केवल उस सामग्री का बैकअप लेने के लिए करें जिसके आप वैध मालिक हैं और जो लागू कानूनों तथा शर्तों के अनुरूप हो।

## प्राप्ति (उदाहरण: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

प्रति-सत्र आवश्यक सामग्री:
- ब्राउज़र session cookies (सामान्य Amazon लॉगिन)
- startReading API कॉल से Rendering token
- renderer द्वारा उपयोग किया जाने वाला अतिरिक्त ADP session token

व्यवहार:
- जब प्रत्येक रिक्वेस्ट ब्राउज़र-समकक्ष headers और cookies के साथ भेजी जाती है, तो यह 5 पृष्ठों तक सीमित एक TAR archive वापस करती है।
- एक लंबी किताब के लिए आपको कई batches की आवश्यकता होगी; प्रत्येक batch glyph IDs के एक अलग randomized mapping का उपयोग करता है।

सामान्य TAR सामग्री:
- page_data_0_4.json — स्थित text runs जो glyph IDs की श्रृंखलाओं के रूप में होते हैं (Unicode नहीं)
- glyphs.json — प्रत्येक glyph और fontFamily के लिए प्रति-रिक्वेस्ट SVG path परिभाषाएँ
- toc.json — विषय-सूची
- metadata.json — पुस्तक metadata
- location_map.json — तार्किक→दृश्य स्थिति मैपिंग

पृष्ठ रन संरचना का उदाहरण:
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
उदाहरण glyphs.json प्रविष्टि:
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

## Layout/EPUB पुनर्निर्माण हीयूरिस्टिक्स

- पैराग्राफ़ ब्रेक: अगर अगले run का top Y पिछले लाइन के baseline से किसी थ्रेशोल्ड (फ़ॉन्ट आकार के सापेक्ष) से अधिक है, तो नया पैराग्राफ़ शुरू करें।
- Alignment: left-aligned पैराग्राफ़ के लिए समान left X के आधार पर समूह बनाएं; centered लाइनों का पता symmetric margins से लगाएँ; right-aligned का पता right edges से लगाएँ।
- Styling: italic/bold को `fontStyle`/`fontWeight` के जरिए बरकरार रखें; headings बनाम body का अनुमान लगाने के लिए `fontSize` buckets के आधार पर CSS classes बदलें।
- Links: अगर runs में link metadata (उदा., `positionId`) शामिल है, तो anchors और internal hrefs उत्पन्न करें।

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Path token normalization पर निर्भर न रहें।
- Avoid stroke rendering; micro relative moves के कारण होने वाले hairline artifacts से बचने के लिए filled solids पर ध्यान दें।
- प्रति render एक स्थिर viewBox रखें ताकि समान shapes batches में सुसंगत रूप से rasterize हों।

## Performance notes

- व्यवहार में, किताबें कुछ सौ unique glyphs पर converge करती हैं (उदा., ~361 ligatures सहित)। SSIM परिणामों को perceptual hash द्वारा cache करें।
- प्रारंभिक खोज के बाद, भविष्य के batches मुख्यतः ज्ञात hashes का पुनः उपयोग करते हैं; decoding I/O-bound हो जाता है।
- औसत SSIM ≈0.95 एक मजबूत संकेत है; कम-स्कोर वाले मैचों को मैनुअल समीक्षा के लिए flag करने पर विचार करें।

## Generalization to other viewers

कोई भी सिस्टम जो:
- request-scoped numeric IDs के साथ positioned glyph runs लौटाता है
- per-request vector glyphs (SVG paths या subset fonts) भेजता है
- bulk export रोकने के लिए प्रति request pages को cap करता है

…उसी normalization के साथ संभाला जा सकता है:
- per-request shapes को rasterize करें → perceptual hash → shape ID
- प्रति font variant के लिए candidate glyphs/ligatures का atlas
- characters असाइन करने के लिए SSIM (या समान perceptual metric)
- run rectangles/styles से layout पुनर्निर्माण करें

## Minimal acquisition example (sketch)

अपने ब्राउज़र के DevTools का उपयोग करके उस reader द्वारा `/renderer/render` अनुरोध करते समय प्रयुक्त exact headers, cookies और tokens कैप्चर करें। फिर इन्हें किसी script या curl से replicate करें। Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
पाठक की मांग के अनुसार पैरामीटराइज़ेशन (book ASIN, page window, viewport) समायोजित करें। प्रति अनुरोध 5-पृष्ठ की सीमा की अपेक्षा रखें।

## प्राप्त परिणाम

- perceptual hashing के माध्यम से 100+ randomized alphabets को एक ही glyph space में संकुचित करना
- जब atlases में ligatures और variants शामिल हों तो average SSIM ~0.95 के साथ unique glyphs का 100% mapping
- पुनर्निर्मित EPUB/HTML दृश्य रूप से मूल से अलग नहीं

## संदर्भ

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
