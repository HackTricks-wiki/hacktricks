# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktične tehnike za oporavak teksta iz web čitača koji isporučuju pozicionirane tokove glyph-ova uz vektor-definicije glyph-ova po zahtevu (SVG paths), i koji nasumično menjaju glyph ID-e po zahtevu da bi sprečili scraping. Osnovna ideja je da se ignorišu numerički glyph ID-evi ograničeni na pojedinačni zahtev i da se otisci vizuelnih oblika naprave pomoću raster hashing, a zatim da se oblici mapiraju na karaktere koristeći SSIM upoređivanjem sa referentnim font atlasom. Radni tok se može generalizovati van Kindle Cloud Reader ka bilo kom viewer-u sa sličnim zaštitama.

Upozorenje: Koristite ove tehnike samo da biste napravili rezervnu kopiju sadržaja koji zakonito posedujete i u skladu sa važećim zakonima i uslovima.

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
- page_data_0_4.json — pozicionirani tekstualni tokovi kao sekvence glyph ID-eva (ne Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
- toc.json — sadržaj
- metadata.json — metapodaci knjige
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
Primer unosa u glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Napomene o trikovima sa putanjama protiv scraping-a:
- Putanje mogu uključivati mikro relativne pomeraje (npr. `m3,1 m1,6 m-4,-7`) koji zbunjuju mnoge vektorske parsere i naivno uzorkovanje putanja.
- Uvek renderujte popunjene kompletne putanje pomoću robusnog SVG motora (npr. CairoSVG) umesto da radite diferenciranje komandi/koordinata.

## Zašto naivno dekodiranje ne uspeva

- Per-request randomized glyph substitution: mapiranje glyph ID→character se menja za svaki batch; ID-jevi nemaju globalno značenje.
- Direktno poređenje SVG koordinata je krhko: identični oblici mogu imati različite numeričke koordinate ili enkodiranje komandi po zahtevu.
- OCR na izolovanim glifovima radi loše (≈50%), meša interpunkciju i slične glifove, i ignoriše ligature.

## Radni tok: request-agnostic normalizacija i mapiranje glifova

1) Rasterizacija SVG glifova po zahtevu
- Napravite minimalan SVG dokument po glifu sa datim `path` i renderujte na fiksni canvas (npr. 512×512) koristeći CairoSVG ili ekvivalentni engine koji obrađuje komplikovane sekvence putanja.
- Renderujte popunjeno crno na belo; izbegavajte stroke da eliminišete artefakte zavisne od renderera i AA.

2) Perceptual hashing za identitet između zahteva
- Izračunajte perceptual hash (npr. pHash preko `imagehash.phash`) svake slike glifa.
- Tretirajte hash kao stabilan ID: isti vizuelni oblik kroz zahteve kolapsira na isti perceptual hash, poništavajući randomizovane ID-jeve.

3) Generisanje referentnog font atlas-a
- Preuzmite ciljne TTF/OTF fontove (npr. Bookerly normal/italic/bold/bold-italic).
- Renderujte kandidate za A–Z, a–z, 0–9, interpukciju, specijalne znakove (em/en crte, navodnici) i eksplicitne ligature: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Držite odvojene atlas-e po varijanti fonta (normal/italic/bold/bold-italic).
- Koristite pravi text shaper (HarfBuzz) ako želite verodostojnost na nivou glifova za ligature; jednostavna rasterizacija preko Pillow ImageFont može biti dovoljna ako renderujete ligaturne nizove direktno i shaping engine ih reši.

4) Vizuelno podudaranje sličnosti pomoću SSIM
- Za svaku nepoznatu sliku glifa, izračunajte SSIM protiv svih kandidata iz svih varijanti font atlas-a.
- Dodelite karakter string najbolje ocenjenom podudaranju. SSIM apsorbuje male razlike u antialiasingu, skali i koordinatama bolje od pikselski eksaktnih poređenja.

5) Rukovanje ivicama i rekonstrukcija
- Kada se glif mapira na ligaturu (višechrakter), proširite je tokom dekodiranja.
- Koristite run rectangle-ove (top/left/right/bottom) da zaključite prekide paragrafa (Y delte), poravnanje (X šablone), stil i veličine.
- Serijalizujte u HTML/EPUB čuvajući `fontStyle`, `fontWeight`, `fontSize` i interne linkove.

### Saveti za implementaciju

- Normalizujte sve slike na istu veličinu i grayscale pre hashing-a i SSIM.
- Keširajte po perceptual hash-u da izbegnete ponovnu izradu SSIM za ponovljene glifove kroz batcheve.
- Koristite visokokvalitetnu raster veličinu (npr. 256–512 px) za bolju diskriminaciju; smanjite razmeru po potrebi pre SSIM da ubrzate.
- Ako koristite Pillow za renderovanje TTF kandidata, postavite istu veličinu canvas-a i centrirajte glif; dodajte padding da izbegnete clipovanje ascendera/descendera.

<details>
<summary>Python: kompletna normalizacija i podudaranje glifova (raster hash + SSIM)</summary>
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

- Paragraph breaks: Ako top Y narednog run-a premaši baseline prethodne linije za više od praga (u odnosu na veličinu fonta), započni novi pasus.
- Alignment: Grupisati po sličnom levom X za levo-poravnate pasuse; detektovati centrirane linije po simetričnim marginama; detektovati desno poravnanje po desnim ivicama.
- Styling: Sačuvati kurziv/podebljano preko `fontStyle`/`fontWeight`; razlikovati CSS klase po `fontSize` bucket-ovima da bi se približno odvojili naslovi od tela teksta.
- Links: Ako run-ovi sadrže link metadata (npr. `positionId`), generiši anchor-e i interne href-ove.

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Avoid stroke rendering; focus on filled solids to sidestep hairline artifacts caused by micro relative moves.
- Keep a stable viewBox per render so that identical shapes rasterize consistently across batches.

## Performance notes

- In practice, books converge to a few hundred unique glyphs (e.g., ~361 including ligatures). Cache SSIM results by perceptual hash.
- After initial discovery, future batches predominantly re-use known hashes; decoding becomes I/O-bound.
- Average SSIM ≈0.95 is a strong signal; consider flagging low-scoring matches for manual review.

## Generalization to other viewers

Any system that:
- Returns positioned glyph runs with request-scoped numeric IDs
- Ships per-request vector glyphs (SVG paths or subset fonts)
- Caps pages per request to prevent bulk export

…can be handled with the same normalization:
- Rasterize per-request shapes → perceptual hash → shape ID
- Atlas of candidate glyphs/ligatures per font variant
- SSIM (or similar perceptual metric) to assign characters
- Reconstruct layout from run rectangles/styles

## Minimal acquisition example (sketch)

Use your browser’s DevTools to capture the exact headers, cookies and tokens used by the reader when requesting `/renderer/render`. Then replicate those from a script or curl. Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Prilagodite parametre (book ASIN, page window, viewport) prema zahtevima čitaoca. Očekujte ograničenje od 5 stranica po zahtevu.

## Rezultati koji se mogu postići

- Sažeti 100+ nasumičnih alfabeta u jedinstveni prostor glifova pomoću perceptual hashing
- 100% mapiranje jedinstvenih glifova sa prosečnim SSIM ~0.95 kada atlasi uključuju ligatures i varijante
- Rekonstruisani EPUB/HTML vizuelno neodvojiv od originala

## Izvori

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
