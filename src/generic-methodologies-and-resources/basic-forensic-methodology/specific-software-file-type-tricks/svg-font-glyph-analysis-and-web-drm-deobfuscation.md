# Analiza SVG/font glyph-ova i Web DRM deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktične tehnike za oporavak teksta iz web čitača koji isporučuju pozicionirane glyph sekvence zajedno sa vektorskim definicijama glyph-ova po zahtevu (SVG putanje), i koji randomizuju ID-jeve glyph-ova po zahtevu kako bi sprečili scraping. Osnovna ideja je ignorisati numeričke ID-jeve glyph-ova vezane za zahtev i fingerprintovati vizuelne oblike pomoću raster hashing-a, a zatim mapirati oblike na karaktere pomoću SSIM-a u odnosu na referentni font atlas. Workflow se može generalizovati i van Kindle Cloud Reader-a, na bilo koji viewer sa sličnim zaštitama.<sup>[[1]](#references)</sup>

Upozorenje: Ove tehnike koristite samo za pravljenje rezervnih kopija sadržaja koji legitimno posedujete i u skladu sa važećim zakonima i uslovima korišćenja.

## Acquisition (primer: Kindle Cloud Reader)

Uočeni endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Potrebni materijali po sesiji:
- Kolačići browser sesije (normalan Amazon login)
- Rendering token iz startReading API poziva
- Dodatni ADP session token koji koristi renderer

Ponašanje:
- Svaki zahtev, kada se pošalje sa header-ima i kolačićima ekvivalentnim browser-u, vraća TAR arhivu ograničenu na 5 stranica.
- Za dugu knjigu biće potrebno mnogo batch-eva; svaki batch koristi drugačije randomizovano mapiranje ID-jeva glyph-ova.

Tipičan sadržaj TAR-a:
- page_data_0_4.json — pozicionirane tekstualne sekvence kao nizovi ID-jeva glyph-ova (ne Unicode)
- glyphs.json — SVG path definicije za svaki glyph i fontFamily po zahtevu
- toc.json — sadržaj
- metadata.json — metadata knjige
- location_map.json — mapiranja logičkih→vizuelnih pozicija

Primer strukture page run-a:
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
Primer glyphs.json unosa:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Napomene o trikovima sa putanjama za anti-scraping:
- Putanje mogu uključivati mikro relativna pomeranja (npr. `m3,1 m1,6 m-4,-7`) koja zbunjuju mnoge vektorske parser-e i naivno uzorkovanje putanja.
- Uvek renderujte popunjene kompletne putanje pomoću robusnog SVG engine-a (npr. CairoSVG), umesto određivanja razlika između komandi/koordinata.

## Zašto naivno dekodiranje ne uspeva

- Randomizovana zamena glyph-ova po zahtevu: mapiranje glyph ID-ja→karakter menja se u svakom batch-u; ID-jevi nemaju globalno značenje.<sup>[[1]](#references)</sup>
- Direktno poređenje SVG koordinata je nepouzdano: identični oblici mogu imati različite numeričke koordinate ili kodiranje komandi u svakom zahtevu.
- OCR nad izolovanim glyph-ovima ima slabe performanse (≈50%), meša interpunkciju i slične glyph-ove i zanemaruje ligature.

## Radni pipeline: normalizacija i mapiranje glyph-ova nezavisno od zahteva

1) Rasterizujte SVG glyph-ove za svaki zahtev
- Napravite minimalni SVG dokument za svaki glyph sa dostavljenom `path` vrednošću i renderujte ga na fiksnom canvas-u (npr. 512×512) pomoću CairoSVG-a ili ekvivalentnog engine-a koji obrađuje problematične sekvence putanja.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderujte crno na beloj podlozi; izbegavajte stroke-ove kako biste uklonili artefakte zavisne od renderer-a i AA-a.

2) Perceptual hashing za identifikaciju između zahteva
- Izračunajte perceptual hash (npr. pHash preko `imagehash.phash`) za svaku sliku glyph-a.<sup>[[3]](#references)</sup>
- Tretirajte hash kao stabilni ID: isti vizuelni oblik u različitim zahtevima svodi se na isti perceptual hash, čime se neutrališu randomizovani ID-jevi.

3) Generisanje referentnog font atlas-a
- Preuzmite ciljne TTF/OTF fontove (npr. Bookerly normal/italic/bold/bold-italic).
- Renderujte kandidate za A–Z, a–z, 0–9, interpunkciju, posebne oznake (em/en dashes, navodnike) i eksplicitne ligature: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Održavajte zasebne atlas-e za svaku varijantu fonta (normal/italic/bold/bold-italic).
- Koristite odgovarajući text shaper (HarfBuzz) ako želite glyph-level fidelity za ligature; jednostavna rasterizacija pomoću Pillow ImageFont može biti dovoljna ako direktno renderujete stringove ligatura i shaping engine ih pravilno razreši.

4) Visual similarity matching pomoću SSIM-a
- Za svaku nepoznatu sliku glyph-a izračunajte SSIM (Structural Similarity Index) u odnosu na sve slike kandidata iz svih font variant atlas-a.<sup>[[4]](#references)</sup>
- Dodelite string karaktera najboljeg podudaranja. SSIM bolje apsorbuje male razlike u antialiasing-u, veličini i koordinatama nego poređenja sa potpuno identičnim pikselima.

5) Obrada ivica i rekonstrukcija
- Kada se glyph mapira na ligaturu (više karaktera), proširite ga tokom dekodiranja.
- Koristite pravougaonike redova (top/left/right/bottom) za zaključivanje o prelomima pasusa (Y delte), poravnanju (X obrasci), stilu i veličinama.
- Serijalizujte u HTML/EPUB uz očuvanje `fontStyle`, `fontWeight`, `fontSize` i internih linkova.

### Saveti za implementaciju

- Normalizujte sve slike na istu veličinu i u grayscale pre hash-ovanja i SSIM-a.
- Keširajte prema perceptual hash-u kako biste izbegli ponovno izračunavanje SSIM-a za ponovljene glyph-ove iz različitih batch-eva.
- Koristite raster veličinu visokog kvaliteta (npr. 256–512 px) za bolje razlikovanje; po potrebi smanjite veličinu pre SSIM-a radi ubrzanja.
- Ako koristite Pillow za renderovanje TTF kandidata, postavite istu veličinu canvas-a i centrirajte glyph; dodajte padding kako biste izbegli odsecanje ascender/descender delova.

<details>
<summary>Python: end-to-end normalizacija i matching glyph-ova (raster hash + SSIM)</summary>
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

## Heuristike za rekonstrukciju Layout/EPUB-a

- Prelomi pasusa: Ako gornja Y koordinata sledećeg run-a premašuje baseline prethodne linije za prag (u odnosu na veličinu fonta), započnite novi pasus.<sup>[[1]](#references)</sup>
- Poravnanje: Grupisati prema sličnom levom X za pasuse poravnate ulevo; detektovati centrirane linije pomoću simetričnih margina; detektovati poravnanje udesno prema desnim ivicama.
- Stilizovanje: Očuvati italic/bold pomoću `fontStyle`/`fontWeight`; menjati CSS klase prema `fontSize` kategorijama kako bi se približno razlikovali naslovi od osnovnog teksta.
- Linkovi: Ako run-ovi sadrže metadata o linkovima (npr. `positionId`), generisati anchors i interne href-ove.

## Ublažavanje SVG anti-scraping trikova sa putanjama

- Koristiti popunjene putanje sa `fill-rule: nonzero` i odgovarajući renderer (CairoSVG, resvg). Ne oslanjati se na normalizaciju tokena putanje.<sup>[[1]](#references)</sup>
- Izbegavati renderovanje stroke-a; fokusirati se na popunjene oblike kako bi se zaobišli artefakti tankih linija izazvani mikrorelativnim pomeranjima.
- Održavati stabilan viewBox pri svakom renderovanju kako bi se identični oblici dosledno rasterizovali kroz batch-eve.

## Napomene o performansama

- U praksi se knjige svode na nekoliko stotina jedinstvenih glyph-ova (npr. ~361, uključujući ligature). Keširati SSIM rezultate prema perceptivnom hash-u.<sup>[[1]](#references)</sup>
- Nakon početnog otkrivanja, naredni batch-evi uglavnom ponovo koriste poznate hash-eve; dekodiranje postaje I/O-bound.
- Prosečan SSIM ≈0.95 predstavlja snažan signal; razmotriti označavanje podudaranja sa niskim skorom za ručnu proveru.

## Generalizacija na druge viewere

Bilo koji sistem koji:<sup>[[1]](#references)</sup>
- Vraća pozicionirane glyph run-ove sa numeričkim ID-ovima ograničenim na zahtev
- Šalje vektorske glyph-ove po zahtevu (SVG putanje ili subset fontovi)
- Ograničava broj stranica po zahtevu kako bi sprečio bulk export

…može se obraditi istom normalizacijom:
- Rasterizovati oblike po zahtevu → perceptivni hash → ID oblika
- Atlas kandidatnih glyph-ova/ligatura po varijanti fonta
- SSIM (ili slična perceptivna metrika) za dodeljivanje karaktera
- Rekonstruisati layout iz pravougaonika run-ova/stilova

## Minimalni primer akvizicije (skica)

Koristiti DevTools svog browsera za hvatanje tačnih headers-a, cookies-a i tokens-a koje reader koristi pri zahtevu ka `/renderer/render`. Zatim ih replicirati iz script-a ili pomoću curl-a.<sup>[[1]](#references)</sup> Okvirni primer:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Prilagodite parameterizaciju (ASIN knjige, prozor stranica, viewport) zahtevima čitaoca. Očekujte ograničenje od 5 stranica po zahtevu.

## Postignuti rezultati

- Svođenje više od 100 randomizovanih alfabeta na jedan prostor glifova pomoću perceptivnog heširanja<sup>[[1]](#references)</sup>
- 100% mapiranje jedinstvenih glifova sa prosečnim SSIM-om od približno 0.95 kada atlasi uključuju ligature i varijante
- Rekonstruisani EPUB/HTML vizuelno se ne razlikuje od originala

## References

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
