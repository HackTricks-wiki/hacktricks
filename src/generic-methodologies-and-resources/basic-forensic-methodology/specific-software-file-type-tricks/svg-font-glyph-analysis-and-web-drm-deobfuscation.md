# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica opisuje praktične tehnike za oporavak teksta iz web čitača koji šalju pozicionirane nizove glyph-ova zajedno sa vektorskim definicijama glyph-ova po zahtevu (SVG putanje), i koji nasumično menjaju ID-jeve glyph-ova pri svakom zahtevu kako bi sprečili scraping. Osnovna ideja je ignorisati numeričke ID-jeve glyph-ova vezane za zahtev i identifikovati vizuelne oblike pomoću raster hashing-a, a zatim mapirati oblike na znakove koristeći SSIM u odnosu na referentni font atlas. Isti pristup se može primeniti i na čitače sa sličnim zaštitama.<sup>[[1]](#references)</sup>

Upozorenje: Ove tehnike koristite samo za pravljenje rezervne kopije sadržaja koji legitimno posedujete i u skladu sa važećim zakonima i uslovima korišćenja.

## Acquisition (example: Kindle Cloud Reader)

Uočeni endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Potrebni materijali po sesiji:<sup>[[1]](#references)</sup>
- Kolačići browser sesije (uobičajena Amazon prijava)
- Rendering token iz startReading API poziva
- Dodatni ADP session token koji koristi renderer

Ponašanje:<sup>[[1]](#references)</sup>
- Svaki zahtev, kada se pošalje sa header-ima i kolačićima ekvivalentnim onima u browseru, vraća TAR arhivu ograničenu na 5 stranica.
- Za dugu knjigu biće potrebno mnogo batch-eva; svaki batch koristi drugačije nasumično mapiranje ID-jeva glyph-ova.

Uobičajeni sadržaj TAR arhive:<sup>[[1]](#references)</sup>
- page_data_0_4.json — pozicionirani nizovi teksta kao sekvence ID-jeva glyph-ova (ne Unicode)
- glyphs.json — SVG definicije putanja za svaki glyph i fontFamily po zahtevu
- toc.json — sadržaj
- metadata.json — metadata knjige
- location_map.json — mapiranja logičkih→vizuelnih pozicija

Primer strukture page run-a:<sup>[[1]](#references)</sup>
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
Primer unosa u glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Napomene o trikovima sa putanjama za sprečavanje scraping-a:<sup>[[1]](#references)</sup>
- Putanje mogu sadržati mikrorelativna pomeranja (npr. `m3,1 m1,6 m-4,-7)` koja zbunjuju mnoge vektorske parser-e i naivno uzorkovanje putanja.
- Uvek renderujte popunjene kompletne putanje pomoću robusnog SVG engine-a (npr. CairoSVG), umesto izračunavanja razlika između komandi/koordinata.

## Zašto naivno dekodiranje ne uspeva

- Randomizovana supstitucija glyph-ova po zahtevu: mapiranje glyph ID→karakter menja se u svakom batch-u; ID-jevi nemaju globalno značenje.<sup>[[1]](#references)</sup>
- Direktno poređenje SVG koordinata je nepouzdano: identični oblici mogu imati različite numeričke koordinate ili kodiranje komandi u svakom zahtevu.<sup>[[1]](#references)</sup>
- OCR nad izolovanim glyph-ovima daje loše rezultate (≈50%), meša interpunkciju i slične glyph-ove i zanemaruje ligature.<sup>[[1]](#references)</sup>

## Radni pipeline: normalizacija i mapiranje glyph-ova nezavisno od zahteva

1) Rasterizujte SVG glyph-ove po zahtevu
- Napravite minimalni SVG dokument za svaki glyph sa prosleđenom `path` vrednošću i renderujte ga na fiksnom canvas-u (npr. 512×512) pomoću CairoSVG-a ili ekvivalentnog engine-a koji obrađuje složene sekvence putanja.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderujte crno na beloj pozadini; izbegavajte stroke-ove kako biste uklonili artefakte zavisne od renderer-a i anti-aliasing-a.

2) Perceptual hashing za identitet između zahteva
- Izračunajte perceptual hash (npr. pHash pomoću `imagehash.phash`) za svaku sliku glyph-a.<sup>[[3]](#references)</sup>
- Tretirajte hash kao stabilni ID: isti vizuelni oblik u različitim zahtevima svodi se na isti perceptual hash, čime se zaobilaze randomizovani ID-jevi.

3) Generisanje referentnog font atlas-a
- Preuzmite ciljne TTF/OTF fontove (npr. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Renderujte kandidate za A–Z, a–z, 0–9, interpunkciju, posebne oznake (em/en crte, navodnike) i eksplicitne ligature: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Održavajte odvojene atlas-e za svaku varijantu fonta (normal/italic/bold/bold-italic).
- Koristite odgovarajući text shaper (HarfBuzz) ako želite vernost na nivou glyph-a za ligature; jednostavna rasterizacija pomoću Pillow ImageFont-a može biti dovoljna ako direktno renderujete stringove ligatura i shaping engine ih pravilno obradi.

4) Uparivanje vizuelne sličnosti pomoću SSIM-a
- Za svaku nepoznatu sliku glyph-a izračunajte SSIM (Structural Similarity Index) u odnosu na sve slike kandidata iz svih atlas-a varijanti fonta.<sup>[[4]](#references)</sup>
- Dodelite znakovni string najboljeg rezultata. SSIM bolje apsorbuje male razlike u anti-aliasing-u, razmeri i koordinatama nego poređenja sa potpuno identičnim pikselima.<sup>[[1]](#references)[[4]](#references)</sup>

5) Obrada ivica i rekonstrukcija
- Kada se glyph mapira na ligaturu (više karaktera), proširite ga tokom dekodiranja.<sup>[[1]](#references)</sup>
- Koristite pravougaonike redova (top/left/right/bottom) za zaključivanje preloma pasusa (Y delta), poravnanja (X obrasci), stila i veličina.<sup>[[1]](#references)</sup>
- Serijalizujte u HTML/EPUB uz očuvanje `fontStyle`, `fontWeight`, `fontSize` i internih linkova.<sup>[[1]](#references)</sup>

### Saveti za implementaciju

- Normalizujte sve slike na istu veličinu i u grayscale pre hash-ovanja i SSIM-a.
- Keširajte prema perceptual hash-u da biste izbegli ponovno računanje SSIM-a za ponovljene glyph-ove kroz različite batch-eve.
- Koristite raster veličine visokog kvaliteta (npr. 256–512 px) za bolje razlikovanje; po potrebi smanjite slike pre SSIM-a radi ubrzanja.
- Ako koristite Pillow za renderovanje TTF kandidata, podesite istu veličinu canvas-a i centrirajte glyph; dodajte padding da biste izbegli odsecanje ascender-a/descender-a.

<details>
<summary>Python: end-to-end normalizacija i uparivanje glyph-ova (raster hash + SSIM)</summary>
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

## Heuristike za rekonstrukciju layout-a/EPUB-a

Izvorni izveštaj je koristio geometriju run-ova, polja stilova i metadata linkova za očuvanje formatiranja rekonstruisanog dokumenta.<sup>[[1]](#references)</sup>

- Prelomi pasusa: Ako gornji Y sledećeg run-a premašuje baseline prethodne linije za prag (u odnosu na veličinu fonta), započnite novi pasus.<sup>[[1]](#references)</sup>
- Poravnanje: Grupisati prema sličnom levom X za levo poravnate pasuse; detektovati centrirane linije prema simetričnim marginama; detektovati desno poravnate linije prema desnim ivicama.
- Stilizovanje: Očuvati italic/bold pomoću `fontStyle`/`fontWeight`; menjati CSS klase prema kategorijama `fontSize` vrednosti radi približnog razlikovanja naslova od glavnog teksta.
- Linkovi: Ako run-ovi uključuju metadata linkova (npr. `positionId`), generisati anchor-e i interne href-ove.

## Ublažavanje SVG anti-scraping trikova sa path-ovima

- Koristiti popunjene path-ove sa `fill-rule: nonzero` i odgovarajući renderer (CairoSVG, resvg). Ne oslanjati se na normalizaciju path tokena.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Izbegavati renderovanje stroke-ova; fokusirati se na popunjene solid oblike kako bi se zaobišli artefakti tankih linija izazvani mikro relativnim pomeranjima.
- Održavati stabilan viewBox po renderovanju kako bi se identični oblici konzistentno rasterizovali kroz batch-eve.

## Napomene o performansama

- U praksi se knjige svode na nekoliko stotina jedinstvenih glyph-ova (npr. ~361 uključujući ligature). Keširati SSIM rezultate prema perceptual hash-u.<sup>[[1]](#references)</sup>
- Nakon početnog otkrivanja, budući batch-evi uglavnom ponovo koriste poznate hash-eve; decoding postaje I/O-bound.
- Navedeni izveštaj je zabeležio prosečan SSIM od oko 0.95; označiti podudaranja sa niskim rezultatom za ručnu proveru.<sup>[[1]](#references)</sup>

## Generalizacija na druge viewere

Kindle workflow ukazuje na to da slični vieweri mogu biti pogodni za istu normalizaciju kada:<sup>[[1]](#references)</sup>
- vraćaju pozicionirane glyph run-ove sa numeričkim ID-jevima ograničenim na zahtev
- isporučuju vektorske glyph-ove po zahtevu (SVG path-ove ili subset fontove)
- ograničavaju broj stranica po zahtevu

…mogu se obraditi istom normalizacijom:
- Rasterizovati oblike po zahtevu → perceptual hash → ID oblika
- Atlas kandidatskih glyph-ova/ligatura po varijanti fonta
- SSIM (ili slična perceptual metrika) za dodeljivanje karaktera
- Rekonstruisati layout iz pravougaonika run-ova/stilova

## Minimalni primer akvizicije (skica)

Koristite DevTools svog browser-a da uhvatite tačna zaglavlja, cookies i tokene koje reader koristi prilikom zahteva ka `/renderer/render`. Zatim ih replikujte iz skripte ili pomoću curl-a.<sup>[[1]](#references)</sup> Okvirni primer:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Prilagodite parameterizaciju (ASIN knjige, opseg stranica, viewport) zahtevima čitaoca. Očekujte ograničenje od 5 stranica po zahtevu.<sup>[[1]](#references)</sup>

## Results achievable

- Svedite više od 100 randomizovanih alfabeta na jedan glyph prostor pomoću perceptual hashing-a.<sup>[[1]](#references)</sup>
- U navedenom testu sa 920 stranica, pronađeno je podudaranje za 361 jedinstveni glyph (100%), uz prosečni SSIM od 0.9527.<sup>[[1]](#references)</sup>
- Izvorni izveštaj opisuje rekonstruisani EPUB kao gotovo nerazlučiv od originala.<sup>[[1]](#references)</sup>

## References

- [1] [Kako sam preokrenuo Amazonovu Kindle Web Obfuscation jer je njihova aplikacija bila loša (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG u PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Svojstva popunjavanja](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG biblioteka za renderovanje](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
