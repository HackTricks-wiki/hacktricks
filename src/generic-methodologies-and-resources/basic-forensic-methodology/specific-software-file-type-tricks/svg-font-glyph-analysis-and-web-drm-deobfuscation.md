# SVG/Font Glyph-analise & Web DRM-deobfuskasie (Raster-hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer praktiese tegnieke om teks te herwin uit weblesers wat geposisioneerde glyph-runs saam met per-versoek vektorglyph-definisies (SVG paths) lewer, en wat glyph-ID's per versoek randomiseer om scraping te voorkom. Die kernidee is om versoek-spesifieke numeriese glyph-ID's te ignoreer en eerder die visuele vorms deur middel van raster-hashing te fingerprint, en dan vorms aan karakters te koppel met SSIM teenoor 'n verwysingsfont-atlas. Dieselfde benadering kan moontlik veralgemeen word na viewers met soortgelyke beskerming.<sup>[[1]](#references)</sup>

Waarskuwing: Gebruik hierdie tegnieke slegs om inhoud waarvan jy wettiglik die eienaar is, te rugsteun en in ooreenstemming met toepaslike wette en bepalings.

## Verkryging (voorbeeld: Kindle Cloud Reader)

Endpoint waargeneem:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Vereiste materiaal per sessie:<sup>[[1]](#references)</sup>
- Browser-sessiecookies (normale Amazon-aanmelding)
- Rendering token van 'n startReading API-call
- Addisionele ADP-sessietoken wat deur die renderer gebruik word

Gedrag:<sup>[[1]](#references)</sup>
- Elke versoek, wanneer dit met browser-ekwivalente headers en cookies gestuur word, lewer 'n TAR-argief wat tot 5 bladsye beperk is.
- Vir 'n lang boek sal jy baie bondels nodig hê; elke bondel gebruik 'n ander gerandomiseerde kartering van glyph-ID's.

Tipiese TAR-inhoud:<sup>[[1]](#references)</sup>
- page_data_0_4.json — geposisioneerde teks-runs as rye glyph-ID's (nie Unicode nie)
- glyphs.json — per-versoek SVG path-definisies vir elke glyph en fontFamily
- toc.json — inhoudsopgawe
- metadata.json — boekmetadata
- location_map.json — logiese→visuele posisie-karterings

Voorbeeld van bladsy-run-struktuur:<sup>[[1]](#references)</sup>
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
Voorbeeld van glyphs.json-inskrywing:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notas oor anti-scraping path-truuks:<sup>[[1]](#references)</sup>
- Paths kan mikro-relatiewe bewegings insluit (byvoorbeeld `m3,1 m1,6 m-4,-7`) wat baie vektorparsers en naïewe path-sampling verwar.
- Lewer altyd volledig ingevulde paths met ’n robuuste SVG-enjin (byvoorbeeld CairoSVG) in plaas daarvan om command/coordinate-differencing te doen.

## Waarom naïewe decoding misluk

- Per-request gerandomiseerde glyph-substitution: glyph ID→character-mapping verander met elke batch; IDs is globaal betekenisloos.<sup>[[1]](#references)</sup>
- Direkte SVG-coordinate-vergelyking is broos: identiese vorms kan per request in numeriese coordinates of command-encoding verskil.<sup>[[1]](#references)</sup>
- OCR op geïsoleerde glyphs presteer swak (≈50%), verwar leestekens en soortgelyke glyphs, en ignoreer ligatures.<sup>[[1]](#references)</sup>

## Werkende pipeline: request-agnostic glyph-normalisering en -mapping

1) Rasterizeer glyphs per request se SVG
- Bou ’n minimale SVG-dokument per glyph met die verskafde `path` en lewer dit op ’n vaste canvas (byvoorbeeld 512×512) met CairoSVG of ’n ekwivalente enjin wat moeilike path-sequences hanteer.<sup>[[1]](#references)[[2]](#references)</sup>
- Lewer gevulde swart op wit; vermy strokes om renderer- en AA-afhanklike artefakte uit te skakel.

2) Perceptual hashing vir cross-request-identiteit
- Bereken ’n perceptual hash (byvoorbeeld pHash via `imagehash.phash`) van elke glyph-image.<sup>[[3]](#references)</sup>
- Behandel die hash as ’n stabiele ID: dieselfde visuele vorm oor requests heen word tot dieselfde perceptual hash saamgevoeg, wat gerandomiseerde IDs verydel.

3) Generering van ’n reference font atlas
- Laai die teiken- TTF/OTF-fonts af (byvoorbeeld Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Lewer kandidate vir A–Z, a–z, 0–9, leestekens, spesiale marks (em/en-dashes, aanhalingstekens) en eksplisiete ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Hou aparte atlasse per font-variant (normal/italic/bold/bold-italic).
- Gebruik ’n behoorlike text shaper (HarfBuzz) as jy glyph-vlak-fideliteit vir ligatures wil hê; eenvoudige rasterization via Pillow ImageFont kan voldoende wees as jy die ligature-strings direk lewer en die shaping engine dit oplos.

4) Visuele similarity-matching met SSIM
- Bereken vir elke onbekende glyph-image SSIM (Structural Similarity Index) teenoor alle kandidaatbeelde oor alle font-variant-atlasse heen.<sup>[[4]](#references)</sup>
- Ken die character-string van die beste telling toe. SSIM absorbeer klein antialiasing-, skaal- en coordinate-verskille beter as pixel-eksakte vergelykings.<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge-hantering en rekonstruksie
- Wanneer ’n glyph na ’n ligature (multi-char) map, brei dit tydens decoding uit.<sup>[[1]](#references)</sup>
- Gebruik run-rectangle (top/left/right/bottom) om paragraafbreuke (Y-deltas), belyning (X-patterns), styl en groottes af te lei.<sup>[[1]](#references)</sup>
- Serialiseer na HTML/EPUB terwyl `fontStyle`, `fontWeight`, `fontSize` en interne links behoue bly.<sup>[[1]](#references)</sup>

### Implementeringswenke

- Normaliseer alle images na dieselfde grootte en grayscale voordat hashing en SSIM toegepas word.
- Cache volgens perceptual hash om te voorkom dat SSIM herhaaldelik vir glyphs oor batches heen herbereken word.
- Gebruik ’n hoëgehalte-rastergrootte (byvoorbeeld 256–512 px) vir beter diskriminasie; verklein soos nodig voordat SSIM toegepas word om dit te versnel.
- As jy Pillow gebruik om TTF-kandidate te lewer, stel dieselfde canvas-grootte in en sentreer die glyph; voeg padding by om clipping van ascenders/descenders te voorkom.

<details>
<summary>Python: end-to-end glyph-normalisering en -matching (raster hash + SSIM)</summary>
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

## Heuristieke vir uitleg/EPUB-rekonstruksie

Die bronverslag het run-geometrie, stylvelde en skakelmetadata gebruik om die herstelde dokument se formatering te behou.<sup>[[1]](#references)</sup>

- Paragraafbreuke: As die volgende run se boonste Y die vorige reël se basislyn met ’n drempelwaarde (relatief tot lettergrootte) oorskry, begin ’n nuwe paragraaf.<sup>[[1]](#references)</sup>
- Belyning: Groepeer volgens soortgelyke linker-X vir linksbelynde paragrawe; bespeur gesentreerde lyne deur simmetriese kantlyne; bespeur regs-belynde lyne volgens regterkante.
- Stilering: Behou kursief/vet via `fontStyle`/`fontWeight`; wissel CSS-klasse volgens `fontSize`-groepe om opskrifte teenoor hoofteks te benader.
- Skakels: As runs skakelmetadata bevat (bv. `positionId`), genereer ankers en interne hrefs.

## Versagting van SVG anti-scraping-padbepalings

- Gebruik gevulde paths met `fill-rule: nonzero` en ’n behoorlike renderer (CairoSVG, resvg). Moenie op path-token-normalisering staatmaak nie.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Vermy stroke-rendering; fokus op gevulde soliede vorms om haarlynartefakte, wat deur mikro-relatiewe verskuiwings veroorsaak word, te omseil.
- Behou ’n stabiele viewBox per render sodat identiese vorms konsekwent oor bondels heen rasteriseer.

## Prestasie-aantekeninge

- In die praktyk konvergeer boeke na ’n paar honderd unieke glyphs (bv. ~361, insluitend ligature). Kas SSIM-resultate volgens perceptuele hash.<sup>[[1]](#references)</sup>
- Ná aanvanklike ontdekking hergebruik toekomstige bondels hoofsaaklik bekende hashes; dekodering word I/O-gebonde.
- Die aangehaalde verslag het ’n gemiddelde SSIM van ongeveer 0.95 waargeneem; merk lae-telling-ooreenstemmings vir handmatige hersiening.<sup>[[1]](#references)</sup>

## Veralgemening na ander viewers

Die Kindle-workflow dui daarop dat soortgelyke viewers moontlik vir dieselfde normalisering vatbaar is wanneer hulle:<sup>[[1]](#references)</sup>
- geposisioneerde glyph-runs met versoekgebonden numeriese IDs terugstuur
- per-versoek-vektorglyphs (SVG-paths of subset fonts) versend
- die aantal bladsye per versoek beperk

…kan met dieselfde normalisering hanteer word:
- Rasteriseer per-versoek-vorms → perceptuele hash → vorm-ID
- Atlas van kandidaat-glyphs/ligature per fontvariant
- SSIM (of soortgelyke perceptuele maatstaf) om karakters toe te ken
- Rekonstrueer uitleg uit run-reghoeke/style

## Minimale verkrygingsvoorbeeld (skets)

Gebruik jou blaaier se DevTools om die presiese headers, cookies en tokens vas te lê wat deur die reader gebruik word wanneer dit `/renderer/render` aanvra. Repliseer dit dan vanuit ’n script of curl.<sup>[[1]](#references)</sup> Voorbeeldskets:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Pas parameterisering (boek-ASIN, bladsyvenster, viewport) aan om by die leser se versoeke te pas. Verwag ’n limiet van 5 bladsye per versoek.<sup>[[1]](#references)</sup>

## Results achievable

- Vou meer as 100 gerandomiseerde alfabette saam tot ’n enkele glyph-ruimte deur perceptuele hashing te gebruik.<sup>[[1]](#references)</sup>
- In die aangehaalde toets van 920 bladsye is 361 unieke glyphs ooreenstemmend gevind (100%), met ’n gemiddelde SSIM van 0.9527.<sup>[[1]](#references)</sup>
- Die bronverslag beskryf die gerekonstrueerde EPUB as byna ononderskeibaar van die oorspronklike.<sup>[[1]](#references)</sup>

## References

- [1] [Hoe ek Amazon se Kindle-webobfuskasie omgekeer het omdat hul toepassing swak was (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG-na-PNG-renderder](https://cairosvg.org/)
- [3] [imagehash – Perseptuele image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Strukturele ooreenkomsindeks (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill-eienskappe](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG-renderingsbiblioteek](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
