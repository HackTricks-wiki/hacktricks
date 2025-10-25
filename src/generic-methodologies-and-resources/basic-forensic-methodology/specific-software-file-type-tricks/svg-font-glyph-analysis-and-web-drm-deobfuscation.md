# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne techniki odzyskiwania tekstu z web readerów, które dostarczają pozycjonowane runy glifów oraz definicje wektorowych glifów per-request (SVG paths), i które randomizują glyph IDs dla każdego żądania, aby zapobiec scrapingowi. Główny pomysł polega na zignorowaniu numerowanych glyph IDs ograniczonych do żądania i fingerprintowaniu wizualnych kształtów za pomocą raster hashing, a następnie mapowaniu kształtów na znaki przy użyciu SSIM względem referencyjnego atlasu fontów. Workflow uogólnia się poza Kindle Cloud Reader na dowolny viewer z podobnymi zabezpieczeniami.

Warning: Używaj tych technik tylko do tworzenia kopii zapasowych treści, które legalnie posiadasz, i zgodnie z obowiązującym prawem oraz warunkami.

## Pozyskiwanie (example: Kindle Cloud Reader)

Zaobserwowany endpoint:
- https://read.amazon.com/renderer/render

Wymagane materiały na sesję:
- Browser session cookies (normal Amazon login)
- Rendering token from a startReading API call
- Additional ADP session token used by the renderer

Zachowanie:
- Każde żądanie, wysłane z nagłówkami i cookies równoważnymi przeglądarce, zwraca archiwum TAR ograniczone do 5 stron.
- Dla długiej książki będziesz potrzebować wielu batchy; każdy batch używa innego zrandomizowanego mapowania glyph IDs.

Typowa zawartość TAR:
- page_data_0_4.json — positioned text runs as sequences of glyph IDs (not Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
- toc.json — spis treści
- metadata.json — metadane książki
- location_map.json — logical→visual position mappings

Przykładowa struktura runu strony:
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
Przykładowy wpis glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes on anti-scraping path tricks:
- Ścieżki mogą zawierać mikro-ruchy względne (np. `m3,1 m1,6 m-4,-7`), które mylą wiele parserów wektorowych i naiwną próbkę ścieżek.
- Zawsze renderuj wypełnione kompletne ścieżki za pomocą solidnego silnika SVG (np. CairoSVG) zamiast robić różnicowanie komend/współrzędnych.

## Why naïve decoding fails

- Per-request randomized glyph substitution: mapowanie glyph ID→character zmienia się przy każdej partii; ID są bez znaczenia globalnie.
- Direct SVG coordinate comparison is brittle: identyczne kształty mogą różnić się liczbowymi współrzędnymi lub kodowaniem komend w zależności od żądania.
- OCR na izolowanych glifach działa słabo (≈50%), myli interpunkcję i podobnie wyglądające glify oraz ignoruje ligatury.

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- Zbuduj minimalny dokument SVG na glif z dostarczonym `path` i renderuj na stałym kanwie (np. 512×512) używając CairoSVG lub równoważnego silnika, który obsługuje trudne sekwencje ścieżek.
- Renderuj wypełnione na czarno na białym tle; unikaj stroke, by wyeliminować artefakty zależne od renderera i AA.

2) Perceptual hashing for cross-request identity
- Oblicz perceptual hash (np. pHash za pomocą `imagehash.phash`) dla każdego obrazu glifu.
- Traktuj hash jako stabilne ID: ten sam wizualny kształt między żądaniami sprowadza się do tego samego perceptual hasha, neutralizując zrandomizowane ID.

3) Reference font atlas generation
- Pobierz docelowe fonty TTF/OTF (np. Bookerly normal/italic/bold/bold-italic).
- Renderuj kandydatów dla A–Z, a–z, 0–9, interpunkcji, znaków specjalnych (em/en dashes, quotes) oraz jawnych ligatur: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Trzymaj oddzielne atlas y dla każdego wariantu fontu (normal/italic/bold/bold-italic).
- Użyj właściwego text shapera (HarfBuzz), jeśli chcesz wierności na poziomie glifów dla ligatur; prosta rasteryzacja przez Pillow ImageFont może wystarczyć, jeśli renderujesz ciągi ligatur bezpośrednio i silnik kształtowania je rozwiązuje.

4) Visual similarity matching with SSIM
- Dla każdego nieznanego obrazu glifu oblicz SSIM (Structural Similarity Index) względem wszystkich kandydatów we wszystkich atlasach wariantów fontu.
- Przypisz łańcuch znaków najlepiej punktującego dopasowania. SSIM absorbuje małe różnice w antialiasingu, skali i współrzędnych lepiej niż porównania piksel-do-piksela.

5) Edge handling and reconstruction
- Gdy glif mapuje się na ligaturę (wiele znaków), rozwiń ją podczas dekodowania.
- Użyj run rectangles (top/left/right/bottom) do wnioskowania przerw akapitowych (delta Y), wyrównania (wzory X), stylu i rozmiarów.
- Serializuj do HTML/EPUB zachowując `fontStyle`, `fontWeight`, `fontSize` oraz linki wewnętrzne.

### Implementation tips

- Normalizuj wszystkie obrazy do tego samego rozmiaru i do skali szarości przed hashingiem i SSIM.
- Cache'uj po perceptual hash, aby uniknąć ponownego liczenia SSIM dla powtarzających się glifów między partiami.
- Użyj wysokiej jakości rozmiaru rastrowego (np. 256–512 px) dla lepszego rozróżniania; przed SSIM downscale'uj w razie potrzeby, by przyspieszyć.
- Jeśli używasz Pillow do renderowania kandydatów TTF, ustaw ten sam rozmiar canvasa i wycentruj glif; dodaj padding, by uniknąć obcinania ascenderów/descenderów.

<details>
<summary>Python: kompleksowa normalizacja i dopasowanie glifów (raster hash + SSIM)</summary>
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

## Heurystyki rekonstrukcji układu/EPUB

- Paragraph breaks: Jeśli górne Y następnego runu przekracza linię bazową poprzedniego wiersza o pewien próg (względem rozmiaru czcionki), rozpocznij nowy akapit.
- Alignment: Grupuj według podobnego lewego X dla akapitów wyrównanych do lewej; wykrywaj linie wyśrodkowane po symetrycznych marginesach; wykrywaj wyrównanie do prawej po prawych krawędziach.
- Styling: Zachowuj kursywę/pogrubienie przez `fontStyle`/`fontWeight`; różnicuj klasy CSS według kubełków `fontSize`, aby przybliżyć nagłówki względem treści.
- Links: Jeśli runy zawierają metadane linku (np. `positionId`), generuj anchory i wewnętrzne hrefy.

## Przeciwdziałanie trików SVG stosowanych przeciw scrapingowi ścieżek

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Avoid stroke rendering; focus on filled solids to sidestep hairline artifacts caused by micro relative moves.
- Keep a stable viewBox per render so that identical shapes rasterize consistently across batches.

## Uwagi wydajnościowe

- In practice, books converge to a few hundred unique glyphs (e.g., ~361 including ligatures). Cache SSIM results by perceptual hash.
- After initial discovery, future batches predominantly re-use known hashes; decoding becomes I/O-bound.
- Average SSIM ≈0.95 is a strong signal; consider flagging low-scoring matches for manual review.

## Uogólnienie do innych czytników

Każdy system, który:
- Zwraca pozycjonowane runy glifów z numerycznymi ID zasięgu żądania
- Dostarcza dla każdego żądania wektorowe glify (ścieżki SVG lub subset fonts)
- Ogranicza liczbę stron na żądanie, aby zapobiec masowemu eksportowi

…może być obsłużony tą samą normalizacją:
- Rasteryzuj kształty dla każdego żądania → percepcyjny hash → ID kształtu
- Atlas kandydatów glifów/ligatur dla każdego wariantu fontu
- SSIM (lub podobna metryka percepcyjna) do przypisania znaków
- Odtwórz układ na podstawie prostokątów i stylów runów

## Minimalny przykład akwizycji (szkic)

Użyj DevTools przeglądarki, aby przechwycić dokładne nagłówki, cookies i tokeny używane przez czytnik przy żądaniu `/renderer/render`. Następnie odtwórz je w skrypcie lub curlu. Zarys przykładu:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Dostosuj parametryzację (book ASIN, page window, viewport) do żądań czytelnika. Przygotuj się na limit 5 stron na żądanie.

## Wyniki osiągalne

- Zredukowanie 100+ zrandomizowanych alfabetów do jednej przestrzeni glifów za pomocą perceptual hashing
- 100% mapowanie unikalnych glifów ze średnim SSIM ~0.95, gdy atlasy zawierają ligatury i warianty
- Odbudowany EPUB/HTML wizualnie nie do odróżnienia od oryginału

## References

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
