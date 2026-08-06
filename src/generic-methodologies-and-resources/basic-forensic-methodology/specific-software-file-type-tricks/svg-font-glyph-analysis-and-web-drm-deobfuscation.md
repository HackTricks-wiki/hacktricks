# Analiza glifów SVG/fontów i deobfuskacja Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne techniki odzyskiwania tekstu z web readers, które dostarczają pozycjonowane serie glifów wraz z definicjami glifów wektorowych (ścieżkami SVG) dla każdego żądania oraz losują identyfikatory glifów przy każdym żądaniu, aby utrudnić scraping. Kluczową ideą jest ignorowanie numerycznych identyfikatorów glifów przypisanych do konkretnego żądania i identyfikowanie wizualnych kształtów za pomocą raster hashing, a następnie mapowanie kształtów na znaki przy użyciu SSIM względem atlasu referencyjnego fontu. Workflow można uogólnić poza Kindle Cloud Reader na dowolny viewer z podobnymi zabezpieczeniami.<sup>[[1]](#references)</sup>

Ostrzeżenie: Używaj tych technik wyłącznie do tworzenia kopii zapasowych treści, które legalnie posiadasz, oraz zgodnie z obowiązującymi przepisami i warunkami korzystania.

## Acquisition (przykład: Kindle Cloud Reader)

Zaobserwowany endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiały wymagane dla każdej sesji:
- Cookies sesji przeglądarki (zwykłe logowanie do Amazon)
- Rendering token z wywołania API startReading
- Dodatkowy ADP session token używany przez renderer

Zachowanie:
- Każde żądanie, wysłane z nagłówkami i cookies odpowiadającymi przeglądarce, zwraca archiwum TAR ograniczone do 5 stron.
- W przypadku długiej książki potrzebnych będzie wiele batchy; każdy batch używa innego losowego mapowania identyfikatorów glifów.

Typowa zawartość TAR:
- page_data_0_4.json — pozycjonowane serie tekstu jako sekwencje identyfikatorów glifów (nie Unicode)
- glyphs.json — definicje ścieżek SVG dla każdego glifu i fontFamily, przypisane do konkretnego żądania
- toc.json — spis treści
- metadata.json — metadane książki
- location_map.json — mapowania pozycji logicznych→wizualnych

Przykładowa struktura serii strony:
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
Przykładowy wpis w glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Uwagi dotyczące sztuczek z path w anti-scraping:
- Paths mogą zawierać mikroprzesunięcia względne (np. `m3,1 m1,6 m-4,-7`), które wprowadzają w błąd wiele parserów wektorowych i naiwnych metod próbkowania paths.
- Zawsze renderuj wypełnione, kompletne paths za pomocą solidnego silnika SVG (np. CairoSVG), zamiast wykonywać różnicowanie komend/współrzędnych.

## Dlaczego naiwne dekodowanie zawodzi

- Losowa substytucja glyphów dla każdego requestu: mapowanie glyph ID→znak zmienia się w każdej batch; ID nie mają globalnego znaczenia.<sup>[[1]](#references)</sup>
- Bezpośrednie porównywanie współrzędnych SVG jest kruche: identyczne kształty mogą różnić się wartościami numerycznymi współrzędnych lub kodowaniem komend w każdym requestcie.
- OCR na izolowanych glyphach działa słabo (≈50%), myli znaki interpunkcyjne i podobne glyphy oraz ignoruje ligatury.

## Działający pipeline: niezależna od requestu normalizacja i mapowanie glyphów

1) Rasteryzuj glyphy SVG dla każdego requestu
- Zbuduj minimalny dokument SVG dla każdego glyphu z dostarczonym `path` i renderuj go na stałym canvasie (np. 512×512), używając CairoSVG lub równoważnego silnika obsługującego trudne sekwencje paths.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderuj wypełnienie w kolorze czarnym na białym tle; unikaj strokes, aby wyeliminować artefakty zależne od renderera i AA.

2) Perceptual hashing na potrzeby identyfikacji między requestami
- Oblicz perceptual hash (np. pHash za pomocą `imagehash.phash`) dla każdego obrazu glyphu.<sup>[[3]](#references)</sup>
- Traktuj hash jako stabilny ID: ten sam wizualny kształt w różnych requestach zostanie sprowadzony do tego samego perceptual hash, neutralizując losowe ID.

3) Generowanie referencyjnego atlasu fontów
- Pobierz docelowe fonty TTF/OTF (np. Bookerly normal/italic/bold/bold-italic).
- Wyrenderuj kandydatów dla A–Z, a–z, 0–9, znaków interpunkcyjnych, znaków specjalnych (półpauzy/em dashes, cudzysłowy) oraz jawnych ligatur: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Zachowaj osobne atlasy dla każdego wariantu fontu (normal/italic/bold/bold-italic).
- Użyj właściwego text shaper (HarfBuzz), jeśli potrzebujesz wierności na poziomie glyphów dla ligatur; prosta rasteryzacja za pomocą Pillow ImageFont może być wystarczająca, jeśli wyrenderujesz bezpośrednio ciągi ligatur, a silnik shaping rozwiąże je prawidłowo.

4) Dopasowywanie podobieństwa wizualnego za pomocą SSIM
- Dla każdego nieznanego obrazu glyphu oblicz SSIM (Structural Similarity Index) względem wszystkich obrazów kandydatów we wszystkich atlasach wariantów fontów.<sup>[[4]](#references)</sup>
- Przypisz ciąg znaków z najlepiej ocenionego dopasowania. SSIM lepiej absorbuje niewielkie różnice w antialiasingu, skali i współrzędnych niż porównania dokładne piksel po pikselu.

5) Obsługa krawędzi i rekonstrukcja
- Gdy glyph mapuje się na ligaturę (wieloznakową), rozwiń ją podczas dekodowania.
- Użyj prostokątów runów (top/left/right/bottom), aby wnioskować o podziałach akapitów (różnice Y), wyrównaniu (wzorce X), stylu i rozmiarach.
- Serializuj do HTML/EPUB, zachowując `fontStyle`, `fontWeight`, `fontSize` oraz linki wewnętrzne.

### Wskazówki implementacyjne

- Znormalizuj wszystkie obrazy do tego samego rozmiaru i skali szarości przed obliczaniem hash oraz SSIM.
- Stosuj cache według perceptual hash, aby uniknąć ponownego obliczania SSIM dla powtarzających się glyphów w kolejnych batchach.
- Używaj wysokiej jakości rozmiaru rasteryzacji (np. 256–512 px), aby uzyskać lepsze rozróżnianie; w razie potrzeby zmniejszaj obrazy przed SSIM w celu przyspieszenia.
- Jeśli używasz Pillow do renderowania kandydatów TTF, ustaw ten sam rozmiar canvasa i wyśrodkuj glyph; dodaj padding, aby uniknąć przycinania ascenderów/descenderów.

<details>
<summary>Python: kompleksowa normalizacja i dopasowywanie glyphów od początku do końca (raster hash + SSIM)</summary>
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

- Podziały akapitów: Jeśli górna współrzędna Y kolejnego runu przekracza bazową linię poprzedniego o próg zależny od rozmiaru fontu, rozpocznij nowy akapit.<sup>[[1]](#references)</sup>
- Wyrównanie: Grupuj według podobnej lewej współrzędnej X dla akapitów wyrównanych do lewej; wykrywaj wyśrodkowane linie na podstawie symetrycznych marginesów; wykrywaj wyrównanie do prawej na podstawie prawych krawędzi.
- Stylowanie: Zachowaj kursywę/pogrubienie za pomocą `fontStyle`/`fontWeight`; różnicuj klasy CSS według przedziałów `fontSize`, aby przybliżyć nagłówki i tekst główny.
- Links: Jeśli runy zawierają metadane linków (np. `positionId`), generuj anchors i wewnętrzne hrefs.

## Ograniczanie sztuczek anti-scraping z użyciem ścieżek SVG

- Używaj wypełnionych ścieżek z `fill-rule: nonzero` i właściwego renderera (CairoSVG, resvg). Nie polegaj na normalizacji tokenów ścieżek.<sup>[[1]](#references)</sup>
- Unikaj renderowania obrysów; skup się na wypełnionych kształtach, aby ominąć artefakty cienkich linii powodowane przez mikroruchy względne.
- Utrzymuj stabilny viewBox dla każdego renderowania, aby identyczne kształty były rasteryzowane spójnie w kolejnych batchach.

## Uwagi dotyczące wydajności

- W praktyce książki ograniczają się do kilkuset unikalnych glyphs (np. około 361 wraz z ligaturami). Cache’uj wyniki SSIM według hasha perceptualnego.<sup>[[1]](#references)</sup>
- Po początkowym rozpoznaniu kolejne batche w większości ponownie wykorzystują znane hashe; dekodowanie staje się ograniczone przez I/O.
- Średnie SSIM ≈0.95 to silny sygnał; rozważ oznaczanie dopasowań z niskim wynikiem do ręcznego przeglądu.

## Uogólnienie na inne viewery

Każdy system, który:<sup>[[1]](#references)</sup>
- Zwraca pozycjonowane runy glyphs z numerycznymi ID zależnymi od requestu
- Dostarcza wektorowe glyphs dla każdego requestu (ścieżki SVG lub subset fonts)
- Ogranicza liczbę stron na request, aby zapobiec masowemu eksportowi

…można obsłużyć za pomocą tej samej normalizacji:
- Rasteryzuj kształty dla każdego requestu → hash perceptualny → ID kształtu
- Atlas kandydatów glyphs/ligatur dla każdego wariantu fontu
- SSIM (lub podobna metryka perceptualna) do przypisywania znaków
- Rekonstruuj układ na podstawie prostokątów/styles runów

## Minimalny przykład pozyskiwania danych (szkic)

Użyj DevTools swojej przeglądarki, aby przechwycić dokładne headers, cookies i tokens używane przez readera podczas żądania `/renderer/render`. Następnie odtwórz je za pomocą skryptu lub curl.<sup>[[1]](#references)</sup> Przykładowy zarys:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Dostosuj parametry (book ASIN, page window, viewport) do żądań czytelnika. Uwzględnij limit 5 stron na żądanie.

## Możliwe do osiągnięcia rezultaty

- Zredukowanie ponad 100 losowych alfabetów do jednej przestrzeni glifów za pomocą perceptual hashing<sup>[[1]](#references)</sup>
- 100% mapowanie unikalnych glifów ze średnim SSIM wynoszącym około 0,95, gdy atlasy zawierają ligatury i warianty
- Odtworzony EPUB/HTML jest wizualnie nie do odróżnienia od oryginału

## Referencje

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
