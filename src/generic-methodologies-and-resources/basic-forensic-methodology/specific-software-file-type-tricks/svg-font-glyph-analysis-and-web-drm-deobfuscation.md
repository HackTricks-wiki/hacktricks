# Analiza glifów SVG/fontów i usuwanie obfuskacji Web DRM (hashowanie rastrowe + SSIM)

Ta strona opisuje praktyczne techniki odzyskiwania tekstu z web readers, które przesyłają pozycjonowane ciągi glifów wraz z definicjami glifów wektorowych (ścieżkami SVG) dla każdego żądania oraz losują identyfikatory glifów przy każdym żądaniu, aby zapobiegać scrapingowi. Główny pomysł polega na ignorowaniu zależnych od żądania numerycznych identyfikatorów glifów i identyfikowaniu wizualnych kształtów za pomocą hashów rastrowych, a następnie mapowaniu kształtów na znaki przy użyciu SSIM względem atlasu fontu referencyjnego. To samo podejście może mieć zastosowanie do viewers z podobnymi zabezpieczeniami.<sup>[[1]](#references)</sup>

Ostrzeżenie: Używaj tych technik wyłącznie do tworzenia kopii zapasowych treści, których jesteś legalnym właścicielem, oraz zgodnie z obowiązującymi przepisami i warunkami.

## Pozyskiwanie (przykład: Kindle Cloud Reader)

Zaobserwowany endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Wymagane materiały dla każdej sesji:<sup>[[1]](#references)</sup>
- Cookies sesji przeglądarki (normalne logowanie do Amazon)
- Token renderowania z wywołania startReading API
- Dodatkowy token sesji ADP używany przez renderer

Działanie:<sup>[[1]](#references)</sup>
- Każde żądanie, wysłane z nagłówkami i cookies odpowiadającymi przeglądarce, zwraca archiwum TAR ograniczone do 5 stron.
- W przypadku długiej książki potrzebnych będzie wiele batchy; każdy batch używa innego, losowego mapowania identyfikatorów glifów.

Typowa zawartość TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — pozycjonowane ciągi tekstu jako sekwencje identyfikatorów glifów (nie Unicode)
- glyphs.json — definicje ścieżek SVG dla każdego glifu i fontFamily, zależne od żądania
- toc.json — spis treści
- metadata.json — metadata książki
- location_map.json — mapowania pozycji logicznych na wizualne

Przykładowa struktura page run:<sup>[[1]](#references)</sup>
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
Przykładowy wpis glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Uwagi dotyczące trików związanych ze ścieżkami anti-scraping:<sup>[[1]](#references)</sup>
- Ścieżki mogą zawierać niewielkie względne przesunięcia (np. `m3,1 m1,6 m-4,-7`), które dezorientują wiele parserów wektorowych i naiwnych metod próbkowania ścieżek.
- Zawsze renderuj wypełnione kompletne ścieżki za pomocą solidnego silnika SVG (np. CairoSVG), zamiast wykonywać różnicowanie poleceń/współrzędnych.

## Dlaczego naiwne dekodowanie zawodzi

- Losowa substytucja glyphów dla każdego requestu: mapowanie glyph ID→znak zmienia się w każdej batch; ID nie mają globalnego znaczenia.<sup>[[1]](#references)</sup>
- Bezpośrednie porównywanie współrzędnych SVG jest kruche: identyczne kształty mogą różnić się wartościami liczbowymi współrzędnych lub kodowaniem poleceń w każdym request.<sup>[[1]](#references)</sup>
- OCR na izolowanych glyphach działa słabo (≈50%), myli znaki interpunkcyjne i podobne glyphy oraz ignoruje ligatury.<sup>[[1]](#references)</sup>

## Działający pipeline: niezależna od requestu normalizacja i mapowanie glyphów

1) Rasteryzuj glyphy SVG dla każdego requestu
- Zbuduj minimalny dokument SVG dla każdego glyphu z dostarczonym `path` i renderuj go na stałym canvasie (np. 512×512), używając CairoSVG lub równoważnego silnika obsługującego problematyczne sekwencje ścieżek.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderuj wypełnienie czarnym kolorem na białym tle; unikaj obrysów, aby wyeliminować artefakty zależne od renderera i AA.

2) Perceptual hashing do identyfikacji między requestami
- Oblicz perceptual hash (np. pHash za pomocą `imagehash.phash`) dla każdego obrazu glyphu.<sup>[[3]](#references)</sup>
- Traktuj hash jako stabilny ID: ten sam wizualny kształt w różnych requestach zostanie sprowadzony do tego samego perceptual hash, niwelując losowe ID.

3) Generowanie referencyjnego atlasu fontów
- Pobierz docelowe fonty TTF/OTF (np. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Wyrenderuj kandydatów dla A–Z, a–z, 0–9, znaków interpunkcyjnych, znaków specjalnych (pauzy em/en, cudzysłowy) oraz jawnych ligatur: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Zachowaj oddzielne atlasy dla każdego wariantu fontu (normal/italic/bold/bold-italic).
- Użyj właściwego text shaper (HarfBuzz), jeśli zależy Ci na wierności na poziomie glyphów dla ligatur; prosta rasteryzacja za pomocą Pillow ImageFont może być wystarczająca, jeśli bezpośrednio renderujesz ciągi ligatur, a silnik kształtowania prawidłowo je rozpoznaje.

4) Dopasowywanie podobieństwa wizualnego za pomocą SSIM
- Dla każdego nieznanego obrazu glyphu oblicz SSIM (Structural Similarity Index) względem wszystkich obrazów kandydatów we wszystkich atlasach wariantów fontów.<sup>[[4]](#references)</sup>
- Przypisz ciąg znaków z najlepiej ocenionego dopasowania. SSIM lepiej absorbuje niewielkie różnice w antialiasingu, skali i współrzędnych niż porównania dokładne na poziomie pikseli.<sup>[[1]](#references)[[4]](#references)</sup>

5) Obsługa przypadków brzegowych i rekonstrukcja
- Jeśli glyph zostanie zmapowany na ligaturę (wiele znaków), rozwiń ją podczas dekodowania.<sup>[[1]](#references)</sup>
- Użyj prostokątów przebiegów (top/left/right/bottom), aby wnioskować o podziałach akapitów (różnice Y), wyrównaniu (wzorce X), stylu i rozmiarach.<sup>[[1]](#references)</sup>
- Serializuj do HTML/EPUB, zachowując `fontStyle`, `fontWeight`, `fontSize` i linki wewnętrzne.<sup>[[1]](#references)</sup>

### Wskazówki implementacyjne

- Normalizuj wszystkie obrazy do tego samego rozmiaru i skali szarości przed obliczaniem hashy i SSIM.
- Buforuj wyniki według perceptual hash, aby uniknąć ponownego obliczania SSIM dla powtarzających się glyphów w kolejnych batchach.
- Używaj wysokiej jakości rozmiaru rasteryzacji (np. 256–512 px), aby uzyskać lepsze rozróżnianie; w razie potrzeby zmniejszaj obrazy przed SSIM, aby przyspieszyć obliczenia.
- Jeśli używasz Pillow do renderowania kandydatów TTF, ustaw ten sam rozmiar canvasa i wyśrodkuj glyph; dodaj margines, aby uniknąć obcinania ascenderów/descenderów.

<details>
<summary>Python: kompleksowa normalizacja i dopasowywanie glyphów (raster hash + SSIM)</summary>
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

Raport źródłowy wykorzystywał geometrię runów, pola stylów i metadane linków do zachowania formatowania rekonstruowanego dokumentu.<sup>[[1]](#references)</sup>

- Podziały akapitów: Jeśli górna współrzędna Y następnego runu przekracza bazową poprzedniej linii o wartość progową (względem rozmiaru fontu), rozpocznij nowy akapit.<sup>[[1]](#references)</sup>
- Wyrównanie: Grupuj według podobnej lewej współrzędnej X dla akapitów wyrównanych do lewej; wykrywaj wyśrodkowane linie na podstawie symetrycznych marginesów; wykrywaj wyrównanie do prawej na podstawie prawych krawędzi.
- Stylowanie: Zachowaj kursywę/pogrubienie za pomocą `fontStyle`/`fontWeight`; różnicuj klasy CSS według przedziałów `fontSize`, aby przybliżyć nagłówki i tekst główny.
- Linki: Jeśli runy zawierają metadane linków (np. `positionId`), generuj anchory i wewnętrzne href.

## Ograniczanie trików anty-scrapingowych wykorzystujących ścieżki SVG

- Używaj wypełnionych ścieżek z `fill-rule: nonzero` i właściwego renderera (CairoSVG, resvg). Nie polegaj na normalizacji tokenów ścieżek.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Unikaj renderowania obrysów; skup się na wypełnionych bryłach, aby ominąć artefakty cienkich linii powodowane przez mikroruchy względne.
- Zachowuj stabilny viewBox dla każdego renderowania, aby identyczne kształty były rasteryzowane spójnie w kolejnych partiach.

## Uwagi dotyczące wydajności

- W praktyce książki sprowadzają się do kilkuset unikalnych glifów (np. ~361, wliczając ligatury). Buforuj wyniki SSIM według hasha percepcyjnego.<sup>[[1]](#references)</sup>
- Po początkowym rozpoznaniu kolejne partie w większości ponownie wykorzystują znane hashe; dekodowanie staje się ograniczone przez I/O.
- W cytowanym raporcie odnotowano średnią wartość SSIM na poziomie około 0,95; oznacz dopasowania z niskim wynikiem do ręcznej weryfikacji.<sup>[[1]](#references)</sup>

## Uogólnienie na inne przeglądarki

Workflow Kindle sugeruje, że podobne przeglądarki mogą nadawać się do tej samej normalizacji, jeśli:<sup>[[1]](#references)</sup>
- zwracają pozycjonowane runy glifów z numerycznymi ID zależnymi od żądania
- dostarczają wektorowe glify dla każdego żądania (ścieżki SVG lub fonty subset)
- ograniczają liczbę stron na żądanie

…można je obsłużyć za pomocą tej samej normalizacji:
- Rasteryzuj kształty dla każdego żądania → hash percepcyjny → ID kształtu
- Atlas kandydatów glifów/ligatur dla każdego wariantu fontu
- SSIM (lub podobna metryka percepcyjna) do przypisywania znaków
- Rekonstruuj układ na podstawie prostokątów runów/stylów

## Minimalny przykład pozyskiwania danych (szkic)

Użyj DevTools swojej przeglądarki, aby przechwycić dokładne nagłówki, cookies i tokeny używane przez czytnik podczas żądania `/renderer/render`. Następnie odtwórz je za pomocą skryptu lub curl.<sup>[[1]](#references)</sup> Zarys przykładu:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Dostosuj parametry (ASIN książki, zakres stron, viewport) do żądań czytelnika. Obowiązuje limit 5 stron na żądanie.<sup>[[1]](#references)</sup>

## Osiągalne wyniki

- Zredukuj ponad 100 losowych alfabetów do jednej przestrzeni glifów za pomocą perceptual hashing.<sup>[[1]](#references)</sup>
- W opisanym teście obejmującym 920 stron dopasowano 361 unikalnych glifów (100%), ze średnim SSIM wynoszącym 0,9527.<sup>[[1]](#references)</sup>
- Raport źródłowy opisuje zrekonstruowany EPUB jako niemal nieodróżnialny od oryginału.<sup>[[1]](#references)</sup>

## References

- [1] [Jak odwróciłem obfuscation Amazon Kindle Web, ponieważ ich aplikacja była beznadziejna (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderer SVG do PNG](https://cairosvg.org/)
- [3] [imagehash – perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – właściwości fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – biblioteka renderująca SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
