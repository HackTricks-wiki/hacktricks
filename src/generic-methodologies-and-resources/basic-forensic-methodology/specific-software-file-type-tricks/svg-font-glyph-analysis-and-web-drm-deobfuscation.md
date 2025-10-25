# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite dokumentiert praktische Techniken, um Text aus Web-Readern wiederherzustellen, die positionierte Glyphenläufe sowie pro-Anfrage Vektor-Glyphendefinitionen (SVG paths) ausliefern und Glyphen-IDs pro Anfrage randomisieren, um Scraping zu verhindern. Die Kernidee ist, anfrage-spezifische numerische Glyphen-IDs zu ignorieren und die visuellen Formen mittels Raster-Hashing zu fingerprinten, dann die Formen mit SSIM gegen ein Referenz-Font-Atlas auf Zeichen zu mappen. Der Workflow verallgemeinert sich über den Kindle Cloud Reader hinaus auf jeden Viewer mit ähnlichen Schutzmechanismen.

Warnung: Verwenden Sie diese Techniken nur, um Inhalte zu sichern, die Sie rechtmäßig besitzen, und in Übereinstimmung mit geltenden Gesetzen und Nutzungsbedingungen.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Benötigte Materialien pro Session:
- Browser session cookies (normales Amazon-Login)
- Rendering token von einem startReading API call
- Zusätzliches ADP session token, das vom Renderer verwendet wird

Verhalten:
- Jede Anfrage liefert, wenn sie mit browser-äquivalenten Headers und Cookies gesendet wird, ein TAR-Archiv mit maximal 5 Seiten.
- Bei einem langen Buch benötigen Sie viele Batches; jedes Batch verwendet eine andere randomisierte Zuordnung der glyph IDs.

Typische TAR-Inhalte:
- page_data_0_4.json — positionierte Textläufe als Sequenzen von glyph IDs (nicht Unicode)
- glyphs.json — pro-Anfrage SVG path-Definitionen für jede glyphe und fontFamily
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logische→visuelle Positionszuordnungen

Beispiel für die Struktur eines page run:
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
Beispiel für einen glyphs.json-Eintrag:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Hinweise zu Anti-Scraping-Pfadtricks:
- Pfade können mikro-relativen Bewegungen enthalten (z. B. `m3,1 m1,6 m-4,-7`), die viele Vektorparser und naive Path-Sampling-Ansätze verwirren.
- Rendern Sie immer gefüllte komplette Pfade mit einer robusten SVG-Engine (z. B. CairoSVG) statt Befehls-/Koordinaten-Differenzierung.

## Warum naive Dekodierung fehlschlägt

- Per-Request randomisierte Glyphen-Substitution: Glyph-ID→Zeichen-Mapping ändert sich mit jeder Charge; IDs sind global bedeutungslos.
- Direkter SVG-Koordinatenvergleich ist brüchig: identische Formen können pro Anfrage in numerischen Koordinaten oder Befehls-Encoding variieren.
- OCR auf isolierten Glyphen liefert schlechte Ergebnisse (≈50%), verwechselt Satzzeichen und ähnlich aussehende Glyphen und ignoriert Ligaturen.

## Arbeitsablauf: anfrageunabhängige Glyph-Normalisierung und Zuordnung

1) Rasterisieren der pro-Anfrage SVG-Glyphen
- Erstellen Sie für jede Glyphe ein minimales SVG-Dokument mit dem angegebenen `path` und rendern Sie es auf eine feste Canvas-Größe (z. B. 512×512) mithilfe von CairoSVG oder einer äquivalenten Engine, die schwierige Pfadsequenzen korrekt verarbeitet.
- Rendern Sie gefüllt schwarz auf weiß; vermeiden Sie strokes, um renderer- und AA-abhängige Artefakte zu eliminieren.

2) Perzeptuelles Hashing für anfrageübergreifende Identität
- Berechnen Sie einen perzeptuellen Hash (z. B. pHash via `imagehash.phash`) jedes Glyphe-Bildes.
- Behandeln Sie den Hash als stabile ID: dieselbe visuelle Form über Requests hinweg kollabiert zum selben perzeptuellen Hash und macht randomisierte IDs unwirksam.

3) Erzeugen eines Referenz-Font-Atlas
- Laden Sie die Ziel-TTF/OTF-Fonts herunter (z. B. Bookerly normal/italic/bold/bold-italic).
- Rendern Sie Kandidaten für A–Z, a–z, 0–9, Interpunktion, Sonderzeichen (Geviert-/Halbgeviertstriche, Anführungszeichen) und explizite Ligaturen: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Führen Sie separate Atlanten pro Font-Variante (normal/italic/bold/bold-italic).
- Verwenden Sie einen richtigen Text Shaper (HarfBuzz), wenn Sie Glyphen-Fidelity auf Ligatur-Ebene benötigen; einfache Rasterisierung via Pillow ImageFont kann ausreichend sein, wenn Sie die Ligatur-Strings direkt rendern und die Shaping-Engine diese auflöst.

4) Visueller Ähnlichkeitsabgleich mit SSIM
- Berechnen Sie für jedes unbekannte Glyphe-Bild SSIM (Structural Similarity Index) gegenüber allen Kandidatenbildern in allen Font-Varianten-Atlanten.
- Weisen Sie die Zeichenfolge des bestbewerteten Matches zu. SSIM kompensiert kleine Anti-Aliasing-, Skalierungs- und Koordinatenunterschiede besser als pixelgenaue Vergleiche.

5) Randbehandlung und Rekonstruktion
- Wenn eine Glyphe auf eine Ligatur (Multi-Char) abgebildet wird, erweitern Sie diese beim Decodieren.
- Verwenden Sie run rectangles (top/left/right/bottom), um Absatzumbrüche (Y-Deltas), Ausrichtung (X-Muster), Stil und Größen zu erschließen.
- Serialisieren Sie zu HTML/EPUB und bewahren Sie `fontStyle`, `fontWeight`, `fontSize` und interne Links.

### Tipps zur Implementierung

- Normalisieren Sie alle Bilder vor Hashing und SSIM auf dieselbe Größe und Graustufen.
- Cache nach perzeptuellem Hash, um SSIM-Neuberechnungen für wiederkehrende Glyphen über Batches zu vermeiden.
- Verwenden Sie eine hochwertige Raster-Größe (z. B. 256–512 px) für bessere Unterscheidbarkeit; bei Bedarf vor SSIM herunter skalieren, um zu beschleunigen.
- Wenn Sie Pillow zum Rendern von TTF-Kandidaten verwenden, setzen Sie dieselbe Canvas-Größe und zentrieren Sie die Glyphe; fügen Sie Padding hinzu, um Abschneiden von Ascender/Descender zu vermeiden.

<details>
<summary>Python: End-to-End-Glyph-Normalisierung und Matching (Raster-Hash + SSIM)</summary>
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

## Layout/EPUB-Rekonstruktions-Heuristiken

- Absatzumbrüche: Wenn das Top-Y des nächsten Runs die Grundlinie der vorherigen Zeile um einen Schwellenwert (relativ zur Schriftgröße) überschreitet, beginne einen neuen Absatz.
- Ausrichtung: Gruppiere nach ähnlichem linken X für linksbündige Absätze; erkenne zentrierte Zeilen an symmetrischen Rändern; erkenne rechtsbündige an den rechten Kanten.
- Styling: Erhalte kursiv/fett über `fontStyle`/`fontWeight`; variiere CSS-Klassen nach `fontSize`-Buckets, um Überschriften vs. Fließtext zu approximieren.
- Links: Wenn Runs Link-Metadaten enthalten (z. B. `positionId`), erzeuge Anker und interne hrefs.

## SVG-Anti-Scraping-Pfad-Tricks mildern

- Verwende gefüllte Pfade mit `fill-rule: nonzero` und einen geeigneten Renderer (CairoSVG, resvg). Verlasse dich nicht auf die Normalisierung von Pfad-Tokens.
- Vermeide stroke rendering; konzentriere dich auf gefüllte Flächen, um Haarlinien-Artefakte zu umgehen, die durch mikroskopische relative Verschiebungen entstehen.
- Behalte pro Render eine stabile viewBox bei, damit identische Formen konsistent über Batches gerastert werden.

## Performance-Hinweise

- In der Praxis konvergieren Bücher auf ein paar hundert einzigartige Glyphen (z. B. ~361 inklusive Ligaturen). Cache SSIM-Ergebnisse anhand eines perceptual hash.
- Nach der anfänglichen Entdeckung verwenden zukünftige Batches überwiegend bekannte Hashes wieder; das Decoding wird I/O-gebunden.
- Ein durchschnittlicher SSIM ≈0.95 ist ein starkes Signal; erwäge, niedrig bewertete Treffer zur manuellen Überprüfung zu markieren.

## Generalisierung auf andere Viewer

Jedes System, das:
- positionierte Glyph-Runs mit request-scoped numerischen IDs zurückgibt
- pro Anfrage vector glyphs (SVG paths oder subset fonts) liefert
- die Seiten pro Anfrage begrenzt, um Bulk-Export zu verhindern

…kann mit derselben Normalisierung behandelt werden:
- Rasterisiere pro Anfrage Formen → perceptual hash → shape ID
- Atlas möglicher Glyphen/Ligaturen pro Font-Variante
- SSIM (oder eine ähnliche perceptual metric) zur Zuordnung von Zeichen
- Rekonstruiere das Layout aus Run-Rechtecken und -Stilen

## Minimales Erfassungsbeispiel (Skizze)

Verwende die DevTools deines Browsers, um die exakten Headers, Cookies und Tokens zu erfassen, die der Reader beim Anfordern von `/renderer/render` verwendet. Repliziere diese anschließend aus einem Script oder curl. Beispiel-Umriss:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Passe die Parametrierung (book ASIN, page window, viewport) an die Anforderungen des Lesers an. Pro Anfrage ist mit einer Obergrenze von 5 Seiten zu rechnen.

## Erreichbare Ergebnisse

- Mehr als 100 randomisierte Alphabete in einen einzigen Glyphenraum zusammenführen mittels perceptual hashing
- 100% Zuordnung einzigartiger Glyphen mit durchschnittlichem SSIM ~0.95, wenn Atlanten Ligaturen und Varianten enthalten
- Rekonstruiertes EPUB/HTML visuell nicht vom Original zu unterscheiden

## Referenzen

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
