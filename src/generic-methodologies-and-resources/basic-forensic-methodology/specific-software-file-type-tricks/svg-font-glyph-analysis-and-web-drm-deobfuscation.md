# SVG-/Font-Glyph-Analyse & Web-DRM-Deobfuscation (Raster-Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite dokumentiert praktische Techniken zur Wiederherstellung von Text aus Webreadern, die positionierte Glyph-Runs zusammen mit vektorbasierten Glyph-Definitionen (SVG-Pfaden) pro Request ausliefern und Glyph-IDs pro Request randomisieren, um Scraping zu verhindern. Die grundlegende Idee besteht darin, requestbezogene numerische Glyph-IDs zu ignorieren und die visuellen Formen per Raster-Hashing zu fingerprinten. Anschließend werden die Formen mithilfe von SSIM gegen eine Referenz-Font-Atlas den Zeichen zugeordnet. Der Workflow lässt sich über den Kindle Cloud Reader hinaus auf jeden Viewer mit ähnlichen Schutzmechanismen übertragen.<sup>[[1]](#references)</sup>

Warnung: Verwende diese Techniken nur, um Inhalte zu sichern, die du rechtmäßig besitzt, und unter Einhaltung der geltenden Gesetze und Nutzungsbedingungen.

## Acquisition (Beispiel: Kindle Cloud Reader)

Beobachteter Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Pro Session benötigte Materialien:
- Browser-Session-Cookies (normaler Amazon-Login)
- Rendering-Token aus einem startReading-API-Call
- Zusätzliches ADP-Session-Token, das vom Renderer verwendet wird

Verhalten:
- Jeder Request gibt bei Verwendung von browseräquivalenten Headers und Cookies ein auf 5 Seiten begrenztes TAR-Archiv zurück.
- Für ein langes Buch werden viele Batches benötigt; jeder Batch verwendet ein anderes randomisiertes Mapping der Glyph-IDs.

Typischer TAR-Inhalt:
- page_data_0_4.json — positionierte Text-Runs als Sequenzen von Glyph-IDs (nicht Unicode)
- glyphs.json — SVG-Pfaddefinitionen pro Request für jedes Glyph und jede fontFamily
- toc.json — Inhaltsverzeichnis
- metadata.json — Buchmetadaten
- location_map.json — Zuordnungen von logischen zu visuellen Positionen

Beispielstruktur eines Page-Runs:
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
Beispiel für einen Eintrag in glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Hinweise zu Anti-Scraping-Pfad-Tricks:
- Pfade können sehr kleine relative Bewegungen enthalten (z. B. `m3,1 m1,6 m-4,-7`), die viele Vektorparser und naives Path-Sampling verwirren.
- Rendere ausgefüllte, vollständige Pfade immer mit einer robusten SVG-Engine (z. B. CairoSVG), anstatt Befehls-/Koordinatendifferenzen zu berechnen.

## Warum naives Decoding fehlschlägt

- Pro-Request randomisierte Glyph-Substitution: Die Glyph-ID→Zeichen-Zuordnung ändert sich in jedem Batch; IDs sind global bedeutungslos.<sup>[[1]](#references)</sup>
- Direkter SVG-Koordinatenvergleich ist fragil: Identische Formen können sich bei numerischen Koordinaten oder der Command-Kodierung pro Request unterscheiden.
- OCR auf isolierten Glyphen funktioniert schlecht (≈50 %), verwechselt Interpunktion und ähnlich aussehende Glyphen und ignoriert Ligaturen.

## Funktionierende Pipeline: Request-agnostische Glyph-Normalisierung und -Zuordnung

1) SVG-Glyphen pro Request rasterisieren
- Erstelle pro Glyph ein minimales SVG-Dokument mit dem bereitgestellten `path` und rendere es auf einer festen Zeichenfläche (z. B. 512×512) mit CairoSVG oder einer gleichwertigen Engine, die problematische Pfadsequenzen verarbeitet.<sup>[[1]](#references)[[2]](#references)</sup>
- Rendere ausgefülltes Schwarz auf Weiß; vermeide Strokes, um Renderer- und AA-abhängige Artefakte zu eliminieren.

2) Perceptual Hashing für requestübergreifende Identität
- Berechne einen perceptual hash (z. B. pHash über `imagehash.phash`) für jedes Glyph-Bild.<sup>[[3]](#references)</sup>
- Behandle den Hash als stabile ID: Dieselbe visuelle Form über mehrere Requests hinweg wird auf denselben perceptual hash reduziert, wodurch randomisierte IDs wirkungslos werden.

3) Erzeugung eines Referenz-Font-Atlas
- Lade die Ziel-TTF/OTF-Fonts herunter (z. B. Bookerly normal/italic/bold/bold-italic).
- Rendere Kandidaten für A–Z, a–z, 0–9, Interpunktion, Sonderzeichen (Geviert-/Halbgeviertstriche, Anführungszeichen) sowie explizite Ligaturen: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Verwende separate Atlanten pro Font-Variante (normal/italic/bold/bold-italic).
- Verwende einen geeigneten Text-Shaper (HarfBuzz), wenn du für Ligaturen Glyph-Level-Fidelity benötigst; einfaches Rasterisieren über Pillow ImageFont kann ausreichen, wenn du die Ligatur-Strings direkt renderst und die Shaping-Engine sie korrekt auflöst.

4) Visuelles Similarity-Matching mit SSIM
- Berechne für jedes unbekannte Glyph-Bild SSIM (Structural Similarity Index) gegenüber allen Kandidatenbildern in allen Font-Varianten-Atlanten.<sup>[[4]](#references)</sup>
- Weise den Zeichen-String des Matches mit dem höchsten Score zu. SSIM absorbiert kleine Unterschiede bei Antialiasing, Skalierung und Koordinaten besser als pixelgenaue Vergleiche.

5) Behandlung von Sonderfällen und Rekonstruktion
- Wenn ein Glyph auf eine Ligatur (mehrere Zeichen) abgebildet wird, erweitere sie während des Decodings.
- Verwende Run-Rechtecke (oben/links/rechts/unten), um Absatzumbrüche (Y-Differenzen), Ausrichtung (X-Muster), Stil und Größen abzuleiten.
- Serialisiere nach HTML/EPUB und bewahre `fontStyle`, `fontWeight`, `fontSize` sowie interne Links.

### Implementierungstipps

- Normalisiere alle Bilder vor dem Hashing und SSIM auf dieselbe Größe und in Graustufen.
- Cache nach perceptual hash, um die erneute Berechnung von SSIM für wiederholte Glyphen über mehrere Batches hinweg zu vermeiden.
- Verwende eine hochwertige Rastergröße (z. B. 256–512 px) für eine bessere Unterscheidbarkeit; verkleinere die Bilder bei Bedarf vor SSIM, um die Verarbeitung zu beschleunigen.
- Wenn du Pillow zum Rendern von TTF-Kandidaten verwendest, setze dieselbe Zeichenflächengröße und zentriere das Glyph; füge Padding hinzu, um das Abschneiden von Ober- und Unterlängen zu vermeiden.

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

## Heuristiken zur Layout-/EPUB-Rekonstruktion

- Absatzumbrüche: Wenn der obere Y-Wert des nächsten Runs die Grundlinie der vorherigen Zeile um einen Schwellenwert überschreitet (relativ zur Schriftgröße), beginne einen neuen Absatz.<sup>[[1]](#references)</sup>
- Ausrichtung: Gruppiere nach ähnlichen linken X-Werten für linksbündige Absätze; erkenne zentrierte Zeilen anhand symmetrischer Ränder; erkenne rechtsbündige Zeilen anhand der rechten Kanten.
- Styling: Bewahre Kursiv- und Fettdruck über `fontStyle`/`fontWeight`; variiere CSS-Klassen anhand von `fontSize`-Buckets, um Überschriften und Fließtext anzunähern.
- Links: Wenn Runs Link-Metadaten enthalten (z. B. `positionId`), gib Anker und interne hrefs aus.

## Abschwächung von SVG-Anti-Scraping-Tricks mit Pfaden

- Verwende gefüllte Pfade mit `fill-rule: nonzero` und einen geeigneten Renderer (CairoSVG, resvg). Verlasse dich nicht auf die Normalisierung von Pfad-Tokens.<sup>[[1]](#references)</sup>
- Vermeide das Rendern von Konturen; konzentriere dich auf gefüllte Flächen, um durch mikroskopische relative Verschiebungen verursachte Haarlinienartefakte zu umgehen.
- Verwende pro Render-Vorgang eine stabile viewBox, damit identische Formen über mehrere Batches hinweg konsistent gerastert werden.

## Hinweise zur Performance

- In der Praxis konvergieren Bücher auf einige hundert eindeutige Glyphen (z. B. ~361 einschließlich Ligaturen). Cache die SSIM-Ergebnisse anhand eines Perceptual Hash.<sup>[[1]](#references)</sup>
- Nach der anfänglichen Erkennung verwenden zukünftige Batches überwiegend bereits bekannte Hashes; die Decodierung wird durch I/O begrenzt.
- Ein durchschnittlicher SSIM-Wert von ≈0.95 ist ein starkes Signal; erwäge, Matches mit niedriger Bewertung zur manuellen Prüfung zu markieren.

## Verallgemeinerung auf andere Viewer

Jedes System, das:<sup>[[1]](#references)</sup>
- Positionierte Glyph-Runs mit anforderungsspezifischen numerischen IDs zurückgibt
- Pro Anfrage Vektor-Glyphen (SVG-Pfade oder Subset-Fonts) ausliefert
- Die Anzahl der Seiten pro Anfrage begrenzt, um Bulk-Export zu verhindern

…kann mit derselben Normalisierung verarbeitet werden:
- Formen pro Anfrage rastern → Perceptual Hash → Shape-ID
- Atlas von Kandidaten-Glyphen/Ligaturen pro Font-Variante
- SSIM (oder eine ähnliche Perceptual Metric), um Zeichen zuzuweisen
- Layout aus Run-Rechtecken/-Styles rekonstruieren

## Minimales Beispiel zur Beschaffung (Skizze)

Verwende die DevTools deines Browsers, um die exakten Header, Cookies und Tokens zu erfassen, die der Reader beim Anfordern von `/renderer/render` verwendet. Repliziere diese anschließend aus einem Script oder mit curl.<sup>[[1]](#references)</sup> Beispielhafte Struktur:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Parameterisierung (Book-ASIN, Seitenfenster, Viewport) an die Anfragen des Lesers anpassen. Ein Limit von 5 Seiten pro Anfrage berücksichtigen.

## Erreichbare Ergebnisse

- 100+ randomisierte Alphabete mithilfe von perceptual hashing<sup>[[1]](#references)</sup> auf einen einzigen Glyphenraum reduzieren
- 100 % Zuordnung eindeutiger Glyphen mit einem durchschnittlichen SSIM von ~0,95, wenn Atlanten Ligaturen und Varianten enthalten
- EPUB/HTML rekonstruieren, das visuell nicht vom Original zu unterscheiden ist

## Referenzen

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
