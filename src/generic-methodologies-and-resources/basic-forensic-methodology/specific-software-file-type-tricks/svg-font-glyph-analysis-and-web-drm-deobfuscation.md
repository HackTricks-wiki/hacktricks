# SVG/Font-Glyph-Analyse & Web-DRM-Deobfuscation (Raster-Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite dokumentiert praktische Techniken, um Text aus Web-Readern wiederherzustellen, die positionierte Glyphenfolgen zusammen mit Glyphendefinitionen als Vektoren (SVG-Pfade) pro Request übertragen und Glyph-IDs pro Request randomisieren, um Scraping zu verhindern. Die Kernidee besteht darin, requestbezogene numerische Glyph-IDs zu ignorieren und die visuellen Formen per Raster-Hashing zu fingerprinten. Anschließend werden die Formen mithilfe von SSIM gegen eine Referenz-Font-Atlas den Zeichen zugeordnet. Derselbe Ansatz kann sich auf Viewer mit ähnlichen Schutzmechanismen verallgemeinern lassen.<sup>[[1]](#references)</sup>

Warnung: Verwende diese Techniken nur zur Sicherung von Inhalten, die dir rechtmäßig gehören, und in Übereinstimmung mit den geltenden Gesetzen und Nutzungsbedingungen.

## Acquisition (Beispiel: Kindle Cloud Reader)

Beobachteter Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Benötigte Materialien pro Session:<sup>[[1]](#references)</sup>
- Browser-Session-Cookies (normaler Amazon-Login)
- Rendering-Token aus einem startReading-API-Call
- Zusätzliches ADP-Session-Token, das vom Renderer verwendet wird

Verhalten:<sup>[[1]](#references)</sup>
- Jeder Request gibt bei Verwendung von Browser-equivalenten Headern und Cookies ein auf 5 Seiten begrenztes TAR-Archiv zurück.
- Für ein langes Buch werden viele Batches benötigt; jeder Batch verwendet ein anderes randomisiertes Mapping der Glyph-IDs.

Typischer TAR-Inhalt:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positionierte Text-Runs als Sequenzen von Glyph-IDs (nicht Unicode)
- glyphs.json — SVG-Pfaddefinitionen pro Request für jede Glyphe und fontFamily
- toc.json — Inhaltsverzeichnis
- metadata.json — Buchmetadaten
- location_map.json — Mappings von logischen zu visuellen Positionen

Beispielstruktur eines Seiten-Runs:<sup>[[1]](#references)</sup>
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
Beispiel für einen glyphs.json-Eintrag:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Hinweise zu Anti-Scraping-Pfadtricks:<sup>[[1]](#references)</sup>
- Pfade können sehr kleine relative Bewegungen enthalten (z. B. `m3,1 m1,6 m-4,-7`), die viele Vektorparser und naives Sampling von Pfaden verwirren.
- Ausgefüllte, vollständige Pfade immer mit einer robusten SVG-Engine (z. B. CairoSVG) rendern, statt eine Differenzbildung von Befehlen/Koordinaten durchzuführen.

## Warum naives Decoding fehlschlägt

- Pro Request randomisierte Glyphensubstitution: Die Zuordnung von Glyphen-ID zu Zeichen ändert sich in jedem Batch; IDs sind global bedeutungslos.<sup>[[1]](#references)</sup>
- Direkter Vergleich von SVG-Koordinaten ist fragil: Identische Formen können sich je nach Request in numerischen Koordinaten oder der Befehlskodierung unterscheiden.<sup>[[1]](#references)</sup>
- OCR auf isolierten Glyphen funktioniert schlecht (≈50 %), verwechselt Satzzeichen und ähnlich aussehende Glyphen und ignoriert Ligaturen.<sup>[[1]](#references)</sup>

## Funktionsfähige Pipeline: Request-agnostische Glyphennormalisierung und Zuordnung

1) SVG-Glyphen pro Request rastern
- Für jede Glyphe ein minimales SVG-Dokument mit dem bereitgestellten `path` erstellen und mit CairoSVG oder einer gleichwertigen Engine, die schwierige Pfadsequenzen verarbeitet, auf eine feste Canvas-Größe (z. B. 512×512) rendern.<sup>[[1]](#references)[[2]](#references)</sup>
- Schwarz auf Weiß ausgefüllt rendern; auf Striche verzichten, um Renderer- und AA-abhängige Artefakte zu vermeiden.

2) Perceptual Hashing für die requestübergreifende Identität
- Für jedes Glyphenbild einen Perceptual Hash (z. B. pHash über `imagehash.phash`) berechnen.<sup>[[3]](#references)</sup>
- Den Hash als stabile ID behandeln: Dieselbe visuelle Form wird über Requests hinweg auf denselben Perceptual Hash reduziert, wodurch randomisierte IDs unwirksam werden.

3) Erzeugung eines Referenz-Font-Atlas
- Die Ziel-TTF/OTF-Fonts herunterladen (z. B. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Kandidaten für A–Z, a–z, 0–9, Satzzeichen, Sonderzeichen (Geviert- und Halbgeviertstriche, Anführungszeichen) sowie explizite Ligaturen rendern: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Separate Atlanten pro Font-Variante (normal/italic/bold/bold-italic) führen.
- Einen geeigneten Text-Shaper (HarfBuzz) verwenden, wenn Ligaturen auf Glyphenebene originalgetreu verarbeitet werden sollen; einfaches Rastern über Pillow ImageFont kann ausreichen, wenn die Ligaturstrings direkt gerendert werden und die Shaping-Engine sie auflöst.

4) Visuelles Ähnlichkeitsmatching mit SSIM
- Für jedes unbekannte Glyphenbild SSIM (Structural Similarity Index) gegen alle Kandidatenbilder aus allen Font-Varianten-Atlanten berechnen.<sup>[[4]](#references)</sup>
- Den Zeichenstring des Ergebnisses mit dem höchsten Score zuweisen. SSIM absorbiert kleine Unterschiede bei Antialiasing, Skalierung und Koordinaten besser als pixelgenaue Vergleiche.<sup>[[1]](#references)[[4]](#references)</sup>

5) Behandlung von Sonderfällen und Rekonstruktion
- Wenn eine Glyphe einer Ligatur (mehreren Zeichen) zugeordnet wird, diese beim Decoding expandieren.<sup>[[1]](#references)</sup>
- Rechtecke der Runs (oben/links/rechts/unten) verwenden, um Absatzumbrüche (Y-Differenzen), Ausrichtung (X-Muster), Stil und Größen abzuleiten.<sup>[[1]](#references)</sup>
- Als HTML/EPUB serialisieren und dabei `fontStyle`, `fontWeight`, `fontSize` sowie interne Links erhalten.<sup>[[1]](#references)</sup>

### Implementierungstipps

- Alle Bilder vor dem Hashing und SSIM auf dieselbe Größe und Graustufen normalisieren.
- Nach Perceptual Hash cachen, um die erneute Berechnung von SSIM für wiederholte Glyphen über mehrere Batches hinweg zu vermeiden.
- Eine hochwertige Rastergröße (z. B. 256–512 px) für eine bessere Unterscheidung verwenden; bei Bedarf vor SSIM zur Beschleunigung herunterskalieren.
- Bei Verwendung von Pillow zum Rendern von TTF-Kandidaten dieselbe Canvas-Größe festlegen und die Glyphe zentrieren; ausreichend Padding verwenden, um das Abschneiden von Ober- und Unterlängen zu vermeiden.

<details>
<summary>Python: End-to-End-Glyphennormalisierung und -matching (Raster-Hash + SSIM)</summary>
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

Der Quellbericht verwendete Run-Geometrie, Style-Felder und Link-Metadaten, um die Formatierung des rekonstruierten Dokuments beizubehalten.<sup>[[1]](#references)</sup>

- Absatzumbrüche: Wenn das obere Y des nächsten Runs die Baseline der vorherigen Zeile um einen Schwellenwert (relativ zur Schriftgröße) überschreitet, einen neuen Absatz beginnen.<sup>[[1]](#references)</sup>
- Ausrichtung: Für linksbündige Absätze nach ähnlichen linken X-Werten gruppieren; zentrierte Zeilen anhand symmetrischer Ränder erkennen; rechtsbündige Zeilen anhand der rechten Kanten erkennen.
- Styling: Kursiv/Fett über `fontStyle`/`fontWeight` beibehalten; CSS-Klassen anhand von `fontSize`-Buckets variieren, um Überschriften gegenüber Fließtext anzunähern.
- Links: Wenn Runs Link-Metadaten (z. B. `positionId`) enthalten, Anker und interne hrefs ausgeben.

## Eindämmung von SVG-Anti-Scraping-Pfad-Tricks

- Gefüllte Pfade mit `fill-rule: nonzero` und einem geeigneten Renderer (CairoSVG, resvg) verwenden. Nicht auf die Normalisierung von Pfad-Tokens vertrauen.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Stroke-Rendering vermeiden; auf gefüllte Flächen konzentrieren, um durch mikroskopische relative Bewegungen verursachte Haarlinienartefakte zu umgehen.
- Pro Render-Vorgang eine stabile viewBox beibehalten, damit identische Shapes über mehrere Batches hinweg konsistent gerastert werden.

## Hinweise zur Performance

- In der Praxis konvergieren Bücher auf einige hundert eindeutige Glyphen (z. B. ~361 einschließlich Ligaturen). SSIM-Ergebnisse per perceptual hash cachen.<sup>[[1]](#references)</sup>
- Nach der anfänglichen Ermittlung verwenden zukünftige Batches überwiegend bereits bekannte Hashes; das Decoding wird I/O-bound.
- Der d report beobachtete einen durchschnittlichen SSIM-Wert von etwa 0,95; Matches mit niedriger Bewertung zur manuellen Prüfung markieren.<sup>[[1]](#references)</sup>

## Generalisierung auf andere Viewer

Der Kindle-Workflow legt nahe, dass ähnliche Viewer für dieselbe Normalisierung geeignet sein könnten, wenn sie:<sup>[[1]](#references)</sup>
- positionierte Glyph-Runs mit request-scoped numerischen IDs zurückgeben
- Vektor-Glyphen pro Request (SVG-Pfade oder subset fonts) ausliefern
- die Anzahl der Seiten pro Request begrenzen

…mit derselben Normalisierung verarbeitet werden können:
- Shapes pro Request rastern → perceptual hash → Shape-ID
- Atlas aus Kandidaten-Glyphen/Ligaturen pro Font-Variante
- SSIM (oder eine ähnliche perceptual metric) zur Zuordnung von Zeichen
- Layout aus Run-Rechtecken/Styles rekonstruieren

## Minimales Beispiel zur Beschaffung (Skizze)

Die DevTools deines Browsers verwenden, um die exakten Header, Cookies und Tokens zu erfassen, die der Reader beim Anfordern von `/renderer/render` verwendet. Diese anschließend aus einem Script oder per curl replizieren.<sup>[[1]](#references)</sup> Beispielgliederung:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Passe die Parameter (Buch-ASIN, Seitenfenster, Viewport) an die Anfragen des Lesers an. Rechne mit einer Begrenzung auf 5 Seiten pro Anfrage.<sup>[[1]](#references)</sup>

## Erzielbare Ergebnisse

- Reduziere mehr als 100 randomisierte Alphabete mithilfe von Perceptual Hashing auf einen einzigen Glyphenraum.<sup>[[1]](#references)</sup>
- Im d 920-Seiten-Test wurden 361 eindeutige Glyphen (100 %) mit einem durchschnittlichen SSIM von 0,9527 zugeordnet.<sup>[[1]](#references)</sup>
- Der Quellbericht beschreibt das rekonstruierte EPUB als nahezu nicht vom Original unterscheidbar.<sup>[[1]](#references)</sup>

## References

- [1] [Wie ich Amazons Kindle-Web-Obfuscation umkehrte, weil ihre App schlecht war (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG-zu-PNG-Renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual Image Hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill-Eigenschaften](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG-Rendering-Bibliothek](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
