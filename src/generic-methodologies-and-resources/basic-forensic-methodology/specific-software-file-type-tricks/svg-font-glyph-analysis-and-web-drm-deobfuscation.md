# SVG-/Font-Glyph-Analyse und Web-DRM-Deobfuscation (Raster-Hashing + SSIM)

Diese Seite dokumentiert praktische Techniken zur Wiederherstellung von Text aus Web-Readern, die positionierte Glyph-Runs zusammen mit request-spezifischen Vektor-Glyph-Definitionen (SVG-Pfaden) ausliefern und Glyph-IDs pro Request randomisieren, um Scraping zu verhindern. Die Kernidee besteht darin, request-bezogene numerische Glyph-IDs zu ignorieren und die visuellen Formen per Raster-Hashing zu fingerprinten. Anschließend werden die Formen mithilfe von SSIM gegen eine Referenz-Font-Atlas den Zeichen zugeordnet. Derselbe Ansatz kann sich auf Viewer mit ähnlichen Schutzmechanismen verallgemeinern lassen.<sup>[[1]](#references)</sup>

Warnung: Verwende diese Techniken nur, um Inhalte zu sichern, die dir rechtmäßig gehören, und unter Einhaltung der geltenden Gesetze und Nutzungsbedingungen.

## Acquisition (Beispiel: Kindle Cloud Reader)

Beobachteter Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Pro Session benötigte Materialien:<sup>[[1]](#references)</sup>
- Browser-Session-Cookies (normaler Amazon-Login)
- Rendering-Token aus einem startReading-API-Aufruf
- Zusätzliches ADP-Session-Token, das vom Renderer verwendet wird

Verhalten:<sup>[[1]](#references)</sup>
- Jeder Request gibt bei Verwendung von browseräquivalenten Headern und Cookies ein auf 5 Seiten begrenztes TAR-Archiv zurück.
- Für ein langes Buch werden viele Batches benötigt; jeder Batch verwendet eine andere randomisierte Zuordnung von Glyph-IDs.

Typischer TAR-Inhalt:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positionierte Text-Runs als Sequenzen von Glyph-IDs (nicht Unicode)
- glyphs.json — request-spezifische SVG-Pfaddefinitionen für jeden Glyph und jede fontFamily
- toc.json — Inhaltsverzeichnis
- metadata.json — Buch-Metadaten
- location_map.json — Zuordnungen von logischen zu visuellen Positionen

Beispielstruktur eines Page-Runs:<sup>[[1]](#references)</sup>
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
- Pfade können minimale relative Bewegungen enthalten (z. B. `m3,1 m1,6 m-4,-7`), die viele Vektorparser und naives Path-Sampling verwirren.
- Rendere vollständige ausgefüllte Pfade immer mit einer robusten SVG-Engine (z. B. CairoSVG), anstatt Befehls-/Koordinatendifferenzen zu bilden.

## Warum naives Decoding fehlschlägt

- Pro Request randomisierte Glyph-Substitution: Die Zuordnung von Glyph-ID zu Zeichen ändert sich in jedem Batch; IDs sind global bedeutungslos.<sup>[[1]](#references)</sup>
- Direkter Vergleich von SVG-Koordinaten ist unzuverlässig: Identische Formen können sich je nach Request in numerischen Koordinaten oder Befehlscodierung unterscheiden.<sup>[[1]](#references)</sup>
- OCR auf isolierten Glyphen funktioniert schlecht (≈50 %), verwechselt Satzzeichen und ähnlich aussehende Glyphen und ignoriert Ligaturen.<sup>[[1]](#references)</sup>

## Funktionsfähige Pipeline: Request-unabhängige Glyph-Normalisierung und -Zuordnung

1) SVG-Glyphen pro Request rastern
- Erstelle pro Glyph ein minimales SVG-Dokument mit dem bereitgestellten `path` und rendere es mit CairoSVG oder einer gleichwertigen Engine, die problematische Pfadsequenzen verarbeitet, auf einer festen Zeichenfläche (z. B. 512×512).<sup>[[1]](#references)[[2]](#references)</sup>
- Rendere ausgefüllte schwarze Glyphen auf weißem Hintergrund; vermeide Konturen, um vom Renderer und von AA abhängige Artefakte zu eliminieren.

2) Perceptual Hashing für requestübergreifende Identität
- Berechne für jedes Glyph-Bild einen Perceptual Hash (z. B. pHash über `imagehash.phash`).<sup>[[3]](#references)</sup>
- Behandle den Hash als stabile ID: Dieselbe visuelle Form in verschiedenen Requests wird auf denselben Perceptual Hash reduziert, wodurch randomisierte IDs wirkungslos werden.

3) Erstellung eines Referenz-Font-Atlas
- Lade die Ziel-TTF/OTF-Fonts herunter (z. B. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Rendere Kandidaten für A–Z, a–z, 0–9, Satzzeichen, Sonderzeichen (Geviert-/Halbgeviertstriche, Anführungszeichen) sowie explizite Ligaturen: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Führe separate Atlanten für jede Font-Variante (normal/italic/bold/bold-italic).
- Verwende einen geeigneten Text-Shaper (HarfBuzz), wenn du bei Ligaturen Glyph-Level-Treue benötigst; einfaches Rastern über Pillow ImageFont kann ausreichen, wenn du die Ligatur-Strings direkt renderst und die Shaping-Engine sie korrekt auflöst.

4) Visuelles Ähnlichkeits-Matching mit SSIM
- Berechne für jedes unbekannte Glyph-Bild den SSIM (Structural Similarity Index) gegenüber allen Kandidatenbildern in allen Font-Varianten-Atlanten.<sup>[[4]](#references)</sup>
- Weise den Zeichen-String des Matches mit der höchsten Bewertung zu. SSIM toleriert kleine Unterschiede bei Antialiasing, Skalierung und Koordinaten besser als pixelgenaue Vergleiche.<sup>[[1]](#references)[[4]](#references)</sup>

5) Behandlung von Sonderfällen und Rekonstruktion
- Wenn ein Glyph auf eine Ligatur (mehrere Zeichen) abgebildet wird, erweitere sie beim Decoding.<sup>[[1]](#references)</sup>
- Verwende Rechtecke pro Textlauf (oben/links/rechts/unten), um Absatzumbrüche (Y-Differenzen), Ausrichtung (X-Muster), Stil und Größen abzuleiten.<sup>[[1]](#references)</sup>
- Serialisiere nach HTML/EPUB und bewahre `fontStyle`, `fontWeight`, `fontSize` sowie interne Links.<sup>[[1]](#references)</sup>

### Tipps zur Implementierung

- Normalisiere alle Bilder vor dem Hashing und SSIM auf dieselbe Größe und in Graustufen.
- Cache nach Perceptual Hash, um die erneute Berechnung von SSIM für wiederholte Glyphen in verschiedenen Batches zu vermeiden.
- Verwende eine hochwertige Rastergröße (z. B. 256–512 px) für eine bessere Unterscheidbarkeit; verkleinere die Bilder bei Bedarf vor SSIM, um die Verarbeitung zu beschleunigen.
- Wenn du Pillow zum Rendern von TTF-Kandidaten verwendest, setze dieselbe Zeichenflächengröße und zentriere das Glyph; verwende einen Rand, um das Abschneiden von Ober- und Unterlängen zu vermeiden.

<details>
<summary>Python: End-to-End-Glyph-Normalisierung und -Matching (Raster-Hash + SSIM)</summary>
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

## Heuristiken zur Rekonstruktion von Layout/EPUB

Der Quellbericht verwendete Run-Geometrie, Style-Felder und Link-Metadaten, um die Formatierung des rekonstruierten Dokuments beizubehalten.<sup>[[1]](#references)</sup>

- Absatzumbrüche: Wenn das obere Y des nächsten Runs die Baseline der vorherigen Zeile um einen Schwellenwert überschreitet (relativ zur Schriftgröße), einen neuen Absatz beginnen.<sup>[[1]](#references)</sup>
- Ausrichtung: Nach ähnlichem linkem X für linksbündige Absätze gruppieren; zentrierte Zeilen anhand symmetrischer Ränder erkennen; rechtsbündige Zeilen anhand der rechten Kanten erkennen.
- Styling: Kursiv/Fettdruck über `fontStyle`/`fontWeight` beibehalten; CSS-Klassen anhand von `fontSize`-Buckets variieren, um Überschriften gegenüber Fließtext anzunähern.
- Links: Wenn Runs Link-Metadaten enthalten (z. B. `positionId`), Anker und interne hrefs ausgeben.

## Abschwächung von SVG-Anti-Scraping-Pfad-Tricks

- Gefüllte Pfade mit `fill-rule: nonzero` und einem geeigneten Renderer (CairoSVG, resvg) verwenden. Nicht auf der Normalisierung von Pfad-Tokens beruhen.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Stroke-Rendering vermeiden; auf gefüllte Flächen konzentrieren, um durch mikroskopische relative Bewegungen verursachte Haarlinienartefakte zu umgehen.
- Pro Render-Vorgang eine stabile viewBox beibehalten, damit identische Formen über mehrere Batches hinweg konsistent gerastert werden.

## Performance-Hinweise

- In der Praxis konvergieren Bücher auf einige hundert eindeutige Glyphen (z. B. etwa 361 einschließlich Ligaturen). SSIM-Ergebnisse nach perceptual hash zwischenspeichern.<sup>[[1]](#references)</sup>
- Nach der anfänglichen Erkennung verwenden zukünftige Batches überwiegend bereits bekannte Hashes; das Decoding wird I/O-bound.
- Der zitierte Bericht beobachtete einen durchschnittlichen SSIM-Wert von etwa 0,95; Matches mit niedriger Bewertung zur manuellen Überprüfung markieren.<sup>[[1]](#references)</sup>

## Verallgemeinerung auf andere Viewer

Der Kindle-Workflow legt nahe, dass sich ähnliche Viewer für dieselbe Normalisierung eignen könnten, wenn sie:<sup>[[1]](#references)</sup>
- positionierte Glyph-Runs mit request-scoped numerischen IDs zurückgeben
- pro Request Vektor-Glyphen (SVG-Pfade oder Subset-Fonts) ausliefern
- die Anzahl der Seiten pro Request begrenzen

…mit derselben Normalisierung verarbeitet werden können:
- Formen pro Request rastern → perceptual hash → Shape-ID
- Atlas von Kandidaten-Glyphen/Ligaturen pro Font-Variante
- SSIM (oder eine ähnliche perceptual metric), um Zeichen zuzuweisen
- Layout aus Run-Rechtecken/-Styles rekonstruieren

## Minimales Beispiel zur Beschaffung (Skizze)

Die DevTools des Browsers verwenden, um die exakten Header, Cookies und Tokens zu erfassen, die der Reader beim Anfordern von `/renderer/render` verwendet. Diese anschließend aus einem Script oder per curl replizieren.<sup>[[1]](#references)</sup> Beispielgliederung:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Passe die Parametrisierung (Buch-ASIN, Seitenfenster, Viewport) an die Anfragen des Readers an. Rechne mit einer Begrenzung auf 5 Seiten pro Anfrage.<sup>[[1]](#references)</sup>

## Erreichbare Ergebnisse

- Mehr als 100 randomisierte Alphabete mithilfe von Perceptual Hashing auf einen einzigen Glyphenraum reduzieren.<sup>[[1]](#references)</sup>
- Im zitierten Test mit 920 Seiten wurden 361 einzigartige Glyphen (100 %) mit einem durchschnittlichen SSIM von 0,9527 zugeordnet.<sup>[[1]](#references)</sup>
- Der Quellbericht beschreibt das rekonstruierte EPUB als nahezu nicht vom Original unterscheidbar.<sup>[[1]](#references)</sup>

## References

- [1] [Wie ich Amazons Kindle-Web-Obfuscation umkehrte, weil ihre App schlecht war (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG-zu-PNG-Renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual Image Hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Fill-Eigenschaften](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG-Rendering-Bibliothek](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
