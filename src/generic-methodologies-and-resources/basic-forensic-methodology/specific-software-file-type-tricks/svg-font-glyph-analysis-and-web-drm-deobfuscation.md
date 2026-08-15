# SVG-/Font-Glyph-Analyse & Web-DRM-Deobfuscation (Raster-Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite dokumentiert praktische Techniken, um Text aus Webreadern wiederherzustellen, die positionierte Glyphenfolgen zusammen mit request-spezifischen Vektor-Glyphendefinitionen (SVG-Pfade) ausliefern und Glyphen-IDs pro Request randomisieren, um Scraping zu verhindern. Die Kernidee besteht darin, die numerischen, request-bezogenen Glyphen-IDs zu ignorieren und die visuellen Formen per Raster-Hashing zu fingerprinten und anschließend die Formen mithilfe von SSIM gegen einen Referenz-Font-Atlas auf Zeichen abzubilden. Derselbe Ansatz kann sich auf Viewer mit ähnlichen Schutzmechanismen übertragen lassen.<sup>[[1]](#references)</sup>

Warnung: Verwende diese Techniken nur, um Inhalte zu sichern, die dir rechtmäßig gehören, und in Übereinstimmung mit den geltenden Gesetzen und Nutzungsbedingungen.

## Acquisition (Beispiel: Kindle Cloud Reader)

Beobachteter Endpoint:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Pro Session erforderliche Materialien:<sup>[[1]](#references)</sup>
- Browser-Session-Cookies (normales Amazon-Login)
- Rendering-Token aus einem startReading-API-Call
- Zusätzliches ADP-Session-Token, das vom Renderer verwendet wird

Verhalten:<sup>[[1]](#references)</sup>
- Jeder Request gibt bei Verwendung von browseräquivalenten Headers und Cookies ein TAR-Archiv zurück, das auf 5 Seiten begrenzt ist.
- Für ein langes Buch werden viele Batches benötigt; jeder Batch verwendet ein anderes randomisiertes Mapping der Glyphen-IDs.

Typischer TAR-Inhalt:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positionierte Text-Runs als Sequenzen von Glyphen-IDs (nicht Unicode)
- glyphs.json — request-spezifische SVG-Pfaddefinitionen für jede Glyphe und fontFamily
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
- Pfade können sehr kleine relative Bewegungen enthalten (z. B. `m3,1 m1,6 m-4,-7`), die viele Vektorparser und naives Pfad-Sampling verwirren.
- Rendere ausgefüllte, vollständige Pfade immer mit einer robusten SVG-Engine (z. B. CairoSVG), anstatt Befehls-/Koordinatendifferenzen zu berechnen.

## Warum naives Decoding fehlschlägt

- Pro Anfrage randomisierte Glyphensubstitution: Die Zuordnung von Glyph-ID zu Zeichen ändert sich bei jedem Batch; IDs sind global bedeutungslos.<sup>[[1]](#references)</sup>
- Direkter Vergleich von SVG-Koordinaten ist fragil: Identische Formen können sich je nach Anfrage in numerischen Koordinaten oder der Befehlskodierung unterscheiden.<sup>[[1]](#references)</sup>
- OCR auf isolierten Glyphen funktioniert schlecht (≈50 %), verwechselt Satzzeichen und ähnlich aussehende Glyphen und ignoriert Ligaturen.<sup>[[1]](#references)</sup>

## Funktionierende Pipeline: Anfrage-agnostische Glyphennormalisierung und Zuordnung

1) SVG-Glyphen pro Anfrage rastern
- Erstelle pro Glyphe ein minimales SVG-Dokument mit dem bereitgestellten `path` und rendere es mit CairoSVG oder einer gleichwertigen Engine, die problematische Pfadsequenzen verarbeitet, auf eine feste Zeichenfläche (z. B. 512×512).<sup>[[1]](#references)[[2]](#references)</sup>
- Rendere ausgefüllt in Schwarz auf Weiß; vermeide Konturen, um renderer- und AA-abhängige Artefakte zu beseitigen.

2) Perceptual Hashing für anfragenübergreifende Identität
- Berechne einen perceptual hash (z. B. pHash über `imagehash.phash`) für jedes Glyphenbild.<sup>[[3]](#references)</sup>
- Behandle den Hash als stabile ID: Dieselbe visuelle Form in verschiedenen Anfragen wird auf denselben perceptual hash reduziert, wodurch randomisierte IDs wirkungslos werden.

3) Erzeugung eines Referenz-Font-Atlas
- Lade die Ziel-TTF/OTF-Fonts herunter (z. B. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Rendere Kandidaten für A–Z, a–z, 0–9, Satzzeichen, Sonderzeichen (Geviert- und Halbgeviertstriche, Anführungszeichen) sowie explizite Ligaturen: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Führe separate Atlanten für jede Fontvariante (normal/italic/bold/bold-italic).
- Verwende einen geeigneten Text-Shaper (HarfBuzz), wenn du bei Ligaturen Glyphen-Level-Treue benötigst; einfaches Rastern über Pillow ImageFont kann ausreichen, wenn du die Ligaturstrings direkt renderst und die Shaping-Engine sie auflöst.

4) Visuelles Ähnlichkeits-Matching mit SSIM
- Berechne für jedes unbekannte Glyphenbild den SSIM (Structural Similarity Index) gegenüber allen Kandidatenbildern in allen Fontvarianten-Atlanten.<sup>[[4]](#references)</sup>
- Weise den Zeichenstring des Kandidaten mit der höchsten Bewertung zu. SSIM gleicht kleine Unterschiede bei Antialiasing, Skalierung und Koordinaten besser aus als pixelgenaue Vergleiche.<sup>[[1]](#references)[[4]](#references)</sup>

5) Randbehandlung und Rekonstruktion
- Wenn eine Glyphe einer Ligatur (mehreren Zeichen) zugeordnet wird, erweitere sie während des Decodings.<sup>[[1]](#references)</sup>
- Verwende Rechtecke von Runs (oben/links/rechts/unten), um Absatzumbrüche (Y-Differenzen), Ausrichtung (X-Muster), Stil und Größen abzuleiten.<sup>[[1]](#references)</sup>
- Serialisiere nach HTML/EPUB und bewahre `fontStyle`, `fontWeight`, `fontSize` sowie interne Links.<sup>[[1]](#references)</sup>

### Implementierungstipps

- Normalisiere alle Bilder vor dem Hashing und SSIM auf dieselbe Größe und in Graustufen.
- Cache nach perceptual hash, um die erneute Berechnung von SSIM für wiederholte Glyphen über mehrere Batches hinweg zu vermeiden.
- Verwende eine hochwertige Rastergröße (z. B. 256–512 px) für eine bessere Unterscheidung; verkleinere die Bilder bei Bedarf vor SSIM, um die Berechnung zu beschleunigen.
- Wenn du Pillow zum Rendern von TTF-Kandidaten verwendest, setze dieselbe Zeichenflächengröße und zentriere die Glyphe; füge Innenabstand hinzu, um das Abschneiden von Ober- und Unterlängen zu vermeiden.

<details>
<summary>Python: End-to-End-Glyphennormalisierung und -Matching (Raster-Hash + SSIM)</summary>
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

- Absatzumbrüche: Wenn das obere Y des nächsten Runs die Baseline der vorherigen Zeile um einen Schwellenwert überschreitet (relativ zur Schriftgröße), beginne einen neuen Absatz.<sup>[[1]](#references)</sup>
- Ausrichtung: Gruppiere linksbündige Absätze nach ähnlichen linken X-Werten; erkenne zentrierte Zeilen anhand symmetrischer Ränder; erkenne rechtsbündige Zeilen anhand der rechten Kanten.
- Styling: Behalte Kursiv-/Fettdruck über `fontStyle`/`fontWeight` bei; variiere CSS-Klassen anhand von `fontSize`-Buckets, um Überschriften und Fließtext anzunähern.
- Links: Wenn Runs Link-Metadaten enthalten (z. B. `positionId`), erzeuge Anker und interne hrefs.

## Abschwächung von SVG-Anti-Scraping-Tricks mit Pfaden

- Verwende gefüllte Pfade mit `fill-rule: nonzero` und einen geeigneten Renderer (CairoSVG, resvg). Verlasse dich nicht auf die Normalisierung von Pfad-Tokens.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Vermeide das Rendern von Strichen; konzentriere dich auf gefüllte Flächen, um durch mikroskopische relative Verschiebungen verursachte Haarlinienartefakte zu umgehen.
- Behalte pro Render-Vorgang eine stabile viewBox bei, damit identische Formen über mehrere Batches hinweg konsistent gerastert werden.

## Hinweise zur Performance

- In der Praxis konvergieren Bücher auf einige hundert einzigartige Glyphen (z. B. ~361 einschließlich Ligaturen). Cache SSIM-Ergebnisse anhand eines Perceptual Hash.<sup>[[1]](#references)</sup>
- Nach der anfänglichen Erkennung verwenden zukünftige Batches überwiegend bereits bekannte Hashes erneut; das Decoding wird I/O-bound.
- Der zitierte Bericht stellte einen durchschnittlichen SSIM von etwa 0,95 fest; markiere Matches mit niedrigen Werten zur manuellen Prüfung.<sup>[[1]](#references)</sup>

## Verallgemeinerung auf andere Viewer

Der Kindle-Workflow legt nahe, dass ähnliche Viewer für dieselbe Normalisierung geeignet sein könnten, wenn sie:<sup>[[1]](#references)</sup>
- positionierte Glyph-Runs mit requestbezogenen numerischen IDs zurückgeben
- Vektor-Glyphen pro Request bereitstellen (SVG-Pfade oder Subset-Fonts)
- die Anzahl der Seiten pro Request begrenzen

…können mit derselben Normalisierung verarbeitet werden:
- Shapes pro Request rastern → Perceptual Hash → Shape-ID
- Atlas mit möglichen Glyphen/Ligaturen pro Font-Variante
- SSIM (oder eine ähnliche Perceptual Metric), um Zeichen zuzuordnen
- Layout aus Run-Rechtecken/Styles rekonstruieren

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
Parameterisierung (Buch-ASIN, Seitenfenster, Viewport) an die Anfragen des Lesers anpassen. Mit einem Limit von 5 Seiten pro Anfrage rechnen.<sup>[[1]](#references)</sup>

## Results achievable

- Über 100 randomisierte Alphabete mithilfe von Perceptual Hashing auf einen einzigen Glyphenraum reduzieren.<sup>[[1]](#references)</sup>
- Im zitierten 920-seitigen Test wurden 361 einzigartige Glyphen (100 %) mit einem durchschnittlichen SSIM von 0,9527 abgeglichen.<sup>[[1]](#references)</sup>
- Der Quellbericht beschreibt das rekonstruierte EPUB als nahezu nicht vom Original unterscheidbar.<sup>[[1]](#references)</sup>

## References

- [1] [Wie ich Amazons Kindle-Web-Obfuscation rückgängig machte, weil ihre App miserabel war (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG-zu-PNG-Renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual Image Hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Füll-Eigenschaften](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG-Rendering-Bibliothek](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
