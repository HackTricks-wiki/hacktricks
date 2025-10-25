# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει πρακτικές τεχνικές για την ανάκτηση κειμένου από web readers που αποστέλλουν positioned glyph runs μαζί με per-request vector glyph definitions (SVG paths), και που τυχαίοποιούν τα glyph IDs ανά request για να αποτρέψουν το scraping. Η βασική ιδέα είναι να αγνοήσουμε τα request-scoped numeric glyph IDs και να fingerprint-άρουμε τα οπτικά σχήματα μέσω raster hashing, και στη συνέχεια να αντιστοιχίσουμε τα σχήματα σε χαρακτήρες με SSIM έναντι ενός reference font atlas. Η ροή εργασίας γενικεύεται πέρα από Kindle Cloud Reader σε οποιονδήποτε viewer με παρόμοιες προστασίες.

Warning: Only use these techniques to back up content you legitimately own and in compliance with applicable laws and terms.

## Απόκτηση (παράδειγμα: Kindle Cloud Reader)

Παρατηρούμενο endpoint:
- [https://read.amazon.com/renderer/render]

Απαιτούμενα υλικά ανά session:
- Browser session cookies (normal Amazon login)
- Rendering token from a startReading API call
- Additional ADP session token used by the renderer

Συμπεριφορά:
- Κάθε request, όταν αποστέλλεται με browser-equivalent headers και cookies, επιστρέφει ένα TAR archive περιορισμένο σε 5 pages.
- Για ένα μεγάλο βιβλίο θα χρειαστείτε πολλά batches· κάθε batch χρησιμοποιεί διαφορετικό randomized mapping των glyph IDs.

Τυπικά περιεχόμενα TAR:
- page_data_0_4.json — positioned text runs as sequences of glyph IDs (not Unicode)
- glyphs.json — per-request SVG path definitions for each glyph and fontFamily
- toc.json — table of contents
- metadata.json — book metadata
- location_map.json — logical→visual position mappings

Παράδειγμα δομής page run:
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
Παράδειγμα εγγραφής στο glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Σημειώσεις σχετικά με anti-scraping path tricks:
- Paths μπορεί να περιλαμβάνουν micro relative moves (π.χ., `m3,1 m1,6 m-4,-7`) που συγχέουν πολλούς vector parsers και naïve path sampling.
- Πάντα αποδώστε γεμάτα, πλήρη paths με έναν αξιόπιστο SVG engine (π.χ., CairoSVG) αντί να κάνετε command/coordinate differencing.

## Γιατί αποτυγχάνει η απλή αποκωδικοποίηση

- Per-request randomized glyph substitution: η αντιστοίχιση glyph ID→character αλλάζει κάθε batch· τα IDs δεν έχουν παγκόσμιο νόημα.
- Η άμεση σύγκριση συντεταγμένων SVG είναι ευαίσθητη: ίδια σχήματα μπορεί να διαφέρουν σε αριθμητικές συντεταγμένες ή στην κωδικοποίηση εντολών ανά αίτηση.
- Το OCR σε απομονωμένα glyphs αποδίδει φτωχά (≈50%), μπερδεύει σημεία στίξης και ομοιάζοντα glyphs, και αγνοεί ligatures.

## Ροή εργασίας: request-agnostic κανονικοποίηση και αντιστοίχιση glyphs

1) Rasterize per-request SVG glyphs
- Δημιουργήστε ένα ελάχιστο SVG έγγραφο ανά glyph με το παρεχόμενο `path` και αποδώστε σε ένα σταθερό canvas (π.χ., 512×512) χρησιμοποιώντας CairoSVG ή έναν ισοδύναμο engine που χειρίζεται σύνθετες ακολουθίες path.
- Αποδώστε γεμάτο μαύρο σε λευκό· αποφύγετε strokes για να εξαλείψετε artifacts εξαρτώμενα από τον renderer και το AA.

2) Perceptual hashing for cross-request identity
- Υπολογίστε ένα perceptual hash (π.χ., pHash via `imagehash.phash`) για κάθε εικόνα glyph.
- Χρησιμοποιήστε το hash ως σταθερό ID: το ίδιο οπτικό σχήμα σε διαφορετικά requests συμπτύσσεται στο ίδιο perceptual hash, εξουδετερώνοντας randomized IDs.

3) Reference font atlas generation
- Κατεβάστε τα στοχευόμενα TTF/OTF fonts (π.χ., Bookerly normal/italic/bold/bold-italic).
- Αποδώστε υποψήφιους για A–Z, a–z, 0–9, σημεία στίξης, ειδικά σημάδια (em/en dashes, quotes) και ρητές ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Κρατήστε ξεχωριστά atlases ανά παραλλαγή font (normal/italic/bold/bold-italic).
- Χρησιμοποιήστε proper text shaper (HarfBuzz) αν θέλετε glyph-level fidelity για ligatures· απλή rasterization μέσω Pillow ImageFont μπορεί να είναι επαρκής αν αποδώσετε τα ligature strings απευθείας και το shaping engine τα επιλύει.

4) Visual similarity matching with SSIM
- Για κάθε άγνωστη εικόνα glyph, υπολογίστε SSIM (Structural Similarity Index) απέναντι σε όλες τις υποψήφιες εικόνες σε όλα τα atlases των παραλλαγών font.
- Αντιστοιχίστε το χαρακτήρα της καλύτερης βαθμολογημένης ταύτισης. Το SSIM απορροφά μικρές διαφορές anti-aliasing, κλίμακας και συντεταγμένων καλύτερα από pixel-exact συγκρίσεις.

5) Edge handling και ανακατασκευή
- Όταν ένα glyph αντιστοιχεί σε ligature (πολλαπλοί χαρακτήρες), επεκτείνετέ το κατά την αποκωδικοποίηση.
- Χρησιμοποιήστε run rectangles (top/left/right/bottom) για να συμπεράνετε διακοπές παραγράφων (Y deltas), στοίχιση (X patterns), style και μεγέθη.
- Σειριοποιήστε σε HTML/EPUB διατηρώντας `fontStyle`, `fontWeight`, `fontSize` και εσωτερικούς συνδέσμους.

### Implementation tips

- Κανονικοποιήστε όλες τις εικόνες στο ίδιο μέγεθος και σε grayscale πριν από hashing και SSIM.
- Κάντε cache ανά perceptual hash για να αποφύγετε επανυπολογισμό SSIM για επαναλαμβανόμενα glyphs σε διαφορετικά batches.
- Χρησιμοποιήστε υψηλής ποιότητας raster size (π.χ. 256–512 px) για καλύτερο διαχωρισμό· κάντε downscale όπως χρειάζεται πριν το SSIM για επιτάχυνση.
- Αν χρησιμοποιείτε Pillow για απόδοση TTF υποψηφίων, ορίστε το ίδιο μέγεθος canvas και κεντράρετε το glyph· προσθέστε padding για να αποφύγετε clipping ascenders/descenders.

<details>
<summary>Python: end-to-end glyph normalization and matching (raster hash + SSIM)</summary>
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

## Διάταξη/Επανακατασκευή EPUB — Ευρετικές

- Διαχωρισμός παραγράφων: Εάν το top Y του επόμενου run υπερβαίνει τη baseline της προηγούμενης γραμμής κατά ένα όριο (σχετικό με το μέγεθος γραμματοσειράς), ξεκινήστε νέα παράγραφο.
- Στοίχιση: Ομαδοποιήστε κατά παρόμοιο left X για αριστερά στοιχισμένες παραγράφους· ανιχνεύστε κεντραρισμένες γραμμές από συμμετρικά περιθώρια· ανιχνεύστε δεξιά στοιχισμένες από τα right edges.
- Στυλ: Διατηρήστε πλάγια/έντονα μέσω `fontStyle`/`fontWeight`; διαφοροποιήστε CSS classes ανά `fontSize` buckets για να προσεγγίσετε headings vs body.
- Συνδέσμοι: Εάν τα runs περιέχουν metadata συνδέσμου (π.χ., `positionId`), παράγετε anchors και εσωτερικά hrefs.

## Αντιμετώπιση τεχνικών anti-scraping σε SVG paths

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Αποφύγετε stroke rendering· εστιάστε σε γεμισμένα solids για να παρακάμψετε hairline artifacts που προκαλούνται από μικρο-σχετικές κινήσεις.
- Κρατήστε σταθερό viewBox ανά render ώστε όμοια σχήματα να rasterize-άρονται συνεπώς σε διάφορα batches.

## Σημειώσεις απόδοσης

- Στην πράξη, τα βιβλία συγκλίνουν σε μερικές εκατοντάδες μοναδικά glyphs (π.χ., ~361 συμπεριλαμβανομένων ligatures). Cache SSIM results by perceptual hash.
- Μετά την αρχική ανακάλυψη, μελλοντικά batches κυρίως επαναχρησιμοποιούν γνωστά hashes· το decoding γίνεται I/O-bound.
- Μέσο SSIM ≈0.95 αποτελεί ισχυρό σήμα· σκεφτείτε να σηματοδοτείτε low-scoring matches για χειροκίνητη ανασκόπηση.

## Γενίκευση σε άλλους viewers

Οποιοδήποτε σύστημα που:
- Επιστρέφει positioned glyph runs με request-scoped numeric IDs
- Στέλνει per-request vector glyphs (SVG paths or subset fonts)
- Περιορίζει σελίδες ανά αίτηση για να αποτρέψει bulk export

…μπορεί να χειριστεί με την ίδια ομαλοποίηση:
- Rasterize per-request shapes → perceptual hash → shape ID
- Atlas of candidate glyphs/ligatures per font variant
- SSIM (or similar perceptual metric) to assign characters
- Reconstruct layout from run rectangles/styles

## Minimal acquisition example (sketch)

Use your browser’s DevTools to capture the exact headers, cookies and tokens used by the reader when requesting `/renderer/render`. Then replicate those from a script or curl. Example outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Προσαρμόστε την παραμετροποίηση (book ASIN, page window, viewport) ώστε να ταιριάζει με τα αιτήματα του αναγνώστη. Αναμένεται όριο 5 σελίδων ανά αίτημα.

## Επιτεύξιμα αποτελέσματα

- Συμπτύξτε 100+ randomized alphabets σε έναν ενιαίο glyph space μέσω perceptual hashing
- Χαρτογράφηση 100% των μοναδικών glyphs με μέση SSIM ~0.95 όταν atlases περιλαμβάνουν ligatures και variants
- Ανακατασκευασμένο EPUB/HTML οπτικά αδιάκριτο από το πρωτότυπο

## Αναφορές

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
