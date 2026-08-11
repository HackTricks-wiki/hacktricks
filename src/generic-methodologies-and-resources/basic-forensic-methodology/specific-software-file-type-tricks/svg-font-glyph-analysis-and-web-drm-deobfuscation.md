# Ανάλυση Glyph SVG/Font και Απο-συσκότιση Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει πρακτικές τεχνικές για την ανάκτηση κειμένου από web readers που αποστέλλουν τοποθετημένα glyph runs μαζί με vector glyph definitions ανά request (SVG paths) και τυχαιοποιούν τα glyph IDs ανά request για την αποτροπή scraping. Η βασική ιδέα είναι να αγνοούνται τα αριθμητικά glyph IDs που ισχύουν μόνο για κάθε request και να γίνεται fingerprinting των οπτικών σχημάτων μέσω raster hashing. Στη συνέχεια, τα σχήματα αντιστοιχίζονται σε χαρακτήρες με SSIM, χρησιμοποιώντας ένα reference font atlas. Η ίδια προσέγγιση μπορεί να γενικευτεί σε viewers με παρόμοιες προστασίες.<sup>[[1]](#references)</sup>

Προειδοποίηση: Χρησιμοποιείτε αυτές τις τεχνικές μόνο για τη δημιουργία αντιγράφων ασφαλείας περιεχομένου που σας ανήκει νόμιμα και σύμφωνα με τους ισχύοντες νόμους και όρους.

## Απόκτηση (παράδειγμα: Kindle Cloud Reader)

Endpoint που παρατηρήθηκε:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Απαιτούμενα στοιχεία ανά session:<sup>[[1]](#references)</sup>
- Browser session cookies (κανονικό Amazon login)
- Rendering token από ένα startReading API call
- Πρόσθετο ADP session token που χρησιμοποιείται από τον renderer

Συμπεριφορά:<sup>[[1]](#references)</sup>
- Κάθε request, όταν αποστέλλεται με headers και cookies ισοδύναμα με του browser, επιστρέφει ένα TAR archive που περιορίζεται σε 5 σελίδες.
- Για ένα μεγάλο βιβλίο θα χρειαστούν πολλά batches· κάθε batch χρησιμοποιεί διαφορετικό randomized mapping των glyph IDs.

Τυπικά περιεχόμενα TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — positioned text runs ως ακολουθίες glyph IDs (όχι Unicode)
- glyphs.json — SVG path definitions ανά request για κάθε glyph και fontFamily
- toc.json — table of contents
- metadata.json — metadata του βιβλίου
- location_map.json — αντιστοιχίσεις logical→visual θέσεων

Παράδειγμα δομής page run:<sup>[[1]](#references)</sup>
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
Παράδειγμα καταχώρισης glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Σημειώσεις για anti-scraping path tricks:<sup>[[1]](#references)</sup>
- Τα Paths μπορεί να περιλαμβάνουν μικροσκοπικές relative μετακινήσεις (π.χ., `m3,1 m1,6 m-4,-7`) που μπερδεύουν πολλούς vector parsers και naïve path sampling.
- Να κάνετε πάντα render σε filled complete paths με έναν robust SVG engine (π.χ. CairoSVG), αντί να κάνετε command/coordinate differencing.

## Γιατί αποτυγχάνει το naïve decoding

- Per-request randomized glyph substitution: το mapping glyph ID→character αλλάζει σε κάθε batch· τα IDs δεν έχουν καθολική σημασία.<sup>[[1]](#references)</sup>
- Η άμεση σύγκριση SVG coordinates είναι brittle: identical shapes μπορεί να διαφέρουν στα numeric coordinates ή στο command encoding ανά request.<sup>[[1]](#references)</sup>
- Το OCR σε isolated glyphs έχει χαμηλή απόδοση (≈50%), συγχέει punctuation και look-alike glyphs και αγνοεί ligatures.<sup>[[1]](#references)</sup>

## Working pipeline: request-agnostic glyph normalization and mapping

1) Rasterize per-request SVG glyphs
- Δημιουργήστε ένα minimal SVG document ανά glyph με το παρεχόμενο `path` και κάντε render σε fixed canvas (π.χ. 512×512) χρησιμοποιώντας CairoSVG ή equivalent engine που χειρίζεται tricky path sequences.<sup>[[1]](#references)[[2]](#references)</sup>
- Κάντε render filled black on white· αποφύγετε τα strokes για να εξαλείψετε renderer- και AA-dependent artifacts.

2) Perceptual hashing για cross-request identity
- Υπολογίστε ένα perceptual hash (π.χ. pHash μέσω `imagehash.phash`) για κάθε glyph image.<sup>[[3]](#references)</sup>
- Αντιμετωπίστε το hash ως stable ID: το ίδιο visual shape σε διαφορετικά requests καταλήγει στο ίδιο perceptual hash, παρακάμπτοντας τα randomized IDs.

3) Reference font atlas generation
- Κατεβάστε τα target TTF/OTF fonts (π.χ. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Κάντε render candidates για A–Z, a–z, 0–9, punctuation, special marks (em/en dashes, quotes) και explicit ligatures: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Διατηρήστε ξεχωριστά atlases ανά font variant (normal/italic/bold/bold-italic).
- Χρησιμοποιήστε proper text shaper (HarfBuzz) αν θέλετε glyph-level fidelity για ligatures· το simple rasterization μέσω Pillow ImageFont μπορεί να είναι επαρκές, εφόσον κάνετε render τα ligature strings απευθείας και το shaping engine τα επιλύει.

4) Visual similarity matching με SSIM
- Για κάθε unknown glyph image, υπολογίστε SSIM (Structural Similarity Index) έναντι όλων των candidate images σε όλα τα font variant atlases.<sup>[[4]](#references)</sup>
- Αντιστοιχίστε το character string του match με το υψηλότερο score. Το SSIM απορροφά μικρές διαφορές στο antialiasing, το scale και τα coordinates καλύτερα από pixel-exact comparisons.<sup>[[1]](#references)[[4]](#references)</sup>

5) Edge handling και reconstruction
- Όταν ένα glyph αντιστοιχεί σε ligature (multi-char), κάντε expand κατά το decoding.<sup>[[1]](#references)</sup>
- Χρησιμοποιήστε run rectangles (top/left/right/bottom) για να συμπεράνετε paragraph breaks (Y deltas), alignment (X patterns), style και sizes.<sup>[[1]](#references)</sup>
- Κάντε serialize σε HTML/EPUB διατηρώντας τα `fontStyle`, `fontWeight`, `fontSize` και τα internal links.<sup>[[1]](#references)</sup>

### Implementation tips

- Κάντε normalize όλες τις images στο ίδιο size και grayscale πριν από το hashing και το SSIM.
- Κάντε cache με βάση το perceptual hash, ώστε να αποφεύγετε τον επανυπολογισμό του SSIM για repeated glyphs σε διαφορετικά batches.
- Χρησιμοποιήστε high-quality raster size (π.χ. 256–512 px) για καλύτερη discrimination· κάντε downscale όπως απαιτείται πριν από το SSIM για επιτάχυνση.
- Αν χρησιμοποιείτε Pillow για το render TTF candidates, ορίστε το ίδιο canvas size και κεντράρετε το glyph· προσθέστε padding για να αποφύγετε το clipping ascenders/descenders.

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

## Ευρετικές ανακατασκευής Layout/EPUB

Το source report χρησιμοποίησε γεωμετρία run, πεδία style και metadata συνδέσμων για να διατηρήσει τη μορφοποίηση του ανακατασκευασμένου εγγράφου.<sup>[[1]](#references)</sup>

- Διακοπές παραγράφων: Αν το top Y του επόμενου run υπερβαίνει το baseline της προηγούμενης γραμμής κατά ένα threshold (σε σχέση με το μέγεθος της γραμματοσειράς), ξεκινήστε νέα παράγραφο.<sup>[[1]](#references)</sup>
- Στοίχιση: Ομαδοποιήστε με βάση παρόμοιο αριστερό X για παραγράφους με αριστερή στοίχιση· εντοπίστε κεντραρισμένες γραμμές μέσω συμμετρικών περιθωρίων· εντοπίστε δεξιά στοίχιση μέσω των δεξιών άκρων.
- Styling: Διατηρήστε το italic/bold μέσω των `fontStyle`/`fontWeight`· διαφοροποιήστε τις CSS classes ανά buckets του `fontSize`, ώστε να προσεγγίσετε τις επικεφαλίδες σε σχέση με το κυρίως σώμα.
- Links: Αν τα runs περιλαμβάνουν metadata συνδέσμων (π.χ. `positionId`), δημιουργήστε anchors και internal hrefs.

## Μετριασμός των SVG anti-scraping τεχνασμάτων με paths

- Χρησιμοποιήστε filled paths με `fill-rule: nonzero` και proper renderer (CairoSVG, resvg). Μην βασίζεστε σε normalization των path tokens.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Αποφύγετε το stroke rendering· επικεντρωθείτε σε filled solids, ώστε να παρακάμψετε τα hairline artifacts που προκαλούνται από micro relative moves.
- Διατηρήστε σταθερό viewBox ανά render, ώστε τα identical shapes να rasterize με συνέπεια μεταξύ batches.

## Σημειώσεις απόδοσης

- Στην πράξη, τα βιβλία συγκλίνουν σε μερικές εκατοντάδες unique glyphs (π.χ. ~361 μαζί με ligatures). Κάντε cache τα αποτελέσματα SSIM μέσω perceptual hash.<sup>[[1]](#references)</sup>
- Μετά την αρχική ανακάλυψη, τα επόμενα batches επαναχρησιμοποιούν κυρίως γνωστά hashes· το decoding γίνεται I/O-bound.
- Το d report παρατήρησε μέσο SSIM περίπου 0.95· επισημάνετε τα matches με χαμηλή βαθμολογία για manual review.<sup>[[1]](#references)</sup>

## Generalization σε άλλους viewers

Το Kindle workflow υποδεικνύει ότι παρόμοιοι viewers μπορεί να είναι συμβατοί με την ίδια normalization όταν:<sup>[[1]](#references)</sup>
- επιστρέφουν positioned glyph runs με request-scoped numeric IDs
- αποστέλλουν per-request vector glyphs (SVG paths ή subset fonts)
- περιορίζουν τον αριθμό σελίδων ανά request

…μπορούν να υποβληθούν σε επεξεργασία με την ίδια normalization:
- Rasterize shapes ανά request → perceptual hash → shape ID
- Atlas υποψήφιων glyphs/ligatures ανά font variant
- SSIM (ή παρόμοιο perceptual metric) για την αντιστοίχιση χαρακτήρων
- Ανακατασκευή του layout από rectangles/styles των runs

## Minimal acquisition example (sketch)

Χρησιμοποιήστε τα DevTools του browser σας για να καταγράψετε τα ακριβή headers, cookies και tokens που χρησιμοποιεί ο reader όταν ζητά το `/renderer/render`. Στη συνέχεια, αναπαράγετε τα από ένα script ή με curl.<sup>[[1]](#references)</sup> Ενδεικτικό outline:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Προσαρμόστε την παραμετροποίηση (book ASIN, page window, viewport) ώστε να ανταποκρίνεται στα αιτήματα του αναγνώστη. Αναμένετε όριο 5 σελίδων ανά request.<sup>[[1]](#references)</sup>

## Αποτελέσματα που μπορούν να επιτευχθούν

- Συγχώνευση 100+ randomized alphabets σε έναν ενιαίο χώρο glyphs μέσω perceptual hashing.<sup>[[1]](#references)</sup>
- Στο d 920-page test, αντιστοιχίστηκαν 361 μοναδικά glyphs (100%) με μέσο SSIM 0.9527.<sup>[[1]](#references)</sup>
- Η αναφορά της πηγής περιγράφει το ανακατασκευασμένο EPUB ως σχεδόν μη διακριτό από το πρωτότυπο.<sup>[[1]](#references)</sup>

## References

- [1] [Πώς αντέστρεψα το Web Obfuscation του Amazon Kindle επειδή η εφαρμογή τους ήταν χάλια (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG σε PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Ιδιότητες fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – SVG rendering library](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
