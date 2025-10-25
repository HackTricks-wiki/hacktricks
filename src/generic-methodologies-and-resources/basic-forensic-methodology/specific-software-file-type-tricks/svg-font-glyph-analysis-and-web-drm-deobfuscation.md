# SVG/Font Glyph Analysis & Web DRM Deobfuscation (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Cette page documente des techniques pratiques pour récupérer du texte à partir de web readers qui livrent des positioned glyph runs ainsi que des définitions vectorielles de glyphes par requête (SVG paths), et qui randomisent les glyph IDs à chaque requête pour empêcher le scraping. L'idée centrale est d'ignorer les glyph IDs numériques spécifiques à la requête et de générer une empreinte des formes visuelles via raster hashing, puis d'associer les formes aux caractères avec SSIM en les comparant à une atlas de polices de référence. Le workflow se généralise au-delà de Kindle Cloud Reader à tout viewer présentant des protections similaires.

Warning: Only use these techniques to back up content you legitimately own and in compliance with applicable laws and terms.

## Acquisition (example: Kindle Cloud Reader)

Endpoint observed:
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Required materials per session:
- Cookies de session du navigateur (connexion Amazon normale)
- Rendering token provenant d'un appel API startReading
- Token de session ADP additionnel utilisé par le renderer

Behavior:
- Chaque requête, lorsqu'elle est envoyée avec des en-têtes et cookies équivalents à un navigateur, renvoie une archive TAR limitée à 5 pages.
- Pour un livre long vous aurez besoin de nombreuses séries ; chaque série utilise un mapping aléatoire différent des glyph IDs.

Typical TAR contents:
- page_data_0_4.json — runs de texte positionnés comme séquences de glyph IDs (pas Unicode)
- glyphs.json — définitions de SVG paths par requête pour chaque glyph et fontFamily
- toc.json — table des matières
- metadata.json — métadonnées du livre
- location_map.json — correspondances positionnelles logical→visual

Exemple de structure de run de page:
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
Exemple d'entrée glyphs.json :
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes sur les astuces anti-scraping de chemins :
- Les chemins peuvent inclure de micro-mouvements relatifs (par ex., `m3,1 m1,6 m-4,-7`) qui perturbent de nombreux analyseurs vectoriels et les échantillonnages naïfs de chemins.
- Toujours rendre les chemins complets remplis avec un moteur SVG robuste (p.ex., CairoSVG) au lieu de faire des différences commandes/coordonnées.

## Pourquoi un décodage naïf échoue

- Per-request randomized glyph substitution: le mapping glyph ID→caractère change à chaque lot ; les IDs sont dénués de sens globalement.
- La comparaison directe des coordonnées SVG est fragile : des formes identiques peuvent différer dans les coordonnées numériques ou l'encodage des commandes selon la requête.
- L'OCR sur glyphes isolés est médiocre (≈50%), confond la ponctuation et les glyphes ressemblants, et ignore les ligatures.

## Pipeline de travail : normalisation et mappage des glyphes indépendants de la requête

1) Rasteriser les glyphes SVG par requête
- Construire un document SVG minimal par glyphe avec le `path` fourni et rendre sur un canevas fixe (p.ex., `512×512`) en utilisant CairoSVG ou un moteur équivalent qui gère les séquences de path complexes.
- Rendre en rempli noir sur fond blanc ; éviter les strokes pour éliminer les artefacts dépendants du moteur et de l'AA.

2) Hachage perceptuel pour l'identité inter-requêtes
- Calculer un hachage perceptuel (p.ex., pHash via `imagehash.phash`) de chaque image de glyphe.
- Traiter le hash comme un ID stable : la même forme visuelle entre requêtes se réduit au même hachage perceptuel, contrant les IDs randomisés.

3) Génération d'un atlas de polices de référence
- Télécharger les polices cibles TTF/OTF (p.ex., Bookerly normal/italic/bold/bold-italic).
- Rendre des candidats pour A–Z, a–z, 0–9, ponctuation, signes spéciaux (tirets em/en, guillemets), et ligatures explicites : `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Conserver des atlas séparés par variante de police (normal/italic/bold/bold-italic).
- Utiliser un proper text shaper (HarfBuzz) si vous voulez une fidélité au niveau glyphe pour les ligatures ; une rasterisation simple via Pillow ImageFont peut suffire si vous rendez directement les chaînes de ligature et que le moteur de shaping les résout.

4) Appariement par similarité visuelle avec SSIM
- Pour chaque image de glyphe inconnue, calculer SSIM (Structural Similarity Index) contre toutes les images candidates à travers tous les atlas de variantes de police.
- Assigner la chaîne de caractères du meilleur score. SSIM absorbe mieux les petites différences d'antialiasing, d'échelle et de coordonnées que les comparaisons pixel-exactes.

5) Gestion des bords et reconstruction
- Quand un glyphe se mappe à une ligature (multi-char), l'étendre lors du décodage.
- Utiliser des run rectangles (top/left/right/bottom) pour inférer les sauts de paragraphe (deltas en Y), l'alignement (patterns en X), le style et les tailles.
- Sérialiser en HTML/EPUB en préservant `fontStyle`, `fontWeight`, `fontSize` et les liens internes.

### Conseils d'implémentation

- Normaliser toutes les images à la même taille et en niveaux de gris avant le hashing et le calcul de SSIM.
- Mettre en cache par hachage perceptuel pour éviter de recomputer le SSIM pour des glyphes répétés entre lots.
- Utiliser une taille de raster de haute qualité (p.ex., `256–512 px`) pour une meilleure discrimination ; réduire l'échelle si nécessaire avant SSIM pour accélérer.
- Si vous utilisez Pillow pour rendre des candidats TTF, définir la même taille de canevas et centrer le glyphe ; ajouter du padding pour éviter le clipping des ascendantes/descendantes.

<details>
<summary>Python : normalisation et appariement des glyphes de bout en bout (raster hash + SSIM)</summary>
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

## Heuristiques de reconstruction de la mise en page/EPUB

- Paragraph breaks: If the next run’s top Y exceeds the previous line’s baseline by a threshold (relative to font size), start a new paragraph.
- Alignment: Group by similar left X for left-aligned paragraphs; detect centered lines by symmetric margins; detect right-aligned by right edges.
- Styling: Preserve italic/bold via `fontStyle`/`fontWeight`; vary CSS classes by `fontSize` buckets to approximate headings vs body.
- Links: If runs include link metadata (e.g., `positionId`), emit anchors and internal hrefs.

## Mitigating SVG anti-scraping path tricks

- Use filled paths with `fill-rule: nonzero` and a proper renderer (CairoSVG, resvg). Do not rely on path token normalization.
- Avoid stroke rendering; focus on filled solids to sidestep hairline artifacts caused by micro relative moves.
- Keep a stable viewBox per render so that identical shapes rasterize consistently across batches.

## Notes de performance

- En pratique, les livres convergent vers quelques centaines de glyphes uniques (p.ex., ~361 incluant les ligatures). Cachez les résultats SSIM par hachage perceptuel.
- After initial discovery, future batches predominantly re-use known hashes; decoding becomes I/O-bound.
- Average SSIM ≈0.95 is a strong signal; consider flagging low-scoring matches for manual review.

## Généralisation à d'autres visualiseurs

Tout système qui :
- Retourne des runs de glyphes positionnés avec des IDs numériques limités à la requête
- Fournit des glyphes vectoriels par requête (SVG paths or subset fonts)
- Caps pages per request to prevent bulk export

…peuvent être traités avec la même normalisation :
- Rasteriser les formes par requête → hachage perceptuel → ID de forme
- Atlas des glyphes/ligatures candidats par variante de police
- SSIM (ou métrique perceptuelle similaire) pour assigner des caractères
- Reconstruire la mise en page à partir des rectangles/styles des runs

## Exemple d'acquisition minimal (esquisse)

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
Ajustez la paramétrisation (ASIN du livre, fenêtre de pages, viewport) pour correspondre aux demandes du lecteur. Prévoyez une limite de 5 pages par requête.

## Résultats réalisables

- Regrouper plus de 100 alphabets aléatoires en un seul espace de glyphes via perceptual hashing
- Cartographie à 100% des glyphes uniques avec un SSIM moyen ~0.95 lorsque les atlas incluent des ligatures et des variantes
- EPUB/HTML reconstruit visuellement indiscernable de l'original

## Références

- [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
