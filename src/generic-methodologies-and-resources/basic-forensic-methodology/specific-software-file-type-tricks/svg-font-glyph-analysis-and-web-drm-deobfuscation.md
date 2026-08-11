# Analyse des glyphes SVG/polices et désobfuscation du DRM Web (hachage raster + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Cette page documente des techniques pratiques pour récupérer du texte à partir de lecteurs Web qui fournissent des séquences de glyphes positionnées ainsi que des définitions de glyphes vectoriels (chemins SVG) par requête, et qui randomisent les identifiants de glyphes à chaque requête afin d'empêcher le scraping. L'idée principale consiste à ignorer les identifiants numériques des glyphes associés à la requête et à identifier les formes visuelles via un hachage raster, puis à associer les formes aux caractères avec SSIM par comparaison à un atlas de police de référence. Cette approche peut également s'appliquer à des viewers dotés de protections similaires.<sup>[[1]](#references)</sup>

Avertissement : utilisez ces techniques uniquement pour sauvegarder du contenu que vous possédez légitimement et conformément aux lois et conditions applicables.

## Acquisition (exemple : Kindle Cloud Reader)

Endpoint observé :<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Éléments requis par session :<sup>[[1]](#references)</sup>
- Cookies de session du navigateur (connexion Amazon normale)
- Rendering token provenant d'un appel à l'API startReading
- Additional ADP session token utilisé par le renderer

Comportement :<sup>[[1]](#references)</sup>
- Chaque requête, lorsqu'elle est envoyée avec des headers et cookies équivalents à ceux du navigateur, renvoie une archive TAR limitée à 5 pages.
- Pour un livre volumineux, vous aurez besoin de nombreux batches ; chaque batch utilise un mapping randomisé différent des identifiants de glyphes.

Contenu typique d'une archive TAR :<sup>[[1]](#references)</sup>
- page_data_0_4.json — séquences de texte positionnées sous forme de séquences d'identifiants de glyphes (pas d'Unicode)
- glyphs.json — définitions de chemins SVG par requête pour chaque glyphe et fontFamily
- toc.json — table des matières
- metadata.json — métadonnées du livre
- location_map.json — mappings de position logique→visuelle

Structure d'un run de page type :<sup>[[1]](#references)</sup>
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
Exemple d’entrée glyphs.json :<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Notes sur les techniques de chemins anti-scraping :<sup>[[1]](#references)</sup>
- Les chemins peuvent inclure de petits déplacements relatifs (p. ex., `m3,1 m1,6 m-4,-7`) qui perturbent de nombreux parseurs vectoriels et l'échantillonnage naïf des chemins.
- Effectuez toujours le rendu des chemins remplis complets avec un moteur SVG robuste (p. ex., CairoSVG) au lieu d'effectuer des différences entre commandes/coordonnées.

## Pourquoi le décodage naïf échoue

- Substitution de glyphes randomisée pour chaque requête : la correspondance ID de glyphe→caractère change à chaque batch ; les ID n'ont aucune signification globale.<sup>[[1]](#references)</sup>
- La comparaison directe des coordonnées SVG est fragile : des formes identiques peuvent différer au niveau des coordonnées numériques ou de l'encodage des commandes d'une requête à l'autre.<sup>[[1]](#references)</sup>
- L'OCR sur des glyphes isolés donne de mauvais résultats (≈50 %), confond la ponctuation et les glyphes ressemblants, et ignore les ligatures.<sup>[[1]](#references)</sup>

## Pipeline fonctionnel : normalisation et mapping de glyphes indépendant des requêtes

1) Rasteriser les glyphes SVG pour chaque requête
- Construisez un document SVG minimal par glyphe avec le `path` fourni et effectuez le rendu sur une canvas fixe (p. ex., 512×512) avec CairoSVG ou un moteur équivalent capable de gérer les séquences de chemins complexes.<sup>[[1]](#references)[[2]](#references)</sup>
- Effectuez le rendu en noir rempli sur fond blanc ; évitez les contours afin d'éliminer les artefacts dépendant du renderer et de l'anti-aliasing.

2) Perceptual hashing pour l'identité inter-requêtes
- Calculez un perceptual hash (p. ex., pHash via `imagehash.phash`) pour chaque image de glyphe.<sup>[[3]](#references)</sup>
- Traitez le hash comme un ID stable : la même forme visuelle entre différentes requêtes produit le même perceptual hash, ce qui neutralise les ID randomisés.

3) Génération de l'atlas de la font de référence
- Téléchargez les fonts TTF/OTF cibles (p. ex., Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Effectuez le rendu des candidats pour A–Z, a–z, 0–9, la ponctuation, les signes spéciaux (tirets em/en, guillemets) et les ligatures explicites : `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Conservez des atlas séparés pour chaque variante de font (normal/italic/bold/bold-italic).
- Utilisez un text shaper approprié (HarfBuzz) si vous voulez une fidélité au niveau des glyphes pour les ligatures ; une rasterisation simple via Pillow ImageFont peut suffire si vous effectuez directement le rendu des chaînes de ligatures et que le moteur de shaping les résout.

4) Matching par similarité visuelle avec SSIM
- Pour chaque image de glyphe inconnue, calculez le SSIM (Structural Similarity Index) avec toutes les images candidates de tous les atlas de variantes de fonts.<sup>[[4]](#references)</sup>
- Attribuez la chaîne de caractères du meilleur résultat. SSIM absorbe mieux les petites différences d'anti-aliasing, d'échelle et de coordonnées que les comparaisons exactes au niveau des pixels.<sup>[[1]](#references)[[4]](#references)</sup>

5) Gestion des cas particuliers et reconstruction
- Lorsqu'un glyphe correspond à une ligature (plusieurs caractères), développez-la pendant le décodage.<sup>[[1]](#references)</sup>
- Utilisez les rectangles d'exécution (haut/gauche/droite/bas) pour déduire les sauts de paragraphe (deltas Y), l'alignement (motifs X), le style et les tailles.<sup>[[1]](#references)</sup>
- Sérialisez en HTML/EPUB en préservant `fontStyle`, `fontWeight`, `fontSize` et les liens internes.<sup>[[1]](#references)</sup>

### Conseils d'implémentation

- Normalisez toutes les images à la même taille et en niveaux de gris avant le hashing et le SSIM.
- Mettez en cache par perceptual hash afin d'éviter de recalculer le SSIM pour les glyphes répétés entre les batches.
- Utilisez une taille de rasterisation élevée (p. ex., 256–512 px) pour une meilleure discrimination ; réduisez-la si nécessaire avant le SSIM afin d'accélérer le traitement.
- Si vous utilisez Pillow pour effectuer le rendu des candidats TTF, définissez la même taille de canvas et centrez le glyphe ; ajoutez des marges pour éviter de tronquer les ascendantes et les descendantes.

<details>
<summary>Python : normalisation et matching de glyphes de bout en bout (raster hash + SSIM)</summary>
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

Le rapport source utilisait la géométrie des séquences, les champs de style et les métadonnées des liens pour préserver le formatage du document reconstruit.<sup>[[1]](#references)</sup>

- Sauts de paragraphe : Si la coordonnée Y supérieure de la séquence suivante dépasse la ligne de base de la ligne précédente selon un seuil (relatif à la taille de la police), commencer un nouveau paragraphe.<sup>[[1]](#references)</sup>
- Alignement : Regrouper selon des coordonnées X gauches similaires pour les paragraphes alignés à gauche ; détecter les lignes centrées grâce à des marges symétriques ; détecter les éléments alignés à droite à partir de leurs bords droits.
- Style : Préserver l’italique et le gras via `fontStyle`/`fontWeight` ; faire varier les classes CSS selon des catégories de `fontSize` afin d’approximer les titres et le corps du texte.
- Liens : Si les séquences incluent des métadonnées de lien (par ex. `positionId`), générer des ancres et des hrefs internes.

## Atténuation des techniques anti-scraping basées sur les chemins SVG

- Utiliser des chemins remplis avec `fill-rule: nonzero` et un renderer approprié (CairoSVG, resvg). Ne pas dépendre de la normalisation des tokens de chemin.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Éviter le rendu des contours ; privilégier les formes pleines afin d’éviter les artefacts de lignes fines causés par les micro-déplacements relatifs.
- Conserver un viewBox stable pour chaque rendu afin que les formes identiques soient rasterisées de manière cohérente entre les lots.

## Notes de performance

- En pratique, les livres convergent vers quelques centaines de glyphes uniques (par ex. environ 361, ligatures comprises). Mettre en cache les résultats SSIM à l’aide d’un hash perceptuel.<sup>[[1]](#references)</sup>
- Après la découverte initiale, les lots suivants réutilisent principalement les hashes connus ; le décodage devient limité par les E/S.
- Le rapport d a observé un SSIM moyen d’environ 0,95 ; signaler les correspondances ayant un score faible pour une vérification manuelle.<sup>[[1]](#references)</sup>

## Généralisation à d’autres viewers

Le workflow Kindle suggère que des viewers similaires pourraient se prêter à la même normalisation lorsqu’ils :<sup>[[1]](#references)</sup>
- renvoient des séquences de glyphes positionnées avec des IDs numériques associés à la requête
- fournissent des glyphes vectoriels par requête (chemins SVG ou subset fonts)
- limitent le nombre de pages par requête

…peuvent être traités avec la même normalisation :
- Rasteriser les formes par requête → hash perceptuel → ID de forme
- Atlas de glyphes/ligatures candidates par variante de police
- SSIM (ou métrique perceptuelle similaire) pour attribuer les caractères
- Reconstruire la mise en page à partir des rectangles/styles des séquences

## Exemple minimal d’acquisition (ébauche)

Utiliser les DevTools de votre navigateur pour capturer les headers, cookies et tokens exacts utilisés par le reader lors de la requête vers `/renderer/render`. Puis les reproduire depuis un script ou avec curl.<sup>[[1]](#references)</sup> Exemple de structure :
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Ajustez la paramétrisation (ASIN du livre, fenêtre de pages, viewport) pour l’adapter aux demandes du lecteur. Prévoyez une limite de 5 pages par requête.<sup>[[1]](#references)</sup>

## Résultats obtenables

- Réduire plus de 100 alphabets randomisés à un seul espace de glyphes via le perceptual hashing.<sup>[[1]](#references)</sup>
- Lors du test de 920 pages, 361 glyphes uniques ont été mis en correspondance (100 %), avec un SSIM moyen de 0,9527.<sup>[[1]](#references)</sup>
- Le rapport source décrit l’EPUB reconstruit comme quasiment indistinguable de l’original.<sup>[[1]](#references)</sup>

## References

- [1] [Comment j’ai inversé l’obfuscation Web de Kindle d’Amazon parce que leur application était nulle (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderer SVG vers PNG](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – propriétés fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – bibliothèque de rendu SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
