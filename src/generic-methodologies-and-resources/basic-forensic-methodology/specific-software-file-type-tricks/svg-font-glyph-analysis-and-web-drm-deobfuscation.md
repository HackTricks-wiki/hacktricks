# Analisi dei glifi SVG/Font e deobfuscation del Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina documenta tecniche pratiche per recuperare testo da web reader che inviano sequenze di glifi posizionati insieme a definizioni di glifi vettoriali per richiesta (percorsi SVG) e che randomizzano gli ID dei glifi a ogni richiesta per impedire lo scraping. L'idea centrale è ignorare gli ID numerici dei glifi specifici della richiesta e identificare le forme visive tramite raster hashing, quindi associare le forme ai caratteri usando SSIM rispetto a un reference font atlas. Il workflow è generalizzabile oltre Kindle Cloud Reader a qualsiasi viewer con protezioni simili.<sup>[[1]](#references)</sup>

Avviso: usa queste tecniche solo per eseguire il backup di contenuti che possiedi legittimamente e nel rispetto delle leggi e dei termini applicabili.

## Acquisition (esempio: Kindle Cloud Reader)

Endpoint osservato:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiali richiesti per sessione:
- Cookie della sessione del browser (normale login Amazon)
- Rendering token ottenuto da una chiamata all'API startReading
- Token di sessione ADP aggiuntivo usato dal renderer

Comportamento:
- Ogni richiesta, quando viene inviata con header e cookie equivalenti a quelli del browser, restituisce un archivio TAR limitato a 5 pagine.
- Per un libro lungo saranno necessari molti batch; ogni batch usa una diversa mappatura randomizzata degli ID dei glifi.

Contenuto tipico del TAR:
- page_data_0_4.json — sequenze di testo posizionato sotto forma di ID dei glifi (non Unicode)
- glyphs.json — definizioni dei percorsi SVG per ogni glifo e fontFamily, specifiche per la richiesta
- toc.json — indice
- metadata.json — metadata del libro
- location_map.json — mappature da posizione logica a visiva

Struttura di esempio di un page run:
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
Esempio di voce glyphs.json:
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Note sui trucchi dei path anti-scraping:
- I path possono includere micro-spostamenti relativi (ad es. `m3,1 m1,6 m-4,-7`) che confondono molti parser vettoriali e il campionamento naïve dei path.
- Eseguire sempre il rendering dei path completi riempiti con un motore SVG robusto (ad es. CairoSVG), invece di eseguire differenze tra comandi/coordinate.

## Perché il decoding naïve fallisce

- Sostituzione dei glyph randomizzata per ogni richiesta: la mappatura glyph ID→carattere cambia a ogni batch; gli ID non hanno significato globale.<sup>[[1]](#references)</sup>
- Il confronto diretto delle coordinate SVG è fragile: forme identiche possono differire nelle coordinate numeriche o nella codifica dei comandi a ogni richiesta.
- L'OCR su glyph isolati funziona male (≈50%), confonde la punteggiatura e i glyph simili e ignora le ligature.

## Pipeline operativa: normalizzazione e mapping dei glyph indipendenti dalla richiesta

1) Rasterizzare i glyph SVG per ogni richiesta
- Creare un documento SVG minimale per ogni glyph con il `path` fornito e renderizzarlo su un canvas di dimensioni fisse (ad es. 512×512) usando CairoSVG o un motore equivalente che gestisca sequenze di path problematiche.<sup>[[1]](#references)[[2]](#references)</sup>
- Eseguire il rendering con riempimento nero su sfondo bianco; evitare gli stroke per eliminare artefatti dipendenti dal renderer e dall'AA.

2) Perceptual hashing per l'identità cross-request
- Calcolare un perceptual hash (ad es. pHash tramite `imagehash.phash`) per ogni immagine glyph.<sup>[[3]](#references)</sup>
- Trattare l'hash come un ID stabile: la stessa forma visiva tra richieste diverse viene ricondotta allo stesso perceptual hash, neutralizzando gli ID randomizzati.

3) Generazione di un reference font atlas
- Scaricare i font TTF/OTF target (ad es. Bookerly normal/italic/bold/bold-italic).
- Eseguire il rendering dei candidati per A–Z, a–z, 0–9, punteggiatura, caratteri speciali (em/en dash, virgolette) e ligature esplicite: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenere atlas separati per ogni variante del font (normal/italic/bold/bold-italic).
- Usare un text shaper appropriato (HarfBuzz) se si desidera una fedeltà a livello di glyph per le ligature; la semplice rasterizzazione tramite Pillow ImageFont può essere sufficiente se si eseguono direttamente il rendering delle stringhe delle ligature e lo shaping engine le risolve.

4) Matching della similarità visiva con SSIM
- Per ogni immagine glyph sconosciuta, calcolare SSIM (Structural Similarity Index) rispetto a tutte le immagini candidate presenti negli atlas di tutte le varianti del font.<sup>[[4]](#references)</sup>
- Assegnare la stringa di caratteri del candidato con il punteggio migliore. SSIM assorbe meglio dei confronti pixel-exact le piccole differenze di antialiasing, scala e coordinate.

5) Gestione dei bordi e ricostruzione
- Quando un glyph corrisponde a una ligature (multi-char), espanderlo durante il decoding.
- Usare i rettangoli delle righe (top/left/right/bottom) per dedurre le interruzioni di paragrafo (delta Y), l'allineamento (pattern X), lo stile e le dimensioni.
- Serializzare in HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize` e i link interni.

### Suggerimenti per l'implementazione

- Normalizzare tutte le immagini alle stesse dimensioni e in scala di grigi prima dell'hashing e del calcolo SSIM.
- Usare una cache basata sul perceptual hash per evitare di ricalcolare SSIM per glyph ripetuti tra batch.
- Usare una dimensione di rasterizzazione di alta qualità (ad es. 256–512 px) per una discriminazione migliore; ridimensionare secondo necessità prima di SSIM per accelerare l'elaborazione.
- Se si usa Pillow per renderizzare candidati TTF, impostare le stesse dimensioni del canvas e centrare il glyph; aggiungere padding per evitare di tagliare ascendenti/discendenti.

<details>
<summary>Python: normalizzazione e matching end-to-end dei glyph (raster hash + SSIM)</summary>
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

## Euristiche per la ricostruzione del layout/EPUB

- Interruzioni di paragrafo: se il valore Y superiore del run successivo supera la baseline della riga precedente di una soglia (relativa alla dimensione del font), inizia un nuovo paragrafo.<sup>[[1]](#references)</sup>
- Allineamento: raggruppa in base a valori X sinistri simili per i paragrafi allineati a sinistra; rileva le righe centrate tramite margini simmetrici; rileva quelle allineate a destra tramite i bordi destri.
- Stile: preserva il corsivo/grassetto tramite `fontStyle`/`fontWeight`; varia le classi CSS in base a fasce di `fontSize` per approssimare titoli e corpo del testo.
- Link: se i run includono metadati dei link (ad esempio `positionId`), emetti ancore e href interni.

## Mitigazione dei path trick anti-scraping SVG

- Usa path riempiti con `fill-rule: nonzero` e un renderer appropriato (CairoSVG, resvg). Non fare affidamento sulla normalizzazione dei token dei path.<sup>[[1]](#references)</sup>
- Evita il rendering dei tratti; concentrati sui solidi riempiti per aggirare gli artefatti delle linee sottili causati da micro-movimenti relativi.
- Mantieni un `viewBox` stabile per ogni render, in modo che forme identiche vengano rasterizzate in modo coerente tra i batch.

## Note sulle performance

- Nella pratica, i libri convergono verso poche centinaia di glyph unici (ad esempio, ~361 incluse le ligature). Memorizza nella cache i risultati SSIM tramite hash percettivo.<sup>[[1]](#references)</sup>
- Dopo la fase iniziale di discovery, i batch successivi riutilizzano principalmente hash già noti; la decodifica diventa I/O-bound.
- Un SSIM medio ≈0.95 è un segnale forte; valuta la possibilità di contrassegnare i match con punteggi bassi per una revisione manuale.

## Generalizzazione ad altri viewer

Qualsiasi sistema che:<sup>[[1]](#references)</sup>
- Restituisce run di glyph posizionati con ID numerici associati alla richiesta
- Invia glyph vettoriali per richiesta (path SVG o subset font)
- Limita il numero di pagine per richiesta per impedire l'esportazione in massa

…può essere gestito con la stessa normalizzazione:
- Rasterizza le forme per richiesta → hash percettivo → ID della forma
- Atlas di glyph/ligature candidate per variante di font
- SSIM (o una metrica percettiva simile) per assegnare i caratteri
- Ricostruisci il layout dai rettangoli/stili dei run

## Esempio minimo di acquisizione (bozza)

Usa i DevTools del browser per acquisire gli header, i cookie e i token esatti utilizzati dal reader quando richiede `/renderer/render`. Poi replicali tramite uno script o curl.<sup>[[1]](#references)</sup> Schema di esempio:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Adatta la parameterization (ASIN del book, intervallo di pagine, viewport) alle richieste del lettore. Considera un limite di 5 pagine per request.

## Risultati ottenibili

- Riduzione di oltre 100 alfabeti randomizzati a un unico spazio di glifi tramite perceptual hashing<sup>[[1]](#references)</sup>
- Mapping del 100% dei glifi univoci con SSIM medio di circa 0,95 quando gli atlanti includono ligature e varianti
- EPUB/HTML ricostruito visivamente indistinguibile dall’originale

## References

- [1] [Kindle Web DRM: Breaking Randomized SVG Glyph Obfuscation with Raster Hashing + SSIM (Pixelmelt blog)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – SVG to PNG renderer](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)

{{#include ../../../banners/hacktricks-training.md}}
