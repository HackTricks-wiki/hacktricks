# Analisi dei glifi SVG/font e deoffuscamento del Web DRM (Raster Hashing + SSIM)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina documenta tecniche pratiche per recuperare testo da lettori web che inviano sequenze di glifi posizionati insieme a definizioni di glifi vettoriali per-request (path SVG) e che randomizzano gli ID dei glifi per ogni request al fine di impedire lo scraping. L'idea principale è ignorare gli ID numerici dei glifi associati alla request e identificare le forme visive tramite raster hashing, quindi mappare le forme ai caratteri con SSIM utilizzando un reference font atlas. Lo stesso approccio può essere generalizzato a viewer con protezioni simili.<sup>[[1]](#references)</sup>

Avviso: usa queste tecniche solo per eseguire il backup di contenuti che possiedi legittimamente e nel rispetto delle leggi e dei termini applicabili.

## Acquisition (esempio: Kindle Cloud Reader)

Endpoint osservato:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiali richiesti per sessione:<sup>[[1]](#references)</sup>
- Cookie della sessione del browser (normale login Amazon)
- Rendering token da una chiamata all'API startReading
- Token di sessione ADP aggiuntivo utilizzato dal renderer

Comportamento:<sup>[[1]](#references)</sup>
- Ogni request, se inviata con header e cookie equivalenti a quelli del browser, restituisce un archivio TAR limitato a 5 pagine.
- Per un libro lungo saranno necessari molti batch; ogni batch utilizza un mapping randomizzato diverso degli ID dei glifi.

Contenuti TAR tipici:<sup>[[1]](#references)</sup>
- page_data_0_4.json — run di testo posizionati come sequenze di ID dei glifi (non Unicode)
- glyphs.json — definizioni dei path SVG per-request per ogni glifo e fontFamily
- toc.json — indice
- metadata.json — metadata del libro
- location_map.json — mapping delle posizioni logiche→visive

Struttura di esempio di un page run:<sup>[[1]](#references)</sup>
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
Esempio di voce glyphs.json:<sup>[[1]](#references)</sup>
```json
{
"24": {"path": "M 450 1480 L 820 1480 L 820 0 L 1050 0 L 1050 1480 ...", "fontFamily": "bookerly_normal"}
}
```
Note sui trucchi relativi ai path anti-scraping:<sup>[[1]](#references)</sup>
- I path possono includere piccoli movimenti relativi (ad es. `m3,1 m1,6 m-4,-7`) che confondono molti parser vettoriali e il campionamento naïve dei path.
- Eseguire sempre il rendering dei path completi riempiti con un motore SVG robusto (ad es. CairoSVG), invece di effettuare differenze tra comandi/coordinate.

## Perché il decoding naïve fallisce

- Sostituzione dei glyph randomizzata per ogni richiesta: la mappatura ID del glyph→carattere cambia a ogni batch; gli ID non hanno significato globale.<sup>[[1]](#references)</sup>
- Il confronto diretto delle coordinate SVG è fragile: forme identiche possono differire nelle coordinate numeriche o nella codifica dei comandi a ogni richiesta.<sup>[[1]](#references)</sup>
- L'OCR su glyph isolati funziona male (≈50%), confonde la punteggiatura e i glyph dall'aspetto simile e ignora le ligature.<sup>[[1]](#references)</sup>

## Pipeline operativa: normalizzazione e mappatura dei glyph indipendenti dalla richiesta

1) Rasterizzare i glyph SVG per ogni richiesta
- Creare un documento SVG minimale per ogni glyph con il `path` fornito ed eseguire il rendering su una canvas di dimensioni fisse (ad es. 512×512) usando CairoSVG o un motore equivalente in grado di gestire sequenze di path complesse.<sup>[[1]](#references)[[2]](#references)</sup>
- Eseguire il rendering con riempimento nero su sfondo bianco; evitare gli stroke per eliminare artefatti dipendenti dal renderer e dall'AA.

2) Hash percettivo per l'identità tra richieste
- Calcolare un hash percettivo (ad es. pHash tramite `imagehash.phash`) per ogni immagine glyph.<sup>[[3]](#references)</sup>
- Trattare l'hash come un ID stabile: la stessa forma visiva tra richieste diverse viene ricondotta allo stesso hash percettivo, neutralizzando gli ID randomizzati.

3) Generazione dell'atlante del font di riferimento
- Scaricare i font TTF/OTF target (ad es. Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Eseguire il rendering dei candidati per A–Z, a–z, 0–9, punteggiatura, simboli speciali (trattini em/en, virgolette) e ligature esplicite: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenere atlanti separati per ogni variante del font (normal/italic/bold/bold-italic).
- Usare un text shaper appropriato (HarfBuzz) se si desidera una fedeltà a livello di glyph per le ligature; la semplice rasterizzazione tramite Pillow ImageFont può essere sufficiente se si esegue direttamente il rendering delle stringhe delle ligature e il motore di shaping le risolve.

4) Matching della similarità visiva con SSIM
- Per ogni immagine glyph sconosciuta, calcolare SSIM (Structural Similarity Index) rispetto a tutte le immagini candidate di tutti gli atlanti delle varianti del font.<sup>[[4]](#references)</sup>
- Assegnare la stringa di caratteri del match con il punteggio migliore. SSIM assorbe meglio le piccole differenze di antialiasing, scala e coordinate rispetto ai confronti pixel-perfect.<sup>[[1]](#references)[[4]](#references)</sup>

5) Gestione dei casi limite e ricostruzione
- Quando un glyph corrisponde a una ligature (con più caratteri), espanderla durante il decoding.<sup>[[1]](#references)</sup>
- Usare i rettangoli delle righe (top/left/right/bottom) per dedurre le interruzioni di paragrafo (delta Y), l'allineamento (pattern X), lo stile e le dimensioni.<sup>[[1]](#references)</sup>
- Serializzare in HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize` e i link interni.<sup>[[1]](#references)</sup>

### Suggerimenti di implementazione

- Normalizzare tutte le immagini alla stessa dimensione e in scala di grigi prima dell'hashing e di SSIM.
- Memorizzare nella cache gli hash percettivi per evitare di ricalcolare SSIM per i glyph ripetuti tra batch.
- Usare una dimensione di rasterizzazione di alta qualità (ad es. 256–512 px) per una migliore discriminazione; ridimensionare secondo necessità prima di SSIM per accelerare l'elaborazione.
- Se si usa Pillow per eseguire il rendering dei candidati TTF, impostare la stessa dimensione della canvas e centrare il glyph; aggiungere padding per evitare il clipping di ascendenti e discendenti.

<details>
<summary>Python: normalizzazione e matching end-to-end dei glyph (hash raster + SSIM)</summary>
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

Il report di origine utilizzava la geometria dei run, i campi di stile e i metadati dei link per preservare la formattazione del documento ricostruito.<sup>[[1]](#references)</sup>

- Interruzioni di paragrafo: se la coordinata Y superiore del run successivo supera la baseline della riga precedente oltre una soglia (relativa alla dimensione del font), inizia un nuovo paragrafo.<sup>[[1]](#references)</sup>
- Allineamento: raggruppa in base a valori X sinistri simili per i paragrafi allineati a sinistra; rileva le righe centrate tramite margini simmetrici; rileva quelle allineate a destra tramite i bordi destri.
- Stile: preserva il corsivo/grassetto tramite `fontStyle`/`fontWeight`; varia le classi CSS in base a intervalli di `fontSize` per approssimare titoli e corpo del testo.
- Link: se i run includono metadati dei link (ad esempio `positionId`), genera ancore e href interni.

## Mitigazione dei path tricks anti-scraping di SVG

- Usa path riempiti con `fill-rule: nonzero` e un renderer appropriato (CairoSVG, resvg). Non fare affidamento sulla normalizzazione dei token dei path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Evita il rendering dei tratti; concentrati sui solidi riempiti per aggirare gli artefatti delle linee sottili causati da micro-spostamenti relativi.
- Mantieni un `viewBox` stabile per ogni render, in modo che forme identiche vengano rasterizzate in modo coerente tra i diversi batch.

## Note sulle performance

- In pratica, i libri convergono verso poche centinaia di glyph unici (ad esempio, circa 361 incluse le ligature). Memorizza nella cache i risultati SSIM tramite perceptual hash.<sup>[[1]](#references)</sup>
- Dopo la discovery iniziale, i batch successivi riutilizzano prevalentemente hash già noti; la decodifica diventa I/O-bound.
- Il report d ha rilevato un SSIM medio di circa 0,95; segnala i match con punteggio basso per una revisione manuale.<sup>[[1]](#references)</sup>

## Generalizzazione ad altri viewer

Il workflow di Kindle suggerisce che viewer simili potrebbero essere compatibili con la stessa normalizzazione quando:<sup>[[1]](#references)</sup>
- restituiscono run di glyph posizionati con ID numerici associati alla richiesta
- inviano glyph vettoriali per richiesta (path SVG o subset font)
- limitano il numero di pagine per richiesta

…possono essere gestiti con la stessa normalizzazione:
- Rasterizza le forme per richiesta → perceptual hash → shape ID
- Crea un atlas di glyph/ligature candidati per ogni variante di font
- Usa SSIM (o una metrica percettiva simile) per assegnare i caratteri
- Ricostruisci il layout a partire dai rettangoli e dagli stili dei run

## Esempio minimo di acquisizione (bozza)

Usa i DevTools del browser per catturare gli header, i cookie e i token esatti utilizzati dal reader quando richiede `/renderer/render`. Poi replicali tramite uno script o curl.<sup>[[1]](#references)</sup> Schema di esempio:
```bash
curl 'https://read.amazon.com/renderer/render' \
-H 'Cookie: session-id=...; at-main=...; sess-at-main=...' \
-H 'x-adp-session: <ADP_SESSION_TOKEN>' \
-H 'authorization: Bearer <RENDERING_TOKEN_FROM_startReading>' \
-H 'User-Agent: <copy from browser>' \
-H 'Accept: application/x-tar' \
--compressed --output batch_000.tar
```
Adatta la parametrizzazione (ASIN del libro, intervallo di pagine, viewport) per adattarla alle richieste del lettore. È previsto un limite massimo di 5 pagine per richiesta.<sup>[[1]](#references)</sup>

## Risultati ottenibili

- Ridurre oltre 100 alfabeti randomizzati a un unico spazio di glifi tramite hashing percettivo.<sup>[[1]](#references)</sup>
- Nel test di 920 pagine, sono stati associati 361 glifi univoci (100%) con uno SSIM medio di 0.9527.<sup>[[1]](#references)</sup>
- Il report originale descrive l'EPUB ricostruito come quasi indistinguibile dall'originale.<sup>[[1]](#references)</sup>

## References

- [1] [Come ho fatto il reverse engineering dell'obfuscation di Kindle Web di Amazon perché la loro app faceva schifo (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – Renderer da SVG a PNG](https://cairosvg.org/)
- [3] [imagehash – Perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – Proprietà di fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – Libreria di rendering SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
