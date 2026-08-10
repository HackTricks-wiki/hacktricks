# Analisi dei glifi SVG/Font e deobfuscation del DRM web (Raster Hashing + SSIM)

Questa pagina documenta tecniche pratiche per recuperare testo da web reader che distribuiscono sequenze di glifi posizionati insieme a definizioni di glifi vettoriali (path SVG) per ogni richiesta e che randomizzano gli ID dei glifi per ogni richiesta, impedendo lo scraping. L'idea principale è ignorare gli ID numerici dei glifi specifici della richiesta e identificare le forme visive tramite raster hashing, quindi associare le forme ai caratteri usando SSIM rispetto a un reference font atlas. Lo stesso approccio può essere applicabile a viewer con protezioni simili.<sup>[[1]](#references)</sup>

Avvertenza: usa queste tecniche solo per eseguire il backup di contenuti che possiedi legittimamente e nel rispetto delle leggi e dei termini applicabili.

## Acquisition (esempio: Kindle Cloud Reader)

Endpoint osservato:<sup>[[1]](#references)</sup>
- [https://read.amazon.com/renderer/render](https://read.amazon.com/renderer/render)

Materiali richiesti per sessione:<sup>[[1]](#references)</sup>
- Cookie della sessione del browser (normale login Amazon)
- Rendering token ottenuto da una chiamata all'API startReading
- Token di sessione ADP aggiuntivo utilizzato dal renderer

Comportamento:<sup>[[1]](#references)</sup>
- Ogni richiesta, quando viene inviata con headers e cookie equivalenti a quelli del browser, restituisce un archivio TAR limitato a 5 pagine.
- Per un libro lungo saranno necessari molti batch; ogni batch utilizza un mapping randomizzato diverso degli ID dei glifi.

Contenuto tipico del TAR:<sup>[[1]](#references)</sup>
- page_data_0_4.json — run di testo posizionati come sequenze di ID dei glifi (non Unicode)
- glyphs.json — definizioni dei path SVG per ogni glifo e fontFamily, specifiche per la richiesta
- toc.json — table of contents
- metadata.json — metadati del libro
- location_map.json — mapping delle posizioni logical→visual

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
Note sui trucchi anti-scraping dei percorsi:<sup>[[1]](#references)</sup>
- I percorsi possono includere micro-spostamenti relativi (ad esempio, `m3,1 m1,6 m-4,-7`) che confondono molti parser vettoriali e il campionamento ingenuo dei percorsi.
- Eseguire sempre il rendering dei percorsi completi riempiti con un motore SVG robusto (ad esempio, CairoSVG), invece di effettuare differenze tra comandi/coordinate.

## Perché la decodifica ingenua non funziona

- Sostituzione dei glifi randomizzata per richiesta: la mappatura ID glifo→carattere cambia a ogni batch; gli ID non hanno un significato globale.<sup>[[1]](#references)</sup>
- Il confronto diretto delle coordinate SVG è fragile: forme identiche possono differire nelle coordinate numeriche o nella codifica dei comandi a ogni richiesta.<sup>[[1]](#references)</sup>
- L'OCR su glifi isolati funziona male (≈50%), confonde la punteggiatura e i glifi simili e ignora le legature.<sup>[[1]](#references)</sup>

## Pipeline operativa: normalizzazione e mappatura dei glifi indipendente dalla richiesta

1) Rasterizzare i glifi SVG per richiesta
- Creare un documento SVG minimo per ogni glifo con il `path` fornito e renderizzarlo su una canvas di dimensioni fisse (ad esempio, 512×512) usando CairoSVG o un motore equivalente che gestisca sequenze di percorsi problematiche.<sup>[[1]](#references)[[2]](#references)</sup>
- Renderizzare il glifo nero pieno su sfondo bianco; evitare i tratti per eliminare gli artefatti dipendenti dal renderer e dall'AA.

2) Hash percettivo per l'identità tra richieste
- Calcolare un hash percettivo (ad esempio, pHash tramite `imagehash.phash`) per ogni immagine del glifo.<sup>[[3]](#references)</sup>
- Trattare l'hash come un ID stabile: la stessa forma visiva tra richieste diverse viene ricondotta allo stesso hash percettivo, vanificando gli ID randomizzati.

3) Generazione dell'atlante del font di riferimento
- Scaricare i font TTF/OTF target (ad esempio, Bookerly normal/italic/bold/bold-italic).<sup>[[1]](#references)</sup>
- Eseguire il rendering dei candidati per A–Z, a–z, 0–9, punteggiatura, segni speciali (trattini em/en, virgolette) e legature esplicite: `ff`, `fi`, `fl`, `ffi`, `ffl`.
- Mantenere atlanti separati per ogni variante del font (normal/italic/bold/bold-italic).
- Usare un text shaper appropriato (HarfBuzz) per ottenere una fedeltà a livello di glifo per le legature; la semplice rasterizzazione tramite Pillow ImageFont può essere sufficiente se si esegue direttamente il rendering delle stringhe delle legature e il motore di shaping le risolve.

4) Matching della similarità visiva con SSIM
- Per ogni immagine di glifo sconosciuta, calcolare SSIM (Structural Similarity Index) rispetto a tutte le immagini candidate in tutti gli atlanti delle varianti del font.<sup>[[4]](#references)</sup>
- Assegnare la stringa di caratteri della corrispondenza con il punteggio migliore. SSIM assorbe meglio dei confronti pixel-perfect le piccole differenze di antialiasing, scala e coordinate.<sup>[[1]](#references)[[4]](#references)</sup>

5) Gestione dei casi limite e ricostruzione
- Quando un glifo corrisponde a una legatura (multi-carattere), espanderla durante la decodifica.<sup>[[1]](#references)</sup>
- Usare i rettangoli delle righe (top/left/right/bottom) per dedurre le interruzioni di paragrafo (delta Y), l'allineamento (pattern X), lo stile e le dimensioni.<sup>[[1]](#references)</sup>
- Serializzare in HTML/EPUB preservando `fontStyle`, `fontWeight`, `fontSize` e i link interni.<sup>[[1]](#references)</sup>

### Suggerimenti per l'implementazione

- Normalizzare tutte le immagini alla stessa dimensione e in scala di grigi prima dell'hashing e di SSIM.
- Eseguire il caching tramite hash percettivo per evitare di ricalcolare SSIM per i glifi ripetuti tra batch.
- Usare una dimensione di rasterizzazione di alta qualità (ad esempio, 256–512 px) per una migliore discriminazione; ridimensionare secondo necessità prima di SSIM per accelerare l'elaborazione.
- Se si usa Pillow per il rendering dei candidati TTF, impostare la stessa dimensione della canvas e centrare il glifo; aggiungere padding per evitare il ritaglio di ascendenti/discendenti.

<details>
<summary>Python: normalizzazione e matching end-to-end dei glifi (hash raster + SSIM)</summary>
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

Il report di origine utilizzava la geometria dei run, i campi di stile e i metadata dei link per preservare la formattazione del documento ricostruito.<sup>[[1]](#references)</sup>

- Interruzioni di paragrafo: se la coordinata Y superiore del run successivo supera la baseline della riga precedente oltre una soglia (relativa alla dimensione del font), inizia un nuovo paragrafo.<sup>[[1]](#references)</sup>
- Allineamento: raggruppa in base a valori X sinistri simili per i paragrafi allineati a sinistra; rileva le righe centrate tramite margini simmetrici; rileva quelle allineate a destra tramite i bordi destri.
- Stile: preserva il corsivo/grassetto tramite `fontStyle`/`fontWeight`; varia le classi CSS in base a intervalli di `fontSize` per approssimare titoli e testo del corpo.
- Link: se i run includono metadata dei link (ad esempio `positionId`), genera ancore e href interni.

## Mitigazione dei trucchi anti-scraping dei path SVG

- Usa path riempiti con `fill-rule: nonzero` e un renderer appropriato (CairoSVG, resvg). Non fare affidamento sulla normalizzazione dei token dei path.<sup>[[1]](#references)[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Evita il rendering dei tratti; concentrati sui solidi riempiti per aggirare gli artefatti delle linee sottili causati da micro-spostamenti relativi.
- Mantieni un viewBox stabile per ogni rendering, in modo che forme identiche vengano rasterizzate in modo coerente tra i vari batch.

## Note sulle prestazioni

- Nella pratica, i libri convergono verso poche centinaia di glyph unici (ad esempio, ~361 incluse le legature). Memorizza nella cache i risultati SSIM tramite perceptual hash.<sup>[[1]](#references)</sup>
- Dopo la discovery iniziale, i batch successivi riutilizzano prevalentemente hash già noti; la decodifica diventa vincolata dall’I/O.
- Il report citato ha osservato un SSIM medio di circa 0.95; segnala per la revisione manuale i match con punteggio basso.<sup>[[1]](#references)</sup>

## Generalizzazione ad altri viewer

Il workflow Kindle suggerisce che viewer simili potrebbero essere soggetti alla stessa normalizzazione quando:<sup>[[1]](#references)</sup>
- restituiscono run di glyph posizionati con ID numerici associati alla richiesta
- inviano glyph vettoriali per richiesta (path SVG o subset font)
- limitano il numero di pagine per richiesta

…possono essere gestiti con la stessa normalizzazione:
- Rasterizza le forme per richiesta → perceptual hash → shape ID
- Atlas di glyph/legature candidati per variante del font
- SSIM (o una metrica percettiva simile) per assegnare i caratteri
- Ricostruisci il layout a partire da rettangoli/stili dei run

## Esempio minimo di acquisizione (schema)

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
Adatta la parameterization (ASIN del libro, finestra di pagine, viewport) per soddisfare le richieste del lettore. Considera un limite di 5 pagine per richiesta.<sup>[[1]](#references)</sup>

## Risultati ottenibili

- Riduci oltre 100 alfabeti randomizzati a un singolo spazio di glyph tramite perceptual hashing.<sup>[[1]](#references)</sup>
- Nel test citato di 920 pagine, sono stati associati 361 glyph unici (100%) con un SSIM medio di 0.9527.<sup>[[1]](#references)</sup>
- Il report originale descrive l'EPUB ricostruito come quasi indistinguibile dall'originale.<sup>[[1]](#references)</sup>

## References

- [1] [Come ho invertito l'obfuscation web di Kindle di Amazon perché la loro app faceva schifo (Pixelmelt)](https://blog.pixelmelt.dev/kindle-web-drm/)
- [2] [CairoSVG – renderer da SVG a PNG](https://cairosvg.org/)
- [3] [imagehash – perceptual image hashing (pHash)](https://pypi.org/project/ImageHash/)
- [4] [scikit-image – Structural Similarity Index (SSIM)](https://scikit-image.org/docs/stable/api/skimage.metrics.html#skimage.metrics.structural_similarity)
- [5] [SVG 1.1 – proprietà fill](https://www.w3.org/TR/SVG11/painting.html#FillRuleProperty)
- [6] [resvg – libreria di rendering SVG](https://github.com/linebender/resvg)
{{#include ../../../banners/hacktricks-training.md}}
