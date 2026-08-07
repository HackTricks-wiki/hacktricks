# Steganografia delle immagini

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei casi di image stego nei CTF rientra in una di queste categorie:

- LSB/bit-planes (PNG/BMP)
- Payload nei metadata/commenti
- Anomalie nei chunk PNG / riparazione della corruzione
- Tool per il dominio DCT JPEG (OutGuess, ecc.)
- Basati sui frame (GIF/APNG)

## Triage rapido

Dai priorita alle evidenze a livello di container prima di un'analisi approfondita del contenuto:

- Convalida il file e ispeziona la struttura: `file`, `magick identify -verbose`, validator del formato (ad esempio `pngcheck`).
- Estrai metadata e stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Controlla la presenza di contenuti incorporati/aggiunti: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Scegli il ramo in base al container:
- PNG/BMP: bit-planes/LSB e anomalie a livello di chunk.
- JPEG: metadata + tooling per il dominio DCT (famiglie in stile OutGuess/F5).
- GIF/APNG: estrazione dei frame, differenziazione tra frame, tecniche sulle palette.

## Bit-planes / LSB

### Technique

PNG/BMP sono popolari nei CTF perche memorizzano i pixel in un modo che rende facili le **manipolazioni a livello di bit**. Il meccanismo classico per nascondere/estrarre dati e il seguente:

- Ogni canale del pixel (R/G/B/A) ha piu bit.
- Il **least significant bit** (LSB) di ogni canale modifica molto poco l'immagine.
- Gli attaccanti nascondono i dati nei bit di ordine piu basso, a volte usando uno stride, una permutazione o una scelta del canale.

Cosa aspettarsi nelle challenge:

- Il payload si trova in un solo canale (ad esempio, LSB di `R`).
- Il payload si trova nel canale alpha.
- Il payload viene compresso/codificato dopo l'estrazione.
- Il messaggio e distribuito tra i piani o nascosto tramite XOR tra i piani.

Altre famiglie che potresti incontrare (a seconda dell'implementazione):

- **LSB matching** (non consiste solo nell'invertire il bit, ma nell'apportare aggiustamenti di +/-1 per far corrispondere il bit target)
- **Palette/index-based hiding** (PNG/GIF indicizzati: il payload si trova negli indici dei colori invece che nei valori RGB grezzi)
- **Alpha-only payloads** (completamente invisibili nella visualizzazione RGB)

### Tooling

#### zsteg

`zsteg` enumera molti pattern di estrazione LSB/bit-plane per PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni dell'immagine, brute forcing delle varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, ispezione dei piani, XOR, ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucchi di visibilità basati su FFT

FFT non è un'estrazione LSB; viene usata nei casi in cui il contenuto è deliberatamente nascosto nello spazio delle frequenze o all'interno di pattern sottili.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Il triage basato sul Web viene spesso usato nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals dei PNG: chunk, corruzione e dati nascosti

### Tecnica

PNG è un formato suddiviso in chunk. In molte challenge il payload è memorizzato a livello di container/chunk anziché nei valori dei pixel:

- **Byte aggiuntivi dopo `IEND`** (molti visualizzatori ignorano i byte finali)
- **Chunk ancillary non standard** contenenti payload
- **Header corrotti** che nascondono le dimensioni o impediscono il parsing finché non vengono corretti

Posizioni dei chunk ad alto valore informativo da esaminare:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, talvolta compressi)
- `iCCP` (profilo ICC) e altri chunk ancillary usati come carrier
- `eXIf` (dati EXIF nei PNG)

### Comandi di triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cosa cercare:

- Combinazioni insolite di larghezza/altezza/profondità dei bit/tipo di colore
- Errori CRC/chunk (`pngcheck` indica solitamente l'offset esatto)
- Avvisi sulla presenza di dati aggiuntivi dopo `IEND`

Se hai bisogno di una visualizzazione più dettagliata dei chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Riferimenti utili:

- Specifica PNG (struttura, chunk): https://www.w3.org/TR/PNG/
- Trucchi sui formati dei file (casi limite PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, strumenti nel dominio DCT e limitazioni di ELA

### Technique

JPEG non viene memorizzato come pixel grezzi; è compresso nel dominio DCT. Per questo gli strumenti di stego per JPEG differiscono dagli strumenti LSB per PNG:

- I payload di metadata/commenti sono a livello file (ad alta rilevanza e rapidi da analizzare)
- Gli strumenti di stego nel dominio DCT incorporano bit nei coefficienti di frequenza

Dal punto di vista operativo, considera JPEG come:

- Un container per segmenti di metadata (ad alta rilevanza e rapidi da analizzare)
- Un dominio di segnali compressi (coefficienti DCT) in cui operano strumenti di stego specializzati

### Controlli rapidi
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Posizioni ad alto segnale:

- Metadati EXIF/XMP/IPTC
- Segmento dei commenti JPEG (`COM`)
- Segmenti applicativi (`APP1` per EXIF, `APPn` per i dati del vendor)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se stai affrontando specificamente payload steghide in JPEG, considera l'uso di `stegseek` (bruteforce più veloce rispetto agli script più datati):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA evidenzia diversi artefatti di ricompressione; può indicare le regioni che sono state modificate, ma non è un rilevatore stego di per sé:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, supponi che il messaggio sia:

- In un singolo frame (facile), oppure
- Distribuito tra i frame (l'ordine è importante), oppure
- Visibile solo quando esegui il diff tra frame consecutivi

### Estrai i frame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Quindi tratta i frame come normali PNG: `zsteg`, `pngcheck`, isolamento dei canali.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei frame)
- `imagemagick`/`magick` per trasformazioni per-frame

Il confronto tra frame è spesso decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Codifica del conteggio dei pixel in APNG

- Rileva i container APNG: `exiftool -a -G1 file.png | grep -i animation` oppure `file`.
- Estrai i frame senza modificare la temporizzazione: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera i payload codificati come conteggi dei pixel per frame:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Le sfide animate possono codificare ogni byte come il conteggio di un colore specifico in ogni frame; concatenando i conteggi si ricostruisce il messaggio.<sup>[[1]](#references)</sup>

## Embedding protetto da password

Se sospetti un embedding protetto da una passphrase anziché una manipolazione a livello di pixel, questo è solitamente il percorso più rapido.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può effettuare l'embedding e l'estrazione di payloads crittografati.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Supporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Riferimenti

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
