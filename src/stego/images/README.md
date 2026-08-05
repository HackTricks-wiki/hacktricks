# Steganografia delle immagini

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei CTF di image stego rientra in una di queste categorie:

- LSB/bit-planes (PNG/BMP)
- Payload nei metadati/commenti
- Anomalie nei chunk PNG / riparazione della corruzione
- Tool nel dominio DCT dei JPEG (OutGuess, ecc.)
- Basati sui frame (GIF/APNG)

## Triage rapido

Dai priorita alle evidenze a livello di container prima di procedere con un'analisi approfondita del contenuto:

- Valida il file e ispezionane la struttura: `file`, `magick identify -verbose`, validator del formato (ad esempio `pngcheck`).
- Estrai i metadati e le stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Controlla la presenza di contenuti embedded/appended: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Scegli in base al container:
- PNG/BMP: bit-planes/LSB e anomalie a livello di chunk.
- JPEG: metadati + tool nel dominio DCT (famiglie in stile OutGuess/F5).
- GIF/APNG: estrazione dei frame, differenziazione tra frame, tecniche sulle palette.

## Bit-planes / LSB

### Tecnica

PNG/BMP sono popolari nei CTF perché memorizzano i pixel in un modo che rende facile la **manipolazione a livello di bit**. Il meccanismo classico per nascondere/estrarre è:

- Ogni canale del pixel (R/G/B/A) contiene più bit.
- Il **least significant bit** (LSB) di ogni canale modifica molto poco l'immagine.
- Gli attacker nascondono i dati in questi bit di ordine inferiore, a volte usando uno stride, una permutation o una scelta del canale.

Cosa aspettarsi nelle challenge:

- Il payload si trova in un solo canale (ad esempio, LSB di `R`).
- Il payload si trova nel canale alpha.
- Il payload è compresso/encoded dopo l'estrazione.
- Il messaggio è distribuito tra i planes o nascosto tramite XOR tra i planes.

Altre famiglie che potresti incontrare (a seconda dell'implementazione):

- **LSB matching** (non consiste solo nell'invertire il bit, ma nell'applicare modifiche +/-1 per adattarsi al bit target)
- **Hiding basato su palette/index** (PNG/GIF indicizzati: il payload si trova negli indici dei colori anziché nei valori RGB grezzi)
- **Payload esclusivamente nell'alpha** (completamente invisibile nella visualizzazione RGB)

### Tool

#### zsteg

`zsteg` enumera molti pattern di estrazione LSB/bit-plane per PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni dell'immagine, brute forcing delle varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, analisi dei piani, XOR, ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucchi di visibilità basati su FFT

FFT non è un'estrazione LSB; viene utilizzata nei casi in cui il contenuto è deliberatamente nascosto nello spazio delle frequenze o all'interno di pattern sottili.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Il triage basato sul web viene spesso utilizzato nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internals dei PNG: chunk, corruzione e dati nascosti

### Tecnica

Il PNG è un formato suddiviso in chunk. In molte challenge il payload è memorizzato a livello di container/chunk anziché nei valori dei pixel:

- **Byte aggiuntivi dopo `IEND`** (molti visualizzatori ignorano i byte finali)
- **Chunk ancillary non standard** contenenti payload
- **Header corrotti** che nascondono le dimensioni o interrompono il funzionamento dei parser finché non vengono corretti

Posizioni dei chunk ad alto valore informativo da esaminare:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, talvolta compressi)
- `iCCP` (profilo ICC) e altri chunk ancillary utilizzati come carrier
- `eXIf` (dati EXIF nei PNG)

### Comandi di triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cosa cercare:

- Combinazioni insolite di larghezza/altezza/profondità in bit/tipo di colore
- Errori CRC/dei chunk (`pngcheck` solitamente indica l'offset esatto)
- Avvisi sulla presenza di dati aggiuntivi dopo `IEND`

Se hai bisogno di una visualizzazione più approfondita dei chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Riferimenti utili:

- Specifica PNG (struttura, chunk): https://www.w3.org/TR/PNG/
- Tecniche per i formati dei file (casi limite di PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, strumenti nel dominio DCT e limitazioni dell'ELA

### Tecnica

JPEG non viene memorizzato come pixel grezzi; è compresso nel dominio DCT. Per questo gli strumenti stego per JPEG differiscono dagli strumenti LSB per PNG:

- I payload di metadata/commenti sono a livello di file (segnale evidente e rapidi da ispezionare)
- Gli strumenti stego nel dominio DCT incorporano bit nei coefficienti di frequenza

A livello operativo, considera JPEG come:

- Un container per segmenti di metadata (segnale evidente, rapido da ispezionare)
- Un dominio di segnale compresso (coefficienti DCT) in cui operano strumenti stego specializzati

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

Se stai affrontando specificamente payload steghide in JPEG, considera l'utilizzo di `stegseek` (bruteforce più veloce rispetto agli script più vecchi):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA evidenzia diversi artefatti di ricompressione; può indicare le regioni che sono state modificate, ma non è di per sé uno stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, supponi che il messaggio sia:

- In un singolo fotogramma (facile), oppure
- Distribuito tra i fotogrammi (l'ordine è importante), oppure
- Visibile solo quando confronti fotogrammi consecutivi

### Estrai fotogrammi
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Quindi tratta i frame come normali PNG: `zsteg`, `pngcheck`, isolamento dei canali.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei frame)
- `imagemagick`/`magick` per le trasformazioni per-frame

La differenziazione tra frame è spesso decisiva:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Codifica del conteggio dei pixel APNG

- Rileva i contenitori APNG: `exiftool -a -G1 file.png | grep -i animation` oppure `file`.
- Estrai i frame senza modificare la temporizzazione: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera i payload codificati come conteggi di pixel per frame:
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
Le challenge animate possono codificare ogni byte come il numero di occorrenze di un colore specifico in ogni frame; concatenando i conteggi si ricostruisce il messaggio.<sup>[[1]](#references)</sup>

## Embedding protetto da password

Se sospetti un embedding protetto da una passphrase anziché una manipolazione a livello di pixel, questo è solitamente il percorso più rapido.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può inserire/estrarre payload cifrati.
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
