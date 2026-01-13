# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La maggior parte degli CTF image stego si riduce a uno di questi casi:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage rapido

Dare priorità alle evidenze a livello di container prima dell'analisi approfondita del contenuto:

- Convalidare il file e ispezionare la struttura: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Estrarre metadati e stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Controllare contenuti incorporati o aggiunti: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Procedere in base al container:
- PNG/BMP: bit-planes/LSB e anomalie a livello di chunk.
- JPEG: metadati + strumenti nel dominio DCT (OutGuess/F5-style families).
- GIF/APNG: estrazione dei frame, differenza tra frame, trucchi con la palette.

## Bit-planes / LSB

### Tecnica

PNG/BMP sono popolari nei CTF perché memorizzano i pixel in modo che renda semplice la **manipolazione a livello di bit**. Il meccanismo classico per nascondere/estrarre è:

- Ogni canale del pixel (R/G/B/A) ha più bit.
- Il **least significant bit** (LSB) di ogni canale altera molto poco l'immagine.
- Gli attacker nascondono dati in quei bit di ordine più basso, a volte usando uno stride, una permutazione o una scelta per canale.

Cosa aspettarsi nelle challenge:

- Il payload è in un solo canale (e.g., `R` LSB).
- Il payload è nel canale alpha.
- Il payload è compresso/encoded dopo l'estrazione.
- Il messaggio è distribuito tra i piani o nascosto tramite XOR tra i piani.

Altre varianti che potresti incontrare (dipendenti dall'implementazione):

- **LSB matching** (non solo invertire il bit, ma aggiustamenti di +/-1 per ottenere il bit target)
- **Palette/index-based hiding** (indexed PNG/GIF: payload negli indici di colore invece che nel RGB grezzo)
- **Alpha-only payloads** (completamente invisibili nella vista RGB)

### Strumenti

#### zsteg

`zsteg` enumera molti pattern di estrazione LSB/bit-plane per PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una batteria di trasformazioni (metadata, trasformazioni di immagine, brute forcing delle varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei channel, ispezione dei plane, XOR, ecc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT non è estrazione LSB; è per i casi in cui il contenuto è deliberatamente nascosto nello spazio delle frequenze o in pattern sottili.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage web spesso usato in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Tecnica

PNG è un formato chunked. In molte challenge il payload è memorizzato a livello di container/chunk piuttosto che nei valori dei pixel:

- **Extra bytes after `IEND`** (molti visualizzatori ignorano i byte finali)
- **Non-standard ancillary chunks** che contengono payload
- **Corrupted headers** che nascondono le dimensioni o rompono i parser finché non vengono corretti

Posizioni di chunk ad alto segnale da esaminare:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, talvolta compressi)
- `iCCP` (ICC profile) e altri ancillary chunks usati come vettore
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cosa cercare:

- Combinazioni insolite di width/height/bit-depth/colour-type
- CRC/chunk errori (pngcheck di solito indica l'offset esatto)
- Avvisi su dati aggiuntivi dopo `IEND`

Se hai bisogno di una vista dei chunk più dettagliata:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Riferimenti utili:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools e limitazioni di ELA

### Tecnica

JPEG non è memorizzato come pixel grezzi; è compresso nel dominio DCT. Per questo i tool stego per JPEG differiscono dagli strumenti LSB per PNG:

- Metadata/comment payloads sono a livello di file (high-signal e rapidi da ispezionare)
- DCT-domain stego tools inseriscono bit nei coefficienti di frequenza

Operativamente, considera JPEG come:

- Un contenitore per i segmenti metadata (high-signal, facili da ispezionare rapidamente)
- Un dominio di segnale compresso (coefficienti DCT) dove operano strumenti stego specializzati

### Controlli rapidi
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Posizioni ad alto segnale:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA mette in evidenza diversi artifact di ricompressione; può indicare regioni che sono state modificate, ma di per sé non è un rilevatore di stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, considera che il messaggio possa essere:

- In un singolo frame (facile), oppure
- Distribuito su più frame (l'ordine conta), oppure
- Visibile solo quando si effettua il diff tra frame consecutivi

### Estrai i frame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Tratta quindi i frame come normali PNG: `zsteg`, `pngcheck`, channel isolation.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei frame)
- `imagemagick`/`magick` per trasformazioni su ogni frame

Il calcolo delle differenze tra frame è spesso decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Individua contenitori APNG: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Estrai i frame senza ritimare: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera payloads codificati come conteggi di pixel per frame:
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
Le sfide animate possono codificare ogni byte come il conteggio di un colore specifico in ogni fotogramma; concatenando i conteggi si ricostruisce il messaggio.

## Embedding protetto da password

Se sospetti che l'embedding sia protetto da una passphrase anziché da manipolazioni a livello di pixel, questa è di solito la via più veloce.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Non vedo il contenuto di src/stego/images/README.md. Per favore incolla qui il testo del file che vuoi tradurre in italiano.

Nota: manterrò intatti markdown, tag, link, percorsi e non tradurrò codice, nomi di tecniche, piattaforme cloud, parole come "leak", né link/refs.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Supporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Riferimenti

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
