# Steganografia delle immagini

{{#include ../../banners/hacktricks-training.md}}

La maggior parte delle stego di immagini nei CTF si riduce a una di queste categorie:

- LSB/bit-planes (PNG/BMP)
- Payload nei metadata/commenti
- Anomalie nei chunk PNG / riparazione della corruzione
- Strumenti DCT-domain per JPEG (OutGuess, etc)
- Basati su frame (GIF/APNG)

## Triage rapido

Dare priorità alle evidenze a livello di contenitore prima di un'analisi approfondita del contenuto:

- Valida il file e ispeziona la struttura: `file`, `magick identify -verbose`, validator di formato (es., `pngcheck`).
- Estrai metadata e stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Controlla contenuti embedded/appended: `binwalk` e ispezione della fine-file (`tail | xxd`).
- Procedi in base al contenitore:
- PNG/BMP: bit-planes/LSB e anomalie a livello di chunk.
- JPEG: metadata + DCT-domain tooling (famiglie OutGuess/F5-style).
- GIF/APNG: estrazione dei frame, differenza tra frame, trucchi della palette.

## Bit-planes / LSB

### Tecnica

PNG/BMP sono popolari nei CTF perché memorizzano i pixel in modo che la **manipolazione a livello di bit** sia semplice. Il meccanismo classico di nascondere/estrarre è:

- Ogni canale del pixel (R/G/B/A) ha più bit.
- Il **bit meno significativo** (LSB) di ogni canale altera molto poco l'immagine.
- Gli attaccanti nascondono dati in quei bit di ordine inferiore, a volte con uno stride, una permutazione o una scelta per canale.

Cosa aspettarsi nelle sfide:

- Il payload è in un solo canale (es., `R` LSB).
- Il payload è nel canale alpha.
- Il payload è compresso/codificato dopo l'estrazione.
- Il messaggio è distribuito attraverso i piani o nascosto tramite XOR tra i piani.

Famiglie aggiuntive che potresti incontrare (dipende dall'implementazione):

- **LSB matching** (non solo invertire il bit, ma aggiustamenti +/-1 per ottenere il bit target)
- **Palette/index-based hiding** (indexed PNG/GIF: payload negli indici di colore anziché nel raw RGB)
- **Alpha-only payloads** (completamente invisibili nella vista RGB)

### Strumenti

#### zsteg

`zsteg` enumera molti pattern di estrazione LSB/bit-plane per PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni dell'immagine, brute forcing di varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, ispezione dei piani, XOR, ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT non è estrazione LSB; è per casi in cui il contenuto è deliberatamente nascosto nello spazio delle frequenze o in pattern sottili.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage basato sul web spesso usato nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Tecnica

PNG è un formato a chunk. In molte sfide il payload è memorizzato a livello di contenitore/chunk anziché nei valori dei pixel:

- **Extra bytes after `IEND`** (molti visualizzatori ignorano i byte finali)
- **Non-standard ancillary chunks** che contengono payload
- **Corrupted headers** che nascondono le dimensioni o rompono i parser fino a quando non vengono riparati

Posizioni di chunk ad alto segnale da esaminare:

- `tEXt` / `iTXt` / `zTXt` (metadati di testo, a volte compressi)
- `iCCP` (ICC profile) e altri chunk ancillari usati come contenitore
- `eXIf` (dati EXIF in PNG)

### Comandi di triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cosa cercare:

- Strane combinazioni di width/height/bit-depth/colour-type
- Errori CRC/chunk (pngcheck di solito indica l'offset esatto)
- Avvisi su dati aggiuntivi dopo `IEND`

Se hai bisogno di una vista dei chunk più approfondita:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Riferimenti utili:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Tecnica

JPEG non è memorizzato come pixel grezzi; è compresso nel dominio DCT. Per questo i JPEG stego tools differiscono dai PNG LSB tools:

- Metadata/comment payloads sono a livello di file (high-signal e veloci da ispezionare)
- DCT-domain stego tools inseriscono bit nei coefficienti di frequenza

Operativamente, considera JPEG come:

- Un contenitore per metadata segments (high-signal, quick to inspect)
- Un dominio del segnale compresso (coefficienti DCT) dove operano stego tools specializzati

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

Se stai trattando payloads steghide in JPEGs, considera l'uso di `stegseek` (bruteforce più veloce rispetto a script più vecchi):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA mette in evidenza diversi artefatti di ricompressione; può indicare regioni che sono state modificate, ma di per sé non è un rilevatore di stego:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Immagini animate

### Tecnica

Per le immagini animate, considera che il messaggio sia:

- In un singolo frame (facile), oppure
- Distribuito su più frame (l'ordine è importante), oppure
- Visibile solo quando si esegue il diff tra frame consecutivi

### Estrai i frame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Quindi tratta i frame come normali PNG: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (estrazione veloce dei frame)
- `imagemagick`/`magick` per trasformazioni per frame

Frame differencing è spesso decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Password-protected embedding

Se sospetti embedding protetto da una passphrase anziché manipolazione a livello di pixel, questa è di solito la via più veloce.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have the contents of src/stego/images/README.md. Please paste the file content here (or the parts you want translated). Once you provide it, I will translate the English text to Italian, preserving all markdown/html tags, links, paths and code as requested.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Supporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
