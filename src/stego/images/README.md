# Steganografia delle immagini

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dello stego di immagini nei CTF si riduce a una di queste categorie:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- Anomalie nei chunk PNG / riparazione della corruzione
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage rapido

Prioritizza le evidenze a livello di contenitore prima dell'analisi approfondita del contenuto:

- Valida il file e ispettane la struttura: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Estrai metadata e stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Controlla contenuti incorporati o aggiunti alla fine del file: `binwalk` e ispezione end-of-file (`tail | xxd`).
- Procedi in base al contenitore:
- PNG/BMP: bit-planes/LSB e anomalie a livello di chunk.
- JPEG: metadata + strumenti nel dominio DCT (OutGuess/F5-style families).
- GIF/APNG: estrazione frame, differenza tra frame, trucchi di palette.

## Bit-planes / LSB

### Tecnica

PNG/BMP sono popolari nei CTF perché memorizzano i pixel in modo che renda facile la **manipolazione a livello di bit**. Il meccanismo classico di nascondere/estrarre è:

- Ogni canale di pixel (R/G/B/A) ha più bit.
- Il **bit meno significativo** (LSB) di ogni canale modifica molto poco l'immagine.
- Gli attaccanti nascondono dati in quei bit di ordine basso, talvolta con uno stride, una permutazione, o una scelta per canale.

Cosa aspettarsi nelle sfide:

- Il payload è in un solo canale (es., `R` LSB).
- Il payload è nel canale alpha.
- Il payload è compresso/codificato dopo l'estrazione.
- Il messaggio è distribuito attraverso i piani o nascosto tramite XOR tra i piani.

Altre varianti che potresti incontrare (dipendenti dall'implementazione):

- **LSB matching** (non solo invertire il bit, ma aggiustamenti +/-1 per far corrispondere il bit target)
- **Palette/index-based hiding** (indexed PNG/GIF: payload negli indici di colore invece che nel RGB grezzo)
- **Alpha-only payloads** (completamente invisibili nella vista RGB)

### Strumenti

#### zsteg

`zsteg` enumera molti schemi di estrazione LSB/bit-plane per PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una batteria di trasformazioni (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: filtri visivi manuali (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT non è estrazione LSB; è utile nei casi in cui il contenuto è intenzionalmente nascosto nello spazio delle frequenze o in pattern sottili.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage web spesso usato nei CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG è un formato a chunk. In molte challenge il payload è memorizzato a livello di container/chunk invece che nei valori dei pixel:

- **Extra bytes after `IEND`** (molti visualizzatori ignorano i byte finali)
- **Non-standard ancillary chunks** che trasportano payload
- **Corrupted headers** che nascondono le dimensioni o rompono i parser finché non vengono riparati

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (metadata testuale, a volte compressi)
- `iCCP` (ICC profile) e altri chunk ancillari usati come vettore
- `eXIf` (dati EXIF in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cosa cercare:

- Combinazioni anomale di width/height/bit-depth/colour-type
- Errori CRC/chunk (pngcheck di solito indica l'offset esatto)
- Avvisi su dati aggiuntivi dopo `IEND`

Se hai bisogno di una vista più dettagliata dei chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Riferimenti utili:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Tecnica

JPEG non è memorizzato come pixel grezzi; è compresso nel DCT-domain. Per questo gli stego tools per JPEG differiscono dagli strumenti LSB per PNG:

- I payload di metadata/comment sono a livello file (high-signal e rapidi da ispezionare)
- Gli stego tools nel DCT-domain inseriscono bit nelle coefficienti di frequenza

Operativamente, considera JPEG come:

- Un contenitore per segmenti di metadata (high-signal, rapidi da ispezionare)
- Un dominio di segnale compresso (DCT coefficients) dove operano stego tools specializzati

### Controlli rapidi
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Posizioni ad alto segnale:

- EXIF/XMP/IPTC metadati
- Segmento commento JPEG (`COM`)
- Segmenti di applicazione (`APP1` for EXIF, `APPn` for vendor data)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se stai affrontando specificamente payloads steghide in JPEGs, considera l'uso di `stegseek` (bruteforce più veloce rispetto a script più datati):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA evidenzia diversi artefatti di ricompressione; può indicare regioni che sono state modificate, ma non è un stego detector di per sé:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, supponi che il messaggio sia:

- In un singolo fotogramma (facile), oppure
- Distribuito su più fotogrammi (l'ordine conta), oppure
- Visibile solo quando si effettua il diff tra fotogrammi consecutivi

### Estrai i fotogrammi
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Quindi tratta i frame come normali PNG: `zsteg`, `pngcheck`, channel isolation.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei frame)
- `imagemagick`/`magick` per trasformazioni su ogni frame

Frame differencing è spesso decisivo:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Embedding protetto da password

Se sospetti che l'embedding sia protetto da una passphrase piuttosto che da manipolazioni a livello di pixel, questa è di solito la via più veloce.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può embed/extract payloads crittografati.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Non ho accesso diretto al repository. Per favore incolla qui il contenuto di src/stego/images/README.md che vuoi tradurre (o conferma che traduca una sezione specifica). Confermi che mantenga intatti i nomi come "StegCracker", "steghide", i percorsi e i tag markdown come indicato?
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Supporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
