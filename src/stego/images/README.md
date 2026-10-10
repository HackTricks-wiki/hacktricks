# Steganografia nelle immagini

{{#include ../../banners/hacktricks-training.md}}

La steganografia nelle immagini dei CTF si riduce spesso a una di queste categorie:

- LSB/piani di bit (PNG/BMP)
- Payload nei metadati/commenti
- Anomalie nei chunk PNG / riparazione di file corrotti
- Strumenti per il dominio DCT JPEG (OutGuess e simili)
- Tecniche basate sui frame (GIF/APNG)

## Triage rapido

Dai la priorità agli indizi a livello di contenitore prima di analizzare in profondità il contenuto:

- Verifica il file ed esamina la struttura: `file`, `magick identify -verbose`, strumenti di convalida del formato (ad esempio, `pngcheck`).
- Estrai i metadati e le stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Cerca contenuti incorporati o aggiunti in coda: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Scegli l'approccio in base al contenitore:
  - PNG/BMP: piani di bit/LSB e anomalie a livello di chunk.
  - JPEG: metadati e strumenti per il dominio DCT (famiglie come OutGuess/F5).
  - GIF/APNG: estrazione dei frame, confronto tra frame, tecniche con le palette.

## Piani di bit / LSB

### Tecnica

PNG/BMP sono diffusi nei CTF perché memorizzano i pixel in modo da rendere facile la **manipolazione a livello di bit**. Il classico meccanismo di occultamento/estrazione è il seguente:

- Ogni canale di un pixel (R/G/B/A) contiene più bit.
- Il **bit meno significativo** (LSB) di ogni canale modifica pochissimo l'immagine.
- Gli attaccanti nascondono dati in questi bit meno significativi, talvolta usando uno stride, una permutazione o una selezione per canale.

Cosa aspettarsi nelle challenge:

- Il payload si trova in un solo canale (ad esempio, nell'LSB di `R`).
- Il payload si trova nel canale alpha.
- Il payload viene compresso/codificato dopo l'estrazione.
- Il messaggio è distribuito su più piani o nascosto tramite XOR tra i piani.

Altre famiglie che potresti incontrare (a seconda dell'implementazione):

- **LSB matching** (non si limita a invertire il bit, ma applica modifiche di +/-1 per ottenere il bit desiderato)
- **Occultamento basato su palette/indici** (PNG/GIF indicizzati: il payload è nei valori degli indici colore anziché nei valori RGB grezzi)
- **Payload solo nel canale alpha** (completamente invisibili nella visualizzazione RGB)

### Strumenti

#### zsteg

`zsteg` enumera molti schemi di estrazione LSB/piani di bit per PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni delle immagini, brute force di varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, ispezione dei piani, XOR ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Tecniche di visibilità basate su FFT

FFT non estrae LSB; serve nei casi in cui il contenuto è nascosto intenzionalmente nello spazio delle frequenze o in pattern sottili.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Strumenti di triage basati sul Web usati spesso nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Interni PNG: chunk, corruzione e dati nascosti

### Tecnica

PNG è un formato suddiviso in chunk. In molte challenge, il payload è memorizzato a livello di container/chunk anziché nei valori dei pixel:

- **Byte aggiuntivi dopo `IEND`** (molti visualizzatori ignorano i byte finali)
- **Chunk ancillary non standard** contenenti payload
- **Header corrotti** che nascondono le dimensioni o impediscono il funzionamento dei parser finché non vengono corretti

Posizioni dei chunk particolarmente rilevanti da controllare:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, a volte compressi)
- `iCCP` (profilo ICC) e altri chunk ancillary usati come vettori
- `eXIf` (dati EXIF in PNG)

### Comandi di triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cosa cercare:

- Combinazioni insolite di larghezza/altezza/profondità di bit/tipo di colore
- Errori CRC/chunk (pngcheck di solito indica l’offset esatto)
- Avvisi sulla presenza di dati aggiuntivi dopo `IEND`

Se ti serve una visualizzazione più dettagliata dei chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Riferimenti utili:

- Specifica PNG (struttura, chunk): https://www.w3.org/TR/PNG/
- Trucchi sui formati di file (casi limite di PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadati, strumenti in dominio DCT e limiti dell'ELA

### Tecnica

JPEG non viene memorizzato come pixel grezzi: è compresso nel dominio DCT. Per questo gli strumenti stego per JPEG sono diversi dagli strumenti LSB per PNG:

- I payload di metadati/commenti sono a livello di file (elevato segnale e rapidi da ispezionare)
- Gli strumenti stego in dominio DCT incorporano bit nei coefficienti di frequenza

Dal punto di vista operativo, considera JPEG come:

- Un contenitore di segmenti di metadati (elevato segnale, rapidi da ispezionare)
- Un dominio di segnale compresso (coefficienti DCT) su cui operano strumenti stego specializzati

### Controlli rapidi

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Posizioni ad alto segnale:

- Metadati EXIF/XMP/IPTC
- Segmento commento JPEG (`COM`)
- Segmenti applicativi (`APP1` per EXIF, `APPn` per i dati dei vendor)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se devi affrontare payload steghide in JPEG, valuta l’uso di `stegseek` (bruteforce più rapido rispetto agli script meno recenti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA evidenzia diversi artefatti di ricompressione; può indicare le aree che sono state modificate, ma da solo non rileva lo stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, supponi che il messaggio sia:

- In un singolo frame (facile), oppure
- Distribuito su più frame (l’ordine è importante), oppure
- Visibile solo facendo il diff tra frame consecutivi

### Estrai i frame

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Poi tratta i frame come normali PNG: `zsteg`, `pngcheck`, isolamento dei canali.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei frame)
- `imagemagick`/`magick` per trasformazioni dei singoli frame

Il confronto tra frame è spesso decisivo:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Encoding tramite conteggio dei pixel APNG

- Rileva i container APNG: `exiftool -a -G1 file.png | grep -i animation` oppure `file`.
- Estrai i frame senza modificarne la temporizzazione: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Le sfide animate possono codificare ogni byte come il numero di pixel di un colore specifico in ogni frame; concatenando i conteggi si ricostruisce il messaggio.<sup>[[1]](#references)</sup>

## Embedding protetto da password

Se sospetti che l'embedding sia protetto da una passphrase anziché basarsi sulla manipolazione a livello di pixel, di solito questa è la via più rapida.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può incorporare/estrarre payload cifrati.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repository: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Supporta PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pink, Lista dei desideri di Babbo Natale, Metadati natalizi, Rumore catturato](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
