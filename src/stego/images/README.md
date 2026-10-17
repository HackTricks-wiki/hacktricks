# Steganografia delle immagini

{{#include ../../banners/hacktricks-training.md}}

La steganografia delle immagini nei CTF si riduce spesso a una di queste categorie:

- LSB/piani di bit (PNG/BMP)
- Payload nei metadati/commenti
- Anomalie nei chunk PNG / riparazione di file danneggiati
- Strumenti per il dominio DCT JPEG (OutGuess ecc.)
- Tecniche basate sui frame (GIF/APNG)

## Analisi rapida

Dai priorità agli indizi a livello di contenitore prima di analizzare il contenuto in profondità:

- Convalida il file e ispezionane la struttura: `file`, `magick identify -verbose`, strumenti di convalida del formato (ad es., `pngcheck`).
- Estrai i metadati e le stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Cerca contenuti incorporati o aggiunti in coda: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Scegli l’approccio in base al contenitore:
  - PNG/BMP: piani di bit/LSB e anomalie a livello di chunk.
  - JPEG: metadati e strumenti per il dominio DCT (famiglie in stile OutGuess/F5).
  - GIF/APNG: estrazione dei frame, confronto tra frame, trucchi con le palette.

## Piani di bit / LSB

### Tecnica

PNG/BMP sono formati diffusi nei CTF perché memorizzano i pixel in modo da rendere semplice la **manipolazione a livello di bit**. Il classico meccanismo di occultamento/estrazione funziona così:

- Ogni canale del pixel (R/G/B/A) ha più bit.
- Il **bit meno significativo** (LSB) di ciascun canale modifica pochissimo l’immagine.
- Gli attaccanti nascondono dati in quei bit meno significativi, talvolta usando un passo, una permutazione o una selezione per canale.

Cosa aspettarsi nelle challenge:

- Il payload è in un solo canale (ad es., LSB di `R`).
- Il payload è nel canale alpha.
- Il payload viene compresso/codificato dopo l’estrazione.
- Il messaggio è distribuito su più piani o nascosto tramite XOR tra piani.

Altre famiglie che potresti incontrare (a seconda dell’implementazione):

- **LSB matching** (non si limita a invertire il bit, ma usa aggiustamenti di +/-1 per ottenere il bit desiderato)
- **Occultamento basato su palette/indici** (PNG/GIF indicizzati: il payload è negli indici dei colori anziché nei valori RGB grezzi)
- **Payload solo nel canale alpha** (completamente invisibile nella visualizzazione RGB)

### Strumenti

#### zsteg

`zsteg` elenca numerosi schemi di estrazione LSB/piani di bit per PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni dell'immagine, brute force delle varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, ispezione dei piani, XOR, ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Tecniche di visibilità basate su FFT

FFT non è un metodo di estrazione LSB; si usa nei casi in cui il contenuto è nascosto deliberatamente nello spazio delle frequenze o in pattern sottili.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Per il triage basato sul Web, spesso usato nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Struttura interna dei PNG: chunk, corruzione e dati nascosti

### Tecnica

PNG è un formato basato su chunk. In molte challenge, il payload è archiviato a livello di container/chunk anziché nei valori dei pixel:

- **Byte aggiuntivi dopo `IEND`** (molti visualizzatori ignorano i byte finali)
- **Chunk ausiliari non standard** che contengono payload; vedi il [workflow per esaminare i chunk PNG ed estrarre i dati](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Header corrotti** che nascondono le dimensioni o impediscono il funzionamento dei parser finché non vengono corretti

Posizioni dei chunk da esaminare con particolare attenzione:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, talvolta compressi)
- `iCCP` (profilo ICC) e altri chunk ausiliari usati come vettori
- `eXIf` (dati EXIF nei PNG)

### Comandi di triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cosa cercare:

- Combinazioni insolite di larghezza/altezza/profondità in bit/tipo di colore
- Errori CRC/chunk (pngcheck di solito indica l'offset esatto)
- Avvisi sulla presenza di dati aggiuntivi dopo `IEND`

Se ti serve una visualizzazione più dettagliata dei chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Riferimenti utili:

- Specifica PNG (struttura, chunk): https://www.w3.org/TR/PNG/
- Trucchi sui formati di file (casi limite di PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadati, strumenti per il dominio DCT e limiti dell’ELA

### Tecnica

JPEG non viene memorizzato come pixel grezzi: viene compresso nel dominio DCT. Per questo gli strumenti stego per JPEG sono diversi dagli strumenti LSB per PNG:

- I payload nei metadati/commenti sono a livello di file (facili e rapidi da individuare)
- Gli strumenti stego per il dominio DCT incorporano bit nei coefficienti di frequenza

Dal punto di vista operativo, considera JPEG come:

- Un contenitore di segmenti di metadati (facili e rapidi da individuare)
- Un dominio di segnale compresso (coefficienti DCT) su cui operano strumenti stego specializzati

### Controlli rapidi

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Posizioni con segnali ad alta intensità:

- Metadati EXIF/XMP/IPTC
- Segmento commento JPEG (`COM`)
- Segmenti applicativi (`APP1` per EXIF, `APPn` per dati del vendor)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se ti trovi specificamente di fronte a payload steghide in JPEG, valuta l’uso di `stegseek` (bruteforce più veloce rispetto agli script meno recenti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Analisi del livello di errore

ELA evidenzia diversi artefatti di ricompressione; può indicare le aree che sono state modificate, ma non è di per sé un rilevatore di stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, supponi che il messaggio sia:

- In un singolo frame (facile), oppure
- Distribuito tra più frame (l’ordine è importante), oppure
- Visibile solo confrontando frame consecutivi

### Estrai i frame

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Poi tratta i fotogrammi come normali PNG: `zsteg`, `pngcheck`, isolamento dei canali.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei fotogrammi)
- `imagemagick`/`magick` per trasformazioni di ogni fotogramma

Il confronto tra fotogrammi è spesso decisivo:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codifica tramite conteggio dei pixel APNG

- Rileva i container APNG: `exiftool -a -G1 file.png | grep -i animation` oppure `file`.
- Estrai i fotogrammi senza modificarne la temporizzazione: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recupera i payload codificati come conteggi di pixel per fotogramma:

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

Le challenge animate possono codificare ogni byte come il conteggio di un colore specifico in ogni frame; concatenando i conteggi si ricostruisce il messaggio.<sup>[[1]](#references)</sup>

## Inserimento protetto da password

Se sospetti che l'inserimento sia protetto da una passphrase anziché basarsi sulla manipolazione dei pixel, di solito è il modo più rapido per procedere.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può incorporare/estrarre payload crittografati.

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



## References

- [1] [Flagvent 2025 (Medium) — rosa, la lista dei desideri di Babbo Natale, metadati natalizi, rumore catturato](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
