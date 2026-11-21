# Steganografia nelle immagini

{{#include ../../banners/hacktricks-training.md}}

La steganografia nelle immagini nei CTF si riduce spesso a una di queste categorie:

- LSB/piani di bit (PNG/BMP)
- Payload nei metadati/commenti
- Anomalie o riparazione di chunk PNG
- Strumenti nel dominio DCT JPEG (OutGuess, ecc.)
- Tecniche basate sui frame (GIF/APNG)

## Triage rapido

Dai priorità alle prove a livello di container prima di analizzare in profondità il contenuto. Consulta il [flusso di lavoro generale per la steganografia](../workflow/) per identificare e recuperare i file prima dei test specifici per le immagini.

- Convalida il file e ispezionane la struttura: `file`, `magick identify -verbose`, validatori di formato (ad es., `pngcheck`).
- Estrai i metadati e le stringhe visibili: `exiftool -a -u -g1`, `strings`.
- Verifica la presenza di contenuti incorporati o aggiunti: `binwalk` e ispezione della fine del file (`tail | xxd`).
- Scegli il percorso in base al container:
  - PNG/BMP: piani di bit/LSB e anomalie a livello di chunk.
  - JPEG: metadati e strumenti nel dominio DCT (famiglie in stile OutGuess/F5).
  - GIF/APNG: estrazione dei frame, differenziazione tra frame, trucchi con le palette.

## Piani di bit / LSB

### Tecnica

PNG/BMP sono popolari nei CTF perché memorizzano i pixel in modo da rendere semplice la **manipolazione a livello di bit**. Il classico meccanismo per nascondere/estrarre dati è il seguente:

- Ogni canale del pixel (R/G/B/A) contiene più bit.
- Il **bit meno significativo** (LSB) di ciascun canale modifica pochissimo l’immagine.
- Gli attacker nascondono dati in questi bit meno significativi, talvolta usando uno stride, una permutazione o una selezione specifica per canale.

Cosa aspettarsi nelle challenge:

- Il payload si trova in un solo canale (ad es., LSB di `R`).
- Il payload si trova nel canale alpha.
- Il payload viene compresso/codificato dopo l’estrazione.
- Il messaggio è distribuito su più piani o nascosto tramite XOR tra i piani.

Altre famiglie che potresti incontrare (a seconda dell’implementazione):

- **LSB matching** (non solo inversione del bit, ma modifiche di +/-1 per ottenere il bit desiderato)
- **Tecniche basate su palette/indici** (PNG/GIF indicizzati: il payload è negli indici dei colori, non nei valori RGB grezzi)
- **Payload solo nel canale alpha** (completamente invisibili nella visualizzazione RGB)

### Indici delle palette a colori indicizzati

Un PNG o GIF indicizzato memorizza un **indice** della palette per ogni pixel, non una terna RGB. Due indici possono corrispondere allo stesso colore visibile, quindi convertire l’immagine in RGB prima dell’analisi può cancellare la distinzione nascosta. Esamina le voci duplicate o quasi duplicate della palette, poi crea una maschera binaria dei pixel che usano ciascun indice sospetto. Questa tecnica ha permesso di scoprire testo nascosto e modifiche a QR code in recenti challenge GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Per un PNG indicizzato a singolo frame (o il **primo frame** di una GIF), mantieni la modalità `P` di Pillow e modifica `target` impostandolo su un indice interessante segnalato dallo script. Considera la trasparenza (`tRNS` o l’indice di trasparenza GIF), oltre ai valori RGB, quando scegli gli indici.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Per le GIF animate, esamina i fotogrammi separatamente. Pillow normalmente converte i fotogrammi successivi in RGB/RGBA durante il compositing; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` mantiene la modalità `P` solo finché la palette non cambia. Se un fotogramma ha una palette locale o è già stato sottoposto a compositing, esamina i dati originali del fotogramma indicizzato invece di trattare i pixel convertiti in RGB come indici.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Strumenti

#### zsteg

`zsteg` enumera numerosi pattern di estrazione LSB/bit-plane per PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: esegue una serie di trasformazioni (metadati, trasformazioni dell’immagine, brute force delle varianti LSB).
- `stegsolve`: filtri visivi manuali (isolamento dei canali, ispezione dei piani, XOR, ecc.).

Download di Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trucchi di visibilità basati su FFT

La FFT non è un metodo di estrazione LSB; serve per i casi in cui il contenuto è nascosto deliberatamente nello spazio delle frequenze o in pattern sottili.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Strumenti di analisi preliminare basati sul web, spesso usati nei CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Interni PNG: chunk, corruzione e dati nascosti

### Tecnica

PNG è un formato basato su chunk. In molte challenge il payload è memorizzato a livello di container/chunk anziché nei valori dei pixel:

- **Byte extra dopo `IEND`** (molti visualizzatori ignorano i byte finali)
- **Chunk ancillari non standard** che contengono payload; vedi il [flusso di lavoro per l’analisi dei chunk PNG e il carving](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Header corrotti** che nascondono le dimensioni o bloccano i parser finché non vengono corretti

Posizioni dei chunk particolarmente interessanti da esaminare:

- `tEXt` / `iTXt` / `zTXt` (metadati testuali, a volte compressi)
- `iCCP` (profilo ICC) e altri chunk ancillari usati come vettori
- `eXIf` (dati EXIF in PNG)

### Byte di filtro delle scanline PNG come vettore

PNG memorizza un byte del tipo di filtro (0–4) prima di ogni scanline nel flusso `IDAT` decompresso. Questi byte non sono valori dei pixel; i pixel RGB decodificati non conservano le scelte originali dei filtri e la ricodifica può modificarle. Un encoder può variare legittimamente i filtri, ma i pattern deliberati possono codificare un breve messaggio; una challenge recente usava i valori di filtro 1–4 come simboli a due bit. Esamina il **file originale** e concatena tutti i dati `IDAT` prima di decomprimerli. Nel caso seguente di immagini RGB/RGBA non interlacciate a 8 bit, lo stride è pari alla larghezza moltiplicata per il numero di canali; le immagini Adam7 richiedono larghezze delle scanline specifiche per ciascun pass.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Elenco dei byte di filtro delle scanline PNG senza ricodificare</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Eseguilo come `python3 filters.py suspect.png`. Verifica se la sequenza dei filtri, anziché i pixel decodificati, segue una mappatura plausibile dei simboli. La mappatura scelta dipende dalla challenge; la sola variazione non è una prova di steganografia.<sup>[[3]](#references)[[7]](#references)</sup>

### Comandi di triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cosa cercare:

- Combinazioni insolite di larghezza/altezza/profondità di bit/tipo di colore
- Errori CRC/chunk (pngcheck di solito indica l’offset esatto)
- Avvisi sulla presenza di dati aggiuntivi dopo `IEND`

Se serve una visualizzazione più dettagliata dei chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Riferimenti utili:

- Specifica PNG (struttura, chunk): https://www.w3.org/TR/PNG/
- Trucchi sui formati di file (casi limite PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, strumenti nel dominio DCT e limiti di ELA

### Tecnica

JPEG non viene memorizzato come pixel grezzi: viene compresso nel dominio DCT. Per questo gli strumenti stego per JPEG sono diversi dagli strumenti LSB per PNG:

- I payload nei metadata/commenti sono a livello di file (facili da individuare e veloci da ispezionare)
- Gli strumenti stego nel dominio DCT incorporano bit nei coefficienti di frequenza

Dal punto di vista operativo, considera JPEG come:

- Un contenitore per segmenti di metadata (facili da individuare e veloci da ispezionare)
- Un dominio di segnali compressi (coefficienti DCT) in cui operano strumenti stego specializzati

### Controlli rapidi

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Posizioni ad alto segnale:

- Metadati EXIF/XMP/IPTC
- Segmento commento JPEG (`COM`)
- Segmenti applicazione (`APP1` per EXIF, `APPn` per dati del produttore)

### Strumenti comuni

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Se stai cercando specificamente payload steghide nei JPEG, valuta l'uso di `stegseek` (bruteforce più veloce rispetto agli script meno recenti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA evidenzia diversi artefatti di ricompressione; può indicare le regioni che sono state modificate, ma non è di per sé un rilevatore di stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Immagini animate

### Tecnica

Per le immagini animate, presumi che il messaggio sia:

- In un singolo frame (facile), oppure
- Distribuito su più frame (l'ordine è importante), oppure
- Visibile solo confrontando frame consecutivi

### Estrai i frame

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Poi tratta i fotogrammi come normali PNG: `zsteg`, `pngcheck`, isolamento dei canali.

Strumenti alternativi:

- `gifsicle --explode anim.gif` (estrazione rapida dei fotogrammi)
- `imagemagick`/`magick` per le trasformazioni dei singoli fotogrammi

Il frame differencing è spesso decisivo:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Codifica APNG tramite conteggio dei pixel

- Rileva i contenitori APNG: `exiftool -a -G1 file.png | grep -i animation` oppure `file`.
- Estrai i frame senza modificarne la temporizzazione: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Le sfide animate possono codificare ogni byte come il numero di pixel di un colore specifico in ogni fotogramma; concatenando i conteggi si ricostruisce il messaggio.<sup>[[1]](#references)</sup>

## Incorporamento protetto da password

Se sospetti che l’incorporamento sia protetto da una passphrase anziché basarsi su manipolazioni a livello di pixel, di solito questa è la strada più rapida.

### steghide

Supporta `JPEG, BMP, WAV, AU` e può incorporare/estrarre payload cifrati.

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

- [1] [Flagvent 2025 (Medium) — pink, La lista dei desideri di Babbo Natale, Metadati di Natale, Rumore catturato](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Write-up HackVent 2024 — Colori contorti](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Specifica Portable Network Graphics (PNG), terza edizione](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — In profondità c’è qualcosa nell’acqua](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Formati di file immagine Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Specifica GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protocollo Afterimage — write-up CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
