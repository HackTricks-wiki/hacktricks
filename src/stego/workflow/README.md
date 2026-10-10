# Workflow di Stego

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi di stego si risolve più rapidamente con un triage sistematico che provando strumenti a caso.

## Flusso principale

### Checklist per il triage rapido

L’obiettivo è rispondere in modo efficiente a due domande:

1. Qual è il container/formato effettivo?
2. Il payload si trova nei metadati, nei byte aggiunti in coda, nei file incorporati o nello stego a livello di contenuto?

#### 1) Identificare il container

```bash
file target
ls -lah target
```

Se `file` e l'estensione non corrispondono, esamina la signature invece di fidarti del suffisso. Anche `file` è euristico e può essere ingannato da input malformati o poliglotti. Quando opportuno, considera i formati comuni come contenitori (per esempio, i documenti OOXML sono pacchetti ZIP).<sup>[[2]](#references)</sup>

#### 2) Cerca metadati e stringhe evidenti

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Prova più codifiche:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Verifica la presenza di dati accodati / file incorporati

```bash
binwalk target
binwalk -e target
```

Se l'estrazione non riesce ma vengono segnalate firme, ritaglia manualmente gli offset con `dd` e riesegui `file` sulla regione ritagliata.

#### 4) Se è un'immagine

- Ispeziona le anomalie: `magick identify -verbose file`
- Se è PNG/BMP, enumera i bit-plane/LSB: `zsteg -a file.png`
- Convalida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visivi (Stegsolve / StegoVeritas) quando il contenuto potrebbe emergere con trasformazioni di canali/plane

#### 5) Se è audio

- Prima lo spettrogramma (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio ricorda toni strutturati, prova la decodifica DTMF

### Strumenti essenziali

Questi rilevano i casi più frequenti a livello di container: payload nei metadati, byte aggiunti e file incorporati camuffati dall'estensione.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Repository del progetto: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Contenitori, dati aggiunti e trucchi poliglotti

Molte sfide di steganografia consistono in byte aggiunti dopo un file valido o in archivi incorporati e camuffati tramite l’estensione.

#### Payload aggiunti

Molti formati ignorano i byte finali. È possibile aggiungere un archivio ZIP/PDF/script a un contenitore immagine/audio.

Controlli rapidi:

```bash
binwalk file
tail -c 200 file | xxd
```

Se conosci un offset, estrai con `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

Quando `file` non riesce a identificare un file, cerca i magic bytes con `xxd` e confrontali con le firme note:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Prova `7z` e `unzip` anche se l’estensione non indica che si tratta di un file zip:

```bash
7z l file
unzip -l file
```

### Curiosità correlate allo stego

Collegamenti rapidi a schemi che si presentano spesso in prossimità dello stego (QR ricavati da dati binari, braille, ecc.).

#### QR code ricavati da dati binari

Se la lunghezza di un blob è un quadrato perfetto, potrebbe contenere i pixel grezzi di un'immagine/QR.

```python
import math
math.isqrt(2500)  # 50
```

Helper da binario a immagine:

- Helper dCode per immagini binarie.<sup>[[5]](#references)</sup>

#### Braille

- Traduttore Braille di Branah.<sup>[[6]](#references)</sup>

Per raccolte più ampie di utility per la steganografia e risorse specifiche per le tecniche, consulta lo stego-toolkit incluso e l’elenco curato da 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Immagine Docker con i più diffusi strumenti di steganografia raccolti insieme](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenzioni di packaging aperto ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Immagine binaria](https://www.dcode.fr/binary-image)
- [6] [Branah — Traduttore Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Risorse sulla steganografia](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
