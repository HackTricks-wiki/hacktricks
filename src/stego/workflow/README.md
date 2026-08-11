# Workflow di Stego

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi di stego si risolve più velocemente con un triage sistematico che provando strumenti casuali.

## Flusso principale

### Checklist di triage rapido

L'obiettivo è rispondere in modo efficiente a due domande:

1. Qual è il vero contenitore/formato?
2. Il payload si trova nei metadati, nei byte aggiunti, nei file incorporati o nello stego a livello di contenuto?

#### 1) Identificare il contenitore
```bash
file target
ls -lah target
```
Se `file` e l'estensione non corrispondono, esamina la firma invece di fidarti del suffisso. Anche `file` è euristico e può essere ingannato da input malformati o poliglotti. Tratta i formati comuni come contenitori quando appropriato (ad esempio, i documenti OOXML sono pacchetti ZIP).<sup>[[2]](#references)</sup>

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
#### 3) Verifica la presenza di dati aggiunti / file incorporati
```bash
binwalk target
binwalk -e target
```
Se l'estrazione fallisce ma vengono riportate delle firme, individua manualmente gli offset con `dd` ed esegui nuovamente `file` sulla regione estratta.

#### 4) Se immagine

- Ispeziona le anomalie: `magick identify -verbose file`
- Se PNG/BMP, enumera bit-plane/LSB: `zsteg -a file.png`
- Convalida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visivi (Stegsolve / StegoVeritas) quando il contenuto può essere rivelato tramite trasformazioni di canale/plane

#### 5) Se audio

- Prima lo spettrogramma (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio assomiglia a toni strutturati, prova il decoding DTMF

### Strumenti essenziali

Questi rilevano i casi più frequenti a livello di container: payload nei metadati, byte aggiunti e file incorporati camuffati tramite l'estensione.<sup>[[1]](#references)[[3]](#references)</sup>

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
#### file / stringhe
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contenitori, dati accodati e tecniche polyglot

Molte sfide di steganografia consistono in byte aggiuntivi dopo un file valido o in archivi incorporati mascherati dall’estensione.

#### Payload accodati

Molti formati ignorano i byte finali. È possibile accodare uno ZIP/PDF/script a un contenitore di immagini o audio.

Controlli rapidi:
```bash
binwalk file
tail -c 200 file | xxd
```
Se conosci un offset, esegui il carving con `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Quando `file` è confuso, cerca i magic bytes con `xxd` e confrontali con firme note:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prova `7z` e `unzip` anche se l’estensione non indica che si tratta di uno zip:
```bash
7z l file
unzip -l file
```
### Anomalie near-stego

Quick links per pattern che compaiono regolarmente accanto a stego (QR-from-binary, braille, ecc.).

#### Codici QR da binary

Se la lunghezza di un blob è un quadrato perfetto, potrebbe trattarsi di pixel grezzi per un'immagine/QR.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Immagine Docker con i più popolari strumenti di steganografia inclusi](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenzioni ECMA-376 per l'impacchettamento aperto](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [ReFirmLabs/binwalk](https://github.com/korczis/foremost)
- [5] [dCode — Immagine binaria](https://www.dcode.fr/binary-image)
- [6] [Branah — Traduttore Braille](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
