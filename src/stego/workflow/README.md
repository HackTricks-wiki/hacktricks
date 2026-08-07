# Workflow di Stego

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi di stego si risolve più rapidamente con un triage sistematico che provando strumenti casuali.

## Flusso principale

### Checklist per il quick triage

L'obiettivo è rispondere in modo efficiente a due domande:

1. Qual è il container/formato reale?
2. Il payload si trova nei metadata, nei byte aggiunti, nei file embedded o nello stego a livello di contenuto?

#### 1) Identificare il container
```bash
file target
ls -lah target
```
Se `file` e l'estensione non corrispondono, fidati di `file`. Considera i formati comuni come container quando appropriato (ad esempio, i documenti OOXML sono file ZIP).

#### 2) Cerca i metadata e le stringhe evidenti
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Prova diverse codifiche:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Verifica la presenza di dati aggiunti / file incorporati
```bash
binwalk target
binwalk -e target
```
Se l'estrazione fallisce ma vengono segnalate delle signatures, estrai manualmente gli offset con `dd` ed esegui nuovamente `file` sulla regione estratta.

#### 4) Se è un'immagine

- Ispeziona le anomalie: `magick identify -verbose file`
- Se è un PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Convalida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visivi (Stegsolve / StegoVeritas) quando il contenuto può essere rivelato tramite trasformazioni di canale/piano

#### 5) Se è un audio

- Prima genera lo spettrogramma (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio assomiglia a toni strutturati, prova la decodifica DTMF

### Strumenti fondamentali

Questi individuano i casi più frequenti a livello di container: payload nei metadata, byte aggiunti e file embedded camuffati tramite l'estensione.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

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
### Contenitori, dati aggiunti e tecniche polyglot

Molte challenge di steganografia consistono in byte aggiuntivi dopo un file valido oppure in archivi incorporati mascherati dall'estensione.

#### Payload aggiunti

Molti formati ignorano i byte finali. Un ZIP/PDF/script può essere aggiunto a un contenitore immagine/audio.

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

Quando `file` è confuso, cerca i magic bytes con `xxd` e confrontali con le firme note:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prova `7z` e `unzip` anche se l’estensione non indica zip:
```bash
7z l file
unzip -l file
```
### Anomalie vicine allo stego

Collegamenti rapidi agli schemi che compaiono regolarmente accanto allo stego (QR da dati binari, braille, ecc.).

#### Codici QR da dati binari

Se la lunghezza di un blob è un quadrato perfetto, potrebbe trattarsi di pixel grezzi per un'immagine/QR.
```python
import math
math.isqrt(2500)  # 50
```
Helper da binario a immagine:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Riferimenti

- [1] [DominicBreuker/stego-toolkit - Immagine Docker con i tool di steganography più diffusi integrati](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
