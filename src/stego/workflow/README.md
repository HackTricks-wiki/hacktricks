# Stego Flusso di lavoro

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi stego si risolve più velocemente con un triage sistematico che provando strumenti a caso.

## Flusso principale

### Checklist di triage rapido

L'obiettivo è rispondere efficacemente a due domande:

1. Qual è il vero container/formato?
2. Il payload è in metadata, appended bytes, embedded files, o content-level stego?

#### 1) Identificare il container
```bash
file target
ls -lah target
```
Se `file` e l'estensione non corrispondono, fidati di `file`. Considera i formati comuni come contenitori quando appropriato (ad es., i documenti OOXML sono file ZIP).

#### 2) Cerca metadata e stringhe ovvie
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
#### 3) Controlla la presenza di dati aggiunti / file incorporati
```bash
binwalk target
binwalk -e target
```
Se l'estrazione fallisce ma vengono segnalate signatures, effettua il carving manuale degli offset con `dd` e rilancia `file` sulla regione ricavata.

#### 4) Se è un'immagine

- Ispeziona anomalie: `magick identify -verbose file`
- Se PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Valida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visivi (Stegsolve / StegoVeritas) quando il contenuto può emergere da trasformazioni di canale/piano

#### 5) Se è un file audio

- Prima lo spettrogramma (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio assomiglia a toni strutturati, verifica la decodifica DTMF

### Strumenti essenziali

Questi catturano i casi ad alta frequenza a livello di container: metadata payloads, appended bytes, e embedded files camuffati dall'estensione.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
Per favore incolla qui il contenuto di src/stego/workflow/README.md che vuoi tradurre (mantieni intatti percorsi, tag e link).
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contenitori, dati aggiunti e polyglot tricks

Molte challenge di steganography sono byte extra dopo un file valido, o archivi incorporati mascherati dall'estensione.

#### Payloads aggiunti

Molti formati ignorano i byte finali. Un ZIP/PDF/script può essere appeso a un container immagine/audio.

Controlli rapidi:
```bash
binwalk file
tail -c 200 file | xxd
```
Se conosci un offset, carve con `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Byte magici

Quando `file` è confuso, cerca byte magici con `xxd` e confrontali con firme note:
```bash
xxd -g 1 -l 32 file
```
#### Zip camuffato

Prova `7z` e `unzip` anche se l'estensione non indica zip:
```bash
7z l file
unzip -l file
```
### Stranezze vicino a stego

Link rapidi per schemi che compaiono regolarmente adiacenti a stego (QR-from-binary, braille, etc).

#### QR codes from binary

Se la lunghezza del blob è un quadrato perfetto, potrebbe essere pixel grezzi per un'immagine/QR.
```python
import math
math.isqrt(2500)  # 50
```
Strumento per convertire binario in immagine:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Elenchi di riferimento

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
