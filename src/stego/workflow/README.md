# Flusso di lavoro Stego

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi stego si risolve più velocemente con un triage sistematico che provando strumenti a caso.

## Flusso principale

### Lista di controllo per il triage rapido

L'obiettivo è rispondere a due domande in modo efficiente:

1. Qual è il vero contenitore/formato?
2. Il payload è nei metadati, in byte aggiunti, in file incorporati o in stego a livello di contenuto?

#### 1) Identificare il contenitore
```bash
file target
ls -lah target
```
Se `file` e l'estensione non corrispondono, fidati di `file`. Considera i formati comuni come container quando appropriato (ad es., i documenti OOXML sono file ZIP).

#### 2) Cerca metadati e stringhe ovvie
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
#### 3) Controllare dati aggiunti / file incorporati
```bash
binwalk target
binwalk -e target
```
Se l'estrazione fallisce ma vengono segnalate delle signatures, carve manualmente gli offset con `dd` e riesegui `file` sulla regione carveata.

#### 4) Se immagine

- Ispeziona anomalie: `magick identify -verbose file`
- Se PNG/BMP, enumera bit-planes/LSB: `zsteg -a file.png`
- Valida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visuali (Stegsolve / StegoVeritas) quando il contenuto può essere rivelato da trasformazioni di channel/plane

#### 5) Se audio

- Spettrogramma prima (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio somiglia a toni strutturati, prova la decodifica DTMF

### Strumenti principali

Questi coprono i casi più frequenti a livello container: metadata payloads, appended bytes e embedded files camuffati dall'estensione.

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
#### file / stringhe
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Contenitori, dati aggiunti, e polyglot tricks

Molte challenge di steganography consistono in byte extra dopo un file valido, o in archivi embedded mascherati dall'estensione.

#### Payloads aggiunti

Molti formati ignorano i byte finali. A ZIP/PDF/script può essere appeso a un contenitore immagine/audio.

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
#### Magic bytes

Quando `file` è confuso, cerca i magic bytes con `xxd` e confrontali con firme conosciute:
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

Link rapidi per schemi che compaiono regolarmente adiacenti a stego (QR-from-binary, braille, ecc).

#### QR codes from binary

Se la lunghezza di un blob è un quadrato perfetto, potrebbe trattarsi di pixel grezzi per un'immagine/QR.
```python
import math
math.isqrt(2500)  # 50
```
Convertitore da binario a immagine:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Liste di riferimento

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
