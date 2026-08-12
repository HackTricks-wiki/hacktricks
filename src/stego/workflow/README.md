# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

La maggior parte dei problemi di stego si risolve più rapidamente con un triage sistematico invece di provare tool casuali.

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
Se `file` e l'estensione non coincidono, analizza la signature invece di fidarti del suffisso. Anche `file` si basa su euristiche e può essere tratto in inganno da input malformati o polyglot. Quando appropriato, tratta i formati comuni come container (per esempio, i documenti OOXML sono pacchetti ZIP).<sup>[[2]](#references)</sup>

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
Se l'estrazione fallisce ma vengono riportate delle signature, estrai manualmente gli offset con `dd` e riesegui `file` sulla regione estratta.

#### 4) Se immagine

- Ispeziona le anomalie: `magick identify -verbose file`
- Se PNG/BMP, enumera bit-plane/LSB: `zsteg -a file.png`
- Convalida la struttura PNG: `pngcheck -v file.png`
- Usa filtri visivi (Stegsolve / StegoVeritas) quando il contenuto può essere rivelato da trasformazioni di canale/plane

#### 5) Se audio

- Prima lo spettrogramma (Sonic Visualiser)
- Decodifica/ispeziona gli stream: `ffmpeg -v info -i file -f null -`
- Se l'audio assomiglia a toni strutturati, prova la decodifica DTMF

### Strumenti fondamentali

Questi individuano i casi più frequenti a livello di container: payload nei metadata, byte aggiunti e file embedded camuffati tramite l'estensione.<sup>[[1]](#references)[[3]](#references)</sup>

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
### Contenitori, dati aggiunti e tecniche polyglot

Molte challenge di steganografia consistono in byte aggiuntivi dopo un file valido oppure in archivi incorporati mascherati dall'estensione.

#### Payload aggiunti

Molti formati ignorano i byte finali. Un file ZIP/PDF/script può essere aggiunto a un contenitore immagine/audio.

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

Quando `file` non riesce a identificare il file, cerca i magic bytes con `xxd` e confrontali con le firme note:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Prova `7z` e `unzip` anche se l’estensione non indica che si tratta di un file zip:
```bash
7z l file
unzip -l file
```
### Anomalie adiacenti a stego

Quick links per i pattern che compaiono regolarmente accanto a stego (QR da binario, braille, ecc.).

#### Codici QR da binario

Se la lunghezza di un blob è un quadrato perfetto, potrebbe trattarsi dei pixel grezzi di un'immagine/QR.
```python
import math
math.isqrt(2500)  # 50
```
Helper da binario a immagine:

- Helper dCode per immagini binarie.<sup>[[5]](#references)</sup>

#### Braille

- Traduttore Braille Branah.<sup>[[6]](#references)</sup>

Per raccolte più ampie di utility per la steganografia e risorse specifiche per tecnica, consulta lo stego-toolkit incluso e l'elenco curato da 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Immagine Docker con i tool di steganografia più diffusi raggruppati insieme](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Convenzioni ECMA-376 per l'impacchettamento aperto](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Immagine binaria](https://www.dcode.fr/binary-image)
- [6] [Branah — Traduttore Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Risorse sulla steganografia](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
