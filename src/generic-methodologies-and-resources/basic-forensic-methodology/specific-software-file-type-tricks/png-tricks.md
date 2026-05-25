# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

I file **PNG** sono molto comuni in **CTFs**, **incident response** e **malware staging** perché sono **lossless**, basati su **chunk** e molti strumenti li renderizzano volentieri anche quando contengono **metadata** extra, **appended payloads** o **chunk** parzialmente corrotti.

Tratta un PNG come un **container**, non solo come un'immagine.

## Quick triage

Inizia con i controlli a livello di container prima di passare allo stego LSB. Per il workflow bit-plane/LSB, consulta [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Cose utili da cercare:

- **Chunk ancillari inattesi** come `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errori CRC** o lunghezze dei chunk malformate
- **Dati aggiuntivi dopo `IEND`**
- **Più marker `IEND`** o frammenti `IDAT` recuperabili dopo la fine formale del file
- Un file che è un PNG valido **e** che sembra anche un ZIP/PDF/script quando viene caricato

Ricorda che la struttura valida minima è di solito:

- `IHDR` (deve essere il primo)
- `IDAT` (uno o più chunk consecutivi)
- `IEND` (deve essere l'ultimo)

## Dati residui dopo `IEND`

Uno degli artefatti PNG più significativi è **dati aggiunti dopo il chunk `IEND` finale**. Molti decoder li ignorano, il che lo rende utile per:

- **Semplice stego / payload nascosto**
- **PNG polyglots**
- **Staging di malware**
- **Recupero di vecchi dati immagine** da editor difettosi

Rilevamento rapido:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Se vuoi estrarre tutto dopo il `IEND` finale:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Prova anche i parser di archivi generici direttamente contro il PNG o il trailer estratto:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recupero in stile Acropalypse di screenshot ritagliati/redatti

Un trucco forense PNG molto pratico e recente è verificare se un editor di screenshot ha **sovrascritto** un PNG senza **troncare** prima il vecchio file. In quei casi, byte della **previous image** possono rimanere dopo `IEND`, e a volte dati `IDAT` extra possono essere ricostruiti parzialmente.

Questo è diventato molto noto con **aCropalypse** (Google Pixel Markup) e il relativo problema di **Windows Snipping Tool**. In pratica, se un PNG "cropped" o "redacted" contiene ancora vecchi dati finali, potresti riuscire a recuperare parte dello screenshot originale.

Flusso di lavoro pratico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Segnali che giustificano fortemente un’analisi più approfondita:

- `pngcheck` segnala **additional data after `IEND`**
- Trovi **più di un `IEND`**
- Trovi **chunk `IDAT` extra** dopo la fine apparente dell’immagine
- Lo screenshot proviene da un dispositivo/editor noto per essere stato colpito

Se succede, passa il file a un **aCropalypse recovery tool** prima di considerare attendibile la redaction.

## Chunk abuse che conta nella pratica

I chunk PNG più interessanti per le indagini di solito non sono quelli ovvi dell’immagine, ma quelli che possono contenere **text**, **metadata** o **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata di testo e testo compresso
- `eXIf` – dati EXIF dentro PNG
- `iCCP` – profilo ICC incorporato
- `PLTE` – dati della palette nelle immagini indicizzate, ma anche utile in scenari di payload-smuggling

Estraili con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Per la persistenza di payload offensivi all'interno di chunk PNG (per esempio **PLTE**, **IDAT** o trucchi **tEXt** che sopravvivono ad alcune trasformazioni PHP delle immagini), consulta le note più dettagliate focalizzate sugli upload qui:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Riparazione di PNG corrotti

Per controllare l'integrità e individuare l'area esatta danneggiata, **pngcheck** rimane uno dei migliori strumenti iniziali:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se il file è danneggiato invece che intenzionalmente malevolo, **PCRT** può essere utile in CTF e attività di laboratorio per correggere problemi comuni come header errati, valori IHDR sbagliati, problemi CRC o layout dei chunk malformati.

Se il tuo obiettivo è **sanitizzare** un PNG che contiene dati trailer sospetti preservando l'immagine visibile, ExifTool può rimuovere esplicitamente il trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Per evidenze sensibili, lavora sempre su una **copia** e conserva gli hash dell’originale prima di tentare riparazioni.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
