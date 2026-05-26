# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

I file **PNG** sono molto comuni nei **CTFs**, nell'**incident response** e nello **staging malware** perché sono **lossless**, basati su **chunk**, e molti tool li renderanno volentieri anche quando contengono **extra metadata**, **appended payloads** o **chunk parzialmente corrotti**.

Considera un PNG come un **container**, non solo come un'immagine.

## Quick triage

Inizia con controlli a livello di container prima di passare allo stego LSB. Per il workflow bit-plane/LSB, consulta [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Cose utili da cercare:

- **Chunk ausiliari inaspettati** come `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errori CRC** o lunghezze dei chunk malformate
- **Dati aggiuntivi dopo `IEND`**
- **Più marker `IEND`** o frammenti `IDAT` recuperabili dopo la fine formale del file
- Un file che è un PNG valido **e** sembra anche un ZIP/PDF/script quando estratto

Ricorda che la struttura minima valida è di solito:

- `IHDR` (deve essere il primo)
- `IDAT` (uno o più chunk consecutivi)
- `IEND` (deve essere l'ultimo)

## Dati residui dopo `IEND`

Uno degli artefatti PNG con il segnale più forte è **dati aggiunti dopo il chunk `IEND` finale**. Molti decoder li ignorano, il che lo rende utile per:

- **Stego semplice / payload nascosto**
- **PNG polyglots**
- **Staging di malware**
- **Recupero di dati immagine più vecchi** da editor difettosi

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
Inoltre prova direttamente i parser generici di archivi contro il PNG o il trailer estratto:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recupero in stile Acropalypse di screenshot ritagliati/redatti

Un trucco forense PNG molto pratico e recente è controllare se un editor di screenshot ha **sovrascritto** un PNG senza **troncare** prima il vecchio file. In questi casi, byte della **previous image** possono rimanere dopo `IEND`, e talvolta dati `IDAT` extra possono essere parzialmente ricostruiti.

Questo è diventato molto noto con **aCropalypse** (Google Pixel Markup) e il relativo problema di **Windows Snipping Tool**. In pratica, se un PNG "cropped" o "redacted" contiene ancora vecchi dati residui alla fine, potresti essere in grado di recuperare parte dello screenshot originale.

Workflow pratico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Segnali che giustificano fortemente un'analisi più approfondita:

- `pngcheck` segnala **additional data after `IEND`**
- Trovi **più di un `IEND`**
- Trovi **extra `IDAT` chunks** dopo la fine apparente dell'immagine
- Lo screenshot proviene da un dispositivo/editor noto per essere stato affetto

Se succede, passa il file a uno strumento di recupero **aCropalypse** prima di considerare affidabile la redazione.

## Chunk abuse che conta nella pratica

I PNG chunks più interessanti per le indagini di solito non sono quelli dell'immagine più ovvi, ma i chunks che possono contenere **text**, **metadata**, o **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata e text compresso
- `eXIf` – dati EXIF dentro PNG
- `iCCP` – profilo ICC incorporato
- `PLTE` – dati della palette nelle immagini indicizzate, ma anche utile in scenari di payload-smuggling

Estraili con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Per la persistenza di payload offensivi all’interno dei chunk PNG (per esempio **PLTE**, **IDAT**, o trucchi **tEXt** che sopravvivono ad alcune trasformazioni delle immagini in PHP), consulta le note più dettagliate focalizzate sugli upload qui:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Riparazione di PNG corrotti

Per verificare l'integrità e individuare l'area esatta danneggiata, **pngcheck** rimane uno dei migliori primi strumenti:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se il file è danneggiato invece che intenzionalmente malevolo, **PCRT** può essere utile in CTF e lavori di laboratorio per correggere problemi comuni come header errati, valori IHDR sbagliati, problemi CRC o layout dei chunk malformati.

Se il tuo obiettivo è **sanitizzare** un PNG che contiene dati trailer sospetti mantenendo l'immagine visibile, ExifTool può rimuovere esplicitamente il trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Per evidenze sensibili, lavora sempre su una **copia** e conserva gli hash dell'originale prima di tentare riparazioni.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
