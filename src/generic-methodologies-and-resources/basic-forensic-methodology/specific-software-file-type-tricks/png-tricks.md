# Trucchi per PNG

{{#include ../../../banners/hacktricks-training.md}}

I **file PNG** sono molto comuni nei **CTF**, nell'**incident response** e nel **malware staging** perché sono **lossless**, basati su **chunk** e molti strumenti li visualizzano senza problemi anche quando contengono **metadati extra**, **payload aggiunti** o **chunk parzialmente corrotti**.

Considera un PNG come un **contenitore**, non solo come un'immagine.

## Triage rapido

Inizia con i controlli a livello di contenitore prima di passare allo stego LSB. Per il workflow bit-plane/LSB, consulta [la pagina dedicata allo stego delle immagini](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Cose utili da cercare:

- **Chunk ancillari imprevisti** come `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errori CRC** o lunghezze dei chunk malformate
- **Dati aggiuntivi dopo `IEND`**
- **Più marker `IEND`** o frammenti `IDAT` recuperabili dopo la fine formale del file
- Un file che è un PNG valido **e** che, durante il carving, appare anche come ZIP/PDF/script

Ricorda che la struttura minima valida solitamente è:

- `IHDR` (deve essere il primo)
- `IDAT` (uno o più chunk consecutivi)
- `IEND` (deve essere l'ultimo)

## Dati finali dopo `IEND`

Uno degli artefatti PNG con il **segnale più evidente** è rappresentato dai **dati aggiunti dopo il chunk `IEND` finale**. Molti decoder li ignorano, rendendoli utili per:

- **Stego semplice / payload nascosti**
- **PNG polyglot**
- **Malware staging**
- **Recuperare dati immagine precedenti** da editor difettosi

Rilevamento rapido:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Se vuoi estrarre tutto ciò che si trova dopo l'ultimo `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Prova anche direttamente i parser generici per archivi sul PNG o sul trailer recuperato:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recupero in stile Acropalypse di screenshot ritagliati/redatti

Una tecnica forense PNG molto pratica e recente consiste nel verificare se un editor di screenshot ha **sovrascritto** un PNG senza prima **troncare** il vecchio file. In questi casi, i byte della **immagine precedente** possono rimanere dopo `IEND` e, talvolta, è possibile ricostruire parzialmente dati `IDAT` aggiuntivi.

La tecnica è diventata nota con **aCropalypse** (Google Pixel Markup) e con il problema correlato dello **Strumento di cattura di Windows**.<sup>[[3]](#references)</sup> In pratica, se un PNG "ritagliato" o "redatto" contiene ancora vecchi dati in coda, potrebbe essere possibile recuperare parte dello screenshot originale.<sup>[[1]](#references)</sup>

Flusso di lavoro pratico:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Segnali che giustificano fortemente un'analisi più approfondita:

- `pngcheck` segnala **dati aggiuntivi dopo `IEND`**
- Trovi **più di un `IEND`**
- Trovi **chunk `IDAT` aggiuntivi** dopo la fine apparente dell'immagine
- Lo screenshot proviene da un dispositivo/editor noto per essere stato interessato

Se ciò accade, sottoponi il file a un **aCropalypse recovery tool** prima di considerare affidabile la redazione.

## Chunk abuse rilevante nella pratica

I chunk PNG più interessanti per le indagini di solito non sono quelli ovvi dell'immagine, ma quelli che possono contenere **testo**, **metadati** o **byte di payload**:

- `tEXt` / `zTXt` / `iTXt` – metadati testuali e testo compresso
- `eXIf` – dati EXIF all'interno del PNG
- `iCCP` – profilo ICC incorporato
- `PLTE` – dati della palette nelle immagini indicizzate, ma utili anche negli scenari di payload-smuggling.<sup>[[2]](#references)</sup>

Esegui il dump con:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Per la persistenza di payload offensivi all'interno dei chunk PNG (ad esempio trucchi con **PLTE**, **IDAT** o **tEXt** che sopravvivono ad alcune trasformazioni di immagini PHP), consulta le note più dettagliate incentrate sugli upload qui:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Riparazione di PNG corrotti

Per verificare l'integrità e individuare l'area esatta danneggiata, **pngcheck** rimane uno dei migliori strumenti iniziali:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se il file è danneggiato anziché intenzionalmente malevolo, **PCRT** può essere utile nei CTF e nelle attività di laboratorio per correggere problemi comuni come header errati, valori IHDR non corretti, problemi CRC o strutture di chunk malformate.

Se il tuo obiettivo è **sanitizzare** un PNG che contiene dati trailer sospetti preservando al contempo l'immagine visibile, ExifTool può rimuovere esplicitamente il trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Per le prove sensibili, lavora sempre su una **copia** e conserva gli hash dell'originale prima di tentare riparazioni.

## References

- [1] [Sfruttare aCropalypse: recuperare PNG troncati](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payload PHP persistenti nei PNG: come iniettare codice PHP in un'immagine e mantenerlo](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
