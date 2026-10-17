# Trucchi PNG

{{#include ../../../banners/hacktricks-training.md}}

I **file PNG** sono molto comuni nei **CTF**, nella **risposta agli incidenti** e nello **staging di malware**, perché sono **senza perdita**, **basati su chunk** e molti strumenti li visualizzano senza problemi anche quando contengono **metadati extra**, **payload aggiunti in coda** o **chunk parzialmente danneggiati**.

Considera un PNG come un **contenitore**, non solo come un'immagine.

## Analisi preliminare rapida

Inizia dai controlli a livello di contenitore prima di passare alla steganografia LSB. Per il flusso di lavoro bit-plane/LSB, consulta [la pagina dedicata alla steganografia nelle immagini](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Cose utili da cercare:

- **Chunk ancillary inattesi** come `tEXt`, `zTXt`, `iTXt`, `eXIf` o `iCCP`
- **Errori CRC** o lunghezze dei chunk malformate
- **Dati aggiuntivi dopo `IEND`**
- **Più marker `IEND`** o frammenti `IDAT` recuperabili dopo la fine formale del file
- Un file che è un PNG valido **e** sembra anche uno ZIP/PDF/script quando viene estratto

Ricorda che la struttura minima valida è di solito:

- `IHDR` (deve essere il primo)
- `IDAT` (uno o più chunk consecutivi)
- `IEND` (deve essere l'ultimo)

## Dati finali dopo `IEND`

Uno degli artefatti PNG più indicativi è la **presenza di dati aggiunti dopo il chunk `IEND` finale**. Molti decoder li ignorano, il che li rende utili per:

- **Stego semplice / payload nascosti**
- **PNG polyglot**
- **Preparazione di malware**
- **Recupero di dati immagine precedenti** da editor difettosi

Rilevamento rapido:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Una ricerca di byte per `IEND` è solo un indizio: gli stessi byte possono comparire nei dati dei chunk o in un trailer contraffatto. Per estrarre i dati in modo affidabile, percorri i chunk con prefisso di lunghezza a partire dalla signature PNG e fermati al primo `IEND` strutturale; il [walker dei chunk qui sotto](#extract-ancillary-chunk-payloads) salva anche il trailer.<sup>[[6]](#references)</sup>

Prova anche a usare parser di archivi generici direttamente sul PNG o sul trailer estratto:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Recupero in stile Acropalypse di screenshot ritagliati/oscurati

Un trucco forense PNG molto pratico e recente consiste nel verificare se un editor di screenshot ha **sovrascritto** un PNG senza prima **troncare** il vecchio file. In questi casi, dopo `IEND` possono rimanere byte della **immagine precedente** e, talvolta, è possibile ricostruire parzialmente dati `IDAT` aggiuntivi.

La questione è diventata nota con **aCropalypse** (Google Pixel Markup) e il problema correlato del **Windows Snipping Tool**.<sup>[[3]](#references)</sup> In pratica, se un PNG "ritagliato" o "oscurato" contiene ancora dati residui in coda, potresti riuscire a recuperare parte dello screenshot originale.<sup>[[1]](#references)</sup>

Procedura pratica:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Segnali che giustificano fortemente un’analisi più approfondita:

- `pngcheck` segnala **dati aggiuntivi dopo `IEND`**
- Trovi **più di un `IEND`**
- Trovi **chunk `IDAT` aggiuntivi** dopo la fine apparente dell’immagine
- Lo screenshot proviene da un dispositivo/editor che risulta essere stato interessato dal problema

Se succede, sottoponi il file a uno **strumento di recupero aCropalypse** prima di considerare affidabile la redazione.

## Abuso dei chunk rilevante nella pratica

I chunk PNG più interessanti per le indagini di solito non sono quelli ovvi dell’immagine, ma quelli che possono contenere **testo**, **metadati** o **byte di payload**:

- `tEXt` / `zTXt` / `iTXt` – metadati testuali e testo compresso
- `eXIf` – dati EXIF all’interno di PNG
- `iCCP` – profilo ICC incorporato
- `PLTE` – dati della palette nelle immagini indicizzate, ma utile anche negli scenari di occultamento del payload.<sup>[[2]](#references)</sup>

Estraili con:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Per la persistenza di payload offensivi nei chunk PNG (per esempio, trucchi con **PLTE**, **IDAT** o **tEXt** che sopravvivono ad alcune trasformazioni di immagini in PHP), consulta qui le note più dettagliate incentrate sugli upload:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Estrazione dei payload dai chunk ancillari

Un attaccante può inserire byte arbitrari in un **chunk ancillare sconosciuto prima di `IEND`**. I normali decoder PNG possono ignorare un chunk ancillare sconosciuto, mentre uno script che recupera l’immagine come sequenza di byte può leggere e usare il payload; aprire il PNG da solo non lo esegue.<sup>[[4]](#references)[[6]](#references)</sup> La ricerca originale ha dimostrato un chunk personalizzato compresso e cifrato.<sup>[[4]](#references)</sup> Un successivo esempio per browser ha usato i byte estratti per fornire HTML o un download.<sup>[[5]](#references)</sup>

Una lettera minuscola come primo carattere del tipo di chunk indica che è *ancillare*; una lettera minuscola come secondo carattere indica che è *privato*. Per esempio, `paMP` è privato, mentre `pAMP` usa lo spazio dei nomi pubblico, anche se quest’ultimo è stato inventato per la dimostrazione.<sup>[[4]](#references)[[6]](#references)</sup> Un chunk ha la struttura `lunghezza (4 byte, big-endian) | tipo (4 byte) | dati | CRC (4 byte)`; il CRC copre tipo e dati. Analizza questa struttura invece di cercare un nome di tipo all’interno dei dati `IDAT` compressi. Il seguente parser verifica i limiti e i CRC, esporta i payload dei chunk ancillari come byte grezzi e scrive tutti i byte successivi a `IEND` strutturale in `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Estrazione dei chunk ancillari e del trailer PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Esamina i byte estratti con `file`, `strings` o `binwalk`; decomprimili solo se il contenitore è effettivamente compresso.<sup>[[4]](#references)</sup> La ricodifica potrebbe rimuovere il contenitore, quindi confronta i byte caricati e quelli recuperati prima di farci affidamento.<sup>[[2]](#references)[[6]](#references)</sup>

## Riparazione di PNG corrotti

Per verificare l’integrità e individuare l’area esatta danneggiata, **pngcheck** resta uno dei migliori strumenti da provare per primo:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se il file è danneggiato, anziché intenzionalmente malevolo, **PCRT** può essere utile nei CTF e nel lavoro in laboratorio per correggere problemi comuni, come intestazioni errate, valori IHDR sbagliati, problemi CRC o strutture dei chunk malformate.

Se il tuo obiettivo è **sanitizzare** un PNG che contiene dati sospetti in coda preservando l’immagine visibile, ExifTool può rimuovere esplicitamente i dati in coda:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Per le prove sensibili, lavora sempre su una **copia** e conserva gli hash dell'originale prima di tentare riparazioni.



## References

- [1] [Sfruttare aCropalypse: recuperare PNG troncati](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payload PHP persistenti nei PNG: come iniettare codice PHP in un'immagine e mantenerlo lì](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [I chunk ancillari sono il luogo perfetto per nascondere informazioni sensibili](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Usare chunk ancillari validi per introdurre di nascosto dati in un endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Specifiche Portable Network Graphics (PNG) (terza edizione)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
