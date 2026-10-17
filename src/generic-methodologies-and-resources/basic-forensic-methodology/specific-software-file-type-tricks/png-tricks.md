# PNG-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-Dateien** sind in **CTFs**, bei der **Incident Response** und beim **Malware-Staging** sehr verbreitet, da sie **verlustfrei** und **chunkbasiert** sind und viele Tools sie problemlos darstellen, selbst wenn sie **zusätzliche Metadaten**, **angehängte Payloads** oder **teilweise beschädigte Chunks** enthalten.

Behandle eine PNG-Datei als **Container**, nicht nur als Bild.

## Schnelle Triage

Beginne mit Prüfungen auf Containerebene, bevor du dich mit LSB-Stego beschäftigst. Informationen zum Bit-Plane-/LSB-Workflow findest du auf der [dedizierten Seite zu Image-Stego](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Nützliche Dinge, auf die du achten solltest:

- **Unerwartete Zusatz-Chunks** wie `tEXt`, `zTXt`, `iTXt`, `eXIf` oder `iCCP`
- **CRC-Fehler** oder fehlerhafte Chunk-Längen
- **Zusätzliche Daten nach `IEND`**
- **Mehrere `IEND`-Marker** oder wiederherstellbare `IDAT`-Fragmente nach dem offiziellen Dateiende
- Eine Datei, die ein gültiges PNG ist **und** beim Carving wie eine ZIP-, PDF- oder Script-Datei aussieht

Beachte: Die minimale gültige Struktur besteht normalerweise aus:

- `IHDR` (muss an erster Stelle stehen)
- `IDAT` (ein oder mehrere aufeinanderfolgende Chunks)
- `IEND` (muss an letzter Stelle stehen)

## Nachgestellte Daten nach `IEND`

Eines der aussagekräftigsten PNG-Artefakte sind **Daten, die nach dem letzten `IEND`-Chunk angehängt wurden**. Viele Decoder ignorieren sie, was sie nützlich macht für:

- **Einfache Stego / versteckte Payloads**
- **PNG-Polyglots**
- **Malware-Staging**
- **Wiederherstellung älterer Bilddaten** von fehlerhaften Editoren

Schnellerkennung:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Eine Byte-Suche nach `IEND` ist nur ein Hinweis: Dieselben Bytes können in Chunk-Daten oder einem gefälschten Trailer vorkommen. Um zuverlässig zu extrahieren, durchlaufe die längenpräfixierten Chunks ab der PNG-Signatur und stoppe beim ersten strukturellen `IEND`; der [untenstehende Chunk-Parser](#extract-ancillary-chunk-payloads) speichert auch den Trailer.<sup>[[6]](#references)</sup>

Probiere außerdem generische Archiv-Parser direkt mit der PNG-Datei oder dem extrahierten Trailer aus:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Wiederherstellung zugeschnittener/geschwärzter Screenshots nach Art von Acropalypse

Ein sehr praktischer neuerer PNG-Forensik-Trick besteht darin zu prüfen, ob ein Screenshot-Editor eine PNG-Datei **überschrieben** hat, ohne die alte Datei vorher **abzuschneiden**. In solchen Fällen können Bytes des **vorherigen Bildes** nach `IEND` erhalten bleiben, und manchmal lassen sich zusätzliche `IDAT`-Daten teilweise rekonstruieren.

Bekannt wurde dies durch **aCropalypse** (Google Pixel Markup) und den damit zusammenhängenden Fehler im **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Wenn eine „zugeschnittene“ oder „geschwärzte“ PNG-Datei in der Praxis noch alte nachgestellte Daten enthält, kannst du möglicherweise einen Teil des ursprünglichen Screenshots wiederherstellen.<sup>[[1]](#references)</sup>

Praktische Vorgehensweise:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Anzeichen, die eine eingehendere Analyse dringend rechtfertigen:

- `pngcheck` meldet **zusätzliche Daten nach `IEND`**
- Du findest **mehr als ein `IEND`**
- Du findest **zusätzliche `IDAT`-Chunks** nach dem scheinbaren Ende des Bildes
- Der Screenshot stammt von einem Gerät/Editor, von dem bekannt ist, dass es betroffen war

Wenn dies der Fall ist, verarbeite die Datei mit einem **aCropalypse-Recovery-Tool**, bevor du der Schwärzung vertraust.

## Chunk-Missbrauch, der in der Praxis relevant ist

Die interessantesten PNG-Chunks für Untersuchungen sind meist nicht die offensichtlichen Bild-Chunks, sondern jene, die **Text**, **Metadaten** oder **Payload-Bytes** enthalten können:

- `tEXt` / `zTXt` / `iTXt` – Textmetadaten und komprimierter Text
- `eXIf` – EXIF-Daten in PNG
- `iCCP` – eingebettetes ICC-Profil
- `PLTE` – Palettendaten in indizierten Bildern, aber auch nützlich in Szenarien mit Payload-Schmuggel.<sup>[[2]](#references)</sup>

Gib sie aus mit:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Für die Persistenz offensiver Payloads in PNG-Chunks (zum Beispiel **PLTE**-, **IDAT**- oder **tEXt**-Tricks, die einige PHP-Bildtransformationen überstehen), findest du hier ausführlichere Hinweise mit Fokus auf Uploads:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Ancillary-Chunk-Payloads extrahieren

Ein Angreifer kann beliebige Bytes in einem **unbekannten Ancillary-Chunk vor `IEND`** platzieren. Gewöhnliche PNG-Decoder können einen unbekannten Ancillary-Chunk ignorieren, während ein Skript, das das Bild als Bytes abruft, die Payload lesen und verwenden kann; das bloße Öffnen der PNG-Datei führt sie nicht aus.<sup>[[4]](#references)[[6]](#references)</sup> Die ursprüngliche Forschung demonstrierte einen komprimierten und verschlüsselten benutzerdefinierten Chunk.<sup>[[4]](#references)</sup> Ein späteres Browserbeispiel verwendete die extrahierten Bytes, um HTML oder einen Download bereitzustellen.<sup>[[5]](#references)</sup>

Ein kleingeschriebener erster Buchstabe des Chunk-Typs bedeutet *ancillary*; ein kleingeschriebener zweiter Buchstabe bedeutet *private*. Zum Beispiel ist `paMP` privat, während `pAMP` den öffentlichen Namensraum verwendet, obwohl letzteres für die Demonstration erfunden wurde.<sup>[[4]](#references)[[6]](#references)</sup> Ein Chunk hat die Struktur `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; die CRC umfasst Typ und Daten. Verarbeite diese Struktur, anstatt in komprimierten `IDAT`-Daten nach einem Typnamen zu suchen. Der folgende Parser prüft Grenzen und CRCs, exportiert Ancillary-Payloads als rohe Bytes und schreibt alle Bytes nach dem strukturellen `IEND` in `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Ancillary-Chunks und den PNG-Trailer extrahieren</summary>

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

Untersuche extrahierte Bytes mit `file`, `strings` oder `binwalk`; dekomprimiere sie nur, wenn der Carrier tatsächlich komprimiert ist.<sup>[[4]](#references)</sup> Eine erneute Kodierung kann den Carrier entfernen. Vergleiche daher die hochgeladenen und abgerufenen Bytes, bevor du dich darauf verlässt.<sup>[[2]](#references)[[6]](#references)</sup>

## Beschädigte PNG-Dateien reparieren

Um die Integrität zu prüfen und den genauen beschädigten Bereich zu lokalisieren, ist **pngcheck** nach wie vor eines der besten ersten Tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Wenn die Datei beschädigt und nicht absichtlich bösartig ist, kann **PCRT** bei CTFs und in Laborumgebungen nützlich sein, um häufige Probleme wie fehlerhafte Header, falsche IHDR-Werte, CRC-Probleme oder fehlerhafte Chunk-Strukturen zu beheben.

Wenn du eine PNG-Datei mit verdächtigen Daten am Ende **bereinigen** und dabei das sichtbare Bild erhalten möchtest, kann ExifTool diese Daten explizit entfernen:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Bewahren Sie bei sensiblen Beweismitteln immer eine **Kopie** auf und sichern Sie die Hashes des Originals, bevor Sie Reparaturen versuchen.



## References

- [1] [aCropalypse ausnutzen: abgeschnittene PNGs wiederherstellen](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistente PHP-Payloads in PNGs: PHP-Code in ein Bild einschleusen – und dort behalten](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Ancillary-Chunks sind der perfekte Ort, um vertrauliche Informationen zu speichern](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Gültige Ancillary-Chunks verwenden, um Daten an einen Endpunkt zu schmuggeln](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG)-Spezifikation (Dritte Ausgabe)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
