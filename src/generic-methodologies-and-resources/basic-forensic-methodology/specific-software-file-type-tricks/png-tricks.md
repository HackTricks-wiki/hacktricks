# PNG Tricks

**PNG-Dateien** sind in **CTFs**, der **Incident Response** und beim **Malware Staging** sehr verbreitet, da sie **verlustfrei**, **chunk-basiert** und viele Tools sie problemlos rendern, selbst wenn sie **zusätzliche Metadaten**, **angehängte Payloads** oder **teilweise beschädigte Chunks** enthalten.

Behandle eine PNG-Datei als **Container**, nicht nur als Bild.

## Schnelle Triage

Beginne mit Prüfungen auf Containerebene, bevor du dich mit LSB-Stego beschäftigst. Für den Bit-Plane-/LSB-Workflow siehe [die spezielle Seite zu Image Stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nützliche Dinge, nach denen du suchen solltest:

- **Unerwartete zusätzliche Chunks** wie `tEXt`, `zTXt`, `iTXt`, `eXIf` oder `iCCP`
- **CRC-Fehler** oder fehlerhafte Chunk-Längen
- **Zusätzliche Daten nach `IEND`**
- **Mehrere `IEND`-Marker** oder wiederherstellbare `IDAT`-Fragmente nach dem formalen Dateiende
- Eine Datei, die ein gültiges PNG ist **und** beim Carving wie ein ZIP/PDF/Script aussieht

Denke daran, dass die minimale gültige Struktur normalerweise so aussieht:

- `IHDR` (muss zuerst kommen)
- `IDAT` (ein oder mehrere aufeinanderfolgende Chunks)
- `IEND` (muss zuletzt kommen)

## Nach `IEND` angehängte Daten

Eines der aussagekräftigsten PNG-Artefakte sind **Daten, die nach dem letzten `IEND`-Chunk angehängt wurden**. Viele Decoder ignorieren sie, wodurch sie nützlich sind für:

- **Einfaches Stego / versteckte Payloads**
- **PNG-Polyglots**
- **Malware-Staging**
- **Wiederherstellung älterer Bilddaten** aus fehlerhaften Editoren

Schneller Nachweis:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Wenn du alles nach dem letzten `IEND` extrahieren möchtest:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Teste außerdem direkt generische Archiv-Parser gegen die PNG-Datei oder den extrahierten Trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Wiederherstellung nach Acropalypse-Art von zugeschnittenen/redigierten Screenshots

Ein sehr praktischer, neuerer PNG-forensischer Trick besteht darin zu prüfen, ob ein Screenshot-Editor eine PNG-Datei **überschrieben** hat, ohne die alte Datei vorher **zu kürzen**. In diesen Fällen können Bytes des **vorherigen Bildes** nach `IEND` verbleiben, und manchmal lassen sich zusätzliche `IDAT`-Daten teilweise rekonstruieren.

Bekannt wurde dies durch **aCropalypse** (Google Pixel Markup) und das damit verbundene Problem des **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Wenn eine „zugeschnittene“ oder „redigierte“ PNG-Datei noch alte Daten am Ende enthält, kann möglicherweise ein Teil des ursprünglichen Screenshots wiederhergestellt werden.<sup>[[1]](#references)</sup>

Praktischer Ablauf:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Anzeichen, die eine eingehendere Analyse stark rechtfertigen:

- `pngcheck` meldet **zusätzliche Daten nach `IEND`**
- Sie finden **mehr als ein `IEND`**
- Sie finden **zusätzliche `IDAT`-Chunks** nach dem scheinbaren Ende des Bildes
- Der Screenshot stammt von einem Gerät/Editor, von dem bekannt ist, dass er betroffen war

Wenn dies passiert, führen Sie die Datei durch ein **aCropalypse recovery tool**, bevor Sie die Schwärzung als vertrauenswürdig betrachten.

## Chunk-Missbrauch, der in der Praxis relevant ist

Die interessantesten PNG-Chunks für Untersuchungen sind normalerweise nicht die offensichtlichen Bild-Chunks, sondern die Chunks, die **Text**, **Metadaten** oder **Payload-Bytes** enthalten können:

- `tEXt` / `zTXt` / `iTXt` – Textmetadaten und komprimierter Text
- `eXIf` – EXIF-Daten innerhalb von PNG
- `iCCP` – eingebettetes ICC-Profil
- `PLTE` – Palettendaten in indizierten Bildern, aber auch nützlich in Szenarien zum Einschleusen von Payloads.<sup>[[2]](#references)</sup>

Geben Sie sie mit folgendem Befehl aus:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Für die Persistenz von **offensive payloads** innerhalb von PNG-chunks (zum Beispiel Tricks mit **PLTE**, **IDAT** oder **tEXt**, die einige PHP-Bildtransformationen überstehen), siehe die detaillierteren, auf Uploads fokussierten Hinweise hier:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Zur Überprüfung der Integrität und zum Auffinden des genau beschädigten Bereichs bleibt **pngcheck** eines der besten Tools für den Einstieg:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Wenn die Datei beschädigt und nicht absichtlich schädlich ist, kann **PCRT** in CTFs und bei der Arbeit in Labs nützlich sein, um häufige Probleme wie fehlerhafte Header, falsche IHDR-Werte, CRC-Probleme oder fehlerhafte Chunk-Strukturen zu beheben.

Wenn dein Ziel darin besteht, ein PNG mit verdächtigen Trailer-Daten zu **sanitizen** und dabei das sichtbare Bild zu erhalten, kann ExifTool den Trailer explizit entfernen:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Für sensible Beweismittel solltest du immer mit einer **Kopie** arbeiten und die Hashes des Originals speichern, bevor du Reparaturen durchführst.

## References

- [1] [Exploiting aCropalypse: Wiederherstellung gekürzter PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistente PHP-Payloads in PNGs: So injizierst du PHP-Code in ein Bild – und behältst ihn dort](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
