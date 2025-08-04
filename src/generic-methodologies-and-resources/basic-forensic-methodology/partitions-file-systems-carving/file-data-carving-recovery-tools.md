# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Mehr Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Bildern ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei verarbeiten, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy für die Unterstützung von Festplattenabbildern und anderen Arten von Bildern entwickelt wurde, jedoch nicht für einfache Dateien.

> **2024-2025 Update** – Version **4.21** (veröffentlicht im Februar 2025) fügte ein neu gestaltetes **Carving-Modul basierend auf SleuthKit v4.13** hinzu, das beim Umgang mit Multi-Terabyte-Bildern merklich schneller ist und parallele Extraktion auf Multi-Core-Systemen unterstützt.¹ Ein kleiner CLI-Wrapper (`autopsycli ingest <case> <image>`) wurde ebenfalls eingeführt, der es ermöglicht, Carving in CI/CD- oder großangelegten Laborumgebungen zu skripten.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. Es kann über `apt` installiert werden und der Quellcode ist auf [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nützliche Befehle**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sicherheitsnotiz** – Versionen **≤2.3.3** sind von einer **Path Traversal**-Schwachstelle (CVE-2022-4510) betroffen. Aktualisieren Sie (oder isolieren Sie mit einem Container/nicht privilegierten UID), bevor Sie nicht vertrauenswürdige Proben analysieren.

### Foremost

Ein weiteres gängiges Tool zum Finden versteckter Dateien ist **foremost**. Sie finden die Konfigurationsdatei von foremost in `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, kommentieren Sie diese aus. Wenn Sie nichts auskommentieren, sucht foremost nach seinen standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **Dateien, die in einer Datei eingebettet sind**, zu finden und zu extrahieren. In diesem Fall müssen Sie die Dateitypen, die Sie extrahieren möchten, aus der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Dieses Tool ist in Kali enthalten, kann aber hier gefunden werden: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kann ein Beweisbild scannen und **pcap Fragmente**, **Netzwerkartefakte (URLs, Domains, IPs, MACs, E-Mails)** und viele andere Objekte **parallel mit mehreren Scannern** auslesen.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Nützliche Nachbearbeitungsskripte (`bulk_diff`, `bulk_extractor_reader.py`) können Artefakte zwischen zwei Images deduplizieren oder Ergebnisse in JSON für die SIEM-Integration umwandeln.

### PhotoRec

Sie finden es unter <https://www.cgsecurity.org/wiki/TestDisk_Download>

Es kommt mit GUI- und CLI-Versionen. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (Imaging fehlerhafter Laufwerke)

Wenn ein physischer Laufwerk instabil ist, ist es eine bewährte Methode, es zuerst **zu image** und nur Carving-Tools gegen das Image auszuführen. `ddrescue` (GNU-Projekt) konzentriert sich darauf, fehlerhafte Festplatten zuverlässig zu kopieren, während es ein Protokoll der unlesbaren Sektoren führt.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Dezember 2024) führte **`--cluster-size`** ein, das die Erstellung von Images von hochkapazitiven SSDs beschleunigen kann, bei denen traditionelle Sektorgrößen nicht mehr mit Flash-Blöcken übereinstimmen.

### Extundelete / Ext4magic (EXT 3/4 Wiederherstellung)

Wenn das Quell-Dateisystem auf Linux EXT basiert, können Sie möglicherweise kürzlich gelöschte Dateien **ohne vollständiges Carving** wiederherstellen. Beide Tools arbeiten direkt auf einem schreibgeschützten Image:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Wenn das Dateisystem nach der Löschung gemountet wurde, könnten die Datenblöcke bereits wiederverwendet worden sein – in diesem Fall ist eine ordnungsgemäße Carving (Foremost/Scalpel) weiterhin erforderlich.

### binvis

Überprüfen Sie den [Code](https://code.google.com/archive/p/binvis/) und das [Webseiten-Tool](https://binvis.io/#/).

#### Funktionen von BinVis

- Visueller und aktiver **Struktur-Viewer**
- Mehrere Diagramme für verschiedene Fokuspunkte
- Fokussierung auf Teile einer Probe
- **Anzeigen von Strings und Ressourcen**, in PE- oder ELF-Executables z. B.
- Erhalten von **Mustern** für die Kryptoanalyse von Dateien
- **Erkennen** von Packer- oder Encoder-Algorithmen
- **Identifizieren** von Steganographie durch Muster
- **Visuelles** binäres Differenzieren

BinVis ist ein großartiger **Ausgangspunkt, um sich mit einem unbekannten Ziel in einem Black-Box-Szenario vertraut zu machen**.

## Spezifische Daten-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem es nach ihren Schlüsselschemata sucht. In der Lage, 128, 192 und 256 Bit Schlüssel zu finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

### YARA-X (Triagierung von ge carve Artefakten)

[YARA-X](https://github.com/VirusTotal/yara-x) ist eine Rust-Neuschreibung von YARA, die 2024 veröffentlicht wurde. Es ist **10-30× schneller** als das klassische YARA und kann verwendet werden, um Tausende von ge carve Objekten sehr schnell zu klassifizieren:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Die Beschleunigung macht es realistisch, alle bearbeiteten Dateien in großangelegten Untersuchungen **automatisch zu kennzeichnen**.

## Ergänzende Werkzeuge

Sie können [**viu** ](https://github.com/atanunq/viu) verwenden, um Bilder aus dem Terminal anzuzeigen.  \
Sie können das Linux-Befehlszeilenwerkzeug **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.

## Referenzen

1. Autopsy 4.21 Versionshinweise – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
