# File-/Daten-Carving & Recovery-Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving- & Recovery-Tools

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Images ist [**Autopsy**](https://www.autopsy.com/download/). Lade es herunter, installiere es und lasse es die Datei ingestieren, um „versteckte“ Dateien zu finden. Beachte, dass Autopsy für die Unterstützung von Disk-Images und anderen Arten von Images entwickelt wurde, nicht jedoch für einfache Dateien.

> **Update 2024–2025** – Version **4.21** (veröffentlicht im Februar 2025) enthält ein neu entwickeltes **Carving-Modul auf Basis von SleuthKit v4.13**, das bei der Verarbeitung von Images mit mehreren Terabyte deutlich schneller ist und die parallele Extraktion auf Multi-Core-Systemen unterstützt. Außerdem wurde ein kleiner CLI-Wrapper (`autopsycli ingest <case> <image>`) eingeführt, mit dem sich Carving innerhalb von CI/CD- oder groß angelegten Laborumgebungen skripten lässt.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. Es kann über `apt` installiert werden, und der Quellcode befindet sich auf [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nützliche Befehle**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sicherheitshinweis** – Versionen **≤2.3.3** sind von einer **Path Traversal**-Schwachstelle (CVE-2022-4510) betroffen. Aktualisieren Sie (oder isolieren Sie mit einem Container/einer nicht privilegierten UID), bevor Sie nicht vertrauenswürdige Samples durchsuchen.<sup>[[2]](#references)</sup>

### Foremost

Ein weiteres häufig verwendetes Tool zum Auffinden versteckter Dateien ist **foremost**. Die Konfigurationsdatei von foremost befindet sich in `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, entfernen Sie deren Auskommentierung. Wenn Sie nichts auskommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, mit dem sich **in einer Datei eingebettete Dateien** finden und extrahieren lassen. In diesem Fall müssen Sie in der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) die Dateitypen einkommentieren, die extrahiert werden sollen.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Dieses Tool ist in Kali enthalten, aber du findest es hier: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kann ein Beweis-Image scannen und **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** sowie viele andere Objekte **parallel mithilfe mehrerer scanner** carven.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Nützliche post-processing scripts (`bulk_diff`, `bulk_extractor_reader.py`) können Artefakte zwischen zwei Images deduplizieren oder Ergebnisse für die SIEM-Aufnahme in JSON konvertieren.

### PhotoRec

Sie finden es unter <https://www.cgsecurity.org/wiki/TestDisk_Download>

Es ist mit GUI- und CLI-Versionen verfügbar. Sie können die **file-types** auswählen, nach denen PhotoRec suchen soll.

![Jeden Scanner ausführen, JPEGs aggressiv carven und eine Bodyfile generieren - PhotoRec: Es ist mit GUI- und CLI-Versionen verfügbar. Sie können die file-types auswählen, nach denen PhotoRec suchen soll](<../../../images/image (242).png>)

### ddrescue + ddrescueview (Imaging fehlerhafter Laufwerke)

Wenn ein physisches Laufwerk instabil ist, empfiehlt es sich, **zuerst ein Image davon zu erstellen** und Carving-Tools erst auf dem Image auszuführen. `ddrescue` (GNU-Projekt) konzentriert sich darauf, fehlerhafte Datenträger zuverlässig zu kopieren und dabei ein Protokoll der nicht lesbaren Sektoren zu führen.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Dezember 2024) führte **`--cluster-size`** ein, was das Imaging von SSDs mit hoher Kapazität beschleunigen kann, bei denen herkömmliche Sektorgrößen nicht mehr mit Flash-Blöcken übereinstimmen.

### Extundelete / Ext4magic (EXT-3/4-Undelete)

Wenn das Quelldateisystem Linux-EXT-basiert ist, können Sie möglicherweise kürzlich gelöschte Dateien **ohne vollständiges Carving** wiederherstellen. Beide Tools arbeiten direkt mit einem schreibgeschützten Image:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Wenn das Dateisystem nach dem Löschen eingebunden wurde, wurden die Datenblöcke möglicherweise bereits wiederverwendet – in diesem Fall ist weiterhin ein ordnungsgemäßes carving (Foremost/Scalpel) erforderlich.

### binvis

Siehe den [code](https://code.google.com/archive/p/binvis/) und das [web page tool](https://binvis.io/#/).

#### Features von BinVis

- Visueller und aktiver **structure viewer**
- Mehrere Plots für verschiedene Fokuspunkte
- Fokussierung auf Teile eines Samples
- **Anzeigen von Strings und Ressourcen**, z. B. in PE- oder ELF-Executables
- Ermitteln von **patterns** für die Kryptoanalyse von Dateien
- **Erkennen** von Packer- oder Encoder-Algorithmen
- **Identifizieren** von Steganography anhand von Patterns
- **Visuelles** binary-diffing

BinVis ist ein hervorragender **Ausgangspunkt, um sich mit einem unbekannten Target vertraut zu machen** in einem black-boxing-Szenario.

## Spezifische Data-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem nach deren key schedules gesucht wird. Kann 128-, 192- und 256-Bit-Schlüssel finden, wie sie beispielsweise von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

### YARA-X (Triaging von Carving-Artefakten)

[YARA-X](https://github.com/VirusTotal/yara-x) ist eine 2024 veröffentlichte Rust-Neuimplementierung von YARA. Es ist **10- bis 30-mal schneller** als klassisches YARA und kann verwendet werden, um Tausende von Carving-Objekten sehr schnell zu klassifizieren:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Die Beschleunigung macht es realistisch, alle extrahierten Dateien bei Untersuchungen in großem Maßstab **automatisch zu taggen**.

## Ergänzende Tools

Du kannst [**viu** ](https://github.com/atanunq/viu) verwenden, um Bilder im Terminal anzuzeigen.  \
Du kannst das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und zu lesen.



## Referenzen

- [1] [Autopsy 4.21 – Versionshinweise](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal in binwalk (CVE-2022-4510) – GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X – VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
