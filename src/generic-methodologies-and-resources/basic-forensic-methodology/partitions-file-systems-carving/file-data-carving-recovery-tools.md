# Datei-/Daten-Carving- und Wiederherstellungstools

## Carving- und Wiederherstellungstools

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten in der Forensik verwendete Tool zum Extrahieren von Dateien aus Images ist [**Autopsy**](https://www.autopsy.com/download/). Lade es herunter, installiere es und lasse es die Datei einlesen, um „versteckte“ Dateien zu finden. Beachte, dass Autopsy für die Unterstützung von Datenträger-Images und anderen Arten von Images entwickelt wurde, nicht jedoch für einfache Dateien.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. Es kann über `apt` installiert werden. Der Quellcode befindet sich auf [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nützliche Befehle**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sicherheitshinweis** – Die Versionen **2.1.2b bis 2.3.3** sind von einer **Path Traversal**-Schwachstelle (CVE-2022-4510) betroffen; der Hinweis führt keine gepatchte pip-Version auf. Vermeide das Extrahieren nicht vertrauenswürdiger Samples mit betroffenen Releases oder isoliere das Tool mit einem Container/einer nicht privilegierten UID.<sup>[[4]](#references)</sup>

### Foremost

Ein weiteres häufig verwendetes Tool zum Auffinden versteckter Dateien ist **foremost**. Die Konfigurationsdatei von foremost findest du unter `/etc/foremost.conf`. Wenn du nur nach bestimmten Dateien suchen möchtest, hebe die Auskommentierung der entsprechenden Einträge auf. Wenn du nichts auskommentierst, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, mit dem **in einer Datei eingebettete Dateien** gefunden und extrahiert werden können. In diesem Fall müssen Sie in der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) die Dateitypen auskommentieren, die extrahiert werden sollen.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Dieses Tool ist in Kali enthalten, aber du findest es hier: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kann ein Beweis-Image scannen und **pcap-Fragmente**, **Netzwerk-Artefakte (URLs, Domains, IPs, MACs, E-Mails)** sowie viele andere Objekte **parallel mithilfe mehrerer Scanner** extrahieren.

Das Release v2.1.1 dokumentiert einen Autotools-Build sowie die Einstellung `-S jpeg_carve_mode=2` zum Extrahieren aller zusammenhängenden JPEGs.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
Das gebündelte `bulk_diff.py` vergleicht zwei `bulk_extractor`-Ausführungen, während `bulk_extractor_reader.py` die Report- und Feature-Dateien liest.<sup>[[3]](#references)</sup>

### PhotoRec

Sie finden es unter <https://www.cgsecurity.org/wiki/TestDisk_Download>

Es ist in GUI- und CLI-Versionen verfügbar. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![Alle Scanner ausführen, JPEGs aggressiv carven und eine Bodyfile erstellen – PhotoRec: Es ist in GUI- und CLI-Versionen verfügbar. Sie können die Dateitypen auswählen, nach denen PhotoRec suchen soll](<../../../images/image (242).png>)

### ddrescue + ddrescueview (Imaging fehlerhafter Laufwerke)

Wenn ein physisches Laufwerk instabil ist, empfiehlt es sich, **zuerst ein Image zu erstellen** und Carving-Tools ausschließlich auf dem Image auszuführen. `ddrescue` (GNU project) konzentriert sich darauf, fehlerhafte Datenträger zuverlässig zu kopieren und dabei ein Protokoll der nicht lesbaren Sektoren zu führen.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Die Option **`--cluster-size`** steuert, wie viele Sektoren gleichzeitig kopiert werden; kleinere Werte können bei langsamen Laufwerken hilfreich sein.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Wenn das Quell-Dateisystem auf Linux EXT basiert, können kürzlich gelöschte Dateien möglicherweise **ohne vollständiges Carving** wiederhergestellt werden; diese journalbasierten Tools funktionieren auf einem nicht eingehängten Dateisystem oder einem schreibgeschützten Image.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Kompatibilitätshinweis** – ext4magic wird nicht mehr weiterentwickelt; auf der Projektseite wird darauf hingewiesen, dass aktuelle Dateisysteme nicht mehr damit kompatibel sind.<sup>[[10]](#references)</sup>

> 🛈 Wenn das Dateisystem nach dem Löschen eingehängt wurde, wurden die Datenblöcke möglicherweise bereits wiederverwendet – in diesem Fall ist weiterhin ordnungsgemäßes Carving (Foremost/Scalpel) erforderlich.

### binvis

Siehe den [Code](https://code.google.com/archive/p/binvis/) und das [Webseiten-Tool](https://binvis.io/#/).

#### Funktionen von BinVis

- Visueller und aktiver **Struktur-Viewer**
- Mehrere Diagramme für unterschiedliche Fokuspunkte
- Fokussierung auf Teile eines Samples
- **Anzeigen von Strings und Ressourcen**, z. B. in PE- oder ELF-Executables
- Ermitteln von **Mustern** zur Kryptoanalyse von Dateien
- **Erkennen** von Packer- oder Encoder-Algorithmen
- **Identifizieren** von Steganografie anhand von Mustern
- **Visuelles** Binary-Diffing

BinVis ist ein hervorragender **Ausgangspunkt, um sich mit einem unbekannten Ziel vertraut zu machen** in einem Black-Boxing-Szenario.

## Spezifische Data-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem nach deren Key-Schedules gesucht wird. Kann 128-, 192- und 256-Bit-Schlüssel finden, wie sie beispielsweise von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

### YARA-X (Triage von Carving-Artefakten)

[YARA-X](https://github.com/VirusTotal/yara-x) ist eine 2024 eingeführte, in Rust vorgenommene Neuentwicklung von YARA; VirusTotal berichtet, dass einige Regeln für reguläre Ausdrücke und komplexe Schleifen deutlich schneller ausgeführt werden können.<sup>[[5]](#references)</sup> Die CLI heißt `yr`, und der Befehl `scan` unterstützt rekursive Scans, eine Thread-Anzahl und die Ausgabe von Metadaten.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Ergänzende Tools

Du kannst [**viu** ](https://github.com/atanunq/viu) verwenden, um Bilder im Terminal anzuzeigen.  \
Du kannst das Linux-Kommandozeilentool **pdftotext** verwenden, um eine PDF-Datei in Text umzuwandeln und zu lesen.



## References

- [1] [Autopsy 4.21-Versionshinweise](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README der bulk_extractor-Python-Tools](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA ist tot, lang lebe YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X-CLI-Befehle](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU-ddrescue-Handbuch](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-Handbuch](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Projektstatus von ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
