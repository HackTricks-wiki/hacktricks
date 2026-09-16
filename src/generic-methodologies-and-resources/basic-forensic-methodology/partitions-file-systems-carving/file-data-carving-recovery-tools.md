# Datei-/Daten-Carving und Recovery-Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving- und Recovery-Tools

Führe Carving immer mit einer **verifizierten Kopie** durch, niemals mit dem Originalgerät. Siehe [Image Acquisition & Mount](../image-acquisition-and-mount.md) für schreibgeschützte Erfassungs- und Hashing-Workflows.

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten verwendete Tool zur Extraktion von Dateien aus Images in der Forensik ist [**Autopsy**](https://www.autopsy.com/download/). Lade es herunter, installiere es und lasse es die Datei einlesen, um „versteckte“ Dateien zu finden. Beachte, dass Autopsy für die Unterstützung von Disk-Images und anderen Arten von Images entwickelt wurde, jedoch nicht für einfache Dateien.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. **Binwalk v3** ist eine in Rust neu geschriebene Version mit automatischer Extraktion (`-e`), Raw-Carving bekannter und unbekannter Objekte (`-c`), rekursivem/Matryoshka-Scanning (`-M`) und konfigurierbaren Worker-Threads. Das Projekt empfiehlt seinen Docker-Build, wenn alle externen Extractors benötigt werden; `cargo install binwalk` installiert die Rust-CLI, jedoch nicht diese externen Abhängigkeiten.<sup>[[11]](#references)</sup>

**Nützliche v3-Befehle**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Die alte v2-Recipe `--dd='.*'` ist **nicht** das v3-Äquivalent zu `-c`; prüfe zuerst `binwalk --version`, wenn du alten CTF-/Write-up-Befehlen folgst.<sup>[[11]](#references)</sup>

⚠️  **Sicherheitshinweis** – Die Versionen **2.1.2b bis 2.3.3** sind von einer **Path Traversal**-Schwachstelle (CVE-2022-4510) betroffen; der Hinweis nennt keine gepatchte pip-Version. Vermeide es, nicht vertrauenswürdige Samples mit betroffenen Releases zu extrahieren, oder isoliere das Tool mit einem Container/einer nicht privilegierten UID.<sup>[[4]](#references)</sup>

### Foremost

Ein weiteres verbreitetes Tool zum Auffinden versteckter Dateien ist **foremost**. Du findest die Konfigurationsdatei von foremost in `/etc/foremost.conf`. Wenn du nur nach bestimmten Dateien suchen möchtest, kommentiere sie aus. Wenn du nichts auskommentierst, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **in einer Datei eingebettete Dateien** zu finden und zu extrahieren. In diesem Fall müssen Sie in der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) die Dateitypen auskommentieren, die extrahiert werden sollen.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Dieses Tool ist in Kali enthalten, aber du findest es hier: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kann ein Evidence-Image scannen und **pcap fragments**, **Netzwerk-Artefakte (URLs, Domains, IPs, MACs, E-Mails)** sowie viele andere Objekte **parallel mithilfe mehrerer Scanner** carven.

Das Release v2.1.1 dokumentiert einen Autotools-Build und die Einstellung `-S jpeg_carve_mode=2` zum Carven aller zusammenhängenden JPEGs.<sup>[[2]](#references)</sup>
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
Der mitgelieferte `bulk_diff.py` vergleicht zwei `bulk_extractor`-Durchläufe, während `bulk_extractor_reader.py` die Report- und Feature-Dateien liest.<sup>[[3]](#references)</sup>

### PhotoRec

Du findest es unter <https://www.cgsecurity.org/wiki/TestDisk_Download>

Es wird mit GUI- und CLI-Versionen geliefert. Du kannst die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![Alle Scanner ausführen, JPEGs aggressiv carven und eine Bodyfile generieren – PhotoRec: Es wird mit GUI- und CLI-Versionen geliefert. Du kannst die Dateitypen auswählen, nach denen PhotoRec suchen soll](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadatenbasiert)

Versuche vor dem Carving anhand roher Signaturen eine dateisystembewusste Wiederherstellung, wenn die Volume-Metadaten noch analysierbar sind. `tsk_recover` exportiert standardmäßig nur nicht zugewiesene Dateien; `-a` wählt zugewiesene Dateien aus und `-e` exportiert beide. Bei einem vollständigen Festplatten-Image übergibst du den **Startsektor** der Partition aus `mmls` an `-o` (wandle ihn nicht in Bytes um). Wenn die Eingabe bereits ein Partitions-Image ist, lasse `-o` weg.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Dieser Durchlauf kann aus dem Dateisystem abgeleitete Namen und Pfade erhalten, die beim Header/Footer-Carving nicht erhalten werden können; führe anschließend Foremost, Scalpel oder PhotoRec für Einträge aus, deren Metadaten fehlen oder unbrauchbar sind.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (Imaging fehlerhafter Laufwerke)

Wenn ein physisches Laufwerk instabil ist, empfiehlt es sich, **zuerst ein Image davon zu erstellen** und Carving-Tools erst anschließend gegen das Image auszuführen. `ddrescue` (GNU project) konzentriert sich darauf, fehlerhafte Datenträger zuverlässig zu kopieren und dabei ein Protokoll der nicht lesbaren Sektoren zu führen.
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

Wenn das Quelldateisystem auf Linux EXT basiert, können Sie möglicherweise kürzlich gelöschte Dateien **ohne vollständiges carving** wiederherstellen; diese journalbasierten Tools funktionieren auf einem nicht eingehängten Dateisystem oder einem schreibgeschützten Abbild.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Kompatibilitätshinweis** – ext4magic wird nicht mehr weiterentwickelt; auf der Projektseite wird darauf hingewiesen, dass aktuelle Dateisysteme nicht mehr damit kompatibel sind.<sup>[[10]](#references)</sup>

> 🛈 Wenn das Dateisystem nach dem Löschen eingehängt wurde, wurden die Datenblöcke möglicherweise bereits wiederverwendet – in diesem Fall ist weiterhin korrektes Carving (Foremost/Scalpel) erforderlich.

### binvis

Siehe den [Code](https://code.google.com/archive/p/binvis/) und das [Webseiten-Tool](https://binvis.io/#/).

#### Funktionen von BinVis

- Visueller und aktiver **Struktur-Viewer**
- Mehrere Diagramme für unterschiedliche Fokuspunkte
- Fokussierung auf Teile eines Samples
- **Anzeigen von Strings und Ressourcen**, z. B. in PE- oder ELF-Executables
- Ermitteln von **Mustern** für die Kryptoanalyse von Dateien
- **Erkennen** von Packer- oder Encoder-Algorithmen
- **Identifizieren** von Steganography anhand von Mustern
- **Visuelles** Binary-Diffing

BinVis ist ein großartiger **Ausgangspunkt, um sich mit einem unbekannten Ziel vertraut zu machen** in einem Black-Boxing-Szenario.

## Spezifische Data-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem nach deren Key-Schedules gesucht wird. Kann 128-, 192- und 256-Bit-Schlüssel finden, wie sie beispielsweise von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

### YARA-X (Triagieren extrahierter Artefakte)

[YARA-X](https://github.com/VirusTotal/yara-x) ist eine in Rust vorgenommene Neufassung von YARA, die 2024 eingeführt wurde; VirusTotal berichtet, dass einige Regeln mit regulären Ausdrücken und komplexen Schleifen deutlich schneller ausgeführt werden können.<sup>[[5]](#references)</sup> Die CLI heißt `yr`, und der Befehl `scan` unterstützt rekursive Scans, eine Thread-Anzahl sowie die Ausgabe von Metadaten.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Ergänzende Tools

Du kannst [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder vom Terminal aus anzuzeigen.  \
Du kannst das Linux-Kommandozeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und zu lesen.





## References

- [1] [Versionshinweise zu Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README der bulk_extractor-Python-Tools](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA ist tot, lang lebe YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X-CLI-Befehle](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU-ddrescue-Handbuch](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-Handbuch](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Projektstatus von ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover-Handbuch](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
