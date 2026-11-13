# File-/Daten-Carving- und Wiederherstellungstools

{{#include ../../../banners/hacktricks-training.md}}

## Carving- und Wiederherstellungstools

Führe Carving immer auf einer **verifizierten Kopie** durch, niemals auf dem Originalgerät. Siehe [Image Acquisition & Mount](../image-acquisition-and-mount.md) zu Workflows für schreibgeschützte Datenerfassung und Hashing.

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten in der Forensik verwendete Tool zum Extrahieren von Dateien aus Images ist [**Autopsy**](https://www.autopsy.com/download/). Lade es herunter, installiere es und lasse es die Datei einlesen, um „versteckte“ Dateien zu finden. Beachte, dass Autopsy für die Unterstützung von Disk-Images und anderen Arten von Images entwickelt wurde, nicht jedoch für einfache Dateien.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. **Binwalk v3** ist eine Neuentwicklung in Rust mit automatischer Extraktion (`-e`), Raw-Carving bekannter und unbekannter Objekte (`-c`), rekursivem Matroschka-Scanning (`-M`) und konfigurierbaren Worker-Threads. Das Projekt empfiehlt den Docker-Build, wenn alle externen Extractors benötigt werden; `cargo install binwalk` installiert die Rust-CLI, jedoch nicht diese externen Abhängigkeiten.<sup>[[11]](#references)</sup>

**Nützliche v3-Befehle**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Die alte v2-`--dd='.*'`-Anleitung ist **nicht** das v3-Äquivalent von `-c`; prüfe zuerst `binwalk --version`, wenn du alte CTF-/Write-up-Befehle verwendest.<sup>[[11]](#references)</sup>

⚠️  **Sicherheitshinweis** – Die Versionen **2.1.2b bis 2.3.3** sind von einer **Path Traversal**-Schwachstelle betroffen (CVE-2022-4510); im Advisory ist keine gepatchte pip-Version aufgeführt. Vermeide es, nicht vertrauenswürdige Samples mit betroffenen Releases zu extrahieren, oder isoliere das Tool in einem Container bzw. mit einer nicht privilegierten UID.<sup>[[4]](#references)</sup>

### Foremost

Ein weiteres verbreitetes Tool zum Auffinden versteckter Dateien ist **foremost**. Die Konfigurationsdatei von foremost befindet sich unter `/etc/foremost.conf`. Wenn du nur nach bestimmten Dateien suchen möchtest, hebe die Auskommentierung der entsprechenden Einträge auf. Wenn du nichts auskommentierst, sucht foremost nach den standardmäßig konfigurierten Dateitypen.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** ist ein weiteres Tool, mit dem sich **in einer Datei eingebettete Dateien** finden und extrahieren lassen. Dazu müssen Sie in der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) die Dateitypen auskommentieren, die extrahiert werden sollen.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Fragmentiertes Carving mit Scalpel3

Wenn die Metadaten-zuerst-Wiederherstellung und zusammenhängende Carver unvollständige Dateien hinterlassen, kann **Scalpel3** unterstützte Formate mithilfe von Datei-/Block-Validatoren wieder zusammensetzen. Es handelt sich um eine andere Codebasis als beim oben genannten Legacy-Befehl `scalpel`. Erstellen Sie zunächst die benötigte Blockmap mit der **gleichen Blockgröße**, die beim Carving verwendet wird; verwenden Sie, falls bekannt, die Clustergröße des Dateisystems aus `fsstat` oder ermitteln Sie vor dem Scannen eines Partitionsabbilds einen vertretbaren Wert. Führen Sie den Vorgang nur mit einer verifizierten Kopie aus und speichern Sie die Ausgabe auf einem separaten Volume.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Ersetzen Sie `4096` durch die ausgewählte Blockgröße. `-w` behält **PROMISING**-Kandidaten ebenso wie validierte Kandidaten bei, und `-b` schreibt Blockvektoren, um rekonstruierte Layouts überprüfen zu können. Eine Datei unter PROMISING oder eine Datei mit einer vertrauten Erweiterung beweist keine vollständige Wiederherstellung; überprüfen Sie den Inhalt vor der Verwendung.<sup>[[13]](#references)[[14]](#references)</sup> Informationen zum Auffinden gelöschter Partitionen oder Lücken vor dem Carving finden Sie unter [Daten außerhalb aufgeführter Partitionen finden](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Dieses Tool ist in Kali enthalten, aber Sie finden es hier: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kann ein Beweisabbild scannen und **pcap-Fragmente**, **Netzwerk-Artefakte (URLs, Domains, IPs, MACs, E-Mails)** sowie viele andere Objekte **parallel mit mehreren Scannern** auslesen.

Die Version 2.1.1 dokumentiert einen Autotools-Build und die Einstellung `-S jpeg_carve_mode=2` zum Carving aller zusammenhängenden JPEGs.<sup>[[2]](#references)</sup>

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

Das gebündelte `bulk_diff.py` vergleicht zwei `bulk_extractor`-Läufe, während `bulk_extractor_reader.py` die Report- und Feature-Dateien liest.<sup>[[3]](#references)</sup>

### PhotoRec

Du findest es unter <https://www.cgsecurity.org/wiki/TestDisk_Download>

Es gibt Versionen mit GUI und CLI. Du kannst die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![Alle Scanner ausführen, aggressiv nach JPEGs suchen und eine Bodyfile erstellen - PhotoRec: Es gibt Versionen mit GUI und CLI. Du kannst die Dateitypen auswählen, nach denen PhotoRec suchen soll](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadatenorientiert)

Versuche vor dem Carving anhand roher Signaturen eine dateisystembewusste Wiederherstellung, wenn die Volume-Metadaten noch analysiert werden können. `tsk_recover` exportiert standardmäßig nur nicht zugewiesene Dateien; `-a` wählt zugewiesene Dateien aus und `-e` exportiert beide. Gib bei einem Datenträgerabbild den **Startsektor** der Partition aus `mmls` mit `-o` an (nicht in Bytes umrechnen). Wenn es sich bei der Eingabe bereits um ein Partitionsabbild handelt, lasse `-o` weg.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Dieser Durchlauf kann dateisystembasierte Namen und Pfade erhalten, die beim Header-/Footer-Carving nicht erhalten bleiben. Führe anschließend Foremost, Scalpel oder PhotoRec für Einträge aus, deren Metadaten fehlen oder unbrauchbar sind.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (Abbilder fehlerhafter Laufwerke erstellen)

Wenn ein physisches Laufwerk instabil ist, empfiehlt es sich, **zuerst ein Abbild davon zu erstellen** und Carving-Tools nur auf diesem Abbild auszuführen. `ddrescue` (GNU-Projekt) konzentriert sich darauf, fehlerhafte Datenträger zuverlässig zu kopieren und dabei ein Protokoll der nicht lesbaren Sektoren zu führen.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Die Option **`--cluster-size`** steuert, wie viele Sektoren auf einmal kopiert werden; kleinere Werte können bei langsamen Laufwerken helfen.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4-Wiederherstellung gelöschter Dateien)

Wenn das Quell-Dateisystem auf Linux EXT basiert, können Sie möglicherweise kürzlich gelöschte Dateien **ohne vollständiges Carving** wiederherstellen; diese journalbasierten Tools funktionieren mit einem nicht eingebundenen Dateisystem oder einem schreibgeschützten Image.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Kompatibilitätshinweis** – ext4magic wird nicht mehr weiterentwickelt; auf der Projektseite wird darauf hingewiesen, dass aktuelle Dateisysteme nicht mehr damit kompatibel sind.<sup>[[10]](#references)</sup>

> 🛈 Wenn das Dateisystem nach dem Löschen eingebunden wurde, wurden die Datenblöcke möglicherweise bereits wiederverwendet – in diesem Fall ist weiterhin korrektes Carving (Foremost/Scalpel) erforderlich.

### binvis

Siehe den [Code](https://code.google.com/archive/p/binvis/) und das [Webseiten-Tool](https://binvis.io/#/).

#### Funktionen von BinVis

- Visueller und interaktiver **Struktur-Viewer**
- Mehrere Diagramme für verschiedene Schwerpunkte
- Fokussierung auf Teile einer Stichprobe
- **Anzeige von Zeichenketten und Ressourcen**, z. B. in PE- oder ELF-Programmen
- Ermittlung von **Mustern** für die Kryptanalyse von Dateien
- **Erkennen** von Packer- oder Encoder-Algorithmen
- **Identifizieren** von Steganografie anhand von Mustern
- **Visueller** Binär-Diff

BinVis ist ein großartiger **Einstieg, um sich in einem Black-Boxing-Szenario mit einem unbekannten Ziel vertraut zu machen**.

## Spezielle Data-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem nach deren Schlüsselplänen gesucht wird. Kann 128-, 192- und 256-Bit-Schlüssel finden, wie sie beispielsweise von TrueCrypt und BitLocker verwendet werden.

Hier herunterladen: [Download](https://sourceforge.net/projects/findaes/).

### YARA-X (Triage von Carving-Artefakten)

[YARA-X](https://github.com/VirusTotal/yara-x) ist eine 2024 eingeführte Neufassung von YARA in Rust; VirusTotal berichtet, dass einige Regeln mit regulären Ausdrücken und komplexen Schleifen deutlich schneller ausgeführt werden können.<sup>[[5]](#references)</sup> Die CLI heißt `yr`, und der Befehl `scan` unterstützt rekursive Scans, die Angabe einer Thread-Anzahl und die Ausgabe von Metadaten.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Ergänzende Tools

Du kannst [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder im Terminal anzuzeigen.  \
Du kannst das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und zu lesen.







## References

- [1] [Autopsy 4.21 – Versionshinweise](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 – README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor-Python-Tools – README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path Traversal in binwalk (CVE-2022-4510) – GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA ist tot, es lebe YARA-X – VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X-CLI-Befehle](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU-ddrescue-Handbuch](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-Handbuch](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Projektstatus von ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 – README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: Handbuch zu tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 – README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3-Handbuch](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3-Test-Workflow](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
