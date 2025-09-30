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


Firmware ist essentielle Software, die Geräte korrekt funktionieren lässt, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und erleichtert. Sie wird in permanentem Speicher abgelegt, wodurch das Gerät von dem Moment an, in dem es eingeschaltet wird, auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Das Untersuchen und gegebenenfalls Modifizieren von Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitslücken.

## **Informationssammlung**

**Informationssammlung** ist ein kritischer erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess umfasst das Sammeln von Daten über:

- Die CPU-Architektur und das darauf laufende Betriebssystem
- Spezifika des Bootloaders
- Hardware-Layout und Datenblätter
- Metriken der Codebasis und Speicherorte des Quellcodes
- Externe Bibliotheken und Lizenztypen
- Update-Historien und behördliche Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **open-source intelligence (OSINT)**-Tools von unschätzbarem Wert, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Das Beschaffen von Firmware kann auf verschiedene Weisen erfolgen, jeweils mit unterschiedlichem Komplexitätsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Bauen** aus den bereitgestellten Anleitungen
- **Herunterladen** von offiziellen Support-Seiten
- Verwenden von **Google dork**-Abfragen, um gehostete Firmware-Dateien zu finden
- Direkter Zugriff auf **cloud storage**, z. B. mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** mittels man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Schnittstellen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen in der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alles andere fehlschlägt, mit geeigneten Hardware-Tools

## Analyse der Firmware

Sobald Sie die **Firmware haben**, müssen Sie Informationen daraus extrahieren, um zu wissen, wie Sie vorgehen sollten. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, prüfe die **entropy** des Images mit `binwalk -E <bin>`; bei niedriger entropy ist es unwahrscheinlich, dass es verschlüsselt ist. Bei hoher entropy ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools benutzen, um **Dateien, die in der Firmware eingebettet sind**, zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) um die Datei zu inspizieren.

### Zugriff auf das Dateisystem

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**, der typischerweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Extraktion des Dateisystems

Manchmal hat binwalk **nicht das Magic-Byte des Dateisystems in seinen Signaturen**. In diesen Fällen verwende binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem aus dem Binary zu carve** und das Dateisystem anschließend entsprechend seinem Typ **manuell zu extrahieren**, indem du die untenstehenden Schritte befolgst.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führe den folgenden **dd command** aus (carving the Squashfs filesystem).
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

- CPIO-Archivdateien

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Für jffs2-Dateisysteme

`$ jefferson rootfsfile.jffs2`

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware analysieren

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dieser Prozess beinhaltet den Einsatz verschiedener Tools, um aus dem Firmware-Image wertvolle Daten zu analysieren und zu extrahieren.

### Initiale Analyse-Tools

Eine Reihe von Befehlen wird zur ersten Untersuchung der Binärdatei (als `<bin>` bezeichnet) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Partitionen sowie Dateisystemdetails zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **entropy** mit `binwalk -E <bin>` überprüft. Niedrige entropy deutet auf fehlende Verschlüsselung hin, während hohe entropy auf mögliche Verschlüsselung oder Kompression hindeutet.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiin­spektion empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man normalerweise das Dateisystem extrahieren, oft in ein Verzeichnis mit dem Namen des Dateisystemtyps (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Dateisystemtyp aufgrund fehlender magic bytes nicht erkennt, ist eine manuelle Extraktion notwendig. Dazu verwendet man `binwalk`, um den Offset des Dateisystems zu ermitteln, und anschließend den `dd`-Befehl, um das Dateisystem auszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden, abhängig vom Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs), unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Filesystem-Analyse

Mit dem extrahierten Dateisystem beginnt die Suche nach Sicherheitslücken. Augenmerk liegt auf unsicheren Netzwerkdaemons, hardcodierten Zugangsdaten, API-Endpunkten, Update-Server-Funktionalitäten, unkompiliertem Code, Startscripts und kompilierten Binaries zur Offline-Analyse.

**Wichtige Orte** und **Elemente**, die geprüft werden, sind:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und -Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf mögliche Schwachstellen
- Eingebettete Binaries zur weiteren Analyse
- Häufige IoT-Geräte-Webserver und Binärdateien

Mehrere Tools unterstützen beim Aufspüren sensibler Informationen und Schwachstellen im Dateisystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binärdateien

Sowohl Quellcode als auch kompilierte Binärdateien im Dateisystem müssen auf Schwachstellen geprüft werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Emulieren von Firmware für dynamische Analyse

Der Prozess der Firmware-Emulation ermöglicht die dynamische Analyse entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Probleme durch Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des root filesystem oder einzelner Binaries auf ein Gerät mit passender Architektur und Endianness, wie z. B. ein Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine, kann weitere Tests erleichtern.

### Emulieren einzelner Binaries

Zum Untersuchen einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um ein Binary für die MIPS-Architektur zu emulieren, kann man folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationstools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian Binaries wäre `qemu-mipsel` die Wahl.

#### ARM-Architektur-Emulation

Bei ARM-Binaries ist der Prozess ähnlich; für die Emulation wird `qemu-arm` eingesetzt.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In diesem Stadium wird entweder eine reale oder emulierte Geräteumgebung für die Analyse verwendet. Shell-Zugriff auf das OS und das Dateisystem ist essenziell. Emulation kann Hardware-Interaktionen nicht perfekt nachbilden, weshalb gelegentliche Neustarts der Emulation nötig sind. Die Analyse sollte das Dateisystem erneut durchsuchen, exponierte Webseiten und Netzwerkdienste untersuchen und Bootloader-Schwachstellen analysieren. Firmware-Integritätstests sind wichtig, um mögliche Backdoor-Schwachstellen zu erkennen.

## Laufzeitanalyse-Techniken

Laufzeitanalyse bedeutet, mit einem Prozess oder Binary in seiner laufenden Umgebung zu interagieren und Tools wie gdb-multiarch, Frida und Ghidra zu nutzen, um Breakpoints zu setzen und Schwachstellen mittels Fuzzing und anderen Techniken zu identifizieren.

## Binary-Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in Low-Level-Sprachen. Binary-Runtime-Protections in Embedded-Systemen sind selten, aber wenn vorhanden, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

## Vorgefertigte Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Sicherheitstests und sind mit den notwendigen Tools ausgestattet.

## Vorgefertigte OS zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die dich bei Security-Assessment und pentesting von Internet of Things (IoT)-Geräten unterstützt. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system basierend auf Ubuntu 18.04, vorinstalliert mit Firmware-Sicherheitstools.

## Firmware-Downgrade-Angriffe & unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptographische Signaturprüfungen für firmware images implementiert, wird **version rollback (downgrade) protection häufig weggelassen**. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten Public Key verifiziert, aber nicht die *version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legal eine **ältere, verwundbare firmware installieren, die weiterhin eine gültige Signatur trägt**, und so gepatchte Schwachstellen wieder einführen.

Typischer Angriffsvorgang:

1. **Älteres signiertes Image beschaffen**
* Vom öffentlichen Download-Portal des Vendors, CDN oder der Support-Seite herunterladen.
* Aus zugehörigen Mobile-/Desktop-Anwendungen extrahieren (z. B. innerhalb einer Android-APK unter `assets/firmware/`).
* Aus Drittanbieter-Repositorien wie VirusTotal, Internet-Archiven, Foren etc. beziehen.
2. **Das Image auf das Gerät hochladen oder bereitstellen** über einen beliebigen exponierten Update-Kanal:
* Web UI, mobile-app API, USB, TFTP, MQTT etc.
* Viele Consumer-IoT-Geräte stellen *unauthenticated* HTTP(S)-Endpunkte bereit, die Base64-codierte firmware-Blobs akzeptieren, serverseitig decodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (z. B. ein später hinzugefügter command-injection-Filter).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um nach Erlangung von persistence die Entdeckung zu vermeiden.

### Beispiel: Command Injection nach Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der anfälligen (heruntergestuften) Firmware wird der `md5`-Parameter direkt in einen Shell-Befehl eingefügt, ohne bereinigt zu werden, was die Injektion beliebiger Befehle ermöglicht (hier – enabling SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch das Fehlen eines Downgrade-Schutzes macht die Behebung wirkungslos.

### Firmware aus mobilen Apps extrahieren

Viele Hersteller packen komplette Firmware-Images in ihre Begleit-Mobilanwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Werkzeuge wie `apktool`, `ghidra` oder sogar simples `unzip` erlauben es dir, signierte Images zu extrahieren, ohne die Hardware anzufassen.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *update endpoint* ausreichend geschützt (TLS + authentication)?
* Vergleicht das Gerät **version numbers** oder einen **monotonic anti-rollback counter**, bevor geflasht wird?
* Wird das Image innerhalb einer secure boot chain verifiziert (z. B. werden signatures vom ROM code geprüft)?
* Führt userland code zusätzliche Sanity-Checks durch (z. B. allowed partition map, model number)?
* Verwenden *partial*- oder *backup*-Update-Flows dieselbe Validierungslogik?

> 💡  Wenn eines der oben Genannten fehlt, ist die Plattform wahrscheinlich anfällig für rollback attacks.

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

## Training und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
