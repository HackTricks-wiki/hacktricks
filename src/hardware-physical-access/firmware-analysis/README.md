# Firmware-Analyse

{{#include ../../banners/hacktricks-training.md}}

## **Einführung**

### Verwandte Ressourcen

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

Firmware ist essentielle Software, die es Geräten ermöglicht, korrekt zu funktionieren, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der die Benutzer interagieren, verwaltet und erleichtert. Sie wird im permanenten Speicher gespeichert, sodass das Gerät von dem Moment an, in dem es eingeschaltet wird, auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Die Untersuchung und potenzielle Modifikation der Firmware ist ein kritischer Schritt zur Identifizierung von Sicherheitsanfälligkeiten.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein kritischer erster Schritt, um die Zusammensetzung eines Geräts und die Technologien, die es verwendet, zu verstehen. Dieser Prozess umfasst das Sammeln von Daten über:

- Die CPU-Architektur und das Betriebssystem, das es ausführt
- Bootloader-Spezifikationen
- Hardware-Layout und Datenblätter
- Codebasis-Metriken und Quellstandorte
- Externe Bibliotheken und Lizenztypen
- Update-Historien und regulatorische Zertifizierungen
- Architektonische und Flussdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence (OSINT)**-Tools von unschätzbarem Wert, ebenso wie die Analyse aller verfügbaren Open-Source-Softwarekomponenten durch manuelle und automatisierte Überprüfungsprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Erwerb der Firmware**

Der Erwerb von Firmware kann auf verschiedene Weise erfolgen, jede mit ihrem eigenen Komplexitätsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Bauen** aus bereitgestellten Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Nutzung von **Google Dork**-Abfragen zur Auffindung gehosteter Firmware-Dateien
- Direkter Zugriff auf **Cloud-Speicher** mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **Updates** über Man-in-the-Middle-Techniken
- **Extrahieren** vom Gerät über Verbindungen wie **UART**, **JTAG** oder **PICit**
- **Sniffen** von Update-Anfragen innerhalb der Gerätekommunikation
- Identifizieren und Verwenden von **hardcodierten Update-Endpunkten**
- **Dumpen** vom Bootloader oder Netzwerk
- **Entfernen und Lesen** des Speicherchips, wenn alles andere fehlschlägt, unter Verwendung geeigneter Hardware-Tools

## Analyse der Firmware

Jetzt, da Sie **die Firmware haben**, müssen Sie Informationen darüber extrahieren, um zu wissen, wie Sie damit umgehen sollen. Verschiedene Tools, die Sie dafür verwenden können:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn Sie mit diesen Tools nicht viel finden, überprüfen Sie die **Entropie** des Bildes mit `binwalk -E <bin>`. Wenn die Entropie niedrig ist, ist es unwahrscheinlich, dass es verschlüsselt ist. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Darüber hinaus können Sie diese Tools verwenden, um **Dateien, die im Firmware eingebettet sind**, zu extrahieren:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu inspizieren.

### Abrufen des Dateisystems

Mit den zuvor kommentierten Tools wie `binwalk -ev <bin>` sollten Sie in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**, der normalerweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystemextraktion

Manchmal hat binwalk **nicht das magische Byte des Dateisystems in seinen Signaturen**. In diesen Fällen verwenden Sie binwalk, um **den Offset des Dateisystems zu finden und das komprimierte Dateisystem** aus der Binärdatei zu extrahieren und das Dateisystem **manuell gemäß seinem Typ** mit den folgenden Schritten zu extrahieren.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Führen Sie den folgenden **dd-Befehl** aus, um das Squashfs-Dateisystem zu extrahieren.
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

- Für ubifs-Dateisysteme mit NAND-Flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-Analyse

Sobald die Firmware beschafft ist, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dieser Prozess umfasst die Nutzung verschiedener Werkzeuge zur Analyse und zum Extrahieren wertvoller Daten aus dem Firmware-Image.

### Werkzeuge zur ersten Analyse

Eine Reihe von Befehlen wird für die erste Inspektion der Binärdatei (bezeichnet als `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, binäre Daten zu analysieren und die Partitionierungs- und Dateisystemdetails zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu bewerten, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Eine niedrige Entropie deutet auf einen Mangel an Verschlüsselung hin, während eine hohe Entropie auf mögliche Verschlüsselung oder Kompression hindeutet.

Für das Extrahieren von **eingebetteten Dateien** werden Werkzeuge und Ressourcen wie die Dokumentation zu **file-data-carving-recovery-tools** und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man normalerweise das Dateisystem extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** jedoch den Dateisystemtyp aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dies beinhaltet die Verwendung von `binwalk`, um den Offset des Dateisystems zu lokalisieren, gefolgt vom `dd`-Befehl, um das Dateisystem herauszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Danach werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Mit dem extrahierten Dateisystem beginnt die Suche nach Sicherheitsanfälligkeiten. Es wird auf unsichere Netzwerk-Daemons, fest codierte Anmeldeinformationen, API-Endpunkte, Funktionen von Update-Servern, nicht kompilierte Codes, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

**Wichtige Standorte** und **Elemente**, die untersucht werden sollten, sind:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und -Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien für weitere Analysen
- Häufige IoT-Geräte-Webserver und Binärdateien

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analysen
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsüberprüfungen von kompilierten Binärdateien

Sowohl Quellcode als auch kompilierte Binärdateien, die im Dateisystem gefunden werden, müssen auf Schwachstellen überprüft werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu identifizieren, die ausgenutzt werden könnten.

## Emulation von Firmware für dynamische Analysen

Der Prozess der Emulation von Firmware ermöglicht die **dynamische Analyse** entweder des Betriebs eines Geräts oder eines einzelnen Programms. Dieser Ansatz kann auf Herausforderungen mit Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des Root-Dateisystems oder spezifischer Binärdateien auf ein Gerät mit passender Architektur und Endianness, wie z. B. einem Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine, kann weitere Tests erleichtern.

### Emulation einzelner Binärdateien

Für die Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu identifizieren.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei der MIPS-Architektur zu emulieren, kann man den Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulationswerkzeuge zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (Big-Endian) wird `qemu-mips` verwendet, und für Little-Endian-Binärdateien wäre `qemu-mipsel` die Wahl.

#### ARM-Architektur-Emulation

Für ARM-Binärdateien ist der Prozess ähnlich, wobei der Emulator `qemu-arm` für die Emulation genutzt wird.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In diesem Stadium wird entweder eine reale oder emulierte Geräteumgebung für die Analyse verwendet. Es ist wichtig, den Shell-Zugriff auf das Betriebssystem und das Dateisystem aufrechtzuerhalten. Die Emulation kann die Hardware-Interaktionen möglicherweise nicht perfekt nachahmen, was gelegentliche Neustarts der Emulation erforderlich macht. Die Analyse sollte das Dateisystem erneut überprüfen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erkunden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Laufzeitanalyse-Techniken

Die Laufzeitanalyse umfasst die Interaktion mit einem Prozess oder einer Binärdatei in seiner Betriebsumgebung, wobei Tools wie gdb-multiarch, Frida und Ghidra verwendet werden, um Haltepunkte zu setzen und Schwachstellen durch Fuzzing und andere Techniken zu identifizieren.

## Binär-Exploitation und Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierung in niedrigeren Programmiersprachen. Binäre Laufzeitschutzmaßnahmen in eingebetteten Systemen sind selten, aber wenn sie vorhanden sind, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

## Vorbereitete Betriebssysteme für die Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für die Sicherheitstests von Firmware, ausgestattet mit den notwendigen Tools.

## Vorbereitete OSs zur Analyse von Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die Ihnen helfen soll, Sicherheitsbewertungen und Penetrationstests von Internet of Things (IoT)-Geräten durchzuführen. Es spart Ihnen viel Zeit, indem es eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Eingebettetes Sicherheitstestbetriebssystem basierend auf Ubuntu 18.04, vorinstalliert mit Tools für die Sicherheitstests von Firmware.

## Firmware-Downgrade-Angriffe & Unsichere Aktualisierungsmechanismen

Selbst wenn ein Anbieter kryptografische Signaturprüfungen für Firmware-Images implementiert, **wird der Schutz vor Versionsrücksetzungen (Downgrade) häufig weggelassen**. Wenn der Boot- oder Wiederherstellungs-Loader nur die Signatur mit einem eingebetteten öffentlichen Schlüssel überprüft, aber die *Version* (oder einen monotonen Zähler) des geflashten Images nicht vergleicht, kann ein Angreifer legitim eine **ältere, verwundbare Firmware installieren, die immer noch eine gültige Signatur trägt** und somit gepatchte Schwachstellen wieder einführen.

Typischer Angriffsablauf:

1. **Erhalten Sie ein älteres signiertes Image**
* Laden Sie es von dem öffentlichen Download-Portal, CDN oder Support-Website des Anbieters herunter.
* Extrahieren Sie es aus begleitenden mobilen/desktopp Anwendungen (z. B. innerhalb einer Android-APK unter `assets/firmware/`).
* Holen Sie es aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw.
2. **Laden Sie das Image auf das Gerät hoch oder stellen Sie es bereit** über einen beliebigen exponierten Aktualisierungskanal:
* Web-UI, mobile-App-API, USB, TFTP, MQTT usw.
* Viele Verbraucher-IoT-Geräte bieten *unauthentifizierte* HTTP(S)-Endpunkte, die Base64-kodierte Firmware-Blobs akzeptieren, diese serverseitig dekodieren und die Wiederherstellung/Aktualisierung auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version gepatcht wurde (zum Beispiel einen Befehlseinschleusungsfilter, der später hinzugefügt wurde).
4. Optional das neueste Image zurückflashen oder Updates deaktivieren, um eine Entdeckung zu vermeiden, sobald Persistenz erreicht ist.

### Beispiel: Befehlseinschleusung nach Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (heruntergestuften) Firmware wird der `md5`-Parameter direkt in einen Shell-Befehl ohne Sanitärmaßnahmen eingefügt, was die Injektion beliebiger Befehle ermöglicht (hier – Aktivierung des SSH-Schlüssel-basierten Root-Zugriffs). Spätere Firmware-Versionen führten einen grundlegenden Zeichenfilter ein, aber das Fehlen eines Downgrade-Schutzes macht die Lösung wirkungslos.

### Extrahieren von Firmware aus mobilen Apps

Viele Anbieter bündeln vollständige Firmware-Images in ihren Begleitmobilanwendungen, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Tools wie `apktool`, `ghidra` oder sogar einfaches `unzip` ermöglichen es Ihnen, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist zur Bewertung der Update-Logik

* Ist der Transport/Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler** vor dem Flashen?
* Wird das Image innerhalb einer sicheren Boot-Kette verifiziert (z.B. Signaturen, die vom ROM-Code überprüft werden)?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z.B. erlaubte Partitionstabelle, Modellnummer)?
* Nutzen *partielle* oder *Backup*-Update-Workflows die gleiche Validierungslogik?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Entdecken von Schwachstellen in Firmware zu üben, verwenden Sie die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Das Damn Vulnerable Router Firmware Project
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

## Schulung und Zertifizierung

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
