# Firmware-Integrität

{{#include ../../banners/hacktricks-training.md}}

Die **custom firmware und/oder kompilierten Binaries können hochgeladen werden, um Schwachstellen bei der Integritäts- oder Signaturprüfung auszunutzen**. Für die Kompilierung einer backdoor bind shell können die folgenden Schritte durchgeführt werden:

1. Die firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Architektur und Endianness der Ziel-firmware sollten identifiziert werden.
3. Mit Buildroot oder anderen geeigneten Methoden kann ein Cross-Compiler für die Umgebung erstellt werden.
4. Die backdoor kann mit dem Cross-Compiler kompiliert werden.
5. Die backdoor kann in das Verzeichnis /usr/bin der extrahierten firmware kopiert werden.
6. Die passende QEMU-Binary kann in das Rootfs der extrahierten firmware kopiert werden.
7. Die backdoor kann mit chroot und QEMU emuliert werden.
8. Auf die backdoor kann mit netcat zugegriffen werden.
9. Die QEMU-Binary sollte aus dem Rootfs der extrahierten firmware entfernt werden.
10. Die modifizierte firmware kann mit FMK neu gepackt werden.
11. Die backdoored firmware kann getestet werden, indem sie mit dem firmware analysis toolkit (FAT) emuliert und mit netcat eine Verbindung zur IP-Adresse und zum Port der Ziel-backdoor hergestellt wird.

Wenn bereits über dynamische Analyse, Manipulation des Bootloaders oder Hardware-Sicherheitstests eine Root-Shell erlangt wurde, können vorkompilierte bösartige Binaries wie Implants oder Reverse Shells ausgeführt werden. Automatisierte Payload-/Implant-Tools wie das Metasploit framework und 'msfvenom' können anhand der folgenden Schritte eingesetzt werden:

1. Die Architektur und Endianness der Ziel-firmware sollten identifiziert werden.
2. Mit Msfvenom können der Ziel-Payload, die IP-Adresse des Angreifer-Hosts, die Listening-Portnummer, der Dateityp, die Architektur, die Plattform und die Ausgabedatei angegeben werden.
3. Der Payload kann auf das kompromittierte Gerät übertragen und mit Ausführungsberechtigungen versehen werden.
4. Metasploit kann für die Verarbeitung eingehender Anfragen vorbereitet werden, indem msfconsole gestartet und die Einstellungen entsprechend dem Payload konfiguriert werden.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.

## Nicht authentifizierte Transport-Bridges zu privilegierten Update-Protokollen

Ein häufiger Designfehler bei Embedded-Systemen besteht darin, **dass dasselbe interne command protocol über mehrere Transportwege bereitgestellt wird**, aber nur einer davon eine Authentifizierung durchsetzt. Beispielsweise kann USB eine Challenge-Response erfordern, während BLE einfach nicht authentifizierte **GATT writes** an denselben privilegierten firmware-update handler weiterleitet.<sup>[[1]](#references)</sup>

Typischer offensiver Workflow:

1. Die BLE-GATT-Datenbank enumerieren und beschreibbare Characteristics identifizieren, die von der offiziellen Mobile-App verwendet werden.
2. Den App-Traffic sniffen und nach **magic bytes / opcodes** suchen, die dem kabelgebundenen Protokoll entsprechen.
3. Privilegierte Befehle über BLE **ohne Pairing** wiedergeben und überprüfen, ob sensible Operationen weiterhin funktionieren.
4. Wenn Firmware-Upgrade-, Config-Write-, Debug- oder Factory-Test-opcodes erreichbar sind, BLE als einen **per Funk erreichbaren Admin-Port** betrachten.

Schnellprüfungen:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Zu überprüfende Punkte beim Reversing:

- Erfordert BLE **Pairing/Bonding** oder nur eine einfache Verbindung?
- Werden alle Transporte an dieselbe interne Dispatcher-Tabelle weitergeleitet?
- Werden privilegierte Opcodes über USB / BLE / UART / Wi-Fi unterschiedlich gefiltert?
- Kann die mobile App Firmware-Update-, Recovery- oder Diagnose-Handler remote auslösen?

## Nur durch Checksums geschützte Firmware-Container werden weiterhin vom Angreifer kontrolliert

Ein Firmware-Container, der nur durch eine **unkeyed checksum** (CRC32, SHA-256, MD5 usw.) geschützt ist, erkennt Beschädigungen, gewährleistet aber **keine Authentizität**. Wenn der Angreifer die Update-Routine erreichen kann, kann er das Image patchen, die Checksumme neu berechnen und beliebigen Code flashen.<sup>[[1]](#references)</sup>

Warnsignale während des RE:

- Der Update-Code validiert nur einen nachgestellten Checksum-Blob wie `CHK2`, `CRC` oder `SHA256`.
- Es ist keine Signaturprüfung oder Secure-Boot-Root-of-Trust vorhanden.
- Es wird kein gerätegebundener MAC / HMAC / keine authentifizierte Verschlüsselung verwendet.
- Der Recovery-Modus akzeptiert dasselbe nicht authentifizierte Image-Format.

Praktischer Validierungsablauf:

1. Firmware-Container extrahieren und Bootloader, Haupt-Firmware sowie Integritätsmetadaten identifizieren.
2. Eine harmlose Zeichenkette oder ein Banner im Image ändern.
3. Die Checksumme genau so neu berechnen, wie es der Updater erwartet.
4. Das Image über den normalen Update-Pfad erneut flashen.
5. Die Änderung beim Booten bestätigen, um den beliebigen Austausch der Firmware nachzuweisen.

Wenn dies über einen remote erreichbaren Transport wie BLE/Wi-Fi funktioniert, handelt es sich effektiv um einen **unauthenticated OTA firmware replacement**-Fehler.

## Ein vertrauenswürdiges USB-Peripheriegerät durch erneutes Flashen der Firmware in BadUSB verwandeln

Wenn das Zielgerät vom Host bereits über USB als vertrauenswürdig eingestuft wird, muss die schädliche Firmware möglicherweise keinen vollständig neuen USB-Stack implementieren. Ein wesentlich einfacherer Pivot ist oft die **Wiederverwendung der vorhandenen HID-Unterstützung**.<sup>[[1]](#references)</sup>

Nützliches Vorgehensmuster:

1. Prüfen, ob das Gerät bereits als **HID Consumer Control**- / Media- / Vendor-HID-Interface enumeriert wird.
2. Den vorhandenen **HID report descriptor** in der Firmware lokalisieren.
3. Descriptor-Einträge anhängen oder ersetzen, damit das Gerät zusätzlich **Keyboard**-Fähigkeiten bewirbt.
4. Vorhandene Firmware-Routinen wiederverwenden, die bereits HID-Reports senden, anstatt eine neue Transport-Implementierung zu schreiben.
5. Key-Press- und Key-Release-Reports injizieren, um Befehle auf dem Host einzugeben.

Dadurch wird die Kompromittierung der Firmware zur **Kompromittierung des Hosts**, weil der PC das erneut geflashte Peripheriegerät als legitime Tastatur vertraut.

### Minimale Assessment-Checkliste

- Zeigen `dmesg`, der Geräte-Manager oder USB-Deskriptoren ein vorhandenes HID-Interface?
- Gibt es freien Platz in der Nähe des Report-Descriptors oder eine relocatable Descriptor-Tabelle?
- Können vorhandene Routinen zum Senden von Media-Control-Reports für Keyboard-Reports wiederverwendet werden?
- Akzeptiert der Host das neue Keyboard-Interface nach dem erneuten Flashen automatisch?

## Zuverlässige Payload-Ausführung innerhalb von RTOS-Firmware

Anstatt fragile Trampolines in zufällige Codepfade einzufügen, sollte nach **vorhandenen RTOS-Tasks** gesucht werden, die im normalen Betrieb ungenutzt sind oder nur geringe Auswirkungen haben.<sup>[[1]](#references)</sup>

Warum dies nützlich ist:

- Der Scheduler startet deine Payload beim Booten auf natürliche Weise.
- Die Beschädigung kritischer Kontrollflüsse wird vermieden.
- Verzögerte Payloads lösen seltener Watchdog-Resets aus, als wenn sie innerhalb eines latenzsensitiven USB-/Netzwerk-Handlers ausgeführt werden.

Geeignete Ziele sind Diagnose-, Factory-Test-, Telemetrie- oder Coprozessor-Service-Tasks, die im normalen Betrieb inaktiv zu sein scheinen.

## Schnelle Exploit-Iteration: Harmlose Protokoll-Handler zweckentfremden

Sobald Firmware-Patching möglich ist, besteht eine kompakte Möglichkeit zur Beschleunigung des RE darin, einen harmlosen Command-Handler (beispielsweise einen **echo/debug opcode**) durch benutzerdefinierte **memory read / write / execute**-Primitives zu ersetzen. Dadurch entfällt das vollständige erneute Flashen bei jedem Experiment. Dies ist besonders nützlich, wenn das Gerät den modifizierten Handler über einen schnellen kabelgebundenen Transport unterstützt.<sup>[[1]](#references)</sup>

Dies kann verwendet werden, um:

- Scatter-geladene Memory-Maps zu überprüfen
- Heap-/Task-Zustände live zu untersuchen
- Kleine Payloads zu testen, bevor sie in den Flash geschrieben werden
- Funktionszeiger, Zeichenketten und Descriptor-Tabellen sicher wiederherzustellen

## Referenzen

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
