# Firmware-Integrität

{{#include ../../banners/hacktricks-training.md}}

Wenn eine autorisierte Prüfung eine schwache oder fehlende Firmware-Signaturüberprüfung feststellt, kann ein modifiziertes Firmware-Image die Auswirkungen auf die Integrität demonstrieren. Der folgende Labor-Workflow fügt eine bind shell hinzu und behält dabei die ursprünglichen Schritte zur Extraktion, Emulation und zum Repackaging bei.<sup>[[2]](#references)[[3]](#references)</sup>

1. Die Firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Architektur und Endianness der Zielfirmware sollten identifiziert werden.
3. Ein cross compiler kann mit Buildroot oder anderen geeigneten Methoden für die Umgebung erstellt werden.
4. Die backdoor kann mit dem cross compiler erstellt werden.
5. Die backdoor kann in das Verzeichnis /usr/bin der extrahierten Firmware kopiert werden.
6. Das passende QEMU-Binary kann in das extrahierte Rootfs der Firmware kopiert werden.
7. Die backdoor kann mit chroot und QEMU emuliert werden.
8. Auf die backdoor kann über netcat zugegriffen werden.
9. Das QEMU-Binary sollte aus dem extrahierten Rootfs der Firmware entfernt werden.
10. Die modifizierte Firmware kann mit FMK neu gepackt werden.
11. Die backdoored Firmware kann getestet werden, indem sie mit dem firmware analysis toolkit (FAT) emuliert und mithilfe von netcat eine Verbindung zur IP-Adresse und zum Port der Ziel-backdoor hergestellt wird.

Wenn bereits eine Root-Shell durch dynamische Analyse, Bootloader-Manipulation oder Hardware-Sicherheitstests erlangt wurde, können vorkompilierte Test-Binaries wie Implants oder reverse shells ausgeführt werden. Metasploit's `msfvenom` kann für diesen Validierungs-Workflow ein architekturspezifisches Payload generieren:<sup>[[4]](#references)</sup>

1. Die Architektur und Endianness der Zielfirmware sollten identifiziert werden.
2. Mit Msfvenom können das Ziel-Payload, die IP-Adresse des Angreifer-Hosts, die Listening-Portnummer, der Dateityp, die Architektur, die Plattform und die Ausgabedatei festgelegt werden.
3. Das Payload kann auf das kompromittierte Gerät übertragen werden. Dabei ist sicherzustellen, dass es Ausführungsberechtigungen besitzt.
4. Metasploit kann für die Verarbeitung eingehender Anfragen vorbereitet werden, indem msfconsole gestartet und die Einstellungen entsprechend dem Payload konfiguriert werden.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.

## Nicht authentifizierte Transport-Bridges zu privilegierten Update-Protokollen

Ein häufiger Designfehler bei Embedded-Systemen besteht darin, dass **dasselbe interne command protocol über mehrere Transportwege verfügbar gemacht wird**, während die Authentifizierung nur bei einem davon durchgesetzt wird. Beispielsweise kann USB eine Challenge-Response erfordern, während BLE nicht authentifizierte **GATT writes** einfach an denselben privilegierten Firmware-Update-Handler weiterleitet.<sup>[[1]](#references)</sup>

Typischer offensiver Workflow:

1. Die BLE-GATT-Datenbank enumerieren und beschreibbare Characteristics identifizieren, die von der offiziellen Mobile-App verwendet werden.
2. Den App-Traffic mitsniffen und nach **magic bytes / opcodes** suchen, die dem kabelgebundenen Protokoll entsprechen.
3. Privilegierte Befehle über BLE **ohne Pairing** wiederholen und überprüfen, ob sensible Operationen weiterhin funktionieren.
4. Wenn Firmware-Upgrades, Config Writes, Debug- oder Factory-Test-Opcodes erreichbar sind, BLE als einen **per Funk erreichbaren Admin-Port** behandeln.

Schnellprüfungen:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Beim Reversing zu überprüfende Punkte:

- Erfordert BLE **Pairing/Bonding** oder nur eine einfache Verbindung?
- Werden alle Transporte an dieselbe interne Dispatcher-Tabelle weitergeleitet?
- Werden privilegierte Opcodes über USB / BLE / UART / Wi-Fi unterschiedlich gefiltert?
- Kann die mobile App Firmware-Update-, Recovery- oder Diagnose-Handler remote auslösen?

## Firmware-Container, die nur durch eine Prüfsumme geschützt sind, enthalten weiterhin vom Angreifer kontrollierte Firmware

Ein Firmware-Container, der nur durch eine **unverschlüsselte Prüfsumme** (CRC32, SHA-256, MD5 usw.) geschützt ist, erkennt Beschädigungen, gewährleistet aber **keine Authentizität**. Wenn der Angreifer die Update-Routine erreichen kann, kann er das Image patchen, die Prüfsumme neu berechnen und beliebigen Code flashen.<sup>[[1]](#references)</sup>

Warnsignale während der RE:

- Der Update-Code validiert nur einen nachgestellten Prüfsummen-Blob wie `CHK2`, `CRC` oder `SHA256`.
- Es gibt keine Signaturprüfung und keine Secure-Boot-Root-of-Trust.
- Es wird kein gerätegebundener MAC / HMAC / keine authentifizierte Verschlüsselung verwendet.
- Der Recovery-Modus akzeptiert dasselbe nicht authentifizierte Image-Format.

Praktischer Validierungsablauf:

1. Den Firmware-Container extrahieren und Bootloader, Haupt-Firmware sowie Integritätsmetadaten identifizieren.
2. Eine harmlose Zeichenfolge oder ein Banner im Image ändern.
3. Die Prüfsumme exakt so neu berechnen, wie es der Updater erwartet.
4. Das Image über den normalen Update-Pfad erneut flashen.
5. Die Änderung beim Booten bestätigen, um den beliebigen Firmware-Austausch nachzuweisen.

Wenn dies über einen remote erreichbaren Transport wie BLE/Wi-Fi funktioniert, handelt es sich effektiv um einen **nicht authentifizierten OTA-Firmware-Austausch**.

## Ein vertrauenswürdiges USB-Peripheriegerät durch Firmware-Reflashing in BadUSB verwandeln

Wenn das Zielgerät vom Host bereits über USB als vertrauenswürdig eingestuft wird, muss die schädliche Firmware möglicherweise keinen vollständig neuen USB-Stack implementieren. Ein deutlich einfacherer Pivot besteht häufig darin, die vorhandene **HID-Unterstützung wiederzuverwenden**.<sup>[[1]](#references)</sup>

Nützliches Vorgehen:

1. Prüfen, ob das Gerät bereits als **HID Consumer Control**- / Medien- / Vendor-HID-Interface enumeriert wird.
2. Den vorhandenen **HID-Report-Descriptor** in der Firmware lokalisieren.
3. Descriptor-Einträge ergänzen oder ersetzen, damit das Gerät zusätzlich **Tastatur**-Fähigkeit ankündigt.
4. Vorhandene Firmware-Routinen wiederverwenden, die bereits HID-Reports senden, statt eine neue Transportimplementierung zu schreiben.
5. Key-Press- und Key-Release-Reports injizieren, um Befehle auf dem Host einzugeben.

Dadurch wird die Kompromittierung der Firmware zur **Kompromittierung des Hosts**, weil der PC das reflashed Peripheriegerät als legitime Tastatur vertraut.

### Minimale Assessment-Checkliste

- Zeigen `dmesg`, der Geräte-Manager oder die USB-Deskriptoren ein vorhandenes HID-Interface?
- Gibt es freien Platz in der Nähe des Report-Descriptors oder eine verschiebbare Descriptor-Tabelle?
- Können vorhandene Routinen zum Senden von Mediensteuerungs-Reports für Tastatur-Reports wiederverwendet werden?
- Akzeptiert der Host das neue Tastatur-Interface nach dem Reflashing automatisch?

## Zuverlässige Payload-Ausführung innerhalb von RTOS-Firmware

Statt fragile Trampolines in zufällige Codepfade einzufügen, sollte man nach **vorhandenen RTOS-Tasks** suchen, die im normalen Betrieb ungenutzt sind oder nur geringe Auswirkungen haben.<sup>[[1]](#references)</sup>

Warum dies nützlich ist:

- Der Scheduler startet den Payload während des Bootens auf natürliche Weise.
- Kritische Kontrollflüsse werden nicht beschädigt.
- Verzögerte Payloads lösen seltener Watchdog-Resets aus, als wenn sie innerhalb eines latenzempfindlichen USB-/Netzwerk-Handlers ausgeführt werden.

Geeignete Ziele sind Diagnose-, Factory-Test-, Telemetrie- oder Coprocessor-Service-Tasks, die im normalen Betrieb inaktiv erscheinen.

## Schnelle Exploit-Iteration: Harmlose Protokoll-Handler zweckentfremden

Sobald Firmware-Patching möglich ist, besteht eine kompakte Möglichkeit, die RE zu beschleunigen, darin, einen harmlosen Command-Handler (zum Beispiel einen **Echo-/Debug-Opcode**) mit eigenen **Memory-Read-/Write-/Execute**-Primitives zu überschreiben. Dadurch entfällt das vollständige Reflashing bei jedem Experiment. Dies ist besonders nützlich, wenn das Gerät den modifizierten Handler über einen schnellen kabelgebundenen Transport unterstützt.<sup>[[1]](#references)</sup>

Dies kann verwendet werden, um:

- Scatter-geladene Memory-Maps zu verifizieren
- Heap-/Task-Zustände live zu untersuchen
- Kleine Payloads zu testen, bevor sie in den Flash geschrieben werden
- Funktionszeiger, Zeichenfolgen und Descriptor-Tabellen sicher wiederherzustellen

## References

- [1] [Pwnd Blaster: Hacking deinen PC mit deinem Lautsprecher, ohne ihn jemals zu berühren](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit – Verwendung von `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
