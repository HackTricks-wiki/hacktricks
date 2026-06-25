# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Die **benutzerdefinierte Firmware und/oder kompilierte Binaries können hochgeladen werden, um Integritäts- oder Signaturverifikationsfehler auszunutzen**. Die folgenden Schritte können für die Kompilierung einer backdoor bind shell verwendet werden:

1. Die Firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Architektur und Endianness der Ziel-Firmware sollten identifiziert werden.
3. Ein Cross-Compiler kann mit Buildroot oder anderen geeigneten Methoden für die Umgebung gebaut werden.
4. Die backdoor kann mit dem Cross-Compiler gebaut werden.
5. Die backdoor kann in das extrahierte Firmware-Verzeichnis /usr/bin kopiert werden.
6. Die passende QEMU-Binary kann in das extrahierte Firmware rootfs kopiert werden.
7. Die backdoor kann mit chroot und QEMU emuliert werden.
8. Auf die backdoor kann über netcat zugegriffen werden.
9. Die QEMU-Binary sollte aus dem extrahierten Firmware rootfs entfernt werden.
10. Die modifizierte Firmware kann mit FMK neu verpackt werden.
11. Die backdoored Firmware kann getestet werden, indem sie mit firmware analysis toolkit (FAT) emuliert und mit netcat zur Ziel-Backdoor-IP und zum -Port verbunden wird.

Wenn bereits eine root shell durch dynamische Analyse, Bootloader-Manipulation oder hardware security testing erlangt wurde, können vorkompilierte bösartige Binaries wie implants oder reverse shells ausgeführt werden. Automatisierte payload/implant-Tools wie das Metasploit framework und 'msfvenom' können mit den folgenden Schritten genutzt werden:

1. Die Architektur und Endianness der Ziel-Firmware sollten identifiziert werden.
2. Msfvenom kann verwendet werden, um den Ziel-payload, die IP des Angreifer-Hosts, die Listening-Port-Nummer, den filetype, die Architektur, die Plattform und die Ausgabedatei anzugeben.
3. Der payload kann auf das kompromittierte Gerät übertragen werden, und es sollte sichergestellt werden, dass er Ausführungsrechte hat.
4. Metasploit kann vorbereitet werden, um eingehende Anfragen zu verarbeiten, indem msfconsole gestartet und die Einstellungen entsprechend dem payload konfiguriert werden.
5. Die meterpreter reverse shell kann auf dem kompromittierten Gerät ausgeführt werden.

## Unauthenticated transport bridges to privileged update protocols

Ein häufiger Fehler im embedded design ist, **denselben internen Befehlsprotokoll über mehrere Transports bereitzustellen**, aber Authentifizierung nur für einen davon zu erzwingen. Zum Beispiel kann USB challenge-response erfordern, während BLE einfach unauthentifizierte **GATT writes** in denselben privilegierten Firmware-Update-Handler weiterleitet.

Typischer offensiver Ablauf:

1. Die BLE GATT-Datenbank auflisten und schreibbare Characteristics identifizieren, die von der offiziellen mobilen App verwendet werden.
2. Den App-Traffic sniffen und nach **magic bytes / opcodes** suchen, die zum kabelgebundenen Protokoll passen.
3. Privilegierte Befehle über BLE **ohne Pairing** erneut senden und prüfen, ob sensible Operationen weiterhin funktionieren.
4. Wenn Firmware-Upgrade-, Config-Write-, Debug- oder Factory-Test-opcodes erreichbar sind, BLE als **radio-reachable admin port** behandeln.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Zu verifizieren beim Reverse Engineering:

- Benötigt BLE **pairing/bonding** oder nur eine einfache Verbindung?
- Werden alle Transports auf dieselbe interne Dispatcher-Tabelle geroutet?
- Werden privilegierte Opcodes auf USB / BLE / UART / Wi-Fi unterschiedlich gefiltert?
- Kann die mobile App Firmware-Update, Recovery oder Diagnostic-Handler remote auslösen?

## Checksum-only firmware containers are still attacker-controlled firmware

Ein Firmware-Container, der nur durch eine **unkeyed checksum** geschützt ist (CRC32, SHA-256, MD5 usw.), bietet Korruptionserkennung, **keine Authentizität**. Wenn der Angreifer die Update-Routine erreichen kann, kann er das Image patchen, die checksum neu berechnen und beliebigen Code flashen.

Red flags während RE:

- Update-Code validiert nur einen nachgestellten checksum-Blob wie `CHK2`, `CRC` oder `SHA256`.
- Keine signature verification oder secure-boot root of trust vorhanden.
- Kein device-bound MAC / HMAC / authenticated encryption wird verwendet.
- Recovery mode akzeptiert dasselbe unauthentifizierte image format.

Praktischer Validierungsablauf:

1. Extrahiere den Firmware-Container und identifiziere Bootloader, Main Firmware und Integritätsmetadaten.
2. Ändere einen harmlosen String oder Banner im Image.
3. Berechne die checksum genau so neu, wie der Updater es erwartet.
4. Spiele das Image über den normalen Update-Pfad erneut auf.
5. Bestätige die Änderung beim Booten, um beliebigen Firmware-Austausch zu beweisen.

Wenn das über einen remote erreichbaren Transport wie BLE/Wi-Fi funktioniert, ist der Bug effektiv **unauthenticated OTA firmware replacement**.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Wenn das Zielgerät dem Host bereits über USB vertraut ist, muss malicious firmware oft keinen vollständigen neuen USB-Stack implementieren. Ein deutlich einfacher Pivot ist häufig, **vorhandene HID-Unterstützung wiederzuverwenden**.

Nützliches Muster:

1. Prüfe, ob das Gerät bereits als **HID Consumer Control** / Media- / Vendor-HID-Interface enumeriert.
2. Finde den vorhandenen **HID report descriptor** in der Firmware.
3. Hänge Descriptor-Einträge an oder ersetze sie, sodass das Gerät zusätzlich **keyboard**-Fähigkeit bewirbt.
4. Nutze vorhandene Firmware-Routinen wieder, die bereits HID reports senden, statt eine neue Transport-Implementierung zu schreiben.
5. Sende key press + key release reports, um Befehle auf dem Host einzutippen.

Das macht aus firmware compromise einen **host compromise**, weil der PC das reflashed peripheral als legitime Tastatur vertraut.

### Minimal assessment checklist

- Zeigen `dmesg`, Device Manager oder USB descriptors ein vorhandenes HID-Interface?
- Gibt es freien Platz nahe am report descriptor oder eine relocatable descriptor table?
- Können vorhandene media-control-Send-Routinen für keyboard reports wiederverwendet werden?
- Akzeptiert der Host die neue keyboard interface nach dem Reflash automatisch?

## Reliable payload execution inside RTOS firmware

Statt fragile trampolines in zufällige code paths einzubauen, suche nach **existing RTOS tasks**, die im Normalbetrieb ungenutzt oder wenig kritisch sind.

Warum das nützlich ist:

- Der Scheduler startet dein Payload natürlich während des Boots.
- Du vermeidest es, kritische control flow zu korrumpieren.
- Verzögerte Payloads lösen weniger wahrscheinlich watchdog resets aus als bei Ausführung in einem latenzsensitiven USB-/network-handler.

Gute Ziele sind diagnostic-, factory-test-, telemetry- oder coprocessor-service-Tasks, die im normalen Gebrauch inaktiv wirken.

## Fast exploit iteration: repurpose benign protocol handlers

Sobald Firmware-Patching möglich ist, ist ein kompakter Weg zur Beschleunigung von RE, einen harmlosen command handler (zum Beispiel einen **echo/debug opcode**) mit eigenen **memory read / write / execute**-Primitives zu überschreiben. Das vermeidet vollständiges Reflashing für jedes Experiment und ist besonders nützlich, wenn das Gerät den modifizierten Handler über einen schnellen kabelgebundenen Transport unterstützt.

Nutze das, um:

- scatter-loaded memory maps zu verifizieren
- heap/task state live zu inspizieren
- kleine Payloads zu testen, bevor du sie in flash brennst
- function pointers, strings und descriptor tables sicher wiederherzustellen

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
