# Firmware-Integrität

{{#include ../../banners/hacktricks-training.md}}

Wenn bei einer autorisierten Prüfung eine schwache oder fehlende Firmware-Signaturprüfung festgestellt wird, kann ein modifiziertes Firmware-Image die Auswirkungen auf die Integrität veranschaulichen. Der folgende Laborablauf fügt eine Bind Shell hinzu und behält dabei die ursprünglichen Schritte zur Extraktion, Emulation und zum erneuten Packen bei.<sup>[[2]](#references)[[3]](#references)</sup>

1. Die Firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Architektur und Endianness der Zielfirmware sollten ermittelt werden.
3. Für die Umgebung kann mit Buildroot oder einer anderen geeigneten Methode ein Cross-Compiler erstellt werden.
4. Die Backdoor kann mit dem Cross-Compiler erstellt werden.
5. Die Backdoor kann in das Verzeichnis /usr/bin der extrahierten Firmware kopiert werden.
6. Die passende QEMU-Binärdatei kann in das Root-Dateisystem der extrahierten Firmware kopiert werden.
7. Die Backdoor kann mit chroot und QEMU emuliert werden.
8. Über netcat kann auf die Backdoor zugegriffen werden.
9. Die QEMU-Binärdatei sollte aus dem Root-Dateisystem der extrahierten Firmware entfernt werden.
10. Die modifizierte Firmware kann mit FMK erneut gepackt werden.
11. Die Firmware mit Backdoor kann getestet werden, indem sie mit dem firmware analysis toolkit (FAT) emuliert und über netcat eine Verbindung zur IP-Adresse und zum Port der Backdoor auf dem Ziel hergestellt wird.

Wenn bereits über dynamische Analyse, Bootloader-Manipulation oder Hardware-Sicherheitstests eine Root-Shell erlangt wurde, können vorkompilierte Test-Binärdateien wie Implants oder Reverse Shells ausgeführt werden. Mit dem `msfvenom`-Tool von Metasploit kann ein architekturspezifischer Payload für diesen Validierungsablauf erstellt werden:<sup>[[4]](#references)</sup>

1. Die Architektur und Endianness der Zielfirmware sollten ermittelt werden.
2. Mit Msfvenom können der Ziel-Payload, die IP-Adresse des Angreifers, die Portnummer zum Lauschen, der Dateityp, die Architektur, die Plattform und die Ausgabedatei angegeben werden.
3. Der Payload kann auf das kompromittierte Gerät übertragen werden; anschließend ist sicherzustellen, dass er Ausführungsberechtigungen besitzt.
4. Metasploit kann für eingehende Anfragen vorbereitet werden, indem msfconsole gestartet und gemäß dem Payload konfiguriert wird.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.

## Nicht authentifizierte Transportbrücken zu privilegierten Update-Protokollen

Ein häufiger Fehler beim Design eingebetteter Systeme besteht darin, **dasselbe interne Befehlsprotokoll über mehrere Transportwege bereitzustellen**, die Authentifizierung aber nur bei einem davon durchzusetzen. Beispielsweise kann USB eine Challenge-Response-Authentifizierung erfordern, während BLE nicht authentifizierte **GATT-Schreibzugriffe** direkt an denselben privilegierten Firmware-Update-Handler weiterleitet.<sup>[[1]](#references)</sup>

Typischer offensiver Ablauf:

1. Die BLE-GATT-Datenbank auflisten und schreibbare Merkmale ermitteln, die von der offiziellen mobilen App verwendet werden.
2. Den App-Datenverkehr mitschneiden und nach **Magic Bytes / Opcodes** suchen, die dem kabelgebundenen Protokoll entsprechen.
3. Privilegierte Befehle **ohne Pairing** über BLE wiedergeben und prüfen, ob sensible Vorgänge weiterhin funktionieren.
4. Wenn Firmware-Upgrade-, Konfigurationsschreib-, Debug- oder Werksprüfungs-Opcodes erreichbar sind, BLE als **per Funk erreichbaren Admin-Port** behandeln.

Schnellprüfungen:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Dinge, die beim Reverse Engineering überprüft werden sollten:

- Erfordert BLE **Pairing/Bonding** oder reicht eine einfache Verbindung?
- Werden alle Transportwege an dieselbe interne Dispatcher-Tabelle geleitet?
- Werden privilegierte Opcodes über USB / BLE / UART / Wi-Fi unterschiedlich gefiltert?
- Kann die mobile App Firmware-Update-, Recovery- oder Diagnose-Handler remote auslösen?

## Firmware-Container, die nur durch eine Prüfsumme geschützt sind, enthalten weiterhin vom Angreifer kontrollierte Firmware

Ein Firmware-Container, der nur durch eine **nicht geheime Prüfsumme** (CRC32, SHA-256, MD5 usw.) geschützt ist, erkennt **Beschädigungen**, gewährleistet aber **keine Authentizität**. Kann der Angreifer die Update-Routine erreichen, kann er das Image patchen, die Prüfsumme neu berechnen und beliebigen Code flashen.<sup>[[1]](#references)</sup>

Warnsignale bei der RE:

- Der Update-Code validiert nur einen abschließenden Prüfsummen-Blob wie `CHK2`, `CRC` oder `SHA256`.
- Es gibt keine Signaturprüfung und keine Vertrauensbasis für Secure Boot.
- Es wird kein gerätegebundener MAC / HMAC / authentifizierte Verschlüsselung verwendet.
- Der Recovery-Modus akzeptiert dasselbe nicht authentifizierte Image-Format.

Praktischer Validierungsablauf:

1. Den Firmware-Container extrahieren und Bootloader, Haupt-Firmware sowie Integritätsmetadaten identifizieren.
2. Einen harmlosen String oder Banner im Image ändern.
3. Die Prüfsumme genau so neu berechnen, wie es der Updater erwartet.
4. Das Image über den normalen Update-Pfad erneut flashen.
5. Die Änderung beim Booten bestätigen, um den Austausch durch beliebige Firmware nachzuweisen.

Funktioniert dies über einen remote erreichbaren Transportweg wie BLE/Wi-Fi, handelt es sich effektiv um einen **nicht authentifizierten OTA-Firmware-Austausch**.

## Fragmentierter Update-Zustand und beschreibbare Integritätsmetadaten

Ein Updater kann während der Installation einen signierten Firmware-Header überprüfen, beim Booten aber dennoch nur einen gespeicherten Integritäts-Hash verwenden. Beim Cypherock X1 rief der Bootloader separate Firewall-Tasks auf, um den Header zu überprüfen und Version/Größe im RAM abzulegen, die Firmware-Signatur im RAM zu speichern, das geschriebene Image zu überprüfen und schließlich den Image-Hash in den persistenten Primary Bootloader Data abzulegen. Die Signatur selbst wurde nicht gespeichert. Diese Tasks konnten einzeln aufgerufen werden, statt eine einzige authentifizierte Upgrade-Transaktion durchzusetzen.<sup>[[5]](#references)</sup>

Mit MCU-Codeausführung und Flash-Schreibzugriff schrieb der beschriebene Angriff das Anwendungs-Image um, änderte die Versions-/Größenwerte im vom Firewall gemeinsam genutzten Bootloader-RAM und rief dann den abschließenden Metadaten-Task auf, um den Hash des bösartigen Images zu speichern und den normalen Boot-Zustand wiederherzustellen. Die normale Boot-Integritätsprüfung akzeptierte diesen Hash, ohne die Signatur erneut zu prüfen. Bei der Untersuchung eines ähnlichen Updaters sollte nachverfolgt werden, **welche Komponente jeden Task aufrufen kann**, wo verifizierte Werte gespeichert werden und ob die Entscheidung beim Booten *dasselbe Image* authentifiziert, dessen Hash gespeichert ist. Dies ist enger gefasst als ein Image-Format, das nur eine Prüfsumme verwendet: Eine Signaturprüfung war vorhanden, aber der Zustandsübergang war nicht daran gebunden.<sup>[[5]](#references)</sup>

## Secure-Element-Signaturen über nicht vertrauenswürdige Firmware-Messwerte

Ein Secure Element attestiert nicht allein dadurch den laufenden Code, dass es einen von diesem Code gelieferten Hash signiert. Bei derselben Wallet signierte das Secure Element die Geräteseriennummer und anschließend das XOR aus einer Cloud-Nonce und einem über den MCU bereitgestellten Firmware-Hash. Eine kompromittierte Firmware konnte einen erwarteten Hash zur Signatur vorlegen, während tatsächlich andere Bytes ausgeführt wurden. Der Companion-Client übermittelte außerdem die Firmware-Version an die Cloud. Der Vergleich mit dem erwarteten Hash durch den Verifizierer stützte sich somit weiterhin auf einen vom MCU stammenden Messwert statt auf ein unabhängiges Auslesen des Flashs.<sup>[[5]](#references)</sup>

Das Ergebnis auf dem Gerät bildete eine separate Vertrauensgrenze: Die Cloud überprüfte das Gerät, aber das Gerät authentifizierte nicht das Urteil der Cloud. Ein modifizierter Client konnte einem manipulierten Gerät lokal Erfolg melden. Prüfen Sie die Herkunft der Messwerte und die Authentifizierung der Antwort getrennt voneinander; eine gültige Secure-Element-Signatur und ein Erfolgsbildschirm beweisen für sich genommen nicht, dass die installierte Anwendung authentisch ist.<sup>[[5]](#references)</sup>

Die Offenlegung des geschützten Codes, die diese Analyse des Updaters ermöglichte, finden Sie unter [Erfassung von Firewall-Copy-Task-Firmware](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Ein vertrauenswürdiges USB-Peripheriegerät durch erneutes Flashen der Firmware in BadUSB verwandeln

Wenn der Host dem Zielgerät bereits über USB vertraut, muss bösartige Firmware möglicherweise keinen vollständigen neuen USB-Stack implementieren. Oft ist es wesentlich einfacher, **vorhandene HID-Unterstützung wiederzuverwenden**.<sup>[[1]](#references)</sup>

Nützliches Vorgehen:

1. Prüfen, ob das Gerät bereits als **HID Consumer Control**- / Media- / Vendor-HID-Schnittstelle enumeriert wird.
2. Den vorhandenen **HID-Report-Descriptor** in der Firmware finden.
3. Descriptor-Einträge ergänzen oder ersetzen, damit das Gerät auch **Tastatur**-Fähigkeiten anbietet.
4. Vorhandene Firmware-Routinen wiederverwenden, die bereits HID-Reports senden, statt eine neue Transport-Implementierung zu schreiben.
5. Tastendruck- und Tastenfreigabe-Reports einspeisen, um Befehle auf dem Host einzugeben.

Dadurch wird die Firmware-Kompromittierung zur **Host-Kompromittierung**, da der PC das neu geflashte Peripheriegerät als legitime Tastatur behandelt.

### Minimale Prüfliste für die Bewertung

- Zeigen `dmesg`, der Geräte-Manager oder die USB-Deskriptoren eine vorhandene HID-Schnittstelle?
- Gibt es freien Platz in der Nähe des Report-Descriptors oder eine verschiebbare Descriptor-Tabelle?
- Lassen sich vorhandene Routinen zum Senden von Media-Control-Reports für Tastatur-Reports wiederverwenden?
- Akzeptiert der Host nach dem erneuten Flashen automatisch die neue Tastaturschnittstelle?

## Zuverlässige Payload-Ausführung in RTOS-Firmware

Statt fragile Trampolines in beliebige Codepfade einzufügen, sollte nach **vorhandenen RTOS-Tasks** gesucht werden, die im normalen Betrieb ungenutzt sind oder nur geringe Auswirkungen haben.<sup>[[1]](#references)</sup>

Vorteile:

- Der Scheduler startet die Payload beim Booten auf natürliche Weise.
- Kritische Kontrollflüsse werden nicht beschädigt.
- Verzögerte Payloads lösen seltener Watchdog-Resets aus als Payloads, die innerhalb eines latenzempfindlichen USB-/Netzwerk-Handlers ausgeführt werden.

Geeignete Ziele sind Diagnose-, Factory-Test-, Telemetrie- oder Coprozessor-Service-Tasks, die im normalen Betrieb inaktiv zu sein scheinen.

## Schnelle Exploit-Iteration: harmlose Protokoll-Handler zweckentfremden

Sobald Firmware-Patching möglich ist, lässt sich die RE mit einem kompakten Ansatz beschleunigen: Ein harmloser Command-Handler (zum Beispiel ein **Echo-/Debug-Opcode**) wird durch eigene **Memory-Read-/Write-/Execute-Primitiven** ersetzt. So muss nicht für jedes Experiment vollständig neu geflasht werden. Besonders nützlich ist dies, wenn das Gerät den modifizierten Handler über einen schnellen kabelgebundenen Transport unterstützt.<sup>[[1]](#references)</sup>

Verwenden Sie dies, um:

- Scatter-geladene Memory-Maps zu überprüfen
- Heap-/Task-Zustände live zu untersuchen
- Kleine Payloads zu testen, bevor sie in den Flash geschrieben werden
- Funktionszeiger, Strings und Descriptor-Tabellen sicher auszulesen

## References

- [1] [Pwnd Blaster: Hacken Sie Ihren PC mit Ihrem Lautsprecher, ohne ihn jemals zu berühren](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit – So verwenden Sie `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Wie und warum wir die Cypherock Hardware Wallet gehackt haben: die ganze Geschichte](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
