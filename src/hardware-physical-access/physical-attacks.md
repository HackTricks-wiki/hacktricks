# Physische Angriffe

{{#include ../banners/hacktricks-training.md}}

## BIOS-Passwort-Wiederherstellung und Systemsicherheit

**Das Zurücksetzen des BIOS** kann auf verschiedene Weise erfolgen. Die meisten Motherboards verfügen über eine **Batterie**, die, wenn sie etwa **30 Minuten** entfernt wird, die BIOS-Einstellungen, einschließlich des Passworts, zurücksetzt. Alternativ kann ein **Jumper auf dem Motherboard** angepasst werden, um diese Einstellungen zurückzusetzen, indem bestimmte Pins verbunden werden.

Für Situationen, in denen Hardwareanpassungen nicht möglich oder praktisch sind, bieten **Software-Tools** eine Lösung. Das Ausführen eines Systems von einer **Live-CD/USB** mit Distributionen wie **Kali Linux** ermöglicht den Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der Wiederherstellung des BIOS-Passworts helfen können.

In Fällen, in denen das BIOS-Passwort unbekannt ist, führt das dreimalige falsche Eingeben normalerweise zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein verwendbares Passwort abzurufen.

### UEFI-Sicherheit

Für moderne Systeme, die **UEFI** anstelle des traditionellen BIOS verwenden, kann das Tool **chipsec** verwendet werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich der Deaktivierung von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM-Analyse und Kaltstartangriffe

RAM speichert Daten kurzzeitig nach einem Stromausfall, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann auf **10 Minuten** verlängert werden, indem kalte Substanzen wie flüssiger Stickstoff angewendet werden. Während dieses verlängerten Zeitraums kann ein **Speicherabbild** mit Tools wie **dd.exe** und **volatility** zur Analyse erstellt werden.

---

## Angriffe über Direct Memory Access (DMA)

**INCEPTION** ist ein Tool, das für die **physische Speicherbearbeitung** über DMA entwickelt wurde und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel ist. Es ermöglicht das Umgehen von Anmeldeverfahren, indem der Speicher so patcht wird, dass jedes Passwort akzeptiert wird. Es ist jedoch gegen **Windows 10**-Systeme ineffektiv.

---

## Live CD/USB für Systemzugriff

Das Ändern von System-Binärdateien wie **_sethc.exe_** oder **_Utilman.exe_** mit einer Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten, was Passwortänderungen ermöglicht.

**Kon-Boot** ist ein Tool, das das Anmelden bei Windows-Systemen ohne Kenntnis des Passworts erleichtert, indem es den Windows-Kernel oder UEFI vorübergehend modifiziert. Weitere Informationen finden Sie unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Umgang mit Windows-Sicherheitsfunktionen

### Boot- und Wiederherstellungstastenkombinationen

- **Supr**: Zugriff auf BIOS-Einstellungen.
- **F8**: In den Wiederherstellungsmodus eintreten.
- Das Drücken von **Shift** nach dem Windows-Banner kann die automatische Anmeldung umgehen.

### BAD USB-Geräte

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **bad USB**-Geräten, die vordefinierte Payloads ausführen können, wenn sie mit einem Zielcomputer verbunden werden.

### Volume Shadow Copy

Administratorrechte ermöglichen die Erstellung von Kopien sensibler Dateien, einschließlich der **SAM**-Datei, über PowerShell.

---

## Umgehen der BitLocker-Verschlüsselung

Die BitLocker-Verschlüsselung kann möglicherweise umgangen werden, wenn das **Wiederherstellungspasswort** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** können dafür verwendet werden.

---

## Social Engineering zur Hinzufügung eines Wiederherstellungsschlüssels

Ein neuer BitLocker-Wiederherstellungsschlüssel kann durch Social-Engineering-Taktiken hinzugefügt werden, indem ein Benutzer überzeugt wird, einen Befehl auszuführen, der einen neuen Wiederherstellungsschlüssel aus Nullen hinzufügt, wodurch der Entschlüsselungsprozess vereinfacht wird.

---

## Ausnutzen von Chassis-Überwachungs-/Wartungsschaltern zum Zurücksetzen des BIOS auf die Werkseinstellungen

Viele moderne Laptops und Desktop-Computer im Kleinformat verfügen über einen **Chassis-Überwachungsschalter**, der vom Embedded Controller (EC) und der BIOS/UEFI-Firmware überwacht wird. Während der Hauptzweck des Schalters darin besteht, einen Alarm auszulösen, wenn ein Gerät geöffnet wird, implementieren Anbieter manchmal eine **nicht dokumentierte Wiederherstellungstastenkombination**, die ausgelöst wird, wenn der Schalter in einem bestimmten Muster umgeschaltet wird.

### Wie der Angriff funktioniert

1. Der Schalter ist mit einem **GPIO-Interrupt** am EC verbunden.
2. Die Firmware, die auf dem EC läuft, verfolgt die **Zeit und die Anzahl der Drücke**.
3. Wenn ein fest codiertes Muster erkannt wird, ruft der EC eine *Mainboard-Reset*-Routine auf, die **den Inhalt des System-NVRAM/CMOS löscht**.
4. Beim nächsten Booten lädt das BIOS die Standardwerte – **Supervisor-Passwort, Secure Boot-Schlüssel und alle benutzerdefinierten Konfigurationen werden gelöscht**.

> Sobald Secure Boot deaktiviert und das Firmware-Passwort entfernt ist, kann der Angreifer einfach ein beliebiges externes OS-Image booten und unbeschränkten Zugriff auf die internen Laufwerke erhalten.

### Beispiel aus der Praxis – Framework 13 Laptop

Die Wiederherstellungstastenkombination für das Framework 13 (11./12./13. Generation) ist:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nach dem zehnten Zyklus setzt der EC ein Flag, das das BIOS anweist, NVRAM beim nächsten Neustart zu löschen. Der gesamte Vorgang dauert ~40 s und erfordert **nichts außer einem Schraubendreher**.

### Allgemeines Ausbeutungsverfahren

1. Schalten Sie das Ziel ein oder setzen Sie es in den Suspend-Modus und wieder zurück, damit der EC läuft.
2. Entfernen Sie die Unterseite, um den Intrusions-/Wartungsschalter freizulegen.
3. Reproduzieren Sie das herstellerspezifische Umschaltmuster (konsultieren Sie die Dokumentation, Foren oder reverse-engineeren Sie die EC-Firmware).
4. Bauen Sie das Gerät wieder zusammen und starten Sie neu – die Firmware-Schutzmaßnahmen sollten deaktiviert sein.
5. Booten Sie ein Live-USB (z. B. Kali Linux) und führen Sie die üblichen Post-Exploitation-Maßnahmen durch (Credential Dumping, Datenexfiltration, Implantation bösartiger EFI-Binärdateien usw.).

### Erkennung & Minderung

* Protokollieren Sie Chassis-Integritätsereignisse in der OS-Verwaltungskonsole und korrelieren Sie diese mit unerwarteten BIOS-Neustarts.
* Verwenden Sie **manipulationssichere Siegel** auf Schrauben/Abdeckungen, um das Öffnen zu erkennen.
* Halten Sie Geräte in **physisch kontrollierten Bereichen**; gehen Sie davon aus, dass physischer Zugang gleich vollständiger Kompromittierung ist.
* Deaktivieren Sie, wo verfügbar, die Funktion „Wartungsschalter zurücksetzen“ des Herstellers oder verlangen Sie eine zusätzliche kryptografische Autorisierung für NVRAM-Rücksetzungen.

---

## Referenzen

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
