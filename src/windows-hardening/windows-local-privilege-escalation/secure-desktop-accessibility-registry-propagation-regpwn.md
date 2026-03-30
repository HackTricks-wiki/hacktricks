# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows Accessibility-Funktionen speichern Benutzerkonfigurationen unter HKCU und propagieren sie in pro-Session HKLM-Pfade. Während einer **Secure Desktop**-Transition (Sperrbildschirm oder UAC-Prompt) kopieren **SYSTEM**-Komponenten diese Werte erneut. Wenn der **pro-Session HKLM-Schlüssel vom Benutzer beschreibbar ist**, wird er zu einem privilegierten Schreib-Choke-Point, der mit **registry symbolic links** umgelenkt werden kann und so einen **beliebigen SYSTEM-Registry-Schreibzugriff** ermöglicht.

Die RegPwn-Technik missbraucht diese Propagationskette mit einem kleinen Rennfenster, das durch einen **opportunistic lock (oplock)** auf eine von `osk.exe` verwendete Datei stabilisiert wird.

## Registrierungs-Propagationskette (Accessibility -> Secure Desktop)

Beispielfeature: **Bildschirmtastatur** (`osk`). Die relevanten Orte sind:

- **Systemweite Feature-Liste**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-User-Konfiguration (vom Benutzer beschreibbar)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-Session HKLM-Konfiguration (von winlogon.exe erstellt, vom Benutzer beschreibbar)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM-Kontext)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation während einer Secure Desktop-Transition (vereinfacht):

1. **Benutzer `atbroker.exe`** kopiert `HKCU\...\ATConfig\osk` nach `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopiert `HKLM\...\Session<session id>\ATConfig\osk` nach `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopiert `HKU\.DEFAULT\...\ATConfig\osk` zurück nach `HKLM\...\Session<session id>\ATConfig\osk`.

Wenn der Session-HKLM-Teilbaum vom Benutzer beschreibbar ist, bieten Schritt 2/3 einen SYSTEM-Schreibzugriff über einen Ort, den der Benutzer ersetzen kann.

## Primitive: Beliebiger SYSTEM-Registry-Schreibzugriff via Registry Links

Ersetze den vom Benutzer beschreibbaren Per-Session-Schlüssel durch einen **registry symbolic link**, der auf ein vom Angreifer gewähltes Ziel zeigt. Wenn die SYSTEM-Kopie erfolgt, folgt sie dem Link und schreibt vom Angreifer kontrollierte Werte in den beliebigen Zielschlüssel.

Kernidee:

- Opfer-Schreibziel (vom Benutzer beschreibbar):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Angreifer ersetzt diesen Schlüssel durch einen **registry link** zu einem beliebigen anderen Schlüssel.
- SYSTEM führt die Kopie aus und schreibt mit SYSTEM-Berechtigungen in den vom Angreifer gewählten Schlüssel.

Das ergibt eine **beliebige SYSTEM-Registry-Schreiboperation**.

## Das Race-Fenster mit Oplocks gewinnen

Es gibt ein kurzes Timing-Fenster zwischen dem Start von **SYSTEM `osk.exe`** und dem Schreiben des Per-Session-Schlüssels. Um es zuverlässig zu machen, platziert der Exploit einen **oplock** auf:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wenn der oplock ausgelöst wird, ersetzt der Angreifer den HKLM-Schlüssel für die jeweilige Sitzung durch einen registry link, lässt SYSTEM schreiben und entfernt dann den Link.

## Beispielhafter Exploitation-Ablauf (High Level)

1. Hole die aktuelle **session ID** aus dem Access-Token.
2. Starte eine versteckte `osk.exe`-Instanz und warte kurz (sicherstellen, dass der oplock ausgelöst wird).
3. Schreibe vom Angreifer kontrollierte Werte in:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Setze einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Löse den **Secure Desktop** (`LockWorkstation()`) aus, wodurch SYSTEM `atbroker.exe` / `osk.exe` gestartet werden.
6. Beim Auslösen des oplock ersetze `HKLM\...\Session<session id>\ATConfig\osk` durch einen **registry link** zu einem beliebigen Ziel.
7. Warte kurz, bis die SYSTEM-Kopie abgeschlossen ist, und entferne dann den Link.

## Umwandlung des Primitives in SYSTEM-Ausführung

Eine einfache Kette ist, einen Wert der **service configuration** zu überschreiben (z. B. `ImagePath`) und dann den Service zu starten. Die RegPwn PoC überschreibt den `ImagePath` von **`msiserver`** und löst diesen aus, indem das **MSI COM object** instanziiert wird, was zu **SYSTEM**-Codeausführung führt.

## Verwandt

Für andere Secure Desktop / UIAccess-Verhalten, siehe:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
