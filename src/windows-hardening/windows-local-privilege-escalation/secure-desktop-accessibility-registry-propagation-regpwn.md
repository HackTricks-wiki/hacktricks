# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows-Accessibility-Features speichern die Benutzerkonfiguration unter HKCU und übertragen sie in sitzungsbezogene HKLM-Speicherorte. Während eines **Secure Desktop**-Wechsels (Sperrbildschirm oder UAC-Eingabeaufforderung kopieren **SYSTEM**-Komponenten diese Werte erneut. Wenn der **sitzungsbezogene HKLM-Schlüssel für den Benutzer beschreibbar ist**, wird er zu einem privilegierten Schreibpunkt, der mithilfe von **registry symbolic links** umgeleitet werden kann. Dadurch entsteht ein **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Die RegPwn-Technik missbraucht diese Übertragungskette mit einem kleinen Race Window, das durch einen **opportunistic lock (oplock)** auf einer von `osk.exe` verwendeten Datei stabilisiert wird.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Beispiel-Feature: **On-Screen Keyboard** (`osk`). Die relevanten Speicherorte sind:

- **Systemweite Feature-Liste**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Benutzerspezifische Konfiguration (für den Benutzer beschreibbar)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Sitzungsbezogene HKLM-Konfiguration (von `winlogon.exe` erstellt, für den Benutzer beschreibbar)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM-Kontext)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Übertragung während eines Secure-Desktop-Wechsels (vereinfacht):

1. **Benutzer-`atbroker.exe`** kopiert `HKCU\...\ATConfig\osk` nach `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM-`atbroker.exe`** kopiert `HKLM\...\Session<session id>\ATConfig\osk` nach `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM-`osk.exe`** kopiert `HKU\.DEFAULT\...\ATConfig\osk` zurück nach `HKLM\...\Session<session id>\ATConfig\osk`.

Wenn der sitzungsbezogene HKLM-Teilbaum für den Benutzer beschreibbar ist, ermöglichen Schritt 2/3 einen SYSTEM-Schreibvorgang über einen Speicherort, den der Benutzer ersetzen kann.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Ersetze den für den Benutzer beschreibbaren sitzungsbezogenen Schlüssel durch einen **registry symbolic link**, der auf ein vom Angreifer gewähltes Ziel zeigt. Wenn der SYSTEM-Kopiervorgang erfolgt, folgt er dem Link und schreibt vom Angreifer kontrollierte Werte in den beliebigen Zielschlüssel.

Kerngedanke:

- Ziel des Schreibvorgangs (für den Benutzer beschreibbar):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Der Angreifer ersetzt diesen Schlüssel durch einen **registry link** auf einen beliebigen anderen Schlüssel.
- SYSTEM führt die Kopie aus und schreibt mit SYSTEM-Berechtigungen in den vom Angreifer gewählten Schlüssel.

Dadurch entsteht ein **arbitrary SYSTEM registry write**-Primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Zwischen dem Start von **SYSTEM `osk.exe`** und dem Schreiben in den sitzungsbezogenen Schlüssel besteht ein kurzes Zeitfenster. Um den Exploit zuverlässig zu machen, platziert der Exploit einen **oplock** auf:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wenn der oplock ausgelöst wird, ersetzt der Angreifer den HKLM-Schlüssel der jeweiligen Sitzung durch einen registry link, lässt den SYSTEM-Schreibvorgang erfolgen und entfernt anschließend den link.<sup>[[1]](#references)</sup>

## Beispielhafter Exploit-Ablauf (High Level)

1. Die aktuelle **Sitzungs-ID** aus dem Zugriffstoken abrufen.
2. Eine versteckte Instanz von `osk.exe` starten und kurz warten (um sicherzustellen, dass der oplock ausgelöst wird).
3. Vom Angreifer kontrollierte Werte in folgende Registry schreiben:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzen.
5. **Secure Desktop** auslösen (`LockWorkstation()`), wodurch SYSTEM `atbroker.exe` / `osk.exe` startet.
6. Beim Auslösen des oplock `HKLM\...\Session<session id>\ATConfig\osk` durch einen **registry link** auf ein beliebiges Ziel ersetzen.
7. Kurz warten, bis die SYSTEM-Kopie abgeschlossen ist, und anschließend den link entfernen.<sup>[[1]](#references)</sup>

## Umwandlung des Primitives in SYSTEM-Ausführung

Eine unkomplizierte Kette besteht darin, einen Wert der **service configuration** (z. B. `ImagePath`) zu überschreiben und anschließend den service zu starten. Der RegPwn PoC überschreibt `ImagePath` von **`msiserver`** und löst den service durch die Instanziierung des **MSI COM object** aus, was zur Ausführung von Code als **SYSTEM** führt.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Verwandte Themen

Weitere Informationen zu anderen Secure Desktop- / UIAccess-Verhaltensweisen:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
