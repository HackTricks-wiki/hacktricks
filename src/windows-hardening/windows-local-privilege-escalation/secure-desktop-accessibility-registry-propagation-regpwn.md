# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows-Accessibility-Features speichern die Benutzerkonfiguration unter HKCU und propagieren sie in sitzungsbezogene HKLM-Speicherorte. Während eines **Secure Desktop**-Übergangs (Sperrbildschirm oder UAC-Eingabeaufforderung) kopieren **SYSTEM**-Komponenten diese Werte erneut. Wenn der **per-session HKLM key** für den Benutzer beschreibbar ist, wird er zu einem privilegierten Schreib-Choke-Point, der mithilfe von **registry symbolic links** umgeleitet werden kann. Dadurch entsteht ein **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Die RegPwn-Technik missbraucht diese Propagationskette mit einem kleinen Race Window, das durch einen **opportunistic lock (oplock)** auf einer von `osk.exe` verwendeten Datei stabilisiert wird.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Beispiel-Feature: **On-Screen Keyboard** (`osk`). Die relevanten Speicherorte sind:

- **Systemweite Feature-Liste**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation während eines Secure-Desktop-Übergangs (vereinfacht):

1. **User `atbroker.exe`** kopiert `HKCU\...\ATConfig\osk` nach `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopiert `HKLM\...\Session<session id>\ATConfig\osk` nach `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopiert `HKU\.DEFAULT\...\ATConfig\osk` zurück nach `HKLM\...\Session<session id>\ATConfig\osk`.

Wenn der HKLM-Teilbaum der Sitzung für den Benutzer beschreibbar ist, ermöglichen Schritt 2/3 einen SYSTEM-Schreibzugriff über einen Speicherort, den der Benutzer ersetzen kann.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Ersetze den für den Benutzer beschreibbaren sitzungsbezogenen Schlüssel durch einen **registry symbolic link**, der auf ein vom Angreifer ausgewähltes Ziel verweist. Wenn der SYSTEM-Kopiervorgang ausgeführt wird, folgt er dem Link und schreibt vom Angreifer kontrollierte Werte in den beliebigen Zielschlüssel.

Kerngedanke:

- Ziel des Opfer-Schreibvorgangs (für den Benutzer beschreibbar):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Der Angreifer ersetzt diesen Schlüssel durch einen **registry link** auf einen beliebigen anderen Schlüssel.
- SYSTEM führt die Kopie aus und schreibt mit SYSTEM-Berechtigungen in den vom Angreifer ausgewählten Schlüssel.

Dadurch entsteht ein **arbitrary SYSTEM registry write**-Primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Zwischen dem Start von **SYSTEM `osk.exe`** und dem Schreiben in den sitzungsbezogenen Schlüssel besteht ein kurzes Timing-Fenster. Um den Ablauf zuverlässig zu machen, platziert der Exploit einen **oplock** auf:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Wenn der oplock ausgelöst wird, ersetzt der Angreifer den HKLM-Schlüssel der jeweiligen Sitzung durch einen registry link, lässt den SYSTEM-Schreibvorgang erfolgen und entfernt anschließend den link.<sup>[[1]](#references)</sup>

## Beispielhafter Exploit-Ablauf (Überblick)

1. Die aktuelle **session ID** aus dem Zugriffstoken abrufen.
2. Eine versteckte `osk.exe`-Instanz starten und kurz warten (damit der oplock ausgelöst wird).
3. Vom Angreifer kontrollierte Werte schreiben nach:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzen.
5. Den **Secure Desktop** auslösen (`LockWorkstation()`), wodurch `atbroker.exe` / `osk.exe` als SYSTEM gestartet werden.
6. Beim Auslösen des oplock `HKLM\...\Session<session id>\ATConfig\osk` durch einen **registry link** auf ein beliebiges Ziel ersetzen.
7. Kurz auf den Abschluss des SYSTEM-Kopiervorgangs warten und anschließend den link entfernen.<sup>[[1]](#references)</sup>

## Umwandlung des Primitives in SYSTEM-Ausführung

Eine einfache Kette besteht darin, einen Wert der **service configuration** (z. B. `ImagePath`) zu überschreiben und anschließend den Dienst zu starten. Der RegPwn PoC überschreibt den `ImagePath` von **`msiserver`** und löst ihn durch die Instanziierung des **MSI COM object** aus, was zur Ausführung von Code als **SYSTEM** führt.<sup>[[1]](#references)[[2]](#references)</sup>

## Verwandte Themen

Weitere Informationen zu Secure Desktop- / UIAccess-Verhalten:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Referenzen

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
