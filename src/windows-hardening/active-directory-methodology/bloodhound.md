# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> HINWEIS: Diese Seite gruppiert einige der nützlichsten Utilities, um Active Directory-Beziehungen zu **enumerate** und zu **visualise**. Für die Erfassung über den unauffälligen **Active Directory Web Services (ADWS)**-Kanal siehe die Referenz oben.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ist ein fortgeschrittener **AD viewer & editor**, der Folgendes ermöglicht:

* GUI-Browsing des Verzeichnisbaums
* Bearbeiten von Objektattributen & Sicherheitsdeskriptoren
* Erstellen/Vergleichen von Snapshots für die Offline-Analyse

### Quick usage

1. Starte das Tool und verbinde dich mit `dc01.corp.local` mit beliebigen Domänenanmeldeinformationen.
2. Erstelle einen Offline-Snapshot via `File ➜ Create Snapshot`.
3. Vergleiche zwei Snapshots mit `File ➜ Compare`, um Permission-Drifts zu erkennen.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrahiert eine große Menge an Artefakten aus einer Domäne (ACLs, GPOs, trusts, CA templates …) und erzeugt einen **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (Graph-Visualisierung)

[BloodHound](https://github.com/SpecterOps/BloodHound) verwendet Graphentheorie, um versteckte Berechtigungsbeziehungen innerhalb von On-Prem-AD, Entra ID und allen zusätzlichen Attack-Surface-Daten aufzudecken, die du über OpenGraph ingestierst.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native oder PowerShell-Variante
* `RustHound-CE` – plattformübergreifender CE-Collector für Linux, macOS und Windows
* `NetExec --bloodhound` – schnelle LDAP-gestützte Erfassung von Linux aus
* `AzureHound` – Entra ID-Enumeration
* **SoaPy + BOFHound** – ADWS-Erfassung (siehe Link oben)

> BloodHound CE `v8+` änderte das Ausgabeformat des Collectors, als OpenGraph eingeführt wurde. Nach dem Upgrade von legacy BloodHound oder älteren CE-Installationen die Erfassung mit aktuellen Collectors erneut ausführen, bevor die Daten importiert werden.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Die Collectors erzeugen JSON, das über die BloodHound GUI eingelesen wird.

#### SharpHound von einem Windows-Host, der nicht in die Domain aufgenommen ist

Wenn deine Operator-VM nicht der Ziel-Domain beigetreten ist, richte DNS auf einen DC, starte eine **network-only** Shell, verifiziere, dass du `SYSVOL`/`NETLOGON` auf einem DC sehen kannst, und sammle dann gegen die Remote-Domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Dies ist nützlich für wegwerfbare Jump Boxes oder Operator-Workstations, die nicht der Domain beitreten sollten.

#### Plattformübergreifende Erfassung von Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` ist ein guter Standard, wenn du CE-kompatible Ausgabe von einem Nicht-Windows-Host willst. `NetExec` ist praktisch, wenn du es bereits für LDAP-Validierung oder Spraying benutzt und einen schnellen Graph-Import willst. Für Nicht-AD-Datasets kann BloodHound OpenGraph mit Collectors wie [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) erweitert werden.

### Privilege & logon-right collection

Windows **token privileges** (z. B. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) können DACL-Prüfungen umgehen, daher deckt das domain-weite Mapping lokale LPE-Edges auf, die ACL-only-Graphs übersehen. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` und ihre `SeDeny*`-Gegenstücke) werden von LSA erzwungen, bevor überhaupt ein Token existiert, und Denies haben Vorrang, sodass sie lateral movement (RDP/SMB/scheduled task/service logon) direkt einschränken.

**Run collectors elevated** wenn möglich: UAC erstellt für interaktive Admins ein gefiltertes Token (via `NtFilterToken`), entfernt sensible Privileges und markiert Admin-SIDs als deny-only. Wenn du Privileges aus einer nicht-elevated Shell enumerierst, bleiben hochrelevante Privileges unsichtbar und BloodHound importiert die Edges nicht.

Es gibt jetzt zwei komplementäre SharpHound-Collection-Strategien:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. GPOs über LDAP enumerieren (`(objectCategory=groupPolicyContainer)`) und jedes `gPCFileSysPath` lesen.
2. `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` aus SYSVOL holen und den Abschnitt `[Privilege Rights]` parsen, der Privilege/logon-right-Namen auf SIDs abbildet.
3. GPO-Links über `gPLink` auf OUs/sites/domains auflösen, Computer in den verknüpften Containern auflisten und die Rights diesen Maschinen zuordnen.
4. Vorteil: funktioniert mit einem normalen User und ist leise; Nachteil: sieht nur Rights, die per GPO gesetzt wurden (lokale Anpassungen werden verpasst).

- **LSA RPC enumeration (noisy, accurate):**
- Aus einem Kontext mit local admin auf dem Ziel die Local Security Policy öffnen und für jedes Privilege/logon right `LsaEnumerateAccountsWithUserRight` aufrufen, um zugewiesene Principals über RPC zu enumerieren.
- Vorteil: erfasst Rights, die lokal oder außerhalb von GPO gesetzt wurden; Nachteil: lauter Netzwerktraffic und Admin-Anforderung auf jedem Host.

**Beispiel-Missbrauchspfad, den diese Edges sichtbar machen:** `CanRDP` ➜ Host, auf dem dein User zusätzlich `SeBackupPrivilege` hat ➜ eine elevated Shell starten, um gefilterte Tokens zu vermeiden ➜ Backup-Semantik nutzen, um trotz restriktiver DACLs die Hives `SAM` und `SYSTEM` zu lesen ➜ exfiltrieren und `secretsdump.py` offline ausführen, um den lokalen Administrator-NTHash für lateral movement/privilege escalation wiederherzustellen.

### Prioritising Kerberoasting with BloodHound

Nutze Graph-Kontext, um das Roasting gezielt zu halten:

1. Einmal mit einem ADWS-kompatiblen Collector sammeln und offline arbeiten:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Das ZIP importieren, den kompromittierten Principal als owned markieren und die eingebauten Queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ausführen, um SPN-Accounts mit Admin-/Infra-Rechten sichtbar zu machen.
3. SPNs nach Blast Radius priorisieren; `pwdLastSet`, `lastLogon` und erlaubte Encryption Types prüfen, bevor du crackst.
4. Nur ausgewählte Tickets anfordern, offline cracken und dann BloodHound mit dem neuen Access erneut abfragen:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriert **Group Policy Objects** und hebt Misconfigurations hervor.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) führt einen **Health-Check** von Active Directory durch und erstellt einen HTML-Report mit Risk Scoring.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
