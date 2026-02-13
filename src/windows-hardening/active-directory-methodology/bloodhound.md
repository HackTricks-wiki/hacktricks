# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> HINWEIS: Diese Seite gruppiert einige der nützlichsten Dienstprogramme, um **enumerate** und **visualise** Active Directory relationships. Für die Sammlung über den stealthy **Active Directory Web Services (ADWS)** channel siehe die Referenz oben.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ist ein fortgeschrittener **AD viewer & editor**, der ermöglicht:

* GUI-Durchsuchen des Verzeichnisbaums
* Bearbeiten von Objektattributen & Sicherheitsdeskriptoren
* Erstellen von Snapshots / Vergleich für die Offline-Analyse

### Quick usage

1. Starten Sie das Tool und verbinden Sie sich mit `dc01.corp.local` mit beliebigen Domain-Anmeldedaten.
2. Erstellen Sie einen Offline-Snapshot über `File ➜ Create Snapshot`.
3. Vergleichen Sie zwei Snapshots mit `File ➜ Compare`, um Änderungen in Berechtigungen zu erkennen.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrahiert eine große Menge an Artefakten aus einer Domain (ACLs, GPOs, trusts, CA templates …) und erzeugt einen Excel-Bericht.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (Graph-Visualisierung)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) nutzt Graphentheorie + Neo4j, um verborgene Privilegienbeziehungen innerhalb von on-prem AD & Azure AD aufzudecken.

### Bereitstellung (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Sammler

* `SharpHound.exe` / `Invoke-BloodHound` – nativ oder PowerShell-Variante
* `AzureHound` – Azure AD-Aufzählung
* **SoaPy + BOFHound** – ADWS-Sammlung (siehe Link oben)

#### Häufige SharpHound-Modi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die Collector erzeugen JSON, das von der BloodHound-GUI eingelesen wird.

### Sammlung von Privilegien und Logon-Rechten

Windows **token privileges** (z. B. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) können DACL-Prüfungen umgehen, daher offenbart ihre domänenweite Zuordnung lokale LPE-Kanten, die ACL-only graphs übersehen. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` und deren `SeDeny*`-Gegenstücke) werden von der LSA durchgesetzt, bevor ein Token überhaupt existiert, und Verweigerungen haben Vorrang; sie schränken lateral movement (RDP/SMB/scheduled task/service logon) maßgeblich ein.

**Collector mit erhöhten Rechten ausführen**, wenn möglich: UAC erstellt für interaktive Admins ein gefiltertes Token (via `NtFilterToken`), entfernt sensible Privilegien und markiert Admin-SIDs als deny-only. Wenn du Privilegien aus einer nicht-erhöhten Shell auflistest, sind hochstufige Privilegien unsichtbar und BloodHound wird die Kanten nicht einlesen.

Es existieren nun zwei komplementäre SharpHound-Sammelstrategien:

- **GPO/SYSVOL parsing (leise, mit niedrigen Rechten):**
1. GPOs über LDAP aufzählen (`(objectCategory=groupPolicyContainer)`) und jeden `gPCFileSysPath` lesen.
2. `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` aus SYSVOL holen und den Abschnitt `[Privilege Rights]` parsen, der Privileg-/Logon-Right-Namen auf SIDs abbildet.
3. GPO-Links über `gPLink` auf OUs/sites/domains auflösen, Computer in den verlinkten Containern auflisten und die Rechte diesen Maschinen zuordnen.
4. Vorteil: funktioniert mit einem normalen Benutzer und ist unauffällig; Nachteil: sieht nur Rechte, die via GPO gesetzt wurden (lokale Anpassungen werden verpasst).

- **LSA RPC enumeration (laut, genau):**
- Aus einem Kontext mit lokalem Admin auf dem Ziel die Local Security Policy öffnen und `LsaEnumerateAccountsWithUserRight` für jedes Privileg/Logon-Right aufrufen, um die zugewiesenen Prinzipale über RPC aufzulisten.
- Vorteil: erfasst Rechte, die lokal oder außerhalb von GPO gesetzt wurden; Nachteil: lauter Netzwerkverkehr und Admin-Recht auf jedem Host erforderlich.

Beispiel für einen durch diese Kanten aufgezeigten Missbrauchspfad: `CanRDP` ➜ Host, auf dem dein Benutzer außerdem `SeBackupPrivilege` hat ➜ eine erhöhte Shell starten, um gefilterte Tokens zu vermeiden ➜ Backup-Semantik verwenden, um trotz restriktiver DACLs die `SAM`- und `SYSTEM`-Hives zu lesen ➜ exfiltrieren und `secretsdump.py` offline ausführen, um den lokalen Administrator-NT-Hash für lateral movement/privilege escalation zu gewinnen.

### Priorisierung von Kerberoasting mit BloodHound

Nutze den Graph-Kontext, um das Roasting zielgerichtet durchzuführen:

1. Einmal mit einem ADWS-kompatiblen Collector sammeln und offline arbeiten:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Die ZIP importieren, das kompromittierte Principal als owned markieren und eingebaute Queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ausführen, um SPN-Konten mit Admin-/Infra-Rechten anzuzeigen.
3. SPNs nach Blast-Radius priorisieren; `pwdLastSet`, `lastLogon` und erlaubte Verschlüsselungstypen vor dem cracking überprüfen.
4. Nur ausgewählte Tickets anfordern, offline cracken, und dann BloodHound mit dem neuen Zugriff erneut abfragen:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriert **Gruppenrichtlinienobjekte** und hebt Fehlkonfigurationen hervor.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) führt einen **Gesundheitscheck** von Active Directory durch und erstellt einen HTML-Bericht mit Risikobewertung.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Quellen

- [HackTheBox Mirage: Verkettung von NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets und Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Jenseits von ACLs: Kartierung von Windows Privilege Escalation Paths mit BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
