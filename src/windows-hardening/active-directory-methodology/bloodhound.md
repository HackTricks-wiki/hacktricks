# BloodHound & andere Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> HINWEIS: Diese Seite fasst einige der nützlichsten Utilities zusammen, um Active-Directory-Beziehungen zu **enumerate** und zu **visualise**. Für die Sammlung über den verdeckten **Active Directory Web Services (ADWS)**-Kanal siehe die obige Referenz.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ist ein fortgeschrittener **AD viewer & editor**, der Folgendes ermöglicht:

* GUI-Browsing des Verzeichnisbaums
* Bearbeiten von Objektattributen & Security Descriptors
* Erstellen / Vergleichen von Snapshots für die Offline-Analyse

### Schnelle Verwendung

1. Starte das Tool und verbinde dich mit `dc01.corp.local` unter Verwendung beliebiger Domain-Credentials.
2. Erstelle über `File ➜ Create Snapshot` einen Offline-Snapshot.
3. Vergleiche zwei Snapshots mit `File ➜ Compare`, um Berechtigungsabweichungen zu erkennen.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrahiert eine große Menge an Artefakten aus einer Domain (ACLs, GPOs, Trusts, CA-Templates …) und erstellt einen **Excel-Report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (Graphvisualisierung)

[BloodHound](https://github.com/SpecterOps/BloodHound) nutzt die Graphentheorie, um verborgene Berechtigungsbeziehungen innerhalb von lokalem AD, Entra ID und allen zusätzlichen Angriffsflächendaten aufzudecken, die du über OpenGraph aufnimmst.<sup>[[1]](#references)</sup>

### Bereitstellung (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collector

* `SharpHound.exe` / `Invoke-BloodHound` – native oder PowerShell-Variante
* `RustHound-CE` – plattformübergreifender CE-Collector für Linux, macOS und Windows
* `NetExec --bloodhound` – schnelle LDAP-basierte Sammlung von Linux aus
* `AzureHound` – Entra-ID-Aufzählung
* **SoaPy + BOFHound** – ADWS-Sammlung (siehe Link oben)

> BloodHound CE `v8+` hat das Collector-Ausgabeformat geändert, als OpenGraph eingeführt wurde. Nach einem Upgrade von Legacy-BloodHound oder älteren CE-Installationen sollte die Erkennung mit aktuellen Collectors erneut ausgeführt werden, bevor die Daten importiert werden.<sup>[[1]](#references)</sup>

#### Häufige SharpHound-Modi
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Die Collector generieren JSON, das über die BloodHound-GUI eingelesen wird.

#### SharpHound von einem nicht domänengebundenen Windows-Host

Wenn deine Operator-VM nicht der Zieldomäne beigetreten ist, setze DNS auf einen DC, starte eine **network-only** Shell, überprüfe, ob du `SYSVOL`/`NETLOGON` auf einem DC sehen kannst, und führe anschließend die Sammlung gegen die Remote-Domäne durch:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Dies ist nützlich für kurzlebige Jump Boxes oder Operator-Workstations, die nicht in die Domäne eingebunden sein sollten.

#### Plattformübergreifende Erfassung von Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` ist eine gute Standardwahl, wenn du von einem Nicht-Windows-Host CE-kompatible Ausgaben benötigst.<sup>[[2]](#references)</sup> `NetExec` ist praktisch, wenn du es bereits für die LDAP-Validierung oder das Spraying verwendest und schnell einen Graph-Import durchführen möchtest. Für Nicht-AD-Datensätze kann BloodHound OpenGraph mit Collectors wie [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) erweitert werden.<sup>[[1]](#references)</sup>

### ADPathFinder (OpenGraph-Priorisierung von Pfaden)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) baut auf BloodHound CE/OpenGraph auf, wenn der Graph zu groß ist, um manuell darin zu pivotieren. Statt nur zu fragen, ob ein Principal ein bestimmtes Ziel erreichen kann, berechnet es die kürzesten Pfade von vielen Benutzern und Computern mit niedrigen Berechtigungen zu hochwertigen Objekten, gruppiert Pfade, die dieselben Kanten wiederverwenden, und zeigt den gemeinsamen Engpass auf, der zuerst behoben werden sollte.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Mit importierten Daten aus `MSSQLHound` und `ConfigManBearPig` kann ein Befund [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) und [SCCM-Angriffspfade](sccm-management-point-relay-sql-policy-secrets.md) miteinander verbinden, anstatt sie als separate Hinweise zu behandeln.<sup>[[4]](#references)</sup> Beispiel für einen gemeinsamen Pfad:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Verfolge den **effektiven Sicherheitskontext** an jeder Kante. Ein Pfad wird domainkritisch, sobald eine Transition als privilegierte Domain-Identität ausgeführt wird, selbst wenn sie von einem normalen Benutzer ausging.
- Gruppierte Findings eignen sich ideal für die **Behebung von Choke Points**: Das Entfernen einer einzigen SQL-Impersonation-Berechtigung, eines Linked-Server-Trusts, eines Certificate-Template-Abuse-Pfads oder einer SCCM-Zuweisung kann viele kürzeste Pfade gleichzeitig beseitigen.
- Bewerte „mittlere“ Findings anhand des **Graph-Kontexts** neu. Deaktiviertes SMB Signing, WebClient-Exposure, Delegation-Fehler oder für NTLM-Relay geeignete SQL-Server verdienen eine höhere Priorität, wenn der kompromittierte Knoten weitere Pfade zu Domain Admins, Domain Controllern, CAs oder SCCM Site Servern besitzt.
- Wenn du außerdem `NTDS.dit`-Output und eine Hashcat-Potfile hast, korreliert `--pwd` geknackte Passwörter mit BloodHound-Eigenschaften, sodass du schnell zwischen gewöhnlicher Password-Reuse und geknackten Credentials privilegierter, Kerberoastable, AS-REP-roastable oder pfadrelevanter Accounts unterscheiden kannst.

### Erfassung von Privilegien und Anmelderechten

Windows-**Token-Privilegien** (z. B. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) können DACL-Prüfungen umgehen. Ihre domainweite Erfassung macht daher lokale LPE-Kanten sichtbar, die ACL-only-Graphen übersehen. **Anmelderechte** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` und ihre `SeDeny*`-Gegenstücke) werden von LSA geprüft, bevor überhaupt ein Token existiert. Verweigerungen haben Vorrang und begrenzen daher die laterale Bewegung maßgeblich (RDP/SMB/Anmeldung über Scheduled Task oder Service).<sup>[[3]](#references)</sup>

**Führe Collector mit erhöhten Rechten aus**, wenn möglich: UAC erstellt für interaktive Administratoren ein gefiltertes Token (über `NtFilterToken`), entfernt sensible Privilegien und markiert Administrator-SIDs als „deny-only“. Wenn du Privilegien aus einer nicht erhöhten Shell enumerierst, bleiben wichtige Privilegien unsichtbar und BloodHound nimmt die Kanten nicht auf.<sup>[[3]](#references)</sup>

Es gibt inzwischen zwei sich ergänzende SharpHound-Collection-Strategien:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL-Parsing (unauffällig, geringe Rechte):**
1. GPOs über LDAP enumerieren (`(objectCategory=groupPolicyContainer)`) und jeweils den Wert `gPCFileSysPath` auslesen.
2. `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` aus SYSVOL abrufen und den Abschnitt `[Privilege Rights]` parsen, der Privilegien-/Anmelderecht-Namen auf SIDs abbildet.
3. GPO-Links über `gPLink` auf OUs/Sites/Domains auflösen, Computer in den verknüpften Containern auflisten und die Rechte diesen Maschinen zuordnen.
4. Vorteil: Funktioniert mit einem normalen Benutzer und ist unauffällig; Nachteil: Es werden nur über GPO gesetzte Rechte erfasst (lokale Anpassungen werden übersehen).

- **LSA-RPC-Enumeration (auffällig, präzise):**
- Aus einem Kontext mit lokalen Administratorrechten auf dem Ziel die Local Security Policy öffnen und für jedes Privileg/Anmelderecht `LsaEnumerateAccountsWithUserRight` aufrufen, um über RPC zugewiesene Principals zu enumerieren.
- Vorteil: Erfasst lokal oder außerhalb von GPO gesetzte Rechte; Nachteil: Auffälliger Netzwerkverkehr und Administratorrechte auf jedem Host erforderlich.

**Beispiel für einen durch diese Kanten sichtbaren Abuse-Pfad:** `CanRDP` ➜ Host, auf dem dein Benutzer außerdem `SeBackupPrivilege` besitzt ➜ eine erhöhte Shell starten, um gefilterte Tokens zu vermeiden ➜ Backup-Semantik verwenden, um trotz restriktiver DACLs die Hives `SAM` und `SYSTEM` zu lesen ➜ exfiltrieren und offline `secretsdump.py` ausführen, um den NT-Hash des lokalen Administrators für laterale Bewegung/Privilege Escalation zu erhalten.<sup>[[3]](#references)</sup>

### Kerberoasting mit BloodHound priorisieren

Nutze den Graph-Kontext, um das Roasting gezielt durchzuführen:

1. Einmalig mit einem ADWS-kompatiblen Collector sammeln und offline arbeiten:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Die ZIP-Datei importieren, den kompromittierten Principal als unter eigener Kontrolle markieren und integrierte Abfragen (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ausführen, um SPN-Accounts mit Administrator- oder Infrastrukturrechten sichtbar zu machen.
3. SPNs nach ihrem Blast Radius priorisieren; vor dem Cracking `pwdLastSet`, `lastLogon` und erlaubte Verschlüsselungstypen prüfen.
4. Nur ausgewählte Tickets anfordern, offline cracken und BloodHound anschließend mit dem neuen Zugriff erneut abfragen:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriert **Group Policy Objects** und hebt Fehlkonfigurationen hervor.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) führt eine **Zustandsprüfung** von Active Directory durch und generiert einen HTML-Bericht mit Risikobewertung.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referenzen

- [1] [BloodHound Community Edition v8 startet mit OpenGraph: Identitäts-Angriffspfade über Active Directory & Entra ID hinaus](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Über ACLs hinaus: Zuordnung von Windows-Privilege-Escalation-Pfaden mit BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: Zuordnung von OpenGraph-Angriffspfaden in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
