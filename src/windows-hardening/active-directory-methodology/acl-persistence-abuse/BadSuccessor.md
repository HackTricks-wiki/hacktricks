# 滥用 Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## 概述

委派的托管服务账户 (**dMSAs**) 是在 **Windows Server 2025** 中引入的一种全新 AD 主体类型。它们旨在通过允许一键“迁移”来替代传统服务账户，自动将旧账户的服务主体名称 (SPNs)、组成员资格、委派设置，甚至加密密钥复制到新的 dMSA 中，从而为应用程序提供无缝切换，并消除 Kerberoasting 风险。

Akamai 研究人员发现，单个属性 — **`msDS‑ManagedAccountPrecededByLink`** — 告诉 KDC 哪个传统账户是 dMSA “继承”的。如果攻击者能够写入该属性（并切换 **`msDS‑DelegatedMSAState` → 2**），KDC 将乐意构建一个 PAC，该 PAC **继承所选受害者的每个 SID**，有效地允许 dMSA 冒充任何用户，包括域管理员。

## dMSA 到底是什么？

* 基于 **gMSA** 技术，但存储为新的 AD 类 **`msDS‑DelegatedManagedServiceAccount`**。
* 支持 **选择性迁移**：调用 `Start‑ADServiceAccountMigration` 将 dMSA 链接到传统账户，授予传统账户对 `msDS‑GroupMSAMembership` 的写入访问权限，并将 `msDS‑DelegatedMSAState` 翻转为 1。
* 在 `Complete‑ADServiceAccountMigration` 之后，替代账户被禁用，dMSA 变为完全功能；任何之前使用传统账户的主机都被自动授权以提取 dMSA 的密码。
* 在身份验证期间，KDC 嵌入一个 **KERB‑SUPERSEDED‑BY‑USER** 提示，以便 Windows 11/24H2 客户端透明地使用 dMSA 重试。

## 攻击要求
1. **至少一个 Windows Server 2025 DC**，以便 dMSA LDAP 类和 KDC 逻辑存在。
2. **在 OU 上的任何对象创建或属性写入权限**（任何 OU） – 例如 `Create msDS‑DelegatedManagedServiceAccount` 或简单地 **Create All Child Objects**。Akamai 发现 91% 的真实租户将此类“良性”OU 权限授予非管理员。
3. 能够从任何域加入的主机上运行工具（PowerShell/Rubeus）以请求 Kerberos 票证。
*不需要对受害者用户的控制；攻击从未直接接触目标账户。*

## 步骤：BadSuccessor*特权提升

1. **定位或创建一个你控制的 dMSA**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

因为你在可以写入的 OU 中创建了对象，所以你自动拥有其所有属性。

2. **在两个 LDAP 写入中模拟“完成迁移”**：
- 设置 `msDS‑ManagedAccountPrecededByLink = DN` 为任何受害者（例如 `CN=Administrator,CN=Users,DC=lab,DC=local`）。
- 设置 `msDS‑DelegatedMSAState = 2`（迁移完成）。

像 **Set‑ADComputer, ldapmodify**，甚至 **ADSI Edit** 这样的工具都可以使用；不需要域管理员权限。

3. **请求 dMSA 的 TGT** — Rubeus 支持 `/dmsa` 标志：

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

返回的 PAC 现在包含 SID 500（Administrator）以及域管理员/企业管理员组。

## 收集所有用户密码

在合法迁移期间，KDC 必须允许新的 dMSA 解密 **在切换之前发给旧账户的票证**。为了避免中断实时会话，它将当前密钥和以前的密钥放入一个新的 ASN.1 blob 中，称为 **`KERB‑DMSA‑KEY‑PACKAGE`**。

因为我们的假迁移声称 dMSA 继承了受害者，KDC 认真地将受害者的 RC4-HMAC 密钥复制到 **previous‑keys** 列表中 — 即使 dMSA 从未拥有“以前”的密码。该 RC4 密钥是未加盐的，因此它实际上是受害者的 NT 哈希，赋予攻击者 **离线破解或“传递哈希”** 的能力。

因此，大规模链接数千个用户使攻击者能够“规模化”地转储哈希，将 **BadSuccessor 变成特权提升和凭证泄露的原语**。

## 工具

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## 参考

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
