# Active Directory Web Services (ADWS) 枚举与隐蔽采集

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) 是 **自 Windows Server 2008 R2 起在每个 Domain Controller 上默认启用**，并在 TCP **9389** 上监听。尽管名称如此，**不涉及任何 HTTP**。相反，该服务通过一系列专有的 .NET 封装协议暴露 LDAP 风格的数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量封装在这些二进制 SOAP 帧内并通过不常见的端口传输，**通过 ADWS 的枚举比经典的 LDAP/389 和 636 流量更不容易被检测、过滤或签名**。对操作者来说，这意味着：

* 更隐蔽的侦察 – 蓝队通常关注 LDAP 查询。
* 可以通过将 9389/TCP 隧道到 SOCKS 代理，从 **非 Windows 主机 (Linux, macOS)** 收集数据。
* 可获取与 LDAP 相同的数据（users、groups、ACLs、schema 等），并能够执行 **写操作**（例如用于 **RBCD** 的 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互通过 WS-Enumeration 实现：每个查询以一个定义 LDAP 过滤器/属性并返回 `EnumerationContext` GUID 的 `Enumerate` 消息开始，随后是一条或多条 `Pull` 消息，按服务器定义的结果窗口流式返回。Contexts 大约在 ~30 分钟后过期，因此工具要么需要对结果进行分页，要么拆分过滤器（按 CN 前缀查询）以避免丢失状态。请求安全描述符时，指定 `LDAP_SERVER_SD_FLAGS_OID` 控制以省略 SACLs，否则 ADWS 会直接在其 SOAP 响应中丢弃 `nTSecurityDescriptor` 属性。

> 注意：ADWS 也被许多 RSAT GUI/PowerShell 工具使用，因此流量可能与合法的管理员活动混合。

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是一个 **用纯 Python 完全重实现 ADWS 协议栈** 的项目。它逐字节构造 NBFX/NBFSE/NNS/NMF 帧，允许从类 Unix 系统收集数据而无需接触 .NET 运行时。

### 主要特点

* 支持 **通过 SOCKS 代理** 转发（对 C2 植入体很有用）。
* 细粒度搜索过滤器，与 LDAP 的 `-q '(objectClass=user)'` 相同。
* 可选的 **写** 操作（ `--set` / `--delete` ）。
* 用于直接导入到 BloodHound 的 **BOFHound 输出模式**。
* `--parse` 标志在需要人类可读性时美化时间戳 / `userAccountControl`。

### 定向收集开关与写操作

SoaPy 附带了精心挑选的开关，复现了在 ADWS 上最常见的 LDAP 搜索任务： `--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于自定义拉取的原始 `--query` / `--filter` 选项。可将这些与写入原语配对，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（用于定向 Kerberoasting 的 SPN 暂存）和 `--asrep`（在 `userAccountControl` 中翻转 `DONT_REQ_PREAUTH`）。

示例：仅返回 `samAccountName` 和 `servicePrincipalName` 的定向 SPN 搜索：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭据立即将发现武器化：使用 `--rbcds` 转储 RBCD-capable 对象，然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来搭建一个 Resource-Based Constrained Delegation 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 获取完整滥用路径）。

### 安装（操作员主机）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - 一个用于 ADWS 的 Golang 实用客户端

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **对象搜索与检索** - `query` / `get`
* **对象生命周期** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账户管理** - `set-password` / `change-password`
* 以及其他例如 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 等。

## SOAPHound – 大规模 ADWS 收集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，将所有 LDAP 交互保持在 ADWS 内，并输出与 BloodHound v4 兼容的 JSON。它一次性构建 `objectSid`, `objectGUID`, `distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高容量的 `--bhdump`, `--certdump` (ADCS), 或 `--dnsdump` (AD-integrated DNS) 执行中重用该缓存，从而只有约 ~35 个关键属性会离开 DC。AutoSplit (`--autosplit --threshold <N>`) 会自动按 CN 前缀对查询进行分片，以在大型林中保持在 30 分钟的 EnumerationContext 超时之内。

Typical workflow on a domain-joined operator VM:
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
导出的 JSON 直接插入到 SharpHound/BloodHound 工作流中——参见 [BloodHound methodology](bloodhound.md) 了解后续制图思路。AutoSplit 使 SOAPHound 在包含数百万对象的森林中更具鲁棒性，同时保持查询次数低于 ADExplorer-style snapshots。

## 隐蔽 AD 收集工作流

下面的工作流展示了如何通过 ADWS 枚举 **域 & ADCS 对象**、将它们转换为 BloodHound JSON，并从 Linux 上追踪基于证书的攻击路径：

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
4. **转换为 BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **在 BloodHound GUI 上传 ZIP** 并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以揭示证书提升路径 (ESC1、ESC8 等)。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将此与 `s4u2proxy`/`Rubeus /getticket` 结合，以实现完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具概要

| 目的 | 工具 | 说明 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读/写 |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS 模式 |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | 将 SoaPy/ldapsearch 日志转换 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 可以通过相同的 SOCKS 代理 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 用于与已知 ADWS 端点交互的通用客户端 - 支持枚举、对象创建、属性修改以及密码更改 |

## 参考资料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
