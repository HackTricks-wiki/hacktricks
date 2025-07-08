# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 协议于 Windows XP 中引入，旨在通过 HTTP 协议进行身份验证，并且在 **Windows XP 到 Windows 8.0 以及 Windows Server 2003 到 Windows Server 2012 中默认启用**。此默认设置导致 **在 LSASS 中以明文存储密码**。攻击者可以使用 Mimikatz **提取这些凭据**，通过执行：
```bash
sekurlsa::wdigest
```
要**启用或禁用此功能**，必须将_HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest_中的_**UseLogonCredential**_和_**Negotiate**_注册表项设置为"1"。如果这些键**缺失或设置为"0"**，则WDigest**被禁用**：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 保护 (PP 和 PPL 受保护进程)

**受保护进程 (PP)** 和 **受保护进程轻量版 (PPL)** 是 **Windows 内核级保护**，旨在防止对敏感进程如 **LSASS** 的未经授权访问。该模型在 **Windows Vista** 中引入，最初是为 **DRM** 执行而创建，仅允许使用 **特殊媒体证书** 签名的二进制文件受到保护。标记为 **PP** 的进程只能被其他 **也为 PP** 且具有 **相等或更高保护级别** 的进程访问，即便如此，**也仅限于有限的访问权限**，除非特别允许。

**PPL** 于 **Windows 8.1** 中引入，是 PP 的更灵活版本。它通过引入基于 **数字签名的 EKU (增强密钥使用)** 字段的 **“保护级别”**，允许 **更广泛的使用案例**（例如，LSASS、Defender）。保护级别存储在 `EPROCESS.Protection` 字段中，这是一个 `PS_PROTECTION` 结构，包含：
- **类型**（`Protected` 或 `ProtectedLight`）
- **签名者**（例如，`WinTcb`、`Lsa`、`Antimalware` 等）

该结构被打包为一个字节，并决定 **谁可以访问谁**：
- **更高的签名者值可以访问较低的**
- **PPL 不能访问 PP**
- **未保护的进程无法访问任何 PPL/PP**

### 从攻击者的角度需要了解的内容

- 当 **LSASS 以 PPL 运行** 时，尝试从普通管理员上下文使用 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` 打开它 **会失败并返回 `0x5 (访问被拒绝)`**，即使 `SeDebugPrivilege` 已启用。
- 你可以使用 Process Hacker 等工具或通过读取 `EPROCESS.Protection` 值以编程方式 **检查 LSASS 的保护级别**。
- LSASS 通常具有 `PsProtectedSignerLsa-Light` (`0x41`)，只能被 **使用更高级别签名者签名的进程** 访问，例如 `WinTcb` (`0x61` 或 `0x62`)。
- PPL 是 **仅限用户空间的限制**；**内核级代码可以完全绕过它**。
- LSASS 为 PPL 并 **不阻止凭据转储，如果你可以执行内核 shellcode** 或 **利用具有适当访问权限的高特权进程**。
- **设置或移除 PPL** 需要重启或 **安全启动/UEFI 设置**，这可以在注册表更改被撤销后仍然保持 PPL 设置。

**绕过 PPL 保护的选项：**

如果你想在 PPL 的情况下转储 LSASS，你有 3 个主要选项：
1. **使用签名的内核驱动程序（例如，Mimikatz + mimidrv.sys）** 来 **移除 LSASS 的保护标志**：

![](../../images/mimidrv.png)

2. **自带易受攻击的驱动程序 (BYOVD)** 以运行自定义内核代码并禁用保护。像 **PPLKiller**、**gdrv-loader** 或 **kdmapper** 的工具使这变得可行。
3. **从另一个打开 LSASS 句柄的进程中窃取现有句柄**（例如，一个 AV 进程），然后 **将其复制** 到你的进程中。这是 `pypykatz live lsa --method handledup` 技术的基础。
4. **利用某些特权进程**，允许你将任意代码加载到其地址空间或另一个特权进程内部，从而有效绕过 PPL 限制。你可以在 [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 或 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) 中查看此示例。

**检查 LSASS 的 LSA 保护 (PPL/PP) 当前状态**：
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
当你运行 **`mimikatz privilege::debug sekurlsa::logonpasswords`** 时，它可能会因为这个原因而失败，错误代码为 `0x00000005`。

- 有关此信息的更多内容，请查看 [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)

## Credential Guard

**Credential Guard** 是 **Windows 10（企业版和教育版）** 独有的功能，通过使用 **虚拟安全模式（VSM）** 和 **基于虚拟化的安全性（VBS）** 来增强机器凭据的安全性。它利用 CPU 虚拟化扩展将关键进程隔离在受保护的内存空间中，远离主操作系统的访问。这种隔离确保即使是内核也无法访问 VSM 中的内存，有效地保护凭据免受 **pass-the-hash** 等攻击。**本地安全机构（LSA）** 在这个安全环境中作为信任组件运行，而主操作系统中的 **LSASS** 进程仅充当与 VSM 的 LSA 的通信者。

默认情况下，**Credential Guard** 并未激活，需要在组织内手动激活。它对于增强抵御像 **Mimikatz** 这样的工具的安全性至关重要，这些工具在提取凭据的能力上受到限制。然而，仍然可以通过添加自定义 **安全支持提供程序（SSP）** 来利用漏洞，在登录尝试期间捕获明文凭据。

要验证 **Credential Guard** 的激活状态，可以检查注册表项 _**LsaCfgFlags**_，位于 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下。值为 "**1**" 表示激活并带有 **UEFI 锁**，"**2**" 表示没有锁，"**0**" 表示未启用。这个注册表检查虽然是一个强有力的指示，但并不是启用 Credential Guard 的唯一步骤。有关启用此功能的详细指导和 PowerShell 脚本可在线获取。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
为了全面了解和启用 **Credential Guard** 在 Windows 10 中的说明，以及在 **Windows 11 Enterprise 和 Education (版本 22H2)** 兼容系统中的自动激活，请访问 [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。

有关实施自定义 SSP 以捕获凭据的更多详细信息，请参阅 [this guide](../active-directory-methodology/custom-ssp.md)。

## RDP RestrictedAdmin Mode

**Windows 8.1 和 Windows Server 2012 R2** 引入了几个新的安全功能，包括 _**Restricted Admin mode for RDP**_。此模式旨在通过减轻与 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 攻击相关的风险来增强安全性。

传统上，通过 RDP 连接到远程计算机时，您的凭据会存储在目标机器上。这带来了显著的安全风险，尤其是在使用具有提升权限的帐户时。然而，随着 _**Restricted Admin mode**_ 的引入，这一风险大大降低。

当使用命令 **mstsc.exe /RestrictedAdmin** 启动 RDP 连接时，对远程计算机的身份验证是在不存储您的凭据的情况下进行的。这种方法确保在发生恶意软件感染或恶意用户获得远程服务器访问权限的情况下，您的凭据不会被泄露，因为它们并未存储在服务器上。

需要注意的是，在 **Restricted Admin mode** 中，从 RDP 会话访问网络资源的尝试将不会使用您的个人凭据；相反，使用的是 **机器的身份**。

此功能标志着在保护远程桌面连接和敏感信息免受安全漏洞暴露方面的重要进展。

![](../../images/RAM.png)

有关更多详细信息，请访问 [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。

## Cached Credentials

Windows 通过 **Local Security Authority (LSA)** 保护 **域凭据**，支持使用 **Kerberos** 和 **NTLM** 等安全协议的登录过程。Windows 的一个关键特性是其能够缓存 **最后十个域登录**，以确保用户即使在 **域控制器离线** 的情况下仍能访问他们的计算机——这对经常远离公司网络的笔记本电脑用户来说是一个福音。

缓存登录的数量可以通过特定的 **注册表项或组策略** 进行调整。要查看或更改此设置，可以使用以下命令：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
访问这些缓存凭据的权限受到严格控制，只有 **SYSTEM** 账户拥有查看它们所需的权限。需要访问此信息的管理员必须以 SYSTEM 用户权限进行操作。凭据存储在： `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** 可以通过命令 `lsadump::cache` 提取这些缓存凭据。

有关更多详细信息，原始 [source](http://juggernaut.wikidot.com/cached-credentials) 提供了全面的信息。

## 受保护用户

加入 **受保护用户组** 会为用户引入几项安全增强措施，确保对凭据盗窃和滥用的更高保护级别：

- **凭据委派 (CredSSP)**：即使 **允许委派默认凭据** 的组策略设置已启用，受保护用户的明文凭据也不会被缓存。
- **Windows Digest**：从 **Windows 8.1 和 Windows Server 2012 R2** 开始，系统将不会缓存受保护用户的明文凭据，无论 Windows Digest 状态如何。
- **NTLM**：系统不会缓存受保护用户的明文凭据或 NT 单向函数 (NTOWF)。
- **Kerberos**：对于受保护用户，Kerberos 认证不会生成 **DES** 或 **RC4 密钥**，也不会缓存明文凭据或超出初始票据授予票 (TGT) 获取的长期密钥。
- **离线登录**：受保护用户在登录或解锁时不会创建缓存验证器，这意味着这些账户不支持离线登录。

这些保护措施在 **受保护用户组** 的成员登录设备时立即激活。这确保了关键安全措施到位，以防止各种凭据泄露方法。

有关更详细的信息，请查阅官方 [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
