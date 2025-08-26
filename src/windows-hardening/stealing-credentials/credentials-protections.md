# Windows 凭证保护

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **在 Windows XP 到 Windows 8.0 以及 Windows Server 2003 到 Windows Server 2012 上默认启用**。此默认设置导致 **密码以明文形式存储在 LSASS** (Local Security Authority Subsystem Service)。攻击者可以使用 Mimikatz 来 **提取这些凭证**，方法是执行：
```bash
sekurlsa::wdigest
```
要 **切换此功能为关闭或开启**，位于 _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 的 _**UseLogonCredential**_ 和 _**Negotiate**_ 注册表键必须设置为 "1"。如果这些键 **不存在或设置为 "0"**，WDigest **被禁用**：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** 和 **Protected Process Light (PPL)** 是 **Windows 内核级保护**，用于防止对像 **LSASS** 这样的敏感进程的未授权访问。最初在 **Windows Vista** 引入，**PP 模型** 最初为 **DRM** 强制而创建，并且只允许使用 **特殊媒体证书** 签名的二进制文件受保护。被标记为 **PP** 的进程只能被其他同为 **PP** 且具有**相同或更高保护级别**的进程访问，即便如此，除非明确允许，访问也**仅限于有限的权限**。

**PPL**（在 **Windows 8.1** 引入）是 PP 的更灵活版本。它通过引入基于数字签名 EKU (Enhanced Key Usage) 字段的**“保护级别”**来支持**更广泛的用例**（例如 LSASS、Defender）。保护级别存储在 `EPROCESS.Protection` 字段中，该字段是一个 `PS_PROTECTION` 结构，包含：
- **Type**（`Protected` 或 `ProtectedLight`）
- **Signer**（例如 `WinTcb`、`Lsa`、`Antimalware` 等）

该结构被打包为单字节，并决定了**谁可以访问谁**：
- **更高的 signer 值可以访问更低的 signer**
- **PPL 不能访问 PP**
- **未受保护的进程不能访问任何 PPL/PP**

### What you need to know from an offensive perspective

- 当 **LSASS 以 PPL 运行时**，从普通管理员上下文调用 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` 的尝试 **会以 `0x5 (Access Denied)` 失败**，即使启用了 `SeDebugPrivilege`。
- 你可以使用 Process Hacker 或通过读取 `EPROCESS.Protection` 值来**检查 LSASS 的保护级别**。
- LSASS 通常会有 `PsProtectedSignerLsa-Light`（`0x41`），只有由更高等级 signer 签名的进程才能访问，例如 `WinTcb`（`0x61` 或 `0x62`）。
- PPL 是**仅对用户态的限制**；**内核级代码可以完全绕过它**。
- 即使 LSASS 为 PPL，如果你能执行内核 shellcode 或 利用具有适当访问权限的高权限进程，仍然**无法阻止 credential dumping**。
- 设置或移除 PPL 需要重启或更改 Secure Boot/UEFI 设置，这些设置可能会在注册表更改回滚后仍然保留 PPL 状态。

### Create a PPL process at launch (documented API)

Windows 提供了一个记录在案的方法，在创建子进程时通过 extended startup attribute list 请求 Protected Process Light 级别。此方法并不会绕过签名要求 — 目标镜像必须为请求的 signer class 签名。

Minimal flow in C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
注意事项和限制：
- 使用 `STARTUPINFOEX` 与 `InitializeProcThreadAttributeList` 和 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`，然后向 `CreateProcess*` 传递 `EXTENDED_STARTUPINFO_PRESENT`。
- 保护 `DWORD` 可以设置为诸如 `PROTECTION_LEVEL_WINTCB_LIGHT`、`PROTECTION_LEVEL_WINDOWS`、`PROTECTION_LEVEL_WINDOWS_LIGHT`、`PROTECTION_LEVEL_ANTIMALWARE_LIGHT` 或 `PROTECTION_LEVEL_LSA_LIGHT` 等常量。
- 只有当子进程的镜像针对该 signer class 进行了签名时，子进程才会以 PPL 启动；否则进程创建会失败，常见错误为 `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`。
- 这不是绕过 —— 这是面向适当签名镜像的受支持 API。可用于强化工具或验证受 PPL 保护的配置。

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**绕过 PPL 保护的选项：**

如果你想在 PPL 存在的情况下 dump LSASS，主要有 3 个选项：
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** 来 **移除 LSASS 的保护标志**：

![](../../images/mimidrv.png)

2. 使用 Bring Your Own Vulnerable Driver (BYOVD) 来运行自定义 kernel 代码并禁用保护。像 **PPLKiller**、**gdrv-loader** 或 **kdmapper** 这样的工具可以实现这一点。
3. 从另一个已打开 LSASS 的进程（例如 AV 进程）窃取现有的 LSASS handle，然后**将其复制到你的进程中**。这是 `pypykatz live lsa --method handledup` 技术的基础。
4. 滥用某些特权进程，使你能够将任意代码加载到其地址空间或另一个特权进程内，从而有效绕过 PPL 限制。可以查看此示例：[bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 或 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump)。

**检查 LSASS 的 LSA 保护 (PPL/PP) 当前状态：**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
当你运行 **`mimikatz privilege::debug sekurlsa::logonpasswords`** 时，可能会因这个原因而以错误代码 `0x00000005` 失败。

- 有关此检查的更多信息，请参见 [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard** 是 **Windows 10 (Enterprise and Education editions)** 专有的一个功能，使用 **Virtual Secure Mode (VSM)** 和 **Virtualization Based Security (VBS)** 来增强机器凭据的安全性。它利用 CPU 虚拟化扩展将关键进程隔离到受保护的内存空间中，隔离于主操作系统之外。该隔离保证即使是内核也无法访问 VSM 中的内存，从而有效保护凭据免受 **pass-the-hash** 之类攻击。**Local Security Authority (LSA)** 在该安全环境中作为 trustlet 运行，而主 OS 中的 **LSASS** 进程仅作为与 VSM 中 LSA 的通讯者。

默认情况下，**Credential Guard** 未启用，需要在组织内手动激活。它对抗诸如 **Mimikatz** 等工具非常重要，因为这些工具在提取凭据方面会受阻。然而，仍然可能通过添加自定义 **Security Support Providers (SSP)** 来利用漏洞，在登录尝试期间捕获明文凭据。

要验证 **Credential Guard** 的启用状态，可以检查注册表键 _**LsaCfgFlags**_（位于 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下）。值为 "**1**" 表示启用并带有 **UEFI lock**，为 "**2**" 表示启用但不带锁，值为 "**0**" 则表示未启用。尽管此注册表检查是一个强烈的指示，但它并不是启用 Credential Guard 的唯一步骤。有关启用此功能的详细指南和 PowerShell 脚本可在网上找到。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
要全面了解并获取在 Windows 10 中启用 **Credential Guard** 的说明，以及在兼容的 **Windows 11 Enterprise and Education (version 22H2)** 系统中自动启用该功能的相关信息，请访问 [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。

有关实现用于凭据捕获的自定义 SSP 的更多细节，请参阅 [this guide](../active-directory-methodology/custom-ssp.md)。

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** 引入了若干新的安全功能，包括 _**Restricted Admin mode for RDP**_。此模式旨在通过减轻与 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 攻击相关的风险来增强安全性。

传统上，通过 RDP 连接到远程计算机时，你的凭据会存储在目标机器上。这带来了重大安全风险，尤其是在使用具有提升权限的帐户时。然而，随着 _**Restricted Admin mode**_ 的引入，这种风险大幅降低。

当使用命令 **mstsc.exe /RestrictedAdmin** 发起 RDP 连接时，对远程计算机的身份验证将在不将你的凭据存储在该计算机上的情况下进行。此方法确保在发生恶意软件感染或恶意用户访问远程服务器的情况下，你的凭据不会被泄露，因为它们并未存储在服务器上。

值得注意的是，在 **Restricted Admin mode** 下，从 RDP 会话尝试访问网络资源不会使用你的个人凭据；取而代之的是使用 **machine's identity**。

该功能在保护远程桌面连接和在发生安全漏洞时防止敏感信息暴露方面迈出了重要一步。

![](../../images/RAM.png)

如需更多详细信息，请访问 [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。

## Cached Credentials

Windows 通过 **Local Security Authority (LSA)** 保护 **domain credentials**，并支持使用 **Kerberos** 和 **NTLM** 等安全协议的登录过程。Windows 的一个关键特性是能够缓存 **last ten domain logins**，以确保即使 **domain controller is offline**，用户仍能访问他们的计算机——这对常常离开公司网络的笔记本用户非常有用。

缓存的登录数量可以通过特定的 **registry key or group policy** 进行调整。要查看或更改此设置，可使用以下命令：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
对这些缓存凭据的访问受到严格控制，只有 **SYSTEM** 帐户拥有查看它们的必要权限。需要访问此信息的管理员必须以 SYSTEM 用户权限执行。凭据存储在：`HKEY_LOCAL_MACHINE\SECURITY\Cache`

可以使用 **Mimikatz** 提取这些缓存凭据，命令为 `lsadump::cache`。

有关更多细节，原始 [source](http://juggernaut.wikidot.com/cached-credentials) 提供了全面的信息。

## Protected Users

成为 **Protected Users group** 的成员会为用户引入若干安全增强措施，从而提高对凭据窃取和滥用的防护等级：

- **Credential Delegation (CredSSP)**：即使组策略设置 **Allow delegating default credentials** 已启用，Protected Users 的明文凭据也不会被缓存。
- **Windows Digest**：从 **Windows 8.1 and Windows Server 2012 R2** 起，无论 Windows Digest 状态如何，系统都不会缓存 Protected Users 的明文凭据。
- **NTLM**：系统不会缓存 Protected Users 的明文凭据或 NT 单向函数 (NTOWF)。
- **Kerberos**：对于 Protected Users，Kerberos 认证不会生成 **DES** 或 **RC4 keys**，也不会缓存明文凭据或在首次获取 TGT (Ticket-Granting Ticket) 之后的长期密钥。
- **Offline Sign-In**：在登录或解锁时不会为 Protected Users 创建缓存的验证器，因此这些帐户不支持离线登录。

当属于 **Protected Users group** 的用户登录到设备时，这些保护即刻生效。这样可以确保关键的安全措施到位，以防止各种凭据被泄露或被滥用的方法。

更多详细信息，请查阅官方 [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。

**表格来自** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
