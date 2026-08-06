# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 协议随 Windows XP 引入，旨在通过 HTTP Protocol 进行身份验证，并且在 **Windows XP 至 Windows 8.0，以及 Windows Server 2003 至 Windows Server 2012 中默认启用**。此默认设置会导致 **在 LSASS**（Local Security Authority Subsystem Service，本地安全机构子系统服务）**中以明文存储密码**。攻击者可以使用 Mimikatz，通过执行以下命令来 **提取这些凭据**：<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
要**关闭或开启此功能**，必须将 _**UseLogonCredential**_ 和 _**Negotiate**_ 注册表键设置为 "1"，路径为 _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_。如果这些键**不存在或设置为 "0"**，则 WDigest **已禁用**：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection（PP 和 PPL protected processes）

**Protected Process (PP)** 和 **Protected Process Light (PPL)** 是 **Windows kernel-level protections**，旨在防止未经授权的访问敏感进程，例如 **LSASS**。**PP model** 于 **Windows Vista** 中引入，最初用于 **DRM** enforcement，并且只允许使用 **special media certificate** 签名的 binaries 受到保护。标记为 **PP** 的进程只能被同样属于 **PP** 且具有**相同或更高 protection level** 的其他进程访问，即使如此，除非有明确允许，否则也只能使用**有限的 access rights**。

**PPL** 于 **Windows 8.1** 中引入，是 PP 更灵活的版本。它通过根据 **digital signature** 的 EKU（Enhanced Key Usage）字段引入 **"protection levels"**，从而支持更广泛的 use cases（例如 LSASS、Defender）。protection level 存储在 `EPROCESS.Protection` 字段中，该字段是一个 `PS_PROTECTION` structure，包含：
- **Type**（`Protected` 或 `ProtectedLight`）
- **Signer**（例如 `WinTcb`、`Lsa`、`Antimalware` 等）

该 structure 被打包为单个 byte，用于决定**谁可以访问谁**：
- **更高的 signer values 可以访问更低的 signer values**
- **PPL 不能访问 PP**
- **Unprotected processes 不能访问任何 PPL/PP**

### 从 offensive perspective 需要了解的内容

- 当 **LSASS 以 PPL 运行时**，从 normal admin context 使用 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` 尝试打开它会失败，并返回 `0x5 (Access Denied)`，即使已启用 `SeDebugPrivilege`。
- 可以使用 Process Hacker 等 tools 检查 **LSASS protection level**，也可以通过读取 `EPROCESS.Protection` value 以 programmatically 的方式检查。
- LSASS 通常具有 `PsProtectedSignerLsa-Light`（`0x41`），只有使用更高 level signer 签名的 processes 才能访问它，例如 `WinTcb`（`0x61` 或 `0x62`）。
- PPL 是**仅限 Userland 的 restriction**；**kernel-level code 可以完全绕过它**。
- LSASS 为 PPL **并不能阻止 credential dumping**，只要你能够执行 kernel shellcode，或利用具有适当 access 的 high-privileged process。
- **设置或移除 PPL** 需要 reboot 或修改 **Secure Boot/UEFI settings**；即使 registry changes 已被恢复，这些设置仍可能持久保留 PPL 设置。

### 在启动时创建 PPL process（documented API）

Windows 提供了一种 documented 方式，可以在创建 child process 时使用 extended startup attribute list 请求 Protected Process Light level。该方式不会绕过 signing requirements —— target image 必须使用所请求的 signer class 进行签名。

C/C++ 中的 minimal flow：
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
- 使用 `STARTUPINFOEX`、`InitializeProcThreadAttributeList` 和 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`，然后向 `CreateProcess*` 传入 `EXTENDED_STARTUPINFO_PRESENT`。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- protection `DWORD` 可以设置为诸如 `PROTECTION_LEVEL_WINTCB_LIGHT`、`PROTECTION_LEVEL_WINDOWS`、`PROTECTION_LEVEL_WINDOWS_LIGHT`、`PROTECTION_LEVEL_ANTIMALWARE_LIGHT` 或 `PROTECTION_LEVEL_LSA_LIGHT` 等常量。
- 只有当子进程的 image 针对相应的 signer class 完成签名时，它才能以 PPL 身份启动；否则进程创建会失败，通常会返回 `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`。
- 这不是 bypass —— 这是一个为具有适当签名的 image 提供的受支持 API。它可用于强化工具或验证 PPL-protected 配置。

使用 minimal loader 的示例 CLI：<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections 的选项：**

如果你希望在 LSASS 处于 PPL 状态时仍然 dump LSASS，主要有 3 种选项：
1. **使用 signed kernel driver（例如 Mimikatz + mimidrv.sys）** 来**移除 LSASS 的 protection flag**：

![显示 credential protection 交互的 Mimikatz mimidrv driver 输出](../../images/mimidrv.png)

2. **自带易受攻击的 Driver（BYOVD）**，运行自定义 kernel code 并禁用 protection。诸如 **PPLKiller**、**gdrv-loader** 或 **kdmapper** 等工具可以实现这一点。
3. **从已打开 LSASS handle 的其他进程（例如某个 AV 进程）中窃取现有的 LSASS handle**，然后将其**duplicate**到你的进程中。这是 `pypykatz live lsa --method handledup` technique 的基础。
4. **滥用某些 privileged process**，让其将任意 code 加载到自身的 address space 或其他 privileged process 内，从而有效 bypass PPL restrictions。你可以在 [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 或 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) 中查看相关示例。

**检查 LSASS 当前的 LSA protection status（PPL/PP）：**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
当你运行 **`mimikatz privilege::debug sekurlsa::logonpasswords`** 时，可能会因以下原因失败，并返回错误代码 `0x00000005`。

- 有关此检查的更多信息，请参阅 [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard** 是 **Windows 10（Enterprise 和 Education 版本）** 独有的功能，通过 **Virtual Secure Mode (VSM)** 和 **Virtualization Based Security (VBS)** 增强计算机凭据的安全性。它利用 CPU 虚拟化扩展，将关键进程隔离在受保护的内存空间中，使其无法被主操作系统访问。这种隔离确保即使是内核也无法访问 VSM 中的内存，从而有效保护凭据免受 **pass-the-hash** 等攻击。**Local Security Authority (LSA)** 作为 trustlet 运行在这一安全环境中，而主操作系统中的 **LSASS** 进程仅负责与 VSM 中的 LSA 通信。

默认情况下，**Credential Guard** 未启用，需要在组织内部手动激活。它对于增强针对 **Mimikatz** 等工具的防护至关重要，因为这些工具提取凭据的能力会受到限制。不过，仍然可以通过添加自定义 **Security Support Providers (SSP)**，在登录尝试期间以明文捕获凭据，从而利用相关漏洞。

要验证 **Credential Guard** 的激活状态，可以检查 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下的注册表键值 _**LsaCfgFlags**_。值为 "**1**" 表示已启用并使用 **UEFI lock**，值为 "**2**" 表示已启用但未使用锁定，值为 "**0**" 表示未启用。虽然此注册表检查是一个有力的指示，但它并不是启用 Credential Guard 的唯一步骤。网上提供了启用此功能的详细指南和 PowerShell 脚本。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
要全面了解在 Windows 10 中启用 **Credential Guard** 的方法，以及其在兼容的 **Windows 11 Enterprise and Education（version 22H2）** 系统中的自动激活，请参阅 [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。<sup>[[9]](#references)</sup>

有关实现用于 credential capture 的自定义 SSP 的更多详细信息，请参阅[此指南](../active-directory-methodology/custom-ssp.md)。

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** 引入了多项新的安全功能，其中包括用于 RDP 的 _**Restricted Admin mode**_。此模式旨在通过降低 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks 带来的风险来增强安全性。

传统上，通过 RDP 连接到远程计算机时，凭据会存储在目标计算机上。这会带来严重的安全风险，尤其是在使用具有提升权限的账户时。然而，随着 _**Restricted Admin mode**_ 的引入，这种风险得到了显著降低。

使用命令 **mstsc.exe /RestrictedAdmin** 发起 RDP 连接时，远程计算机执行身份验证时不会在其上存储你的凭据。这种方式可以确保：即使发生 malware infection，或恶意用户获得了远程服务器的访问权限，你的凭据也不会因存储在服务器上而遭到泄露。

需要注意的是，在 **Restricted Admin mode** 中，尝试从 RDP session 访问网络资源时，不会使用你的个人凭据；而是使用**计算机的身份**。

此功能是保护远程桌面连接以及防止敏感信息在发生安全 breach 时暴露的重要进步。

![用于 credential extraction context 的 Windows RAM memory diagram](../../images/RAM.png)

如需更多详细信息，请访问[此资源](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。<sup>[[6]](#references)</sup>

## Cached Credentials

Windows 通过 **Local Security Authority (LSA)** 保护**域凭据**，并使用 **Kerberos** 和 **NTLM** 等 security protocols 支持 logon processes。Windows 的一项关键功能是能够缓存**最近十次域登录**，从而确保用户即使在**域控制器 offline** 时仍能访问其计算机——这对经常离开公司网络的 laptop 用户尤其有帮助。

缓存登录次数可以通过特定的**注册表项或组策略**进行调整。要查看或更改此设置，可以使用以下命令：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
对这些缓存凭据的访问受到严格控制，只有 **SYSTEM** 账户具有查看它们所需的权限。需要访问此信息的管理员必须使用 SYSTEM 用户权限。凭据存储在：`HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** 可以使用命令 `lsadump::cache` 提取这些缓存凭据。

如需进一步了解，原始 [来源](http://juggernaut.wikidot.com/cached-credentials) 提供了全面的信息。<sup>[[7]](#references)</sup>

## Protected Users

加入 **Protected Users group** 会为用户引入多项安全增强功能，从而提供更高水平的保护，防止凭据被窃取和滥用：

- **Credential Delegation (CredSSP)**：即使启用了组策略设置 **Allow delegating default credentials**，Protected Users 的明文凭据也不会被缓存。
- **Windows Digest**：从 **Windows 8.1 和 Windows Server 2012 R2** 开始，无论 Windows Digest 的状态如何，系统都不会缓存 Protected Users 的明文凭据。
- **NTLM**：系统不会缓存 Protected Users 的明文凭据或 NT 单向函数（NTOWF）。
- **Kerberos**：对于 Protected Users，Kerberos authentication 不会生成 **DES** 或 **RC4 keys**，也不会在初始 Ticket-Granting Ticket（TGT）获取之后缓存明文凭据或长期密钥。
- **Offline Sign-In**：Protected Users 在登录或解锁时不会创建缓存验证器，这意味着这些账户不支持离线登录。

当属于 **Protected Users group** 的用户登录设备时，这些保护措施会立即启用。这确保了关键安全措施得以实施，以防范各种凭据泄露方式。

如需更详细的信息，请参阅官方[文档](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。<sup>[[10]](#references)</sup>

**来自**[**文档**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**的表格。**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins            | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers       | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins        | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators          | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins            | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators         | Server Operators         | Server Operators                                                              | Server Operators             |

## 参考资料

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
