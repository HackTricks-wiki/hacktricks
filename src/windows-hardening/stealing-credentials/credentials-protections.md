# Windows 凭据保护

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 协议随 Windows XP 引入，旨在通过 HTTP 协议进行身份验证，并且**在 Windows XP 到 Windows 8.0，以及 Windows Server 2003 到 Windows Server 2012 中默认启用**。此默认设置会导致**在 LSASS**（Local Security Authority Subsystem Service，本地安全机构子系统服务）**中以明文存储密码**。攻击者可以使用 Mimikatz 执行以下命令来**提取这些凭据**：<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
要**关闭或开启此功能**，必须将 _**UseLogonCredential**_ 和 _**Negotiate**_ 注册表项设置为“1”，路径为 _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_。如果这些注册表项**不存在或设置为“0”**，则 WDigest **处于禁用状态**：
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection（受 PP 和 PPL 保护的进程）

**Protected Process (PP)** 和 **Protected Process Light (PPL)** 是 **Windows 内核级保护机制**，旨在防止未经授权访问 **LSASS** 等敏感进程。**PP 模型**于 **Windows Vista** 中引入，最初用于实施 **DRM**，并且只允许由**特殊媒体证书**签名的二进制文件受到保护。标记为 **PP** 的进程只能被其他同样是 **PP** 且具有**相同或更高保护级别**的进程访问，即使如此，也只能获得**有限的访问权限**，除非有明确许可。

**PPL** 于 **Windows 8.1** 中引入，是 PP 的更灵活版本。它通过引入基于**数字签名的 EKU（Enhanced Key Usage）**字段的**“保护级别”**，支持更广泛的使用场景（例如 LSASS、Defender）。保护级别存储在 `EPROCESS.Protection` 字段中，该字段是一个 `PS_PROTECTION` 结构，包含：
- **Type**（`Protected` 或 `ProtectedLight`）
- **Signer**（例如 `WinTcb`、`Lsa`、`Antimalware` 等）

该结构会被打包到单个字节中，并决定**谁可以访问谁**：
- **较高的 signer 值可以访问较低的 signer 值**
- **PPL 无法访问 PP**
- **Unprotected 进程无法访问任何 PPL/PP**

### 从 offensive 角度需要了解的内容

- 当 **LSASS 以 PPL 运行**时，从普通管理员上下文使用 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` 尝试打开它会失败，并返回 `0x5 (Access Denied)`，即使已启用 `SeDebugPrivilege` 也是如此。
- 可以使用 Process Hacker 等工具，或通过程序读取 `EPROCESS.Protection` 值，来**检查 LSASS 的保护级别**。
- LSASS 通常具有 `PsProtectedSignerLsa-Light`（`0x41`），只有使用更高级别 signer（例如 `WinTcb`（`0x61` 或 `0x62`））签名的进程才能访问它。
- PPL 是**仅限 Userland 的限制**；**内核级代码可以完全绕过它**。
- LSASS 为 PPL **并不能阻止 credential dumping**，前提是你能够执行 kernel shellcode，或**利用具有适当访问权限的高权限进程**。
- **设置或移除 PPL** 需要重启，或需要修改 **Secure Boot/UEFI 设置**；即使还原了 registry 更改，PPL 设置也可能继续生效。

### 在启动时创建 PPL 进程（documented API）

Windows 提供了一种 documented 方法，可以在创建子进程时通过 extended startup attribute list 请求 Protected Process Light 级别。这不会绕过签名要求——目标 image 必须使用符合所请求 signer class 的签名。

C/C++ 中的最小流程：
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
- 使用 `STARTUPINFOEX`、`InitializeProcThreadAttributeList` 和 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`，然后将 `EXTENDED_STARTUPINFO_PRESENT` 传递给 `CreateProcess*`。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- protection `DWORD` 可以设置为诸如 `PROTECTION_LEVEL_WINTCB_LIGHT`、`PROTECTION_LEVEL_WINDOWS`、`PROTECTION_LEVEL_WINDOWS_LIGHT`、`PROTECTION_LEVEL_ANTIMALWARE_LIGHT` 或 `PROTECTION_LEVEL_LSA_LIGHT` 等常量。
- 只有当其 image 针对相应 signer class 完成签名时，子进程才能以 PPL 身份启动；否则进程创建会失败，通常返回 `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`。
- 这不是 bypass——这是一个为具有适当签名的 image 提供支持的 API。它可用于增强工具的安全性，或验证受 PPL 保护的配置。

使用 minimal loader 的示例 CLI：<sup>[[1]](#references)</sup>
- Antimalware signer：`CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer：`CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**绕过 PPL 保护的选项：**

如果你希望在 LSASS 受 PPL 保护的情况下 dump LSASS，主要有 3 种选项：
1. **使用已签名的 kernel driver（例如 Mimikatz + mimidrv.sys）** 来**移除 LSASS 的 protection flag**：

![显示凭据保护交互的 Mimikatz mimidrv driver 输出](../../images/mimidrv.png)

2. **自带易受攻击的 Driver（BYOVD）**，以运行自定义 kernel code 并禁用该保护。诸如 **PPLKiller**、**gdrv-loader** 或 **kdmapper** 等工具使其成为可能。
3. 从已打开 LSASS handle 的其他进程（例如某个 AV 进程）中**窃取现有的 LSASS handle**，然后将其**duplicate**到你的进程中。这是 `pypykatz live lsa --method handledup` 技术的基础。
4. **滥用某些 privileged process**，使其允许你将任意 code 加载到其 address space，或加载到另一个 privileged process 内部，从而有效绕过 PPL 限制。你可以在 [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 或 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) 中查看相关示例。

**检查 LSASS 当前的 LSA protection（PPL/PP）状态**：
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
运行 **`mimikatz privilege::debug sekurlsa::logonpasswords`** 时，由于此保护机制，该命令很可能会失败并返回错误代码 `0x00000005`。

- 有关此检查的更多信息，请参阅 [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard** 是一项仅适用于 **Windows 10（Enterprise 和 Education 版本）** 的功能，它通过 **Virtual Secure Mode (VSM)** 和 **Virtualization Based Security (VBS)** 增强计算机凭据的安全性。它利用 CPU 虚拟化扩展，将关键进程隔离在受保护的内存空间中，使其远离主操作系统的访问范围。这种隔离确保即使是内核也无法访问 VSM 中的内存，从而有效保护凭据免受 **pass-the-hash** 等攻击。**Local Security Authority (LSA)** 以 trustlet 的形式在此安全环境中运行，而主操作系统中的 **LSASS** 进程仅充当与 VSM 的 LSA 通信的组件。

默认情况下，**Credential Guard** 未启用，需要在组织内手动激活。它对于增强针对 **Mimikatz** 等工具的安全性至关重要，因为这些工具提取凭据的能力会受到限制。不过，攻击者仍可通过添加自定义 **Security Support Providers (SSP)** 来利用漏洞，在登录尝试期间捕获明文凭据。

要验证 **Credential Guard** 的激活状态，可以检查 _**HKLM\System\CurrentControlSet\Control\LSA**_ 下的注册表项 _**LsaCfgFlags**_。值为 "**1**" 表示已启用并使用 **UEFI lock**，值为 "**2**" 表示已启用但未使用锁定，值为 "**0**" 表示未启用。虽然此注册表检查是一个重要指标，但它并不是启用 Credential Guard 的唯一步骤。网上提供了用于启用此功能的详细指南和 PowerShell 脚本。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
如需全面了解在 Windows 10 中启用 **Credential Guard** 的方法，以及 **Windows 11 Enterprise 和 Education（版本 22H2）**兼容系统中的自动启用机制，请访问 [Microsoft 的文档](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。<sup>[[9]](#references)</sup>

有关实施用于 credential capture 的自定义 SSP 的更多详细信息，请参阅[本指南](../active-directory-methodology/custom-ssp.md)。

## RDP RestrictedAdmin Mode

**Windows 8.1 和 Windows Server 2012 R2** 引入了多项新的安全功能，其中包括 _**Restricted Admin mode for RDP**_。此模式旨在通过降低 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 攻击所带来的风险来增强安全性。

传统上，通过 RDP 连接到远程计算机时，凭据会存储在目标计算机上。这会带来重大安全风险，尤其是在使用具有提升权限的账户时。然而，随着 _**Restricted Admin mode**_ 的引入，这一风险得到了大幅降低。

使用命令 **mstsc.exe /RestrictedAdmin** 发起 RDP 连接时，远程计算机会在不存储凭据的情况下完成身份验证。这种方式可确保在发生 malware 感染或恶意用户获得远程服务器访问权限时，凭据不会因存储在服务器上而遭到泄露。

需要注意的是，在 **Restricted Admin mode** 中，尝试从 RDP 会话访问网络资源时不会使用个人凭据，而是使用**计算机身份**。

此功能是保护远程桌面连接并防止敏感信息在安全漏洞发生时暴露的重要进步。

![用于凭据提取场景的 Windows RAM 内存图](../../images/RAM.png)

如需更多详细信息，请访问[此资源](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。<sup>[[6]](#references)</sup>

## Cached Credentials

Windows 通过 **Local Security Authority (LSA)** 保护**域凭据**，并使用 **Kerberos** 和 **NTLM** 等安全协议支持登录过程。Windows 的一项关键功能是缓存**最近十次域登录**，从而确保用户即使在**域控制器处于离线状态**时仍能访问自己的计算机——这对经常离开公司网络的笔记本电脑用户尤为有用。

缓存登录次数可以通过特定的**注册表项或组策略**进行调整。若要查看或更改此设置，可以使用以下命令：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
对这些缓存凭据的访问受到严格控制，只有 **SYSTEM** 账户拥有查看它们所需的权限。需要访问此信息的管理员必须使用 SYSTEM 用户权限执行操作。凭据存储在：`HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** 可使用命令 `lsadump::cache` 提取这些缓存凭据。

如需进一步了解详情，原始[来源](http://juggernaut.wikidot.com/cached-credentials)提供了全面的信息。<sup>[[7]](#references)</sup>

## Protected Users

加入 **Protected Users group** 后，会为用户引入多项安全增强措施，从而更好地防范凭据窃取和滥用：

- **Credential Delegation (CredSSP)**：即使启用了 **Allow delegating default credentials** Group Policy 设置，也不会缓存 Protected Users 的明文凭据。
- **Windows Digest**：从 **Windows 8.1 and Windows Server 2012 R2** 开始，无论 Windows Digest 的状态如何，系统都不会缓存 Protected Users 的明文凭据。
- **NTLM**：系统不会缓存 Protected Users 的明文凭据或 NT 单向函数（NTOWF）。
- **Kerberos**：对于 Protected Users，Kerberos 身份验证不会生成 **DES** 或 **RC4 keys**，也不会缓存初始 Ticket-Granting Ticket（TGT）获取之后的明文凭据或长期密钥。
- **Offline Sign-In**：Protected Users 在登录或解锁时不会创建缓存验证器，这意味着这些账户不支持离线登录。

当属于 **Protected Users group** 的用户登录设备时，这些保护措施会立即启用。这确保了关键安全措施能够及时生效，以防范各种凭据泄露方式。

如需更详细的信息，请参阅官方[文档](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)。<sup>[[10]](#references)</sup>

**来自** [**文档**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**的表格。**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators                |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins            | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators        | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – 最小 PPL 进程启动器](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX 结构（Win32 API）](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList（Win32 API）](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute（Win32 API）](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – 背景与内部机制](https://itm4n.github.io/lsass-runasppl/)
- [6] [RDP 的 Restricted Admin Mode](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
