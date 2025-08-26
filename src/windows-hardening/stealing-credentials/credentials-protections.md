# Windows 자격 증명 보호

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 프로토콜은 Windows XP에서 도입되었으며 HTTP Protocol을 통한 인증을 위해 설계되었습니다. 이 프로토콜은 **Windows XP부터 Windows 8.0 및 Windows Server 2003부터 Windows Server 2012까지 기본적으로 활성화되어 있습니다**. 이 기본 설정으로 인해 **LSASS (Local Security Authority Subsystem Service)에 평문 비밀번호가 저장됩니다**. 공격자는 Mimikatz를 사용하여 **이 자격증명을 추출할 수 있습니다**:
```bash
sekurlsa::wdigest
```
이 기능을 **끄거나 켜려면**, _**UseLogonCredential**_ 및 _**Negotiate**_ 레지스트리 키가 _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 안에서 "1"로 설정되어야 합니다. 이러한 키가 **없거나 또는 "0"으로 설정되어 있다면**, WDigest는 **비활성화됩니다**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 보호 (PP & PPL 보호된 프로세스)

**Protected Process (PP)** 및 **Protected Process Light (PPL)**은 **Windows 커널 수준 보호**로, **LSASS**와 같은 민감한 프로세스에 대한 무단 액세스를 방지하도록 설계되었습니다. **Windows Vista**에서 도입된 **PP 모델**은 원래 **DRM** 강제를 위해 만들어졌으며, **특수 미디어 인증서**로 서명된 바이너리만 보호될 수 있었습니다. **PP**로 표시된 프로세스는 **동일하게 PP이거나 더 높은 보호 수준을 가진 다른 PP 프로세스**만 접근할 수 있으며, 그 경우에도 명시적으로 허용되지 않으면 **제한된 접근 권한**만 허용됩니다.

**PPL**은 **Windows 8.1**에서 도입된 보다 유연한 버전의 PP입니다. 디지털 서명의 **EKU (Enhanced Key Usage)** 필드를 기반으로 한 **"보호 수준"**을 도입하여 **LSASS, Defender** 등에서 **더 넓은 사용 사례**를 허용합니다. 보호 수준은 `EPROCESS.Protection` 필드에 저장되며, 이는 다음을 포함하는 `PS_PROTECTION` 구조체입니다:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (예: `WinTcb`, `Lsa`, `Antimalware` 등)

이 구조체는 단일 바이트로 패킹되어 **누가 누구에 접근할 수 있는지**를 결정합니다:
- **Higher signer values can access lower ones**
- **PPLs can’t access PPs**
- **Unprotected processes can't access any PPL/PP**

### 공격 관점에서 알아야 할 점

- **LSASS가 PPL로 실행될 때**, 일반 관리자 컨텍스트에서 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)`로 열려고 하면 `SeDebugPrivilege`가 활성화되어 있어도 **0x5 (Access Denied)**로 실패합니다.
- `Process Hacker` 같은 도구를 사용하거나 `EPROCESS.Protection` 값을 읽어 프로그래밍적으로 **LSASS 보호 수준을 확인**할 수 있습니다.
- LSASS는 일반적으로 `PsProtectedSignerLsa-Light` (`0x41`)를 가지며, 이는 `WinTcb` (`0x61` 또는 `0x62`)와 같은 **더 높은 수준의 signer로 서명된 프로세스만 접근**할 수 있습니다.
- **PPL은 Userland 전용 제한**이며, **커널 수준 코드로는 완전히 우회**할 수 있습니다.
- LSASS가 PPL이라 하더라도 **kernel shellcode를 실행할 수 있거나 적절한 접근 권한을 가진 고권한 프로세스를 이용할 수 있다면 credential dumping을 방지하지 못합니다.**
- PPL 설정 또는 제거는 재부팅 또는 **Secure Boot/UEFI 설정**을 필요로 하며, 레지스트리 변경을 되돌린 후에도 PPL 설정이 지속될 수 있습니다.

### 런치 시 PPL 프로세스 생성 (문서화된 API)

Windows는 확장된 시작 속성 목록(extended startup attribute list)을 사용해 생성 중에 자식 프로세스에 대해 Protected Process Light 수준을 요청하는 문서화된 방법을 제공합니다. 이는 서명 요구사항을 우회하지 않으며 — 대상 이미지는 요청된 signer 클래스에 맞게 서명되어 있어야 합니다.

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
노트 및 제약:
- `STARTUPINFOEX`를 `InitializeProcThreadAttributeList`와 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`와 함께 사용한 다음, `EXTENDED_STARTUPINFO_PRESENT`를 `CreateProcess*`에 전달합니다.
- 보호 `DWORD`는 `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, 또는 `PROTECTION_LEVEL_LSA_LIGHT`와 같은 상수로 설정할 수 있습니다.
- 자식 프로세스는 해당 이미지가 그 signer class로 서명된 경우에만 PPL로 시작합니다. 그렇지 않으면 프로세스 생성이 실패하며, 일반적으로 `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`로 나타납니다.
- 이것은 우회가 아닙니다 — 적절히 서명된 이미지에 대해 의도된 지원 API입니다. 도구를 강화하거나 PPL로 보호된 구성의 유효성을 검사하는 데 유용합니다.

최소 로더를 사용한 CLI 예시:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

PPL에도 불구하고 LSASS를 덤프하려면 주요 옵션이 3가지 있습니다:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)**를 사용하여 **LSASS의 보호 플래그를 제거**합니다.

![](../../images/mimidrv.png)

2. 취약한 드라이버를 자체적으로 가져와(BYOVD) 커스텀 커널 코드를 실행하고 보호를 비활성화합니다. **PPLKiller**, **gdrv-loader**, 또는 **kdmapper**와 같은 도구들이 이를 가능하게 합니다.
3. 다른 프로세스(예: AV 프로세스)가 열어둔 기존 LSASS 핸들을 훔쳐서(steal) 그 핸들을 자신의 프로세스로 **복제(duplicate)** 합니다. 이것이 `pypykatz live lsa --method handledup` 기법의 기반입니다.
4. 임의의 코드를 해당 주소 공간이나 다른 권한있는 프로세스 내부에 로드하도록 허용하는 일부 권한있는 프로세스를 악용하여 PPL 제한을 우회합니다. 이에 대한 예시는 [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 또는 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump)에서 확인할 수 있습니다.

**LSASS에 대한 LSA 보호(PPL/PP)의 현재 상태 확인:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, a feature exclusive to **Windows 10 (Enterprise and Education editions)**, enhances the security of machine credentials using **Virtual Secure Mode (VSM)** and **Virtualization Based Security (VBS)**. It leverages CPU virtualization extensions to isolate key processes within a protected memory space, away from the main operating system's reach. This isolation ensures that even the kernel cannot access the memory in VSM, effectively safeguarding credentials from attacks like **pass-the-hash**. The **Local Security Authority (LSA)** operates within this secure environment as a trustlet, while the **LSASS** process in the main OS acts merely as a communicator with the VSM's LSA.

By default, **Credential Guard** is not active and requires manual activation within an organization. It's critical for enhancing security against tools like **Mimikatz**, which are hindered in their ability to extract credentials. However, vulnerabilities can still be exploited through the addition of custom **Security Support Providers (SSP)** to capture credentials in clear text during login attempts.

To verify **Credential Guard**'s activation status, the registry key _**LsaCfgFlags**_ under _**HKLM\System\CurrentControlSet\Control\LSA**_ can be inspected. A value of "**1**" indicates activation with **UEFI lock**, "**2**" without lock, and "**0**" denotes it is not enabled. This registry check, while a strong indicator, is not the sole step for enabling Credential Guard. Detailed guidance and a PowerShell script for enabling this feature are available online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** introduced several new security features, including the _**Restricted Admin mode for RDP**_. This mode was designed to enhance security by mitigating the risks associated with [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks.

전통적으로 RDP를 통해 원격 컴퓨터에 연결할 때, 사용자의 자격 증명은 대상 머신에 저장됩니다. 이는 권한이 높은 계정을 사용할 때 특히 큰 보안 위험을 초래합니다. 그러나 _**Restricted Admin mode**_가 도입되면서 이 위험은 상당히 줄어들었습니다.

mstsc.exe /RestrictedAdmin 명령으로 RDP 연결을 시작하면, 원격 컴퓨터에 대한 인증이 해당 자격 증명을 그곳에 저장하지 않고 수행됩니다. 이렇게 하면 악성코드 감염 또는 원격 서버에 악의적 사용자가 접근하더라도 자격 증명이 서버에 저장되지 않으므로 노출되지 않습니다.

중요한 점은 **Restricted Admin mode**에서는 RDP 세션에서 네트워크 리소스에 접근하려 할 때 개인 자격 증명을 사용하지 않고 대신 **컴퓨터 신원**이 사용된다는 것입니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 침해 시 민감한 정보가 노출되는 것을 방지하는 데 중요한 진전을 의미합니다.

![](../../images/RAM.png)

자세한 정보는 [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)를 참조하세요.

## Cached Credentials

Windows는 **domain credentials**을 통해 **Local Security Authority (LSA)**로 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜로 로그온 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 사용자가 **domain controller가 오프라인**인 경우에도 컴퓨터에 액세스할 수 있도록 **마지막 10개의 도메인 로그인**을 캐시하는 기능입니다. 이는 회사 네트워크에서 자주 떨어져 있는 노트북 사용자에게 매우 유용합니다.

캐시된 로그인 수는 특정 **registry key 또는 group policy**를 통해 조정할 수 있습니다. 이 설정을 확인하거나 변경하려면 다음 명령을 사용합니다:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
이 캐시된 자격 증명에 대한 접근은 엄격히 통제되며, 해당 정보를 볼 수 있는 권한은 오직 **SYSTEM** 계정에만 있습니다. 이 정보에 접근해야 하는 관리자는 SYSTEM 사용자 권한으로 접근해야 합니다. 자격 증명은 다음에 저장됩니다: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**를 사용해 `lsadump::cache` 명령으로 이 캐시된 자격 증명을 추출할 수 있습니다.

자세한 내용은 원문 [source](http://juggernaut.wikidot.com/cached-credentials)에서 확인하세요.

## Protected Users

**Protected Users group**의 구성원 자격은 사용자에게 여러 보안 강화 기능을 적용하여 자격 증명 탈취 및 남용으로부터 더 높은 수준의 보호를 제공합니다:

- **Credential Delegation (CredSSP)**: Group Policy의 **Allow delegating default credentials** 설정이 활성화되어 있어도, Protected Users의 평문 자격 증명은 캐시되지 않습니다.
- **Windows Digest**: **Windows 8.1 and Windows Server 2012 R2**부터는 Windows Digest 상태와 관계없이 Protected Users의 평문 자격 증명을 캐시하지 않습니다.
- **NTLM**: 시스템은 Protected Users의 평문 자격 증명이나 NT one-way functions (NTOWF)을 캐시하지 않습니다.
- **Kerberos**: Protected Users의 경우 Kerberos 인증은 **DES** 또는 **RC4 keys**를 생성하지 않으며, 초기 Ticket-Granting Ticket (TGT) 획득을 넘어서 평문 자격 증명이나 장기 키를 캐시하지 않습니다.
- **Offline Sign-In**: Protected Users는 로그인 또는 잠금 해제 시 캐시된 검증자(verifier)가 생성되지 않으므로 오프라인 로그인은 지원되지 않습니다.

이러한 보호는 사용자가 **Protected Users group**의 구성원으로 기기에 로그인하는 순간 적용됩니다. 이는 다양한 자격 증명 침해 방법으로부터 보호하기 위한 중요한 보안 조치가 활성화되도록 합니다.

자세한 정보는 공식 [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) 를 참조하세요.

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

## 참고자료

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
