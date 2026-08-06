# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) 프로토콜은 Windows XP와 함께 도입되었으며 HTTP Protocol을 통한 인증을 위해 설계되었습니다. 또한 **Windows XP부터 Windows 8.0까지와 Windows Server 2003부터 Windows Server 2012까지 기본적으로 enabled**되어 있습니다. 이 기본 설정으로 인해 **LSASS**(Local Security Authority Subsystem Service)에 **plain-text password가 저장**됩니다. 공격자는 Mimikatz를 사용하여 다음을 실행함으로써 **이 자격 증명을 추출**할 수 있습니다:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
이 기능을 **끄거나 켜려면**, _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 내 _**UseLogonCredential**_ 및 _**Negotiate**_ registry key를 "1"로 설정해야 합니다. 이러한 key가 **없거나 "0"으로 설정된 경우**, WDigest는 **비활성화**됩니다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** 및 **Protected Process Light (PPL)**은 **LSASS**와 같은 민감한 프로세스에 대한 무단 액세스를 방지하도록 설계된 **Windows kernel-level protections**입니다. **Windows Vista**에서 도입된 **PP model**은 원래 **DRM** 적용을 위해 만들어졌으며, **special media certificate**로 서명된 바이너리만 보호할 수 있었습니다. **PP**로 표시된 프로세스는 **동일하게 PP**이고 **동등하거나 더 높은 protection level**을 가진 다른 프로세스만 액세스할 수 있으며, 그 경우에도 별도로 허용되지 않는 한 **제한된 access rights**만 사용할 수 있습니다.

**Windows 8.1**에서 도입된 **PPL**은 PP의 더 유연한 버전입니다. **digital signature의 EKU (Enhanced Key Usage)** 필드를 기반으로 한 **"protection levels"**를 도입하여 더 광범위한 사용 사례(예: LSASS, Defender)를 지원합니다. protection level은 `EPROCESS.Protection` 필드에 저장되며, 다음 항목을 포함하는 `PS_PROTECTION` 구조체입니다.
- **Type** (`Protected` 또는 `ProtectedLight`)
- **Signer** (예: `WinTcb`, `Lsa`, `Antimalware` 등)

이 구조체는 단일 byte로 패킹되며 **누가 누구에게 액세스할 수 있는지**를 결정합니다.
- **더 높은 signer 값은 더 낮은 값에 액세스할 수 있음**
- **PPL은 PP에 액세스할 수 없음**
- **Unprotected processes는 어떤 PPL/PP에도 액세스할 수 없음**

### 공격 관점에서 알아야 할 내용

- **LSASS가 PPL로 실행 중인 경우**, 일반적인 admin context에서 `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)`를 사용해 LSASS를 열려고 하면 `SeDebugPrivilege`가 활성화되어 있어도 **`0x5 (Access Denied)`**로 실패합니다.
- Process Hacker와 같은 도구를 사용하거나, 프로그래밍 방식으로 `EPROCESS.Protection` 값을 읽어 **LSASS protection level**을 확인할 수 있습니다.
- LSASS는 일반적으로 `PsProtectedSignerLsa-Light` (`0x41`)를 사용하며, `WinTcb` (`0x61` 또는 `0x62`)와 같이 더 높은 level의 signer로 서명된 프로세스만 액세스할 수 있습니다.
- PPL은 **Userland-only restriction**이며, **kernel-level code는 이를 완전히 우회할 수 있습니다**.
- LSASS가 PPL이라고 해서 **kernel shellcode를 실행**하거나 **적절한 access 권한을 가진 high-privileged process를 활용**할 수 있는 경우 credential dumping이 방지되는 것은 아닙니다.
- **PPL을 설정하거나 제거**하려면 reboot 또는 **Secure Boot/UEFI settings**가 필요하며, registry 변경을 되돌린 후에도 PPL 설정이 유지될 수 있습니다.

### Create a PPL process at launch (documented API)

Windows는 extended startup attribute list를 사용하여 프로세스 생성 중 child process에 Protected Process Light level을 요청하는 documented 방법을 제공합니다. 이는 signing requirements를 우회하지 않으며, target image는 요청된 signer class에 맞게 서명되어 있어야 합니다.

C/C++의 최소 흐름:
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
Notes and constraints:
- `STARTUPINFOEX`를 `InitializeProcThreadAttributeList` 및 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`과 함께 사용한 다음, `CreateProcess*`에 `EXTENDED_STARTUPINFO_PRESENT`를 전달합니다.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 보호 `DWORD`는 `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` 또는 `PROTECTION_LEVEL_LSA_LIGHT`와 같은 상수로 설정할 수 있습니다.
- 해당 이미지가 signer class에 맞게 서명된 경우에만 child가 PPL로 시작됩니다. 그렇지 않으면 일반적으로 `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`와 함께 process creation이 실패합니다.
- 이는 bypass가 아닙니다. 적절히 서명된 이미지용으로 제공되는 supported API입니다. 도구를 harden하거나 PPL-protected configuration을 검증하는 데 유용합니다.

minimal loader를 사용하는 Example CLI:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL protection 우회 옵션:**

PPL에도 불구하고 LSASS를 dump하려는 경우, 주요 옵션은 3가지입니다:
1. **signed kernel driver(예: Mimikatz + mimidrv.sys)를 사용하여** **LSASS의 protection flag를 제거**합니다:

![credential protection 상호작용을 보여주는 Mimikatz mimidrv driver 출력](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**를 사용하여 custom kernel code를 실행하고 protection을 비활성화합니다. **PPLKiller**, **gdrv-loader** 또는 **kdmapper**와 같은 도구를 사용하면 이를 수행할 수 있습니다.
3. 이미 LSASS handle을 열어 둔 다른 process(예: AV process)에서 기존 LSASS handle을 **탈취한 다음**, 이를 자신의 process로 **duplicate**합니다. 이는 `pypykatz live lsa --method handledup` technique의 기반입니다.
4. arbitrary code를 해당 process의 address space 또는 다른 privileged process 내부에 load할 수 있도록 허용하는 일부 privileged process를 **abuse**하여 PPL restriction을 사실상 우회합니다. 이에 대한 예시는 [userland에서 LSA protection 우회](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) 또는 [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump)에서 확인할 수 있습니다.

**LSA protection(PPL/PP)의 현재 LSASS 상태 확인**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`**를 실행하면 다음과 같은 이유로 오류 코드 `0x00000005`와 함께 실패할 가능성이 높습니다.

- 이 검사에 대한 자세한 정보는 [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>를 참고하세요.


## Credential Guard

**Credential Guard**는 **Windows 10 (Enterprise 및 Education editions)** 전용 기능으로, **Virtual Secure Mode (VSM)**와 **Virtualization Based Security (VBS)**를 사용하여 시스템 자격 증명의 보안을 강화합니다. CPU virtualization extensions를 활용하여 주요 프로세스를 보호된 메모리 공간 내에 격리하고, 기본 운영 체제가 해당 공간에 접근하지 못하도록 합니다. 이러한 격리를 통해 커널조차 VSM의 메모리에 접근할 수 없으므로 **pass-the-hash**와 같은 공격으로부터 자격 증명을 효과적으로 보호합니다. **Local Security Authority (LSA)**는 이 보안 환경에서 trustlet으로 실행되며, 기본 OS의 **LSASS** 프로세스는 VSM의 LSA와 통신하는 역할만 수행합니다.

기본적으로 **Credential Guard**는 활성화되어 있지 않으며 조직에서 수동으로 활성화해야 합니다. 이는 자격 증명 추출 기능이 제한되는 **Mimikatz**와 같은 도구에 대한 보안을 강화하는 데 중요합니다. 그러나 로그인 시도 중 자격 증명을 clear text로 캡처하기 위해 사용자 지정 **Security Support Providers (SSP)**를 추가하는 방식으로 여전히 취약점을 악용할 수 있습니다.

**Credential Guard**의 활성화 상태를 확인하려면 _**HKLM\System\CurrentControlSet\Control\LSA**_ 아래의 레지스트리 키 _**LsaCfgFlags**_를 검사할 수 있습니다. "**1**"은 **UEFI lock**과 함께 활성화되었음을, "**2**"는 lock 없이 활성화되었음을 나타내며, "**0**"은 활성화되지 않았음을 의미합니다. 이 레지스트리 검사는 강력한 지표이지만 Credential Guard를 활성화하는 유일한 단계는 아닙니다. 이 기능을 활성화하기 위한 자세한 지침과 PowerShell script는 온라인에서 확인할 수 있습니다.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10에서 **Credential Guard**를 활성화하는 방법과 **Windows 11 Enterprise 및 Education (version 22H2)**의 호환 시스템에서 자동으로 활성화되는 방식에 대한 종합적인 이해와 지침은 [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)을 참조하세요.<sup>[[9]](#references)</sup>

credential capture를 위한 custom SSP 구현에 대한 자세한 내용은 [this guide](../active-directory-methodology/custom-ssp.md)에 제공되어 있습니다.

## RDP RestrictedAdmin Mode

**Windows 8.1 및 Windows Server 2012 R2**에는 _**Restricted Admin mode for RDP**_를 비롯한 여러 새로운 보안 기능이 도입되었습니다. 이 모드는 [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) 공격과 관련된 위험을 완화하여 보안을 강화하기 위해 설계되었습니다.

기존에는 RDP를 통해 원격 컴퓨터에 연결할 때 자격 증명이 대상 머신에 저장되었습니다. 이는 특히 높은 권한을 가진 계정을 사용할 때 심각한 보안 위험을 초래합니다. 그러나 _**Restricted Admin mode**_가 도입되면서 이러한 위험이 크게 줄어들었습니다.

**mstsc.exe /RestrictedAdmin** 명령을 사용하여 RDP 연결을 시작하면 자격 증명을 저장하지 않고 원격 컴퓨터에 인증이 수행됩니다. 이 방식은 malware 감염이 발생하거나 악의적인 사용자가 원격 서버에 액세스하더라도 자격 증명이 서버에 저장되지 않으므로 자격 증명이 손상되지 않도록 합니다.

**Restricted Admin mode**에서는 RDP 세션에서 네트워크 리소스에 액세스하려는 시도가 개인 자격 증명을 사용하지 않고 **machine's identity**를 사용한다는 점에 유의해야 합니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 침해가 발생했을 때 민감한 정보가 노출되지 않도록 보호하는 데 있어 중요한 발전입니다.

![credential extraction context를 위한 Windows RAM memory diagram](../../images/RAM.png)

자세한 내용은 [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)를 참조하세요.<sup>[[6]](#references)</sup>

## Cached Credentials

Windows는 **Local Security Authority (LSA)**를 통해 **domain credentials**를 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜을 사용하여 logon 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 **last ten domain logins**를 캐시하여 **domain controller가 offline** 상태인 경우에도 사용자가 컴퓨터에 액세스할 수 있도록 하는 것입니다. 이는 회사 네트워크에서 자주 벗어나 있는 laptop 사용자에게 특히 유용합니다.

캐시되는 logins 수는 특정 **registry key 또는 group policy**를 통해 조정할 수 있습니다. 이 설정을 확인하거나 변경하려면 다음 명령을 사용합니다:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
이러한 cached credentials에 대한 접근은 엄격하게 제어되며, 이를 확인하는 데 필요한 권한을 가진 계정은 **SYSTEM** 계정뿐입니다. 이 정보에 접근해야 하는 Administrators는 SYSTEM user 권한으로 수행해야 합니다. credentials는 다음 위치에 저장됩니다: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**를 사용하여 `lsadump::cache` 명령으로 이러한 cached credentials를 추출할 수 있습니다.

자세한 내용은 종합적인 정보를 제공하는 원본 [source](http://juggernaut.wikidot.com/cached-credentials)를 참조하세요.<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users group**의 구성원이 되면 사용자에게 여러 보안 강화 기능이 적용되어 credential theft 및 오용에 대한 보호 수준이 높아집니다:

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** Group Policy 설정이 활성화되어 있더라도 Protected Users의 plain text credentials는 cache되지 않습니다.
- **Windows Digest**: **Windows 8.1 및 Windows Server 2012 R2**부터 Windows Digest 상태와 관계없이 Protected Users의 plain text credentials를 cache하지 않습니다.
- **NTLM**: 시스템은 Protected Users의 plain text credentials 또는 NT one-way functions (NTOWF)를 cache하지 않습니다.
- **Kerberos**: Protected Users의 경우 Kerberos authentication은 **DES** 또는 **RC4 keys**를 생성하지 않으며, 최초의 Ticket-Granting Ticket (TGT) 획득 이후 plain text credentials 또는 long-term keys를 cache하지 않습니다.
- **Offline Sign-In**: Protected Users는 sign-in 또는 unlock 시 cached verifier가 생성되지 않으므로 이러한 계정에서는 offline sign-in이 지원되지 않습니다.

이러한 보호 기능은 **Protected Users group**의 구성원인 사용자가 device에 sign-in하는 즉시 활성화됩니다. 이를 통해 다양한 credential compromise 방법으로부터 보호하는 핵심 보안 조치가 적용됩니다.

자세한 내용은 공식 [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)을 참조하세요.<sup>[[10]](#references)</sup>

**다음은** [**docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**의 표입니다.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators                |
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
| Schema Admins            | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

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
