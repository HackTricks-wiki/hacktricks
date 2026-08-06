# UIAccess를 통한 Admin Protection Bypass

{{#include ../../banners/hacktricks-training.md}}

## 개요
- Windows AppInfo는 UIAccess 프로세스를 생성하기 위해 `RAiLaunchAdminProcess`를 노출합니다. 이는 접근성을 위해 설계되었습니다. UIAccess는 대부분의 User Interface Privilege Isolation (UIPI) 메시지 필터링을 우회하므로, 접근성 software가 더 높은-IL UI를 제어할 수 있습니다.
- UIAccess를 직접 활성화하려면 **SeTcbPrivilege**를 사용한 `NtSetInformationToken(TokenUIAccess)`가 필요하므로, low-priv caller는 service에 의존합니다. service는 UIAccess를 설정하기 전에 대상 binary에 대해 다음 세 가지 검사를 수행합니다:
- Embedded manifest에 `uiAccess="true"`가 포함되어 있는지 확인합니다.
- Local Machine root store가 신뢰하는 모든 certificate로 서명되었는지 확인합니다(EKU/Microsoft requirement는 없음).
- system drive의 administrator-only path에 위치하는지 확인합니다(예: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`; 특정 writable subpath는 제외).
- `RAiLaunchAdminProcess`는 UIAccess launch에 대해 consent prompt를 수행하지 않습니다(그렇지 않으면 accessibility tooling이 prompt를 제어할 수 없음).<sup>[[1]](#references)</sup>

## Token shaping 및 integrity levels
- 검사가 성공하면 AppInfo는 **caller token을 복사**하고, UIAccess를 활성화한 뒤 Integrity Level (IL)을 높입니다:
- Limited admin user(user가 Administrators에 속하지만 filtered 상태로 실행 중) ➜ **High IL**.
- Non-admin user ➜ IL이 **+16 levels** 증가하며 **High** cap까지 적용됩니다(System IL은 할당되지 않음).
- caller token에 이미 UIAccess가 있으면 IL은 변경되지 않습니다.
- “Ratchet” trick: UIAccess process는 자체 UIAccess를 비활성화하고 `RAiLaunchAdminProcess`를 통해 다시 launch한 뒤, 추가로 +16 IL increment를 얻을 수 있습니다. Medium➜High에는 255회의 relaunch가 필요합니다(noisy하지만 작동함).<sup>[[1]](#references)</sup>

## UIAccess가 Admin Protection escape를 가능하게 하는 이유
- UIAccess를 사용하면 lower-IL process가 higher-IL window로 window message를 전송할 수 있습니다(UIPI filter 우회). **동일한 IL**에서는 `SetWindowsHookEx`와 같은 classic UI primitive가 window를 소유한 모든 process에 **code injection/DLL loading**을 허용합니다(COM에서 사용하는 **message-only window**도 포함).
- Admin Protection은 UIAccess process를 **limited user의 identity**로 실행하지만 **High IL**에서 조용히 실행합니다. 이 High-IL UIAccess process 내부에서 arbitrary code가 실행되면 attacker는 desktop의 다른 High-IL process(서로 다른 user에 속한 경우도 포함)에 inject할 수 있어, 의도된 separation이 무너집니다.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+에서 API는 Win32k로 이동했으며(`NtUserGetWindowProcessHandle`), caller가 제공한 `DesiredAccess`를 사용해 process handle을 열 수 있습니다. kernel path는 `ObOpenObjectByPointer(..., KernelMode, ...)`를 사용하며, 일반적인 user-mode access check를 우회합니다.<sup>[[2]](#references)</sup>
- 실제 precondition: 대상 window가 동일한 desktop에 있어야 하며 UIPI check가 통과해야 합니다. 과거에는 UIAccess를 가진 caller가 UIPI failure를 우회하고도 kernel-mode handle을 얻을 수 있었습니다(CVE-2023-41772로 수정됨).
- 영향: window handle은 **capability**가 되어, caller가 일반적으로 열 수 없는 강력한 process handle(일반적으로 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`)을 얻을 수 있습니다. 이를 통해 cross-sandbox access가 가능해지고, 대상이 window를 노출하는 경우(message-only window 포함) Protected Process / PPL boundary가 무너질 수 있습니다.
- Practical abuse flow: HWND를 enumerate하거나 locate하고(예: `EnumWindows`/`FindWindowEx`), 소유 PID를 resolve한 뒤(`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd`를 호출하고, 반환된 handle을 memory read/write 또는 code-hijack primitive에 사용합니다.
- Post-fix behavior: UIAccess는 더 이상 UIPI failure 시 kernel-mode open을 허용하지 않으며, 허용되는 access right는 legacy hook set으로 제한됩니다. Windows 11 24H2에는 process-protection check와 feature-flagged safer path가 추가되었습니다. UIPI를 system-wide로 비활성화하면(`EnforceUIPI=0`) 이러한 protection이 약화됩니다.<sup>[[2]](#references)</sup>

## Secure-directory validation weakness (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo는 `GetFinalPathNameByHandle`을 통해 제공된 path를 resolve한 다음, hardcoded root/exclusion에 대해 **string allow/deny check**를 적용합니다. 이러한 단순한 validation에서 여러 bypass class가 발생합니다:
- **Directory named stream**: 제외된 writable directory(예: `C:\Windows\tracing`)는 directory 자체의 named stream을 사용해 bypass할 수 있습니다. 예: `C:\Windows\tracing:file.exe`. string check는 `C:\Windows\`를 확인하지만 제외된 subpath를 놓칩니다.
- **허용된 root 내부의 writable file/directory**: `CreateProcessAsUser`는 **`.exe` extension을 요구하지 않습니다**. 허용된 root 아래의 writable file을 executable payload로 overwrite하거나, signed `uiAccess="true"` EXE를 writable subdirectory(예: 존재하는 경우 `Tasks_Migrated`와 같은 update leftover)에 복사하면 secure-path check를 통과할 수 있습니다.
- **MSIX를 `C:\Program Files\WindowsApps`에 설치(수정됨)**: Non-admin은 `WindowsApps`에 위치하는 signed MSIX package를 install할 수 있었으며, 이 path는 exclude되지 않았습니다. MSIX 내부에 UIAccess binary를 packaging한 후 `RAiLaunchAdminProcess`로 launch하면 **promptless High-IL UIAccess process**가 생성되었습니다. Microsoft는 이 path를 제외하는 방식으로 완화했으며, `uiAccess` restricted MSIX capability 자체는 이미 admin install을 요구합니다.<sup>[[1]](#references)</sup>

## Attack workflow (prompt 없이 High IL)
1. **signed UIAccess binary**(manifest `uiAccess="true"`)를 obtain/build합니다.
2. AppInfo의 allowlist가 허용하는 위치에 배치하거나, 위와 같은 path-validation edge case/writable artifact를 abuse합니다.
3. `RAiLaunchAdminProcess`를 호출해 UIAccess + elevated IL로 **조용히** spawn합니다.
4. 이 High-IL foothold에서 **window hook/DLL injection** 또는 기타 same-IL primitive를 사용해 desktop의 다른 High-IL process를 target하고 admin context를 완전히 compromise합니다.<sup>[[1]](#references)</sup>

## Candidate writable path 열거
PowerShell helper를 실행해 선택한 token의 관점에서 nominally secure root 내부의 writable/overwritable object를 확인합니다:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 더 넓은 가시성을 위해 관리자 권한으로 실행하고, 해당 토큰의 access를 그대로 반영하려면 `-ProcessId`를 권한이 낮은 프로세스로 설정합니다.
- `RAiLaunchAdminProcess`와 함께 후보를 사용하기 전에 알려진 허용되지 않은 하위 디렉터리를 수동으로 필터링합니다.

## 관련 항목

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 참고 자료

- [1] [UI Access 악용을 통한 Administrator Protection 우회](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
