# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo는 UIAccess 프로세스(접근성 용도로 의도됨)를 생성하기 위해 `RAiLaunchAdminProcess`를 노출합니다. UIAccess는 대부분의 User Interface Privilege Isolation (UIPI) 메시지 필터링을 우회해 접근성 소프트웨어가 더 높은 IL(Integrity Level) UI를 제어할 수 있게 합니다.
- UIAccess를 직접 활성화하려면 `NtSetInformationToken(TokenUIAccess)`에 **SeTcbPrivilege**가 필요하므로 권한이 낮은 호출자는 서비스에 의존합니다. 서비스는 UIAccess를 설정하기 전에 대상 바이너리에 대해 세 가지 검사를 수행합니다:
- 임베디드 매니페스트에 `uiAccess="true"`가 포함되어 있는지.
- 로컬 머신 루트 저장소에서 신뢰하는 인증서로 서명되었는지 (EKU/Microsoft 요구사항 없음).
- 시스템 드라이브의 관리자 전용 경로에 위치하는지 (예: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, 특정 쓰기 가능한 하위 경로는 제외).
- `RAiLaunchAdminProcess`는 UIAccess 런치에 대해 동의 프롬프트를 표시하지 않습니다(그렇지 않으면 접근성 도구가 프롬프트를 제어할 수 없음).

## Token shaping and integrity levels
- 검사가 통과되면 AppInfo는 **호출자 토큰을 복사**하고 UIAccess를 활성화하며 Integrity Level(IL)을 올립니다:
- 제한된 관리자 사용자(사용자가 Administrators에 속하지만 필터링된 상태로 실행) ➜ **High IL**.
- 비관리자 사용자 ➜ IL이 **+16 레벨**만큼 증가하며 **High** 상한까지 올립니다(System IL은 절대 할당되지 않음).
- 호출자 토큰에 이미 UIAccess가 있으면 IL은 변경되지 않습니다.
- “Ratchet” 트릭: UIAccess 프로세스가 스스로의 UIAccess를 비활성화하고 `RAiLaunchAdminProcess`로 재실행하면 또 다른 +16 IL 증가를 얻을 수 있습니다. Medium➜High로 올리려면 255회 재실행이 필요합니다(시끄럽지만 동작함).

## Why UIAccess enables an Admin Protection escape
- UIAccess는 낮은 IL 프로세스가 높은 IL 창으로 윈도우 메시지를 보낼 수 있게 해 UIPI 필터를 우회합니다. 동등한 IL에서는 `SetWindowsHookEx` 같은 고전적인 UI 원시 기능이 창을 소유한 어떤 프로세스(메시지만 사용하는 창을 포함, COM에서 사용됨)에도 코드 인젝션/DLL 로드를 허용합니다.
- Admin Protection은 UIAccess 프로세스를 **제한된 사용자 신원**으로, 그러나 **High IL**에서 조용히 실행하도록 합니다. 일단 해당 High-IL UIAccess 프로세스 내에서 임의 코드가 실행되면 공격자는 데스크탑상의 다른 High-IL 프로세스(다른 사용자 소유 프로세스 포함)에 인젝션할 수 있어 의도된 분리를 깨뜨립니다.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+에서 API는 Win32k(`NtUserGetWindowProcessHandle`)로 이동했고, 호출자가 제공한 `DesiredAccess`를 사용해 프로세스 핸들을 열 수 있게 되었습니다. 커널 경로는 `ObOpenObjectByPointer(..., KernelMode, ...)`를 사용하므로 일반 사용자 모드 접근 검사들을 우회합니다.
- 실제 전제조건: 대상 창은 동일한 데스크탑에 있어야 하고 UIPI 검사가 통과되어야 합니다. 역사적으로 UIAccess가 있는 호출자는 UIPI 실패를 우회하고 여전히 커널 모드 핸들을 얻을 수 있었으나(CVE-2023-41772) 수정되었습니다.
- 영향: 창 핸들은 호출자가 통상적으로 열 수 없던 강력한 프로세스 핸들(일반적으로 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`)을 얻기 위한 능력(capability)이 됩니다. 이는 크로스 샌드박스 접근을 가능하게 하고 대상이 어떤 창(메시지 전용 창 포함)을 노출하면 Protected Process / PPL 경계도 무너질 수 있습니다.
- 실제 악용 흐름: HWND를 열거하거나 찾기(e.g., `EnumWindows`/`FindWindowEx`), 소유 PID 확인(`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` 호출, 반환된 핸들로 메모리 읽기/쓰기 또는 코드 하이재킹 원시 기능 수행.
- 패치 이후 동작: UIAccess는 더 이상 UIPI 실패 시 커널 모드 오픈을 부여하지 않으며 허용된 접근 권한이 레거시 훅 세트로 제한됩니다; Windows 11 24H2는 프로세스 보호 검사 및 기능 플래그된 안전한 경로를 추가합니다. UIPI를 시스템 전역에서 비활성화(`EnforceUIPI=0`)하면 이러한 보호가 약화됩니다.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo는 제공된 경로를 `GetFinalPathNameByHandle`로 해석한 후 하드코딩된 루트/제외 경로에 대해 **문자열 허용/거부 검사**를 적용합니다. 그 단순한 검증으로 인해 여러 우회 기법이 발생합니다:
- **Directory named streams**: 제외된 쓰기 가능한 디렉터리(예: `C:\Windows\tracing`)는 디렉터리 자체의 네임드 스트림을 사용하여 우회할 수 있습니다(예: `C:\Windows\tracing:file.exe`). 문자열 검사는 `C:\Windows\`를 보고 제외된 하위 경로를 놓칩니다.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser`는 **`.exe` 확장자를 필요로 하지 않습니다**. 허용된 루트 아래의 쓰기 가능한 파일을 실행 파일로 덮어쓰거나 서명된 `uiAccess="true"` EXE를 쓰기 가능한 하위 디렉터리(예: 존재하는 경우 `Tasks_Migrated`와 같은 업데이트 잔재)에 복사하면 secure-path 검사를 통과합니다.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: 비관리자가 서명된 MSIX 패키지를 설치하여 `WindowsApps`에 배치할 수 있었고, 이 경로는 제외 대상이 아니었습니다. MSIX에 UIAccess 바이너리를 패키징하고 `RAiLaunchAdminProcess`로 실행하면 **프롬프트 없는 High-IL UIAccess 프로세스**가 생성되었습니다. Microsoft는 이 경로를 제외하여 완화했고; `uiAccess`가 제한된 MSIX 권한 자체는 이미 관리자 설치를 요구합니다.

## Attack workflow (High IL without a prompt)
1. 서명된 UIAccess 바이너리(매니페스트 `uiAccess="true"`)를 확보하거나 빌드합니다.
2. AppInfo의 허용 목록에 들어가는 위치에 두거나(또는 위의 경로 검증 엣지 케이스/쓰기 가능한 아티팩트를 악용).
3. `RAiLaunchAdminProcess`를 호출해 UIAccess + 증가된 IL로 **조용히** 실행합니다.
4. 그 High-IL 거점에서 **window hooks/DLL injection** 또는 기타 동일 IL 원시 기능을 사용해 데스크탑 상의 다른 High-IL 프로세스를 겨냥하여 관리자 컨텍스트를 완전히 장악합니다.

## Enumerating candidate writable paths
선택한 토큰 관점에서 명목상 안전한 루트 내의 쓰기 가능/덮어쓸 수 있는 객체를 발견하려면 PowerShell 헬퍼를 실행하세요:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator로 실행하여 더 넓은 가시성을 확보하세요; 토큰의 접근 권한을 반영하려면 `-ProcessId`를 낮은 권한의 프로세스로 설정하세요.
- 후보를 `RAiLaunchAdminProcess`로 사용하기 전에 알려진 허용되지 않는 하위 디렉토리를 수동으로 제외하도록 필터링하세요.

## 관련

Secure Desktop 접근성 레지스트리 전파 LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 참조
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
