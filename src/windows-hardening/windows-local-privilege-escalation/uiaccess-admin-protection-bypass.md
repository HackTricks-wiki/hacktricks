# UIAccess를 통한 Admin Protection 우회

{{#include ../../banners/hacktricks-training.md}}

## 개요
- Windows AppInfo는 UIAccess 프로세스를 생성하기 위해 `RAiLaunchAdminProcess`를 노출합니다(접근성용으로 의도됨). UIAccess는 대부분의 User Interface Privilege Isolation (UIPI) 메시지 필터링을 우회하여 접근성 소프트웨어가 더 높은 IL의 UI를 제어할 수 있게 합니다.
- UIAccess를 직접 활성화하려면 `NtSetInformationToken(TokenUIAccess)`를 **SeTcbPrivilege**와 함께 호출해야 하므로 권한이 낮은 호출자는 서비스에 의존합니다. 서비스는 UIAccess를 설정하기 전에 대상 바이너리에 대해 세 가지 검사를 수행합니다:
  - 임베디드 매니페스트에 `uiAccess="true"`가 포함되어 있는지.
  - Local Machine 루트 저장소에서 신뢰하는 인증서로 서명되었는지(특정 EKU/Microsoft 요구사항 없음).
  - 시스템 드라이브의 관리자 전용 경로에 위치하는지(예: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, 특정 쓰기 가능한 하위 경로 제외).
- `RAiLaunchAdminProcess`는 UIAccess 실행에 대해 동의(consent) 프롬프트를 표시하지 않습니다(그렇지 않으면 접근성 도구가 프롬프트를 제어할 수 없습니다).

## Token shaping 및 무결성 수준
- 검사가 통과되면 AppInfo는 **호출자 토큰을 복사하고**, UIAccess를 활성화하며 무결성 수준(IL)을 상승시킵니다:
  - 제한된 관리자 사용자(Administrators 그룹에 속하지만 필터링된 상태) ➜ **High IL**.
  - 비관리자 사용자 ➜ IL이 **+16 레벨**씩 증가하여 최대 **High**까지 상승(시스템 IL은 부여되지 않음).
- 호출자 토큰에 이미 UIAccess가 있으면 IL은 변경되지 않습니다.
- “Ratchet” 기법: UIAccess 프로세스가 스스로의 UIAccess를 비활성화하고 `RAiLaunchAdminProcess`로 재실행하면 추가로 +16 IL 증가를 얻을 수 있습니다. Medium➜High는 255번의 재실행이 필요합니다(시끄럽지만 작동함).

## UIAccess가 Admin Protection 우회를 가능하게 하는 이유
- UIAccess는 더 낮은 IL 프로세스가 더 높은 IL의 윈도우로 윈도우 메시지를 보낼 수 있게 하여 UIPI 필터를 우회합니다. 동일 IL에서는 `SetWindowsHookEx`와 같은 전통적 UI 원시가 윈도우를 소유한 모든 프로세스(예: COM에서 사용하는 **message-only windows** 포함)에 코드 인젝션/DLL 로딩을 허용합니다.
- Admin Protection은 UIAccess 프로세스를 **제한된 사용자 신원**으로, 그러나 **High IL**로 조용히 실행합니다. 해당 High-IL UIAccess 프로세스 내부에서 임의 코드가 실행되면 공격자는 데스크탑의 다른 High-IL 프로세스(다른 사용자 소유인 경우도 포함)에 인젝션할 수 있어 의도된 분리가 깨집니다.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803 이상에서 해당 API는 Win32k로 이동하여(`NtUserGetWindowProcessHandle`) 호출자가 제공한 `DesiredAccess`를 사용해 프로세스 핸들을 열 수 있게 되었습니다. 커널 경로는 `ObOpenObjectByPointer(..., KernelMode, ...)`를 사용하여 일반적인 사용자 모드 접근 검사를 우회합니다.
- 실무상 전제조건: 대상 윈도우는 같은 데스크탑에 있어야 하며 UIPI 검사를 통과해야 합니다. 역사적으로 UIAccess를 가진 호출자는 UIPI 실패를 우회하고 여전히 커널 모드 핸들을 얻을 수 있었는데(이는 CVE-2023-41772로 수정됨).
- 영향: 윈도우 핸들은 호출자가 정상적으로 열 수 없던 강력한 프로세스 핸들(주로 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`)을 얻을 수 있는 **capability**가 됩니다. 이는 샌드박스 간 접근을 가능하게 하고, 대상이 어떤 윈도우(예: message-only windows)를 노출하면 Protected Process / PPL 경계를 무너뜨릴 수 있습니다.
- 실제 악용 흐름: HWND를 열거하거나 찾기(예: `EnumWindows`/`FindWindowEx`), 소유 PID 확인(`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` 호출, 반환된 핸들로 메모리 읽기/쓰기 또는 코드 하이재킹 원시를 수행합니다.
- 패치 이후 동작: UIAccess는 더 이상 UIPI 실패 시 커널 모드 오픈을 허용하지 않으며 허용된 접근 권한은 레거시 후크 집합으로 제한됩니다; Windows 11 24H2는 프로세스 보호 검사와 기능 플래그로 제어되는 안전한 경로를 추가했습니다. 시스템 전체에서 UIPI를 비활성화(`EnforceUIPI=0`)하면 이러한 보호가 약화됩니다.

## 보안 디렉터리 검증 취약점 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo는 제공된 경로를 `GetFinalPathNameByHandle`로 해석한 다음 하드코딩된 루트/제외 목록에 대해 **문자열 허용/거부 검사**를 적용합니다. 그 단순한 검증으로 인해 여러 우회 유형이 발생합니다:
- **Directory named streams**: 제외된 쓰기 가능한 디렉터리(예: `C:\Windows\tracing`)는 디렉터리 자체의 named stream을 이용해 우회할 수 있습니다. 예: `C:\Windows\tracing:file.exe`. 문자열 검사는 `C:\Windows\`를 보고 제외된 하위 경로를 놓칩니다.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser`는 **`.exe` 확장자를 요구하지 않습니다**. 허용된 루트 아래의 쓰기 가능한 파일을 실행 파일 페이로드로 덮어쓰거나 서명된 `uiAccess="true"` EXE를 쓰기 가능한 하위 디렉터리(예: `Tasks_Migrated`와 같은 업데이트 잔여물)로 복사하면 secure-path 검사를 통과합니다.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: 비관리자는 `WindowsApps`에 설치된 서명된 MSIX 패키지를 설치할 수 있었고 해당 경로는 제외 대상이 아니었습니다. MSIX에 UIAccess 바이너리를 포함시키고 `RAiLaunchAdminProcess`로 실행하면 **프롬프트 없는 High-IL UIAccess 프로세스**를 얻을 수 있었습니다. Microsoft는 이 경로를 제외하여 완화했으며, `uiAccess`로 제한된 MSIX 기능 자체는 이미 관리자 설치를 요구합니다.

## 공격 워크플로우 (프롬프트 없는 High IL)
1. 서명된 UIAccess 바이너리(**signed UIAccess binary**)를 획득하거나 제작합니다(매니페스트 `uiAccess="true"`).
2. AppInfo의 허용 목록이 허용하는 위치에 배치하거나(또는 위에서 언급한 경로 검증 엣지케이스/쓰기 가능한 아티팩트를 악용).
3. `RAiLaunchAdminProcess`를 호출해 UIAccess + 상승된 IL로 **조용히** 실행합니다.
4. 그 High-IL 발판에서 **window hooks/DLL injection** 또는 다른 동일 IL 원시를 이용해 데스크탑의 다른 High-IL 프로세스를 표적으로 삼아 관리자 컨텍스트를 완전히 장악합니다.

## 후보 쓰기 가능한 경로 열거
선택한 토큰 관점에서 명목상 안전한 루트 내의 쓰기/덮어쓸 수 있는 객체를 찾기 위해 PowerShell 헬퍼를 실행합니다:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 관리자 권한으로 실행하여 더 넓은 가시성을 확보하세요; `-ProcessId`를 low-priv 프로세스로 설정하여 해당 token의 접근 권한을 미러하세요.
- `RAiLaunchAdminProcess`로 후보를 사용하기 전에 알려진 허용되지 않는 하위 디렉터리를 수동으로 필터링하세요.

## 참조
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
