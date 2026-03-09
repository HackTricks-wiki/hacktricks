# UIAccess를 통한 Admin Protection 우회

{{#include ../../banners/hacktricks-training.md}}

## 개요
- Windows의 AppInfo는 UIAccess 프로세스를 생성하기 위한 `RAiLaunchAdminProcess`를 노출한다(접근성용으로 의도됨). UIAccess는 대부분의 User Interface Privilege Isolation (UIPI) 메시지 필터링을 우회하여 접근성 소프트웨어가 더 높은 IL의 UI를 조작할 수 있게 한다.
- UIAccess를 직접 활성화하려면 `NtSetInformationToken(TokenUIAccess)`를 **SeTcbPrivilege**와 함께 호출해야 하므로 저-권한 호출자는 서비스에 의존한다. 서비스는 UIAccess를 설정하기 전에 대상 바이너리에 대해 세 가지 검사를 수행한다:
  - 임베디드 매니페스트에 `uiAccess="true"`가 포함되어 있어야 한다.
  - Local Machine 루트 저장소에서 신뢰하는 어떤 인증서로 서명되어야 한다(EKU/Microsoft 요구사항 없음).
  - 시스템 드라이브의 관리자 전용 경로에 위치해야 한다(예: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, 특정 쓰기 가능한 하위경로는 제외).
- `RAiLaunchAdminProcess`는 UIAccess 실행에 대해 승인 프롬프트를 표시하지 않는다(그렇지 않으면 접근성 도구가 프롬프트를 조작할 수 없기 때문).

## 토큰 조작 및 무결성 레벨
- 검사가 통과되면 AppInfo는 호출자 토큰을 **복사**하고 UIAccess를 활성화한 뒤 무결성 레벨(IL)을 올린다:
  - 제한된 관리자 사용자(사용자가 Administrators에 속하지만 필터링된 상태로 실행) ➜ **High IL**.
  - 비관리자 사용자 ➜ IL이 **+16 레벨**씩 증가하여 **High** 한도까지 올라간다(절대 System IL은 부여되지 않음).
  - 호출자 토큰에 이미 UIAccess가 있으면 IL은 변경되지 않는다.
- “Ratchet” 트릭: UIAccess 프로세스가 자기 자신의 UIAccess를 비활성화한 뒤 `RAiLaunchAdminProcess`로 재실행하면 또다시 +16 IL 증분을 얻을 수 있다. Medium➜High는 255번의 재실행이 필요하다(소음이 크지만 동작함).

## UIAccess가 Admin Protection 우회를 가능하게 하는 이유
- UIAccess는 낮은 IL 프로세스가 높은 IL의 창으로 윈도우 메시지를 보낼 수 있게 해주어 UIPI 필터를 우회한다. 동일한 IL에서는 `SetWindowsHookEx` 같은 전통적 UI 프리미티브가 윈도우를 소유한 모든 프로세스(COM에서 사용하는 **message-only windows** 포함)에 코드 인젝션/DLL 로드를 허용한다.
- Admin Protection은 UIAccess 프로세스를 **제한된 사용자 신원**으로, 그러나 **High IL**로 조용히 실행한다. 그 High-IL UIAccess 프로세스 내부에서 임의 코드가 실행되면, 공격자는 데스크톱의 다른 High-IL 프로세스(다른 사용자 소유도 포함)에 인젝션할 수 있어 의도된 분리가 깨진다.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+에서 해당 API는 Win32k(`NtUserGetWindowProcessHandle`)로 이동했으며 호출자가 제공한 `DesiredAccess`를 이용해 프로세스 핸들을 열 수 있다. 커널 경로는 `ObOpenObjectByPointer(..., KernelMode, ...)`를 사용하여 일반 사용자 모드 접근 검사를 우회한다.
- 실무상의 전제조건: 대상 창은 같은 데스크톱에 있어야 하고 UIPI 검사를 통과해야 한다. 과거에는 UIAccess를 가진 호출자가 UIPI 실패를 우회하고도 커널 모드 핸들을 얻을 수 있었는데(해결: CVE-2023-41772) 수정되었다.
- 영향: 윈도우 핸들이 호출자가 통상적으로 열 수 없는 강력한 프로세스 핸들(보통 `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`)을 얻기 위한 **capability**가 된다. 이는 샌드박스 간 접근을 가능하게 하고 대상이 어떤 윈도우(message-only windows 포함)를 노출하면 Protected Process / PPL 경계를 무너뜨릴 수 있다.
- 실제 악용 흐름: HWND를 열거하거나 찾기(예: `EnumWindows`/`FindWindowEx`), 소유 PID 해결(`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` 호출, 반환된 핸들을 메모리 읽기/쓰기 또는 코드 하이재킹 프리미티브에 사용.
- 수정 후 동작: UIAccess는 더 이상 UIPI 실패 시 커널 모드 오픈을 허용하지 않으며 허용된 접근 권한은 레거시 훅 집합으로 제한된다; Windows 11 24H2는 프로세스 보호 검사와 기능 플래그된 안전한 경로를 추가했다. 시스템 전체에서 UIPI를 비활성화(`EnforceUIPI=0`)하면 이러한 보호가 약화된다.

## 보안 디렉터리 검증 취약점 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo는 제공된 경로를 `GetFinalPathNameByHandle`로 해석한 후 하드코딩된 루트/제외 항목에 대해 **문자열 허용/거부 검사**를 적용한다. 그 단순한 검증에서 여러 우회 기법이 발생한다:
- **디렉터리 네임드 스트림**: 제외된 쓰기 가능한 디렉터리(예: `C:\Windows\tracing`)는 디렉터리 자체의 네임드 스트림을 이용해 우회할 수 있다(예: `C:\Windows\tracing:file.exe`). 문자열 검사는 `C:\Windows\`만 보고 제외된 하위경로를 놓친다.
- **허용된 루트 내부의 쓰기 가능한 파일/디렉터리**: `CreateProcessAsUser`는 **`.exe` 확장자를 요구하지 않는다**. 허용된 루트 아래의 쓰기 가능한 파일을 실행 가능 페이로드로 덮어쓰기하거나 서명된 `uiAccess="true"` EXE를 어떤 쓰기 가능한 하위디렉터리(예: 존재하는 경우 `Tasks_Migrated` 같은 업데이트 잔재)에 복사하면 보안 경로 검사를 통과시킬 수 있다.
- **MSIX를 `C:\Program Files\WindowsApps`에 설치(수정됨)**: 비관리자도 `WindowsApps`에 설치된 서명된 MSIX 패키지를 설치할 수 있었고, 해당 경로가 제외되지 않았다. MSIX 안에 UIAccess 바이너리를 패키징하고 `RAiLaunchAdminProcess`로 실행하면 **프롬프트 없는 High-IL UIAccess 프로세스**가 생성되었다. Microsoft는 이 경로를 제외함으로써 완화했고, `uiAccess` 제한 MSIX 기능 자체도 이미 관리자 설치를 필요로 한다.

## 공격 흐름 (프롬프트 없는 High IL)
1. **서명된 UIAccess 바이너리**를 확보/생성한다(매니페스트 `uiAccess="true"`).
2. AppInfo의 허용 목록이 받아들이는 위치에 놓거나(또는 위에서 언급한 경로 검증 에지케이스/쓰기 가능한 아티팩트를 악용).
3. `RAiLaunchAdminProcess`를 호출하여 UIAccess와 상승된 IL로 그것을 **조용히** 스폰한다.
4. 그 High-IL 발판에서 **window hooks/DLL injection** 또는 기타 동일 IL 프리미티브를 사용해 데스크톱의 다른 High-IL 프로세스를 표적화하여 관리자 컨텍스트를 완전히 탈취한다.

## 후보 쓰기 가능한 경로 나열
선택한 토큰 관점에서 명목상 안전한 루트 내의 쓰기/덮어쓰기 가능한 객체를 찾기 위해 PowerShell 헬퍼를 실행한다:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 더 넓은 가시성을 위해 Administrator로 실행하세요; 토큰의 접근을 미러링하기 위해 `-ProcessId`를 낮은 권한 프로세스로 설정하세요.
- `RAiLaunchAdminProcess`를 사용하기 전에 후보에서 알려진 금지된 하위 디렉터리를 수동으로 필터링하여 제외하세요.

## 참조
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
