# UIAccess를 통한 Admin Protection 우회

{{#include ../../banners/hacktricks-training.md}}

## 개요
- Windows AppInfo는 UIAccess 프로세스(접근성용)를 생성하기 위해 `RAiLaunchAdminProcess`를 노출한다. UIAccess는 대부분의 User Interface Privilege Isolation (UIPI) 메시지 필터링을 우회하여 접근성 소프트웨어가 더 높은 IL의 UI를 조작할 수 있게 한다.
- UIAccess를 직접 활성화하려면 `NtSetInformationToken(TokenUIAccess)`를 **SeTcbPrivilege** 권한과 함께 호출해야 하므로, 낮은 권한 호출자는 서비스에 의존한다. 서비스는 UIAccess를 설정하기 전에 대상 바이너리에 대해 세 가지 검사를 수행한다:
  - 포함된 매니페스트에 `uiAccess="true"`가 존재할 것.
  - Local Machine 루트 스토어에 신뢰된 아무 인증서로 서명되어 있을 것(EKU/Microsoft 요구사항 없음).
  - 시스템 드라이브의 관리자 전용 경로에 위치할 것(예: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, 특정 쓰기 가능한 하위 경로는 제외).
- `RAiLaunchAdminProcess`는 UIAccess 실행에 대해 동의 프롬프트를 표시하지 않는다(그렇지 않으면 접근성 툴링이 프롬프트를 조작할 수 없었을 것).

## 토큰 조형 및 무결성 수준
- 검사가 통과하면 AppInfo는 호출자 토큰을 **복사하고**, UIAccess를 활성화하며, 무결성 수준(IL)을 올린다:
  - 제한된 관리자 사용자(user가 Administrators에 속하지만 필터링된 상태) ➜ **높은 IL**.
  - 비관리자 사용자 ➜ IL을 **+16 레벨**만큼 올리며 **높음(High)** 한도까지 증가(시스템 IL은 절대 할당되지 않음).
- 호출자 토큰에 이미 UIAccess가 있으면 IL은 변경되지 않는다.
- “래칫(ratchet)” 기법: UIAccess 프로세스가 자신에서 UIAccess를 비활성화한 뒤 `RAiLaunchAdminProcess`로 재실행하면 또 다른 +16 IL 증가를 얻을 수 있다. Medium➜High는 255회 재실행이 필요(시끄러움, 하지만 작동).

## UIAccess가 Admin Protection 탈출을 가능하게 하는 이유
- UIAccess는 낮은 IL 프로세스가 더 높은 IL 창으로 윈도우 메시지를 보낼 수 있게 허용하여 UIPI 필터를 우회한다. 같은 IL에서는 `SetWindowsHookEx`와 같은 고전적인 UI 원시 기법이 어떤 창을 소유한 프로세스(예: COM에서 사용하는 메시지 전용 윈도우 포함)라도 코드 인젝션/DLL 로딩을 허용한다.
- Admin Protection은 UIAccess 프로세스를 제한된 사용자 신분으로, 그러나 **높은 IL**로 조용히 실행한다. 그 높은 IL의 UIAccess 프로세스 내부에서 임의 코드가 실행되면, 공격자는 데스크톱의 다른 높은 IL 프로세스(심지어 다른 사용자 소유 프로세스)로 인젝션할 수 있어 의도된 분리를 깨뜨린다.

## 보안 디렉터리 검증 약점 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo는 제공된 경로를 `GetFinalPathNameByHandle`로 해석한 뒤 하드코딩된 루트/제외 항목에 대해 **문자열 허용/거부 검사**를 적용한다. 그 단순한 검증에서 여러 회피 클래스가 발생한다:
- 디렉터리 네임드 스트림(Directory named streams): 제외된 쓰기 가능한 디렉터리(예: `C:\Windows\tracing`)는 디렉터리 자체의 네임드 스트림을 이용해 우회할 수 있다(예: `C:\Windows\tracing:file.exe`). 문자열 검사는 `C:\Windows\`만 보고 제외된 하위 경로를 놓친다.
- 허용된 루트 내부의 쓰기 가능한 파일/디렉터리: `CreateProcessAsUser`는 **`.exe` 확장자를 요구하지 않는다**. 허용된 루트 아래의 아무 쓰기 가능한 파일을 실행 가능한 페이로드로 덮어써도 통과하며, 서명된 `uiAccess="true"` EXE를 쓰기 가능한 하위 디렉터리(예: 존재하는 경우 업데이트 잔여물인 `Tasks_Migrated`)에 복사해도 secure-path 검사를 통과시킬 수 있다.
- MSIX가 `C:\Program Files\WindowsApps`에 들어가는 경우(수정됨): 비관리자는 `WindowsApps`에 서명된 MSIX 패키지를 설치할 수 있었고, 이 경로는 제외되지 않았었다. MSIX에 UIAccess 바이너리를 패키징하고 `RAiLaunchAdminProcess`로 실행하면 프롬프트 없이 높은 IL의 UIAccess 프로세스가 생성되었다. Microsoft는 이 경로를 제외함으로써 완화했으며, `uiAccess` 제한 MSIX 권한 자체는 이미 관리자 설치를 요구한다.

## 공격 워크플로우 (프롬프트 없이 High IL)
1. 서명된 UIAccess 바이너리(매니페스트 `uiAccess="true"`)를 획득/작성한다.
2. AppInfo의 허용 목록이 받아들이는 위치에 배치하거나(또는 위에서 설명한 경로 검증 엣지케이스/쓰기 가능한 아티팩트를 악용한다).
3. `RAiLaunchAdminProcess`를 호출해 UIAccess + 상승된 IL로 **조용히** 실행한다.
4. 그 높은 IL 발판에서, 다른 데스크톱 상의 높은 IL 프로세스를 대상으로 **윈도우 훅/DLL 인젝션** 또는 다른 동일 IL 원시 기법을 사용하여 관리자 컨텍스트를 완전히 탈취한다.

## 후보 쓰기 가능 경로 열거
선택한 토큰 관점에서 명목상 안전한 루트 내의 쓰기/덮어쓰기 가능한 객체를 찾기 위해 PowerShell 헬퍼를 실행한다:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- 관리자 권한으로 실행해 더 넓은 가시성을 확보하세요; `-ProcessId`를 권한이 낮은 프로세스로 설정해 해당 token의 접근 권한을 반영하세요.
- `RAiLaunchAdminProcess`로 후보를 사용하기 전에 알려진 허용되지 않는 하위 디렉터리를 수동으로 필터링해 제외하세요.

## 참고
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
