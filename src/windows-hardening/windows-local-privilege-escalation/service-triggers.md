# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers는 Service Control Manager(SCM)가 특정 조건이 발생했을 때(예: IP 주소가 사용 가능해짐, named pipe 연결 시도, ETW 이벤트 게시 등) 서비스를 시작/중지할 수 있게 합니다. 대상 서비스에 대해 SERVICE_START 권한이 없더라도 트리거가 발동하도록 유도하면 서비스를 시작할 수 있습니다.

이 페이지는 공격자에게 유리한 열거 방법과 일반적인 트리거를 활성화하는 낮은 마찰의 방법들에 중점을 둡니다.

> Tip: 권한이 높은 빌트인 서비스(예: RemoteRegistry, WebClient/WebDAV, EFS)를 시작하면 새로운 RPC/named-pipe 리스너가 노출되어 추가적인 악용 체인이 열릴 수 있습니다.

## Enumerating Service Triggers

- sc.exe (local)
- 서비스의 트리거 나열: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- 트리거는 다음에 위치: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 재귀 덤프: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8)를 사용하여 QueryServiceConfig2를 호출하면 SERVICE_TRIGGER_INFO를 가져옵니다.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM은 원격으로 쿼리하여 트리거 정보를 가져올 수 있습니다. TrustedSec의 Titanis는 이를 노출합니다: `Scm.exe qtriggers`.
- Impacket은 msrpc MS-SCMR의 구조체를 정의합니다; 이를 이용해 원격 쿼리를 구현할 수 있습니다.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

클라이언트가 IPC 엔드포인트에 접속을 시도할 때 서비스를 시작합니다. 낮은 권한 사용자가 유용한 이유는 SCM이 클라이언트가 실제로 연결하기 전에 자동으로 서비스를 시작해주기 때문입니다.

- Named pipe trigger
- 동작: 클라이언트가 \\.\pipe\<PipeName>에 연결을 시도하면, SCM이 해당 서비스가 리스닝을 시작할 수 있도록 서비스를 시작합니다.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- 참고: Named Pipe Client Impersonation은 서비스 시작 후 악용에 유용합니다.

- RPC endpoint trigger (Endpoint Mapper)
- 동작: 서비스에 연결된 인터페이스 UUID에 대해 Endpoint Mapper(EPM, TCP/135)를 조회하면, SCM이 해당 서비스가 자신의 엔드포인트를 등록할 수 있도록 서비스를 시작합니다.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

서비스는 ETW provider/event에 바인딩된 트리거를 등록할 수 있습니다. 추가적인 필터(keyword/level/binary/string)가 설정되어 있지 않다면, 해당 provider의 어떤 이벤트든 서비스 시작을 유발할 수 있습니다.

- 예시 (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- 트리거 나열: `sc.exe qtriggerinfo webclient`
- provider가 등록되어 있는지 확인: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 일치하는 이벤트를 발생시키려면 일반적으로 해당 provider에 로깅하는 코드가 필요합니다; 필터가 없다면 어떤 이벤트든 충분합니다.

### Group Policy Triggers

하위 유형: Machine/User. 도메인 가입된 호스트에서 해당 정책이 존재하면 트리거는 부팅 시 실행됩니다. 단순히 `gpupdate`만으로는 변경이 없으면 트리거가 발동하지 않습니다. 하지만:

- Activation: `gpupdate /force`
- 관련 정책 유형이 존재하면, 이것으로 트리거가 신뢰성 있게 발동하여 서비스를 시작시킵니다.

### IP Address Available

첫 번째 IP가 얻어졌을 때(또는 마지막이 사라졌을 때) 발동합니다. 부팅 시 자주 트리거됩니다.

- Activation: 연결을 토글하여 재발동시키기, 예:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

일치하는 device interface가 도착하면 서비스를 시작합니다. 데이터 아이템이 지정되지 않은 경우 트리거 서브타입 GUID와 일치하는 어떤 장치도 트리거를 발동시킬 수 있습니다. 부팅 시와 핫플러그 시에 평가됩니다.

- Activation: 트리거 서브타입에 지정된 클래스/하드웨어 ID와 일치하는 장치(물리적 또는 가상)를 연결/삽입합니다.

### Domain Join State

MSDN의 혼란스러운 문구에도 불구하고, 이는 부팅 시 도메인 상태를 평가합니다:
- DOMAIN_JOIN_GUID → 도메인에 가입되어 있으면 서비스를 시작
- DOMAIN_LEAVE_GUID → 도메인에 가입되어 있지 않을 때만 서비스를 시작

### System State Change – WNF (undocumented)

일부 서비스는 문서화되지 않은 WNF 기반 트리거(SERVICE_TRIGGER_TYPE 0x7)를 사용합니다. 활성화하려면 관련 WNF 상태를 publish해야 하며, 구체사항은 상태 이름에 따라 다릅니다. 연구 배경: Windows Notification Facility 내부 동작.

### Aggregate Service Triggers (undocumented)

Windows 11의 일부 서비스(예: CDPSvc)에서 관찰됩니다. 집계된 구성은 다음에 저장됩니다:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

서비스의 Trigger 값은 GUID이고, 해당 GUID를 가진 서브키가 집계된 이벤트를 정의합니다. 구성요소 이벤트 중 어느 하나라도 트리거되면 서비스가 시작됩니다.

### Firewall Port Event (quirks and DoS risk)

특정 포트/프로토콜에 범위가 정해진 트리거가 관찰된 바에 따르면, 실제 지정된 포트 변경뿐만 아니라 방화벽 규칙의 아무 변경(비활성화/삭제/추가)에도 시작될 수 있습니다. 더 악화되는 경우, 프로토콜 없이 포트를 구성하면 재부팅 시 BFE 시작이 손상되어 연쇄적으로 많은 서비스가 실패하고 방화벽 관리가 망가질 수 있습니다. 극도로 주의해서 다루십시오.

## Practical Workflow

1) 흥미로운 서비스(RemoteRegistry, WebClient, EFS, …)의 트리거를 열거합니다:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint 트리거가 있는 경우:
- Named pipe → \\.\pipe\<PipeName>에 대한 클라이언트 오픈 시도
- RPC endpoint → 인터페이스 UUID에 대해 Endpoint Mapper 조회 수행

3) ETW 트리거가 있는 경우:
- `sc.exe qtriggerinfo`로 provider 및 필터를 확인; 필터가 없으면 해당 provider의 어떤 이벤트라도 서비스를 시작합니다

4) Group Policy/IP/Device/Domain 트리거의 경우:
- 환경을 이용한 조작: `gpupdate /force`, NIC 토글, 장치 핫플러그 등

## Related

- Named Pipe 트리거를 통해 권한 높은 서비스를 시작한 후에는 해당 서비스를 임퍼슨네이션할 수 있을 수 있습니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Detection and Hardening Notes

- 서비스 전반에서 TriggerInfo의 베이스라인을 만들고 감사하십시오. 또한 집계 트리거는 HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents를 검토하십시오.
- 권한이 높은 서비스 UUID에 대한 의심스러운 EPM 조회 및 서비스 시작에 앞선 named-pipe 연결 시도를 모니터링하십시오.
- 누가 서비스 트리거를 수정할 수 있는지 제한하십시오; 트리거 변경 후 예기치 않은 BFE 실패는 의심스러운 징후로 취급하십시오.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
