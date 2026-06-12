# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers는 Service Control Manager (SCM)가 특정 조건이 발생했을 때 서비스의 시작/중지를 하도록 합니다(예: IP address가 사용 가능해짐, named pipe connection 시도, ETW event publish). 대상 서비스에 대해 SERVICE_START 권한이 없더라도, trigger를 발생시켜 서비스를 시작할 수 있을 수 있습니다.

이 페이지는 공격자 친화적인 enumeration과 일반적인 trigger를 낮은 마찰로 활성화하는 방법에 초점을 맞춥니다.

> Tip: 권한이 높은 built-in service(예: RemoteRegistry, WebClient/WebDAV, EFS)를 시작하면 새로운 RPC/named-pipe listener가 열리고 추가 abuse chain이 가능해질 수 있습니다.

## Enumerating Service Triggers

- sc.exe (local)
- 서비스의 trigger 목록 보기: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers는 다음 위치에 있습니다: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 재귀적으로 dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- `SERVICE_CONFIG_TRIGGER_INFO (8)`와 함께 `QueryServiceConfig2`를 호출해 `SERVICE_TRIGGER_INFO`를 가져옵니다.
- Docs: QueryServiceConfig2[W/A] 및 SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM은 MS‑SCMR을 사용해 원격으로 query하여 trigger 정보를 가져올 수 있습니다. TrustedSec의 Titanis가 이를 제공합니다: `Scm.exe qtriggers`.
- Impacket은 msrpc MS-SCMR에 구조체를 정의합니다; 이를 사용해 원격 query를 구현할 수 있습니다.
- PowerShell (bulk enumeration)
- `TriggerInfo` key를 노출하는 모든 서비스를 빠르게 나열:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw의 `NtObjectManager` module은 `sc.exe` 출력 scraping 없이 trigger metadata를 파싱하는 `Get-Win32ServiceTrigger`를 제공합니다.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

이것들은 client가 IPC endpoint와 통신을 시도할 때 서비스를 시작합니다. SCM이 client가 실제로 connect하기 전에 서비스를 자동 시작하므로 low-priv users에게 유용합니다.

- Named pipe trigger
- Behavior: client가 `\\.\pipe\<PipeName>`로 connection을 시도하면 SCM이 서비스를 시작해 listening을 시작하게 합니다.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers는 등록된 trigger pipe name에 대한 open을 감시하는 filesystem minifilter인 `npsvctrig.sys`에 의해 뒷받침됩니다. 이것이 서비스 자체가 pipe를 생성하거나 listen하기 전의 open 시도만으로도 서비스를 시작할 수 있는 이유입니다.
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: 서비스와 연결된 interface UUID에 대해 Endpoint Mapper (EPM, TCP/135)를 query하면 SCM이 이를 시작해 endpoint를 등록하게 합니다.
- Activation (Impacket):
```bash
# 로컬 EPM을 query; 서비스 interface GUID로 UUID를 교체
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

서비스는 ETW provider/event에 바인딩된 trigger를 등록할 수 있습니다. 추가 filter(keyword/level/binary/string)가 없으면, 해당 provider의 어떤 event든 서비스를 시작합니다.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Trigger 목록 보기: `sc.exe qtriggerinfo webclient`
- provider가 등록되었는지 확인: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 일치하는 event를 내보내려면 일반적으로 해당 provider에 log하는 code가 필요합니다; filter가 없으면 어떤 event든 충분합니다.
- provider를 firing하기 위한 최소 C 형태(추가 ETW filter가 설정되지 않은 경우):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. 도메인 가입 호스트에서 해당 policy가 존재하면 trigger는 boot 시 실행됩니다. `gpupdate`만으로는 변경이 없으면 trigger되지 않지만:

- Activation: `gpupdate /force`
- 관련 policy type이 존재하면, 이것이 trigger를 확실하게 발생시켜 서비스를 시작합니다.

### IP Address Available

첫 IP를 얻을 때(또는 마지막 IP를 잃을 때) 실행됩니다. 종종 boot 시 trigger됩니다.

- Activation: 연결을 토글해 다시 trigger, 예:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

일치하는 device interface가 도착하면 서비스를 시작합니다. data item이 지정되지 않으면 trigger subtype GUID와 일치하는 어떤 device든 trigger를 발생시킵니다. boot 시와 hot-plug 시 평가됩니다.

- Activation: trigger subtype에 지정된 class/hardware ID와 일치하는 device를 연결/삽입합니다(physical 또는 virtual).

### Domain Join State

혼동스러운 MSDN wording에도 불구하고, 이것은 boot 시 domain state를 평가합니다:
- DOMAIN_JOIN_GUID → domain-joined이면 서비스를 시작
- DOMAIN_LEAVE_GUID → domain-joined가 **아니면** 서비스를 시작

### System State Change – WNF (undocumented)

일부 서비스는 undocumented WNF-based trigger (SERVICE_TRIGGER_TYPE 0x7)를 사용합니다. 활성화하려면 관련 WNF state를 publish해야 하며, 세부 사항은 state name에 따라 달라집니다. 연구 배경: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Windows 11의 일부 서비스(예: CDPSvc)에서 관찰됩니다. aggregated configuration은 다음에 저장됩니다:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

서비스의 Trigger 값은 GUID입니다; 해당 GUID의 subkey가 aggregated event를 정의합니다. 구성 요소 event 중 하나라도 trigger되면 서비스가 시작됩니다.

### Firewall Port Event (quirks and DoS risk)

특정 port/protocol에 scoped 된 trigger는 지정된 port뿐 아니라 firewall rule 변경(disable/delete/add)만으로도 start되는 것이 관찰되었습니다. 더 심각하게는, protocol 없이 port를 구성하면 재부팅 간 BFE startup이 손상되어 많은 service failure를 연쇄적으로 유발하고 firewall management를 망가뜨릴 수 있습니다. 매우 주의해서 다루세요.

## Practical Workflow

1) 관심 있는 서비스(RemoteRegistry, WebClient, EFS, …)의 trigger를 enumerate:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint trigger가 있으면:
- Named pipe → `\\.\pipe\<PipeName>`에 client open 시도
- RPC endpoint → interface UUID에 대해 Endpoint Mapper lookup 수행

3) ETW trigger가 있으면:
- `sc.exe qtriggerinfo`로 provider와 filter를 확인; filter가 없으면 해당 provider의 어떤 event든 서비스를 시작합니다

4) Group Policy/IP/Device/Domain trigger의 경우:
- 환경적 수단 사용: `gpupdate /force`, NIC 토글, device hot-plug 등

## Related

- Named Pipe trigger를 통해 권한 높은 서비스를 시작한 뒤, 이를 impersonate할 수 있을 수 있습니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- 먼저 `sc.exe qc <Service>`로 service start type을 확인하세요. `DISABLED`이면 trigger를 발생시키는 것만으로는 부족합니다; 먼저 configuration을 변경할 방법을 찾아야 합니다.
- Trigger-start services는 idle 상태가 되면 다시 멈출 수 있습니다. 후속 action이 짧게 살아있는 listener(RPC/named pipe/WebDAV)에 의존한다면, 즉시 trigger하고 consume하세요.
- `sc.exe qtriggerinfo`는 모든 undocumented trigger type을 완전히 이해하지 못합니다. 최신 Windows build의 aggregate trigger는 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`에서 backing GUID와 constituent event를 확인하세요.

## Detection and Hardening Notes

- 서비스 전반의 TriggerInfo를 baseline으로 잡고 audit하세요. 또한 aggregate trigger를 위해 HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents도 검토하세요.
- 권한 높은 service UUID에 대한 수상한 EPM lookup과 service start를 앞서는 named-pipe connection attempt를 모니터링하세요.
- service trigger를 수정할 수 있는 대상을 제한하세요; trigger 변경 후 예상치 못한 BFE failure는 의심 대상으로 보세요.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
