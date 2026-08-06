# Windows Service Triggers: 열거 및 악용

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers를 사용하면 조건이 발생했을 때(예: IP 주소를 사용할 수 있게 되거나, named pipe 연결이 시도되거나, ETW event가 게시될 때) Service Control Manager(SCM)가 service를 시작하거나 중지할 수 있습니다. 대상 service에 대한 SERVICE_START 권한이 없더라도 trigger를 발생시켜 해당 service를 시작할 수 있는 경우가 있습니다.<sup>[[1]](#references)</sup>

이 페이지에서는 attacker에게 유용한 열거 방법과 일반적인 trigger를 활성화하는 간단한 방법을 중점적으로 다룹니다.

> Tip: 권한이 높은 기본 제공 service(예: RemoteRegistry, WebClient/WebDAV, EFS)를 시작하면 새로운 RPC/named-pipe listener가 노출되고 추가적인 abuse chain을 사용할 수 있습니다.

## Service Trigger 열거

- sc.exe (local)
- service의 trigger 나열: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger는 다음 위치에 저장됩니다: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 재귀적으로 dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8)를 사용해 QueryServiceConfig2를 호출하여 SERVICE_TRIGGER_INFO를 가져옵니다.
- Docs: QueryServiceConfig2[W/A] 및 SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- MS-SCMR을 통한 RPC (remote)
- SCM은 MS-SCMR을 사용해 원격으로 query하여 trigger 정보를 가져올 수 있습니다. TrustedSec의 Titanis는 이를 `Scm.exe qtriggers`로 제공합니다.
- Impacket은 msrpc MS-SCMR에 해당 구조체를 정의하고 있으므로 이를 사용해 remote query를 구현할 수 있습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- `TriggerInfo` key를 노출하는 모든 service를 빠르게 나열:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw의 `NtObjectManager` module은 `sc.exe` output을 scrape하지 않고 trigger metadata를 parse하는 `Get-Win32ServiceTrigger`를 제공합니다.

## 주요 Trigger 유형 및 활성화 방법

### Network Endpoint Trigger

client가 IPC endpoint와 통신하려고 할 때 service를 시작합니다. 실제로 client가 연결되기 전에 SCM이 service를 자동으로 시작하므로 low-priv user에게 유용합니다.<sup>[[1]](#references)</sup>

- Named pipe trigger
- 동작: \\.\pipe\<PipeName>에 대한 client connection attempt가 발생하면 SCM이 service를 시작하여 listening을 시작할 수 있도록 합니다.
- 활성화 (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals 참고: named-pipe trigger는 등록된 trigger pipe name에 대한 open을 감시하는 filesystem minifilter인 `npsvctrig.sys`를 기반으로 합니다. 따라서 service 자체가 pipe를 생성하거나 listening하기 전에도 open attempt만으로 service를 시작할 수 있습니다.<sup>[[5]](#references)</sup>
- 참고: 시작 후 abuse를 위해 Named Pipe Client Impersonation을 사용할 수 있습니다.

- RPC endpoint trigger (Endpoint Mapper)
- 동작: service와 연결된 interface UUID를 Endpoint Mapper(EPM, TCP/135)에 query하면 SCM이 service를 시작하여 endpoint를 등록할 수 있도록 합니다.
- 활성화 (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Trigger

service는 ETW provider/event에 연결된 trigger를 등록할 수 있습니다. 추가 filter(keyword/level/binary/string)가 설정되지 않은 경우 해당 provider의 모든 event가 service를 시작합니다.<sup>[[1]](#references)</sup>

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Trigger 나열: `sc.exe qtriggerinfo webclient`
- Provider 등록 여부 확인: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 일치하는 event를 emit하려면 일반적으로 해당 provider에 log를 기록하는 code가 필요합니다. filter가 없다면 어떤 event든 충분합니다.
- provider를 fire하기 위한 최소 C 형태(추가 ETW filter가 설정되지 않은 경우):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Trigger

Subtype: Machine/User. domain-joined host에서 해당 policy가 존재하는 경우 trigger는 boot 시 실행됩니다. 변경 사항이 없으면 `gpupdate`만으로는 trigger가 실행되지 않지만:<sup>[[1]](#references)</sup>

- 활성화: `gpupdate /force`
- 관련 policy type이 존재하면 trigger가 안정적으로 실행되어 service가 시작됩니다.

### IP Address Available

첫 번째 IP를 획득하거나 마지막 IP를 잃을 때 실행됩니다. boot 시 실행되는 경우가 많습니다.<sup>[[1]](#references)</sup>

- 활성화: 다음과 같이 connectivity를 toggle하여 다시 실행:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

일치하는 device interface가 도착하면 service를 시작합니다. data item이 지정되지 않은 경우 trigger subtype GUID와 일치하는 모든 device가 trigger를 실행합니다. boot 시 및 hot-plug 시 평가됩니다.<sup>[[1]](#references)</sup>

- 활성화: trigger subtype에 지정된 class/hardware ID와 일치하는 device(physical 또는 virtual)를 연결하거나 삽입합니다.

### Domain Join State

혼동을 일으키는 MSDN 문구와 달리, boot 시 domain state를 평가합니다:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → domain-joined 상태이면 service 시작
- DOMAIN_LEAVE_GUID → domain-joined 상태가 아닌 경우에만 service 시작

### System State Change – WNF (undocumented)

일부 service는 undocumented WNF 기반 trigger(SERVICE_TRIGGER_TYPE 0x7)를 사용합니다. 활성화하려면 관련 WNF state를 publish해야 하며, 구체적인 방법은 state name에 따라 달라집니다. Research background: Windows Notification Facility internals.

### Aggregate Service Trigger (undocumented)

Windows 11의 일부 service(예: CDPSvc)에서 관찰됩니다. aggregated configuration은 다음 위치에 저장됩니다:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

service의 Trigger value는 GUID이며, 해당 GUID를 가진 subkey가 aggregated event를 정의합니다. 구성 요소 event 중 하나라도 trigger하면 service가 시작됩니다.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

특정 port/protocol로 범위가 지정된 trigger가 해당 port에서만이 아니라 모든 firewall rule 변경(disable/delete/add) 시 시작되는 것이 관찰되었습니다. 더 심각한 문제로, protocol 없이 port를 구성하면 reboot 이후 BFE startup이 손상될 수 있으며, 이로 인해 다수의 service failure가 연쇄적으로 발생하고 firewall management가 중단됩니다. 각별히 주의하여 사용해야 합니다.<sup>[[1]](#references)</sup>

## Practical Workflow

1) 관심 있는 service(RemoteRegistry, WebClient, EFS, …)의 trigger 열거:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint trigger가 존재하는 경우:
- Named pipe → \\.\pipe\<PipeName>에 대한 client open 시도
- RPC endpoint → interface UUID에 대한 Endpoint Mapper lookup 수행

3) ETW trigger가 존재하는 경우:
- `sc.exe qtriggerinfo`로 provider와 filter 확인. filter가 없으면 해당 provider의 모든 event가 service를 시작합니다.

4) Group Policy/IP/Device/Domain trigger의 경우:
- 환경적 수단 사용: `gpupdate /force`, NIC toggle, device hot-plug 등

## Related

- Named Pipe trigger를 통해 권한이 높은 service를 시작한 후 해당 service를 impersonate할 수 있습니다:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Trigger 나열(local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider 확인(WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- 먼저 `sc.exe qc <Service>`로 service start type을 확인합니다. `DISABLED`인 경우 trigger를 실행하는 것만으로는 충분하지 않으며, 먼저 configuration을 변경할 방법을 찾아야 합니다.
- Trigger-start service는 idle 상태가 되면 다시 중지될 수 있습니다. 후속 작업이 수명이 짧은 listener(RPC/named pipe/WebDAV)에 의존한다면 즉시 trigger하고 consume해야 합니다.
- `sc.exe qtriggerinfo`는 모든 undocumented trigger type을 완전히 이해하지 못합니다. 최신 Windows build의 aggregate trigger의 경우 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`에서 backing GUID와 구성 요소 event를 확인해야 합니다.

## Detection and Hardening Notes

- service 전반의 TriggerInfo를 baseline으로 설정하고 audit합니다. 또한 aggregate trigger를 위해 HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents도 검토합니다.
- 권한이 높은 service UUID에 대한 의심스러운 EPM lookup과 service start 전에 발생하는 named-pipe connection attempt를 monitor합니다.
- service trigger를 수정할 수 있는 사용자를 제한합니다. trigger 변경 후 예상치 못한 BFE failure가 발생하면 의심스러운 상황으로 간주합니다.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
