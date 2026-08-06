# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers により、条件が発生したとき（例: IP アドレスが利用可能になる、named pipe への接続が試行される、ETW event が公開されるなど）に Service Control Manager (SCM) が service を start/stop できます。対象 service に対する SERVICE_START 権限がない場合でも、trigger を発火させることで service を start できる可能性があります。<sup>[[1]](#references)</sup>

このページでは、attacker にとって有用な enumeration と、一般的な trigger を簡単に activate する方法に焦点を当てます。

> Tip: 特権を持つ組み込み service（例: RemoteRegistry、WebClient/WebDAV、EFS）を start すると、新しい RPC/named-pipe listener が公開され、さらなる abuse chain が可能になる場合があります。

## Enumerating Service Triggers

- sc.exe (local)
- service の trigger を一覧表示: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers は次の場所にあります: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 再帰的に dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8) を指定して QueryServiceConfig2 を呼び出し、SERVICE_TRIGGER_INFO を取得します。
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC over MS-SCMR (remote)
- SCM は MS-SCMR を使用して remote から query し、trigger info を取得できます。TrustedSec の Titanis はこれを公開しています: `Scm.exe qtriggers`
- Impacket は msrpc MS-SCMR 内でこれらの structures を定義しています。それらを使用して remote query を実装できます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- `TriggerInfo` key を公開しているすべての service をすばやく一覧表示:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw の `NtObjectManager` module は、`sc.exe` output を scraping せずに trigger metadata を parse する `Get-Win32ServiceTrigger` を公開しています。

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

これらは client が IPC endpoint との通信を試みたときに service を start します。client が実際に connect する前に SCM が service を auto-start するため、low-priv user にとって有用です。<sup>[[1]](#references)</sup>

- Named pipe trigger
- Behavior: `\\.\pipe\<PipeName>` への client connection attempt により、SCM が service を start し、service が listening を開始できるようにします。
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe trigger は `npsvctrig.sys` によって処理されます。これは登録済みの trigger pipe name に対する open を監視する filesystem minifilter です。そのため、service 自体が pipe を作成して listening を開始する前でも、open attempt によって service を start できます。<sup>[[5]](#references)</sup>
- See also: post-start abuse のための Named Pipe Client Impersonation。

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: service に関連付けられた interface UUID を Endpoint Mapper (EPM、TCP/135) に query すると、SCM が service を start し、endpoint を register できるようにします。
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

service は ETW provider/event に bind された trigger を register できます。追加の filter（keyword/level/binary/string）が設定されていない場合、その provider からの任意の event によって service が start します。<sup>[[1]](#references)</sup>

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- matching event の emit には通常、その provider に log する code が必要です。filter がない場合は、どの event でも十分です。
- Minimal C shape for firing the provider (when no additional ETW filters are configured):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtype: Machine/User。domain-joined host 上で対応する policy が存在する場合、trigger は boot 時に実行されます。`gpupdate` だけでは変更がなければ trigger されませんが、次の方法があります。<sup>[[1]](#references)</sup>

- Activation: `gpupdate /force`
- 該当する policy type が存在する場合、これにより確実に trigger が発火し、service が start します。

### IP Address Available

最初の IP が取得されたとき（または最後の IP が失われたとき）に発火します。多くの場合、boot 時に trigger されます。<sup>[[1]](#references)</sup>

- Activation: 次のように connectivity を toggle して再度 trigger します:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

一致する device interface が到着したときに service を start します。data item が指定されていない場合、trigger subtype GUID に一致する任意の device によって trigger が発火します。boot 時および hot-plug 時に評価されます。<sup>[[1]](#references)</sup>

- Activation: trigger subtype で指定された class/hardware ID に一致する device（physical または virtual）を attach/insert します。

### Domain Join State

紛らわしい MSDN の記述とは異なり、これは boot 時の domain state を評価します。<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → domain-joined の場合に service を start
- DOMAIN_LEAVE_GUID → domain-joined ではない場合にのみ service を start

### System State Change – WNF (undocumented)

一部の service は、undocumented の WNF-based trigger（SERVICE_TRIGGER_TYPE 0x7）を使用します。activation には該当する WNF state の publish が必要です。詳細は state name に依存します。Research background: Windows Notification Facility internals。

### Aggregate Service Triggers (undocumented)

Windows 11 で一部の service（例: CDPSvc）に対して確認されています。aggregated configuration は次の場所に保存されます。

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

service の Trigger value は GUID です。その GUID を持つ subkey が aggregated event を定義します。構成要素となる event のいずれかを trigger すると、service が start します。<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

特定の port/protocol を対象とする trigger は、指定された port だけでなく、任意の firewall rule change（disable/delete/add）で start することが確認されています。さらに、protocol なしで port を設定すると、reboot 後の BFE startup が破損し、多数の service failure を引き起こして firewall management を停止させる可能性があります。十分に注意して扱ってください。<sup>[[1]](#references)</sup>

## Practical Workflow

1) 興味のある service（RemoteRegistry、WebClient、EFS、…）の trigger を enumeration:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint trigger が存在する場合:
- Named pipe → `\\.\pipe\<PipeName>` に対して client open を試行
- RPC endpoint → interface UUID に対して Endpoint Mapper lookup を実行

3) ETW trigger が存在する場合:
- `sc.exe qtriggerinfo` で provider と filter を確認。filter がない場合、その provider からの任意の event により service が start します

4) Group Policy/IP/Device/Domain trigger の場合:
- `gpupdate /force`、NIC の toggle、device の hot-plug など、environmental lever を使用

## Related

- Named Pipe trigger によって privileged service を start した後、その service を impersonate できる可能性があります:

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

- 最初に `sc.exe qc <Service>` で service start type を確認してください。`DISABLED` の場合、trigger を発火させるだけでは不十分であり、まず configuration を変更する方法を見つける必要があります。
- Trigger-start service は idle になると再び stop する場合があります。後続 action が短時間だけ存在する listener（RPC/named pipe/WebDAV）に依存する場合は、trigger と consume を直ちに行ってください。
- `sc.exe qtriggerinfo` は、すべての undocumented trigger type を完全には理解しません。新しい Windows build の aggregate trigger では、`HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` にある backing GUID と構成要素の event を確認してください。

## Detection and Hardening Notes

- service 全体の TriggerInfo を baseline 化して audit してください。また、aggregate trigger については `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` も確認してください。
- privileged service UUID に対する不審な EPM lookup と、service start に先行する named-pipe connection attempt を monitor してください。
- service trigger を modify できるユーザーを制限してください。trigger 変更後に発生する予期しない BFE failure は suspicious なものとして扱ってください。

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
