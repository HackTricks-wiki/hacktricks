# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers は、条件が発生したときに Service Control Manager (SCM) が service を開始/停止できるようにします（例: IP address が利用可能になる、named pipe connection が試行される、ETW event が publish される）。対象 service に対する SERVICE_START 権限がなくても、その trigger を発火させることで service を開始できる場合があります。

このページでは、攻撃者向けの enumeration と、一般的な trigger を低い摩擦で発火させる方法に焦点を当てます。

> Tip: 権限のある built-in service（例: RemoteRegistry, WebClient/WebDAV, EFS）を開始すると、新しい RPC/named-pipe listener が露出し、さらなる abuse chain が可能になることがあります。

## Enumerating Service Triggers

- sc.exe (local)
- service の trigger を一覧表示: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers は以下に存在: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 再帰的に dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- `QueryServiceConfig2` を SERVICE_CONFIG_TRIGGER_INFO (8) とともに呼び出して SERVICE_TRIGGER_INFO を取得する。
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM は MS‑SCMR を使ってリモートから問い合わせでき、trigger info を取得できる。TrustedSec の Titanis はこれを公開している: `Scm.exe qtriggers`.
- Impacket は msrpc MS-SCMR に構造体を定義している。これらを使って remote query を実装できる。
- PowerShell (bulk enumeration)
- `TriggerInfo` key を公開している service を素早く列挙:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw の `NtObjectManager` module は、`sc.exe` の出力を解析せずに trigger metadata を扱う `Get-Win32ServiceTrigger` を公開している。

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

これらは、client が IPC endpoint と通信しようとしたときに service を開始します。SCM が client が実際に接続する前に service を自動起動するため、low-priv user に有用です。

- Named pipe trigger
- Behavior: client が `\\.\pipe\<PipeName>` への接続を試みると、SCM は service を開始し、listen を開始できるようにします。
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers は `npsvctrig.sys` によって支えられており、これは登録された trigger pipe name に対する open を監視する filesystem minifilter です。これにより、service 自体が pipe を作成/listen する前でも open attempt だけで service を開始できます。
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Endpoint Mapper (EPM, TCP/135) に対して、service に関連付けられた interface UUID を問い合わせると、SCM は service を開始して endpoint を register できるようにします。
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

service は ETW provider/event に紐づいた trigger を登録できます。追加の filter（keyword/level/binary/string）が設定されていない場合、その provider からの任意の event で service が開始されます。

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 一致する event の発行には通常、その provider に書き込む code が必要です。filter がない場合は、任意の event で十分です。
- provider を発火させる最小限の C 形:
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. 対応する policy が存在する domain-joined host では、trigger は boot 時に実行されます。`gpupdate` だけでは変更がない限り trigger は発火しませんが:

- Activation: `gpupdate /force`
- 関連する policy type が存在する場合、これにより trigger が確実に fire し、service が開始されます。

### IP Address Available

最初の IP が取得されたとき（または最後の IP が失われたとき）に fire します。多くの場合 boot 時に trigger されます。

- Activation: 接続を切り替えて再 trigger する。例:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

一致する device interface が到着したときに service を開始します。data item が指定されていない場合、trigger subtype GUID に一致する任意の device が trigger を fire します。boot 時および hot-plug 時に評価されます。

- Activation: trigger subtype で指定された class/hardware ID に一致する device を接続/挿入する（physical または virtual）。

### Domain Join State

MSDN の記述は紛らわしいですが、これは boot 時に domain state を評価します:
- DOMAIN_JOIN_GUID → domain-joined なら service を開始
- DOMAIN_LEAVE_GUID → domain-joined ではない場合のみ service を開始

### System State Change – WNF (undocumented)

一部の service は undocumented な WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7) を使用します。Activation には関連する WNF state の publish が必要です。詳細は state name に依存します。研究背景: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Windows 11 の一部 service（例: CDPSvc）で観測されています。aggregated configuration は以下に保存されます:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

service の Trigger value は GUID です。その GUID を持つ subkey が aggregated event を定義します。構成要素のいずれかの event を trigger すると service が開始されます。

### Firewall Port Event (quirks and DoS risk)

特定の port/protocol にスコープされた trigger は、指定された port だけでなく、任意の firewall rule change（disable/delete/add）で開始されることが観測されています。さらに悪いことに、protocol なしで port を設定すると、reboot をまたいで BFE の startup が破損し、多数の service failure や firewall management の破壊につながる可能性があります。極めて慎重に扱ってください。

## Practical Workflow

1) Interesting service（RemoteRegistry, WebClient, EFS, …）の trigger を enumerate:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint trigger が存在する場合:
- Named pipe → `\\.\pipe\<PipeName>` への client open を試行
- RPC endpoint → interface UUID に対して Endpoint Mapper lookup を実行

3) ETW trigger が存在する場合:
- `sc.exe qtriggerinfo` で provider と filters を確認。filter がなければ、その provider からの任意の event で service が開始される

4) Group Policy/IP/Device/Domain trigger の場合:
- `gpupdate /force`、NIC の toggle、device の hot-plug など、environmental lever を使用する

## Related

- Named Pipe trigger を使って privileged service を開始した後、それを impersonate できる場合があります:

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

- まず service の start type を `sc.exe qc <Service>` で確認してください。`DISABLED` なら、trigger を fire させるだけでは不十分です。先に configuration を変更する方法を見つける必要があります。
- trigger-start service は idle になると再び停止することがあります。後続の action が短命な listener（RPC/named pipe/WebDAV）に依存するなら、すぐに trigger して consume してください。
- `sc.exe qtriggerinfo` は undocumented な trigger type をすべて正しく理解するわけではありません。新しい Windows build の aggregate trigger では、`HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` で backing GUID と構成要素 event を確認してください。

## Detection and Hardening Notes

- service 全体で TriggerInfo を baseline 化し audit してください。さらに HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents も確認し、aggregate trigger を調べてください。
- 権限のある service UUID に対する suspicious な EPM lookup や、service start に先行する named-pipe connection attempt を監視してください。
- service trigger を変更できるユーザーを制限してください。trigger 変更後に予期しない BFE failure が起きたら suspicious と見なしてください。

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
