# Windows Service Triggers: 枚举与滥用

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers 允许 Service Control Manager (SCM) 在某个条件发生时启动/停止一个 service（例如，某个 IP address 变为可用、尝试连接某个 named pipe、发布某个 ETW event）。即使你没有目标 service 的 SERVICE_START 权限，你仍然可能通过触发其 trigger 来启动它。

本页重点介绍对 attacker 友好的枚举方式，以及激活常见 trigger 的低摩擦方法。

> Tip: 启动一个特权 built-in service（例如 RemoteRegistry、WebClient/WebDAV、EFS）可以暴露新的 RPC/named-pipe listeners，并解锁进一步的 abuse chains。

## Enumerating Service Triggers

- sc.exe (local)
- 列出某个 service 的 triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers 位于: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 递归 dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- 调用 QueryServiceConfig2 并使用 SERVICE_CONFIG_TRIGGER_INFO (8) 以获取 SERVICE_TRIGGER_INFO。
- Docs: QueryServiceConfig2[W/A] 和 SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- 可以通过 MS‑SCMR 远程查询 SCM 以获取 trigger info。TrustedSec 的 Titanis 提供了这个功能: `Scm.exe qtriggers`.
- Impacket 在 msrpc MS-SCMR 中定义了这些结构；你可以基于它们实现远程查询。
- PowerShell (bulk enumeration)
- 快速列出每个暴露 `TriggerInfo` key 的 service:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw 的 `NtObjectManager` module 提供了 `Get-Win32ServiceTrigger`，可在不抓取 `sc.exe` 输出的情况下解析 trigger metadata。

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

这些会在客户端尝试与某个 IPC endpoint 通信时启动一个 service。对 low-priv users 很有用，因为 SCM 会在你的 client 真正连上之前自动启动该 service。

- Named pipe trigger
- 行为: 客户端尝试连接 `\\.\pipe\<PipeName>` 会导致 SCM 启动该 service，以便它开始监听。
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- 内部说明: named-pipe triggers 由 `npsvctrig.sys` 支持，它是一个 filesystem minifilter，会监视对已注册 trigger pipe names 的打开操作。这就是为什么在 service 本身还没创建/监听该 pipe 之前，open 尝试就能启动它。
- See also: Named Pipe Client Impersonation for post-start abuse。

- RPC endpoint trigger (Endpoint Mapper)
- 行为: 查询 Endpoint Mapper (EPM, TCP/135) 中与某个 service 关联的 interface UUID，会导致 SCM 启动该 service，以便它注册自己的 endpoint。
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

某个 service 可以注册一个绑定到 ETW provider/event 的 trigger。如果没有额外 filters（keyword/level/binary/string），来自该 provider 的任意 event 都会启动该 service。

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 生成匹配 event 通常需要能够向该 provider 写日志的 code；如果没有 filters，任意 event 都足够。
- 在未配置额外 ETW filters 时，用于触发该 provider 的最小 C 形状:
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User。在存在对应 policy 的 domain-joined hosts 上，该 trigger 会在 boot 时运行。`gpupdate` 单独执行不会在没有变化时触发，但：

- Activation: `gpupdate /force`
- 如果相关 policy type 存在，这会可靠地触发 trigger 并启动 service。

### IP Address Available

当获得第一个 IP（或失去最后一个 IP）时触发。通常在 boot 时触发。

- Activation: 切换连接状态以重新触发，例如:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

当匹配的 device interface 到达时启动 service。如果未指定 data item，任何匹配 trigger subtype GUID 的 device 都会触发它。会在 boot 和 hot-plug 时评估。

- Activation: 连接/插入一个与 trigger subtype 指定的 class/hardware ID 匹配的 device（物理或虚拟）。

### Domain Join State

尽管 MSDN 的描述容易让人困惑，这会在 boot 时评估 domain state:
- DOMAIN_JOIN_GUID → 如果 domain-joined，则启动 service
- DOMAIN_LEAVE_GUID → 只有在 NOT domain-joined 时才启动 service

### System State Change – WNF (undocumented)

某些 service 使用未公开的基于 WNF 的 triggers（SERVICE_TRIGGER_TYPE 0x7）。Activation 需要发布相关的 WNF state；具体取决于 state name。研究背景: Windows Notification Facility internals。

### Aggregate Service Triggers (undocumented)

在 Windows 11 上观察到某些 service（例如 CDPSvc）使用这种机制。聚合配置存储在:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

某个 service 的 Trigger value 是一个 GUID；该 GUID 对应的 subkey 定义了聚合 event。触发其中任一 constituent event 都会启动该 service。

### Firewall Port Event (quirks and DoS risk)

观察到某个针对特定 port/protocol 的 trigger 会在任何 firewall rule change（disable/delete/add）时启动，而不仅仅是指定 port。更糟的是，配置 port 时如果不指定 protocol，可能会在多次 reboot 间破坏 BFE startup，连锁导致许多 service failure 并破坏 firewall management。请极度谨慎对待。

## Practical Workflow

1) 枚举感兴趣的 service 上的 triggers（RemoteRegistry、WebClient、EFS、…）:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) 如果存在 Network Endpoint trigger:
- Named pipe → 尝试对 `\\.\pipe\<PipeName>` 执行 client open
- RPC endpoint → 对 interface UUID 执行 Endpoint Mapper lookup

3) 如果存在 ETW trigger:
- 使用 `sc.exe qtriggerinfo` 检查 provider 和 filters；如果没有 filters，来自该 provider 的任意 event 都会启动 service

4) 对于 Group Policy/IP/Device/Domain triggers:
- 使用环境层面的手段：`gpupdate /force`、切换 NIC、热插拔 device 等

## Related

- 通过 Named Pipe trigger 启动特权 service 后，你可能可以冒充它:

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

- 先使用 `sc.exe qc <Service>` 检查 service start type。如果是 `DISABLED`，仅触发 trigger 不够；你必须先找到办法修改 configuration。
- Trigger-start services 在变得 idle 后可能会再次停止。如果你的后续操作依赖一个短生命周期的 listener（RPC/named pipe/WebDAV），请立即触发并消费它。
- `sc.exe qtriggerinfo` 并不能完全理解每一种未公开的 trigger type。对于较新的 Windows build 上的 aggregate triggers，请在 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` 中确认对应的 backing GUID 和 constituent events。

## Detection and Hardening Notes

- 为各个 service 建立基线并审计 TriggerInfo。也要检查 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` 中的 aggregate triggers。
- 监控对特权 service UUID 的可疑 EPM lookup，以及先于 service start 的 named-pipe connection attempts。
- 限制谁可以修改 service triggers；在 trigger changes 之后出现意外的 BFE failure，应视为可疑。

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
