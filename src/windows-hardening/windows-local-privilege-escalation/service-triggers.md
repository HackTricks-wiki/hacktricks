# Windows Service Triggers：枚举与滥用

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers 允许 Service Control Manager（SCM）在某个条件发生时启动或停止服务（例如 IP 地址变为可用、尝试连接 named pipe、发布 ETW event）。即使你没有目标服务的 SERVICE_START 权限，仍可能通过触发其 trigger 来启动它。<sup>[[1]](#references)</sup>

本页面重点介绍便于攻击者进行的枚举，以及激活常见 trigger 的低摩擦方法。

> Tip：启动特权内置服务（例如 RemoteRegistry、WebClient/WebDAV、EFS）可能会暴露新的 RPC/named-pipe 监听器，并为后续 abuse chains 提供入口。

## 枚举 Service Triggers

- sc.exe（本地）
- 列出服务的 triggers：`sc.exe qtriggerinfo <ServiceName>`
- Registry（本地）
- Triggers 位于：`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 递归导出：`reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API（本地）
- 调用 QueryServiceConfig2 并传入 SERVICE_CONFIG_TRIGGER_INFO (8)，以获取 SERVICE_TRIGGER_INFO。
- 文档：QueryServiceConfig2[W/A] 和 SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- 通过 MS-SCMR 的 RPC（远程）
- 可以远程查询 SCM，以获取 trigger 信息。TrustedSec 的 Titanis 提供了此功能：`Scm.exe qtriggers`。
- Impacket 在 msrpc MS-SCMR 中定义了相关 structures；你可以使用这些 structures 实现远程查询。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell（批量枚举）
- 快速列出所有暴露 `TriggerInfo` key 的服务：
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell（编程方式）
- James Forshaw 的 `NtObjectManager` module 提供了 `Get-Win32ServiceTrigger`，可用于解析 trigger metadata，而无需抓取 `sc.exe` 输出。

## 高价值 Trigger 类型及其激活方式

### Network Endpoint Triggers

当 client 尝试与 IPC endpoint 通信时，这些 trigger 会启动服务。它们对 low-priv user 很有用，因为 SCM 会在 client 实际连接之前自动启动服务。<sup>[[1]](#references)</sup>

- Named pipe trigger
- 行为：client 尝试连接 `\\.\pipe\<PipeName>` 时，SCM 会启动服务，使其开始监听。
- 激活（PowerShell）：
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note：named-pipe triggers 由 `npsvctrig.sys` 提供支持，这是一个 filesystem minifilter，用于监视针对已注册 trigger pipe names 的 opens。这就是为什么即使服务本身尚未创建或监听该 pipe，open attempt 也能启动服务。<sup>[[5]](#references)</sup>
- 另请参阅：Named Pipe Client Impersonation，用于 post-start abuse。

- RPC endpoint trigger（Endpoint Mapper）
- 行为：向 Endpoint Mapper（EPM，TCP/135）查询与某服务关联的 interface UUID，会使 SCM 启动该服务，以便其注册 endpoint。
- 激活（Impacket）：
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

服务可以注册绑定到 ETW provider/event 的 trigger。如果未配置其他 filters（keyword/level/binary/string），该 provider 的任何 event 都会启动服务。<sup>[[1]](#references)</sup>

- 示例（WebClient/WebDAV）：provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- 列出 trigger：`sc.exe qtriggerinfo webclient`
- 验证 provider 是否已注册：`logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 生成匹配 events 通常需要向该 provider 记录日志的 code；如果不存在 filters，任何 event 都足够。
- 在未配置其他 ETW filters 时，用于触发该 provider 的最小 C 结构：
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

子类型：Machine/User。在存在对应 policy 的 domain-joined hosts 上，该 trigger 会在 boot 时运行。单独执行 `gpupdate` 不会在没有 changes 的情况下触发，但：<sup>[[1]](#references)</sup>

- 激活：`gpupdate /force`
- 如果存在相关 policy type，这会可靠地触发 trigger 并启动服务。

### IP Address Available

在获取第一个 IP（或丢失最后一个 IP）时触发。通常会在 boot 时触发。<sup>[[1]](#references)</sup>

- 激活：切换 connectivity 以重新触发，例如：
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

当匹配的 device interface 到达时启动服务。如果未指定 data item，则任何匹配 trigger subtype GUID 的 device 都会触发该 trigger。在 boot 时以及 hot-plug 时进行评估。<sup>[[1]](#references)</sup>

- 激活：连接/插入与 trigger subtype 中指定的 class/hardware ID 匹配的 device（physical 或 virtual）。

### Domain Join State

尽管 MSDN 的措辞容易造成混淆，但此 trigger 会在 boot 时评估 domain state：<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → 如果已 domain-joined，则启动服务
- DOMAIN_LEAVE_GUID → 仅当未 domain-joined 时启动服务

### System State Change – WNF（undocumented）

某些服务使用基于 undocumented WNF 的 triggers（SERVICE_TRIGGER_TYPE 0x7）。激活需要发布相关 WNF state；具体细节取决于 state name。研究背景：Windows Notification Facility internals。

### Aggregate Service Triggers（undocumented）

在 Windows 11 上，已观察到某些服务使用此类 triggers（例如 CDPSvc）。聚合配置存储于：

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

某个服务的 Trigger value 是一个 GUID；包含该 GUID 的 subkey 定义了 aggregated event。触发任意 constituent event 都会启动服务。<sup>[[1]](#references)</sup>

### Firewall Port Event（quirks 和 DoS risk）

据观察，作用域限定为特定 port/protocol 的 trigger 会在任何 firewall rule change（disable/delete/add）时启动，而不仅仅是在指定 port 发生变化时。更严重的是，在未指定 protocol 的情况下配置 port 可能会破坏 BFE 在 reboot 时的启动过程，进而导致许多服务故障并破坏 firewall management。务必极其谨慎。<sup>[[1]](#references)</sup>

## Practical Workflow

1) 枚举感兴趣服务（RemoteRegistry、WebClient、EFS、……）上的 triggers：
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) 如果存在 Network Endpoint trigger：
- Named pipe → 尝试对 `\\.\pipe\<PipeName>` 执行 client open
- RPC endpoint → 针对 interface UUID 执行 Endpoint Mapper lookup

3) 如果存在 ETW trigger：
- 使用 `sc.exe qtriggerinfo` 检查 provider 和 filters；如果没有 filters，该 provider 的任何 event 都会启动服务

4) 对于 Group Policy/IP/Device/Domain triggers：
- 使用环境层面的 levers：`gpupdate /force`、切换 NIC、hot-plug devices 等。

## Related

- 通过 Named Pipe trigger 启动特权服务后，你可能能够 impersonate 它：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- 列出 triggers（本地）：`sc.exe qtriggerinfo <Service>`
- Registry view：`reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API：`QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote（Titanis）：`Scm.exe qtriggers`
- ETW provider check（WebClient）：`logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- 首先使用 `sc.exe qc <Service>` 检查服务的 start type。如果是 `DISABLED`，触发 trigger 并不足够；你必须先找到修改 configuration 的方法。
- Trigger-start services 在变为空闲后可能再次停止。如果后续 action 依赖短生命周期的 listener（RPC/named pipe/WebDAV），应立即 trigger 并 consume。
- `sc.exe qtriggerinfo` 无法完全理解每一种 undocumented trigger type。对于较新 Windows builds 上的 aggregate triggers，应在 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` 中确认 backing GUID 和 constituent events。

## Detection and Hardening Notes

- 对各服务的 TriggerInfo 建立 baseline 并进行 audit。同时检查 `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` 中的 aggregate triggers。
- 监控针对特权服务 UUID 的可疑 EPM lookups，以及发生在服务启动之前的 named-pipe connection attempts。
- 限制可修改 service triggers 的人员；trigger changes 后出现意外的 BFE failures 应视为可疑行为。

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
