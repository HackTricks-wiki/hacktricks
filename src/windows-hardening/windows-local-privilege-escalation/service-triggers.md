# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers 允许 Service Control Manager (SCM) 在某个条件发生时启动/停止服务（例如：IP 地址可用、尝试连接命名管道、发布 ETW 事件）。即使你没有目标服务的 SERVICE_START 权限，也可能通过触发它的 trigger 来启动它。

本页聚焦于对攻击者友好的枚举方法以及低摩擦地激活常见触发器的方法。

> 提示：启动一个有特权的内置服务（例如 RemoteRegistry、WebClient/WebDAV、EFS）可能会暴露新的 RPC/命名管道监听器，并解锁后续滥用链。

## Enumerating Service Triggers

- sc.exe (local)
- 列出服务的 triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers 存放在: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 递归导出: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- 调用 QueryServiceConfig2 并使用 SERVICE_CONFIG_TRIGGER_INFO (8) 来检索 SERVICE_TRIGGER_INFO。
- 文档: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- 可以通过 MS‑SCMR 远程查询 SCM 以获取 trigger 信息。TrustedSec 的 Titanis 提供了此功能：`Scm.exe qtriggers`。
- Impacket 在 msrpc MS-SCMR 中定义了结构；你可以使用这些结构实现远程查询。

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

当客户端尝试与 IPC 端点通信时，这些触发器会启动服务。对低权限用户很有用，因为 SCM 会在你的客户端真正连接之前自动启动服务。

- Named pipe trigger
- 行为：对 \\.\pipe\<PipeName> 的客户端连接尝试会导致 SCM 启动该服务，以便它可以开始监听。
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- 另见：Named Pipe Client Impersonation，用于服务启动后的滥用。

- RPC endpoint trigger (Endpoint Mapper)
- 行为：对与某服务关联的 interface UUID 查询 Endpoint Mapper (EPM, TCP/135) 会导致 SCM 启动该服务，以便它可以注册其端点。
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

服务可以注册绑定到 ETW provider/事件 的触发器。如果没有配置额外的过滤条件（keyword/level/binary/string），来自该 provider 的任何事件都会启动服务。

- 示例（WebClient/WebDAV）：provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- 列出触发器: `sc.exe qtriggerinfo webclient`
- 验证 provider 是否已注册: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- 触发匹配事件通常需要记录到该 provider 的代码；如果没有过滤器，任何事件都足够。

### Group Policy Triggers

子类型：Machine/User。在域加入的主机上，如果存在相应的策略，触发器会在启动时运行。单纯运行 `gpupdate` 并不会在没有更改的情况下触发，但：

- Activation: `gpupdate /force`
- 如果存在相关的策略类型，这通常会可靠地触发并启动服务。

### IP Address Available

在获取第一个 IP（或丢失最后一个 IP）时触发。通常在启动时触发。

- Activation: 切换连接以重新触发，例如：
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

当匹配的设备接口到达时启动服务。如果未指定数据项，任何匹配触发器子类型 GUID 的设备都会触发。该触发器在启动时以及热插拔时评估。

- Activation: 连接/插入一个与触发器子类型指定的 class/hardware ID 匹配的设备（物理或虚拟）。

### Domain Join State

尽管 MSDN 的措辞有些混淆，这在启动时评估域状态：
- DOMAIN_JOIN_GUID → 如果已域加入则启动服务
- DOMAIN_LEAVE_GUID → 仅在未域加入时启动服务

### System State Change – WNF (undocumented)

一些服务使用基于 WNF 的未记录触发器（SERVICE_TRIGGER_TYPE 0x7）。激活需要发布相应的 WNF 状态；细节取决于状态名称。研究背景：Windows Notification Facility 内部机制。

### Aggregate Service Triggers (undocumented)

在 Windows 11 上对某些服务（例如 CDPSvc）观察到的聚合配置存储在：

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

服务的 Trigger 值是一个 GUID；该 GUID 的子项定义了聚合事件。触发任一组成事件会启动服务。

### Firewall Port Event (quirks and DoS risk)

针对特定端口/协议作用域的触发器已被观察到在任何防火墙规则更改（禁用/删除/添加）时启动，而不只是指定端口。更糟的是，为端口配置但不指定协议可能会破坏 BFE 在重启时的启动，导致级联的服务失败并破坏防火墙管理。对此务必极其小心。

## Practical Workflow

1) 枚举感兴趣服务的触发器（RemoteRegistry、WebClient、EFS 等）：
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) 如果存在 Network Endpoint trigger：
- Named pipe → 尝试对 \\.\pipe\<PipeName> 进行客户端打开
- RPC endpoint → 对接口 UUID 执行 Endpoint Mapper 查找

3) 如果存在 ETW trigger：
- 使用 `sc.exe qtriggerinfo` 检查 provider 和过滤器；如果没有过滤器，来自该 provider 的任何事件都会启动服务

4) 对于 Group Policy/IP/Device/Domain triggers：
- 使用环境手段：`gpupdate /force`、切换 NIC、热插拔设备等。

## Related

- 在通过 Named Pipe trigger 启动有特权的服务后，你可能能够对其进行模拟：

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- 列出触发器（本地）： `sc.exe qtriggerinfo <Service>`
- Registry 查看： `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC 远程（Titanis）： `Scm.exe qtriggers`
- ETW provider 检查（WebClient）： `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Detection and Hardening Notes

- 对服务的 TriggerInfo 进行基线和审计。还要检查 HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents 以查看聚合触发器。
- 监控针对特权服务 UUID 的可疑 EPM 查找以及在服务启动之前的命名管道连接尝试。
- 限制谁可以修改服务触发器；在触发器更改后遇到意外的 BFE 故障应视为可疑。

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
