# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers дозволяють Service Control Manager (SCM) запускати/зупиняти сервіс при настанні певної умови (наприклад, коли доступна IP‑адреса, відбувається спроба підключення до іменованої труби, публікується ETW‑подія). Навіть якщо у вас немає прав SERVICE_START на цільовий сервіс, ви все ще можете змусити його запуститися, спричинивши спрацьовування тригера.

Ця сторінка зосереджена на дружній до нападника інструментації та простих способах активувати поширені тригери.

> Tip: Starting a privileged built-in service (e.g., RemoteRegistry, WebClient/WebDAV, EFS) can expose new RPC/named-pipe listeners and unlock further abuse chains.

## Enumerating Service Triggers

- sc.exe (local)
- List a service's triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers live under: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Call QueryServiceConfig2 with SERVICE_CONFIG_TRIGGER_INFO (8) to retrieve SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- The SCM can be queried remotely to fetch trigger info using MS‑SCMR. TrustedSec’s Titanis exposes this: `Scm.exe qtriggers`.
- Impacket defines the structures in msrpc MS-SCMR; you can implement a remote query using those.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Вони запускають сервіс, коли клієнт намагається під’єднатися до IPC‑ендзпоїнта. Корисно для користувачів з невисокими правами, оскільки SCM автозапустить сервіс ще до того, як ваш клієнт зможе фактично встановити з’єднання.

- Named pipe trigger
- Behavior: A client connection attempt to \\.\pipe\<PipeName> causes the SCM to start the service so it can begin listening.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Querying the Endpoint Mapper (EPM, TCP/135) for an interface UUID associated with a service causes the SCM to start it so it can register its endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Сервіс може зареєструвати тригер, прив’язаний до ETW‑провайдера/події. Якщо додаткові фільтри (keyword/level/binary/string) не налаштовані, будь‑яка подія від цього провайдера запустить сервіс.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events typically requires code that logs to that provider; if no filters are present, any event suffices.

### Group Policy Triggers

Підтипи: Machine/User. На хостах, приєднаних до домену, де існує відповідна політика, тригер запускається під час завантаження. `gpupdate` сам по собі не викликає спрацювання без змін, але:

- Activation: `gpupdate /force`
- If the relevant policy type exists, this reliably causes the trigger to fire and start the service.

### IP Address Available

Спрацьовує, коли отримано першу IP‑адресу (або втрачено останню). Часто спрацьовує під час завантаження.

- Activation: Toggle connectivity to retrigger, e.g.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Запускає сервіс при появі пристрою, інтерфейс якого відповідає умовам тригера. Якщо не вказано data item, будь‑який пристрій, що відповідає GUID підтипу тригера, його спровокує. Оцінюється під час завантаження та при hot‑plug.

- Activation: Attach/insert a device (physical or virtual) that matches the class/hardware ID specified by the trigger subtype.

### Domain Join State

Незважаючи на заплутані формулювання MSDN, це перевіряє стан приєднання до домену під час завантаження:
- DOMAIN_JOIN_GUID → start the service if domain-joined
- DOMAIN_LEAVE_GUID → start the service only if NOT domain-joined

### System State Change – WNF (undocumented)

Деякі сервіси використовують недокументовані WNF‑тригери (SERVICE_TRIGGER_TYPE 0x7). Активація потребує публікації відповідного WNF‑стану; деталі залежать від імені стану. Дослідження: внутрішні механізми Windows Notification Facility.

### Aggregate Service Triggers (undocumented)

Спостерігалося у Windows 11 для деяких сервісів (наприклад, CDPSvc). Агрегована конфігурація зберігається в:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Значення Trigger сервісу — це GUID; підключ з цим GUID визначає агрегований event. Спрацювання будь‑якого складового події запускає сервіс.

### Firewall Port Event (quirks and DoS risk)

Тригер, прив’язаний до конкретного порту/протоколу, іноді спрацьовує при будь‑якій зміні правила брандмауера (відключення/видалення/додавання), а не лише по вказаному порту. Гірше: налаштування порту без протоколу може пошкодити запуск BFE через перезавантаження, що спричинить каскадну відмову багатьох сервісів і порушення керування брандмауером. Поводьтеся з крайньою обережністю.

## Practical Workflow

1) Enumerate triggers on interesting services (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) If a Network Endpoint trigger exists:
- Named pipe → attempt a client open to \\.\pipe\<PipeName>
- RPC endpoint → perform an Endpoint Mapper lookup for the interface UUID

3) If an ETW trigger exists:
- Check provider and filters with `sc.exe qtriggerinfo`; if no filters, any event from that provider will start the service

4) For Group Policy/IP/Device/Domain triggers:
- Use environmental levers: `gpupdate /force`, toggle NICs, hot-plug devices, etc.

## Related

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

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

- Baseline and audit TriggerInfo across services. Also review HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents for aggregate triggers.
- Monitor for suspicious EPM lookups for privileged service UUIDs and named-pipe connection attempts that precede service starts.
- Restrict who can modify service triggers; treat unexpected BFE failures after trigger changes as suspicious.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
