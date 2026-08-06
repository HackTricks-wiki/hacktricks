# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers дозволяють Service Control Manager (SCM) запускати/зупиняти service, коли виникає певна умова (наприклад, стає доступною IP-адреса, здійснюється спроба підключення до named pipe або публікується ETW-подія). Навіть якщо у вас немає прав `SERVICE_START` для цільового service, ви все одно можете запустити його, спричинивши спрацювання його trigger.<sup>[[1]](#references)</sup>

Ця сторінка зосереджена на зручній для attacker enumeration та простих способах активації поширених triggers.

> Порада: запуск привілейованого вбудованого service (наприклад, RemoteRegistry, WebClient/WebDAV, EFS) може відкрити нові RPC/named-pipe listeners і розблокувати подальші ланцюжки abuse.

## Enumerating Service Triggers

- sc.exe (local)
- Перелік triggers service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers зберігаються в: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Рекурсивний dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Викличте QueryServiceConfig2 із SERVICE_CONFIG_TRIGGER_INFO (8), щоб отримати SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] та SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC через MS-SCMR (remote)
- SCM можна опитати remotely, щоб отримати trigger info, використовуючи MS-SCMR. TrustedSec’s Titanis надає цю можливість: `Scm.exe qtriggers`.
- Impacket визначає structures у msrpc MS-SCMR; ви можете реалізувати remote query, використовуючи їх.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- Швидко вивести кожен service, що має ключ `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Модуль `NtObjectManager` від James Forshaw надає `Get-Win32ServiceTrigger` для parsing trigger metadata без scraping виводу `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Вони запускають service, коли client намагається взаємодіяти з IPC endpoint. Це корисно для low-priv users, оскільки SCM автоматично запустить service до того, як ваш client фактично зможе підключитися.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Поведінка: спроба client підключитися до \\.\pipe\<PipeName> змушує SCM запустити service, щоб він почав listening.
- Активація (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Примітка щодо internals: named-pipe triggers підтримуються `npsvctrig.sys` — filesystem minifilter, який відстежує opens до зареєстрованих trigger pipe names. Саме тому спроба open може запустити service ще до того, як service створить pipe або почне listening на ньому.<sup>[[5]](#references)</sup>
- Див. також: Named Pipe Client Impersonation для post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Поведінка: запит до Endpoint Mapper (EPM, TCP/135) для interface UUID, пов’язаного із service, змушує SCM запустити його, щоб він міг зареєструвати свій endpoint.
- Активація (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Service може зареєструвати trigger, прив’язаний до ETW provider/event. Якщо додаткові filters (keyword/level/binary/string) не налаштовані, будь-яка подія від цього provider запустить service.<sup>[[1]](#references)</sup>

- Приклад (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Перелік trigger: `sc.exe qtriggerinfo webclient`
- Перевірка, що provider зареєстрований: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Генерування matching events зазвичай потребує code, який записує дані до цього provider; якщо filters відсутні, достатньо будь-якої події.
- Мінімальна C shape для firing provider (якщо додаткові ETW filters не налаштовані):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. На domain-joined hosts, де існує відповідна policy, trigger запускається під час boot. Сам по собі `gpupdate` не спричинить trigger без змін, але:<sup>[[1]](#references)</sup>

- Активація: `gpupdate /force`
- Якщо відповідний тип policy існує, це надійно спричиняє спрацювання trigger і запуск service.

### IP Address Available

Спрацьовує, коли отримано першу IP-адресу (або втрачено останню). Часто trigger спрацьовує під час boot.<sup>[[1]](#references)</sup>

- Активація: перемкніть connectivity для повторного trigger, наприклад:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Запускає service, коли з’являється відповідний device interface. Якщо data item не вказано, будь-який device, що відповідає GUID trigger subtype, спричинить trigger. Перевіряється під час boot і після hot-plug.<sup>[[1]](#references)</sup>

- Активація: під’єднайте або вставте device (physical чи virtual), який відповідає class/hardware ID, вказаному в trigger subtype.

### Domain Join State

Попри неоднозначне формулювання MSDN, цей trigger перевіряє domain state під час boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → запустити service, якщо host є domain-joined
- DOMAIN_LEAVE_GUID → запустити service, лише якщо host НЕ є domain-joined

### System State Change – WNF (undocumented)

Деякі services використовують undocumented WNF-based triggers (`SERVICE_TRIGGER_TYPE 0x7`). Активація потребує публікації відповідного WNF state; specifics залежать від state name. Довідкова інформація: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Спостерігаються у Windows 11 для деяких services (наприклад, CDPSvc). Aggregated configuration зберігається в:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Значення Trigger service є GUID; subkey із цим GUID визначає aggregated event. Triggering будь-якої constituent event запускає service.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Було помічено, що trigger, обмежений певним port/protocol, запускається після будь-якої зміни firewall rule (disable/delete/add), а не лише для вказаного port. Ще гірше: налаштування port без protocol може пошкодити запуск BFE після reboot, спричинивши каскадні збої багатьох services і порушивши firewall management. Будьте вкрай обережні.<sup>[[1]](#references)</sup>

## Practical Workflow

1) Перерахуйте triggers у цікавих services (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Якщо існує Network Endpoint trigger:
- Named pipe → спробуйте відкрити client connection до \\.\pipe\<PipeName>
- RPC endpoint → виконайте Endpoint Mapper lookup для interface UUID

3) Якщо існує ETW trigger:
- Перевірте provider і filters за допомогою `sc.exe qtriggerinfo`; якщо filters відсутні, будь-яка подія від цього provider запустить service

4) Для Group Policy/IP/Device/Domain triggers:
- Використовуйте environmental levers: `gpupdate /force`, перемикання NICs, hot-plug devices тощо.

## Related

- Після запуску привілейованого service через Named Pipe trigger ви можете отримати можливість impersonate його:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Перелік triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Спочатку перевірте service start type за допомогою `sc.exe qc <Service>`. Якщо він має значення `DISABLED`, спрацювання trigger недостатньо; спочатку потрібно знайти спосіб змінити configuration.
- Services, що запускаються trigger, можуть знову зупинитися після переходу в idle. Якщо ваша follow-on action залежить від short-lived listener (RPC/named pipe/WebDAV), виконайте trigger і споживіть його негайно.
- `sc.exe qtriggerinfo` не повністю розуміє кожен undocumented trigger type. Для aggregate triggers у новіших Windows builds перевірте backing GUID і constituent events у `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Створіть baseline і проводьте audit TriggerInfo для всіх services. Також перевіряйте `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` на наявність aggregate triggers.
- Відстежуйте підозрілі EPM lookups для UUID привілейованих services і спроби підключення до named pipes, що передують запуску services.
- Обмежте коло користувачів, які можуть змінювати service triggers; несподівані збої BFE після змін triggers вважайте підозрілими.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
