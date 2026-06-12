# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers huruhusu Service Control Manager (SCM) kuanzisha/kusimamisha service wakati hali fulani inapotokea (kwa mfano, an IP address inapatikana, named pipe connection inajaribiwa, ETW event inachapishwa). Hata ukikosa haki za SERVICE_START kwenye target service, bado unaweza kuianzisha kwa kusababisha trigger yake ifire.

Ukurasa huu unalenga enumeration rafiki kwa attacker na njia zisizo ngumu za kuamsha common triggers.

> Tip: Kuanzisha privileged built-in service (kwa mfano, RemoteRegistry, WebClient/WebDAV, EFS) kunaweza kufichua RPC/named-pipe listeners mpya na kufungua abuse chains zaidi.

## Enumerating Service Triggers

- sc.exe (local)
- Orodhesha triggers za service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers zipo chini ya: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump kwa recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Piga QueryServiceConfig2 na SERVICE_CONFIG_TRIGGER_INFO (8) ili kupata SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM inaweza kuulizwa remotely ili kuchukua trigger info kwa kutumia MS‑SCMR. TrustedSec’s Titanis inaonyesha hili: `Scm.exe qtriggers`.
- Impacket ina define structures katika msrpc MS-SCMR; unaweza kutekeleza remote query kwa kutumia hizo.
- PowerShell (bulk enumeration)
- Orodhesha haraka kila service inayofichua `TriggerInfo` key:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw's `NtObjectManager` module inatoa `Get-Win32ServiceTrigger` kwa kuchambua trigger metadata bila scraping output ya `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Hizi huanzisha service wakati client anajaribu kuzungumza na IPC endpoint. Ni muhimu kwa low-priv users kwa sababu SCM ita-auto-start service kabla ya client yako kuweza ku-connect kweli.

- Named pipe trigger
- Behavior: Jaribio la client connection kwa `\\.\pipe\<PipeName>` husababisha SCM kuanzisha service ili iweze kuanza listening.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers zinaungwa mkono na `npsvctrig.sys`, filesystem minifilter inayofuatilia opens dhidi ya registered trigger pipe names. Ndiyo maana open attempt inaweza kuanzisha service hata kabla service yenyewe haijaunda/kusikiliza pipe.
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Kuuliza Endpoint Mapper (EPM, TCP/135) kwa interface UUID inayohusishwa na service husababisha SCM kuianzisha ili iweze kusajili endpoint yake.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Service inaweza kusajili trigger iliyofungwa kwa ETW provider/event. Ikiwa hakuna additional filters (keyword/level/binary/string) zilizosanidiwa, event yoyote kutoka kwa provider huyo itaianzisha service.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Orodhesha trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events kawaida huhitaji code inayolog kwa provider huyo; ikiwa hakuna filters, event yoyote inatosha.
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

Subtypes: Machine/User. Kwenye hosts zilizounganishwa na domain ambapo corresponding policy ipo, trigger hukimbia wakati wa boot. `gpupdate` pekee haitairusha bila mabadiliko, lakini:

- Activation: `gpupdate /force`
- Ikiwa relevant policy type ipo, hii kwa uhakika husababisha trigger ifire na kuanzisha service.

### IP Address Available

Hufire wakati first IP inapopatikana (au last inapopotea). Mara nyingi huchochewa wakati wa boot.

- Activation: Badilisha connectivity ili ku-trigger tena, kwa mfano:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Huanzisha service wakati matching device interface inafika. Ikiwa data item haijabainishwa, device yoyote inayolingana na trigger subtype GUID itafire trigger. Hukaguliwa wakati wa boot na wakati wa hot-plug.

- Activation: Ambatisha/ingiza device (physical au virtual) inayolingana na class/hardware ID iliyobainishwa na trigger subtype.

### Domain Join State

Licha ya maneno ya MSDN yanayochanganya, hii hukagua domain state wakati wa boot:
- DOMAIN_JOIN_GUID → anzisha service ikiwa domain-joined
- DOMAIN_LEAVE_GUID → anzisha service tu ikiwa HAIJA domain-joined

### System State Change – WNF (undocumented)

Baadhi ya services hutumia undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Activation inahitaji publishing state ya WNF husika; specifics hutegemea state name. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Imeonekana kwenye Windows 11 kwa baadhi ya services (kwa mfano, CDPSvc). Aggregated configuration huhifadhiwa katika:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Trigger value ya service ni GUID; subkey yenye GUID hiyo hufafanua aggregated event. Kuintia any constituent event hufanya service ianze.

### Firewall Port Event (quirks and DoS risk)

Trigger iliyowekwa kwa port/protocol maalum imeonekana kuanza kwenye firewall rule change yoyote (disable/delete/add), si port iliyoainishwa tu. Mbaya zaidi, kusanidi port bila protocol kunaweza kuharibu startup ya BFE katika reboots, na kusababisha failures nyingi za service na kuvunja firewall management. Shughulikia kwa tahadhari kali.

## Practical Workflow

1) Enumerate triggers kwenye services za kuvutia (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ikiwa Network Endpoint trigger ipo:
- Named pipe → jaribu client open kwa `\\.\pipe\<PipeName>`
- RPC endpoint → fanya Endpoint Mapper lookup kwa interface UUID

3) Ikiwa ETW trigger ipo:
- Kagua provider na filters kwa `sc.exe qtriggerinfo`; ikiwa hakuna filters, event yoyote kutoka kwa provider huyo itaanzisha service

4) Kwa Group Policy/IP/Device/Domain triggers:
- Tumia environmental levers: `gpupdate /force`, toggle NICs, hot-plug devices, n.k.

## Related

- Baada ya kuanzisha privileged service kupitia Named Pipe trigger, unaweza kuweza kuimpersonate:

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

- Kagua service start type kwanza kwa `sc.exe qc <Service>`. Ikiwa ni `DISABLED`, firing ya trigger haitoshi; lazima kwanza upate njia ya kubadilisha configuration.
- Trigger-start services zinaweza kusimama tena baada ya kuwa idle. Ikiwa hatua yako inayofuata inategemea short-lived listener (RPC/named pipe/WebDAV), trigger na uitumie mara moja.
- `sc.exe qtriggerinfo` haielewi kikamilifu kila undocumented trigger type. Kwa aggregate triggers kwenye newer Windows builds, thibitisha backing GUID na constituent events katika `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Weka baseline na audit TriggerInfo across services. Pia kagua HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents kwa aggregate triggers.
- Fuatilia suspicious EPM lookups kwa privileged service UUIDs na named-pipe connection attempts zinazotangulia service starts.
- Zuia nani anaweza kurekebisha service triggers; tazama BFE failures zisizotarajiwa baada ya trigger changes kama za kushukiwa.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
