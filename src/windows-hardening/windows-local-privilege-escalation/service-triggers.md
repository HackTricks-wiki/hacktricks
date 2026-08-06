# Windows Service Triggers: Uorodheshaji na Matumizi Mabaya

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers huruhusu Service Control Manager (SCM) kuanzisha/kusimamisha service hali fulani inapotokea (kwa mfano, anwani ya IP inapopatikana, muunganisho wa named pipe unapojaribiwa, au tukio la ETW linapochapishwa). Hata kama huna haki za SERVICE_START kwenye service lengwa, bado unaweza kuweza kuiwasha kwa kusababisha trigger yake iwashe.<sup>[[1]](#references)</sup>

Ukurasa huu unaangazia uorodheshaji unaomfaa attacker na njia rahisi za kuamilisha triggers zinazotumika mara kwa mara.

> Tip: Kuanzisha service ya built-in yenye privileges (kwa mfano, RemoteRegistry, WebClient/WebDAV, EFS) kunaweza kufichua wasikilizaji wapya wa RPC/named-pipe na kuwezesha abuse chains zaidi.

## Kuorodhesha Service Triggers

- sc.exe (local)
- Orodhesha triggers za service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers huhifadhiwa chini ya: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Fanya dump kwa kujirudia: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Ita QueryServiceConfig2 pamoja na SERVICE_CONFIG_TRIGGER_INFO (8) ili kupata SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] na SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC kupitia MS-SCMR (remote)
- SCM inaweza kuulizwa remotely ili kupata trigger info kwa kutumia MS-SCMR. Titanis ya TrustedSec inaonyesha hili: `Scm.exe qtriggers`.
- Impacket inafafanua structures katika msrpc MS-SCMR; unaweza kutekeleza remote query ukitumia hizo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- Orodhesha haraka kila service inayofichua key ya `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Module ya James Forshaw ya `NtObjectManager` inafichua `Get-Win32ServiceTrigger` kwa kuchanganua trigger metadata bila kuscrape output ya `sc.exe`.

## Aina za Triggers Zenye Thamani Kubwa na Jinsi ya Kuziamilisha

### Network Endpoint Triggers

Hizi huanzisha service client anapojaribu kuwasiliana na IPC endpoint. Ni muhimu kwa low-priv users kwa sababu SCM itaanzisha service automatically kabla client yako haijaweza kuunganishwa.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Tabia: Jaribio la muunganisho wa client kwenye \\.\pipe\<PipeName> husababisha SCM kuanzisha service ili ianze kusikiliza.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Dokezo la internals: named-pipe triggers hutegemea `npsvctrig.sys`, filesystem minifilter inayofuatilia opens dhidi ya majina ya trigger pipe yaliyosajiliwa. Ndiyo maana open attempt inaweza kuanzisha service hata kabla service yenyewe haijaunda/kusikiliza kwenye pipe.<sup>[[5]](#references)</sup>
- Tazama pia: Named Pipe Client Impersonation kwa post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Tabia: Kuuliza Endpoint Mapper (EPM, TCP/135) kuhusu interface UUID inayohusishwa na service husababisha SCM kuianzisha ili iweze kusajili endpoint yake.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Service inaweza kusajili trigger inayohusishwa na ETW provider/event. Ikiwa hakuna filters za ziada (keyword/level/binary/string) zilizosanidiwa, event yoyote kutoka kwa provider huyo itaianzisha service.<sup>[[1]](#references)</sup>

- Mfano (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Orodhesha trigger: `sc.exe qtriggerinfo webclient`
- Thibitisha kuwa provider amesajiliwa: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Kuchapisha matching events kwa kawaida huhitaji code inayolog kwenye provider huyo; ikiwa hakuna filters, event yoyote inatosha.
- Muundo mdogo wa C wa ku-fire provider (wakati hakuna ETW filters za ziada zilizosaniwa):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Kwenye hosts zilizojiunga na domain ambako policy inayohusika ipo, trigger huendesha wakati wa boot. `gpupdate` pekee haiwezi ku-trigger bila mabadiliko, lakini:<sup>[[1]](#references)</sup>

- Activation: `gpupdate /force`
- Ikiwa aina ya policy inayohusika ipo, hii husababisha trigger i-fire kwa uhakika na kuanzisha service.

### IP Address Available

Hufire IP ya kwanza inapopatikana (au ya mwisho inapopotea). Mara nyingi hufire wakati wa boot.<sup>[[1]](#references)</sup>

- Activation: Badilisha connectivity ili ku-trigger tena, kwa mfano:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Huanzisha service wakati device interface inayolingana inapowasili. Ikiwa hakuna data item iliyobainishwa, device yoyote inayolingana na trigger subtype GUID ita-fire trigger. Hupimwa wakati wa boot na wakati wa hot-plug.<sup>[[1]](#references)</sup>

- Activation: Unganisha/ingiza device (ya kimwili au virtual) inayolingana na class/hardware ID iliyobainishwa na trigger subtype.

### Domain Join State

Licha ya maneno yanayoweza kuchanganya kwenye MSDN, hii hupima hali ya domain wakati wa boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → anzisha service ikiwa imejiunga na domain
- DOMAIN_LEAVE_GUID → anzisha service ikiwa tu haijaunganishwa na domain

### System State Change – WNF (undocumented)

Baadhi ya services hutumia WNF-based triggers ambazo hazijaandikwa rasmi (SERVICE_TRIGGER_TYPE 0x7). Activation inahitaji kuchapisha WNF state inayohusika; maelezo hutegemea state name. Background ya utafiti: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Zimeonekana kwenye Windows 11 kwa baadhi ya services (kwa mfano, CDPSvc). Configuration iliyounganishwa huhifadhiwa katika:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Thamani ya Trigger ya service ni GUID; subkey yenye GUID hiyo hufafanua aggregated event. Ku-trigger event yoyote kati ya constituent events huanzisha service.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Trigger iliyowekewa scope ya port/protocol maalum imeonekana kuanza kwenye mabadiliko yoyote ya firewall rule (disable/delete/add), si port iliyobainishwa pekee. Zaidi ya hayo, kusanidi port bila protocol kunaweza kuharibu BFE startup kwenye reboots zote, na kusababisha service nyingi kushindwa na kuvuruga firewall management. Tumia kwa tahadhari kubwa sana.<sup>[[1]](#references)</sup>

## Practical Workflow

1) Orodhesha triggers kwenye services zinazovutia (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ikiwa kuna Network Endpoint trigger:
- Named pipe → jaribu client open kwenye \\.\pipe\<PipeName>
- RPC endpoint → fanya Endpoint Mapper lookup kwa interface UUID

3) Ikiwa kuna ETW trigger:
- Kagua provider na filters kwa `sc.exe qtriggerinfo`; ikiwa hakuna filters, event yoyote kutoka kwa provider huyo itaanzisha service

4) Kwa Group Policy/IP/Device/Domain triggers:
- Tumia environmental levers: `gpupdate /force`, badilisha NICs, hot-plug devices, n.k.

## Related

- Baada ya kuanzisha service yenye privileges kupitia Named Pipe trigger, unaweza kuweza kui-impersonate:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Orodhesha triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Kagua kwanza service start type kwa `sc.exe qc <Service>`. Ikiwa ni `DISABLED`, ku-fire trigger hakutoshi; lazima kwanza upate njia ya kubadilisha configuration.
- Services zinazoanza kupitia trigger zinaweza kusimama tena baada ya kuwa idle. Ikiwa hatua yako inayofuata inategemea listener ya muda mfupi (RPC/named pipe/WebDAV), trigger na itumie mara moja.
- `sc.exe qtriggerinfo` haielewi kikamilifu kila aina ya trigger ambayo haijaandikwa rasmi. Kwa aggregate triggers kwenye Windows builds mpya, thibitisha backing GUID na constituent events katika `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Weka baseline na ukague TriggerInfo kwenye services zote. Pia kagua HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents kwa aggregate triggers.
- Fuatilia EPM lookups zinazotiliwa shaka za privileged service UUIDs na majaribio ya muunganisho wa named-pipe yanayotangulia service starts.
- Zuia ni nani anayeweza kurekebisha service triggers; chukulia BFE failures zisizotarajiwa baada ya trigger changes kuwa za kutiliwa shaka.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
