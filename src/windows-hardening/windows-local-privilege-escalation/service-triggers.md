# Windows Service Triggers: Enumerasie en Misbruik

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers laat die Service Control Manager (SCM) toe om ’n diens te start/stop wanneer ’n toestand plaasvind (bv. ’n IP-adres word beskikbaar, ’n named pipe-verbinding word probeer, ’n ETW event word gepubliseer). Selfs wanneer jy nie SERVICE_START-regte op ’n teikendienst het nie, kan jy dit dalk steeds start deur sy trigger te laat afgaan.

Hierdie blad fokus op aanvaller-vriendelike enumerasie en lae-wrywing maniere om algemene triggers te aktiveer.

> Tip: Om ’n bevoorregte ingeboude diens te start (bv. RemoteRegistry, WebClient/WebDAV, EFS) kan nuwe RPC/named-pipe listeners blootstel en verdere misbruik-kettings ontsluit.

## Enumerating Service Triggers

- sc.exe (local)
- Lys ’n diens se triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers leef onder: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump rekursief: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Roep QueryServiceConfig2 met SERVICE_CONFIG_TRIGGER_INFO (8) aan om SERVICE_TRIGGER_INFO te haal.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC oor MS‑SCMR (remote)
- Die SCM kan op afstand bevraagteken word om trigger-info te haal met MS‑SCMR. TrustedSec se Titanis stel dit bloot: `Scm.exe qtriggers`.
- Impacket definieer die strukture in msrpc MS-SCMR; jy kan ’n remote query daarmee implementeer.
- PowerShell (bulk enumeration)
- Lys vinnig elke diens wat ’n `TriggerInfo`-sleutel blootstel:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw se `NtObjectManager` module stel `Get-Win32ServiceTrigger` bloot vir die ontleding van trigger-metadata sonder om `sc.exe`-output te skraap.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Hierdie start ’n diens wanneer ’n client probeer om met ’n IPC-endpoint te praat. Nuttig vir low-priv users omdat die SCM die diens outomaties sal start voordat jou client werklik kan connect.

- Named pipe trigger
- Gedrag: ’n client connection attempt na \\.\pipe\<PipeName> laat die SCM die diens start sodat dit kan begin luister.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers word ondersteun deur `npsvctrig.sys`, ’n filesystem minifilter wat opens teen geregistreerde trigger pipe names monitor. Dit is hoekom die open attempt die diens kan start selfs voordat die diens self die pipe geskep/geluister het.
- See also: Named Pipe Client Impersonation vir post-start misbruik.

- RPC endpoint trigger (Endpoint Mapper)
- Gedrag: Om die Endpoint Mapper (EPM, TCP/135) te query vir ’n interface UUID wat met ’n diens geassosieer word, laat die SCM dit start sodat dit sy endpoint kan registreer.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

’n Diens kan ’n trigger registreer wat aan ’n ETW provider/event gebind is. As geen bykomende filters (keyword/level/binary/string) gekonfigureer is nie, sal enige event van daardie provider die diens start.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Lys trigger: `sc.exe qtriggerinfo webclient`
- Verifieer provider is geregistreer: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Om ooreenstemmende events te emit vereis tipies code wat na daardie provider log; as geen filters teenwoordig is nie, is enige event genoeg.
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

Subtypes: Machine/User. Op domain-joined hosts waar die ooreenstemmende policy bestaan, loop die trigger by boot. `gpupdate` alleen sal nie trigger sonder changes nie, maar:

- Activation: `gpupdate /force`
- As die relevante policy type bestaan, laat dit die trigger betroubaar afgaan en die diens start.

### IP Address Available

Vuur wanneer die eerste IP verkry word (of die laaste verloor word). Trigger dikwels by boot.

- Activation: Skakel connectivity aan en af om weer te trigger, bv.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Start ’n diens wanneer ’n ooreenstemmende device interface arriveer. As geen data item gespesifiseer is nie, sal enige device wat by die trigger subtype GUID pas die trigger afvuur. Word by boot en by hot-plug geëvalueer.

- Activation: Heg/prop ’n device (fisies of virtueel) aan wat ooreenstem met die class/hardware ID wat deur die trigger subtype gespesifiseer word.

### Domain Join State

Ten spyte van verwarrende MSDN-bewoording, evalueer dit domain state by boot:
- DOMAIN_JOIN_GUID → start die diens as dit domain-joined is
- DOMAIN_LEAVE_GUID → start die diens slegs as dit NIE domain-joined is nie

### System State Change – WNF (undocumented)

Sommige dienste gebruik undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Activation vereis die publisering van die relevante WNF state; besonderhede hang af van die state name. Navorsingsagtergrond: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Waargeneem op Windows 11 vir sommige dienste (bv. CDPSvc). Die geaggregeerde konfigurasie word gestoor in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

’n Diens se Trigger value is ’n GUID; die subkey met daardie GUID definieer die geaggregeerde event. Om enige van die samestellende events te trigger, start die diens.

### Firewall Port Event (quirks and DoS risk)

’n Trigger wat op ’n spesifieke port/protocol geskoei is, is waargeneem om te start op enige firewall rule change (disable/delete/add), nie net die gespesifiseerde port nie. Erger nog, om ’n port sonder ’n protocol te konfigureer kan BFE startup oor reboots korrupteer, wat in baie diensfoute kan oorspoel en firewall management breek. Hanteer met uiterste versigtigheid.

## Practical Workflow

1) Enumereer triggers op interessante dienste (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) As ’n Network Endpoint trigger bestaan:
- Named pipe → probeer ’n client open na \\.\pipe\<PipeName>
- RPC endpoint → voer ’n Endpoint Mapper lookup vir die interface UUID uit

3) As ’n ETW trigger bestaan:
- Kontroleer provider en filters met `sc.exe qtriggerinfo`; as daar geen filters is nie, sal enige event van daardie provider die diens start

4) Vir Group Policy/IP/Device/Domain triggers:
- Gebruik omgewingshefbome: `gpupdate /force`, skakel NICs aan/af, hot-plug devices, ens.

## Related

- Nadat jy ’n bevoorregte diens via ’n Named Pipe trigger gestart het, kan jy dit dalk impersonate:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Lys triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Kontroleer eers die service start type met `sc.exe qc <Service>`. As dit `DISABLED` is, is dit nie genoeg om die trigger af te vuur nie; jy moet eers ’n manier vind om die configuration te verander.
- Trigger-start dienste kan weer stop nadat hulle idle word. As jou opvolg-aksie van ’n kortlewe listener afhang (RPC/named pipe/WebDAV), trigger en gebruik dit onmiddellik.
- `sc.exe qtriggerinfo` verstaan nie ten volle elke undocumented trigger type nie. Vir aggregate triggers op nuwer Windows builds, bevestig die backing GUID en samestellende events in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Baseline en audit TriggerInfo oor dienste. Hersien ook HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents vir aggregate triggers.
- Monitor vir verdagte EPM lookups vir bevoorregte service UUIDs en named-pipe connection attempts wat diens-starts voorafgaan.
- Beperk wie service triggers kan verander; behandel onverwagte BFE failures ná trigger changes as verdag.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
