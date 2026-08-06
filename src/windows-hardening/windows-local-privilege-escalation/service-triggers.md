# Windows Service Triggers: Enumerasie en Misbruik

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers laat die Service Control Manager (SCM) toe om 'n diens te begin/stop wanneer 'n toestand voorkom (byvoorbeeld wanneer 'n IP-adres beskikbaar word, 'n named pipe-verbinding probeer word, of 'n ETW-event gepubliseer word). Selfs wanneer jy nie SERVICE_START-regte op 'n teikendiens het nie, kan jy dit moontlik steeds begin deur die trigger daarvan te laat aktiveer.<sup>[[1]](#references)</sup>

Hierdie bladsy fokus op aanvallervriendelike enumerasie en eenvoudige maniere om algemene triggers te aktiveer.

> Wenk: Die begin van 'n bevoorregte ingeboude diens (byvoorbeeld RemoteRegistry, WebClient/WebDAV, EFS) kan nuwe RPC/named-pipe-luisteraars blootstel en verdere misbruikskakels ontsluit.

## Enumerasie van Service Triggers

- sc.exe (plaaslik)
- Lys 'n diens se triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (plaaslik)
- Triggers is geleë onder: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump rekursief: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (plaaslik)
- Roep QueryServiceConfig2 met SERVICE_CONFIG_TRIGGER_INFO (8) aan om SERVICE_TRIGGER_INFO te verkry.
- Docs: QueryServiceConfig2[W/A] en SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC oor MS-SCMR (afgeleë)
- Die SCM kan op afstand navraag gedoen word om trigger-inligting met MS-SCMR te verkry. TrustedSec se Titanis stel dit bloot: `Scm.exe qtriggers`.
- Impacket definieer die strukture in msrpc MS-SCMR; jy kan 'n afgeleë navraag daarmee implementeer.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk-enumerasie)
- Lys vinnig elke diens wat 'n `TriggerInfo`-sleutel blootstel:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmaties)
- James Forshaw se `NtObjectManager`-module stel `Get-Win32ServiceTrigger` bloot om trigger-metadata te parse sonder om `sc.exe`-uitset te scrape.

## Hoëwaarde-Triggertipes en Hoe om Hulle te Aktiveer

### Network Endpoint Triggers

Hierdie begin 'n diens wanneer 'n kliënt probeer om met 'n IPC-endpoint te kommunikeer. Dit is nuttig vir low-priv-gebruikers omdat die SCM die diens outomaties sal begin voordat jou kliënt werklik kan koppel.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Gedrag: 'n Kliëntverbindingpoging na \\.\pipe\<PipeName> veroorsaak dat die SCM die diens begin sodat dit kan begin luister.
- Aktivering (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Interne nota: named-pipe-triggers word ondersteun deur `npsvctrig.sys`, 'n filesystem minifilter wat kyk vir opens teen geregistreerde trigger-pipename. Daarom kan die open-poging die diens begin selfs voordat die diens self die pipe geskep het of daarna luister.<sup>[[5]](#references)</sup>
- Sien ook: Named Pipe Client Impersonation vir post-start-misbruik.

- RPC endpoint trigger (Endpoint Mapper)
- Gedrag: Deur die Endpoint Mapper (EPM, TCP/135) te navraag doen vir 'n interface-UUID wat met 'n diens geassosieer word, veroorsaak jy dat die SCM dit begin sodat dit sy endpoint kan registreer.
- Aktivering (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

'n Diens kan 'n trigger registreer wat aan 'n ETW-provider/event gebind is. Indien geen bykomende filters (keyword/level/binary/string) gekonfigureer is nie, sal enige event van daardie provider die diens begin.<sup>[[1]](#references)</sup>

- Voorbeeld (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Lys trigger: `sc.exe qtriggerinfo webclient`
- Verifieer dat provider geregistreer is: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Die uitstuur van ooreenstemmende events vereis gewoonlik code wat by daardie provider log; indien geen filters teenwoordig is nie, sal enige event voldoen.
- Minimale C-vorm vir die afvuur van die provider (wanneer geen bykomende ETW-filters gekonfigureer is nie):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtipes: Machine/User. Op domeingekoppelde hosts waar die ooreenstemmende policy bestaan, loop die trigger tydens boot. `gpupdate` alleen sal dit nie aktiveer sonder veranderinge nie, maar:<sup>[[1]](#references)</sup>

- Aktivering: `gpupdate /force`
- Indien die relevante policy-tipe bestaan, veroorsaak dit betroubaar dat die trigger afvuur en die diens begin.

### IP Address Available

Dit aktiveer wanneer die eerste IP verkry word (of die laaste een verlore gaan). Dit word dikwels tydens boot geaktiveer.<sup>[[1]](#references)</sup>

- Aktivering: Wissel konnektiwiteit om dit weer te aktiveer, byvoorbeeld:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Begin 'n diens wanneer 'n ooreenstemmende device interface arriveer. Indien geen data-item gespesifiseer is nie, sal enige device wat met die trigger-subtype-GUID ooreenstem, die trigger aktiveer. Dit word tydens boot en met hot-plug geëvalueer.<sup>[[1]](#references)</sup>

- Aktivering: Koppel/prop 'n device in (fisies of virtueel) wat ooreenstem met die klas/hardware-ID wat deur die trigger-subtype gespesifiseer word.

### Domain Join State

Ten spyte van verwarrende MSDN-bewoording, evalueer dit die domeintoestand tydens boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → begin die diens indien dit aan 'n domein gekoppel is
- DOMAIN_LEAVE_GUID → begin die diens slegs indien dit NIE aan 'n domein gekoppel is nie

### System State Change – WNF (undocumented)

Sommige dienste gebruik undocumented WNF-gebaseerde triggers (SERVICE_TRIGGER_TYPE 0x7). Aktivering vereis dat die relevante WNF-toestand gepubliseer word; die besonderhede hang van die toestandnaam af. Navorsingsagtergrond: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Waargeneem op Windows 11 vir sommige dienste (byvoorbeeld CDPSvc). Die geaggregeerde konfigurasie word gestoor in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

'n Diens se Trigger-waarde is 'n GUID; die subkey met daardie GUID definieer die geaggregeerde event. Die aktivering van enige samestellende event begin die diens.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Daar is waargeneem dat 'n trigger wat tot 'n spesifieke port/protokol beperk is, op enige firewall-reëlverandering begin (disable/delete/add), nie slegs op die gespesifiseerde port nie. Erger nog, die konfigurasie van 'n port sonder 'n protokol kan BFE-startup oor reboots heen korrupteer, wat tot baie diensfoute lei en firewall-bestuur breek. Hanteer dit met uiterste omsigtigheid.<sup>[[1]](#references)</sup>

## Praktiese Werksvloei

1) Enumereer triggers op interessante dienste (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Indien 'n Network Endpoint-trigger bestaan:
- Named pipe → probeer 'n kliënt-open na \\.\pipe\<PipeName>
- RPC endpoint → voer 'n Endpoint Mapper-lookup vir die interface-UUID uit

3) Indien 'n ETW-trigger bestaan:
- Kontroleer provider en filters met `sc.exe qtriggerinfo`; indien daar geen filters is nie, sal enige event van daardie provider die diens begin

4) Vir Group Policy/IP/Device/Domain-triggers:
- Gebruik omgewingshefbome: `gpupdate /force`, wissel NICs, koppel devices warm, ens.

## Verwant

- Nadat jy 'n bevoorregte diens via 'n Named Pipe-trigger begin het, kan jy dit moontlik impersonateer:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Vinnige opdragopsomming

- Lys triggers (plaaslik): `sc.exe qtriggerinfo <Service>`
- Registry-aansig: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW-providerkontrole (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Kontroleer eers die diens se starttipe met `sc.exe qc <Service>`. Indien dit `DISABLED` is, is die afvuur van die trigger nie genoeg nie; jy moet eers 'n manier vind om die konfigurasie te verander.
- Trigger-start-dienste kan weer stop nadat hulle idle geword het. Indien jou opvolgaksie van 'n kortlewende listener (RPC/named pipe/WebDAV) afhanklik is, aktiveer die trigger en gebruik dit onmiddellik.
- `sc.exe qtriggerinfo` verstaan nie elke undocumented triggertipe volledig nie. Vir aggregate triggers op nuwer Windows-builds, bevestig die ondersteunende GUID en samestellende events in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Stel 'n baseline op en oudit TriggerInfo oor alle dienste. Hersien ook HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents vir aggregate triggers.
- Monitor vir verdagte EPM-lookups vir bevoorregte diens-UUIDs en named-pipe-verbindingspogings wat diensstarts voorafgaan.
- Beperk wie diens-triggers mag wysig; behandel onverwagte BFE-foute ná trigger-veranderinge as verdag.

## Verwysings
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
