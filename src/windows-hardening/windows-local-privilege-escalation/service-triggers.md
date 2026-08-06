# Windows Service Triggers: Enumeration और Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers, किसी condition के होने पर Service Control Manager (SCM) को किसी service को start/stop करने की अनुमति देते हैं (जैसे, IP address उपलब्ध होना, named pipe connection का प्रयास किया जाना, या ETW event publish होना)। किसी target service पर SERVICE_START rights न होने पर भी, उसके trigger को fire करवाकर उसे start करना संभव हो सकता है।<sup>[[1]](#references)</sup>

यह page attacker-friendly enumeration और common triggers को activate करने के आसान तरीकों पर केंद्रित है।

> Tip: किसी privileged built-in service (जैसे RemoteRegistry, WebClient/WebDAV, EFS) को start करने से नए RPC/named-pipe listeners expose हो सकते हैं और आगे की abuse chains unlock हो सकती हैं।

## Service Triggers की Enumeration

- sc.exe (local)
- किसी service के triggers की सूची: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers यहां मौजूद होते हैं: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Recursively dump करें: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8) के साथ QueryServiceConfig2 को call करके SERVICE_TRIGGER_INFO प्राप्त करें।
- Docs: QueryServiceConfig2[W/A] और SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- MS-SCMR के माध्यम से RPC (remote)
- SCM को MS-SCMR का उपयोग करके remotely query कर trigger info प्राप्त की जा सकती है। TrustedSec का Titanis इसे expose करता है: `Scm.exe qtriggers`.
- Impacket, msrpc MS-SCMR में इन structures को define करता है; इनके उपयोग से remote query implement की जा सकती है।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- `TriggerInfo` key expose करने वाली हर service को जल्दी से list करें:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw का `NtObjectManager` module, `sc.exe` output को scrape किए बिना trigger metadata parse करने के लिए `Get-Win32ServiceTrigger` expose करता है।

## High-Value Trigger Types और उन्हें Activate करने के तरीके

### Network Endpoint Triggers

जब कोई client किसी IPC endpoint से communicate करने का प्रयास करता है, तब ये किसी service को start करते हैं। ये low-priv users के लिए उपयोगी हैं क्योंकि client के वास्तव में connect करने से पहले SCM service को auto-start कर देता है।<sup>[[1]](#references)</sup>

- Named pipe trigger
- Behavior: `\\.\pipe\<PipeName>` से client connection attempt होने पर SCM service को start करता है, ताकि वह listening शुरू कर सके।
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers को `npsvctrig.sys` support करता है, जो एक filesystem minifilter है और registered trigger pipe names पर होने वाले opens को monitor करता है। इसी कारण open attempt service के स्वयं pipe create/listen करने से पहले ही उसे start कर सकता है।<sup>[[5]](#references)</sup>
- यह भी देखें: post-start abuse के लिए Named Pipe Client Impersonation।

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: किसी service से associated interface UUID के लिए Endpoint Mapper (EPM, TCP/135) को query करने पर SCM service को start करता है, ताकि वह अपना endpoint register कर सके।
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

कोई service किसी ETW provider/event से bound trigger register कर सकती है। यदि कोई अतिरिक्त filter (keyword/level/binary/string) configured नहीं है, तो उस provider का कोई भी event service को start कर देगा।<sup>[[1]](#references)</sup>

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Trigger list करें: `sc.exe qtriggerinfo webclient`
- Verify करें कि provider registered है: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Matching events emit करने के लिए आमतौर पर उस provider में log करने वाला code आवश्यक होता है; यदि कोई filter मौजूद नहीं है, तो कोई भी event पर्याप्त है।
- Provider को fire करने के लिए Minimal C shape (जब कोई अतिरिक्त ETW filters configured न हों):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Domain-joined hosts पर, जहां corresponding policy मौजूद है, trigger boot के समय run होता है। केवल `gpupdate` बिना changes के trigger नहीं चलाएगा, लेकिन:<sup>[[1]](#references)</sup>

- Activation: `gpupdate /force`
- यदि relevant policy type मौजूद है, तो इससे trigger reliably fire होगा और service start होगी।

### IP Address Available

पहला IP प्राप्त होने पर (या अंतिम IP खोने पर) fire होता है। यह अक्सर boot के समय trigger होता है।<sup>[[1]](#references)</sup>

- Activation: Connectivity को toggle करके retrigger करें, जैसे:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Matching device interface आने पर service start करता है। यदि कोई data item specified नहीं है, तो trigger subtype GUID से match करने वाला कोई भी device trigger fire करेगा। इसका evaluation boot के समय और hot-plug होने पर किया जाता है।<sup>[[1]](#references)</sup>

- Activation: ऐसा physical या virtual device attach/insert करें, जो trigger subtype में specified class/hardware ID से match करता हो।

### Domain Join State

भ्रमित करने वाली MSDN wording के बावजूद, यह boot के समय domain state का evaluation करता है:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → यदि host domain-joined है, तो service start करें
- DOMAIN_LEAVE_GUID → केवल तभी service start करें जब host domain-joined न हो

### System State Change – WNF (undocumented)

कुछ services undocumented WNF-based triggers (`SERVICE_TRIGGER_TYPE 0x7`) का उपयोग करती हैं। Activation के लिए relevant WNF state publish करना आवश्यक है; details state name पर निर्भर करती हैं। Research background: Windows Notification Facility internals।

### Aggregate Service Triggers (undocumented)

Windows 11 पर कुछ services (जैसे CDPSvc) के लिए observed। Aggregated configuration यहां stored होती है:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

किसी service का Trigger value एक GUID होता है; उस GUID वाली subkey aggregated event define करती है। किसी भी constituent event को trigger करने पर service start हो जाती है।<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks और DoS risk)

Specific port/protocol तक scoped trigger को केवल specified port पर ही नहीं, बल्कि किसी भी firewall rule change (disable/delete/add) पर start होते हुए observe किया गया है। इससे भी खराब बात यह है कि protocol के बिना port configure करने पर reboots के दौरान BFE startup corrupt हो सकता है, जिससे कई service failures cascade हो सकते हैं और firewall management टूट सकता है। इसे अत्यधिक सावधानी के साथ handle करें।<sup>[[1]](#references)</sup>

## Practical Workflow

1) Interesting services (RemoteRegistry, WebClient, EFS, …) पर triggers enumerate करें:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) यदि Network Endpoint trigger मौजूद हो:
- Named pipe → `\\.\pipe\<PipeName>` पर client open का प्रयास करें
- RPC endpoint → interface UUID के लिए Endpoint Mapper lookup करें

3) यदि ETW trigger मौजूद हो:
- `sc.exe qtriggerinfo` से provider और filters check करें; यदि कोई filter नहीं है, तो उस provider का कोई भी event service start कर देगा

4) Group Policy/IP/Device/Domain triggers के लिए:
- Environmental levers का उपयोग करें: `gpupdate /force`, NICs toggle करना, devices को hot-plug करना आदि।

## Related

- Named Pipe trigger के माध्यम से privileged service start करने के बाद, आप उसका impersonate करने में सक्षम हो सकते हैं:

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

- पहले `sc.exe qc <Service>` से service start type check करें। यदि यह `DISABLED` है, तो trigger fire करना पर्याप्त नहीं होगा; पहले configuration बदलने का तरीका खोजना होगा।
- Trigger-start services idle होने के बाद फिर stop हो सकती हैं। यदि आपका follow-on action short-lived listener (RPC/named pipe/WebDAV) पर निर्भर है, तो उसे तुरंत trigger और consume करें।
- `sc.exe qtriggerinfo` हर undocumented trigger type को पूरी तरह नहीं समझता। नए Windows builds पर aggregate triggers के लिए `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` में backing GUID और constituent events confirm करें।

## Detection and Hardening Notes

- सभी services में TriggerInfo का baseline और audit रखें। Aggregate triggers के लिए `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` की भी समीक्षा करें।
- Privileged service UUIDs के लिए suspicious EPM lookups और service starts से पहले होने वाले named-pipe connection attempts को monitor करें।
- Service triggers को modify करने वालों को restrict करें; trigger changes के बाद होने वाली unexpected BFE failures को suspicious मानें।

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
