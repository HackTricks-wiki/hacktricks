# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers, Service Control Manager (SCM) को किसी condition के होने पर किसी service को start/stop करने देते हैं (जैसे, एक IP address उपलब्ध हो जाता है, एक named pipe connection attempt होता है, एक ETW event publish होता है)। भले ही आपके पास target service पर SERVICE_START rights न हों, फिर भी आप उसके trigger को fire करवाकर उसे start कर सकते हैं।

यह page attacker-friendly enumeration और common triggers को activate करने के low-friction तरीकों पर focus करता है।

> Tip: एक privileged built-in service (जैसे, RemoteRegistry, WebClient/WebDAV, EFS) शुरू करने से नए RPC/named-pipe listeners exposed हो सकते हैं और आगे की abuse chains unlock हो सकती हैं।

## Enumerating Service Triggers

- sc.exe (local)
- एक service के triggers list करें: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers यहाँ रहते हैं: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Recursively dump करें: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8) के साथ QueryServiceConfig2 call करके SERVICE_TRIGGER_INFO retrieve करें।
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM को remote query करके MS‑SCMR का उपयोग करते हुए trigger info fetch किया जा सकता है। TrustedSec का Titanis यह expose करता है: `Scm.exe qtriggers`.
- Impacket इन structures को msrpc MS-SCMR में define करता है; आप उनका उपयोग करके remote query implement कर सकते हैं।
- PowerShell (bulk enumeration)
- हर service जो `TriggerInfo` key expose करती है, उसे जल्दी से list करें:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw का `NtObjectManager` module `Get-Win32ServiceTrigger` expose करता है, जिससे `sc.exe` output scrape किए बिना trigger metadata parse किया जा सकता है।

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

ये तब service start करते हैं जब कोई client किसी IPC endpoint से बात करने की कोशिश करता है। low-priv users के लिए उपयोगी, क्योंकि SCM आपके client के वास्तव में connect करने से पहले ही service auto-start कर देगा।

- Named pipe trigger
- Behavior: `\\.\pipe\<PipeName>` पर client connection attempt होने पर SCM service को start करता है ताकि वह listening शुरू कर सके।
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers `npsvctrig.sys` से backed होते हैं, जो एक filesystem minifilter है और registered trigger pipe names के against opens को watch करता है। इसी वजह से open attempt service को start कर सकता है, even before service ने pipe create/listen किया हो।
- See also: Named Pipe Client Impersonation for post-start abuse।

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Endpoint Mapper (EPM, TCP/135) को किसी interface UUID के लिए query करना जो service से associated है, SCM को उसे start करने के लिए मजबूर करता है ताकि वह अपना endpoint register कर सके।
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

एक service किसी ETW provider/event से bound trigger register कर सकती है। यदि कोई अतिरिक्त filters (keyword/level/binary/string) configured नहीं हैं, तो उस provider का कोई भी event service को start कर देगा।

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Trigger list करें: `sc.exe qtriggerinfo webclient`
- Verify करें कि provider registered है: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Matching events emit करने के लिए आमतौर पर ऐसे code की ज़रूरत होती है जो उस provider में log करे; यदि कोई filters नहीं हैं, तो कोई भी event पर्याप्त है।
- Provider fire करने के लिए minimal C shape (जब कोई अतिरिक्त ETW filters configured न हों):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Domain-joined hosts पर जहाँ corresponding policy मौजूद है, trigger boot पर run होता है। `gpupdate` alone बिना changes के trigger नहीं करेगा, लेकिन:

- Activation: `gpupdate /force`
- यदि relevant policy type मौजूद हो, तो यह reliably trigger को fire करके service start कर देता है।

### IP Address Available

पहला IP मिलने पर (या आखिरी के खोने पर) fire होता है। अक्सर boot पर trigger होता है।

- Activation: connectivity toggle करके retrigger करें, जैसे:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

जब कोई matching device interface arrive होती है, तो service start होती है। यदि कोई data item specified नहीं है, तो trigger subtype GUID से matching कोई भी device trigger fire कर देगा। Boot पर और hot-plug पर evaluated होता है।

- Activation: कोई device (physical या virtual) attach/insert करें जो trigger subtype द्वारा specified class/hardware ID से match करता हो।

### Domain Join State

MSDN की confusing wording के बावजूद, यह boot पर domain state evaluate करता है:
- DOMAIN_JOIN_GUID → यदि domain-joined है तो service start करें
- DOMAIN_LEAVE_GUID → service केवल तब start करें जब domain-joined न हो

### System State Change – WNF (undocumented)

कुछ services undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7) use करती हैं। Activation के लिए relevant WNF state publish करना पड़ता है; specifics state name पर depend करते हैं। Research background: Windows Notification Facility internals।

### Aggregate Service Triggers (undocumented)

Windows 11 पर कुछ services (जैसे, CDPSvc) के लिए observed है। Aggregated configuration यहाँ stored होती है:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Service का Trigger value एक GUID होता है; उस GUID वाला subkey aggregated event define करता है। Constituent events में से किसी एक को trigger करने से service start हो जाती है।

### Firewall Port Event (quirks and DoS risk)

किसी specific port/protocol से scoped trigger को किसी भी firewall rule change (disable/delete/add) पर start होते देखा गया है, केवल specified port पर नहीं। इससे भी बुरा, बिना protocol के port configure करने से reboots के across BFE startup corrupt हो सकता है, जिससे कई service failures और firewall management टूट सकती है। अत्यधिक caution के साथ handle करें।

## Practical Workflow

1) Interesting services (RemoteRegistry, WebClient, EFS, …) पर triggers enumerate करें:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) यदि Network Endpoint trigger मौजूद है:
- Named pipe → `\\.\pipe\<PipeName>` पर client open attempt करें
- RPC endpoint → interface UUID के लिए Endpoint Mapper lookup करें

3) यदि ETW trigger मौजूद है:
- `sc.exe qtriggerinfo` के साथ provider और filters check करें; यदि कोई filters नहीं हैं, तो उस provider का कोई भी event service start कर देगा

4) Group Policy/IP/Device/Domain triggers के लिए:
- Environmental levers use करें: `gpupdate /force`, NICs toggle करें, hot-plug devices, etc.

## Related

- Named Pipe trigger के माध्यम से privileged service start करने के बाद, आप उसे impersonate कर सकते हैं:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Triggers list करें (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- पहले service start type check करें: `sc.exe qc <Service>`. यदि यह `DISABLED` है, तो trigger fire करना पर्याप्त नहीं है; पहले आपको configuration बदलने का तरीका ढूँढना होगा।
- Trigger-start services idle होने के बाद फिर से stop हो सकती हैं। यदि आपकी आगे की action short-lived listener (RPC/named pipe/WebDAV) पर depend करती है, तो उसे तुरंत trigger करें और consume करें।
- `sc.exe qtriggerinfo` हर undocumented trigger type को पूरी तरह नहीं समझता। Newer Windows builds पर aggregate triggers के लिए, backing GUID और constituent events को `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` में confirm करें।

## Detection and Hardening Notes

- Services के across TriggerInfo baseline और audit करें। Aggregate triggers के लिए `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` भी review करें।
- Privileged service UUIDs के लिए suspicious EPM lookups और service starts से पहले होने वाले named-pipe connection attempts monitor करें।
- Service triggers modify करने की अनुमति को restrict करें; trigger changes के बाद unexpected BFE failures को suspicious मानें।

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
