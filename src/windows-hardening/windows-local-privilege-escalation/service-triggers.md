# Windows Service Triggers: एन्यूमरेशन और दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers Service Control Manager (SCM) को किसी शर्त होने पर सेवा start/stop करने की अनुमति देते हैं (उदाहरण: कोई IP address उपलब्ध हो जाना, named pipe कनेक्शन की कोशिश, या कोई ETW event प्रकाशित होना)। भले ही आपके पास लक्ष्य सेवा पर SERVICE_START अधिकार न हो, आप उसकी trigger को फायर कर के उसे शुरू करवा सकते हैं।

यह पृष्ठ हमलावर के अनुकूल एन्यूमरेशन और आम ट्रिगर्स को सक्रिय करने के कम‑घर्षण तरीके पर केंद्रित है।

> Tip: किसी privileged built-in service को शुरू करना (उदाहरण: RemoteRegistry, WebClient/WebDAV, EFS) नए RPC/named-pipe listeners उजागर कर सकता है और आगे के दुरुपयोग चेन अनलॉक कर सकता है।

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

ये तब एक सेवा शुरू करते हैं जब कोई क्लाइंट किसी IPC endpoint से बात करने की कोशिश करता है। यह कम-privileged यूज़र्स के लिए उपयोगी है क्योंकि SCM आपकी क्लाइंट कनेक्शन से पहले सेवा को auto-start कर देगा।

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

कोई सेवा ETW provider/event से बाउंड ट्रिगर रजिस्टर कर सकती है। यदि अतिरिक्त फ़िल्टर (keyword/level/binary/string) कॉन्फ़िगर नहीं हैं, तो उस provider से कोई भी event सेवा को शुरू कर देगा।

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events typically requires code that logs to that provider; if no filters are present, any event suffices.

### Group Policy Triggers

Subtypes: Machine/User. Domain-joined hosts पर जहाँ संबंधित policy मौजूद है, trigger boot पर चलता है। सिर्फ `gpupdate` बिना किसी बदलाव के trigger नहीं चलाएगा, पर:

- Activation: `gpupdate /force`
- If the relevant policy type exists, this reliably causes the trigger to fire and start the service.

### IP Address Available

पहली बार IP मिलने पर (या आखिरी खोने पर) यह फायर होता है। अक्सर boot पर trigger होता है।

- Activation: Toggle connectivity to retrigger, e.g.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

जब कोई matching device interface आता है तो यह सेवा शुरू करता है। अगर कोई data item specified नहीं है, तो उस trigger subtype GUID से मेल खाने वाला कोई भी device trigger को फायर करेगा। यह boot पर और hot‑plug पर दोनों पर मूल्यांकन किया जाता है।

- Activation: Attach/insert a device (physical or virtual) that matches the class/hardware ID specified by the trigger subtype.

### Domain Join State

MSDN की भ्रामक शब्दावली के बावजूद, यह boot पर domain state का मूल्यांकन करता है:
- DOMAIN_JOIN_GUID → service शुरू करें अगर domain‑joined है
- DOMAIN_LEAVE_GUID → service केवल तभी शुरू करें अगर NOT domain‑joined हो

### System State Change – WNF (undocumented)

कुछ सेवाएँ undocumented WNF‑based triggers (SERVICE_TRIGGER_TYPE 0x7) का उपयोग करती हैं। सक्रिय करने के लिए संबंधित WNF state publish करना आवश्यक है; विशिष्ट विवरण state name पर निर्भर करते हैं। Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Windows 11 पर कुछ सेवाओं (उदा., CDPSvc) में aggregated configuration देखी गई है। Aggregated configuration इस स्थान पर स्टोर होती है:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

किसी सेवा का Trigger मान एक GUID होता है; उस GUID के साथ subkey aggregated event को परिभाषित करता है। किसी भी constituent event के trigger होने पर सेवा शुरू हो जाती है।

### Firewall Port Event (quirks and DoS risk)

एक trigger जो किसी specific port/protocol पर scoped है, देखा गया है कि यह किसी भी firewall rule change (disable/delete/add) पर शुरू हो जाता है, सिर्फ निर्दिष्ट port पर नहीं। और भी खराब, किसी protocol के बिना port कॉन्फ़िगर करने से BFE startup across reboots करप्ट हो सकता है, जिससे कई सेवाएँ फेल हो सकती हैं और firewall management टूट सकता है। अत्यंत सावधानी से व्यवहार करें।

## Practical Workflow

1) रोचक सेवाओं (RemoteRegistry, WebClient, EFS, …) पर triggers enumerate करें:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) यदि Network Endpoint trigger मौजूद है:
- Named pipe → \\.\pipe\<PipeName> पर client open का प्रयास करें
- RPC endpoint → interface UUID के लिए Endpoint Mapper lookup करें

3) यदि ETW trigger मौजूद है:
- `sc.exe qtriggerinfo` से provider और filters जांचें; अगर कोई filters नहीं हैं तो उस provider का कोई भी event सेवा शुरू कर देगा

4) Group Policy/IP/Device/Domain triggers के लिए:
- पर्यावरणीय लीवर्स का उपयोग करें: `gpupdate /force`, NICs toggle करें, devices hot‑plug करें, आदि।

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

- सेवाओं में TriggerInfo का baseline और audit करें। साथ ही HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents को aggregate triggers के लिए रिव्यू करें।
- privileged service UUIDs के लिए संदिग्ध EPM lookups और service starts से पहले होने वाले named-pipe connection attempts की निगरानी करें।
- जो लोग service triggers को modify कर सकते हैं उन्हें सीमित करें; trigger बदलाव के बाद unexpected BFE failures को संदिग्ध समझें।

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
