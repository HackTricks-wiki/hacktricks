# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers omogućavaju Service Control Manager-u (SCM) da startuje/zaustavi service kada se dogodi određeni uslov (npr. IP address postane dostupna, pokuša se konekcija na named pipe, ETW event se objavi). Čak i kada nemaš SERVICE_START prava nad ciljanim service-om, i dalje možeš uspeti da ga startuješ tako što ćeš naterati njegov trigger da se aktivira.

Ova stranica se fokusira na attacker-friendly enumeration i na niskofrikcione načine za aktiviranje uobičajenih trigger-a.

> Tip: Startovanje privilegovanog built-in service-a (npr. RemoteRegistry, WebClient/WebDAV, EFS) može otkriti nove RPC/named-pipe listener-e i otključati dodatne abuse chains.

## Enumerating Service Triggers

- sc.exe (local)
- Prikaži trigger-e nekog service-a: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger-i se nalaze pod: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekurzivno dumpovanje: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Pozovi QueryServiceConfig2 sa SERVICE_CONFIG_TRIGGER_INFO (8) da dobiješ SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] i SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC preko MS‑SCMR (remote)
- SCM može da se upita remotely da bi se preuzele informacije o trigger-ima koristeći MS‑SCMR. TrustedSec-ov Titanis ovo izlaže: `Scm.exe qtriggers`.
- Impacket definiše strukture u msrpc MS-SCMR; možeš implementirati remote query koristeći njih.
- PowerShell (bulk enumeration)
- Brzo izlistaj svaki service koji izlaže `TriggerInfo` ključ:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw-ov `NtObjectManager` modul izlaže `Get-Win32ServiceTrigger` za parsiranje trigger metadata bez scraping-a `sc.exe` output-a.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Ovi startuju service kada klijent pokuša da razgovara sa IPC endpoint-om. Korisni su low-priv user-ima jer će SCM automatski startovati service pre nego što tvoj client zaista može da se konektuje.

- Named pipe trigger
- Ponašanje: Pokušaj klijentske konekcije na \\.\pipe\<PipeName> navodi SCM da startuje service kako bi mogao da počne da osluškuje.
- Aktivacija (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals napomena: named-pipe trigger-i su podržani od strane `npsvctrig.sys`, filesystem minifilter-a koji nadgleda opens nad registrovanim trigger pipe imenima. Zato pokušaj otvaranja može da startuje service čak i pre nego što je sam service kreirao/osluškuje na pipe-u.
- Vidi i: Named Pipe Client Impersonation za post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Ponašanje: Upit Endpoint Mapper-a (EPM, TCP/135) za interface UUID povezan sa service-om navodi SCM da ga startuje kako bi mogao da registruje svoj endpoint.
- Aktivacija (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Service može da registruje trigger vezan za ETW provider/event. Ako nisu podešeni dodatni filter-i (keyword/level/binary/string), bilo koji event od tog provider-a će startovati service.

- Primer (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Prikaži trigger: `sc.exe qtriggerinfo webclient`
- Proveri da li je provider registrovan: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitovanje matching event-ova obično zahteva code koji loguje u taj provider; ako nema filter-a, dovoljan je bilo koji event.
- Minimal C shape za aktiviranje provider-a (kada nisu konfigurisani dodatni ETW filter-i):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Podtipovi: Machine/User. Na domain-joined host-ovima gde odgovarajuća policy postoji, trigger radi pri boot-u. `gpupdate` sam po sebi neće okinuti bez promena, ali:

- Aktivacija: `gpupdate /force`
- Ako relevantan tip policy-ja postoji, ovo pouzdano izaziva okidanje trigger-a i startovanje service-a.

### IP Address Available

Okida se kada se dobije prva IP address (ili se izgubi poslednja). Često se aktivira pri boot-u.

- Aktivacija: Uključi/isključi connectivity da bi se ponovo okinulo, npr.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Startuje service kada stigne odgovarajući device interface. Ako nije naveden data item, bilo koji device koji odgovara trigger subtype GUID-u će aktivirati trigger. Evaluira se pri boot-u i pri hot-plug-u.

- Aktivacija: Priključi/ubaci device (fizički ili virtuelni) koji odgovara class/hardware ID-ju navedenom od strane trigger subtype-a.

### Domain Join State

Uprkos zbunjujućem MSDN tekstu, ovo evaluira domain state pri boot-u:
- DOMAIN_JOIN_GUID → startuj service ako je domain-joined
- DOMAIN_LEAVE_GUID → startuj service samo ako NIJE domain-joined

### System State Change – WNF (undocumented)

Neki service-i koriste undocumented WNF-based trigger-e (SERVICE_TRIGGER_TYPE 0x7). Aktivacija zahteva objavljivanje odgovarajućeg WNF state-a; detalji zavise od state name-a. Research pozadina: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Primećeno na Windows 11 za neke service-e (npr. CDPSvc). Agregirana konfiguracija se čuva u:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Trigger value service-a je GUID; subkey sa tim GUID-om definiše agregirani event. Aktiviranje bilo kog sastavnog event-a startuje service.

### Firewall Port Event (quirks and DoS risk)

Trigger vezan za određeni port/protocol primećen je da se pokreće na bilo koju firewall rule promenu (disable/delete/add), a ne samo na navedeni port. Još gore, konfiguracija porta bez protocol-a može da ošteti BFE startup kroz reboot-ove, što zatim izaziva mnoge service failure-e i kvari upravljanje firewall-om. Postupaj sa ekstremnim oprezom.

## Practical Workflow

1) Enumeriši trigger-e na zanimljivim service-ima (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ako postoji Network Endpoint trigger:
- Named pipe → pokušaj client open na \\.\pipe\<PipeName>
- RPC endpoint → uradi Endpoint Mapper lookup za interface UUID

3) Ako postoji ETW trigger:
- Proveri provider i filter-e sa `sc.exe qtriggerinfo`; ako nema filter-a, bilo koji event tog provider-a će startovati service

4) Za Group Policy/IP/Device/Domain trigger-e:
- Koristi environmental levers: `gpupdate /force`, toggle NIC-ove, hot-plug device-e, itd.

## Related

- Nakon startovanja privilegovanog service-a preko Named Pipe trigger-a, možda ćeš moći da ga impersonate:

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

- Prvo proveri service start type sa `sc.exe qc <Service>`. Ako je `DISABLED`, okidanje trigger-a nije dovoljno; prvo moraš da pronađeš način da promeniš konfiguraciju.
- Trigger-start service-i mogu ponovo da se zaustave nakon što postanu idle. Ako tvoja sledeća akcija zavisi od kratkotrajnog listener-a (RPC/named pipe/WebDAV), aktiviraj ga i odmah ga iskoristi.
- `sc.exe qtriggerinfo` ne razume u potpunosti svaki undocumented trigger type. Za aggregate trigger-e na novijim Windows build-ovima, potvrdi backing GUID i sastavne event-e u `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Postavi baseline i audituj TriggerInfo kroz service-e. Takođe pregledaj HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents za aggregate trigger-e.
- Prati sumnjive EPM lookup-ove za privileged service UUID-ove i pokušaje konekcije na named pipe koji prethode startovanju service-a.
- Ograniči ko može da menja service trigger-e; tretiraj neočekivane BFE failure-e nakon promena trigger-a kao sumnjive.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
