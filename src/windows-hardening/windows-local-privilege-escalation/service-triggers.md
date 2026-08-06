# Windows Service Triggers: Enumeracija i zloupotreba

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers omogućavaju Service Control Manager-u (SCM) da pokrene/zaustavi servis kada se dogodi određeni uslov (npr. IP adresa postane dostupna, pokuša se povezivanje na named pipe ili se objavi ETW događaj). Čak i kada nemate SERVICE_START prava nad ciljnim servisom, možda ćete i dalje moći da ga pokrenete izazivanjem aktiviranja njegovog trigger-a.<sup>[[1]](#references)</sup>

Ova stranica se fokusira na enumeraciju prilagođenu napadačima i načine sa malo prepreka za aktiviranje uobičajenih trigger-a.

> Savet: Pokretanje privilegovanog ugrađenog servisa (npr. RemoteRegistry, WebClient/WebDAV, EFS) može izložiti nove RPC/named-pipe listenere i omogućiti dalje abuse chain-ove.

## Enumeracija Service Trigger-a

- sc.exe (lokalno)
- Izlistavanje trigger-a servisa: `sc.exe qtriggerinfo <ServiceName>`
- Registry (lokalno)
- Trigger-i se nalaze pod: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekurzivni dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (lokalno)
- Pozovite QueryServiceConfig2 sa SERVICE_CONFIG_TRIGGER_INFO (8) da biste preuzeli SERVICE_TRIGGER_INFO.
- Dokumentacija: QueryServiceConfig2[W/A] i SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC preko MS-SCMR (udaljeno)
- SCM se može udaljeno upitati radi preuzimanja informacija o trigger-ima korišćenjem MS-SCMR. TrustedSec-ov Titanis ovo omogućava: `Scm.exe qtriggers`.
- Impacket definiše strukture u msrpc MS-SCMR; pomoću njih možete implementirati udaljeni upit.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeracija)
- Brzo izlistavanje svakog servisa koji izlaže `TriggerInfo` ključ:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programski)
- James Forshaw-ov `NtObjectManager` module izlaže `Get-Win32ServiceTrigger` za parsiranje metadata trigger-a bez scraping-a izlaza komande `sc.exe`.

## High-Value Trigger Types i načini njihovog aktiviranja

### Network Endpoint Triggers

Oni pokreću servis kada klijent pokuša da komunicira sa IPC endpoint-om. Korisni su za low-priv korisnike zato što će SCM automatski pokrenuti servis pre nego što vaš klijent zaista može da se poveže.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Ponašanje: Pokušaj povezivanja klijenta na \\.\pipe\<PipeName> izaziva SCM da pokrene servis kako bi on počeo da osluškuje.
- Aktiviranje (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Interna napomena: named-pipe trigger-i se oslanjaju na `npsvctrig.sys`, filesystem minifilter koji prati otvaranja registrovanih trigger pipe imena. Zato pokušaj otvaranja može pokrenuti servis čak i pre nego što je sam servis kreirao ili počeo da osluškuje pipe.<sup>[[5]](#references)</sup>
- Pogledajte i: Named Pipe Client Impersonation za post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Ponašanje: Upit Endpoint Mapper-a (EPM, TCP/135) za interface UUID povezan sa servisom izaziva SCM da ga pokrene kako bi mogao da registruje svoj endpoint.
- Aktiviranje (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Servis može registrovati trigger vezan za ETW provider/event. Ako nisu konfigurisani dodatni filteri (keyword/level/binary/string), svaki događaj tog provider-a pokrenuće servis.<sup>[[1]](#references)</sup>

- Primer (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Izlistavanje trigger-a: `sc.exe qtriggerinfo webclient`
- Provera da li je provider registrovan: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitovanje odgovarajućih događaja obično zahteva code koji loguje u taj provider; ako nema filtera, dovoljan je bilo koji događaj.
- Minimalni C oblik za aktiviranje provider-a (kada nisu konfigurisani dodatni ETW filteri):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Podtipovi: Machine/User. Na domain-joined hostovima na kojima postoji odgovarajuća policy, trigger se izvršava pri boot-u. Sam `gpupdate` neće aktivirati trigger bez izmena, ali:<sup>[[1]](#references)</sup>

- Aktiviranje: `gpupdate /force`
- Ako relevantni tip policy-ja postoji, ovo pouzdano izaziva aktiviranje trigger-a i pokretanje servisa.

### IP Address Available

Aktivira se kada se dobije prva IP adresa (ili izgubi poslednja). Često se aktivira pri boot-u.<sup>[[1]](#references)</sup>

- Aktiviranje: Prekinite i ponovo uspostavite konektivnost da biste ponovo aktivirali trigger, na primer:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Pokreće servis kada stigne odgovarajući device interface. Ako nije naveden nijedan data item, bilo koji uređaj koji odgovara GUID-u podtipa trigger-a aktiviraće trigger. Proverava se pri boot-u i nakon hot-plug događaja.<sup>[[1]](#references)</sup>

- Aktiviranje: Povežite/ubacite uređaj (fizički ili virtuelni) koji odgovara class/hardware ID-ju navedenom u podtipu trigger-a.

### Domain Join State

Uprkos zbunjujućem MSDN opisu, ovo proverava stanje domena pri boot-u:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → pokrenuti servis ako je računar domain-joined
- DOMAIN_LEAVE_GUID → pokrenuti servis samo ako računar nije domain-joined

### System State Change – WNF (undocumented)

Neki servisi koriste undocumented WNF-based trigger-e (SERVICE_TRIGGER_TYPE 0x7). Aktiviranje zahteva objavljivanje relevantnog WNF state-a; detalji zavise od naziva state-a. Istraživačka pozadina: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Primećeni su na Windows 11 za neke servise (npr. CDPSvc). Agregirana konfiguracija čuva se u:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Vrednost Trigger servisa je GUID; subkey sa tim GUID-om definiše agregirani događaj. Aktiviranje bilo kog constituent event-a pokreće servis.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Primećeno je da se trigger ograničen na određeni port/protocol aktivira pri bilo kojoj promeni firewall pravila (disable/delete/add), a ne samo za navedeni port. Još gore, konfigurisanje porta bez protocol-a može oštetiti BFE startup nakon reboot-a, što se može proširiti na mnoge otkaze servisa i onemogućiti upravljanje firewall-om. Postupajte sa izuzetnim oprezom.<sup>[[1]](#references)</sup>

## Practical Workflow

1) Enumerišite trigger-e na interesantnim servisima (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ako postoji Network Endpoint trigger:
- Named pipe → pokušajte otvaranje klijenta prema \\.\pipe\<PipeName>
- RPC endpoint → izvršite Endpoint Mapper lookup za interface UUID

3) Ako postoji ETW trigger:
- Proverite provider i filtere pomoću `sc.exe qtriggerinfo`; ako nema filtera, bilo koji događaj tog provider-a pokrenuće servis

4) Za Group Policy/IP/Device/Domain trigger-e:
- Koristite environmental levers: `gpupdate /force`, uključivanje/isključivanje NIC-ova, hot-plug uređaja itd.

## Related

- Nakon pokretanja privilegovanog servisa putem Named Pipe trigger-a, možda ćete moći da ga impersonate-ujete:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Izlistavanje trigger-a (lokalno): `sc.exe qtriggerinfo <Service>`
- Registry prikaz: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider provera (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Prvo proverite start type servisa pomoću `sc.exe qc <Service>`. Ako je `DISABLED`, aktiviranje trigger-a nije dovoljno; najpre morate pronaći način da promenite konfiguraciju.
- Trigger-start servisi se mogu ponovo zaustaviti nakon što postanu idle. Ako vaš follow-on action zavisi od kratkotrajno dostupnog listener-a (RPC/named pipe/WebDAV), aktivirajte trigger i odmah ga iskoristite.
- `sc.exe qtriggerinfo` ne razume u potpunosti svaki undocumented trigger type. Za aggregate trigger-e na novijim Windows build-ovima potvrdite backing GUID i constituent events u `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Napravite baseline i audit TriggerInfo podataka za sve servise. Takođe pregledajte HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents za aggregate trigger-e.
- Pratite sumnjive EPM lookup-e za UUID-ove privilegovanih servisa i pokušaje povezivanja na named pipe koji prethode pokretanju servisa.
- Ograničite ko može da menja service trigger-e; neočekivane BFE greške nakon izmena trigger-a tretirajte kao sumnjive.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
