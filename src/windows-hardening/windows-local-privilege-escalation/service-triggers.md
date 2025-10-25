# Windows Service Triggers: Enumeracija i zloupotreba

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers omogućavaju Service Control Manageru (SCM) da pokrene/zaustavi servis kada se desi određeni uslov (npr. dostupna IP adresa, pokušaj konekcije na named pipe, objavljen ETW događaj). Čak i bez prava SERVICE_START na ciljnom servisu, i dalje možete uspeti da ga pokrenete izazivanjem odgovarajućeg triggera.

Ova stranica se fokusira na tehnike za jednostavnu enumeraciju i niske-frikcijske načine aktiviranja uobičajenih triggera.

Savjet: Pokretanje privilegovanog ugrađenog servisa (npr. RemoteRegistry, WebClient/WebDAV, EFS) može otkriti nove RPC/named-pipe slušaoce i otvoriti mogućnosti za dalje zloupotrebe.

## Enumeracija Service Triggera

- sc.exe (lokalno)
- Listing triggera servisa: `sc.exe qtriggerinfo <ServiceName>`
- Registry (lokalno)
- Triggeri su pod: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump rekurzivno: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (lokalno)
- Pozvati QueryServiceConfig2 sa SERVICE_CONFIG_TRIGGER_INFO (8) da dobijete SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] i SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC preko MS‑SCMR (remote)
- SCM se može upitati udaljeno da bi se dobile informacije o triggerima koristeći MS‑SCMR. TrustedSec‑ov Titanis izlaže ovo: `Scm.exe qtriggers`.
- Impacket definiše strukture u msrpc MS-SCMR; možete implementirati udaljeni upit koristeći te strukture.

## Tipovi visokovrednih triggera i kako ih aktivirati

### Network Endpoint Triggers

Pokreću servis kada klijent pokuša da komunicira sa IPC endpoint-om. Korisno za korisnike sa niskim privilegijama jer SCM automatski pokreće servis pre nego što klijent stvarno može da se poveže.

- Named pipe trigger
- Ponašanje: Pokušaj klijentske konekcije na \\.\pipe\<PipeName> izaziva da SCM pokrene servis kako bi počeo da sluša.
- Aktivacija (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Vidi takođe: Named Pipe Client Impersonation za zloupotrebu nakon starta.

- RPC endpoint trigger (Endpoint Mapper)
- Ponašanje: Upit Endpoint Mapperu (EPM, TCP/135) za interface UUID povezan sa servisom izaziva da SCM pokrene servis kako bi registrovao svoj endpoint.
- Aktivacija (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Servis može registrovati trigger vezan za ETW provider/događaj. Ako nema dodatnih filtera (keyword/level/binary/string), bilo koji događaj od tog providera će pokrenuti servis.

- Primer (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List triggera: `sc.exe qtriggerinfo webclient`
- Provera da li je provider registrovan: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emisjonovanje odgovarajućih događaja obično zahteva kod koji loguje tom provideru; ako nema filtera, dovoljan je bilo koji događaj.

### Group Policy Triggers

Podtipovi: Machine/User. Na domain-joined hostovima gde odgovarajuća politika postoji, trigger se pokreće pri boot-u. Sam `gpupdate` bez promena neće izazvati trigger, ali:

- Aktivacija: `gpupdate /force`
- Ako odgovarajući tip politike postoji, ovo pouzdano izaziva fire trigger i startuje servis.

### IP Address Available

Okida kada se dobije prva IP adresa (ili izgubi poslednja). Često se aktivira pri boot-u.

- Aktivacija: Isključite/ponovo uključite konektivnost da ponovo izazovete trigger, npr.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Pokreće servis kada stigne odgovarajući device interface. Ako nije specificiran data item, bilo koji uređaj koji odgovara trigger subtype GUID‑u će pokrenuti trigger. Procjenjuje se pri boot-u i pri hot‑plug događajima.

- Aktivacija: Povežite/ubacite uređaj (fizički ili virtuelni) koji odgovara class/hardware ID navedenom u trigger subtype‑u.

### Domain Join State

Iako MSDN formulacija može biti zbunjujuća, ovo ocenjuje stanje domena pri boot-u:
- DOMAIN_JOIN_GUID → startuje servis ako je mašina u domenu
- DOMAIN_LEAVE_GUID → startuje servis samo ako NIJE u domenu

### System State Change – WNF (nedokumentovano)

Neki servisi koriste nedokumentovane WNF‑based triggere (SERVICE_TRIGGER_TYPE 0x7). Aktivacija zahteva publish odgovarajućeg WNF stanja; detalji zavise od imena stanja. Pozadinsko istraživanje: internals Windows Notification Facility.

### Aggregate Service Triggers (nedokumentovano)

Primećeno na Windows 11 za neke servise (npr. CDPSvc). Agregovana konfiguracija je pohranjena u:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Vrednost Trigger servisa je GUID; subkey sa tim GUID‑om definiše agregirani događaj. Okidanje bilo kojeg sastavnog događaja pokreće servis.

### Firewall Port Event (quirks i rizik DoS)

Trigger vezan za specifičan port/protokol primećen je da se pokreće na svaku promenu firewall pravila (disable/delete/add), ne samo za navedeni port. Još gore, konfigurisanje porta bez protokola može korumpirati BFE startup preko rebootova, što dovodi do kaskadnog pada mnogih servisa i onemogućava upravljanje firewall‑om. Postupajte sa ekstremnim oprezom.

## Praktični workflow

1) Enumerišite triggere na zanimljivim servisima (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ako postoji Network Endpoint trigger:
- Named pipe → pokušajte klijentsko otvaranje \\.\pipe\<PipeName>
- RPC endpoint → izvršite Endpoint Mapper lookup za interface UUID

3) Ako postoji ETW trigger:
- Proverite providera i filtere sa `sc.exe qtriggerinfo`; ako nema filtera, bilo koji događaj od tog providera će pokrenuti servis

4) Za Group Policy/IP/Device/Domain triggere:
- Koristite okolinske poluge: `gpupdate /force`, toggle NIC-ove, hot‑plug uređaje, itd.

## Povezano

- Nakon pokretanja privilegovanog servisa preko Named Pipe triggera, možda ćete moći da ga impersonirate:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Brzi pregled komandi

- List triggers (lokalno): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Napomene za detekciju i hardening

- Uspostavite baseline i audituje TriggerInfo preko servisa. Takođe pregledajte `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` za agregirane triggere.
- Monitorišite sumnjive EPM upite za UUID‑ove privilegovanih servisa i pokušaje konekcije na named‑pipe pre nego što se servis pokrene.
- Ograničite ko može menjati service triggere; tretirajte neočekivane BFE greške nakon promena triggera kao sumnjive.

## Reference
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
