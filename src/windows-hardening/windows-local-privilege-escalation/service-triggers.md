# Windows Service Triggers: Enumerasie en Misbruik

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers laat die Service Control Manager (SCM) 'n diens begin/stop wanneer 'n voorwaarde voorkom (bv. 'n IP-adres word beskikbaar, 'n named pipe-verbinding word probeer, 'n ETW-geleentheid word gepubliseer). Selfs as jy nie SERVICE_START-regte op 'n teikendiens het nie, mag jy steeds daarin slaag om dit te begin deur die trigger te laat afgaan.

Hierdie bladsy fokus op aanvaller-vriendelike enumerasie en lae-wrywing metodes om algemene triggers te aktiveer.

> Wenk: Om 'n bevoorregte ingeboude diens te begin (bv. RemoteRegistry, WebClient/WebDAV, EFS) kan nuwe RPC-/named-pipe-luisteraars blootstel en verdere misbruikkettings ontsluit.

## Enumerasie van Service Triggers

- sc.exe (lokaal)
- Lys 'n diens se triggers: `sc.exe qtriggerinfo <ServiceName>`
- Register (lokaal)
- Triggers lê onder: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump rekursief: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (lokaal)
- Roep QueryServiceConfig2 met SERVICE_CONFIG_TRIGGER_INFO (8) om SERVICE_TRIGGER_INFO te bekom.
- Dokumentasie: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC oor MS‑SCMR (afgeleë)
- Die SCM kan op afstand bevra word om trigger-inligting te haal met MS‑SCMR. TrustedSec’s Titanis bied dit aan: `Scm.exe qtriggers`.
- Impacket definieer die strukture in msrpc MS-SCMR; jy kan 'n afgeleë navraag implementeer met behulp hiervan.

## Hoëwaarde Trigger-tipes en Hoe om dit te Aktiveer

### Netwerk-endpunt-triggers

Hierdie begin 'n diens wanneer 'n kliënt probeer kommunikeer met 'n IPC-endpunt. Nuttig vir lae-privilege gebruikers omdat die SCM die diens outomaties sal begin voordat jou kliënt eintlik kan verbind.

- Named pipe trigger
- Gedrag: 'n Kliënt se verbindingspoging na \\.\pipe\<PipeName> veroorsaak dat die SCM die diens begin sodat dit kan begin luister.
- Aktivering (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Sien ook: Named Pipe Client Impersonation vir post-start misbruik.

- RPC endpoint trigger (Endpoint Mapper)
- Gedrag: Navraag by die Endpoint Mapper (EPM, TCP/135) vir 'n interface UUID geassosieer met 'n diens veroorsaak dat die SCM dit begin sodat dit sy endpunt kan registreer.
- Aktivering (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Aangepaste (ETW) Triggers

'n Diens kan 'n trigger registreer gebind aan 'n ETW-provider/geleentheid. As daar geen addisionele filters (keyword/level/binary/string) gekonfigureer is nie, sal enige gebeurtenis van daardie provider die diens begin.

- Voorbeeld (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Lys trigger: `sc.exe qtriggerinfo webclient`
- Verifieer provider is geregistreer: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Om ooreenstemmende gebeurtenisse te stuur vereis gewoonlik kode wat na daardie provider log; as daar geen filters is nie, volstaan enige gebeurtenis.

### Groepsbeleid-triggers

Subtipes: Masjien/Gebruiker. Op domein-aangeslote hosts waar die ooreenstemmende beleid bestaan, voer die trigger by opstart uit. `gpupdate` alleen sal nie afvuur sonder veranderings nie, maar:

- Aktivering: `gpupdate /force`
- As die relevante beleidstipe bestaan, veroorsaak dit betroubaar dat die trigger afvuur en die diens begin.

### IP Address Available

Vuur af wanneer die eerste IP verkry word (of die laaste verlore). Word dikwels by opstart geaktiveer.

- Aktivering: Skakel connectivity om om weer te trigger, bv:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Toestel-koppelvlak-aankoms

Begin 'n diens wanneer 'n ooreenstemmende toestel-koppelvlak aanmeld. As geen data-item gespesifiseer is nie, sal enige toestel wat ooreenstem met die trigger-subtipe GUID die trigger afvuur. Word geëvalueer by opstart en by hot‑plug.

- Aktivering: Koppel/insteek 'n toestel (fisies of virtueel) wat pas by die klas/hardware-ID wat deur die trigger-subtipe spesifiseer is.

### Domein-join-status

Ten spyte van verwarrende MSDN-woordeskat, evalueer dit domeinstatus by opstart:
- DOMAIN_JOIN_GUID → begin die diens as dit aan 'n domein gekoppel is
- DOMAIN_LEAVE_GUID → begin die diens slegs as dit NIE aan 'n domein gekoppel is NIE

### Stelseltoestandverandering – WNF (ondokumenteer)

Sommige dienste gebruik ondokumenteerde WNF-gebaseerde triggers (SERVICE_TRIGGER_TYPE 0x7). Aktivering vereis die publiseer van die relevante WNF-staat; besonderhede hang af van die staatnaam. Navorsingsagtergrond: Windows Notification Facility internals.

### Geaggregeerde Service Triggers (ondokumenteer)

Waargeneem op Windows 11 vir sommige dienste (bv. CDPSvc). Die geaggregeerde konfigurasie word gestoor in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

'n Diens se Trigger-waarde is 'n GUID; die subsleutel met daardie GUID definieer die geaggregeerde gebeurtenis. Die trigger van enige samestellende gebeurtenis begin die diens.

### Firewall Port Event (eienaardighede en DoS-risiko)

'n Trigger wat geskoop is na 'n spesifieke poort/protokol is waargeneem om te begin op enige firewall-reëlverandering (deaktiveer/verwyder/toevoeg), nie net die gespesifiseerde poort nie. Erger, die konfigurasie van 'n poort sonder 'n protokol kan BFE-opstart oor herlaaie korrupteer, wat kan lei tot baie diensfoute en firewall-bestuur wat breek. Hanteer met uiterste omsigtigheid.

## Praktiese Werksvloei

1) Enumereer triggers op interessante dienste (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) As 'n Network Endpoint trigger bestaan:
- Named pipe → probeer 'n kliënt-open na \\.\pipe\<PipeName>
- RPC endpoint → voer 'n Endpoint Mapper-lookup uit vir die interface UUID

3) As 'n ETW trigger bestaan:
- Kontroleer provider en filters met `sc.exe qtriggerinfo`; as daar geen filters is nie, sal enige gebeurtenis van daardie provider die diens begin

4) Vir Groepsbeleid/IP/Toestel/Domein triggers:
- Gebruik omgewingshefbome: `gpupdate /force`, skakel NICs, hot-plug toestelle, ens.

## Verwante

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Vinnige opdrag-oorsig

- Lys triggers (lokaal): `sc.exe qtriggerinfo <Service>`
- Register-oorsig: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC afgeleë (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Opsporing en Verhardingswenke

- Maak baseline en oudit van TriggerInfo oor dienste. Hersien ook HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents vir geaggregeerde triggers.
- Monitor vir verdagte EPM-lookups vir bevoorregte diens-UUIDs en named-pipe-verbintenispogings wat diens-opstart voorafgaan.
- Beperk wie diens-triggers kan wysig; behandel onverwags BFE-foute na trigger-wysigings as verdag.

## Verwysings
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
