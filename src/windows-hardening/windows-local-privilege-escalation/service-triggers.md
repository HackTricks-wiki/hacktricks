# Windows Service Triggers: Enumerazione e abuso

{{#include ../../banners/hacktricks-training.md}}

I Windows Service Triggers consentono al Service Control Manager (SCM) di avviare/arrestare un servizio quando si verifica una condizione (ad esempio, quando un indirizzo IP diventa disponibile, viene tentata una connessione a una named pipe o viene pubblicato un evento ETW). Anche quando non si dispone dei diritti `SERVICE_START` su un servizio target, potrebbe comunque essere possibile avviarlo causando l'attivazione del relativo trigger.<sup>[[1]](#references)</sup>

Questa pagina si concentra sull'enumerazione utile agli attacker e sui metodi a bassa complessità per attivare i trigger comuni.

> Suggerimento: l'avvio di un servizio integrato privilegiato (ad esempio RemoteRegistry, WebClient/WebDAV, EFS) può esporre nuovi listener RPC/named pipe e consentire ulteriori abuse chain.

## Enumerazione dei Service Triggers

- sc.exe (locale)
- Elencare i trigger di un servizio: `sc.exe qtriggerinfo <ServiceName>`
- Registry (locale)
- I trigger si trovano in: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Eseguire il dump ricorsivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (locale)
- Chiamare QueryServiceConfig2 con SERVICE_CONFIG_TRIGGER_INFO (8) per recuperare SERVICE_TRIGGER_INFO.
- Documentazione: QueryServiceConfig2[W/A] e SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC tramite MS-SCMR (remoto)
- Lo SCM può essere interrogato in remoto per recuperare le informazioni sui trigger utilizzando MS-SCMR. Titanis di TrustedSec espone questa funzionalità: `Scm.exe qtriggers`.
- Impacket definisce le strutture in msrpc MS-SCMR; è possibile implementare una query remota utilizzandole.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (enumerazione massiva)
- Elencare rapidamente ogni servizio che espone una chiave `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatico)
- Il modulo `NtObjectManager` di James Forshaw espone `Get-Win32ServiceTrigger` per analizzare i metadati dei trigger senza elaborare l'output di `sc.exe`.

## Tipi di trigger di alto valore e come attivarli

### Network Endpoint Triggers

Avviano un servizio quando un client tenta di comunicare con un endpoint IPC. Sono utili agli utenti low-priv perché lo SCM avvia automaticamente il servizio prima che il client possa effettivamente connettersi.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Comportamento: un tentativo di connessione del client a \\.\pipe\<PipeName> induce lo SCM ad avviare il servizio affinché possa iniziare l'ascolto.
- Attivazione (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Nota sugli internals: i named-pipe trigger sono supportati da `npsvctrig.sys`, un minifilter del filesystem che monitora le aperture verso i nomi delle pipe di trigger registrati. Per questo il tentativo di apertura può avviare il servizio anche prima che il servizio stesso abbia creato o iniziato ad ascoltare sulla pipe.<sup>[[5]](#references)</sup>
- Vedere anche: Named Pipe Client Impersonation per l'abuso post-start.

- RPC endpoint trigger (Endpoint Mapper)
- Comportamento: interrogare l'Endpoint Mapper (EPM, TCP/135) per un interface UUID associato a un servizio induce lo SCM ad avviarlo affinché possa registrare il proprio endpoint.
- Attivazione (Impacket):
```bash
# Interroga l'EPM locale; sostituire UUID con il GUID dell'interfaccia del servizio
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un servizio può registrare un trigger associato a un provider/evento ETW. Se non sono configurati filtri aggiuntivi (keyword/level/binary/string), qualsiasi evento proveniente da quel provider avvierà il servizio.<sup>[[1]](#references)</sup>

- Esempio (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Elencare il trigger: `sc.exe qtriggerinfo webclient`
- Verificare che il provider sia registrato: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- L'emissione di eventi corrispondenti richiede in genere codice che esegua il logging verso quel provider; se non sono presenti filtri, è sufficiente qualsiasi evento.
- Struttura C minima per generare un evento dal provider (quando non sono configurati filtri ETW aggiuntivi):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Sottotipi: Machine/User. Negli host aggiunti a un dominio in cui esiste la policy corrispondente, il trigger viene eseguito all'avvio. `gpupdate` da solo non attiva il trigger in assenza di modifiche, tuttavia:<sup>[[1]](#references)</sup>

- Attivazione: `gpupdate /force`
- Se esiste il tipo di policy rilevante, questa operazione causa in modo affidabile l'attivazione del trigger e l'avvio del servizio.

### IP Address Available

Si attiva quando viene ottenuto il primo IP (o quando viene perso l'ultimo). Spesso si attiva all'avvio.<sup>[[1]](#references)</sup>

- Attivazione: disattivare e riattivare la connettività per riattivarlo, ad esempio:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Avvia un servizio quando arriva un'interfaccia di dispositivo corrispondente. Se non è specificato alcun data item, qualsiasi dispositivo corrispondente al GUID del sottotipo del trigger attiverà il trigger. Viene valutato all'avvio e durante l'hot-plug.<sup>[[1]](#references)</sup>

- Attivazione: collegare/inserire un dispositivo (fisico o virtuale) corrispondente alla classe/hardware ID specificata dal sottotipo del trigger.

### Domain Join State

Nonostante la formulazione ambigua di MSDN, questo stato viene valutato all'avvio:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → avvia il servizio se il computer è aggiunto a un dominio
- DOMAIN_LEAVE_GUID → avvia il servizio solo se il computer NON è aggiunto a un dominio

### System State Change – WNF (undocumented)

Alcuni servizi utilizzano trigger basati su WNF non documentati (`SERVICE_TRIGGER_TYPE 0x7`). L'attivazione richiede la pubblicazione dello stato WNF rilevante; i dettagli dipendono dal nome dello stato. Informazioni di ricerca: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Osservati su Windows 11 per alcuni servizi (ad esempio, CDPSvc). La configurazione aggregata è memorizzata in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Il valore Trigger di un servizio è un GUID; la sottochiave con quel GUID definisce l'evento aggregato. L'attivazione di un qualsiasi evento costituente avvia il servizio.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

È stato osservato che un trigger associato a una porta/protocollo specifico si attiva in seguito a qualsiasi modifica a una firewall rule (disabilitazione/eliminazione/aggiunta), non solo per la porta specificata. Inoltre, configurare una porta senza un protocollo può corrompere l'avvio di BFE tra i reboot, causando a cascata il malfunzionamento di molti servizi e interrompendo la gestione del firewall. Usare con estrema cautela.<sup>[[1]](#references)</sup>

## Flusso di lavoro pratico

1) Enumerare i trigger sui servizi interessanti (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se esiste un Network Endpoint trigger:
- Named pipe → tentare un'apertura client verso \\.\pipe\<PipeName>
- RPC endpoint → eseguire una ricerca nell'Endpoint Mapper per l'interface UUID

3) Se esiste un ETW trigger:
- Controllare provider e filtri con `sc.exe qtriggerinfo`; se non sono presenti filtri, qualsiasi evento proveniente da quel provider avvierà il servizio

4) Per i trigger Group Policy/IP/Device/Domain:
- Utilizzare leve ambientali: `gpupdate /force`, disattivare e riattivare le NIC, collegare dispositivi tramite hot-plug, ecc.

## Correlati

- Dopo aver avviato un servizio privilegiato tramite un Named Pipe trigger, potrebbe essere possibile impersonarlo:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Riepilogo rapido dei comandi

- Elencare i trigger (locale): `sc.exe qtriggerinfo <Service>`
- Vista del Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remoto (Titanis): `Scm.exe qtriggers`
- Verifica del provider ETW (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotcha / note operative

- Controllare prima il tipo di avvio del servizio con `sc.exe qc <Service>`. Se è `DISABLED`, l'attivazione del trigger non è sufficiente; è prima necessario trovare un modo per modificare la configurazione.
- I servizi avviati da un trigger possono arrestarsi nuovamente dopo essere rimasti inattivi. Se l'azione successiva dipende da un listener di breve durata (RPC/named pipe/WebDAV), attivare il trigger e utilizzarlo immediatamente.
- `sc.exe qtriggerinfo` non comprende completamente ogni tipo di trigger non documentato. Per gli aggregate trigger sulle build più recenti di Windows, confermare il GUID di supporto e gli eventi costituenti in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Note su rilevamento e hardening

- Creare una baseline e controllare TriggerInfo per tutti i servizi. Esaminare anche HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents per gli aggregate trigger.
- Monitorare le query EPM sospette per gli UUID di servizi privilegiati e i tentativi di connessione a named pipe che precedono l'avvio dei servizi.
- Limitare chi può modificare i service trigger; considerare sospetti i malfunzionamenti di BFE successivi a modifiche ai trigger.

## Riferimenti
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
