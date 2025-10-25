# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers permettono al Service Control Manager (SCM) di avviare/fermare un servizio quando si verifica una condizione (es. un indirizzo IP diventa disponibile, viene tentata una connessione a una named pipe, viene pubblicato un evento ETW). Anche quando non si possiedono i diritti SERVICE_START su un servizio target, potrebbe comunque essere possibile avviarlo facendo scattare il suo trigger.

Questa pagina si concentra sull'enumerazione amichevole per l'attaccante e su modi a basso attrito per attivare trigger comuni.

> Tip: Avviare un servizio integrato privilegiato (es., RemoteRegistry, WebClient/WebDAV, EFS) può esporre nuovi listener RPC/named-pipe e sbloccare ulteriori catene di abuso.

## Enumerating Service Triggers

- sc.exe (locale)
- Elencare i trigger di un servizio: `sc.exe qtriggerinfo <ServiceName>`
- Registry (locale)
- I trigger risiedono sotto: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump ricorsivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (locale)
- Chiamare QueryServiceConfig2 con SERVICE_CONFIG_TRIGGER_INFO (8) per recuperare SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remoto)
- Lo SCM può essere interrogato da remoto per ottenere info sui trigger usando MS‑SCMR. TrustedSec’s Titanis espone questo: `Scm.exe qtriggers`.
- Impacket definisce le strutture in msrpc MS-SCMR; è possibile implementare una query remota usando quelle.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Questi avviano un servizio quando un client tenta di parlare con un endpoint IPC. Utile per utenti a basso privilegio perché lo SCM avvierà automaticamente il servizio prima che il client riesca realmente a connettersi.

- Named pipe trigger
- Comportamento: Un tentativo di connessione client a \\.\pipe\<PipeName> causa l'avvio del servizio da parte dello SCM in modo che possa cominciare ad ascoltare.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Vedi anche: Named Pipe Client Impersonation per abuso post-start.

- RPC endpoint trigger (Endpoint Mapper)
- Comportamento: Interrogare l'Endpoint Mapper (EPM, TCP/135) per un interface UUID associata a un servizio causa l'avvio del servizio così che questo possa registrare il suo endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un servizio può registrare un trigger legato a un provider/evento ETW. Se non sono configurati filtri aggiuntivi (keyword/level/binary/string), qualsiasi evento da quel provider avvierà il servizio.

- Esempio (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Elenca trigger: `sc.exe qtriggerinfo webclient`
- Verifica che il provider sia registrato: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emettere eventi corrispondenti normalmente richiede codice che logga su quel provider; se non ci sono filtri, qualsiasi evento è sufficiente.

### Group Policy Triggers

Sottotipi: Machine/User. Su host joinati al dominio dove esiste la corrispondente policy, il trigger viene eseguito all'avvio. `gpupdate` da solo non farà scattare il trigger senza cambiamenti, ma:

- Activation: `gpupdate /force`
- Se il tipo di policy rilevante esiste, questo causa in modo affidabile lo scatto del trigger e l'avvio del servizio.

### IP Address Available

Scatta quando viene ottenuto il primo IP (o quando l'ultimo viene perso). Spesso scatta all'avvio.

- Activation: Disabilitare/riabilitare la connettività per riattivare il trigger, es.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Avvia un servizio quando arriva un'interfaccia dispositivo corrispondente. Se non è specificato alcun data item, qualsiasi dispositivo che corrisponde al GUID del subtype del trigger farà scattare il trigger. Valutato all'avvio e al momento dell'hot‑plug.

- Activation: Collegare/inserire un dispositivo (fisico o virtuale) che corrisponda alla class/hardware ID specificata dal subtype del trigger.

### Domain Join State

Nonostante la wording confusa su MSDN, questo valuta lo stato di join del dominio all'avvio:
- DOMAIN_JOIN_GUID → avvia il servizio se joinato al dominio
- DOMAIN_LEAVE_GUID → avvia il servizio solo se NON joinato al dominio

### System State Change – WNF (undocumented)

Alcuni servizi usano trigger basati su WNF non documentati (SERVICE_TRIGGER_TYPE 0x7). L'attivazione richiede di pubblicare lo stato WNF rilevante; le specifiche dipendono dal nome dello stato. Background di ricerca: internals di Windows Notification Facility.

### Aggregate Service Triggers (undocumented)

Osservati su Windows 11 per alcuni servizi (es., CDPSvc). La configurazione aggregata è memorizzata in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Il valore Trigger di un servizio è un GUID; la sottochiave con quel GUID definisce l'evento aggregato. Attivando uno qualsiasi degli eventi costituenti si avvia il servizio.

### Firewall Port Event (quirks and DoS risk)

Un trigger limitato a una specifica porta/protocollo è stato osservato scattare su qualsiasi modifica di regola firewall (disabilita/elimina/aggiungi), non solo sulla porta specificata. Peggio, configurare una porta senza protocollo può corrompere l'avvio di BFE attraverso i reboot, causando il fallimento di molti servizi e rompendo la gestione del firewall. Trattare con estrema cautela.

## Practical Workflow

1) Enumerare i trigger sui servizi interessanti (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se esiste un Network Endpoint trigger:
- Named pipe → tentare un client open a \\.\pipe\<PipeName>
- RPC endpoint → eseguire una lookup di Endpoint Mapper per l'interface UUID

3) Se esiste un ETW trigger:
- Controllare provider e filtri con `sc.exe qtriggerinfo`; se non ci sono filtri, qualsiasi evento dal provider avvierà il servizio

4) Per Group Policy/IP/Device/Domain triggers:
- Usare leve ambientali: `gpupdate /force`, togglare NICs, hot‑plug di dispositivi, ecc.

## Related

- Dopo aver avviato un servizio privilegiato tramite un Named Pipe trigger, potresti essere in grado di impersonarlo:

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

- Baseline e auditare TriggerInfo su tutti i servizi. Revisionare anche HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents per i trigger aggregati.
- Monitorare lookup EPM sospetti per UUID di servizi privilegiati e tentativi di connessione a named-pipe che precedono l'avvio di servizi.
- Restringere chi può modificare i service triggers; considerare sospette le failure inaspettate di BFE dopo modifiche ai trigger.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
