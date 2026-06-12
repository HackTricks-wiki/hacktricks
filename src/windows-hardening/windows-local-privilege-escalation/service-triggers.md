# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers consentono al Service Control Manager (SCM) di avviare/arrestare un servizio quando si verifica una condizione (ad es. un indirizzo IP diventa disponibile, si tenta una connessione a una named pipe, viene pubblicato un evento ETW). Anche quando non hai i diritti SERVICE_START sul servizio bersaglio, potresti comunque riuscire ad avviarlo facendo scattare il suo trigger.

Questa pagina si concentra su enumerazione adatta a un attacker e su modi a basso attrito per attivare trigger comuni.

> Tip: Avviare un servizio built-in con privilegi elevati (ad es. RemoteRegistry, WebClient/WebDAV, EFS) può esporre nuovi listener RPC/named-pipe e sbloccare ulteriori catene di abuse.

## Enumerating Service Triggers

- sc.exe (local)
- Elenca i trigger di un servizio: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- I trigger si trovano sotto: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump ricorsivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Chiama QueryServiceConfig2 con SERVICE_CONFIG_TRIGGER_INFO (8) per recuperare SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- Lo SCM può essere interrogato da remoto per ottenere le informazioni sui trigger usando MS‑SCMR. Titanis di TrustedSec espone questa funzione: `Scm.exe qtriggers`.
- Impacket definisce le strutture in msrpc MS-SCMR; puoi implementare una query remota usando quelle.
- PowerShell (bulk enumeration)
- Elenca rapidamente ogni servizio che espone una chiave `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Il modulo `NtObjectManager` di James Forshaw espone `Get-Win32ServiceTrigger` per analizzare i metadati dei trigger senza fare scraping dell'output di `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Questi avviano un servizio quando un client tenta di parlare con un endpoint IPC. Utili per utenti low-priv perché lo SCM avvierà automaticamente il servizio prima che il client possa effettivamente connettersi.

- Named pipe trigger
- Comportamento: Un tentativo di connessione client a \\.\pipe\<PipeName> induce lo SCM ad avviare il servizio così che possa iniziare ad ascoltare.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: i named-pipe trigger sono supportati da `npsvctrig.sys`, un minifilter del filesystem che monitora le open verso i nomi di pipe trigger registrati. Ecco perché il tentativo di open può avviare il servizio anche prima che il servizio stesso abbia creato/iniziato ad ascoltare sulla pipe.
- See also: Named Pipe Client Impersonation per abuse post-start.

- RPC endpoint trigger (Endpoint Mapper)
- Comportamento: Interrogare l'Endpoint Mapper (EPM, TCP/135) per una interface UUID associata a un servizio induce lo SCM ad avviarlo così che possa registrare il suo endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un servizio può registrare un trigger legato a un provider/evento ETW. Se non sono configurati ulteriori filtri (keyword/level/binary/string), qualsiasi evento di quel provider avvierà il servizio.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emittere eventi corrispondenti di solito richiede codice che registri log su quel provider; se non ci sono filtri, basta qualsiasi evento.
- Minimal C shape for firing the provider (when no additional ETW filters are configured):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Su host joined al domain dove esiste la policy corrispondente, il trigger viene eseguito al boot. `gpupdate` da solo non lo attiverà senza modifiche, ma:

- Activation: `gpupdate /force`
- Se esiste il tipo di policy rilevante, questo fa scattare in modo affidabile il trigger e avvia il servizio.

### IP Address Available

Si attiva quando viene ottenuto il primo IP (o quando si perde l'ultimo). Spesso scatta al boot.

- Activation: Alterna la connettività per riattivarlo, ad es.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Avvia un servizio quando arriva una device interface corrispondente. Se non è specificato alcun data item, qualsiasi device che corrisponda al subtype GUID del trigger farà scattare il trigger. Valutato al boot e durante hot-plug.

- Activation: Collega/inserisci un device (fisico o virtuale) che corrisponda alla class/hardware ID specificata dal subtype del trigger.

### Domain Join State

Nonostante il testo ambiguo di MSDN, questo valuta lo stato del domain al boot:
- DOMAIN_JOIN_GUID → avvia il servizio se domain-joined
- DOMAIN_LEAVE_GUID → avvia il servizio solo se NON domain-joined

### System State Change – WNF (undocumented)

Alcuni servizi usano trigger WNF-based non documentati (SERVICE_TRIGGER_TYPE 0x7). L'attivazione richiede la pubblicazione del relativo stato WNF; i dettagli dipendono dal nome dello stato. Contesto di ricerca: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Osservati su Windows 11 per alcuni servizi (ad es. CDPSvc). La configurazione aggregata è memorizzata in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Il valore Trigger di un servizio è un GUID; il subkey con quel GUID definisce l'evento aggregato. Attivare uno qualsiasi degli eventi costituenti avvia il servizio.

### Firewall Port Event (quirks and DoS risk)

È stato osservato che un trigger limitato a una porta/protocollo specifici si avvia con qualsiasi modifica alla regola del firewall (disable/delete/add), non solo sulla porta specificata. Peggio ancora, configurare una porta senza un protocollo può corrompere l'avvio di BFE attraverso i reboot, innescando molte failure dei servizi e rompendo la gestione del firewall. Trattalo con estrema cautela.

## Practical Workflow

1) Enumera i trigger sui servizi interessanti (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se esiste un Network Endpoint trigger:
- Named pipe → tenta una open client su \\.\pipe\<PipeName>
- RPC endpoint → esegui una lookup Endpoint Mapper per l'interface UUID

3) Se esiste un trigger ETW:
- Verifica provider e filtri con `sc.exe qtriggerinfo`; se non ci sono filtri, qualsiasi evento di quel provider avvierà il servizio

4) Per trigger Group Policy/IP/Device/Domain:
- Usa leve ambientali: `gpupdate /force`, alterna le NIC, hot-plug dei device, ecc.

## Related

- Dopo aver avviato un servizio privilegiato via un Named Pipe trigger, potresti riuscire a impersonarlo:

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

- Controlla prima il service start type con `sc.exe qc <Service>`. Se è `DISABLED`, far scattare il trigger non basta; devi prima trovare un modo per cambiare la configurazione.
- I servizi avviati da trigger possono fermarsi di nuovo dopo essere diventati idle. Se la tua azione successiva dipende da un listener di breve durata (RPC/named pipe/WebDAV), attivalo e consumalo immediatamente.
- `sc.exe qtriggerinfo` non comprende completamente ogni tipo di trigger non documentato. Per i trigger aggregati sulle build Windows più recenti, conferma il GUID di supporto e gli eventi costituenti in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Baseline e audit di TriggerInfo su tutti i servizi. Controlla anche HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents per i trigger aggregati.
- Monitora lookup EPM sospette per UUID di servizi privilegiati e tentativi di connessione a named-pipe che precedono l'avvio dei servizi.
- Limita chi può modificare i trigger dei servizi; considera sospetti i failure inattesi di BFE dopo modifiche ai trigger.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
