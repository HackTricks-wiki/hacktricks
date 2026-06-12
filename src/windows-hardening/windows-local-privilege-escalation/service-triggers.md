# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers erlauben es dem Service Control Manager (SCM), einen Dienst zu starten/stoppen, wenn ein Ereignis eintritt (z. B. wenn eine IP-Adresse verfügbar wird, ein Named Pipe-Verbindungsversuch erfolgt, ein ETW-Ereignis veröffentlicht wird). Selbst wenn dir auf einem Ziel-Dienst die SERVICE_START-Rechte fehlen, kannst du ihn möglicherweise trotzdem starten, indem du seinen Trigger auslöst.

Diese Seite konzentriert sich auf angreiferfreundliche Enumeration und einfache Wege, gängige Trigger zu aktivieren.

> Tip: Das Starten eines privilegierten integrierten Dienstes (z. B. RemoteRegistry, WebClient/WebDAV, EFS) kann neue RPC/named-pipe-Listener freilegen und weitere abuse chains ermöglichen.

## Enumerating Service Triggers

- sc.exe (local)
- Einen Trigger eines Dienstes auflisten: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger liegen unter: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekursiv dumpen: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Rufe QueryServiceConfig2 mit SERVICE_CONFIG_TRIGGER_INFO (8) auf, um SERVICE_TRIGGER_INFO abzurufen.
- Docs: QueryServiceConfig2[W/A] und SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC über MS‑SCMR (remote)
- Der SCM kann remote abgefragt werden, um Trigger-Infos über MS‑SCMR zu holen. TrustedSec’s Titanis stellt das bereit: `Scm.exe qtriggers`.
- Impacket definiert die Strukturen in msrpc MS-SCMR; du kannst damit eine Remote-Abfrage implementieren.
- PowerShell (bulk enumeration)
- Liste schnell jeden Dienst auf, der einen `TriggerInfo`-Key hat:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw’s `NtObjectManager`-Modul bietet `Get-Win32ServiceTrigger`, um Trigger-Metadaten zu parsen, ohne `sc.exe`-Output auszuwerten.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Diese starten einen Dienst, wenn ein Client versucht, mit einem IPC-Endpoint zu sprechen. Nützlich für Low-Priv-User, weil der SCM den Dienst automatisch startet, bevor dein Client tatsächlich verbinden kann.

- Named pipe trigger
- Verhalten: Ein Verbindungsversuch eines Clients zu \\.\pipe\<PipeName> führt dazu, dass der SCM den Dienst startet, damit er mit dem Lauschen beginnen kann.
- Aktivierung (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers werden von `npsvctrig.sys` unterstützt, einem Filesystem-Minifilter, der Öffnungen gegen registrierte Trigger-Pipe-Namen überwacht. Deshalb kann der Öffnungsversuch den Dienst starten, noch bevor der Dienst selbst die Pipe erstellt/angehört hat.
- See also: Named Pipe Client Impersonation für post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Verhalten: Eine Abfrage des Endpoint Mapper (EPM, TCP/135) nach einer Interface-UUID, die einem Dienst zugeordnet ist, führt dazu, dass der SCM ihn startet, damit er seinen Endpoint registrieren kann.
- Aktivierung (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Ein Dienst kann einen Trigger registrieren, der an einen ETW-Provider/Event gebunden ist. Wenn keine zusätzlichen Filter (keyword/level/binary/string) konfiguriert sind, startet jedes Event dieses Providers den Dienst.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Trigger auflisten: `sc.exe qtriggerinfo webclient`
- Prüfen, ob der Provider registriert ist: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Das Auslösen passender Events erfordert normalerweise Code, der in diesen Provider loggt; wenn keine Filter vorhanden sind, reicht jedes Event aus.
- Minimale C-Form zum Auslösen des Providers (wenn keine zusätzlichen ETW-Filter konfiguriert sind):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Auf Domain-joined-Hosts, auf denen die entsprechende Richtlinie existiert, läuft der Trigger beim Booten. `gpupdate` allein löst ihn ohne Änderungen nicht aus, aber:

- Aktivierung: `gpupdate /force`
- Wenn der relevante Policy-Typ existiert, führt das zuverlässig dazu, dass der Trigger auslöst und den Dienst startet.

### IP Address Available

Löst aus, wenn die erste IP bezogen wird (oder die letzte verloren geht). Triggert oft beim Booten.

- Aktivierung: Konnektivität umschalten, um erneut auszulösen, z. B.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Startet einen Dienst, wenn ein passendes Device Interface erscheint. Wenn kein Data Item angegeben ist, löst jedes Gerät aus, das zur Trigger-Subtype-GUID passt. Wird beim Booten und beim Hot-Plug ausgewertet.

- Aktivierung: Ein Gerät anhängen/einstecken (physisch oder virtuell), das zur Klasse/HW-ID passt, die durch den Trigger-Subtype angegeben ist.

### Domain Join State

Trotz verwirrender MSDN-Formulierung wird hier der Domain-Status beim Booten ausgewertet:
- DOMAIN_JOIN_GUID → starte den Dienst, wenn domain-joined
- DOMAIN_LEAVE_GUID → starte den Dienst nur, wenn NICHT domain-joined

### System State Change – WNF (undocumented)

Einige Dienste verwenden undokumentierte WNF-basierte Trigger (SERVICE_TRIGGER_TYPE 0x7). Die Aktivierung erfordert das Veröffentlichen des relevanten WNF-Status; Details hängen vom State Name ab. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Auf Windows 11 bei einigen Diensten beobachtet (z. B. CDPSvc). Die aggregierte Konfiguration wird gespeichert unter:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Der Trigger-Wert eines Dienstes ist eine GUID; der Subkey mit dieser GUID definiert das aggregierte Event. Das Auslösen eines beliebigen enthaltenen Events startet den Dienst.

### Firewall Port Event (quirks and DoS risk)

Es wurde beobachtet, dass ein Trigger für einen bestimmten Port/Protokoll bei jeder Firewall-Regeländerung (disable/delete/add) startet, nicht nur beim angegebenen Port. Noch schlimmer: Das Konfigurieren eines Ports ohne Protokoll kann den BFE-Start über Reboots hinweg beschädigen, was zu vielen Dienstfehlern und kaputter Firewall-Verwaltung führt. Mit äußerster Vorsicht behandeln.

## Practical Workflow

1) Trigger auf interessanten Diensten enumerieren (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Wenn ein Network Endpoint Trigger existiert:
- Named pipe → versuche ein Client-Open auf \\.\pipe\<PipeName>
- RPC endpoint → führe eine Endpoint-Mapper-Abfrage für die Interface-UUID aus

3) Wenn ein ETW-Trigger existiert:
- Prüfe Provider und Filter mit `sc.exe qtriggerinfo`; wenn keine Filter vorhanden sind, startet jedes Event dieses Providers den Dienst

4) Für Group Policy/IP/Device/Domain-Trigger:
- Nutze Umwelthebel: `gpupdate /force`, NICs umschalten, Geräte hot-pluggen, etc.

## Related

- Nachdem du einen privilegierten Dienst über einen Named Pipe trigger gestartet hast, kannst du ihn möglicherweise impersonaten:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Trigger auflisten (local): `sc.exe qtriggerinfo <Service>`
- Registry-Ansicht: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Prüfe zuerst den Starttyp des Dienstes mit `sc.exe qc <Service>`. Wenn er `DISABLED` ist, reicht das Auslösen des Triggers nicht; du musst zuerst eine Möglichkeit finden, die Konfiguration zu ändern.
- Trigger-start-Dienste können sich nach Inaktivität erneut stoppen. Wenn deine Folgeaktion von einem kurzlebigen Listener (RPC/named pipe/WebDAV) abhängt, triggere und nutze ihn sofort.
- `sc.exe qtriggerinfo` versteht nicht jeden undokumentierten Trigger-Typ vollständig. Bei aggregierten Triggern auf neueren Windows-Builds solltest du die zugrunde liegende GUID und die enthaltenen Events in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` bestätigen.

## Detection and Hardening Notes

- Baseline und audit TriggerInfo über alle Dienste. Prüfe außerdem HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents auf aggregierte Trigger.
- Überwache verdächtige EPM-Lookups für privilegierte Service-UUIDs und named-pipe-Verbindungsversuche, die Dienststarts vorausgehen.
- Beschränke, wer Service-Trigger ändern darf; behandle unerwartete BFE-Fehler nach Trigger-Änderungen als verdächtig.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
