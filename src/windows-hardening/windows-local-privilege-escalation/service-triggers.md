# Windows Service-Trigger: Aufklärung und Missbrauch

{{#include ../../banners/hacktricks-training.md}}

Windows Service-Trigger erlauben dem Service Control Manager (SCM), einen Dienst zu starten/stoppen, wenn eine Bedingung eintritt (z. B. eine IP-Adresse verfügbar wird, ein named pipe-Verbindungsversuch erfolgt, ein ETW-Ereignis veröffentlicht wird). Selbst wenn Sie keine SERVICE_START-Rechte für einen Ziel-Dienst haben, können Sie ihn möglicherweise dennoch starten, indem Sie dessen Trigger auslösen.

Diese Seite konzentriert sich auf angreiferfreundliche Aufklärung und einfache Möglichkeiten, gängige Trigger zu aktivieren.

> Tipp: Das Starten eines privilegierten integrierten Dienstes (z. B. RemoteRegistry, WebClient/WebDAV, EFS) kann neue RPC/named-pipe-Listener offenlegen und weitere Missbrauchsketten ermöglichen.

## Auflisten von Service-Triggern

- sc.exe (local)
- Trigger eines Dienstes auflisten: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger befinden sich unter: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekursiv ausgeben: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Call QueryServiceConfig2 with SERVICE_CONFIG_TRIGGER_INFO (8) to retrieve SERVICE_TRIGGER_INFO.
- Doku: QueryServiceConfig2[W/A] und SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- The SCM can be queried remotely to fetch trigger info using MS‑SCMR. TrustedSec’s Titanis exposes this: `Scm.exe qtriggers`.
- Impacket definiert die Strukturen in msrpc MS-SCMR; Sie können eine Remote-Abfrage mit diesen implementieren.

## Wertvolle Trigger‑Typen und wie man sie aktiviert

### Netzwerk-Endpunkt-Trigger

Diese starten einen Dienst, wenn ein Client versucht, mit einem IPC-Endpunkt zu kommunizieren. Für Benutzer mit geringen Rechten nützlich, da der SCM den Dienst automatisch startet, bevor Ihr Client tatsächlich verbinden kann.

- Named pipe trigger
- Verhalten: Ein Verbindungsversuch eines Clients zu \\.\pipe\<PipeName> veranlasst den SCM, den Dienst zu starten, damit er zu lauschen beginnen kann.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Siehe auch: Named Pipe Client Impersonation für Missbrauch nach dem Start.

- RPC endpoint trigger (Endpoint Mapper)
- Verhalten: Das Abfragen des Endpoint Mapper (EPM, TCP/135) nach einer Interface-UUID, die mit einem Dienst verknüpft ist, veranlasst den SCM, den Dienst zu starten, damit er seinen Endpunkt registrieren kann.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Ein Dienst kann einen Trigger registrieren, der an einen ETW-Provider/Ereignis gebunden ist. Wenn keine zusätzlichen Filter (keyword/level/binary/string) konfiguriert sind, reicht jedes Ereignis dieses Providers, um den Dienst zu starten.

- Beispiel (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Trigger auflisten: `sc.exe qtriggerinfo webclient`
- Überprüfen, ob der Provider registriert ist: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Das Aussenden passender Ereignisse erfordert typischerweise Code, der an diesen Provider loggt; wenn keine Filter vorhanden sind, genügt jedes Ereignis.

### Group Policy Triggers

Subtypen: Machine/User. Auf domain-joined Hosts, auf denen die entsprechende Richtlinie existiert, läuft der Trigger beim Boot. `gpupdate` alleine löst nichts aus, ohne Änderungen, aber:

- Activation: `gpupdate /force`
- Wenn der relevante Richtlinientyp vorhanden ist, verursacht das zuverlässig, dass der Trigger feuert und den Dienst startet.

### IP Address Available

Feuert, wenn die erste IP erhalten wird (oder die letzte verloren geht). Tritt oft beim Boot auf.

- Activation: Connectivity umschalten, um erneut auszulösen, z. B.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Startet einen Dienst, wenn ein passendes Geräte-Interface erscheint. Wenn kein data item angegeben ist, löst jedes Gerät, das mit der Trigger-Subtype-GUID übereinstimmt, den Trigger aus. Bewertet beim Boot und beim Hot‑plug.

- Activation: Ein Gerät (physisch oder virtuell) anschließen/einstecken, das der Klasse/hardware ID entspricht, die vom Trigger-Subtype spezifiziert ist.

### Domain Join State

Trotz verwirrender MSDN-Formulierungen wird hier der Domain-Status beim Boot ausgewertet:
- DOMAIN_JOIN_GUID → Dienst starten, wenn domain-joined
- DOMAIN_LEAVE_GUID → Dienst nur starten, wenn NICHT domain-joined

### System State Change – WNF (undokumentiert)

Einige Dienste nutzen undokumentierte WNF-basierte Trigger (SERVICE_TRIGGER_TYPE 0x7). Die Aktivierung erfordert das Publizieren des relevanten WNF-States; Details hängen vom State-Namen ab. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undokumentiert)

Beobachtet unter Windows 11 für einige Dienste (z. B. CDPSvc). Die aggregierte Konfiguration ist gespeichert in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Der Trigger-Wert eines Dienstes ist eine GUID; der Unterschlüssel mit dieser GUID definiert das aggregierte Ereignis. Das Auslösen eines beliebigen Bestandteils startet den Dienst.

### Firewall Port Event (quirks and DoS risk)

Ein auf einen bestimmten Port/Protokoll beschränkter Trigger wurde beobachtet, der bei jeder Änderung an einer Firewall-Regel (deaktivieren/löschen/hinzufügen) ausgelöst wird, nicht nur beim angegebenen Port. Schlimmer noch: Das Konfigurieren eines Ports ohne Protokoll kann den BFE-Start über Neustarts hinweg beschädigen, was zu vielen Dienstfehlern und gebrochener Firewall-Verwaltung führt. Mit äußerster Vorsicht behandeln.

## Praktisches Vorgehen

1) Trigger auf interessanten Diensten auflisten (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Wenn ein Network Endpoint trigger existiert:
- Named pipe → versuche, einen Client-Open zu \\.\pipe\<PipeName> durchzuführen
- RPC endpoint → führe einen Endpoint Mapper Lookup für die Interface-UUID durch

3) Wenn ein ETW trigger existiert:
- Prüfe Provider und Filter mit `sc.exe qtriggerinfo`; wenn keine Filter vorhanden sind, startet jedes Ereignis dieses Providers den Dienst

4) Für Group Policy/IP/Device/Domain Trigger:
- Verwende Umgebungshebel: `gpupdate /force`, NICs umschalten, Geräte hot-pluggen usw.

## Verwandte

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Schnelle Befehlzusammenfassung

- Trigger auflisten (lokal): `sc.exe qtriggerinfo <Service>`
- Registry-Ansicht: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW-Provider-Check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Erkennung und Härtungshinweise

- Baseline und Audit von TriggerInfo über Dienste hinweg. Ebenso HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents auf aggregierte Trigger prüfen.
- Überwache verdächtige EPM-Abfragen nach UUIDs privilegierter Dienste und named-pipe-Verbindungsversuche, die Service-Starts vorausgehen.
- Beschränke, wer Service-Trigger ändern darf; behandle unerwartete BFE-Fehler nach Trigger-Änderungen als verdächtig.

## Referenzen
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
