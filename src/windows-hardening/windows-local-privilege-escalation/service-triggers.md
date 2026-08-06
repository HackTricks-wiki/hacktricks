# Windows Service Triggers: Aufzählung und Missbrauch

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers ermöglichen es dem Service Control Manager (SCM), einen Service zu starten/stoppen, wenn eine Bedingung eintritt (z. B. wenn eine IP-Adresse verfügbar wird, eine Named-Pipe-Verbindung versucht wird oder ein ETW-Ereignis veröffentlicht wird). Selbst wenn dir SERVICE_START-Berechtigungen für einen Zielservice fehlen, kannst du ihn möglicherweise dennoch starten, indem du seinen Trigger auslöst.<sup>[[1]](#references)</sup>

Diese Seite konzentriert sich auf eine angreiferfreundliche Aufzählung und unkomplizierte Methoden zum Aktivieren gängiger Trigger.

> Tipp: Das Starten eines privilegierten integrierten Services (z. B. RemoteRegistry, WebClient/WebDAV, EFS) kann neue RPC-/Named-Pipe-Listener verfügbar machen und weitere Abuse Chains ermöglichen.

## Aufzählen von Service Triggers

- sc.exe (lokal)
- Trigger eines Services auflisten: `sc.exe qtriggerinfo <ServiceName>`
- Registry (lokal)
- Trigger befinden sich unter: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekursiv ausgeben: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (lokal)
- QueryServiceConfig2 mit SERVICE_CONFIG_TRIGGER_INFO (8) aufrufen, um SERVICE_TRIGGER_INFO abzurufen.
- Docs: QueryServiceConfig2[W/A] und SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC über MS-SCMR (remote)
- Der SCM kann remote abgefragt werden, um Trigger-Informationen über MS-SCMR abzurufen. TrustedSecs Titanis stellt dies bereit: `Scm.exe qtriggers`.
- Impacket definiert die Strukturen in msrpc MS-SCMR; damit kann eine remote Abfrage implementiert werden.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (umfangreiche Aufzählung)
- Schnell jeden Service auflisten, der einen `TriggerInfo`-Key bereitstellt:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatisch)
- James Forshaws `NtObjectManager`-Modul stellt `Get-Win32ServiceTrigger` bereit, um Trigger-Metadaten zu analysieren, ohne die Ausgabe von `sc.exe` zu parsen.

## Hochwertige Trigger-Typen und ihre Aktivierung

### Network Endpoint Triggers

Diese starten einen Service, wenn ein Client versucht, mit einem IPC-Endpoint zu kommunizieren. Das ist für Benutzer mit niedrigen Rechten nützlich, da der SCM den Service automatisch startet, bevor sich dein Client tatsächlich verbinden kann.<sup>[[1]](#references)</sup>

- Named-Pipe-Trigger
- Verhalten: Ein Client-Verbindungsversuch zu \\.\pipe\<PipeName> veranlasst den SCM, den Service zu starten, damit dieser mit dem Lauschen beginnen kann.
- Aktivierung (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Hinweis zu den Internals: Named-Pipe-Trigger werden von `npsvctrig.sys` unterstützt, einem Dateisystem-Minifilter, der das Öffnen registrierter Trigger-Pipe-Namen überwacht. Deshalb kann der Öffnungsversuch den Service starten, noch bevor der Service selbst die Pipe erstellt hat oder auf ihr lauscht.<sup>[[5]](#references)</sup>
- Siehe auch: Named Pipe Client Impersonation für Post-Start-Abuse.

- RPC-Endpoint-Trigger (Endpoint Mapper)
- Verhalten: Das Abfragen des Endpoint Mappers (EPM, TCP/135) nach einer mit einem Service verknüpften Interface-UUID veranlasst den SCM, den Service zu starten, damit dieser seinen Endpoint registrieren kann.
- Aktivierung (Impacket):
```bash
# Fragt den lokalen EPM ab; UUID durch die Interface-GUID des Services ersetzen
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Benutzerdefinierte (ETW-)Trigger

Ein Service kann einen an einen ETW-Provider bzw. ein ETW-Ereignis gebundenen Trigger registrieren. Wenn keine zusätzlichen Filter (Keyword/Level/Binary/String) konfiguriert sind, startet jedes Ereignis dieses Providers den Service.<sup>[[1]](#references)</sup>

- Beispiel (WebClient/WebDAV): Provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Trigger auflisten: `sc.exe qtriggerinfo webclient`
- Überprüfen, ob der Provider registriert ist: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Das Ausgeben passender Ereignisse erfordert normalerweise Code, der in diesen Provider loggt; wenn keine Filter vorhanden sind, genügt jedes Ereignis.
- Minimale C-Struktur zum Auslösen des Providers (wenn keine zusätzlichen ETW-Filter konfiguriert sind):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group-Policy-Trigger

Subtypen: Machine/User. Auf domain-joined Hosts, auf denen die entsprechende Policy vorhanden ist, wird der Trigger beim Boot ausgeführt. `gpupdate` allein löst ihn ohne Änderungen nicht aus, aber:<sup>[[1]](#references)</sup>

- Aktivierung: `gpupdate /force`
- Wenn der relevante Policy-Typ vorhanden ist, führt dies zuverlässig dazu, dass der Trigger ausgelöst und der Service gestartet wird.

### IP-Adresse verfügbar

Wird ausgelöst, wenn die erste IP-Adresse bezogen wird (oder die letzte verloren geht). Wird häufig beim Boot ausgelöst.<sup>[[1]](#references)</sup>

- Aktivierung: Verbindung umschalten, um den Trigger erneut auszulösen, z. B.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Ankunft einer Geräte-Schnittstelle

Startet einen Service, wenn eine passende Geräte-Schnittstelle verfügbar wird. Wenn kein Datenelement angegeben ist, löst jedes Gerät, das zur GUID des Trigger-Subtyps passt, den Trigger aus. Wird beim Boot und beim Hot-Plug überprüft.<sup>[[1]](#references)</sup>

- Aktivierung: Ein physisches oder virtuelles Gerät anschließen/einstecken, das zur durch den Trigger-Subtyp angegebenen Klasse bzw. Hardware-ID passt.

### Domain-Join-Status

Trotz der verwirrenden MSDN-Formulierung wird der Domain-Status beim Boot ausgewertet:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → Service starten, wenn der Host domain-joined ist
- DOMAIN_LEAVE_GUID → Service nur starten, wenn der Host NICHT domain-joined ist

### System State Change – WNF (undokumentiert)

Einige Services verwenden undokumentierte WNF-basierte Trigger (SERVICE_TRIGGER_TYPE 0x7). Für die Aktivierung muss der relevante WNF-Status veröffentlicht werden; die Details hängen vom Namen des Status ab. Forschungshintergrund: Internals der Windows Notification Facility.

### Aggregate Service Triggers (undokumentiert)

Wurde unter Windows 11 bei einigen Services beobachtet (z. B. CDPSvc). Die aggregierte Konfiguration wird gespeichert unter:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Der Trigger-Wert eines Services ist eine GUID; der Unterschlüssel mit dieser GUID definiert das aggregierte Ereignis. Das Auslösen eines beliebigen enthaltenen Ereignisses startet den Service.<sup>[[1]](#references)</sup>

### Firewall-Port-Ereignis (Besonderheiten und DoS-Risiko)

Es wurde beobachtet, dass ein auf einen bestimmten Port bzw. ein bestimmtes Protokoll beschränkter Trigger bei jeder Änderung einer Firewall-Regel (Deaktivieren/Löschen/Hinzufügen) startet, nicht nur beim angegebenen Port. Noch problematischer: Die Konfiguration eines Ports ohne Protokoll kann den BFE-Start über mehrere Reboots hinweg beschädigen, zahlreiche Service-Ausfälle verursachen und die Firewall-Verwaltung beeinträchtigen. Mit äußerster Vorsicht behandeln.<sup>[[1]](#references)</sup>

## Praktischer Workflow

1) Trigger auf interessanten Services aufzählen (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Wenn ein Network-Endpoint-Trigger vorhanden ist:
- Named Pipe → einen Client-Versuch zum Öffnen von \\.\pipe\<PipeName> durchführen
- RPC-Endpoint → eine Endpoint-Mapper-Abfrage nach der Interface-UUID durchführen

3) Wenn ein ETW-Trigger vorhanden ist:
- Provider und Filter mit `sc.exe qtriggerinfo` prüfen; wenn keine Filter vorhanden sind, startet jedes Ereignis dieses Providers den Service

4) Für Group-Policy-/IP-/Geräte-/Domain-Trigger:
- Umgebungsbedingungen nutzen: `gpupdate /force`, NICs umschalten, Geräte hot-pluggen usw.

## Verwandt

- Nach dem Starten eines privilegierten Services über einen Named-Pipe-Trigger kannst du möglicherweise dessen Identität annehmen:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Kurzübersicht der Befehle

- Trigger auflisten (lokal): `sc.exe qtriggerinfo <Service>`
- Registry-Ansicht: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW-Provider-Prüfung (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Stolperfallen / Hinweise für Operator

- Zuerst den Service-Starttyp mit `sc.exe qc <Service>` prüfen. Wenn er `DISABLED` ist, reicht das Auslösen des Triggers nicht aus; zuerst muss eine Möglichkeit gefunden werden, die Konfiguration zu ändern.
- Trigger-startende Services können nach dem Wechsel in den Idle-Zustand wieder stoppen. Wenn deine Folgeaktion von einem kurzlebigen Listener (RPC/Named Pipe/WebDAV) abhängt, den Trigger auslösen und den Listener sofort verwenden.
- `sc.exe qtriggerinfo` versteht nicht jeden undokumentierten Trigger-Typ vollständig. Bei Aggregate Triggers auf neueren Windows-Builds die zugrunde liegende GUID und die enthaltenen Ereignisse in `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` bestätigen.

## Hinweise zu Detection und Hardening

- TriggerInfo für alle Services als Baseline erfassen und auditieren. Außerdem `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` auf Aggregate Triggers überprüfen.
- Auf verdächtige EPM-Abfragen nach privilegierten Service-UUIDs und Named-Pipe-Verbindungsversuche achten, die Service-Starts vorausgehen.
- Einschränken, wer Service Triggers ändern darf; unerwartete BFE-Ausfälle nach Trigger-Änderungen als verdächtig behandeln.

## Referenzen
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
