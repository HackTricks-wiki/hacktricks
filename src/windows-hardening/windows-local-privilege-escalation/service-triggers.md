# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers pozwalają Service Control Manager (SCM) uruchamiać/zatrzymywać usługę, gdy wystąpi określony warunek (np. adres IP staje się dostępny, podejmowana jest próba połączenia z named pipe, publikowane jest zdarzenie ETW). Nawet jeśli nie masz praw SERVICE_START do docelowej usługi, możesz nadal być w stanie ją uruchomić, wywołując jej trigger.

Ta strona koncentruje się na przyjaznym dla atakującego enum oraz na mało inwazyjnych sposobach aktywacji typowych triggerów.

> Tip: Uruchomienie uprzywilejowanej wbudowanej usługi (np. RemoteRegistry, WebClient/WebDAV, EFS) może ujawnić nowe RPC/named-pipe listenery i odblokować dalsze łańcuchy abuse.

## Enumerating Service Triggers

- sc.exe (local)
- Wypisz triggery usługi: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggery znajdują się pod: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Zrzut rekurencyjny: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Wywołaj QueryServiceConfig2 z SERVICE_CONFIG_TRIGGER_INFO (8), aby pobrać SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM można odpytać zdalnie, aby pobrać informacje o triggerach, używając MS‑SCMR. TrustedSec’s Titanis udostępnia to: `Scm.exe qtriggers`.
- Impacket definiuje struktury w msrpc MS-SCMR; możesz zaimplementować zdalne zapytanie, używając ich.
- PowerShell (bulk enumeration)
- Szybko wypisz każdą usługę, która ma klucz `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Moduł Jamesa Forshawa `NtObjectManager` udostępnia `Get-Win32ServiceTrigger` do parsowania metadanych triggerów bez scrape'owania wyjścia `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Te triggery uruchamiają usługę, gdy klient próbuje komunikować się z endpointem IPC. Są użyteczne dla low-priv users, ponieważ SCM automatycznie uruchomi usługę, zanim klient zdoła się faktycznie połączyć.

- Named pipe trigger
- Behaviour: Próba połączenia klienta z \\.\pipe\<PipeName> powoduje, że SCM uruchamia usługę, aby mogła zacząć nasłuch.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggery są wspierane przez `npsvctrig.sys`, filesystem minifilter, który obserwuje otwarcia względem zarejestrowanych nazw pipe triggerów. Dlatego próba otwarcia może uruchomić usługę jeszcze zanim sama usługa utworzy/nasłuchuje na pipe.
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behaviour: Odpytywanie Endpoint Mapper (EPM, TCP/135) o UUID interfejsu powiązany z usługą powoduje, że SCM uruchamia ją, aby mogła zarejestrować swój endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Usługa może zarejestrować trigger powiązany z providerem/zdarzeniem ETW. Jeśli nie skonfigurowano dodatkowych filtrów (keyword/level/binary/string), dowolne zdarzenie z tego providera uruchomi usługę.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitowanie pasujących eventów zwykle wymaga kodu, który loguje do tego providera; jeśli nie ma filtrów, wystarczy dowolne event.
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

Podtypy: Machine/User. Na hostach dołączonych do domeny, gdzie istnieje odpowiadająca polityka, trigger uruchamia się przy boot. `gpupdate` samo w sobie nie wywoła tego bez zmian, ale:

- Activation: `gpupdate /force`
- Jeśli istnieje odpowiedni typ polityki, to niezawodnie powoduje uruchomienie triggera i start usługi.

### IP Address Available

Uruchamia się, gdy pierwszy IP zostanie uzyskany (lub ostatni zostanie utracony). Często triggeruje przy boot.

- Activation: Przełącz łączność, aby wywołać trigger ponownie, np.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Uruchamia usługę, gdy pojawi się pasujący device interface. Jeśli nie podano żadnego itemu danych, dowolne urządzenie pasujące do GUID podtypu triggera wywoła trigger. Oceniane przy boot oraz po hot-plug.

- Activation: Podłącz/włóż urządzenie (fizyczne lub wirtualne), które pasuje do class/hardware ID określonego przez podtyp triggera.

### Domain Join State

Mimo mylącego brzmienia w MSDN, to ocenia stan domeny przy boot:
- DOMAIN_JOIN_GUID → uruchom usługę, jeśli host jest dołączony do domeny
- DOMAIN_LEAVE_GUID → uruchom usługę tylko jeśli host NIE jest dołączony do domeny

### System State Change – WNF (undocumented)

Niektóre usługi używają nieudokumentowanych triggerów opartych o WNF (SERVICE_TRIGGER_TYPE 0x7). Aktywacja wymaga opublikowania odpowiedniego stanu WNF; szczegóły zależą od nazwy stanu. Tło badawcze: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Zaobserwowane w Windows 11 dla niektórych usług (np. CDPSvc). Skonfigurowany agregat jest przechowywany w:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Wartość Trigger usługi to GUID; podklucz z tym GUID definiuje agregowany event. Wywołanie dowolnego składowego eventu uruchamia usługę.

### Firewall Port Event (quirks and DoS risk)

Trigger powiązany z konkretnym portem/protokółem zaobserwowano jako uruchamiający się przy dowolnej zmianie reguły firewalla (disable/delete/add), a nie tylko dla wskazanego portu. Co gorsza, skonfigurowanie portu bez protokołu może uszkodzić start BFE po rebootach, powodując lawinę błędów wielu usług i psując zarządzanie firewallem. Traktuj to z najwyższą ostrożnością.

## Practical Workflow

1) Enum triggerów na interesujących usługach (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Jeśli istnieje Network Endpoint trigger:
- Named pipe → spróbuj client open do \\.\pipe\<PipeName>
- RPC endpoint → wykonaj lookup w Endpoint Mapper dla UUID interfejsu

3) Jeśli istnieje ETW trigger:
- Sprawdź provider i filtry przez `sc.exe qtriggerinfo`; jeśli nie ma filtrów, dowolny event z tego provider uruchomi usługę

4) Dla triggerów Group Policy/IP/Device/Domain:
- Użyj dźwigni środowiskowych: `gpupdate /force`, przełączaj NIC, hot-plug urządzeń itd.

## Related

- Po uruchomieniu uprzywilejowanej usługi przez Named Pipe trigger możesz być w stanie ją impersonate:

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

- Najpierw sprawdź typ startu usługi przez `sc.exe qc <Service>`. Jeśli jest `DISABLED`, samo wywołanie triggera nie wystarczy; najpierw musisz znaleźć sposób na zmianę konfiguracji.
- Usługi uruchamiane przez trigger mogą ponownie się zatrzymać, gdy staną się idle. Jeśli dalsza akcja zależy od krótkotrwałego listenera (RPC/named pipe/WebDAV), wywołaj trigger i użyj go natychmiast.
- `sc.exe qtriggerinfo` nie w pełni rozumie każdy nieudokumentowany typ triggera. Dla aggregate triggers na nowszych buildach Windows potwierdź wspierający GUID i składowe eventy w `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Zbuduj baseline i audytuj TriggerInfo w usługach. Przejrzyj też `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` pod kątem aggregate triggers.
- Monitoruj podejrzane lookupy EPM dla UUID uprzywilejowanych usług oraz próby połączeń z named-pipe, które poprzedzają start usług.
- Ogranicz, kto może modyfikować triggery usług; traktuj nieoczekiwane awarie BFE po zmianach triggerów jako podejrzane.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
