# Windows Service Triggers: Enumeracja i nadużycia

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers pozwalają Service Control Manager (SCM) uruchamiać/zatrzymywać usługę, gdy wystąpi określony warunek (np. stanie się dostępny adres IP, zostanie podjęta próba połączenia z named pipe lub zostanie opublikowane zdarzenie ETW). Nawet jeśli nie masz uprawnień SERVICE_START do docelowej usługi, nadal możesz być w stanie ją uruchomić, powodując aktywację jej triggera.<sup>[[1]](#references)</sup>

Ta strona koncentruje się na przyjaznej atakującemu enumeracji oraz prostych sposobach aktywowania popularnych triggerów.

> Wskazówka: Uruchomienie uprzywilejowanej wbudowanej usługi (np. RemoteRegistry, WebClient/WebDAV, EFS) może udostępnić nowe listenery RPC/named pipe i otworzyć drogę do kolejnych abuse chains.

## Enumeracja Service Triggers

- sc.exe (lokalnie)
- Wyświetlenie triggerów usługi: `sc.exe qtriggerinfo <ServiceName>`
- Registry (lokalnie)
- Triggery znajdują się w: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekurencyjny dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (lokalnie)
- Wywołaj QueryServiceConfig2 z SERVICE_CONFIG_TRIGGER_INFO (8), aby pobrać SERVICE_TRIGGER_INFO.
- Dokumentacja: QueryServiceConfig2[W/A] i SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC przez MS-SCMR (zdalnie)
- SCM można odpytać zdalnie w celu pobrania informacji o triggerach za pomocą MS-SCMR. Titanis firmy TrustedSec udostępnia tę funkcję: `Scm.exe qtriggers`.
- Impacket definiuje struktury w msrpc MS-SCMR; możesz za ich pomocą zaimplementować zdalne zapytanie.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (enumeracja zbiorcza)
- Szybkie wyświetlenie każdej usługi udostępniającej klucz `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programowo)
- Moduł `NtObjectManager` autorstwa Jamesa Forshawa udostępnia `Get-Win32ServiceTrigger` do parsowania metadanych triggerów bez przetwarzania wyjścia `sc.exe`.

## Najcenniejsze typy triggerów i sposoby ich aktywacji

### Network Endpoint Triggers

Uruchamiają usługę, gdy klient próbuje komunikować się z endpointem IPC. Są przydatne dla użytkowników o niskich uprawnieniach, ponieważ SCM automatycznie uruchomi usługę, zanim klient faktycznie będzie mógł się z nią połączyć.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Działanie: Próba połączenia klienta z \\.\pipe\<PipeName> powoduje, że SCM uruchamia usługę, aby mogła rozpocząć nasłuchiwanie.
- Aktywacja (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Uwaga dotycząca działania wewnętrznego: Triggery named pipe są obsługiwane przez `npsvctrig.sys`, czyli filesystem minifilter monitorujący otwarcia zarejestrowanych nazw triggerów pipe. Dlatego próba otwarcia może uruchomić usługę, zanim sama usługa utworzy pipe lub rozpocznie na nim nasłuchiwanie.<sup>[[5]](#references)</sup>
- Zobacz także: Named Pipe Client Impersonation w celu wykorzystania usługi po jej uruchomieniu.

- RPC endpoint trigger (Endpoint Mapper)
- Działanie: Odpytywanie Endpoint Mapper (EPM, TCP/135) o interface UUID powiązany z usługą powoduje, że SCM ją uruchamia, aby mogła zarejestrować swój endpoint.
- Aktywacja (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Usługa może zarejestrować trigger powiązany z providerem/zdarzeniem ETW. Jeśli nie skonfigurowano dodatkowych filtrów (keyword/level/binary/string), dowolne zdarzenie od tego providera uruchomi usługę.<sup>[[1]](#references)</sup>

- Przykład (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Wyświetlenie triggera: `sc.exe qtriggerinfo webclient`
- Sprawdzenie, czy provider jest zarejestrowany: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitowanie pasujących zdarzeń zazwyczaj wymaga kodu logującego do tego providera; jeśli nie ma filtrów, wystarczy dowolne zdarzenie.
- Minimalny kształt kodu C do wyzwolenia providera (gdy nie skonfigurowano dodatkowych filtrów ETW):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Podtypy: Machine/User. Na hostach dołączonych do domeny, na których istnieje odpowiednia policy, trigger uruchamia się podczas boot. Samo `gpupdate` nie uruchomi triggera bez zmian, ale:<sup>[[1]](#references)</sup>

- Aktywacja: `gpupdate /force`
- Jeśli istnieje odpowiedni typ policy, spowoduje to niezawodną aktywację triggera i uruchomienie usługi.

### IP Address Available

Uruchamia się po uzyskaniu pierwszego adresu IP (lub utracie ostatniego). Często aktywuje się podczas boot.<sup>[[1]](#references)</sup>

- Aktywacja: Przełącz łączność, aby ponownie wywołać trigger, np.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Uruchamia usługę po pojawieniu się pasującego interfejsu urządzenia. Jeśli nie określono elementu danych, dowolne urządzenie pasujące do GUID podtypu triggera aktywuje trigger. Jest sprawdzany podczas boot oraz po hot-plug.<sup>[[1]](#references)</sup>

- Aktywacja: Podłącz/włóż urządzenie (fizyczne lub wirtualne) pasujące do klasy/hardware ID określonego przez podtyp triggera.

### Domain Join State

Pomimo mylącego sformułowania w MSDN, ten trigger sprawdza stan domeny podczas boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → uruchom usługę, jeśli host jest dołączony do domeny
- DOMAIN_LEAVE_GUID → uruchom usługę tylko wtedy, gdy host NIE jest dołączony do domeny

### System State Change – WNF (undocumented)

Niektóre usługi używają undocumented triggerów opartych na WNF (SERVICE_TRIGGER_TYPE 0x7). Aktywacja wymaga opublikowania odpowiedniego stanu WNF; szczegóły zależą od nazwy stanu. Materiały wprowadzające: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Zaobserwowano je w Windows 11 dla niektórych usług (np. CDPSvc). Zagregowana konfiguracja jest przechowywana w:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Wartość Trigger usługi to GUID; podklucz z tym GUID definiuje zagregowane zdarzenie. Aktywacja dowolnego składowego zdarzenia uruchamia usługę.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Zaobserwowano, że trigger ograniczony do konkretnego portu/protokołu uruchamia się po dowolnej zmianie reguły firewalla (wyłączeniu/usunięciu/dodaniu), a nie tylko dla określonego portu. Co gorsza, skonfigurowanie portu bez protokołu może uszkodzić uruchamianie BFE po rebootach, powodując kaskadowe awarie wielu usług i uniemożliwiając zarządzanie firewallem. Należy zachować najwyższą ostrożność.<sup>[[1]](#references)</sup>

## Practical Workflow

1) Wylicz triggery interesujących usług (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Jeśli istnieje Network Endpoint trigger:
- Named pipe → spróbuj otworzyć pipe jako klient \\.\pipe\<PipeName>
- RPC endpoint → wykonaj zapytanie Endpoint Mapper dla interface UUID

3) Jeśli istnieje ETW trigger:
- Sprawdź providera i filtry za pomocą `sc.exe qtriggerinfo`; jeśli nie ma filtrów, dowolne zdarzenie od tego providera uruchomi usługę

4) Dla triggerów Group Policy/IP/Device/Domain:
- Użyj dźwigni środowiskowych: `gpupdate /force`, przełącz interfejsy NIC, podłącz urządzenia hot-plug itd.

## Related

- Po uruchomieniu uprzywilejowanej usługi za pomocą Named Pipe trigger możesz być w stanie dokonać jej impersonation:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Wyświetlenie triggerów (lokalnie): `sc.exe qtriggerinfo <Service>`
- Widok Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- Zdalny RPC (Titanis): `Scm.exe qtriggers`
- Sprawdzenie providera ETW (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Najpierw sprawdź typ uruchamiania usługi za pomocą `sc.exe qc <Service>`. Jeśli ma wartość `DISABLED`, aktywacja triggera nie wystarczy; najpierw musisz znaleźć sposób na zmianę konfiguracji.
- Usługi uruchamiane przez triggery mogą ponownie się zatrzymać po przejściu w stan bezczynności. Jeśli kolejne działanie zależy od krótkotrwałego listenera (RPC/named pipe/WebDAV), aktywuj trigger i użyj listenera natychmiast.
- `sc.exe qtriggerinfo` nie obsługuje w pełni każdego undocumented typu triggera. W przypadku aggregate triggerów w nowszych kompilacjach Windows potwierdź bazowy GUID i składowe zdarzenia w `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Utwórz baseline i przeprowadzaj audyt TriggerInfo dla usług. Sprawdź również `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` pod kątem aggregate triggerów.
- Monitoruj podejrzane zapytania EPM dotyczące UUID uprzywilejowanych usług oraz próby połączeń z named pipe poprzedzające uruchomienia usług.
- Ogranicz osoby, które mogą modyfikować triggery usług; nieoczekiwane awarie BFE po zmianach triggerów traktuj jako podejrzane.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
