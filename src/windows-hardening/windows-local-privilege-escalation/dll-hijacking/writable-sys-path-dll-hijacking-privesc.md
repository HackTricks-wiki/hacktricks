# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Αν μπορείτε να **γράψετε σε έναν κατάλογο του system-wide `PATH`** (όχι απλώς στο `PATH` του χρήστη σας), ενδέχεται να μπορέσετε να **κάνετε privilege escalation** στο σύστημα.

Αυτό μπορεί να γίνει κατάχρηση μέσω **DLL hijacking**, όταν μια υπηρεσία ή διεργασία με περισσότερα privileges προσπαθεί να φορτώσει ένα DLL που δεν υπάρχει στις προηγούμενες τοποθεσίες αναζήτησης και τελικά αναζητά στον εγγράψιμο κατάλογο του system `PATH`.

Μια εγγράψιμη καταχώρηση του Machine `PATH` είναι μόνο ένα **primitive**, όχι απόδειξη εκτέλεσης κώδικα. Για μια unpackaged εφαρμογή που χρησιμοποιεί την τυπική σειρά αναζήτησης, το `PATH` προσεγγίζεται μετά τα redirection, API sets, SxS, τη λίστα των loaded modules, τα KnownDLLs, τους καταλόγους της εφαρμογής και των Windows και τον τρέχοντα κατάλογο. Ένα full path ή η πολιτική `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` μπορεί να αποκλείσει πλήρως το `PATH`.<sup>[[4]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με το **DLL hijacking**, δείτε:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Εύρεση ενός DLL που λείπει

Αρχικά, **εντοπίστε μια διεργασία** που εκτελείται με **περισσότερα privileges** και προσπαθεί να **φορτώσει ένα DLL από έναν εγγράψιμο κατάλογο του system `PATH`**.

Θυμηθείτε ότι αυτή η τεχνική εξαρτάται από μια καταχώρηση του **Machine/System PATH**, όχι μόνο από το **User PATH**. Επομένως, πριν αφιερώσετε χρόνο στο Procmon, αξίζει να απαριθμήσετε τις καταχωρήσεις του **Machine PATH** και να ελέγξετε ποιες είναι εγγράψιμες:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Το κείμενο ACL μπορεί να είναι παραπλανητικό, επειδή η συμμετοχή σε ομάδες, τα deny ACEs και τα κληρονομημένα δικαιώματα επηρεάζουν το αποτέλεσμα. Σε μια εξουσιοδοτημένη δοκιμή, ένας έλεγχος create/delete επαληθεύει την **πραγματική πρόσβαση του τρέχοντος token** (είναι παρεμβατικός και μπορεί να δημιουργήσει alerts):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Επιβεβαίωση του effective `PATH` του target

Το Machine `PATH` που διαβάζεται από το registry είναι configuration data· ο loader χρησιμοποιεί το environment block του **target process**. Κάθε process διαθέτει ένα environment block, και ένα child συνήθως κληρονομεί ένα αντίγραφο του environment του parent του. Κατά συνέπεια, ένα long-running service μπορεί να διατηρεί μια παλαιότερη τιμή, ενώ ένα service που εκκινείται με custom environment μπορεί να διαφέρει από την τιμή που εμφανίζεται στο shell σας. Θεωρήστε ένα παρατηρημένο Procmon probe του ακριβούς directory από το target PID ως ground truth· αφού αλλάξετε το `PATH` σε lab, κάντε restart το σχετικό process tree ή reboot πριν καταλήξετε ότι το lookup δεν πραγματοποιείται.<sup>[[5]](#references)</sup>

Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι αυτά τα processes πιθανότατα εκτελούνται ήδη. Για να εντοπίσετε DLLs που τα services προσπαθούν και αποτυγχάνουν να φορτώσουν, εκκινήστε το Procmon όσο το δυνατόν νωρίτερα (πριν ξεκινήσουν τα processes) και, στη συνέχεια:

> [!WARNING]
> Η προσθήκη ενός user-writable directory στο Machine `PATH` **δημιουργεί την ευάλωτη συνθήκη**. Κάντε το μόνο σε ένα isolated research VM για να αποκαλύψετε ποια privileged processes φτάνουν στο `PATH`· σε assessed host, παρακολουθήστε το υπάρχον writable entry χωρίς να αλλάξετε το system configuration.<sup>[[1]](#references)</sup>

- **Δημιουργήστε** τον φάκελο `C:\privesc_hijacking` και προσθέστε το path `C:\privesc_hijacking` στη **System Path env variable**. Μπορείτε να το κάνετε **χειροκίνητα** ή με **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Εκκινήστε το **`procmon`** και μεταβείτε στο **`Options`** --> **`Enable boot logging`** και πατήστε **`OK`** στο prompt.
- Στη συνέχεια, κάντε **reboot**. Όταν γίνει επανεκκίνηση του υπολογιστή, το **`procmon`** θα ξεκινήσει να **καταγράφει** events άμεσα.
- Μόλις **ξεκινήσουν τα Windows, εκτελέστε ξανά το `procmon`**. Θα σας ενημερώσει ότι εκτελούνταν ήδη και θα σας **ρωτήσει αν θέλετε να αποθηκεύσετε** τα events σε ένα αρχείο. Απαντήστε **yes** και **αποθηκεύστε τα events σε ένα αρχείο**.
- **Αφού** δημιουργηθεί το **αρχείο**, κλείστε το ανοιχτό παράθυρο του **`procmon`** και ανοίξτε το **αρχείο events**.
- Προσθέστε αυτά τα **filters** για να βρείτε όλα τα DLLs που ένα **process προσπάθησε να φορτώσει** από τον writable φάκελο του System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το **boot logging απαιτείται μόνο για services που ξεκινούν πολύ νωρίς** ώστε να παρατηρηθούν διαφορετικά. Αν μπορείτε να **ενεργοποιήσετε το target service/program κατά απαίτηση** (για παράδειγμα, αλληλεπιδρώντας με το COM interface του, κάνοντας restart στο service ή εκκινώντας ξανά ένα scheduled task), συνήθως είναι ταχύτερο να διατηρήσετε ένα κανονικό Procmon capture με filters όπως **`Path contains .dll`**, **`Result is NAME NOT FOUND`** και **`Path begins with <writable_machine_path>`**.

### DLLs που δεν εντοπίστηκαν

Εκτελώντας αυτό σε ένα δωρεάν **virtual (vmware) Windows 11 machine**, πήρα τα εξής αποτελέσματα:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, αγνοήστε τα αποτελέσματα `.exe`. Τα missing-DLL probes προήλθαν από:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Το παρακάτω παράδειγμα χρησιμοποιεί την τεχνική που περιγράφεται σε αυτό το άρθρο σχετικά με [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Άλλοι υποψήφιοι που αξίζει να εξεταστούν

Το `WptsExtensions.dll` είναι ένα καλό παράδειγμα, αλλά δεν είναι το μοναδικό επαναλαμβανόμενο **phantom DLL** που εμφανίζεται σε privileged services. Οι σύγχρονοι hunting rules και οι public hijack catalogs εξακολουθούν να παρακολουθούν ονόματα όπως:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Κλασικός υποψήφιος για **SYSTEM** σε client systems. Χρήσιμο όταν ο writable directory βρίσκεται στο **Machine PATH** και το service κάνει probe στο DLL κατά την εκκίνηση. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Ενδιαφέρον σε **server editions**, επειδή το service εκτελείται ως **SYSTEM** και μπορεί να **ενεργοποιηθεί κατά απαίτηση από έναν normal user** σε ορισμένα builds, γεγονός που το καθιστά καλύτερο από περιπτώσεις που απαιτούν μόνο reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Συνήθως επιστρέφει αρχικά **`NT AUTHORITY\LOCAL SERVICE`**. Αυτό συχνά εξακολουθεί να επαρκεί, επειδή το token διαθέτει **`SeImpersonatePrivilege`**, οπότε μπορείτε να το συνδυάσετε με [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Αντιμετωπίστε αυτά τα ονόματα ως **triage hints**, όχι ως εγγυημένες επιτυχίες: εξαρτώνται από το **SKU/build** και η Microsoft μπορεί να αλλάξει τη συμπεριφορά μεταξύ releases. Το σημαντικό συμπέρασμα είναι να αναζητάτε **missing DLLs σε privileged services που διασχίζουν το Machine PATH**, ειδικά αν το service μπορεί να **ενεργοποιηθεί ξανά χωρίς reboot**.

### Επικυρώστε έναν υποψήφιο πριν τον weaponize

Ένα event `NAME NOT FOUND` από μόνο του δεν αρκεί. Πριν τοποθετήσετε ένα payload, επαληθεύστε ολόκληρη την αλυσίδα:<sup>[[1]](#references)[[4]](#references)</sup>

1. Το event ανήκει στο αναμενόμενο **PID, command line, service account και integrity level**, και το path που δεν βρέθηκε είναι ο ακριβής writable κατάλογος του Machine `PATH`.
2. Για το ίδιο DLL basename, κανένας προηγούμενος directory δεν επιστρέφει `SUCCESS` και το module δεν ικανοποιείται από τη loaded-module list, τα KnownDLLs, το redirection ή ένα SxS manifest.
3. Το probe επαναλαμβάνεται όταν ένας low-privileged user εκτελεί το intended trigger. Ένα boot-only lookup είναι αξιοποιήσιμο, αλλά λειτουργικά πολύ χειρότερο από ένα on-demand lookup.
4. Η αρχιτεκτονική του payload ταιριάζει με το process. Αν η εφαρμογή κάνει αργότερα resolve exports, κάντε proxy το legitimate DLL ή κάντε export τα αναμενόμενα symbols. Δείτε [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Αρχικά χρησιμοποιήστε ένα harmless canary DLL που καταγράφει το PID, την ταυτότητα και το timestamp. Στο Procmon, απαιτήστε ένα επιτυχημένο **`Load Image`** από το planted path αντί να υποθέτετε ότι ένα προηγούμενο file probe προκάλεσε execution.

### Exploitation

Για να κάνετε **privilege escalation**, κάντε hijack το **`WptsExtensions.dll`**. Μόλις είναι γνωστά το **path** και το **name**, δημιουργήστε το malicious DLL.

Μπορείτε να [**try to use any of these examples**](README.md#creating-and-compiling-dlls). Θα μπορούσατε να εκτελέσετε payloads όπως: να αποκτήσετε rev shell, να προσθέσετε έναν user, να εκτελέσετε ένα beacon...

> [!WARNING]
> Σημειώστε ότι **δεν εκτελούνται όλα τα services** ως **`NT AUTHORITY\SYSTEM`**. Ορισμένα εκτελούνται ως **`NT AUTHORITY\LOCAL SERVICE`**, το οποίο έχει **λιγότερα privileges**, επομένως η κατάχρηση ενός από αυτά τα services μπορεί να μη σας επιτρέψει να δημιουργήσετε νέο user.\
> Ωστόσο, αυτό το account διαθέτει το user right **`SeImpersonatePrivilege`**, οπότε μπορείτε να χρησιμοποιήσετε το [**Potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Σε αυτή την περίπτωση, ένα reverse shell είναι καλύτερη επιλογή από την προσπάθεια δημιουργίας user.

Το service **Task Scheduler** συνήθως εκτελείται ως **`NT AUTHORITY\SYSTEM`**, αλλά επαληθεύστε το πραγματικό deployment και μην συμπεραίνετε την execution identity μόνο από το όνομα του service:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Αφού **δημιουργήσετε το malicious Dll** (_στην περίπτωσή μου χρησιμοποίησα x64 rev shell και πήρα shell πίσω, αλλά το defender το τερμάτισε επειδή προερχόταν από το msfvenom_), αποθηκεύστε το στο writable System Path με το όνομα **WptsExtensions.dll** και κάντε **restart** στον υπολογιστή (ή κάντε restart στο service ή κάντε ό,τι απαιτείται για να εκτελεστεί ξανά το επηρεαζόμενο service/πρόγραμμα).

Όταν γίνει restart στο service, το **DLL θα πρέπει να φορτωθεί και να εκτελεστεί** (μπορείτε να **επαναχρησιμοποιήσετε** το trick με το **Procmon** για να ελέγξετε αν η **library φορτώθηκε όπως αναμενόταν**).

> [!NOTE]
> Σχεδιάστε το cleanup πριν από το triggering. Ένα service μπορεί να διατηρεί το DLL mapped και να κλειδώνει το αρχείο μέχρι να σταματήσει· για το `WptsExtensions.dll`, η διακοπή του Task Scheduler απαιτεί elevated rights. Αφού αποκτήσετε το επιθυμητό context, σταματήστε με ασφάλεια το target, αφαιρέστε το payload και επαναφέρετε οποιαδήποτε αλλαγή στο `PATH` που έγινε μόνο για το lab.<sup>[[1]](#references)</sup>

### Remediation / detection

Αφαιρέστε τα weak write grants από κάθε κατάλογο του Machine `PATH` και αφαιρέστε τα stale entries. Οι developers θα πρέπει να φορτώνουν trusted libraries χρησιμοποιώντας full path ή να περιορίζουν το resolution με τα `SetDefaultDllDirectories` / `LoadLibraryEx` search flags. Οι defenders μπορούν να συσχετίζουν αλλαγές στο Machine `PATH` με privileged processes που φορτώνουν DLLs από non-system, user-writable directories.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Το Windows DLL Hijacking (ελπίζουμε) αποσαφηνισμένο](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Ύποπτο DLL που φορτώθηκε για Persistence ή Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Σειρά αναζήτησης Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Μεταβλητές περιβάλλοντος](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
