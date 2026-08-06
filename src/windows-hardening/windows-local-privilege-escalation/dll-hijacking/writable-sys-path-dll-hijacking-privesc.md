# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Αν διαπιστώσετε ότι μπορείτε να **γράψετε σε έναν φάκελο του System Path** (σημειώστε ότι αυτό δεν θα λειτουργήσει αν μπορείτε να γράψετε σε έναν φάκελο του User Path), είναι πιθανό να μπορείτε να **κάνετε privilege escalation** στο σύστημα.

Για να το πετύχετε, μπορείτε να εκμεταλλευτείτε ένα **Dll Hijacking**, όπου θα κάνετε **hijack σε μια βιβλιοθήκη που φορτώνεται** από μια υπηρεσία ή διεργασία με **περισσότερα privileges** από τα δικά σας. Επειδή αυτή η υπηρεσία φορτώνει ένα Dll που πιθανότατα δεν υπάρχει καν σε ολόκληρο το σύστημα, θα προσπαθήσει να το φορτώσει από το System Path, όπου μπορείτε να γράψετε.

Για περισσότερες πληροφορίες σχετικά με το **τι είναι το Dll Hijacking**, δείτε:


{{#ref}}
./
{{#endref}}

## Privesc με Dll Hijacking

### Εντοπισμός ενός missing Dll

Το πρώτο πράγμα που χρειάζεστε είναι να **εντοπίσετε μια διεργασία** που εκτελείται με **περισσότερα privileges** από εσάς και προσπαθεί να **φορτώσει ένα Dll από το System Path** στο οποίο μπορείτε να γράψετε.

Θυμηθείτε ότι αυτή η τεχνική εξαρτάται από μια καταχώριση στο **Machine/System PATH**, όχι μόνο από το **User PATH**. Επομένως, πριν αφιερώσετε χρόνο στο Procmon, αξίζει να κάνετε enumeration των καταχωρίσεων του **Machine PATH** και να ελέγξετε ποιες είναι writable:<sup>[[1]](#references)</sup>
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
Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι πιθανότατα αυτές οι processes εκτελούνται ήδη. Για να βρείτε ποια Dlls λείπουν από τα services, πρέπει να εκκινήσετε το procmon το συντομότερο δυνατό (πριν φορτωθούν οι processes). Επομένως, για να βρείτε τα .dlls που λείπουν:

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
- Στη συνέχεια, κάντε **reboot**. Όταν γίνει επανεκκίνηση του υπολογιστή, το **`procmon`** θα ξεκινήσει να **καταγράφει** events το συντομότερο δυνατό.
- Μόλις γίνει **εκκίνηση των Windows, εκτελέστε ξανά το `procmon`**. Θα σας ενημερώσει ότι εκτελούνταν ήδη και θα **σας ρωτήσει αν θέλετε να αποθηκεύσετε** τα events σε ένα αρχείο. Απαντήστε **yes** και **αποθηκεύστε τα events σε ένα αρχείο**.
- **Αφού** δημιουργηθεί το **αρχείο**, κλείστε το ανοιχτό παράθυρο του **`procmon`** και **ανοίξτε το αρχείο events**.
- Προσθέστε αυτά τα **filters** και θα βρείτε όλα τα Dlls που κάποιο **process προσπάθησε να φορτώσει** από τον writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το **boot logging απαιτείται μόνο για services που ξεκινούν πολύ νωρίς**, ώστε να μπορείτε να τα παρατηρήσετε. Αν μπορείτε να **ενεργοποιήσετε το target service/program κατά απαίτηση** (για παράδειγμα, αλληλεπιδρώντας με το COM interface του, κάνοντας restart το service ή εκτελώντας ξανά ένα scheduled task), συνήθως είναι ταχύτερο να διατηρήσετε ένα κανονικό Procmon capture με filters όπως **`Path contains .dll`**, **`Result is NAME NOT FOUND`** και **`Path begins with <writable_machine_path>`**.

### DLLs που παραλείφθηκαν

Εκτελώντας αυτό σε ένα δωρεάν **virtual (vmware) Windows 11 machine**, έλαβα τα εξής αποτελέσματα:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, τα .exe είναι άχρηστα, επομένως αγνοήστε τα. Τα DLLs που παραλείφθηκαν προέρχονταν από:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Αφού το βρήκα αυτό, εντόπισα αυτό το ενδιαφέρον blog post, το οποίο επίσης εξηγεί πώς να [**κάνετε abuse το WptsExtensions.dll για privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Αυτό ακριβώς **θα κάνουμε τώρα**.<sup>[[3]](#references)</sup>

### Άλλοι υποψήφιοι που αξίζει να εξεταστούν

Το `WptsExtensions.dll` είναι ένα καλό παράδειγμα, αλλά δεν είναι το μοναδικό recurring **phantom DLL** που εμφανίζεται σε privileged services. Οι σύγχρονοι κανόνες hunting και οι public hijack catalogs εξακολουθούν να παρακολουθούν ονόματα όπως τα εξής:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Κλασικός υποψήφιος **SYSTEM** σε client systems. Χρήσιμο όταν ο writable directory βρίσκεται στο **Machine PATH** και το service κάνει probe για το DLL κατά την εκκίνησή του. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Ενδιαφέρον σε **server editions**, επειδή το service εκτελείται ως **SYSTEM** και σε ορισμένα builds μπορεί να **ενεργοποιηθεί κατά απαίτηση από έναν κανονικό user**, γεγονός που το κάνει καλύτερο από περιπτώσεις που απαιτούν μόνο reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Συνήθως δίνει αρχικά **`NT AUTHORITY\LOCAL SERVICE`**. Αυτό συχνά εξακολουθεί να είναι αρκετό, επειδή το token διαθέτει **`SeImpersonatePrivilege`**, οπότε μπορείτε να το κάνετε chain με το [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Αντιμετωπίστε αυτά τα ονόματα ως **hints για triage** και όχι ως εγγυημένες επιτυχίες: εξαρτώνται από το **SKU/build** και η Microsoft ενδέχεται να αλλάξει τη συμπεριφορά μεταξύ διαφορετικών releases. Το σημαντικό συμπέρασμα είναι να αναζητάτε **missing DLLs σε privileged services που διασχίζουν το Machine PATH**, ειδικά αν το service μπορεί να **ενεργοποιηθεί ξανά χωρίς reboot**.

### Exploitation

Έτσι, για να **κάνουμε privilege escalation**, θα κάνουμε hijack το library **WptsExtensions.dll**. Έχοντας το **path** και το **name**, το μόνο που χρειάζεται είναι να **δημιουργήσουμε το malicious DLL**.

Μπορείτε να [**δοκιμάσετε να χρησιμοποιήσετε οποιοδήποτε από αυτά τα examples**](#creating-and-compiling-dlls). Μπορείτε να εκτελέσετε payloads όπως: να πάρετε ένα rev shell, να προσθέσετε έναν user, να εκτελέσετε ένα beacon...

> [!WARNING]
> Σημειώστε ότι **δεν εκτελούνται όλα τα services** με **`NT AUTHORITY\SYSTEM`**. Ορισμένα εκτελούνται επίσης με **`NT AUTHORITY\LOCAL SERVICE`**, το οποίο έχει **λιγότερα privileges**, και **δεν θα μπορείτε να δημιουργήσετε νέο user** κάνοντας abuse των permissions του.\
> Ωστόσο, αυτός ο user διαθέτει το privilege **`seImpersonate`**, επομένως μπορείτε να χρησιμοποιήσετε το[ **potato suite για privilege escalation**](../roguepotato-and-printspoofer.md). Σε αυτή την περίπτωση, ένα rev shell είναι καλύτερη επιλογή από την προσπάθεια δημιουργίας user.

Κατά τη στιγμή της σύνταξης, το **Task Scheduler** service εκτελείται με **Nt AUTHORITY\SYSTEM**.

Αφού **δημιουργήσετε το malicious DLL** (_στη δική μου περίπτωση χρησιμοποίησα x64 rev shell και πήρα shell πίσω, αλλά το defender το τερμάτισε επειδή προερχόταν από msfvenom_), αποθηκεύστε το στο writable System Path με το όνομα **WptsExtensions.dll** και κάντε **restart** στον υπολογιστή (ή κάντε restart το service ή κάντε ό,τι απαιτείται για να εκτελεστεί ξανά το επηρεαζόμενο service/program).

Όταν γίνει restart του service, το **DLL θα πρέπει να φορτωθεί και να εκτελεστεί** (μπορείτε να **χρησιμοποιήσετε ξανά το** trick του **procmon** για να ελέγξετε αν το **library φορτώθηκε όπως αναμενόταν**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
