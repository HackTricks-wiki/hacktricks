# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Αν μπορείτε να **γράψετε σε έναν κατάλογο του system-wide `PATH`** (και όχι απλώς στο `PATH` του χρήστη σας), ενδέχεται να μπορείτε να κάνετε **escalate privileges** στο σύστημα.

Αυτό μπορεί να γίνει abuse μέσω **DLL hijacking** όταν μια υπηρεσία ή process με περισσότερα privileges προσπαθεί να φορτώσει ένα DLL που δεν υπάρχει στις προηγούμενες τοποθεσίες αναζήτησης και τελικά αναζητά στον εγγράψιμο κατάλογο του system `PATH`.

Για περισσότερες πληροφορίες σχετικά με το **DLL hijacking**, δείτε:


{{#ref}}
./
{{#endref}}

## Privesc με Dll Hijacking

### Εύρεση ενός Missing DLL

Αρχικά, **εντοπίστε ένα process** που εκτελείται με **περισσότερα privileges** και προσπαθεί να **φορτώσει ένα DLL από έναν εγγράψιμο κατάλογο του system `PATH`**.

Να θυμάστε ότι αυτή η τεχνική εξαρτάται από μια καταχώριση του **Machine/System PATH**, όχι μόνο από το **User PATH**. Επομένως, πριν αφιερώσετε χρόνο στο Procmon, αξίζει να απαριθμήσετε τις καταχωρίσεις του **Machine PATH** και να ελέγξετε ποιες είναι εγγράψιμες:<sup>[[1]](#references)</sup>
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
Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι αυτές οι διεργασίες πιθανότατα εκτελούνται ήδη. Για να εντοπίσετε DLLs που οι υπηρεσίες προσπαθούν και αποτυγχάνουν να φορτώσουν, εκκινήστε το Procmon όσο το δυνατόν νωρίτερα (πριν από την εκκίνηση των διεργασιών) και, στη συνέχεια:

- **Δημιουργήστε** τον φάκελο `C:\privesc_hijacking` και προσθέστε τη διαδρομή `C:\privesc_hijacking` στη **System Path env variable**. Μπορείτε να το κάνετε **χειροκίνητα** ή με **PS**:
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
- Εκκινήστε το **`procmon`** και μεταβείτε στις **`Options`** --> **`Enable boot logging`**, και πατήστε **`OK`** στο prompt.
- Στη συνέχεια, κάντε **reboot**. Όταν γίνει επανεκκίνηση του υπολογιστή, το **`procmon`** θα αρχίσει να **καταγράφει** events αμέσως.
- Μόλις γίνει **εκκίνηση των Windows**, εκτελέστε ξανά το **`procmon`**. Θα σας ενημερώσει ότι εκτελούνταν ήδη και θα σας **ρωτήσει αν θέλετε να αποθηκεύσετε** τα events σε ένα αρχείο. Απαντήστε **yes** και **αποθηκεύστε τα events σε ένα αρχείο**.
- **Αφού** δημιουργηθεί το **αρχείο**, κλείστε το ανοιχτό παράθυρο του **`procmon`** και **ανοίξτε το αρχείο events**.
- Προσθέστε αυτά τα **filters** για να βρείτε όλα τα DLLs που ένα **process προσπάθησε να φορτώσει** από τον writable φάκελο του System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το **Boot logging απαιτείται μόνο για services που ξεκινούν πολύ νωρίς**, ώστε να είναι δυνατή η παρατήρησή τους με άλλο τρόπο. Αν μπορείτε να **ενεργοποιήσετε το target service/program on demand** (για παράδειγμα, αλληλεπιδρώντας με το COM interface του, κάνοντας restart το service ή κάνοντας relaunch ένα scheduled task), συνήθως είναι πιο γρήγορο να διατηρήσετε ένα κανονικό Procmon capture με filters όπως **`Path contains .dll`**, **`Result is NAME NOT FOUND`** και **`Path begins with <writable_machine_path>`**.

### Dlls που παραλείφθηκαν

Εκτελώντας το παρακάτω σε ένα δωρεάν **virtual (vmware) Windows 11 machine**, έλαβα τα εξής αποτελέσματα:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Σε αυτήν την περίπτωση, αγνοήστε τα αποτελέσματα **`.exe`**. Τα probes για missing DLLs προήλθαν από:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Το ακόλουθο παράδειγμα χρησιμοποιεί την τεχνική που περιγράφεται σε αυτό το άρθρο σχετικά με το [**abusing του `WptsExtensions.dll` για privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Άλλοι υποψήφιοι που αξίζει να εξεταστούν

Το `WptsExtensions.dll` είναι ένα καλό παράδειγμα, αλλά δεν είναι το μοναδικό recurring **phantom DLL** που εμφανίζεται σε privileged services. Οι σύγχρονοι hunting rules και οι public hijack catalogs εξακολουθούν να παρακολουθούν ονόματα όπως τα εξής:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Κλασικός υποψήφιος για **SYSTEM** σε client systems. Χρήσιμο όταν ο writable directory βρίσκεται στο **Machine PATH** και το service κάνει probe για το DLL κατά την εκκίνησή του. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Ενδιαφέρον σε **server editions**, επειδή το service εκτελείται ως **SYSTEM** και σε ορισμένα builds μπορεί να **ενεργοποιηθεί on demand από έναν κανονικό user**, γεγονός που το καθιστά καλύτερο από περιπτώσεις που απαιτούν μόνο reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Συνήθως αποδίδει αρχικά **`NT AUTHORITY\LOCAL SERVICE`**. Αυτό συχνά εξακολουθεί να είναι αρκετό, επειδή το token διαθέτει **`SeImpersonatePrivilege`**, οπότε μπορείτε να το κάνετε chain με το [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Αντιμετωπίστε αυτά τα ονόματα ως **hints για triage**, όχι ως εγγυημένες επιτυχίες: εξαρτώνται από το **SKU/build** και η Microsoft μπορεί να αλλάξει τη συμπεριφορά μεταξύ releases. Το σημαντικό συμπέρασμα είναι να αναζητάτε **missing DLLs σε privileged services που διασχίζουν το Machine PATH**, ειδικά αν το service μπορεί να **ενεργοποιηθεί ξανά χωρίς reboot**.

### Exploitation

Για να **κάνετε privilege escalation**, κάντε hijack το **`WptsExtensions.dll`**. Μόλις είναι γνωστά το **path** και το **name**, δημιουργήστε το malicious DLL.

Μπορείτε να [**δοκιμάσετε να χρησιμοποιήσετε οποιοδήποτε από αυτά τα examples**](#creating-and-compiling-dlls). Μπορείτε να εκτελέσετε payloads όπως: να λάβετε ένα rev shell, να προσθέσετε έναν user, να εκτελέσετε ένα beacon...

> [!WARNING]
> Σημειώστε ότι **δεν εκτελούνται όλα τα services** ως **`NT AUTHORITY\SYSTEM`**. Ορισμένα εκτελούνται ως **`NT AUTHORITY\LOCAL SERVICE`**, το οποίο έχει **λιγότερα privileges**, επομένως η κατάχρηση ενός από αυτά τα services μπορεί να μη σας επιτρέψει να δημιουργήσετε νέο user.\
> Ωστόσο, αυτός ο account διαθέτει το user right **`SeImpersonatePrivilege`**, επομένως μπορείτε να χρησιμοποιήσετε το [**Potato suite για privilege escalation**](../roguepotato-and-printspoofer.md). Σε αυτήν την περίπτωση, ένα reverse shell είναι καλύτερη επιλογή από την προσπάθεια δημιουργίας user.

Τη στιγμή της συγγραφής, το service **Task Scheduler** εκτελείται με **Nt AUTHORITY\SYSTEM**.

Αφού **δημιουργήσετε το malicious Dll** (_στην περίπτωσή μου χρησιμοποίησα x64 rev shell και έλαβα shell πίσω, αλλά το defender το τερμάτισε επειδή προερχόταν από το msfvenom_), αποθηκεύστε το στο writable System Path με το όνομα **WptsExtensions.dll** και κάντε **restart** στον υπολογιστή (ή κάντε restart το service ή κάντε οτιδήποτε απαιτείται για να εκτελεστεί ξανά το επηρεαζόμενο service/program).

Όταν γίνει restart το service, το **dll θα πρέπει να φορτωθεί και να εκτελεστεί** (μπορείτε να **χρησιμοποιήσετε ξανά** το **procmon** trick για να ελέγξετε αν η **library φορτώθηκε όπως αναμενόταν**).

## References

- [1] [Τα Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Ύποπτο DLL που φορτώθηκε για Persistence ή Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
