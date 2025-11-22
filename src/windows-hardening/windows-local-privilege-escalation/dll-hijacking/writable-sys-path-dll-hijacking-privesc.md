# Εγγράψιμο Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Αν ανακαλύψετε ότι μπορείτε να **γράψετε σε έναν φάκελο System Path** (σημειώστε ότι αυτό δεν θα λειτουργήσει αν μπορείτε να γράψετε σε φάκελο User Path) υπάρχει πιθανότητα να μπορέσετε να **αυξήσετε τα προνόμια** στο σύστημα.

Για να το πετύχετε αυτό μπορείτε να καταχραστείτε ένα **Dll Hijacking** όπου θα **υποκλέψετε μια βιβλιοθήκη που φορτώνεται** από μια υπηρεσία ή διεργασία με **περισσότερα προνόμια** από τα δικά σας, και επειδή αυτή η υπηρεσία φορτώνει ένα Dll που πιθανότατα δεν υπάρχει καν ολόκληρο στο σύστημα, θα προσπαθήσει να το φορτώσει από το System Path όπου μπορείτε να γράψετε.

For more info about **what is Dll Hijackig** check:


{{#ref}}
./
{{#endref}}

## Privesc με Dll Hijacking

### Εύρεση ελλείποντος Dll

Το πρώτο που χρειάζεστε είναι να **εντοπίσετε μια διεργασία** που τρέχει με **περισσότερα προνόμια** από εσάς και προσπαθεί να **φορτώσει ένα Dll από το System Path** στο οποίο μπορείτε να γράψετε.

Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι πιθανότατα αυτές οι διεργασίες ήδη τρέχουν. Για να βρείτε ποια Dll λείπουν πρέπει να ξεκινήσετε το procmon το συντομότερο δυνατό (πριν φορτωθούν οι διεργασίες). Έτσι, για να βρείτε τα ελλείποντα .dll κάντε:

- **Δημιουργήστε** τον φάκελο `C:\privesc_hijacking` και προσθέστε τη διαδρομή `C:\privesc_hijacking` στο **System Path env variable**. Μπορείτε να το κάνετε **χειροκίνητα** ή με **PS**:
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
- Εκκινήστε **`procmon`** και πηγαίνετε στο **`Options`** --> **`Enable boot logging`** και πατήστε **`OK`** στο prompt.
- Έπειτα, **reboot**. Όταν ο υπολογιστής επανεκκινήσει το **`procmon`** θα αρχίσει να **καταγράφει** events το συντομότερο δυνατό.
- Μόλις **Windows** έχει **ξεκινήσει** εκτελέστε ξανά το `procmon`, θα σας πει ότι έχει τρέξει και θα σας **ρωτήσει αν θέλετε να αποθηκεύσετε** τα events σε αρχείο. Πείτε **yes** και **αποθηκεύστε τα events σε αρχείο**.
- **Μετά** τη **δημιουργία του αρχείου**, **κλείστε** το ανοιχτό παράθυρο του **`procmon`** και **ανοίξτε το αρχείο των events**.
- Προσθέστε αυτά τα **φίλτρα** και θα βρείτε όλα τα Dlls που κάποια **process προσπάθησε να φορτώσει** από το εγγράψιμο φάκελο System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Χαμένα Dlls

Εκτελώντας αυτό σε μια δωρεάν virtual (vmware) μηχανή Windows 11 πήρα τα ακόλουθα αποτελέσματα:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση τα .exe είναι άχρηστα οπότε αγνοήστε τα, τα χαμένα DLLs ήταν από:

| Υπηρεσία                        | Dll                | Γραμμή CMD                                                           |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Μετά από αυτό, βρήκα ένα ενδιαφέρον blog post που επίσης εξηγεί πώς να [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Το οποίο είναι αυτό που **πρόκειται να κάνουμε τώρα**.

### Εκμετάλλευση

Έτσι, για να **αυξήσουμε προνόμια** πρόκειται να hijack-άρουμε τη βιβλιοθήκη **WptsExtensions.dll**. Έχοντας το **path** και το **όνομα** χρειάζεται μόνο να **παράγουμε το κακόβουλο dll**.

Μπορείτε να [**δοκιμάσετε να χρησιμοποιήσετε οποιοδήποτε από αυτά τα παραδείγματα**](#creating-and-compiling-dlls). Μπορείτε να τρέξετε payloads όπως: να πάρετε rev shell, να προσθέσετε χρήστη, να εκτελέσετε ένα beacon...

> [!WARNING]
> Σημειώστε ότι **όλες οι υπηρεσίες δεν τρέχουν** με **`NT AUTHORITY\SYSTEM`** — κάποιες τρέχουν με **`NT AUTHORITY\LOCAL SERVICE`** που έχει **λιγότερα προνόμια** και δεν θα μπορείτε να δημιουργήσετε νέο χρήστη ή να καταχραστείτε τα δικαιώματά του.\
> Ωστόσο, αυτός ο χρήστης διαθέτει το προνόμιο **`seImpersonate`**, οπότε μπορείτε να χρησιμοποιήσετε το[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Έτσι, σε αυτή την περίπτωση ένα rev shell είναι καλύτερη επιλογή από το να προσπαθήσετε να δημιουργήσετε χρήστη.

Τη στιγμή της συγγραφής η υπηρεσία **Task Scheduler** τρέχει με **NT AUTHORITY\SYSTEM**.

Αφού **δημιουργήσετε το κακόβουλο Dll** (_στην περίπτωσή μου χρησιμοποίησα x64 rev shell και πήρα πίσω ένα shell αλλά ο defender το τερμάτισε επειδή ήταν από msfvenom_), αποθηκεύστε το στο εγγράψιμο System Path με το όνομα **WptsExtensions.dll** και **επανεκκινήστε** τον υπολογιστή (ή επανεκκινήστε την υπηρεσία ή κάντε ό,τι χρειάζεται για να ξανατρέξει η επηρεαζόμενη υπηρεσία/πρόγραμμα).

Όταν η υπηρεσία επανεκκινηθεί, το **dll θα πρέπει να φορτωθεί και να εκτελεστεί** (μπορείτε να **ξαναχρησιμοποιήσετε** το κόλπο του **procmon** για να ελέγξετε αν η **βιβλιοθήκη φορτώθηκε όπως αναμενόταν**).

{{#include ../../../banners/hacktricks-training.md}}
