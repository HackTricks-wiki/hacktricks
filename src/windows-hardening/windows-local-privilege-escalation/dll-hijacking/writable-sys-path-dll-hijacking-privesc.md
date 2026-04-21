# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Αν βρήκες ότι μπορείς να **γράψεις σε έναν φάκελο System Path** (σημείωση ότι αυτό δεν θα δουλέψει αν μπορείς να γράψεις σε έναν φάκελο User Path), είναι πιθανό να μπορείς να **κλιμακώσεις δικαιώματα** στο σύστημα.

Για να το κάνεις αυτό, μπορείς να εκμεταλλευτείς ένα **Dll Hijacking**, όπου θα **υφαρπάξεις μια βιβλιοθήκη που φορτώνεται** από μια service ή process με **περισσότερα δικαιώματα** από τα δικά σου, και επειδή αυτό το service φορτώνει ένα Dll που πιθανότατα δεν υπάρχει καν σε ολόκληρο το σύστημα, θα προσπαθήσει να το φορτώσει από το System Path όπου μπορείς να γράψεις.

Για περισσότερες πληροφορίες για το **τι είναι Dll Hijackig** δες:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Το πρώτο πράγμα που χρειάζεσαι είναι να **εντοπίσεις μια process** που τρέχει με **περισσότερα δικαιώματα** από εσένα και προσπαθεί να **φορτώσει ένα Dll από το System Path** στο οποίο μπορείς να γράψεις.

Θυμήσου ότι αυτή η τεχνική εξαρτάται από μια καταχώρηση **Machine/System PATH**, όχι μόνο από το **User PATH** σου. Επομένως, πριν ξοδέψεις χρόνο στο Procmon, αξίζει να κάνεις enumerate τις καταχωρήσεις του **Machine PATH** και να ελέγξεις ποιες είναι writable:
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
Το πρόβλημα σε αυτές τις περιπτώσεις είναι ότι πιθανότατα αυτές οι διεργασίες ήδη εκτελούνται. Για να βρεις ποια Dlls λείπουν από τις υπηρεσίες, πρέπει να εκκινήσεις το procmon όσο το δυνατόν νωρίτερα (πριν φορτωθούν οι διεργασίες). Άρα, για να βρεις τα .dll που λείπουν, κάνε:

- **Create** το φάκελο `C:\privesc_hijacking` και πρόσθεσε το path `C:\privesc_hijacking` στη **System Path env variable**. Μπορείς να το κάνεις αυτό **manually** ή με **PS**:
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
- Εκκινήστε το **`procmon`** και πηγαίνετε στο **`Options`** --> **`Enable boot logging`** και πατήστε **`OK`** στο prompt.
- Έπειτα, κάντε **reboot**. Όταν ο υπολογιστής επανεκκινηθεί, το **`procmon`** θα ξεκινήσει να **recording** events το συντομότερο δυνατό.
- Μόλις ξεκινήσει το **Windows**, εκτελέστε ξανά το **`procmon`**· θα σας πει ότι ήδη τρέχει και θα σας **ρωτήσει αν θέλετε να αποθηκεύσετε** τα events σε αρχείο. Πείτε **yes** και **store the events in a file**.
- **Αφού** δημιουργηθεί το **file**, **κλείστε** το ανοιχτό παράθυρο **`procmon`** και **ανοίξτε το events file**.
- Προσθέστε αυτά τα **filters** και θα βρείτε όλα τα Dlls που κάποιο **proccess προσπάθησε να φορτώσει** από τον writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Τρέχοντας αυτό σε ένα δωρεάν **virtual (vmware) Windows 11 machine** πήρα αυτά τα αποτελέσματα:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση τα .exe είναι άχρηστα, οπότε αγνοήστε τα· τα missed DLLs ήταν από:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Αφού το βρήκα αυτό, βρήκα αυτό το ενδιαφέρον blog post που επίσης εξηγεί πώς να [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Κάτι που είναι ακριβώς αυτό που **θα κάνουμε τώρα**.

### Other candidates worth triaging

Το `WptsExtensions.dll` είναι ένα καλό παράδειγμα, αλλά δεν είναι το μόνο επαναλαμβανόμενο **phantom DLL** που εμφανίζεται σε privileged services. Οι σύγχρονοι hunting rules και τα δημόσια hijack catalogs εξακολουθούν να παρακολουθούν ονόματα όπως:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Κλασικό **SYSTEM** candidate σε client systems. Καλό όταν ο writable directory βρίσκεται στο **Machine PATH** και το service probes το DLL κατά την εκκίνηση. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Ενδιαφέρον σε **server editions** επειδή το service τρέχει ως **SYSTEM** και μπορεί να **triggered on demand by a normal user** σε ορισμένα builds, κάτι που το κάνει καλύτερο από reboot-only cases. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Συνήθως δίνει πρώτα **`NT AUTHORITY\LOCAL SERVICE`**. Αυτό συχνά είναι ακόμα αρκετό επειδή το token έχει **`SeImpersonatePrivilege`**, οπότε μπορείτε να το αλυσοδέσετε με [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Να αντιμετωπίζετε αυτά τα ονόματα ως **triage hints**, όχι ως εγγυημένα wins: εξαρτώνται από **SKU/build** και η Microsoft μπορεί να αλλάξει τη συμπεριφορά μεταξύ releases. Το σημαντικό συμπέρασμα είναι να ψάχνετε για **missing DLLs σε privileged services που traversrse το Machine PATH**, ειδικά αν το service μπορεί να **re-triggered without rebooting**.

### Exploitation

Λοιπόν, για να **escalate privileges** θα κάνουμε hijack τη βιβλιοθήκη **WptsExtensions.dll**. Έχοντας το **path** και το **name**, χρειάζεται απλώς να **generate the malicious dll**.

Μπορείτε να [**try to use any of these examples**](#creating-and-compiling-dlls). Θα μπορούσατε να εκτελέσετε payloads όπως: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Σημειώστε ότι **not all the service are run** με **`NT AUTHORITY\SYSTEM`**· κάποια τρέχουν επίσης ως **`NT AUTHORITY\LOCAL SERVICE`**, το οποίο έχει **less privileges** και **won't be able to create a new user** abuse its permissions.\
> Ωστόσο, αυτός ο user έχει το **`seImpersonate`** privilege, οπότε μπορείτε να χρησιμοποιήσετε τη[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Άρα, σε αυτή την περίπτωση ένα rev shell είναι καλύτερη επιλογή από το να προσπαθήσετε να δημιουργήσετε user.

Τη στιγμή που γράφεται αυτό, το service **Task Scheduler** τρέχει ως **Nt AUTHORITY\SYSTEM**.

Αφού **generated the malicious Dll** (_στη δική μου περίπτωση χρησιμοποίησα x64 rev shell και πήρα shell πίσω, αλλά το defender το σκότωσε επειδή ήταν από msfvenom_), αποθηκεύστε το στο writable System Path με το όνομα **WptsExtensions.dll** και κάντε **restart** τον υπολογιστή (ή κάντε restart το service ή ό,τι χρειάζεται για να ξανατρέξει το affected service/program).

Όταν το service γίνει re-started, το **dll should be loaded and executed** (μπορείτε να **reuse** το **procmon** trick για να ελέγξετε αν η **library was loaded as expected**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
