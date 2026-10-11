# Κλιμάκωση προνομίων με Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

Το **Wmic** μπορεί να χρησιμοποιηθεί για την εκτέλεση προγραμμάτων κατά την **εκκίνηση**. Δείτε ποια εκτελέσιμα έχουν προγραμματιστεί να εκτελούνται κατά την εκκίνηση με:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Προγραμματισμένες εργασίες

Οι **εργασίες** μπορούν να προγραμματιστούν ώστε να εκτελούνται με **συγκεκριμένη συχνότητα**. Χρησιμοποιήστε τις ακόλουθες εντολές για να δείτε ποια εκτελέσιμα αρχεία έχουν προγραμματιστεί να εκτελούνται:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Μια ενεργοποιημένη εργασία που εκτελείται ως SYSTEM αξίζει έλεγχο ακόμη κι όταν ο ορισμός της εργασίας και το αρχείο action προστατεύονται. [Το Task Scheduler απαιτεί δικαίωμα εκτέλεσης στην εργασία για να την εκτελέσει κατ’ απαίτηση](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Αν ένας χρήστης με χαμηλά προνόμια έχει αυτό το δικαίωμα, ελέγξτε το ακριβές action, ιδιαίτερα τα PowerShell scripts που τροποποιούν ACLs του Active Directory ή επαναφέρουν ρυθμίσεις προστασίας λογαριασμού. Ελέγξτε τη ρύθμιση `AllowDemandStart` της εργασίας και επαληθεύστε τις εισόδους και τις επιδράσεις του script· η άδεια εκκίνησης μιας σταθερής εργασίας από μόνη της δεν συνεπάγεται αυθαίρετη εκτέλεση κώδικα.

## Φάκελοι

Όλα τα binaries που βρίσκονται στους **φακέλους εκκίνησης θα εκτελεστούν κατά την εκκίνηση**. Οι συνήθεις φάκελοι εκκίνησης είναι αυτοί που παρατίθενται παρακάτω, αλλά ο φάκελος εκκίνησης καθορίζεται στο registry. [Διαβάστε εδώ για να μάθετε πού.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Η καταχώριση Startup ενός χρήστη με υψηλότερα προνόμια μπορεί να εκκινεί ένα προστατευμένο script που ανοίγει επανειλημμένα αρχεία από έναν κατάλογο στον οποίο μπορεί να γράψει άλλος χρήστης. Ελέγξτε την **πραγματική ταυτότητα σύνδεσης** της καταχώρισης, τον κατάλογο εισόδου του script και τα ACL του, καθώς και την ακριβή ενέργεια, πριν θεωρήσετε ότι ο κατάλογος αποτελεί διαδρομή κλιμάκωσης προνομίων. Ειδικότερα, το [`hh.exe` ανοίγει αρχεία HTML Help που έχουν μεταγλωττιστεί (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program)· ένα script που του περνά αρχεία τα οποία παρέχονται από τον καλούντα διασχίζει ένα όριο εμπιστοσύνης περιεχομένου, ακόμη κι αν ελέγχει το όνομα αρχείου ή τα πρώτα bytes. [Οι πολιτικές HTML Help μπορούν να περιορίσουν τις εκτελέσιμες συντομεύσεις](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), επομένως επιβεβαιώστε την εγκατεστημένη πολιτική και τη συμπεριφορά του προσβάσιμου περιεχομένου. Μια επέκταση `.chm` ή τα magic bytes από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα με υψηλότερα προνόμια. Επιθεωρήστε την autorun, τη γραμμή εντολών της διεργασίας και τα δικαιώματα πρόσβασης στις διαδρομές, χωρίς να ανοίξετε το μη έμπιστο αρχείο κατά την απογραφή.

Το ίδιο όριο περιεχομένου υπάρχει όταν ένα άτομο με υψηλότερα προνόμια **ανοίγει χειροκίνητα** ένα `.chm` από έναν φάκελο τεκμηρίωσης που μπορεί να αντικαταστήσει άλλος χρήστης. Επιβεβαιώστε το ακριβές αρχείο και τα δικαιώματα εγγραφής στον γονικό κατάλογο, την πραγματική ταυτότητα του προγράμματος προβολής και το συμβάν ανοίγματος, καθώς και την ισχύουσα πολιτική HTML Help. Ένας φάκελος με δυνατότητα εγγραφής ή ένα αίτημα για έλεγχο τεκμηρίωσης δεν αποδεικνύει ότι η ταυτότητα με τα υψηλότερα προνόμια άνοιξε περιεχόμενο ελεγχόμενο από τον επιτιθέμενο.

> **FYI**: Τα vulnerabilities *path traversal* κατά την εξαγωγή αρχείων (όπως αυτό που αξιοποιήθηκε στο WinRAR πριν από την έκδοση 7.13 – CVE-2025-8088) μπορούν να χρησιμοποιηθούν για την **απευθείας τοποθέτηση payloads μέσα σε αυτούς τους φακέλους Startup κατά την αποσυμπίεση**, με αποτέλεσμα την εκτέλεση κώδικα στην επόμενη σύνδεση χρήστη. Για μια εις βάθος ανάλυση αυτής της τεχνικής, δείτε:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Μητρώο

> [!TIP]
> [Σημείωση από εδώ](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Η καταχώριση μητρώου **Wow6432Node** υποδεικνύει ότι εκτελείτε έκδοση 64-bit των Windows. Το λειτουργικό σύστημα χρησιμοποιεί αυτό το κλειδί για να εμφανίζει ξεχωριστή προβολή του HKEY_LOCAL_MACHINE\SOFTWARE για εφαρμογές 32-bit που εκτελούνται σε εκδόσεις 64-bit των Windows.

### Εκτελέσεις

**Συνήθεις γνωστές** καταχωρίσεις μητρώου AutoRun:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Τα κλειδιά μητρώου που είναι γνωστά ως **Run** και **RunOnce** έχουν σχεδιαστεί ώστε να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας χρήστης συνδέεται στο σύστημα. Η γραμμή εντολών που εκχωρείται ως τιμή δεδομένων ενός κλειδιού περιορίζεται σε 260 χαρακτήρες ή λιγότερους.<sup>[[2]](#references)</sup>

**Εκτελέσεις υπηρεσιών** (μπορούν να ελέγχουν την αυτόματη εκκίνηση υπηρεσιών κατά την εκκίνηση):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Στα Windows Vista και σε νεότερες εκδόσεις, τα κλειδιά μητρώου **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι καταχωρίσεις σε αυτά τα κλειδιά μπορούν είτε να εκκινούν προγράμματα απευθείας είτε να τα καθορίζουν ως εξαρτήσεις. Για παράδειγμα, για τη φόρτωση ενός αρχείου DLL κατά τη σύνδεση, μπορεί να χρησιμοποιηθεί το κλειδί μητρώου **RunOnceEx** μαζί με ένα κλειδί "Depend". Αυτό παρουσιάζεται με την προσθήκη μιας καταχώρισης μητρώου για την εκτέλεση του "C:\temp\evil.dll" κατά την εκκίνηση του συστήματος:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Αν μπορείς να γράψεις σε οποιοδήποτε από τα αναφερόμενα registry μέσα στο **HKLM**, μπορείς να κλιμακώσεις τα προνόμιά σου όταν συνδεθεί ένας διαφορετικός χρήστης.

> [!TIP]
> **Exploit 2**: Αν μπορείς να αντικαταστήσεις οποιοδήποτε από τα binaries που υποδεικνύονται σε οποιοδήποτε registry μέσα στο **HKLM**, μπορείς να τροποποιήσεις αυτό το binary με ένα backdoor όταν συνδεθεί ένας διαφορετικός χρήστης και να κλιμακώσεις τα προνόμιά σου.

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Διαδρομή εκκίνησης

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Οι συντομεύσεις που τοποθετούνται στον φάκελο **Startup** ενεργοποιούν αυτόματα την εκκίνηση υπηρεσιών ή εφαρμογών κατά τη σύνδεση του χρήστη ή την επανεκκίνηση του συστήματος. Η θέση του φακέλου **Startup** ορίζεται στο registry για τα πεδία **Local Machine** και **Current User**. Αυτό σημαίνει ότι οποιαδήποτε συντόμευση προστεθεί σε αυτές τις καθορισμένες θέσεις **Startup** διασφαλίζει ότι η συνδεδεμένη υπηρεσία ή το πρόγραμμα θα εκκινηθεί μετά τη σύνδεση ή την επανεκκίνηση, παρέχοντας έναν απλό τρόπο προγραμματισμού αυτόματης εκτέλεσης προγραμμάτων.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Αν μπορείς να αντικαταστήσεις οποιοδήποτε [User] Shell Folder κάτω από το **HKLM**, θα μπορείς να το κατευθύνεις σε έναν φάκελο που ελέγχεις και να τοποθετήσεις εκεί ένα backdoor που θα εκτελείται κάθε φορά που ένας χρήστης συνδέεται στο σύστημα, κλιμακώνοντας τα προνόμια.

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Αυτή η τιμή μητρώου ανά χρήστη μπορεί να δείχνει σε ένα script ή command που εκτελείται όταν ο χρήστης συνδέεται. Χρησιμοποιείται κυρίως ως primitive **persistence**, επειδή εκτελείται μόνο στο πλαίσιο του επηρεαζόμενου χρήστη, αλλά αξίζει και πάλι να ελέγχεται κατά το post-exploitation και τις αναθεωρήσεις autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Αν μπορείτε να γράψετε αυτήν την τιμή για τον τρέχοντα χρήστη, μπορείτε να προκαλέσετε ξανά την εκτέλεση στην επόμενη interactive σύνδεση, χωρίς να χρειάζεστε δικαιώματα admin. Αν μπορείτε να τη γράψετε στο hive μητρώου άλλου χρήστη, ενδέχεται να αποκτήσετε εκτέλεση κώδικα όταν συνδεθεί αυτός ο χρήστης.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Σημειώσεις:

- Προτιμήστε πλήρεις διαδρομές προς αρχεία `.bat`, `.cmd`, `.ps1` ή άλλα αρχεία launcher στα οποία έχει ήδη πρόσβαση ο χρήστης-στόχος.
- Αυτό παραμένει ενεργό μετά από αποσύνδεση/επανεκκίνηση, μέχρι να αφαιρεθεί η τιμή.
- Σε αντίθεση με το `HKLM\...\Run`, αυτό **δεν** παρέχει από μόνο του elevation· πρόκειται για persistence σε επίπεδο χρήστη.

### Κλειδιά Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το κλειδί **Userinit** έχει οριστεί σε **userinit.exe**. Ωστόσο, αν τροποποιηθεί αυτό το κλειδί, το καθορισμένο εκτελέσιμο θα εκκινηθεί επίσης από το **Winlogon** κατά τη σύνδεση του χρήστη. Παρομοίως, το κλειδί **Shell** προορίζεται να δείχνει στο **explorer.exe**, το οποίο είναι το προεπιλεγμένο shell των Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Αν μπορείτε να αντικαταστήσετε την τιμή του registry ή το binary, θα μπορέσετε να κλιμακώσετε τα προνόμιά σας.

### Ρυθμίσεις πολιτικής

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Ελέγξτε το κλειδί **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Αλλαγή της γραμμής εντολών σε Safe Mode

Στο Windows Registry, κάτω από το `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή **`AlternateShell`** που από προεπιλογή έχει οριστεί σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγετε «Safe Mode with Command Prompt» κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Ωστόσο, μπορείτε να ρυθμίσετε τον υπολογιστή σας ώστε να εκκινεί αυτόματα σε αυτήν τη λειτουργία, χωρίς να χρειάζεται να πατήσετε F8 και να την επιλέξετε χειροκίνητα.

Βήματα για να δημιουργήσετε μια επιλογή εκκίνησης που ξεκινά αυτόματα σε «Safe Mode with Command Prompt»:<sup>[[5]](#references)</sup>

1. Αλλάξτε τα attributes του αρχείου `boot.ini` για να καταργήσετε τις σημαίες read-only, system και hidden: `attrib c:\boot.ini -r -s -h`
2. Ανοίξτε το `boot.ini` για επεξεργασία.
3. Εισαγάγετε μια γραμμή όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθηκεύστε τις αλλαγές στο `boot.ini`.
5. Επαναφέρετε τα αρχικά attributes του αρχείου: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Η αλλαγή του registry key **AlternateShell** επιτρέπει τη ρύθμιση ενός προσαρμοσμένου command shell, που ενδέχεται να χρησιμοποιηθεί για μη εξουσιοδοτημένη πρόσβαση.
- **Exploit 2 (PATH Write Permissions):** Η δυνατότητα εγγραφής σε οποιοδήποτε σημείο της μεταβλητής συστήματος **PATH**, ειδικά πριν από το `C:\Windows\system32`, σας επιτρέπει να εκτελέσετε ένα προσαρμοσμένο `cmd.exe`, το οποίο θα μπορούσε να είναι backdoor αν το σύστημα εκκινηθεί σε Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Η δυνατότητα εγγραφής στο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Safe Mode, διευκολύνοντας τη μη εξουσιοδοτημένη πρόσβαση στην επόμενη επανεκκίνηση.

Για να ελέγξετε την τρέχουσα ρύθμιση του **AlternateShell**, χρησιμοποιήστε αυτές τις εντολές:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Εγκατεστημένο στοιχείο

Το Active Setup είναι μια λειτουργία των Windows που **ξεκινά πριν φορτωθεί πλήρως το περιβάλλον εργασίας**. Δίνει προτεραιότητα στην εκτέλεση ορισμένων εντολών, οι οποίες πρέπει να ολοκληρωθούν πριν συνεχιστεί η σύνδεση του χρήστη. Αυτή η διαδικασία πραγματοποιείται ακόμη και πριν ενεργοποιηθούν άλλες εγγραφές εκκίνησης, όπως αυτές στις ενότητες μητρώου Run ή RunOnce.

Το Active Setup διαχειρίζεται μέσω των ακόλουθων κλειδιών μητρώου:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Σε αυτά τα κλειδιά υπάρχουν διάφορα δευτερεύοντα κλειδιά, καθένα από τα οποία αντιστοιχεί σε ένα συγκεκριμένο στοιχείο. Οι τιμές κλειδιού που παρουσιάζουν ιδιαίτερο ενδιαφέρον περιλαμβάνουν:

- **IsInstalled:**
  - Η τιμή `0` υποδεικνύει ότι η εντολή του στοιχείου δεν θα εκτελεστεί.
  - Η τιμή `1` σημαίνει ότι η εντολή θα εκτελεστεί μία φορά για κάθε χρήστη· αυτή είναι η προεπιλεγμένη συμπεριφορά αν λείπει η τιμή `IsInstalled`.
- **StubPath:** Καθορίζει την εντολή που θα εκτελεστεί από το Active Setup. Μπορεί να είναι οποιαδήποτε έγκυρη γραμμή εντολών, όπως η εκκίνηση του `notepad`.

**Πληροφορίες ασφαλείας:**

- Η τροποποίηση ή η εγγραφή σε ένα κλειδί όπου το **`IsInstalled`** έχει οριστεί σε `"1"` και υπάρχει συγκεκριμένο **`StubPath`** μπορεί να οδηγήσει σε μη εξουσιοδοτημένη εκτέλεση εντολών, ενδεχομένως για κλιμάκωση προνομίων.
- Η τροποποίηση του δυαδικού αρχείου που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** μπορεί επίσης να επιτύχει κλιμάκωση προνομίων, εφόσον υπάρχουν επαρκή δικαιώματα.

Για την επιθεώρηση των ρυθμίσεων **`StubPath`** στα στοιχεία του Active Setup, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Αντικείμενα Βοήθειας Προγράμματος Περιήγησης

### Επισκόπηση των Αντικειμένων Βοήθειας Προγράμματος Περιήγησης (BHOs)

Τα Browser Helper Objects (BHOs) είναι μονάδες DLL που προσθέτουν επιπλέον δυνατότητες στον Internet Explorer της Microsoft. Φορτώνονται στον Internet Explorer και στον Windows Explorer κάθε φορά που εκκινούν. Ωστόσο, η εκτέλεσή τους μπορεί να αποκλειστεί ορίζοντας το κλειδί **NoExplorer** σε 1, ώστε να μην φορτώνονται στις παρουσίες του Windows Explorer.<sup>[[1]](#references)</sup>

Τα BHOs είναι συμβατά με τα Windows 10 μέσω του Internet Explorer 11, αλλά δεν υποστηρίζονται στον Microsoft Edge, το προεπιλεγμένο πρόγραμμα περιήγησης στις νεότερες εκδόσεις των Windows.

Για να εντοπίσετε τα BHOs που είναι καταχωρισμένα σε ένα σύστημα, μπορείτε να ελέγξετε τα ακόλουθα κλειδιά μητρώου:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO αναπαρίσταται στο μητρώο από το **CLSID** του, το οποίο λειτουργεί ως μοναδικό αναγνωριστικό. Λεπτομερείς πληροφορίες για κάθε CLSID μπορείτε να βρείτε στη διαδρομή `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για την αναζήτηση BHOs στο μητρώο, μπορείτε να χρησιμοποιήσετε τις ακόλουθες εντολές:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Επεκτάσεις του Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημειώστε ότι το μητρώο θα περιέχει μία νέα εγγραφή για κάθε dll, η οποία θα αναγνωρίζεται από το **CLSID**. Μπορείτε να βρείτε τις πληροφορίες του CLSID στη διαδρομή `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Προγράμματα οδήγησης γραμματοσειρών

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Εντολή ανοίγματος

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM handlers μενού περιβάλλοντος

Οι handlers μενού περιβάλλοντος του Explorer είναι shell extensions που έχουν καταχωριστεί σε κλειδιά όπως `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` και `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Η προεπιλεγμένη τιμή ενός handler ή, μερικές φορές, το όνομα του κλειδιού του είναι ένα CLSID. Ακολουθήστε αυτό το CLSID έως το `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`. Η προεπιλεγμένη τιμή του καθορίζει το DLL που φορτώνεται όταν καλείται ο handler.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Ελέγξτε τόσο τις προβολές μητρώου 32-bit όσο και 64-bit. Το `HKCR` συγχωνεύει τις καταχωρίσεις κλάσεων ανά χρήστη και σε επίπεδο μηχανήματος, επομένως επαληθεύστε σε ποιο υποκείμενο κλειδί θα καταλήξει μια διεργασία. Μια ταυτότητα με χαμηλά προνόμια που μπορεί να αλλάξει μια τιμή `InprocServer32` σε επίπεδο μηχανήματος μπορεί να ανακατευθύνει μια διεργασία με περισσότερα προνόμια σε διαφορετικό DLL, αλλά η κλιμάκωση απαιτεί η διεργασία να καλέσει τον handler. Μια εγγράψιμη διαδρομή DLL μπορεί να δημιουργήσει παρόμοιο κίνδυνο, ακόμη κι όταν η ίδια η τιμή μητρώου είναι προστατευμένη.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Σημειώστε ότι όλες οι τοποθεσίες όπου μπορείτε να βρείτε autoruns έχουν **ήδη ελεγχθεί από το**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πιο ολοκληρωμένη λίστα αρχείων που εκτελούνται αυτόματα**, μπορείτε να χρησιμοποιήσετε το [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) από το systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως τα registry keys στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Συνήθεις μηχανισμοί persistence malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Αυτόματη εκτέλεση κατά την εκκίνηση ή τη σύνδεση: Registry Run Keys / Φάκελος Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts αρχικοποίησης κατά την εκκίνηση ή τη σύνδεση: Script σύνδεσης (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Κατηγορίες αυτόματης εκκίνησης (Αντιμετώπιση προβλημάτων με τα εργαλεία Windows Sysinternals, 2η έκδοση)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Πώς μπορώ να προσθέσω μια επιλογή εκκίνησης που ξεκινά ένα εναλλακτικό shell;](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Ανασκόπηση Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
