# Κατάχρηση Δικαιωμάτων

{{#include ../../banners/hacktricks-training.md}}

## Δικαιώματα

Αν **δεν ξέρετε τι είναι τα Windows Access Tokens** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:

{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορείτε να αναβαθμίσετε τα δικαιώματα σας καταχρώντας τα δικαιώματα που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι το δικαίωμα που κατέχει οποιαδήποτε διαδικασία που επιτρέπει την προσωποποίηση (αλλά όχι τη δημιουργία) οποιουδήποτε δικαιώματος, εφόσον μπορεί να αποκτηθεί ένα handle σε αυτό. Ένα προνομιακό δικαίωμα μπορεί να αποκτηθεί από μια υπηρεσία Windows (DCOM) προκαλώντας την να εκτελέσει NTLM authentication κατά ενός exploit, επιτρέποντας στη συνέχεια την εκτέλεση μιας διαδικασίας με δικαιώματα SYSTEM. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα εργαλεία, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί να είναι απενεργοποιημένο το winrm), [SweetPotato](https://github.com/CCob/SweetPotato), και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα προνομιακό δικαίωμα.\
Στη συνέχεια, αυτό το δικαίωμα επιτρέπει **να αναθέσει ένα πρωτεύον δικαίωμα** σε μια νέα/ανασταλμένη διαδικασία. Με το προνομιακό δικαίωμα προσωποποίησης μπορείτε να παράγετε ένα πρωτεύον δικαίωμα (DuplicateTokenEx).\
Με το δικαίωμα, μπορείτε να δημιουργήσετε μια **νέα διαδικασία** με 'CreateProcessAsUser' ή να δημιουργήσετε μια διαδικασία ανασταλμένη και **να ορίσετε το δικαίωμα** (γενικά, δεν μπορείτε να τροποποιήσετε το πρωτεύον δικαίωμα μιας εκτελούμενης διαδικασίας).

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το δικαίωμα μπορείτε να χρησιμοποιήσετε **KERB_S4U_LOGON** για να αποκτήσετε ένα **δικαίωμα προσωποποίησης** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήρια, **να προσθέσετε μια αυθαίρετη ομάδα** (admins) στο δικαίωμα, να ορίσετε το **επίπεδο ακεραιότητας** του δικαιώματος σε "**medium**", και να αναθέσετε αυτό το δικαίωμα στο **τρέχον νήμα** (SetThreadToken).

### SeBackupPrivilege

Το σύστημα προκαλεί να **παρέχει πλήρη πρόσβαση** ανάγνωσης σε οποιοδήποτε αρχείο (περιορισμένο σε λειτουργίες ανάγνωσης) μέσω αυτού του δικαιώματος. Χρησιμοποιείται για **ανάγνωση των κατακερματισμών κωδικών πρόσβασης των τοπικών λογαριασμών Διαχειριστή** από τη μητρώο, μετά την οποία, εργαλεία όπως "**psexec**" ή "**wmiexec**" μπορούν να χρησιμοποιηθούν με τον κατακερματισμό (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο συνθήκες: όταν ο λογαριασμός τοπικού διαχειριστή είναι απενεργοποιημένος, ή όταν υπάρχει πολιτική που αφαιρεί τα διοικητικά δικαιώματα από τους τοπικούς διαχειριστές που συνδέονται απομακρυσμένα.\
Μπορείτε να **καταχραστείτε αυτό το δικαίωμα** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **αναβάθμιση δικαιωμάτων με Backup Operators** του:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Η άδεια για **πρόσβαση εγγραφής** σε οποιοδήποτε αρχείο συστήματος, ανεξαρτήτως της Λίστας Ελέγχου Πρόσβασης (ACL) του αρχείου, παρέχεται από αυτό το δικαίωμα. Ανοίγει πολλές δυνατότητες για αναβάθμιση, συμπεριλαμβανομένης της δυνατότητας **τροποποίησης υπηρεσιών**, εκτέλεσης DLL Hijacking, και ρύθμισης **debuggers** μέσω των Επιλογών Εκτέλεσης Αρχείων Εικόνας μεταξύ άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι μια ισχυρή άδεια, ιδιαίτερα χρήσιμη όταν ένας χρήστης έχει τη δυνατότητα να προσωποποιεί δικαιώματα, αλλά και στην απουσία του SeImpersonatePrivilege. Αυτή η ικανότητα εξαρτάται από την ικανότητα να προσωποποιεί ένα δικαίωμα που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει αυτό της τρέχουσας διαδικασίας.

**Κύρια Σημεία:**

- **Προσωποποίηση χωρίς SeImpersonatePrivilege:** Είναι δυνατόν να εκμεταλλευτείτε το SeCreateTokenPrivilege για EoP προσωποποιώντας δικαιώματα υπό συγκεκριμένες συνθήκες.
- **Συνθήκες για Προσωποποίηση Δικαιωμάτων:** Η επιτυχής προσωποποίηση απαιτεί το στοχευμένο δικαίωμα να ανήκει στον ίδιο χρήστη και να έχει επίπεδο ακεραιότητας που είναι μικρότερο ή ίσο με το επίπεδο ακεραιότητας της διαδικασίας που προσπαθεί να προσωποποιήσει.
- **Δημιουργία και Τροποποίηση Δικαιωμάτων Προσωποποίησης:** Οι χρήστες μπορούν να δημιουργήσουν ένα δικαίωμα προσωποποίησης και να το ενισχύσουν προσθέτοντας ένα SID (Security Identifier) προνομιακής ομάδας.

### SeLoadDriverPrivilege

Αυτό το δικαίωμα επιτρέπει να **φορτώνει και να ξεφορτώνει οδηγούς συσκευών** με τη δημιουργία μιας καταχώρησης μητρώου με συγκεκριμένες τιμές για το `ImagePath` και `Type`. Δεδομένου ότι η άμεση πρόσβαση εγγραφής στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από τον πυρήνα για τη ρύθμιση του οδηγού, πρέπει να ακολουθηθεί μια συγκεκριμένη διαδρομή.

Αυτή η διαδρομή είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου `<RID>` είναι ο Σχετικός Αναγνωριστής του τρέχοντος χρήστη. Μέσα στο `HKCU`, αυτή η ολόκληρη διαδρομή πρέπει να δημιουργηθεί, και δύο τιμές πρέπει να οριστούν:

- `ImagePath`, που είναι η διαδρομή προς το δυαδικό αρχείο που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα που πρέπει να ακολουθηθούν:**

1. Πρόσβαση στο `HKCU` αντί για `HKLM` λόγω περιορισμένης πρόσβασης εγγραφής.
2. Δημιουργία της διαδρομής `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` εντός του `HKCU`, όπου `<RID>` αντιπροσωπεύει τον Σχετικό Αναγνωριστή του τρέχοντος χρήστη.
3. Ορισμός του `ImagePath` στη διαδρομή εκτέλεσης του δυαδικού αρχείου.
4. Ανάθεση του `Type` ως `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Περισσότεροι τρόποι για να καταχραστεί αυτή η προνομία στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διαδικασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του προοριζόμενου κλειδιού μητρώου για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL για να επιτραπούν οι λειτουργίες εγγραφής.
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

Αυτό το προνόμιο επιτρέπει την **αποσφαλμάτωση άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Διάφορες στρατηγικές για την ένεση μνήμης, ικανές να παρακάμψουν τις περισσότερες λύσεις antivirus και πρόληψης εισβολών φιλοξενίας, μπορούν να χρησιμοποιηθούν με αυτό το προνόμιο.

#### Dump memory

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων χρηστών μόλις ένας χρήστης έχει συνδεθεί επιτυχώς σε ένα σύστημα.

Μπορείτε στη συνέχεια να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Αν θέλετε να αποκτήσετε ένα `NT SYSTEM` shell μπορείτε να χρησιμοποιήσετε:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Έλεγχος δικαιωμάτων
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Απενεργοποιημένα** μπορούν να ενεργοποιηθούν, μπορείτε πραγματικά να εκμεταλλευτείτε τα _Ενεργοποιημένα_ και _Απενεργοποιημένα_ tokens.

### Ενεργοποίηση Όλων των tokens

Αν έχετε tokens που είναι απενεργοποιημένα, μπορείτε να χρησιμοποιήσετε το σενάριο [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το **script** που είναι ενσωματωμένο σε αυτήν την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Πλήρης οδηγός προνομίων token στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η παρακάτω σύνοψη θα αναφέρει μόνο άμεσους τρόπους εκμετάλλευσης του προνομίου για την απόκτηση μιας διαχειριστικής συνεδρίας ή την ανάγνωση ευαίσθητων αρχείων.

| Προνόμιο                  | Επιπτώσεις  | Εργαλείο                | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                                     | Σημειώσεις                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Διαχειριστής**_ | 3rd party tool          | _"Θα επέτρεπε σε έναν χρήστη να μιμηθεί tokens και να αποκτήσει δικαιώματα στο nt system χρησιμοποιώντας εργαλεία όπως το potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω να το ξαναδιατυπώσω σε κάτι πιο συνταγές σύντομα.                                                                                                                                                                                         |
| **`SeBackup`**             | **Απειλή**  | _**Ενσωματωμένες εντολές**_ | Διαβάστε ευαίσθητα αρχεία με `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε το %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (και robocopy) δεν είναι χρήσιμο όταν πρόκειται για ανοιχτά αρχεία.<br><br>- Το Robocopy απαιτεί τόσο το SeBackup όσο και το SeRestore για να λειτουργήσει με την παράμετρο /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Διαχειριστής**_ | 3rd party tool          | Δημιουργία αυθαίρετου token που περιλαμβάνει δικαιώματα τοπικού διαχειριστή με `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Διαχειριστής**_ | **PowerShell**          | Διπλασιάστε το token του `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Το script μπορεί να βρεθεί στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Διαχειριστής**_ | 3rd party tool          | <p>1. Φορτώστε ελαττωματικό kernel driver όπως το <code>szkg64.sys</code><br>2. Εκμεταλλευτείτε την ευπάθεια του driver<br><br>Εναλλακτικά, το προνόμιο μπορεί να χρησιμοποιηθεί για να ξεφορτωθείτε drivers που σχετίζονται με την ασφάλεια με την ενσωματωμένη εντολή <code>ftlMC</code>. π.χ.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Η ευπάθεια <code>szkg64</code> αναφέρεται ως <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Ο <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">κωδικός εκμετάλλευσης</a> δημιουργήθηκε από τον <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Διαχειριστής**_ | **PowerShell**          | <p>1. Εκκινήστε το PowerShell/ISE με το προνόμιο SeRestore παρόν.<br>2. Ενεργοποιήστε το προνόμιο με <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομάστε το utilman.exe σε utilman.old<br>4. Μετονομάστε το cmd.exe σε utilman.exe<br>5. Κλειδώστε την κονσόλα και πατήστε Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσίας που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο προνόμιο</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Διαχειριστής**_ | _**Ενσωματωμένες εντολές**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε το cmd.exe σε utilman.exe<br>4. Κλειδώστε την κονσόλα και πατήστε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσίας που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο προνόμιο.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Διαχειριστής**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Αναφορά

- Ρίξτε μια ματιά σε αυτόν τον πίνακα που ορίζει τα Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Ρίξτε μια ματιά σε [**αυτήν την εργασία**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) σχετικά με την εκμετάλλευση με tokens.

{{#include ../../banners/hacktricks-training.md}}
