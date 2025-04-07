# Κατάχρηση Δικαιωμάτων

{{#include ../../../banners/hacktricks-training.md}}

## Δικαιώματα

Αν **δεν ξέρετε τι είναι τα Windows Access Tokens** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:

{{#ref}}
../access-tokens.md
{{#endref}}

**Ίσως να μπορείτε να αναβαθμίσετε τα δικαιώματα σας καταχρώντας τα δικαιώματα που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι ένα δικαίωμα που κατέχει οποιαδήποτε διαδικασία και επιτρέπει την προσωποποίηση (αλλά όχι τη δημιουργία) οποιουδήποτε δικαιώματος, εφόσον μπορεί να αποκτηθεί ένα handle σε αυτό. Ένα προνομιακό δικαίωμα μπορεί να αποκτηθεί από μια υπηρεσία Windows (DCOM) προκαλώντας την να εκτελέσει NTLM authentication κατά ενός exploit, επιτρέποντας στη συνέχεια την εκτέλεση μιας διαδικασίας με δικαιώματα SYSTEM. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα εργαλεία, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί να είναι απενεργοποιημένο το winrm), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
../roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
../juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα προνομιακό δικαίωμα.\
Στη συνέχεια, αυτό το δικαίωμα επιτρέπει **να αναθέσει ένα πρωτεύον δικαίωμα** σε μια νέα/ανασταλμένη διαδικασία. Με το προνομιακό δικαίωμα προσωποποίησης μπορείτε να παράγετε ένα πρωτεύον δικαίωμα (DuplicateTokenEx).\
Με το δικαίωμα, μπορείτε να δημιουργήσετε μια **νέα διαδικασία** με 'CreateProcessAsUser' ή να δημιουργήσετε μια διαδικασία ανασταλμένη και **να ορίσετε το δικαίωμα** (γενικά, δεν μπορείτε να τροποποιήσετε το πρωτεύον δικαίωμα μιας εκτελούμενης διαδικασίας).

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το δικαίωμα μπορείτε να χρησιμοποιήσετε **KERB_S4U_LOGON** για να αποκτήσετε ένα **δικαίωμα προσωποποίησης** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήρια, **να προσθέσετε μια αυθαίρετη ομάδα** (admins) στο δικαίωμα, να ορίσετε το **επίπεδο ακεραιότητας** του δικαιώματος σε "**medium**", και να αναθέσετε αυτό το δικαίωμα στο **τρέχον νήμα** (SetThreadToken).

### SeBackupPrivilege

Το σύστημα προκαλεί να **παρέχει πλήρη πρόσβαση** ανάγνωσης σε οποιοδήποτε αρχείο (περιορισμένο σε λειτουργίες ανάγνωσης) μέσω αυτού του δικαιώματος. Χρησιμοποιείται για **ανάγνωση των κατακερματισμών κωδικών πρόσβασης των τοπικών λογαριασμών Διαχειριστή** από τη μητρώο, μετά την οποία, εργαλεία όπως το "**psexec**" ή το "**wmiexec**" μπορούν να χρησιμοποιηθούν με τον κατακερματισμό (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο συνθήκες: όταν ο λογαριασμός τοπικού διαχειριστή είναι απενεργοποιημένος, ή όταν υπάρχει πολιτική που αφαιρεί τα διοικητικά δικαιώματα από τους τοπικούς διαχειριστές που συνδέονται απομακρυσμένα.\
Μπορείτε να **καταχραστείτε αυτό το δικαίωμα** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **αναβάθμιση δικαιωμάτων με Backup Operators** του:

{{#ref}}
../../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Η άδεια για **πρόσβαση εγγραφής** σε οποιοδήποτε αρχείο συστήματος, ανεξαρτήτως της Λίστας Ελέγχου Πρόσβασης (ACL) του αρχείου, παρέχεται από αυτό το δικαίωμα. Ανοίγει πολλές δυνατότητες για αναβάθμιση, συμπεριλαμβανομένης της δυνατότητας **τροποποίησης υπηρεσιών**, εκτέλεσης DLL Hijacking, και ρύθμισης **debuggers** μέσω των Επιλογών Εκτέλεσης Αρχείων Εικόνας μεταξύ άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι μια ισχυρή άδεια, ιδιαίτερα χρήσιμη όταν ένας χρήστης έχει τη δυνατότητα να προσωποποιεί δικαιώματα, αλλά και στην απουσία του SeImpersonatePrivilege. Αυτή η ικανότητα εξαρτάται από την ικανότητα να προσωποποιεί ένα δικαίωμα που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει αυτό της τρέχουσας διαδικασίας.

**Κύρια Σημεία:**

- **Προσωποποίηση χωρίς SeImpersonatePrivilege:** Είναι δυνατόν να εκμεταλλευτείτε το SeCreateTokenPrivilege για EoP προσωποποιώντας δικαιώματα υπό συγκεκριμένες συνθήκες.
- **Συνθήκες για Προσωποποίηση Δικαιωμάτων:** Η επιτυχής προσωποποίηση απαιτεί το στοχευμένο δικαίωμα να ανήκει στον ίδιο χρήστη και να έχει επίπεδο ακεραιότητας που είναι μικρότερο ή ίσο με το επίπεδο ακεραιότητας της διαδικασίας που προσπαθεί να προσωποποιήσει.
- **Δημιουργία και Τροποποίηση Δικαιωμάτων Προσωποποίησης:** Οι χρήστες μπορούν να δημιουργήσουν ένα δικαίωμα προσωποποίησης και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) μιας προνομιακής ομάδας.

### SeLoadDriverPrivilege

Αυτό το δικαίωμα επιτρέπει να **φορτώνει και να ξεφορτώνει οδηγούς συσκευών** με τη δημιουργία μιας καταχώρισης μητρώου με συγκεκριμένες τιμές για το `ImagePath` και το `Type`. Δεδομένου ότι η άμεση πρόσβαση εγγραφής στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από τον πυρήνα για τη ρύθμιση του οδηγού, πρέπει να ακολουθηθεί μια συγκεκριμένη διαδρομή.

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
Περισσότεροι τρόποι για να καταχραστεί αυτή η εξουσία στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

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

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ή το [SharpDump](https://github.com/GhostPack/SharpDump) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων χρηστών μόλις ένας χρήστης έχει συνδεθεί επιτυχώς σε ένα σύστημα.

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
### SeManageVolumePrivilege

Το `SeManageVolumePrivilege` είναι ένα δικαίωμα χρήστη των Windows που επιτρέπει στους χρήστες να διαχειρίζονται δίσκους, συμπεριλαμβανομένης της δημιουργίας και διαγραφής τους. Ενώ προορίζεται για διαχειριστές, αν παραχωρηθεί σε μη διαχειριστές χρήστες, μπορεί να εκμεταλλευτεί για αναβάθμιση δικαιωμάτων.

Είναι δυνατόν να εκμεταλλευτείτε αυτό το δικαίωμα για να χειριστείτε τους δίσκους, οδηγώντας σε πλήρη πρόσβαση στους δίσκους. Το [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) μπορεί να χρησιμοποιηθεί για να δώσει πλήρη πρόσβαση σε όλους τους χρήστες για το C:\

Επιπλέον, η διαδικασία που περιγράφεται σε [αυτό το άρθρο του Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) περιγράφει τη χρήση DLL hijacking σε συνδυασμό με το `SeManageVolumePrivilege` για την αναβάθμιση δικαιωμάτων. Τοποθετώντας ένα payload DLL `C:\Windows\System32\wbem\tzres.dll` και καλώντας το `systeminfo`, η dll εκτελείται.

## Check privileges
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Απενεργοποιημένα** μπορούν να ενεργοποιηθούν, μπορείτε πραγματικά να εκμεταλλευτείτε τα _Ενεργοποιημένα_ και _Απενεργοποιημένα_ tokens.

### Ενεργοποίηση Όλων των tokens

Αν έχετε tokens απενεργοποιημένα, μπορείτε να χρησιμοποιήσετε το σενάριο [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Διαχειριστής**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Απειλή**  | _**Ενσωματωμένες εντολές**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- May be more interesting if you can read %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) is not helpful when it comes to open files.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Διαχειριστής**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Διαχειριστής**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Διαχειριστής**_ | 3rd party tool          | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Διαχειριστής**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Διαχειριστής**_ | _**Ενσωματωμένες εντολές**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Διαχειριστής**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.

{{#include ../../../banners/hacktricks-training.md}}
