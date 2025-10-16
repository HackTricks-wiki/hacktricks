# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορείτε να αποκτήσετε αυξημένα προνόμια εκμεταλλευόμενοι τα tokens που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι προνόμιο που κατέχει οποιαδήποτε διεργασία και επιτρέπει την impersonation (αλλά όχι τη δημιουργία) οποιουδήποτε token, εφόσον μπορεί να αποκτηθεί ένα handle σε αυτό. Ένα privileged token μπορεί να αποκτηθεί από μια Windows service (DCOM) προκαλώντας την να πραγματοποιήσει NTLM authentication ενάντια σε ένα exploit, επιτρέποντας στη συνέχεια την εκτέλεση μιας διεργασίας με SYSTEM privileges. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί με διάφορα εργαλεία, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί το winrm να είναι απενεργοποιημένο), [SweetPotato](https://github.com/CCob/SweetPotato), και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, χρησιμοποιεί την **ίδια μέθοδο** για να αποκτήσει ένα privileged token. Στη συνέχεια, αυτό το προνόμιο επιτρέπει **να ανατεθεί ένα primary token** σε μια νέα/ανεσταλμένη διεργασία. Με το privileged impersonation token μπορείτε να παράγετε (derive) ένα primary token (DuplicateTokenEx).\
Με το token, μπορείτε να δημιουργήσετε μια **καινούργια διεργασία** με 'CreateProcessAsUser' ή να δημιουργήσετε μια διεργασία σε κατάσταση suspended και **να ορίσετε το token** (γενικά, δεν μπορείτε να τροποποιήσετε το primary token μιας διεργασίας που τρέχει).

### SeTcbPrivilege

Εάν έχετε ενεργοποιημένο αυτό το προνόμιο μπορείτε να χρησιμοποιήσετε **KERB_S4U_LOGON** για να πάρετε ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα credentials, **να προσθέσετε μια αυθαίρετη ομάδα** (π.χ. admins) στο token, να ορίσετε το **integrity level** του token σε "**medium**", και να αναθέσετε αυτό το token στο **τρέχον thread** (SetThreadToken).

### SeBackupPrivilege

Αυτό το προνόμιο προκαλεί στο σύστημα να **παρέχει πλήρη δικαιώματα ανάγνωσης** για οποιοδήποτε αρχείο (περιορισμένο σε read operations). Χρησιμοποιείται για την **ανάγνωση των password hashes των local Administrator** λογαριασμών από το registry, μετά από το οποίο εργαλεία όπως το "**psexec**" ή το "**wmiexec**" μπορούν να χρησιμοποιηθούν με το hash (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο προϋποθέσεις: όταν ο Local Administrator account είναι απενεργοποιημένος, ή όταν υπάρχει πολιτική που αφαιρεί τα administrative rights από Local Administrators που συνδέονται απομακρυσμένα.\
Μπορείτε να **καταχραστείτε αυτό το προνόμιο** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **escalating privileges with Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Παρέχει δικαιώματα για **εγγραφή σε οποιοδήποτε σύστημα αρχείων**, ανεξάρτητα από το Access Control List (ACL). Ανοίγει πολλές δυνατότητες για escalation, συμπεριλαμβανομένης της ικανότητας να **τροποποιήσετε services**, να εκμεταλλευτείτε DLL Hijacking, και να ορίσετε **debuggers** μέσω Image File Execution Options μεταξύ άλλων τεχνικών.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege είναι ένα ισχυρό προνόμιο, ιδιαίτερα χρήσιμο όταν ένας χρήστης έχει τη δυνατότητα να impersonate tokens, αλλά και στην απουσία του SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στην ικανότητα να impersonate ένα token που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το integrity level δεν υπερβαίνει αυτό της τρέχουσας διεργασίας.

Key Points:

- **Impersonation χωρίς SeImpersonatePrivilege:** Είναι δυνατό να χρησιμοποιηθεί το SeCreateTokenPrivilege για EoP εκμεταλλευόμενο impersonation tokens υπό συγκεκριμένες συνθήκες.
- **Προϋποθέσεις για Token Impersonation:** Η επιτυχημένη impersonation απαιτεί το target token να ανήκει στον ίδιο χρήστη και να έχει integrity level μικρότερο ή ίσο με αυτό της διεργασίας που προσπαθεί την impersonation.
- **Δημιουργία και Τροποποίηση Impersonation Tokens:** Οι χρήστες μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID μιας privileged ομάδας (Security Identifier).

### SeLoadDriverPrivilege

Αυτό το προνόμιο επιτρέπει το **load και unload device drivers** με τη δημιουργία μιας καταχώρησης registry με συγκεκριμένες τιμές για `ImagePath` και `Type`. Εφόσον η άμεση εγγραφή σε `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, πρέπει να χρησιμοποιηθεί `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να αναγνωριστεί το `HKCU` από τον kernel για ρύθμιση driver, πρέπει να ακολουθηθεί μια συγκεκριμένη διαδρομή.

Αυτή η διαδρομή είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου `<RID>` είναι το Relative Identifier του τρέχοντος χρήστη. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρη αυτή η διαδρομή, και να ρυθμιστούν δύο τιμές:

- `ImagePath`, που είναι το path προς το binary που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Πρόσβαση στο `HKCU` αντί για `HKLM` λόγω περιορισμένης δυνατότητας εγγραφής.
2. Δημιουργία της διαδρομής `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου `<RID>` αντιπροσωπεύει το Relative Identifier του τρέχοντος χρήστη.
3. Ορισμός του `ImagePath` στο path εκτέλεσης του binary.
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής των δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του επιλεγμένου κλειδιού μητρώου για σκοπούς εγγραφής και στη συνέχεια την τροποποίηση του DACL ώστε να επιτραπούν οι λειτουργίες εγγραφής.
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

Αυτό το προνόμιο επιτρέπει την **αποσφαλμάτωση άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Διάφορες στρατηγικές για εισαγωγή στη μνήμη, ικανές να παρακάμπτουν τα περισσότερα antivirus και λύσεις πρόληψης εισβολών, μπορούν να χρησιμοποιηθούν με αυτό το προνόμιο.

#### Εξαγωγή μνήμης

Μπορείτε να χρησιμοποιήσετε [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία της υπηρεσίας **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων χρηστών αφού ένας χρήστης έχει συνδεθεί επιτυχώς σε ένα σύστημα.

Μπορείτε στη συνέχεια να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Αν θέλετε να αποκτήσετε ένα shell `NT SYSTEM`, μπορείτε να χρησιμοποιήσετε:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) για άμεση I/O στον δίσκο που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στον τόμο διαβάζοντας τα υποκείμενα blocks, επιτρέποντας αυθαίρετη ανάγνωση αρχείων με ευαίσθητο περιεχόμενο (π.χ. machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Είναι ιδιαίτερα κρίσιμο σε CA servers όπου η εξαγωγή του CA private key επιτρέπει το forging ενός Golden Certificate για να μιμηθεί οποιονδήποτε principal.

Δείτε αναλυτικές τεχνικές και μέτρα μετριασμού:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Έλεγχος προνομίων
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** μπορούν να ενεργοποιηθούν — στην πραγματικότητα μπορείτε να εκμεταλλευτείτε τόσο τα _Enabled_ όσο και τα _Disabled_ tokens.

### Ενεργοποίηση όλων των tokens

Εάν έχετε tokens disabled, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το ενσωματωμένο **script** σε αυτήν την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), το παρακάτω περίληψη θα απαριθμήσει μόνο άμεσους τρόπους για εκμετάλλευση του privilege προκειμένου να αποκτηθεί μια admin συνεδρία ή να διαβαστούν ευαίσθατα αρχεία.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστίες σε [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω σύντομα να το ξαναδιατυπώσω με πιο «συνταγοποιημένο» τρόπο.                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (και το robocopy) δεν βοηθάει όταν πρόκειται για ανοικτά αρχεία.<br><br>- Το Robocopy απαιτεί τόσο SeBackup όσο και SeRestore για να λειτουργήσει με την παράμετρο /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευτεί από κάποια AV λογισμικά.</p><p>Μια εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries αποθηκευμένων στο "Program Files" χρησιμοποιώντας το ίδιο privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευτεί από κάποια AV λογισμικά.</p><p>Μια εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries αποθηκευμένων στο "Program Files" χρησιμοποιώντας το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Ρίξτε μια ματιά σε αυτόν τον πίνακα που ορίζει τα Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Δείτε [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) σχετικά με privesc με tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
