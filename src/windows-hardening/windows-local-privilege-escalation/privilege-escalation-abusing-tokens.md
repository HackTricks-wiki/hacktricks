# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν ξέρετε τι είναι τα Windows Access Tokens** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορείτε να αυξήσετε τα προνόμια εκμεταλλευόμενοι τα tokens που ήδη έχετε**

### SeImpersonatePrivilege

This is privilege that is held by any process allows the impersonation (but not creation) of any token, given that a handle to it can be obtained. A privileged token can be acquired from a Windows service (DCOM) by inducing it to perform NTLM authentication against an exploit, subsequently enabling the execution of a process with SYSTEM privileges. This vulnerability can be exploited using various tools, such as [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).

### SeTcbPrivilege

If you have enabled this token you can use **KERB_S4U_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege

This privilege causes the system to **grant all read access** control to any file (limited to read operations). It is utilized for **reading the password hashes of local Administrator** accounts from the registry, following which, tools like "**psexec**" or "**wmiexec**" can be used with the hash (Pass-the-Hash technique). However, this technique fails under two conditions: when the Local Administrator account is disabled, or when a policy is in place that removes administrative rights from Local Administrators connecting remotely.\
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Permission for **write access** to any system file, irrespective of the file's Access Control List (ACL), is provided by this privilege. It opens up numerous possibilities for escalation, including the ability to **modify services**, perform DLL Hijacking, and set **debuggers** via Image File Execution Options among various other techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is a powerful permission, especially useful when a user possesses the ability to impersonate tokens, but also in the absence of SeImpersonatePrivilege. This capability hinges on the ability to impersonate a token that represents the same user and whose integrity level does not exceed that of the current process.

**Κύρια Σημεία:**

- **Impersonation without SeImpersonatePrivilege:** It's possible to leverage SeCreateTokenPrivilege for EoP by impersonating tokens under specific conditions.
- **Conditions for Token Impersonation:** Successful impersonation requires the target token to belong to the same user and have an integrity level that is less or equal to the integrity level of the process attempting impersonation.
- **Creation and Modification of Impersonation Tokens:** Users can create an impersonation token and enhance it by adding a privileged group's SID (Security Identifier).

### SeLoadDriverPrivilege

This privilege allows to **load and unload device drivers** with the creation of a registry entry with specific values for `ImagePath` and `Type`. Since direct write access to `HKLM` (HKEY_LOCAL_MACHINE) is restricted, `HKCU` (HKEY_CURRENT_USER) must be utilized instead. However, to make `HKCU` recognizable to the kernel for driver configuration, a specific path must be followed.

This path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Inside `HKCU`, this entire path must be created, and two values need to be set:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, with a value of `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα προς Ακολούθηση:**

1. Access `HKCU` instead of `HKLM` due to restricted write access.
2. Create the path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` within `HKCU`, where `<RID>` represents the current user's Relative Identifier.
3. Set the `ImagePath` to the binary's execution path.
4. Assign the `Type` as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής των δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του προοριζόμενου registry key για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL ώστε να επιτραπούν λειτουργίες εγγραφής.
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

Αυτό το προνόμιο επιτρέπει το **debug other processes**, συμπεριλαμβανομένης της δυνατότητας ανάγνωσης και εγγραφής στη μνήμη. Διάφορες στρατηγικές για memory injection, ικανές να παρακάμπτουν τα περισσότερα antivirus και host intrusion prevention solutions, μπορούν να χρησιμοποιηθούν με αυτό το προνόμιο.

#### Dump memory

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από τη [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **capture the memory of a process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διαδικασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων χρήστη αφότου ένας χρήστης έχει επιτυχώς συνδεθεί στο σύστημα.

Στη συνέχεια μπορείτε να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
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

Αυτό το προνόμιο (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ., \\.\C:) για απευθείας disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στον τόμο διαβάζοντας τα υποκείμενα blocks, επιτρέποντας αυθαίρετη ανάγνωση αρχείων ευαίσθητου υλικού (π.χ., ιδιωτικά κλειδιά μηχανής στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS μέσω VSS). Είναι ιδιαίτερα σημαντικό σε CA servers όπου η εξαγωγή του ιδιωτικού κλειδιού του CA επιτρέπει την πλαστογράφηση ενός Golden Certificate για να μιμηθεί οποιονδήποτε principal.

Δείτε αναλυτικές τεχνικές και μετριασμούς:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Έλεγχος προνομίων
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** μπορούν να ενεργοποιηθούν — στην πραγματικότητα μπορείτε να καταχραστείτε τα _Enabled_ και _Disabled_ tokens.

### Ενεργοποίηση όλων των tokens

Αν έχετε tokens που είναι disabled, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το ενσωματωμένο **script** σε αυτό το [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η σύνοψη παρακάτω θα αναφέρει μόνο άμεσους τρόπους για να εκμεταλλευτείτε το δικαίωμα ώστε να αποκτήσετε μια admin συνεδρία ή να διαβάσετε ευαίσθητα αρχεία.

| Privilege                  | Επίπτωση   | Εργαλείο                | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                                 | Παρατηρήσεις                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | εργαλείο τρίτου         | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω να το διατυπώσω πιο πολύ σαν συνταγή σύντομα.                                                                                                                                                                                             |
| **`SeBackup`**             | **Απειλή**  | _**Built-in commands**_ | Διαβάστε ευαίσθητα αρχεία με `robocopy /b`                                                                                                                                                                                                                                                                                                       | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (και robocopy) δεν βοηθά όταν πρόκειται για ανοικτά αρχεία.<br><br>- Το Robocopy απαιτεί τόσο SeBackup όσο και SeRestore για να λειτουργήσει με την παράμετρο /b.</p>                                           |
| **`SeCreateToken`**        | _**Admin**_ | εργαλείο τρίτου         | Δημιουργήστε αυθαίρετο token συμπεριλαμβανομένων τοπικών δικαιωμάτων admin με `NtCreateToken`.                                                                                                                                                                                                                                                   |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Δημιουργία αντιγράφου του token του `lsass.exe`.                                                                                                                                                                                                                                                                                                 | Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | εργαλείο τρίτου         | <p>1. Φορτώστε προβληματικό kernel driver όπως <code>szkg64.sys</code><br>2. Εκμεταλλευτείτε την ευπάθεια του driver<br><br>Εναλλακτικά, το δικαίωμα μπορεί να χρησιμοποιηθεί για να ξεφορτώσει drivers σχετιζόμενους με ασφάλεια με την ενσωματωμένη εντολή <code>ftlMC</code>. π.χ.: <code>fltMC sysmondrv</code></p> | <p>1. Η ευπάθεια του <code>szkg64</code> καταχωρείται ως <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Ο κώδικας του <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> δημιουργήθηκε από <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκινήστε PowerShell/ISE με παρόν το δικαίωμα SeRestore.<br>2. Ενεργοποιήστε το δικαίωμα με <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Μετονομάστε <code>utilman.exe</code> σε <code>utilman.old</code><br>4. Μετονομάστε <code>cmd.exe</code> σε <code>utilman.exe</code><br>5. Κλειδώστε την κονσόλα και πατήστε Win+U</p> | <p>Η επίθεση ενδέχεται να ανιχνευθεί από κάποιο AV λογισμικό.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των service binaries αποθηκευμένων στο "Program Files" χρησιμοποιώντας το ίδιο δικαίωμα</p>                                                                                                        |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε <code>cmd.exe</code> σε <code>utilman.exe</code><br>4. Κλειδώστε την κονσόλα και πατήστε Win+U</p>                                                                                                     | <p>Η επίθεση ενδέχεται να ανιχνευθεί από κάποιο AV λογισμικό.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των service binaries αποθηκευμένων στο "Program Files" χρησιμοποιώντας το ίδιο δικαίωμα.</p>                                                                                                  |
| **`SeTcb`**                | _**Admin**_ | εργαλείο τρίτου         | <p>Χειρισμός tokens ώστε να περιλαμβάνονται τοπικά δικαιώματα admin. Μπορεί να απαιτεί SeImpersonate.</p><p>Να εξακριβωθεί.</p>                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |

## Αναφορές

- Ρίξτε μια ματιά σε αυτόν τον πίνακα που ορίζει τα Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Δείτε [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) σχετικά με privesc με tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
